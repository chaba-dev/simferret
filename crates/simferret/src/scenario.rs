use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::protocol::MAX_REQUEST_DATA_LENGTH;

pub const SCENARIO_VERSION: u16 = 1;
pub const CHOICE_PLAN_VERSION: u16 = 1;
pub const MAX_SCENARIO_SOURCE_BYTES: usize = 1024 * 1024;
pub const MAX_SCENARIO_NAME_BYTES: usize = 256;
pub const MAX_REQUEST_COUNT: usize = 256;
pub const MAX_TOTAL_PAYLOAD_BYTES: usize = 1024 * 1024;

/// The version of the workload-driven acceptance scenario. It shares the
/// network fixture fields of [`Scenario`] but adds a seeded process-fault choice
/// point, so it is a separate versioned contract rather than a change to the
/// frozen Phase 4 scenario.
pub const WORKLOAD_SCENARIO_VERSION: u16 = 1;
/// The version of the workload-driven choice plan.
pub const WORKLOAD_CHOICE_PLAN_VERSION: u16 = 1;
/// A workload scenario must be able to place the process fault strictly inside
/// the request sequence and keep it distinct from both fault transitions, so it
/// needs at least one request before the fault and one after.
pub const MIN_WORKLOAD_REQUEST_COUNT: usize = 4;
/// The pinned acceptance fixture accepts only `[A-Za-z0-9_-]` tokens shorter than
/// 128 bytes, and a planned payload is hex-encoded before it is written to the
/// fixture's stdin, so a payload may not exceed 63 bytes. The bound is a property
/// of the fixture contract, not of the transport, and is checked here so an
/// oversized payload fails during preparation instead of inside the guest.
pub const MAX_WORKLOAD_PAYLOAD_BYTES: usize = 63;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub version: u16,
    pub name: String,
    pub request_count: usize,
    pub payload_bytes: usize,
    pub fixture_peer: String,
    pub outage_event_bound: u64,
    pub liveness_event_bound: u64,
    #[serde(default)]
    pub corrupt_responses: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChoicePlan {
    pub version: u16,
    pub seed: u64,
    pub outage_activation_request_index: usize,
    pub restoration_request_index: usize,
    pub requests: Vec<PlannedRequest>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedRequest {
    pub request_id: String,
    pub payload: String,
}

/// One workload-driven acceptance scenario. It reuses the proven restricted
/// TFTP fixture fields, but the requests are originated by the packaged workload
/// through recorded `stdin-write` commands rather than by the agent, and the
/// seeded plan additionally chooses where the process fault and restart are
/// materialized.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadScenario {
    pub version: u16,
    pub name: String,
    pub request_count: usize,
    pub payload_bytes: usize,
    pub fixture_peer: String,
    pub outage_event_bound: u64,
    pub liveness_event_bound: u64,
    pub corrupt_responses: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadChoicePlan {
    pub version: u16,
    pub seed: u64,
    /// The request index before which the first invocation is terminated and the
    /// second invocation is started from a fresh root.
    pub process_fault_request_index: usize,
    pub outage_activation_request_index: usize,
    pub restoration_request_index: usize,
    pub requests: Vec<PlannedRequest>,
}

impl WorkloadScenario {
    pub fn read(path: &Path) -> io::Result<(Self, Vec<u8>)> {
        let mut source = Vec::new();
        File::open(path)?
            .take(MAX_SCENARIO_SOURCE_BYTES as u64 + 1)
            .read_to_end(&mut source)?;
        Self::parse(source)
    }

    pub fn parse(source: Vec<u8>) -> io::Result<(Self, Vec<u8>)> {
        if source.len() > MAX_SCENARIO_SOURCE_BYTES {
            return Err(invalid(format!(
                "scenario source must not exceed {MAX_SCENARIO_SOURCE_BYTES} bytes"
            )));
        }
        let text = std::str::from_utf8(&source)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let scenario: Self = toml::from_str(text)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        scenario.validate()?;
        Ok((scenario, source))
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.version != WORKLOAD_SCENARIO_VERSION {
            return Err(invalid(format!(
                "unsupported workload scenario version {}",
                self.version
            )));
        }
        if self.name.is_empty() || self.name.len() > MAX_SCENARIO_NAME_BYTES {
            return Err(invalid(format!(
                "scenario name must contain between 1 and {MAX_SCENARIO_NAME_BYTES} bytes"
            )));
        }
        if !(MIN_WORKLOAD_REQUEST_COUNT..=MAX_REQUEST_COUNT).contains(&self.request_count) {
            return Err(invalid(format!(
                "request_count must be between {MIN_WORKLOAD_REQUEST_COUNT} and {MAX_REQUEST_COUNT}"
            )));
        }
        if self.payload_bytes == 0 || self.payload_bytes > MAX_WORKLOAD_PAYLOAD_BYTES {
            return Err(invalid(format!(
                "payload_bytes must be between 1 and {MAX_WORKLOAD_PAYLOAD_BYTES}, because the fixture's hex-encoded token must stay under 128 bytes"
            )));
        }
        let total_payload_bytes = self
            .request_count
            .checked_mul(self.payload_bytes)
            .ok_or_else(|| invalid("scenario payload budget overflowed"))?;
        if total_payload_bytes > MAX_TOTAL_PAYLOAD_BYTES {
            return Err(invalid(format!(
                "request_count * payload_bytes must not exceed {MAX_TOTAL_PAYLOAD_BYTES}"
            )));
        }
        if self.outage_event_bound == 0 || self.liveness_event_bound < 2 {
            return Err(invalid(
                "outage_event_bound must be positive and liveness_event_bound must be at least 2",
            ));
        }
        let peer: std::net::IpAddr = self
            .fixture_peer
            .parse()
            .map_err(|error| invalid(format!("invalid fixture_peer: {error}")))?;
        if peer != std::net::Ipv4Addr::new(10, 0, 2, 2) {
            return Err(invalid(
                "fixture_peer must be the fixed private peer 10.0.2.2",
            ));
        }
        Ok(())
    }

    /// Derive the seeded request plan and the process-fault and fault-transition
    /// choice points. The process fault is always strictly inside the sequence
    /// and distinct from both transitions, so the acceptance never conflates a
    /// restart with an outage transition.
    pub fn choices(&self, seed: u64) -> WorkloadChoicePlan {
        let mut random = SplitMix64(seed);
        let outage_activation_request_index = 1 + random.next() as usize % (self.request_count - 2);
        let restoration_request_index = outage_activation_request_index
            + 1
            + random.next() as usize % (self.request_count - outage_activation_request_index - 1);
        let candidates = (1..self.request_count)
            .filter(|index| {
                *index != outage_activation_request_index && *index != restoration_request_index
            })
            .collect::<Vec<_>>();
        let process_fault_request_index = candidates[random.next() as usize % candidates.len()];
        let requests = (0..self.request_count)
            .map(|index| {
                let nonce = random.next();
                PlannedRequest {
                    request_id: format!("request-{index:04}-{nonce:016x}"),
                    payload: random.hex_bytes(self.payload_bytes),
                }
            })
            .collect();
        WorkloadChoicePlan {
            version: WORKLOAD_CHOICE_PLAN_VERSION,
            seed,
            process_fault_request_index,
            outage_activation_request_index,
            restoration_request_index,
            requests,
        }
    }
}

impl Scenario {
    pub fn read(path: &Path) -> io::Result<(Self, Vec<u8>)> {
        let mut source = Vec::new();
        File::open(path)?
            .take(MAX_SCENARIO_SOURCE_BYTES as u64 + 1)
            .read_to_end(&mut source)?;
        Self::parse(source)
    }

    pub fn parse(source: Vec<u8>) -> io::Result<(Self, Vec<u8>)> {
        if source.len() > MAX_SCENARIO_SOURCE_BYTES {
            return Err(invalid(format!(
                "scenario source must not exceed {MAX_SCENARIO_SOURCE_BYTES} bytes"
            )));
        }
        let text = std::str::from_utf8(&source)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let scenario: Self = toml::from_str(text)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        scenario.validate()?;
        Ok((scenario, source))
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.version != SCENARIO_VERSION {
            return Err(invalid(format!(
                "unsupported scenario version {}",
                self.version
            )));
        }
        if self.name.is_empty() || self.name.len() > MAX_SCENARIO_NAME_BYTES {
            return Err(invalid(format!(
                "scenario name must contain between 1 and {MAX_SCENARIO_NAME_BYTES} bytes"
            )));
        }
        if !(3..=MAX_REQUEST_COUNT).contains(&self.request_count) {
            return Err(invalid(format!(
                "request_count must be between 3 and {MAX_REQUEST_COUNT}"
            )));
        }
        if self.payload_bytes == 0 || self.payload_bytes > MAX_REQUEST_DATA_LENGTH / 4 {
            return Err(invalid(format!(
                "payload_bytes must be between 1 and {}",
                MAX_REQUEST_DATA_LENGTH / 4
            )));
        }
        let total_payload_bytes = self
            .request_count
            .checked_mul(self.payload_bytes)
            .ok_or_else(|| invalid("scenario payload budget overflowed"))?;
        if total_payload_bytes > MAX_TOTAL_PAYLOAD_BYTES {
            return Err(invalid(format!(
                "request_count * payload_bytes must not exceed {MAX_TOTAL_PAYLOAD_BYTES}"
            )));
        }
        if self.outage_event_bound == 0 || self.liveness_event_bound < 2 {
            return Err(invalid(
                "outage_event_bound must be positive and liveness_event_bound must be at least 2",
            ));
        }
        let peer: std::net::IpAddr = self
            .fixture_peer
            .parse()
            .map_err(|error| invalid(format!("invalid fixture_peer: {error}")))?;
        if peer != std::net::Ipv4Addr::new(10, 0, 2, 2) {
            return Err(invalid(
                "fixture_peer must be the fixed private peer 10.0.2.2",
            ));
        }
        Ok(())
    }

    pub fn choices(&self, seed: u64) -> ChoicePlan {
        let mut random = SplitMix64(seed);
        let outage_activation_request_index = 1 + random.next() as usize % (self.request_count - 2);
        let restoration_request_index = outage_activation_request_index
            + 1
            + random.next() as usize % (self.request_count - outage_activation_request_index - 1);
        let requests = (0..self.request_count)
            .map(|index| {
                let nonce = random.next();
                PlannedRequest {
                    request_id: format!("request-{index:04}-{nonce:016x}"),
                    payload: random.hex_bytes(self.payload_bytes),
                }
            })
            .collect();
        ChoicePlan {
            version: CHOICE_PLAN_VERSION,
            seed,
            outage_activation_request_index,
            restoration_request_index,
            requests,
        }
    }
}

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn hex_bytes(&mut self, length: usize) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(length * 2);
        let mut value = 0;
        for index in 0..length {
            if index % 8 == 0 {
                value = self.next();
            }
            let byte = (value >> ((index % 8) * 8)) as u8;
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0xf) as usize] as char);
        }
        output
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario() -> Scenario {
        Scenario {
            version: SCENARIO_VERSION,
            name: "network-outage".into(),
            request_count: 6,
            payload_bytes: 8,
            fixture_peer: "10.0.2.2".into(),
            outage_event_bound: 1,
            liveness_event_bound: 2,
            corrupt_responses: false,
        }
    }

    #[test]
    fn choices_are_stable_and_seed_dependent() {
        let scenario = scenario();
        let first = scenario.choices(42);
        assert_eq!(first, scenario.choices(42));
        assert_ne!(first, scenario.choices(43));
        assert!((1..scenario.request_count - 1).contains(&first.outage_activation_request_index));
        assert!(first.restoration_request_index > first.outage_activation_request_index);
        assert!(first.restoration_request_index < scenario.request_count);
        assert_eq!(first.version, CHOICE_PLAN_VERSION);
        assert_eq!(first.requests.len(), scenario.request_count);
    }

    #[test]
    fn scenario_parser_is_strict_and_validates_bounds() {
        let encoded = toml::to_string(&scenario()).unwrap();
        let parsed: Scenario = toml::from_str(&encoded).unwrap();
        parsed.validate().unwrap();
        assert!(toml::from_str::<Scenario>(&format!("{encoded}unknown = 1\n")).is_err());

        let mut invalid = scenario();
        invalid.request_count = 2;
        assert!(invalid.validate().is_err());

        invalid = scenario();
        invalid.request_count = MAX_REQUEST_COUNT + 1;
        assert!(invalid.validate().is_err());

        invalid = scenario();
        invalid.request_count = MAX_REQUEST_COUNT;
        invalid.payload_bytes = MAX_TOTAL_PAYLOAD_BYTES / MAX_REQUEST_COUNT + 1;
        assert!(invalid.validate().is_err());

        invalid = scenario();
        invalid.name = "x".repeat(MAX_SCENARIO_NAME_BYTES + 1);
        assert!(invalid.validate().is_err());
    }

    fn workload_scenario() -> WorkloadScenario {
        WorkloadScenario {
            version: WORKLOAD_SCENARIO_VERSION,
            name: "workload-network-outage".into(),
            request_count: 6,
            payload_bytes: 8,
            fixture_peer: "10.0.2.2".into(),
            outage_event_bound: 8,
            liveness_event_bound: 8,
            corrupt_responses: false,
        }
    }

    #[test]
    fn workload_choices_place_every_choice_inside_the_sequence() {
        let scenario = workload_scenario();
        for seed in 0..64 {
            let plan = scenario.choices(seed);
            assert_eq!(plan.version, WORKLOAD_CHOICE_PLAN_VERSION);
            assert_eq!(plan.seed, seed);
            assert_eq!(plan.requests.len(), scenario.request_count);
            assert!(
                (1..scenario.request_count - 1).contains(&plan.outage_activation_request_index)
            );
            assert!(plan.restoration_request_index > plan.outage_activation_request_index);
            assert!(plan.restoration_request_index < scenario.request_count);
            assert!((1..scenario.request_count).contains(&plan.process_fault_request_index));
            assert_ne!(
                plan.process_fault_request_index,
                plan.outage_activation_request_index
            );
            assert_ne!(
                plan.process_fault_request_index,
                plan.restoration_request_index
            );
        }
        let first = scenario.choices(42);
        assert_eq!(first, scenario.choices(42));
        assert_ne!(first, scenario.choices(43));
    }

    #[test]
    fn workload_scenario_parser_is_strict_and_validates_bounds() {
        let encoded = toml::to_string(&workload_scenario()).unwrap();
        let parsed: WorkloadScenario = toml::from_str(&encoded).unwrap();
        parsed.validate().unwrap();
        assert!(toml::from_str::<WorkloadScenario>(&format!("{encoded}unknown = 1\n")).is_err());

        let mut invalid = workload_scenario();
        invalid.request_count = MIN_WORKLOAD_REQUEST_COUNT - 1;
        assert!(invalid.validate().is_err());

        invalid = workload_scenario();
        invalid.request_count = MAX_REQUEST_COUNT + 1;
        assert!(invalid.validate().is_err());

        invalid = workload_scenario();
        invalid.version = WORKLOAD_SCENARIO_VERSION + 1;
        assert!(invalid.validate().is_err());

        invalid = workload_scenario();
        invalid.fixture_peer = "127.0.0.1".into();
        assert!(invalid.validate().is_err());

        invalid = workload_scenario();
        invalid.outage_event_bound = 0;
        assert!(invalid.validate().is_err());

        invalid = workload_scenario();
        invalid.liveness_event_bound = 1;
        assert!(invalid.validate().is_err());

        // The fixture's hex-encoded token must stay under its 128-byte limit, so
        // a payload at the transport bound is rejected during preparation.
        invalid = workload_scenario();
        invalid.payload_bytes = MAX_WORKLOAD_PAYLOAD_BYTES + 1;
        assert!(invalid.validate().is_err());

        invalid = workload_scenario();
        invalid.payload_bytes = MAX_REQUEST_DATA_LENGTH / 4;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn oversized_scenario_source_is_rejected_by_a_bounded_read() {
        let path = std::env::temp_dir().join(format!(
            "simferret-oversized-scenario-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, vec![b'x'; MAX_SCENARIO_SOURCE_BYTES + 1]).unwrap();
        let error = Scenario::read(&path).unwrap_err();
        std::fs::remove_file(path).unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("must not exceed"));
    }
}
