use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::protocol::MAX_REQUEST_DATA_LENGTH;

pub const SCENARIO_VERSION: u16 = 1;
pub const CHOICE_PLAN_VERSION: u16 = 1;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub version: u16,
    pub name: String,
    pub request_count: usize,
    pub payload_bytes: usize,
    pub server_address: String,
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
    pub fault_request_index: usize,
    pub requests: Vec<PlannedRequest>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedRequest {
    pub request_id: String,
    pub payload: String,
}

impl Scenario {
    pub fn read(path: &Path) -> io::Result<(Self, Vec<u8>)> {
        let source = fs::read(path)?;
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
        if self.name.is_empty() {
            return Err(invalid("scenario name must not be empty"));
        }
        if self.request_count < 3 {
            return Err(invalid("request_count must be at least 3"));
        }
        if self.payload_bytes == 0 || self.payload_bytes > MAX_REQUEST_DATA_LENGTH / 4 {
            return Err(invalid(format!(
                "payload_bytes must be between 1 and {}",
                MAX_REQUEST_DATA_LENGTH / 4
            )));
        }
        if self.outage_event_bound == 0 || self.liveness_event_bound < 2 {
            return Err(invalid(
                "outage_event_bound must be positive and liveness_event_bound must be at least 2",
            ));
        }
        let address: std::net::SocketAddr = self
            .server_address
            .parse()
            .map_err(|error| invalid(format!("invalid server_address: {error}")))?;
        if address.port() == 0 || !address.ip().is_loopback() {
            return Err(invalid(
                "server_address must be numeric loopback with a nonzero port",
            ));
        }
        Ok(())
    }

    pub fn choices(&self, seed: u64) -> ChoicePlan {
        let mut random = SplitMix64(seed);
        let fault_request_index = 1 + random.next() as usize % (self.request_count - 2);
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
            fault_request_index,
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
            name: "echo-process-restart".into(),
            request_count: 6,
            payload_bytes: 8,
            server_address: "127.0.0.1:4000".into(),
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
        assert!((1..scenario.request_count - 1).contains(&first.fault_request_index));
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
    }
}
