use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::assertions::AssertionReport;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_LENGTH: usize = 1024 * 1024;
pub const MAX_REQUEST_DATA_LENGTH: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandFrame {
    pub protocol_version: u16,
    pub command_id: u64,
    pub command: Command,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    StartServer {
        address: String,
        corrupt_responses: bool,
    },
    StopServer {},
    Request {
        request_id: String,
        payload: String,
        phase: RequestPhase,
    },
    Check {
        outage_event_bound: u64,
        liveness_event_bound: u64,
    },
    Shutdown {},
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestPhase {
    Running,
    Stopped,
    Restarted,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventFrame {
    pub protocol_version: u16,
    pub event_id: u64,
    pub command_id: u64,
    pub event: Event,
    #[serde(default, skip_serializing_if = "DiagnosticFields::is_empty")]
    pub diagnostics: DiagnosticFields,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    AgentReady {},
    ServerStarted {
        address: String,
        corrupt_responses: bool,
    },
    ServerStopped {},
    RequestAttempted {
        request_id: String,
        payload: String,
        phase: RequestPhase,
    },
    RequestSucceeded {
        request_id: String,
        request_payload: String,
        response_id: String,
        response_payload: String,
        phase: RequestPhase,
    },
    RequestUnavailable {
        request_id: String,
        phase: RequestPhase,
    },
    AssertionsEvaluated {
        report: AssertionReport,
    },
    AgentStopped {},
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_received_at_unix_nanos: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temporary_path: Option<String>,
}

impl DiagnosticFields {
    fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedEvent {
    pub protocol_version: u16,
    pub event_id: u64,
    pub command_id: u64,
    pub event: Event,
}

impl EventFrame {
    /// Removes the complete, explicit set of non-semantic fields: guest PID,
    /// host receipt timestamp, and temporary host path.
    pub fn normalize(&self) -> NormalizedEvent {
        NormalizedEvent {
            protocol_version: self.protocol_version,
            event_id: self.event_id,
            command_id: self.command_id,
            event: self.event.clone(),
        }
    }
}

pub fn write_frame<T: Serialize>(writer: &mut impl Write, value: &T) -> io::Result<()> {
    let body = serde_json::to_vec(value).map_err(io::Error::other)?;
    if body.len() > MAX_FRAME_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame exceeds maximum length",
        ));
    }
    writer.write_all(&(body.len() as u32).to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()
}

pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> io::Result<Option<T>> {
    let mut length = [0_u8; 4];
    loop {
        match reader.read(&mut length[..1]) {
            Ok(0) => return Ok(None),
            Ok(1) => break,
            Ok(_) => unreachable!("one-byte buffer accepted more than one byte"),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    reader.read_exact(&mut length[1..])?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds maximum length",
        ));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn require_version(version: u16) -> io::Result<()> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported protocol version {version}"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read};

    use serde_json::json;

    use super::*;

    #[test]
    fn frame_round_trip_and_version_check() {
        let command = CommandFrame {
            protocol_version: PROTOCOL_VERSION,
            command_id: 9,
            command: Command::StopServer {},
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &command).unwrap();
        assert_eq!(read_frame(&mut bytes.as_slice()).unwrap(), Some(command));
        assert!(require_version(PROTOCOL_VERSION + 1).is_err());
    }

    #[test]
    fn normalization_only_removes_enumerated_diagnostics() {
        let frame = EventFrame {
            protocol_version: PROTOCOL_VERSION,
            event_id: 2,
            command_id: 1,
            event: Event::ServerStarted {
                address: "127.0.0.1:8080".into(),
                corrupt_responses: true,
            },
            diagnostics: DiagnosticFields {
                guest_pid: Some(42),
                host_received_at_unix_nanos: Some(99),
                temporary_path: Some("/tmp/run.123".into()),
            },
        };
        let normalized = frame.normalize();
        assert_eq!(normalized.protocol_version, PROTOCOL_VERSION);
        assert_eq!(normalized.event_id, 2);
        assert_eq!(normalized.command_id, 1);
        assert_eq!(normalized.event, frame.event);
        assert!(
            !serde_json::to_string(&normalized)
                .unwrap()
                .contains("guest_pid")
        );
    }

    #[test]
    fn oversized_frame_is_rejected_before_allocation() {
        let mut bytes = ((MAX_FRAME_LENGTH + 1) as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(b"{}");
        assert_eq!(
            read_frame::<CommandFrame>(&mut bytes.as_slice())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn truncated_length_is_not_treated_as_clean_eof() {
        assert_eq!(
            read_frame::<CommandFrame>(&mut [0_u8, 0].as_slice())
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn interrupted_header_read_is_retried() {
        struct InterruptedOnce {
            interrupted: bool,
            bytes: Cursor<Vec<u8>>,
        }

        impl Read for InterruptedOnce {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                self.bytes.read(buffer)
            }
        }

        let command = CommandFrame {
            protocol_version: PROTOCOL_VERSION,
            command_id: 1,
            command: Command::StopServer {},
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &command).unwrap();
        let mut reader = InterruptedOnce {
            interrupted: false,
            bytes: Cursor::new(bytes),
        };
        assert_eq!(read_frame(&mut reader).unwrap(), Some(command));
    }

    #[test]
    fn unknown_fields_are_rejected_at_every_wire_level() {
        let cases = [
            json!({
                "protocol_version": 1,
                "event_id": 1,
                "command_id": 1,
                "event": {"type": "server_stopped"},
                "unknown_envelope_field": true
            }),
            json!({
                "protocol_version": 1,
                "event_id": 1,
                "command_id": 1,
                "event": {"type": "server_stopped", "reason": "unexpected"}
            }),
            json!({
                "protocol_version": 1,
                "event_id": 1,
                "command_id": 1,
                "event": {"type": "server_stopped"},
                "diagnostics": {"guest_pid": 42, "unknown_diagnostic": true}
            }),
            json!({
                "protocol_version": 1,
                "event_id": 1,
                "command_id": 1,
                "event": {
                    "type": "assertions_evaluated",
                    "report": {"passed": true, "assertions": [], "unknown_report_field": true}
                }
            }),
        ];

        for value in cases {
            assert!(serde_json::from_value::<EventFrame>(value).is_err());
        }

        let command = json!({
            "protocol_version": 1,
            "command_id": 1,
            "command": {"type": "stop_server", "unknown_command_field": true}
        });
        assert!(serde_json::from_value::<CommandFrame>(command).is_err());
    }
}
