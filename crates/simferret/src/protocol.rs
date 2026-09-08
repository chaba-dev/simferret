use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::assertions::AssertionReport;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_LENGTH: usize = 1024 * 1024;
pub const MAX_REQUEST_DATA_LENGTH: usize = 64 * 1024;
pub const SERIAL_ACK: u8 = 0;

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
    ConfigureNetwork {
        interface: String,
        guest_cidr: String,
        gateway: String,
    },
    ActivateOutage {
        peer_cidr: String,
    },
    RestoreNetwork {
        peer_cidr: String,
    },
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
    PreOutage,
    Outage,
    Recovery,
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
    NetworkConfigured {
        interface: String,
        guest_cidr: String,
        gateway: String,
    },
    OutageActivated {
        peer_cidr: String,
        rule: String,
    },
    NetworkRestored {
        peer_cidr: String,
    },
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
        error: RequestError,
        errno: Option<i32>,
    },
    AssertionsEvaluated {
        report: AssertionReport,
    },
    AgentStopped {},
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestError {
    AdministrativeProhibited,
    Transport,
    InvalidResponse,
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

pub fn write_line_frame<T: Serialize>(writer: &mut impl Write, value: &T) -> io::Result<()> {
    let body = serde_json::to_vec(value).map_err(io::Error::other)?;
    if body.len() > MAX_FRAME_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame exceeds maximum length",
        ));
    }
    writer.write_all(&body)?;
    writer.write_all(b"\n")?;
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

pub fn read_line_frame<T: DeserializeOwned>(reader: &mut impl Read) -> io::Result<Option<T>> {
    let mut body = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) if body.is_empty() => return Ok(None),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated line-delimited frame",
                ));
            }
            Ok(1) if byte[0] == b'\n' => break,
            Ok(1) => {
                if body.len() >= MAX_FRAME_LENGTH {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "frame exceeds maximum length",
                    ));
                }
                body.push(byte[0]);
            }
            Ok(_) => unreachable!("one-byte buffer accepted more than one byte"),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn read_acknowledged_line_frame<T: DeserializeOwned>(
    reader: &mut impl Read,
    acknowledgements: &mut impl Write,
) -> io::Result<Option<T>> {
    let mut body = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) if body.is_empty() => return Ok(None),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated line-delimited frame",
                ));
            }
            Ok(1) => {
                acknowledgements.write_all(&[SERIAL_ACK])?;
                acknowledgements.flush()?;
                if byte[0] == b'\n' {
                    break;
                }
                if body.len() >= MAX_FRAME_LENGTH {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "frame exceeds maximum length",
                    ));
                }
                body.push(byte[0]);
            }
            Ok(_) => unreachable!("one-byte buffer accepted more than one byte"),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
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
    use serde_json::json;

    use super::*;

    fn command() -> CommandFrame {
        CommandFrame {
            protocol_version: PROTOCOL_VERSION,
            command_id: 9,
            command: Command::ActivateOutage {
                peer_cidr: "10.0.2.2/32".into(),
            },
        }
    }

    #[test]
    fn version_one_network_command_round_trips() {
        let command = command();
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &command).unwrap();
        assert_eq!(read_frame(&mut bytes.as_slice()).unwrap(), Some(command));
        assert!(require_version(PROTOCOL_VERSION + 1).is_err());
    }

    #[test]
    fn acknowledged_line_frame_acks_every_byte() {
        let command = command();
        let mut bytes = Vec::new();
        write_line_frame(&mut bytes, &command).unwrap();
        let mut acknowledgements = Vec::new();
        assert_eq!(
            read_acknowledged_line_frame(&mut bytes.as_slice(), &mut acknowledgements).unwrap(),
            Some(command)
        );
        assert_eq!(acknowledgements, vec![SERIAL_ACK; bytes.len()]);
    }

    #[test]
    fn oversized_and_truncated_frames_are_rejected() {
        let oversized = vec![b' '; MAX_FRAME_LENGTH + 1];
        assert_eq!(
            read_line_frame::<CommandFrame>(&mut oversized.as_slice())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            read_line_frame::<CommandFrame>(&mut b"{}".as_slice())
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn wire_types_reject_unknown_fields() {
        let command = json!({
            "protocol_version": PROTOCOL_VERSION,
            "command_id": 1,
            "command": {
                "type": "activate_outage",
                "peer_cidr": "10.0.2.2/32",
                "unexpected": true
            }
        });
        assert!(serde_json::from_value::<CommandFrame>(command).is_err());
    }
}
