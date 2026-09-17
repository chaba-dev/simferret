use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::assertions::AssertionReport;
use crate::workload::LaunchIdentity;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_LENGTH: usize = 1024 * 1024;
pub const MAX_REQUEST_DATA_LENGTH: usize = 64 * 1024;
pub const SERIAL_ACK: u8 = 0;

/// The largest exact byte string one `stdin-write` command may carry.
pub const MAX_STDIN_FRAME_BYTES: usize = 4096;
/// The largest exact byte string one live output frame may carry.
pub const MAX_OUTPUT_FRAME_BYTES: usize = 4096;
/// The complete bounded input one invocation may accept.
pub const MAX_INVOCATION_INPUT_BYTES: usize = 16 << 20;
/// The complete bounded output one invocation may produce per stream.
pub const MAX_INVOCATION_OUTPUT_BYTES: usize = 16 << 20;
/// The initial profile's unconditional termination signal.
pub const TERMINATION_SIGNAL: i32 = libc::SIGKILL;

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
    Start {
        invocation: u64,
        launch: LaunchIdentity,
    },
    StdinWrite {
        invocation: u64,
        offset: u64,
        /// Lowercase hexadecimal exact bytes, bounded by
        /// [`MAX_STDIN_FRAME_BYTES`].
        bytes: String,
    },
    StdinEof {
        invocation: u64,
    },
    Terminate {
        invocation: u64,
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
    WorkloadStarted {
        invocation: u64,
        launch: LaunchIdentity,
    },
    InputAccepted {
        invocation: u64,
        offset: u64,
        bytes: u64,
        eof: bool,
    },
    TerminationRequested {
        invocation: u64,
        signal: i32,
    },
    WorkloadOutput {
        invocation: u64,
        stream: OutputStream,
        offset: u64,
        sequence: u64,
        /// Lowercase hexadecimal exact bytes, bounded by
        /// [`MAX_OUTPUT_FRAME_BYTES`].
        bytes: String,
    },
    WorkloadExited {
        invocation: u64,
        exit: ProcessExit,
        stdout_bytes: u64,
        stdout_sha256: String,
        stderr_bytes: u64,
        stderr_sha256: String,
        frames: u64,
    },
    LaunchFailed {
        invocation: u64,
        failure: LaunchFailure,
        detail: String,
    },
    CleanupComplete {
        invocation: u64,
        reaped: u64,
    },
    AgentStopped {},
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

impl OutputStream {
    pub fn name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum ProcessExit {
    Exited {
        #[serde(deserialize_with = "deserialize_exit_code")]
        code: i32,
    },
    Signaled {
        #[serde(deserialize_with = "deserialize_signal")]
        signal: i32,
    },
}

/// Require a real Linux wait status exit code. The range is enforced while the
/// record is deserialized, so a malformed frame cannot cross the wire boundary
/// and reach a consumer that assumes the contract.
fn deserialize_exit_code<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let code = i32::deserialize(deserializer)?;
    if (0..=255).contains(&code) {
        Ok(code)
    } else {
        Err(serde::de::Error::custom(
            "a process exit code must be between 0 and 255",
        ))
    }
}

/// Require a real Linux signal number, for the same reason as the exit code.
fn deserialize_signal<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let signal = i32::deserialize(deserializer)?;
    if (1..=64).contains(&signal) {
        Ok(signal)
    } else {
        Err(serde::de::Error::custom(
            "a process termination signal must be between 1 and 64",
        ))
    }
}

impl ProcessExit {
    /// The shell-style status code. A signal value outside the Linux range is
    /// saturated instead of overflowing, so a hostile event frame cannot panic
    /// or wrap the host.
    pub fn status_code(self) -> i32 {
        match self {
            Self::Exited { code } => code,
            Self::Signaled { signal } => 128_i32.saturating_add(signal),
        }
    }
}

/// Typed reasons a workload child could not be launched. The companion
/// `detail` string is bounded and never contains environment values or output
/// bytes. Limits, offsets, and transport failures are infrastructure errors
/// rather than launch results, so they are reported by failing the agent
/// instead of by this type.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchFailure {
    NoRuntime,
    InvocationActive,
    InvocationRepeated,
    Materialization,
    Executable,
    WorkingDirectory,
    Pipe,
    Fork,
    Setup,
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

/// Encode exact bytes as the lowercase hexadecimal form used by bounded
/// `stdin-write` and output frames.
pub fn encode_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    output
}

/// Decode the lowercase hexadecimal form of at most `limit` exact bytes.
/// Rejects odd length, non-hexadecimal characters, and any encoded value
/// longer than the limit, so a frame can never expand past its bound.
pub fn decode_bytes(text: &str, limit: usize) -> io::Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) || text.len() > limit.saturating_mul(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("byte frame must encode at most {limit} bytes"),
        ));
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().as_chunks::<2>().0 {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_digit(byte: u8) -> io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "byte frame contains a non-hexadecimal character",
        )),
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
    fn process_commands_and_events_round_trip() {
        let launch = crate::workload::LaunchIdentity {
            executable: "/bin/app".into(),
            arguments: vec!["/bin/app".into(), "--flag".into()],
            environment: vec!["MODE=test".into()],
            working_directory: "/".into(),
            uid: 65534,
            gid: 65534,
        };
        let commands = [
            Command::Start {
                invocation: 1,
                launch: launch.clone(),
            },
            Command::StdinWrite {
                invocation: 1,
                offset: 0,
                bytes: encode_bytes(b"\x00\xff exact"),
            },
            Command::StdinEof { invocation: 1 },
            Command::Terminate { invocation: 1 },
        ];
        for command in commands {
            let mut bytes = Vec::new();
            write_frame(&mut bytes, &command).unwrap();
            assert_eq!(read_frame(&mut bytes.as_slice()).unwrap(), Some(command));
        }
        let events = [
            Event::WorkloadStarted {
                invocation: 1,
                launch,
            },
            Event::InputAccepted {
                invocation: 1,
                offset: 3,
                bytes: 2,
                eof: false,
            },
            Event::TerminationRequested {
                invocation: 1,
                signal: TERMINATION_SIGNAL,
            },
            Event::WorkloadOutput {
                invocation: 1,
                stream: OutputStream::Stdout,
                offset: 0,
                sequence: 1,
                bytes: encode_bytes(b"hi"),
            },
            Event::WorkloadExited {
                invocation: 1,
                exit: ProcessExit::Signaled {
                    signal: TERMINATION_SIGNAL,
                },
                stdout_bytes: 2,
                stdout_sha256: "0".repeat(64),
                stderr_bytes: 0,
                stderr_sha256: "0".repeat(64),
                frames: 1,
            },
            Event::LaunchFailed {
                invocation: 1,
                failure: LaunchFailure::Materialization,
                detail: "the fresh root could not be created".into(),
            },
            Event::CleanupComplete {
                invocation: 1,
                reaped: 2,
            },
        ];
        for event in events {
            let mut bytes = Vec::new();
            write_line_frame(&mut bytes, &event).unwrap();
            assert_eq!(read_line_frame(&mut bytes.as_slice()).unwrap(), Some(event));
        }
    }

    #[test]
    fn process_exit_records_reject_foreign_fields_and_bound_status_codes() {
        // A record carrying a field from the other variant is not a valid exit.
        let foreign = json!({"kind": "exited", "code": 0, "signal": 9});
        assert!(serde_json::from_value::<ProcessExit>(foreign).is_err());
        let unknown = json!({"kind": "exited", "code": 0, "unexpected": true});
        assert!(serde_json::from_value::<ProcessExit>(unknown).is_err());
        // A hostile signal value saturates instead of overflowing.
        let extreme = ProcessExit::Signaled { signal: i32::MAX };
        assert_eq!(extreme.status_code(), i32::MAX);
    }

    /// A malformed exit record must be refused while the frame is read, not by
    /// a validator the caller has to remember to invoke.
    #[test]
    fn malformed_process_exit_records_are_rejected_by_the_frame_reader() {
        for exit in [
            json!({"kind": "exited", "code": -1}),
            json!({"kind": "exited", "code": 256}),
            json!({"kind": "exited", "code": i32::MAX}),
            json!({"kind": "signaled", "signal": 0}),
            json!({"kind": "signaled", "signal": -9}),
            json!({"kind": "signaled", "signal": 65}),
            json!({"kind": "signaled", "signal": i32::MAX}),
        ] {
            assert!(
                serde_json::from_value::<ProcessExit>(exit.clone()).is_err(),
                "{exit} must not deserialize"
            );
            // A complete, otherwise valid frame whose only defect is the exit
            // value, so the reader cannot reject it for an unrelated reason.
            let frame = EventFrame {
                protocol_version: PROTOCOL_VERSION,
                event_id: 1,
                command_id: 1,
                event: Event::WorkloadExited {
                    invocation: 1,
                    exit: ProcessExit::Exited { code: 0 },
                    stdout_bytes: 0,
                    stdout_sha256: String::new(),
                    stderr_bytes: 0,
                    stderr_sha256: String::new(),
                    frames: 0,
                },
                diagnostics: DiagnosticFields::default(),
            };
            let mut value = serde_json::to_value(&frame).unwrap();
            value["event"]["exit"] = exit.clone();
            let mut bytes = serde_json::to_vec(&value).unwrap();
            bytes.push(b'\n');
            assert!(
                read_line_frame::<EventFrame>(&mut bytes.as_slice()).is_err(),
                "{value} must not be accepted by the frame reader"
            );
        }
        // The boundary values a real wait status can produce still round trip.
        for exit in [
            ProcessExit::Exited { code: 0 },
            ProcessExit::Exited { code: 255 },
            ProcessExit::Signaled { signal: 1 },
            ProcessExit::Signaled { signal: 64 },
        ] {
            let frame = EventFrame {
                protocol_version: PROTOCOL_VERSION,
                event_id: 1,
                command_id: 1,
                event: Event::WorkloadExited {
                    invocation: 1,
                    exit,
                    stdout_bytes: 0,
                    stdout_sha256: String::new(),
                    stderr_bytes: 0,
                    stderr_sha256: String::new(),
                    frames: 0,
                },
                diagnostics: DiagnosticFields::default(),
            };
            let mut bytes = Vec::new();
            write_line_frame(&mut bytes, &frame).unwrap();
            assert_eq!(read_line_frame(&mut bytes.as_slice()).unwrap(), Some(frame));
        }
    }

    #[test]
    fn byte_frames_are_exact_and_bounded() {
        assert_eq!(encode_bytes(b"\x00\x01\xfe\xff"), "0001feff");
        assert_eq!(decode_bytes("0001feff", 4).unwrap(), b"\x00\x01\xfe\xff");
        assert!(decode_bytes("001fe", 4).is_err());
        assert!(decode_bytes("0001ff", 1).is_err());
        assert!(decode_bytes("zz", 4).is_err());
        assert!(decode_bytes("", 4).unwrap().is_empty());
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
