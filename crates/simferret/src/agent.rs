use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;
use std::process::Command as ProcessCommand;
use std::time::Duration;

use crate::assertions::evaluate;
use crate::protocol::{
    Command, CommandFrame, DiagnosticFields, Event, EventFrame, LaunchFailure, PROTOCOL_VERSION,
    RequestError, SERIAL_ACK, read_acknowledged_line_frame, read_frame, require_version,
    write_frame, write_line_frame,
};
use crate::runtime::{Runtime, RuntimeConfig};

const INTERFACE: &str = "eth0";
const GUEST_CIDR: &str = "10.0.2.15/24";
const GATEWAY: &str = "10.0.2.2";
const PEER_CIDR: &str = "10.0.2.2/32";
const OUTAGE_RULE: &str = "prohibit 10.0.2.2/32";
const BUSYBOX: &str = "/bin/busybox";
/// The bounded wait for control input while a workload is live. The guest
/// runtime is drained as soon as either the control channel or an output pipe
/// becomes ready, so this only bounds idle latency.
const CONTROL_POLL: Duration = Duration::from_millis(50);

pub fn run(input: &mut impl Read, output: &mut impl Write, _executable: &Path) -> io::Result<i32> {
    run_with_framing(input, output, false, None)
}

/// The production guest entry point: the control channel is a raw serial
/// channel, and a workload runtime supervises packaged processes.
pub fn run_serial(
    input: &mut std::fs::File,
    output: &mut impl Write,
    _executable: &Path,
) -> io::Result<i32> {
    // A network-only image has no workload template, so the runtime is optional
    // and `start` reports a typed `no-runtime` launch failure instead. A present
    // template is validated strictly before any command is accepted.
    let runtime = if std::path::Path::new(crate::runtime::GUEST_TEMPLATE_ROOT).exists() {
        Some(Runtime::new(RuntimeConfig::guest())?)
    } else {
        None
    };
    run_serial_with_runtime(input, output, runtime)
}

/// The serial control loop with an explicit runtime, so the guest entry point
/// and the runtime tests share one implementation.
pub fn run_serial_with_runtime(
    input: &mut std::fs::File,
    output: &mut impl Write,
    runtime: Option<Runtime>,
) -> io::Result<i32> {
    let mut agent = Agent::new(true, runtime);
    agent.poll_loop(input.as_raw_fd(), output)?;
    Ok(agent.exit_code)
}

fn run_with_framing(
    input: &mut impl Read,
    output: &mut impl Write,
    line_framing: bool,
    runtime: Option<Runtime>,
) -> io::Result<i32> {
    let mut agent = Agent::new(line_framing, runtime);
    agent.command_loop(input, output)?;
    Ok(agent.exit_code)
}

struct Agent {
    events: Vec<EventFrame>,
    next_event_id: u64,
    exit_code: i32,
    line_framing: bool,
    network_configured: bool,
    outage_active: bool,
    runtime: Option<Runtime>,
    last_command_id: u64,
}

impl Agent {
    fn new(line_framing: bool, runtime: Option<Runtime>) -> Self {
        Self {
            events: Vec::new(),
            next_event_id: 1,
            exit_code: 0,
            line_framing,
            network_configured: false,
            outage_active: false,
            runtime,
            last_command_id: 0,
        }
    }

    /// The blocking control loop used without a workload runtime.
    fn command_loop(&mut self, input: &mut impl Read, output: &mut impl Write) -> io::Result<()> {
        loop {
            let frame = if self.line_framing {
                read_acknowledged_line_frame::<CommandFrame>(input, output)?
            } else {
                read_frame::<CommandFrame>(input)?
            };
            let Some(frame) = frame else { return Ok(()) };
            require_version(frame.protocol_version)?;
            self.last_command_id = frame.command_id;
            if !self.dispatch(frame.command_id, frame.command, output)? {
                return Ok(());
            }
        }
    }

    /// The guest control loop. It polls the control channel and the live
    /// workload output pipes together, so output frames are emitted while the
    /// workload runs instead of only between commands.
    fn poll_loop(&mut self, input_fd: RawFd, output: &mut impl Write) -> io::Result<()> {
        let mut buffer = Vec::new();
        loop {
            self.service_runtime(output)?;
            let mut descriptors = vec![libc::pollfd {
                fd: input_fd,
                events: libc::POLLIN,
                revents: 0,
            }];
            for fd in self.runtime_output_fds() {
                descriptors.push(libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
            // SAFETY: `descriptors` is a live, initialized array of pollfd
            // values and the control descriptor is owned by the caller.
            let ready = unsafe {
                libc::poll(
                    descriptors.as_mut_ptr(),
                    descriptors.len() as libc::nfds_t,
                    CONTROL_POLL.as_millis() as i32,
                )
            };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 || descriptors[0].revents == 0 {
                continue;
            }
            let Some(frames) = read_serial_frames(input_fd, &mut buffer, output)? else {
                // The control channel closed. Terminate any live workload so
                // the cleanup barrier runs before the guest powers off.
                self.shutdown_runtime(output)?;
                return Ok(());
            };
            for frame in frames {
                require_version(frame.protocol_version)?;
                self.last_command_id = frame.command_id;
                if !self.dispatch(frame.command_id, frame.command, output)? {
                    return Ok(());
                }
            }
        }
    }

    fn runtime_output_fds(&self) -> Vec<RawFd> {
        self.runtime
            .as_ref()
            .map(Runtime::output_fds)
            .unwrap_or_default()
    }

    fn service_runtime(&mut self, output: &mut impl Write) -> io::Result<()> {
        let events = match self.runtime.as_mut() {
            Some(runtime) => match runtime.poll(Duration::ZERO) {
                Ok(events) => events,
                Err(error) => {
                    // A limit, pipe, or transport failure is fatal: kill the
                    // invocation, run the barrier, and report the failure.
                    let _ = runtime.shutdown();
                    return Err(error);
                }
            },
            None => return Ok(()),
        };
        for event in events {
            self.emit(self.last_command_id, event, output)?;
        }
        Ok(())
    }

    fn shutdown_runtime(&mut self, output: &mut impl Write) -> io::Result<()> {
        let events = match self.runtime.as_mut() {
            Some(runtime) => runtime.shutdown()?,
            None => Vec::new(),
        };
        for event in events {
            self.emit(self.last_command_id, event, output)?;
        }
        Ok(())
    }

    fn require_runtime(&mut self) -> io::Result<&mut Runtime> {
        self.runtime.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "no workload runtime is configured",
            )
        })
    }

    /// Handle one command. Returns `false` when the agent should stop.
    fn dispatch(
        &mut self,
        command_id: u64,
        command: Command,
        output: &mut impl Write,
    ) -> io::Result<bool> {
        match command {
            Command::ConfigureNetwork {
                interface,
                guest_cidr,
                gateway,
            } => {
                require_network_values(&interface, &guest_cidr, &gateway)?;
                if self.network_configured {
                    return Err(invalid("network is already configured"));
                }
                configure_network()?;
                self.network_configured = true;
                self.emit(
                    command_id,
                    Event::NetworkConfigured {
                        interface,
                        guest_cidr,
                        gateway,
                    },
                    output,
                )?;
            }
            Command::ActivateOutage { peer_cidr } => {
                self.require_network()?;
                require_peer(&peer_cidr)?;
                if self.outage_active {
                    return Err(invalid("outage is already active"));
                }
                set_outage(true)?;
                self.outage_active = true;
                self.emit(
                    command_id,
                    Event::OutageActivated {
                        peer_cidr,
                        rule: OUTAGE_RULE.into(),
                    },
                    output,
                )?;
            }
            Command::RestoreNetwork { peer_cidr } => {
                self.require_network()?;
                require_peer(&peer_cidr)?;
                if !self.outage_active {
                    return Err(invalid("outage is not active"));
                }
                set_outage(false)?;
                self.outage_active = false;
                self.emit(command_id, Event::NetworkRestored { peer_cidr }, output)?;
            }
            Command::Request {
                request_id,
                payload,
                phase,
            } => {
                self.require_network()?;
                validate_request(&request_id, &payload, GATEWAY)?;
                self.emit(
                    command_id,
                    Event::RequestAttempted {
                        request_id: request_id.clone(),
                        payload: payload.clone(),
                        phase,
                    },
                    output,
                )?;
                let event = match crate::fixture::tftp_request(GATEWAY, &request_id) {
                    Ok((response_id, response_payload)) => Event::RequestSucceeded {
                        request_id,
                        request_payload: payload,
                        response_id,
                        response_payload,
                        phase,
                    },
                    Err(error) => {
                        let errno = error.raw_os_error();
                        let error = if errno == Some(libc::EACCES) {
                            RequestError::AdministrativeProhibited
                        } else if error.kind() == io::ErrorKind::InvalidData {
                            RequestError::InvalidResponse
                        } else {
                            RequestError::Transport
                        };
                        Event::RequestUnavailable {
                            request_id,
                            phase,
                            error,
                            errno,
                        }
                    }
                };
                self.emit(command_id, event, output)?;
            }
            Command::Check {
                outage_event_bound,
                liveness_event_bound,
            } => {
                let report = evaluate(&self.events, outage_event_bound, liveness_event_bound);
                self.exit_code = self.exit_code.max(report.exit_code());
                self.emit(command_id, Event::AssertionsEvaluated { report }, output)?;
            }
            Command::Start { invocation, launch } => {
                let events = match self.runtime.as_mut() {
                    Some(runtime) => runtime.start(invocation, &launch),
                    None => vec![Event::LaunchFailed {
                        invocation,
                        failure: LaunchFailure::NoRuntime,
                        detail: "no workload runtime is configured".into(),
                    }],
                };
                for event in events {
                    self.emit(command_id, event, output)?;
                }
            }
            Command::StdinWrite {
                invocation,
                offset,
                bytes,
            } => {
                let events = self
                    .require_runtime()?
                    .stdin_write(invocation, offset, &bytes)?;
                for event in events {
                    self.emit(command_id, event, output)?;
                }
            }
            Command::StdinEof { invocation } => {
                let events = self.require_runtime()?.stdin_eof(invocation)?;
                for event in events {
                    self.emit(command_id, event, output)?;
                }
            }
            Command::Terminate { invocation } => {
                let events = self.require_runtime()?.terminate(invocation)?;
                for event in events {
                    self.emit(command_id, event, output)?;
                }
            }
            Command::Shutdown {} => {
                if self.outage_active {
                    return Err(invalid("cannot shut down while outage is active"));
                }
                self.shutdown_runtime(output)?;
                self.emit(command_id, Event::AgentStopped {}, output)?;
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn require_network(&self) -> io::Result<()> {
        if self.network_configured {
            Ok(())
        } else {
            Err(invalid("network is not configured"))
        }
    }

    fn emit(&mut self, command_id: u64, event: Event, output: &mut impl Write) -> io::Result<()> {
        let frame = EventFrame {
            protocol_version: PROTOCOL_VERSION,
            event_id: self.next_event_id,
            command_id,
            event,
            diagnostics: DiagnosticFields::default(),
        };
        self.next_event_id += 1;
        if self.line_framing {
            write_line_frame(output, &frame)?;
        } else {
            write_frame(output, &frame)?;
        }
        self.events.push(frame);
        Ok(())
    }
}

/// Read whatever control bytes are available, acknowledge every one, and
/// return any complete line-delimited command frames. `None` reports end of
/// file on the control channel.
fn read_serial_frames(
    fd: RawFd,
    buffer: &mut Vec<u8>,
    output: &mut impl Write,
) -> io::Result<Option<Vec<CommandFrame>>> {
    let mut chunk = [0_u8; 4096];
    // SAFETY: `chunk` is a writable buffer of its own length and `fd` is the
    // live control descriptor.
    let read = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
    if read < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted || error.kind() == io::ErrorKind::WouldBlock {
            return Ok(Some(Vec::new()));
        }
        return Err(error);
    }
    if read == 0 {
        return Ok(None);
    }
    let bytes = &chunk[..read as usize];
    for _ in bytes {
        output.write_all(&[SERIAL_ACK])?;
    }
    output.flush()?;
    buffer.extend_from_slice(bytes);
    let mut frames = Vec::new();
    while let Some(index) = buffer.iter().position(|byte| *byte == b'\n') {
        let line: Vec<u8> = buffer.drain(..=index).collect();
        let body = &line[..line.len() - 1];
        if body.is_empty() {
            continue;
        }
        frames.push(
            serde_json::from_slice(body)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
        );
    }
    if buffer.len() > crate::protocol::MAX_FRAME_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds maximum length",
        ));
    }
    Ok(Some(frames))
}

fn configure_network() -> io::Result<()> {
    run_busybox(["insmod", "/modules/mii.ko"])?;
    run_busybox(["insmod", "/modules/8139cp.ko"])?;
    run_busybox(["ip", "link", "set", INTERFACE, "up"])?;
    run_busybox(["ip", "address", "add", GUEST_CIDR, "dev", INTERFACE])?;
    run_busybox(["ip", "route", "add", "default", "via", GATEWAY])?;
    let driver = std::fs::read_link("/sys/class/net/eth0/device/driver")?;
    if driver.file_name() != Some(std::ffi::OsStr::new("8139cp")) {
        return Err(io::Error::other("rtl8139 NIC did not bind to 8139cp"));
    }
    Ok(())
}

fn set_outage(active: bool) -> io::Result<()> {
    let action = if active { "add" } else { "del" };
    run_busybox(["ip", "route", action, "prohibit", PEER_CIDR])?;
    let output = ProcessCommand::new(BUSYBOX)
        .args(["ip", "route", "show", "exact", PEER_CIDR])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("could not inspect peer-specific route"));
    }
    let route = String::from_utf8_lossy(&output.stdout);
    let present = route.starts_with(OUTAGE_RULE)
        || route.trim_end() == "prohibit 10.0.2.2"
        || route.starts_with("prohibit 10.0.2.2 ");
    if present != active {
        return Err(io::Error::other(
            "peer-specific prohibit route transition was not confirmed",
        ));
    }
    Ok(())
}

fn run_busybox<const N: usize>(arguments: [&str; N]) -> io::Result<()> {
    let status = ProcessCommand::new(BUSYBOX).args(arguments).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "busybox command failed with {status}"
        )))
    }
}

fn require_network_values(interface: &str, guest_cidr: &str, gateway: &str) -> io::Result<()> {
    if (interface, guest_cidr, gateway) == (INTERFACE, GUEST_CIDR, GATEWAY) {
        Ok(())
    } else {
        Err(invalid(
            "network configuration differs from the version-1 profile",
        ))
    }
}

fn require_peer(peer_cidr: &str) -> io::Result<()> {
    if peer_cidr == PEER_CIDR {
        Ok(())
    } else {
        Err(invalid("fault peer differs from the version-1 profile"))
    }
}

fn validate_request(request_id: &str, payload: &str, peer: &str) -> io::Result<()> {
    if request_id.is_empty()
        || !request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || request_id.len().saturating_add(payload.len()) > crate::protocol::MAX_REQUEST_DATA_LENGTH
        || peer != GATEWAY
    {
        Err(invalid(
            "request differs from the bounded network fixture contract",
        ))
    } else {
        Ok(())
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_and_fault_commands_are_fixed_to_the_versioned_profile() {
        require_network_values(INTERFACE, GUEST_CIDR, GATEWAY).unwrap();
        assert!(require_network_values("lo", GUEST_CIDR, GATEWAY).is_err());
        require_peer(PEER_CIDR).unwrap();
        assert!(require_peer("0.0.0.0/0").is_err());
    }

    #[test]
    fn fixture_filenames_and_peer_are_bounded() {
        validate_request("request-0001", "payload", GATEWAY).unwrap();
        assert!(validate_request("../escape", "payload", GATEWAY).is_err());
        assert!(validate_request("request", "payload", "127.0.0.1").is_err());
    }

    #[test]
    fn process_commands_without_a_runtime_report_a_typed_launch_failure() {
        let mut output = Vec::new();
        let mut agent = Agent::new(false, None);
        agent
            .dispatch(
                1,
                Command::Start {
                    invocation: 1,
                    launch: crate::workload::LaunchIdentity {
                        executable: "/bin/app".into(),
                        arguments: vec!["/bin/app".into()],
                        environment: Vec::new(),
                        working_directory: "/".into(),
                        uid: 65534,
                        gid: 65534,
                    },
                },
                &mut output,
            )
            .unwrap();
        assert!(matches!(
            &agent.events[0].event,
            Event::LaunchFailed {
                failure: LaunchFailure::NoRuntime,
                ..
            }
        ));
    }

    #[test]
    fn line_framed_control_input_is_acknowledged_and_split_into_frames() {
        let frame = CommandFrame {
            protocol_version: PROTOCOL_VERSION,
            command_id: 7,
            command: Command::StdinEof { invocation: 1 },
        };
        let mut input = serde_json::to_vec(&frame).unwrap();
        input.push(b'\n');
        let mut output = Vec::new();
        let mut buffer = Vec::new();
        // A pipe is required to read the bytes; use a temporary file instead.
        let path = std::env::temp_dir().join(format!(
            "simferret-agent-frame-{}-{}",
            std::process::id(),
            agent_test_counter()
        ));
        std::fs::write(&path, &input).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let frames = read_serial_frames(file.as_raw_fd(), &mut buffer, &mut output)
            .unwrap()
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(frames, vec![frame]);
        assert_eq!(output, vec![SERIAL_ACK; input.len()]);
        assert!(buffer.is_empty());
    }

    fn agent_test_counter() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }
}
