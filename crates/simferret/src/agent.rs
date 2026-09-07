use std::io::{self, Read, Write};
use std::path::Path;
use std::process::Command as ProcessCommand;

use crate::assertions::evaluate;
use crate::protocol::{
    Command, CommandFrame, DiagnosticFields, Event, EventFrame, PROTOCOL_VERSION, RequestError,
    read_acknowledged_line_frame, read_frame, require_version, write_frame, write_line_frame,
};

const INTERFACE: &str = "eth0";
const GUEST_CIDR: &str = "10.0.2.15/24";
const GATEWAY: &str = "10.0.2.2";
const PEER_CIDR: &str = "10.0.2.2/32";
const OUTAGE_RULE: &str = "prohibit 10.0.2.2/32";
const BUSYBOX: &str = "/bin/busybox";

pub fn run(input: &mut impl Read, output: &mut impl Write, _executable: &Path) -> io::Result<i32> {
    run_with_framing(input, output, false)
}

pub fn run_serial(
    input: &mut impl Read,
    output: &mut impl Write,
    _executable: &Path,
) -> io::Result<i32> {
    run_with_framing(input, output, true)
}

fn run_with_framing(
    input: &mut impl Read,
    output: &mut impl Write,
    line_framing: bool,
) -> io::Result<i32> {
    let mut agent = Agent {
        events: Vec::new(),
        next_event_id: 1,
        exit_code: 0,
        line_framing,
        network_configured: false,
        outage_active: false,
    };
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
}

impl Agent {
    fn command_loop(&mut self, input: &mut impl Read, output: &mut impl Write) -> io::Result<()> {
        loop {
            let frame = if self.line_framing {
                read_acknowledged_line_frame::<CommandFrame>(input, output)?
            } else {
                read_frame::<CommandFrame>(input)?
            };
            let Some(frame) = frame else { return Ok(()) };
            require_version(frame.protocol_version)?;
            let command_id = frame.command_id;
            match frame.command {
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
                Command::Shutdown {} => {
                    if self.outage_active {
                        return Err(invalid("cannot shut down while outage is active"));
                    }
                    self.emit(command_id, Event::AgentStopped {}, output)?;
                    return Ok(());
                }
            }
        }
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
            write_line_frame(output, &frame)?
        } else {
            write_frame(output, &frame)?
        }
        self.events.push(frame);
        Ok(())
    }
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
            "network configuration differs from the version-2 profile",
        ))
    }
}

fn require_peer(peer_cidr: &str) -> io::Result<()> {
    if peer_cidr == PEER_CIDR {
        Ok(())
    } else {
        Err(invalid("fault peer differs from the version-2 profile"))
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
}
