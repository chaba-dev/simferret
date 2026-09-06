use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use crate::assertions::evaluate;
use crate::fixture;
use crate::protocol::{
    Command, CommandFrame, DiagnosticFields, Event, EventFrame, PROTOCOL_VERSION,
    read_acknowledged_line_frame, read_frame, require_version, write_frame, write_line_frame,
};

const START_TIMEOUT: Duration = Duration::from_secs(2);

pub fn run(input: &mut impl Read, output: &mut impl Write, executable: &Path) -> io::Result<i32> {
    run_with_framing(input, output, executable, false)
}

pub fn run_serial(
    input: &mut impl Read,
    output: &mut impl Write,
    executable: &Path,
) -> io::Result<i32> {
    run_with_framing(input, output, executable, true)
}

fn run_with_framing(
    input: &mut impl Read,
    output: &mut impl Write,
    executable: &Path,
    line_framing: bool,
) -> io::Result<i32> {
    let mut agent = Agent::new(executable, line_framing);
    let result = agent.command_loop(input, output);
    let stop_result = agent.stop_server();
    result.and(stop_result.map(|()| agent.exit_code))
}

struct Agent<'a> {
    executable: &'a Path,
    server: Option<Child>,
    configured_address: Option<String>,
    events: Vec<EventFrame>,
    next_event_id: u64,
    exit_code: i32,
    line_framing: bool,
}

impl<'a> Agent<'a> {
    fn new(executable: &'a Path, line_framing: bool) -> Self {
        Self {
            executable,
            server: None,
            configured_address: None,
            events: Vec::new(),
            next_event_id: 1,
            exit_code: 0,
            line_framing,
        }
    }

    fn command_loop(&mut self, input: &mut impl Read, output: &mut impl Write) -> io::Result<()> {
        loop {
            let frame = if self.line_framing {
                read_acknowledged_line_frame::<CommandFrame>(input, output)?
            } else {
                read_frame::<CommandFrame>(input)?
            };
            let Some(frame) = frame else {
                return Ok(());
            };
            require_version(frame.protocol_version)?;
            let command_id = frame.command_id;
            match frame.command {
                Command::StartServer {
                    address,
                    corrupt_responses,
                } => {
                    let address = self.start_server(&address, corrupt_responses)?;
                    self.emit(
                        command_id,
                        Event::ServerStarted {
                            address,
                            corrupt_responses,
                        },
                        output,
                    )?;
                }
                Command::StopServer {} => {
                    if self.server.is_none() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "server is not running",
                        ));
                    }
                    self.stop_server_controlled()?;
                    self.emit(command_id, Event::ServerStopped {}, output)?;
                }
                Command::Request {
                    request_id,
                    payload,
                    phase,
                } => {
                    validate_request(&request_id, &payload)?;
                    let address = self.configured_address.clone().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "server endpoint has not been configured",
                        )
                    })?;
                    self.emit(
                        command_id,
                        Event::RequestAttempted {
                            request_id: request_id.clone(),
                            payload: payload.clone(),
                            phase,
                        },
                        output,
                    )?;
                    let event = match fixture::request(&address, &request_id, &payload) {
                        Ok((response_id, response_payload)) => Event::RequestSucceeded {
                            request_id,
                            request_payload: payload,
                            response_id,
                            response_payload,
                            phase,
                        },
                        Err(_) => Event::RequestUnavailable { request_id, phase },
                    };
                    self.emit(command_id, event, output)?;
                }
                Command::Check {
                    outage_event_bound,
                    liveness_event_bound,
                } => {
                    self.require_server_healthy()?;
                    let report = evaluate(&self.events, outage_event_bound, liveness_event_bound);
                    self.exit_code = self.exit_code.max(report.exit_code());
                    self.emit(command_id, Event::AssertionsEvaluated { report }, output)?;
                }
                Command::Shutdown {} => {
                    self.stop_server()?;
                    self.emit(command_id, Event::AgentStopped {}, output)?;
                    return Ok(());
                }
            }
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

    fn start_server(&mut self, address: &str, corrupt_responses: bool) -> io::Result<String> {
        if self.server.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "server is already running",
            ));
        }
        let address: SocketAddr = address
            .parse()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if address.port() == 0 || !address.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fixture server address must be a numeric loopback address with a nonzero port",
            ));
        }
        let address = address.to_string();
        let mut child = ProcessCommand::new(self.executable)
            .arg("fixture-server")
            .arg(&address)
            .arg(if corrupt_responses { "corrupt" } else { "echo" })
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        let mut ready = child
            .stdout
            .take()
            .expect("child stdout was configured as piped");
        let (sender, receiver) = mpsc::channel();
        let reader = match thread::Builder::new()
            .name("fixture-readiness".into())
            .spawn(move || {
                let mut marker = vec![0; fixture::SERVER_READY.len()];
                let result = ready.read_exact(&mut marker).map(|()| marker);
                let _ = sender.send(result);
            }) {
            Ok(reader) => reader,
            Err(error) => {
                terminate(&mut child)?;
                return Err(error);
            }
        };
        let startup = match receiver.recv_timeout(START_TIMEOUT) {
            Ok(result) => result.and_then(|marker| {
                if marker == fixture::SERVER_READY {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "fixture server emitted an invalid readiness marker",
                    ))
                }
            }),
            Err(RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture server readiness timed out",
            )),
            Err(RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "fixture server readiness pipe disconnected",
            )),
        };
        if let Err(error) = startup {
            terminate(&mut child)?;
            reader
                .join()
                .map_err(|_| io::Error::other("readiness reader panicked"))?;
            return Err(error);
        }
        reader
            .join()
            .map_err(|_| io::Error::other("readiness reader panicked"))?;
        self.server = Some(child);
        self.configured_address = Some(address.clone());
        Ok(address)
    }

    fn stop_server(&mut self) -> io::Result<()> {
        if let Some(mut child) = self.server.take() {
            terminate(&mut child)?;
        }
        Ok(())
    }

    fn stop_server_controlled(&mut self) -> io::Result<()> {
        let mut child = self
            .server
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "server is not running"))?;
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!(
                "fixture server exited before controlled stop with {status}"
            )));
        }
        child.kill()?;
        let status = child.wait()?;
        if !is_controlled_kill(status) {
            Err(io::Error::other(format!(
                "fixture server exited before controlled stop with {status}"
            )))
        } else {
            Ok(())
        }
    }

    fn require_server_healthy(&mut self) -> io::Result<()> {
        let Some(child) = self.server.as_mut() else {
            return Ok(());
        };
        if let Some(status) = child.try_wait()? {
            self.server.take();
            Err(io::Error::other(format!(
                "fixture server exited unexpectedly with {status}"
            )))
        } else {
            Ok(())
        }
    }
}

fn terminate(child: &mut Child) -> io::Result<()> {
    if child.try_wait()?.is_none() {
        child.kill()?;
    }
    child.wait()?;
    Ok(())
}

#[cfg(unix)]
fn is_controlled_kill(status: std::process::ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt;

    status.signal() == Some(9)
}

#[cfg(not(unix))]
fn is_controlled_kill(status: std::process::ExitStatus) -> bool {
    !status.success()
}

fn validate_request(request_id: &str, payload: &str) -> io::Result<()> {
    if request_id.len().saturating_add(payload.len()) <= crate::protocol::MAX_REQUEST_DATA_LENGTH {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "request identifier and payload exceed the protocol limit",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command as ProcessCommand;

    use super::*;

    #[test]
    fn request_data_limit_is_inclusive() {
        let maximum = "x".repeat(crate::protocol::MAX_REQUEST_DATA_LENGTH - 2);
        assert!(validate_request("id", &maximum).is_ok());
        assert!(validate_request("id", &(maximum + "x")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn only_sigkill_is_a_controlled_kill_status() {
        let mut killed = ProcessCommand::new("sleep").arg("10").spawn().unwrap();
        killed.kill().unwrap();
        assert!(is_controlled_kill(killed.wait().unwrap()));

        let status = ProcessCommand::new("sh")
            .args(["-c", "kill -TERM $$"])
            .status()
            .unwrap();
        assert!(!is_controlled_kill(status));
    }

    #[test]
    fn controlled_stop_rejects_an_already_exited_child() {
        let mut child = ProcessCommand::new("sh")
            .args(["-c", "exit 23"])
            .spawn()
            .unwrap();
        while child.try_wait().unwrap().is_none() {
            thread::yield_now();
        }
        let mut agent = Agent::new(Path::new("unused"), false);
        agent.server = Some(child);
        assert!(agent.stop_server_controlled().is_err());
    }
}
