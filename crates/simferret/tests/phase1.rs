use std::io::{self, Read};
use std::net::TcpListener;
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::Value;

use simferret::protocol::{
    Command, CommandFrame, Event, EventFrame, PROTOCOL_VERSION, RequestPhase, read_frame,
    write_frame,
};

#[test]
fn guest_agent_runs_restart_scenario_and_reports_all_properties() {
    let result = run_scenario(false);
    assert!(result.status.success(), "stderr: {}", result.stderr);
    let report = result.events.iter().find_map(|frame| match &frame.event {
        Event::AssertionsEvaluated { report } => Some(report),
        _ => None,
    });
    assert!(report.unwrap().passed);
    assert!(result.events.iter().any(|frame| matches!(
        frame.event,
        Event::RequestUnavailable {
            phase: RequestPhase::Stopped,
            ..
        }
    )));
}

#[test]
fn intentional_corruption_propagates_to_nonzero_agent_result() {
    let result = run_scenario(true);
    assert_eq!(result.status.code(), Some(1), "stderr: {}", result.stderr);
    let report = result.events.iter().find_map(|frame| match &frame.event {
        Event::AssertionsEvaluated { report } => Some(report),
        _ => None,
    });
    let report = report.unwrap();
    assert!(!report.passed);
    assert!(!report.assertions[0].passed);
}

#[test]
fn stopped_phase_request_still_contacts_the_configured_endpoint() {
    let address = unused_address();
    let listener_address = address.clone();
    let mut agent = AgentProcess::spawn();
    agent.send(
        1,
        Command::StartServer {
            address: address.clone(),
            corrupt_responses: false,
        },
    );
    assert!(matches!(agent.read().event, Event::ServerStarted { .. }));
    agent.send(2, Command::StopServer {});
    assert!(matches!(agent.read().event, Event::ServerStopped {}));

    let listener = TcpListener::bind(listener_address).unwrap();
    listener.set_nonblocking(true).unwrap();
    let responder = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request: Value = read_frame(&mut stream).unwrap().unwrap();
                    write_frame(&mut stream, &request).unwrap();
                    return true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("listener failed: {error}"),
            }
        }
    });
    agent.send(
        3,
        Command::Request {
            request_id: "outage".into(),
            payload: "probe".into(),
            phase: RequestPhase::Stopped,
        },
    );
    assert!(matches!(agent.read().event, Event::RequestAttempted { .. }));
    assert!(matches!(agent.read().event, Event::RequestSucceeded { .. }));
    assert!(responder.join().unwrap(), "workload client was not invoked");

    agent.send(
        4,
        Command::Check {
            outage_event_bound: 1,
            liveness_event_bound: 1,
        },
    );
    let report = match agent.read().event {
        Event::AssertionsEvaluated { report } => report,
        event => panic!("expected assertion report, got {event:?}"),
    };
    assert!(!report.assertions[1].passed);
    agent.shutdown(5);
}

#[test]
fn occupied_server_address_does_not_produce_started_event() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let commands = [Command::StartServer {
        address: listener.local_addr().unwrap().to_string(),
        corrupt_responses: false,
    }];
    let result = run_commands(commands);
    assert!(!result.status.success());
    assert!(
        !result
            .events
            .iter()
            .any(|frame| matches!(frame.event, Event::ServerStarted { .. }))
    );
}

#[test]
fn unusable_server_addresses_are_rejected_before_started_event() {
    let port = unused_address().rsplit_once(':').unwrap().1.to_owned();
    for address in ["127.0.0.1:0".to_owned(), format!("localhost:{port}")] {
        let result = run_commands([Command::StartServer {
            address,
            corrupt_responses: false,
        }]);
        assert!(!result.status.success());
        assert!(
            !result
                .events
                .iter()
                .any(|frame| matches!(frame.event, Event::ServerStarted { .. }))
        );
    }
}

#[test]
fn terminating_agent_also_stops_fixture_child() {
    let address = unused_address();
    let mut agent = AgentProcess::spawn();
    agent.send(
        1,
        Command::StartServer {
            address: address.clone(),
            corrupt_responses: false,
        },
    );
    assert!(matches!(agent.read().event, Event::ServerStarted { .. }));
    drop(agent);

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match TcpListener::bind(&address) {
            Ok(_) => break,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Err(error) => panic!("fixture child survived its agent: {error}"),
        }
    }
}

#[test]
fn oversized_logical_request_is_rejected_before_attempt() {
    let address = unused_address();
    let commands = [
        Command::StartServer {
            address,
            corrupt_responses: false,
        },
        Command::Request {
            request_id: "large".into(),
            payload: "x".repeat(simferret::protocol::MAX_REQUEST_DATA_LENGTH - 4),
            phase: RequestPhase::Running,
        },
    ];
    let result = run_commands(commands);
    assert!(!result.status.success());
    assert!(
        !result
            .events
            .iter()
            .any(|frame| matches!(frame.event, Event::RequestAttempted { .. }))
    );
}

struct ScenarioResult {
    status: std::process::ExitStatus,
    events: Vec<EventFrame>,
    stderr: String,
}

fn run_scenario(corrupt_first_response: bool) -> ScenarioResult {
    let address = unused_address();
    let commands = [
        Command::StartServer {
            address: address.clone(),
            corrupt_responses: corrupt_first_response,
        },
        Command::Request {
            request_id: "initial".into(),
            payload: "hello".into(),
            phase: RequestPhase::Running,
        },
        Command::StopServer {},
        Command::Request {
            request_id: "outage".into(),
            payload: "during-stop".into(),
            phase: RequestPhase::Stopped,
        },
        Command::StartServer {
            address,
            corrupt_responses: false,
        },
        Command::Request {
            request_id: "recovered".into(),
            payload: "after-restart".into(),
            phase: RequestPhase::Restarted,
        },
        Command::Check {
            outage_event_bound: 1,
            liveness_event_bound: 2,
        },
        Command::Shutdown {},
    ];
    run_commands(commands)
}

fn run_commands(commands: impl IntoIterator<Item = Command>) -> ScenarioResult {
    let mut child = ProcessCommand::new(env!("CARGO_BIN_EXE_simferret"))
        .arg("guest-agent")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let mut errors = child.stderr.take().unwrap();
    let commands: Vec<_> = commands.into_iter().collect();
    let writer = thread::spawn(move || -> io::Result<()> {
        for (index, command) in commands.into_iter().enumerate() {
            write_frame(
                &mut input,
                &CommandFrame {
                    protocol_version: PROTOCOL_VERSION,
                    command_id: index as u64 + 1,
                    command,
                },
            )?;
        }
        Ok(())
    });
    let output_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        output.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let error_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        errors.read_to_end(&mut bytes).unwrap();
        bytes
    });

    let outcome = wait_for_exit(&mut child);
    let write_result = writer.join().unwrap();
    let output = output_reader.join().unwrap();
    let errors = error_reader.join().unwrap();
    assert!(!outcome.timed_out, "timed out waiting for guest agent");
    if outcome.status.success() {
        write_result.unwrap();
    }
    let mut bytes = output.as_slice();
    let mut events = Vec::new();
    while let Some(event) = read_frame(&mut bytes).unwrap() {
        events.push(event);
    }
    ScenarioResult {
        status: outcome.status,
        events,
        stderr: String::from_utf8(errors).unwrap(),
    }
}

struct AgentProcess {
    child: std::process::Child,
    events: Receiver<io::Result<Option<EventFrame>>>,
    reader: Option<JoinHandle<()>>,
}

impl AgentProcess {
    fn spawn() -> Self {
        let mut child = ProcessCommand::new(env!("CARGO_BIN_EXE_simferret"))
            .arg("guest-agent")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut output = child.stdout.take().unwrap();
        let (sender, events) = mpsc::channel();
        let reader = thread::spawn(move || {
            loop {
                let event = read_frame(&mut output);
                let finished = !matches!(event, Ok(Some(_)));
                if sender.send(event).is_err() || finished {
                    break;
                }
            }
        });
        Self {
            child,
            events,
            reader: Some(reader),
        }
    }

    fn send(&mut self, command_id: u64, command: Command) {
        write_frame(
            self.child.stdin.as_mut().unwrap(),
            &CommandFrame {
                protocol_version: PROTOCOL_VERSION,
                command_id,
                command,
            },
        )
        .unwrap();
    }

    fn read(&mut self) -> EventFrame {
        match self.events.recv_timeout(Duration::from_secs(3)) {
            Ok(Ok(Some(event))) => event,
            Ok(Ok(None)) => panic!("agent event stream ended unexpectedly"),
            Ok(Err(error)) => panic!("agent event stream failed: {error}"),
            Err(RecvTimeoutError::Timeout) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("timed out waiting for agent event")
            }
            Err(RecvTimeoutError::Disconnected) => panic!("agent event reader disconnected"),
        }
    }

    fn shutdown(mut self, command_id: u64) {
        self.send(command_id, Command::Shutdown {});
        assert!(matches!(self.read().event, Event::AgentStopped {}));
        drop(self.child.stdin.take());
        let outcome = wait_for_exit(&mut self.child);
        self.reader.take().unwrap().join().unwrap();
        assert!(!outcome.timed_out, "timed out waiting for guest agent");
        assert_eq!(outcome.status.code(), Some(1));
    }
}

impl Drop for AgentProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

struct WaitOutcome {
    status: std::process::ExitStatus,
    timed_out: bool,
}

fn wait_for_exit(child: &mut std::process::Child) -> WaitOutcome {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return WaitOutcome {
                status,
                timed_out: false,
            };
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            return WaitOutcome {
                status: child.wait().unwrap(),
                timed_out: true,
            };
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn unused_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    drop(listener);
    address
}
