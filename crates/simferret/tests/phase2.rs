use std::io;
use std::process::{Command as ProcessCommand, Stdio};
use std::thread;

use simferret::protocol::{
    Command, CommandFrame, Event, EventFrame, PROTOCOL_VERSION, read_frame, write_frame,
};

#[test]
fn network_commands_are_rejected_before_configuration() {
    let result = run_commands([Command::ActivateOutage {
        peer_cidr: "10.0.2.2/32".into(),
    }]);
    assert!(!result.status.success());
    assert!(result.events.is_empty());
}

#[test]
fn check_reports_all_four_network_properties() {
    let result = run_commands([
        Command::Check {
            outage_event_bound: 1,
            liveness_event_bound: 2,
        },
        Command::Shutdown {},
    ]);
    assert_eq!(result.status.code(), Some(1));
    let report = match &result.events[0].event {
        Event::AssertionsEvaluated { report } => report,
        event => panic!("expected assertion report, got {event:?}"),
    };
    assert_eq!(report.assertions.len(), 4);
    assert!(!report.passed);
}

struct Result {
    status: std::process::ExitStatus,
    events: Vec<EventFrame>,
}

fn run_commands(commands: impl IntoIterator<Item = Command>) -> Result {
    let commands = commands.into_iter().collect::<Vec<_>>();
    let mut child = ProcessCommand::new(env!("CARGO_BIN_EXE_simferret"))
        .arg("guest-agent")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
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
    let mut events = Vec::new();
    while let Ok(Some(event)) = read_frame(&mut output) {
        events.push(event);
    }
    let _ = writer.join().unwrap();
    Result {
        status: child.wait().unwrap(),
        events,
    }
}
