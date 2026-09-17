//! RFD 3 Phase 2 acceptance: the guest process runtime.
//!
//! The runtime changes the child root, drops to nonzero credentials, and
//! creates the overlay device nodes, so these tests require root. They skip
//! with an explicit diagnostic when the effective user is not root; the guest
//! path exercises the same code as PID 1 in the QEMU acceptance.
//!
//! The fixture is the pinned static busybox, copied into the template and
//! executed as the workload. It is ordinary Linux software with no SimFerret
//! library dependency, so the runtime supervises exactly what a packaged
//! workload would be.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use simferret::protocol::{Event, LaunchFailure, OutputStream, ProcessExit, encode_bytes};
use simferret::runtime::{MemberScope, Runtime, RuntimeConfig, RuntimeLimits};
use simferret::workload::LaunchIdentity;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "simferret-phase2-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn require_root() -> bool {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    eprintln!("skipping: the guest process runtime requires root to change root and credentials");
    false
}

fn busybox() -> Option<Vec<u8>> {
    let path = std::env::var_os("SIMFERRET_BUSYBOX")?;
    Some(fs::read(path).expect("the pinned static busybox must be readable"))
}

/// A template containing only the static fixture at `/bin/sh`.
fn template(label: &str) -> (TempDir, PathBuf) {
    let root = TempDir::new(label);
    let template = root.0.join("template");
    let bin = template.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let busybox = busybox().expect("SIMFERRET_BUSYBOX must be set for the runtime tests");
    let shell = bin.join("sh");
    fs::write(&shell, busybox).unwrap();
    fs::set_permissions(&shell, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&template, fs::Permissions::from_mode(0o755)).unwrap();
    // A second applet name so the escaped-descendant fixture can call `setsid`
    // without relying on busybox standalone applet lookup.
    std::os::unix::fs::symlink("sh", bin.join("setsid")).unwrap();
    fs::create_dir_all(template.join("tmp")).unwrap();
    fs::create_dir_all(template.join("dev")).unwrap();
    (root, shell)
}

fn runtime(root: &TempDir) -> Runtime {
    Runtime::new(RuntimeConfig {
        template_root: root.0.join("template"),
        runtime_root: root.0.join("runtime"),
        limits: RuntimeLimits::default(),
        scope: MemberScope::ProcessGroup,
    })
    .unwrap()
}

fn launch(script: &str) -> LaunchIdentity {
    LaunchIdentity {
        executable: "/bin/sh".into(),
        arguments: vec!["/bin/sh".into(), "-c".into(), script.into()],
        environment: vec!["PATH=/bin".into()],
        working_directory: "/".into(),
        uid: 65534,
        gid: 65534,
    }
}

fn poll_until_cleanup(runtime: &mut Runtime, events: &mut Vec<Event>) {
    for _ in 0..400 {
        events.extend(runtime.poll(Duration::from_millis(50)).unwrap());
        if events
            .iter()
            .any(|event| matches!(event, Event::CleanupComplete { .. }))
        {
            return;
        }
    }
    panic!("the runtime did not reach the cleanup barrier: {events:#?}");
}

fn run_script(runtime: &mut Runtime, invocation: u64, script: &str) -> Vec<Event> {
    let mut events = runtime.start(invocation, &launch(script));
    poll_until_cleanup(runtime, &mut events);
    events
}

fn stdout_bytes(events: &[Event]) -> Vec<u8> {
    let mut output = Vec::new();
    for event in events {
        if let Event::WorkloadOutput {
            stream: OutputStream::Stdout,
            bytes,
            ..
        } = event
        {
            output.extend_from_slice(&simferret::protocol::decode_bytes(bytes, 4096).unwrap());
        }
    }
    output
}

fn stream_summary(events: &[Event], stream: OutputStream) -> (u64, String) {
    events
        .iter()
        .find_map(|event| match event {
            Event::WorkloadExited {
                stdout_bytes,
                stdout_sha256,
                stderr_bytes,
                stderr_sha256,
                ..
            } => Some(match stream {
                OutputStream::Stdout => (*stdout_bytes, stdout_sha256.clone()),
                OutputStream::Stderr => (*stderr_bytes, stderr_sha256.clone()),
            }),
            _ => None,
        })
        .expect("the invocation must report an exit record")
}

#[test]
fn live_output_frames_carry_exact_bytes_offsets_and_sequence() {
    if !require_root() {
        return;
    }
    let (root, _) = template("output");
    let mut runtime = runtime(&root);
    let events = run_script(&mut runtime, 1, "printf 'first\\n'; printf 'err\\n' 1>&2");
    let stdout = stdout_bytes(&events);
    assert_eq!(stdout, b"first\n");
    let frames: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::WorkloadOutput {
                stream,
                offset,
                sequence,
                bytes,
                ..
            } => Some((*stream, *offset, *sequence, bytes.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(frames.len(), 2, "one frame per stream: {frames:#?}");
    assert_eq!(frames[0].0, OutputStream::Stdout);
    assert_eq!(frames[0].1, 0);
    assert_eq!(frames[0].2, 1);
    assert_eq!(frames[1].0, OutputStream::Stderr);
    assert_eq!(frames[1].1, 0);
    assert_eq!(frames[1].2, 2);
    assert_eq!(
        simferret::protocol::decode_bytes(&frames[1].3, 4096).unwrap(),
        b"err\n"
    );
    let (stdout_count, stdout_digest) = stream_summary(&events, OutputStream::Stdout);
    assert_eq!(stdout_count, 6);
    assert_eq!(stdout_digest, sha256_hex(b"first\n"));
    let (stderr_count, stderr_digest) = stream_summary(&events, OutputStream::Stderr);
    assert_eq!(stderr_count, 4);
    assert_eq!(stderr_digest, sha256_hex(b"err\n"));
    assert!(matches!(
        events.last(),
        Some(Event::CleanupComplete { reaped, .. }) if *reaped >= 1
    ));
}

#[test]
fn standard_input_round_trips_through_contiguous_offsets() {
    if !require_root() {
        return;
    }
    let (root, _) = template("stdin");
    let mut runtime = runtime(&root);
    let mut events = runtime.start(
        1,
        &launch("while IFS= read -r line; do printf 'got:%s\\n' \"$line\"; done"),
    );
    events.extend(
        runtime
            .stdin_write(1, 0, &encode_bytes(b"alpha\n"))
            .unwrap(),
    );
    events.extend(runtime.stdin_write(1, 6, &encode_bytes(b"beta\n")).unwrap());
    events.extend(runtime.stdin_eof(1).unwrap());
    poll_until_cleanup(&mut runtime, &mut events);
    assert_eq!(stdout_bytes(&events), b"got:alpha\ngot:beta\n");
    let accepted: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::InputAccepted {
                offset, bytes, eof, ..
            } => Some((*offset, *bytes, *eof)),
            _ => None,
        })
        .collect();
    assert_eq!(accepted, vec![(6, 6, false), (11, 5, false), (11, 0, true)]);
}

#[test]
fn a_non_contiguous_offset_kills_the_invocation_and_is_fatal() {
    if !require_root() {
        return;
    }
    let (root, _) = template("offset");
    let mut runtime = runtime(&root);
    runtime.start(1, &launch("read line"));
    let error = runtime.stdin_write(1, 7, &encode_bytes(b"x")).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    let mut events = Vec::new();
    poll_until_cleanup(&mut runtime, &mut events);
    assert!(matches!(
        events
            .iter()
            .find(|event| matches!(event, Event::WorkloadExited { .. })),
        Some(Event::WorkloadExited {
            exit: ProcessExit::Signaled { signal },
            ..
        }) if *signal == simferret::protocol::TERMINATION_SIGNAL
    ));
}

#[test]
fn terminate_kills_and_reaps_the_invocation() {
    if !require_root() {
        return;
    }
    let (root, _) = template("terminate");
    let mut runtime = runtime(&root);
    let mut events = runtime.start(1, &launch("read line"));
    events.extend(runtime.terminate(1).unwrap());
    assert!(events.iter().any(|event| matches!(
        event,
        Event::TerminationRequested { signal, .. }
            if *signal == simferret::protocol::TERMINATION_SIGNAL
    )));
    poll_until_cleanup(&mut runtime, &mut events);
    assert!(matches!(
        events
            .iter()
            .find(|event| matches!(event, Event::WorkloadExited { .. })),
        Some(Event::WorkloadExited {
            exit: ProcessExit::Signaled { signal },
            ..
        }) if *signal == simferret::protocol::TERMINATION_SIGNAL
    ));
}

#[test]
fn a_second_start_is_refused_while_an_invocation_is_active() {
    if !require_root() {
        return;
    }
    let (root, _) = template("active");
    let mut runtime = runtime(&root);
    let events = runtime.start(1, &launch("read line"));
    assert!(matches!(events[0], Event::WorkloadStarted { .. }));
    let second = runtime.start(2, &launch("read line"));
    assert!(matches!(
        second[0],
        Event::LaunchFailed {
            failure: LaunchFailure::InvocationActive,
            ..
        }
    ));
    let mut events = events;
    runtime.terminate(1).unwrap();
    poll_until_cleanup(&mut runtime, &mut events);
    let third = runtime.start(3, &launch("printf 'again\\n'"));
    assert!(matches!(third[0], Event::WorkloadStarted { .. }));
    let mut events = third;
    poll_until_cleanup(&mut runtime, &mut events);
    assert_eq!(stdout_bytes(&events), b"again\n");
}

#[test]
fn each_invocation_materializes_a_fresh_root() {
    if !require_root() {
        return;
    }
    let (root, _) = template("fresh");
    let mut runtime = runtime(&root);
    let first = run_script(&mut runtime, 1, ": > /tmp/marker; printf 'created\\n'");
    assert_eq!(stdout_bytes(&first), b"created\n");
    let second = run_script(
        &mut runtime,
        2,
        "if [ -e /tmp/marker ]; then printf 'stale\\n'; else printf 'fresh\\n'; fi",
    );
    assert_eq!(stdout_bytes(&second), b"fresh\n");
}

#[test]
fn the_runtime_overlay_is_visible_inside_the_workload_root() {
    if !require_root() {
        return;
    }
    let (root, _) = template("overlay");
    let mut runtime = runtime(&root);
    let events = run_script(
        &mut runtime,
        1,
        "if [ -c /dev/null ]; then printf 'null=char\\n'; else printf 'null=other\\n'; fi; \
         if [ -c /dev/zero ]; then printf 'zero=char\\n'; else printf 'zero=other\\n'; fi; \
         if [ -d /tmp ] && [ -k /tmp ] && [ -w /tmp ]; then printf 'tmp=sticky-writable\\n'; else printf 'tmp=wrong\\n'; fi",
    );
    assert_eq!(
        String::from_utf8_lossy(&stdout_bytes(&events)),
        "null=char\nzero=char\ntmp=sticky-writable\n"
    );
}

#[test]
fn a_descendant_retaining_the_output_pipe_is_killed_by_the_cleanup_barrier() {
    if !require_root() {
        return;
    }
    let (root, _) = template("descendant");
    let mut runtime = runtime(&root);
    // The background descendant inherits the output pipes. The primary shell
    // exits immediately, so the barrier can only complete after the descendant
    // is killed and the pipes reach end of file.
    let events = run_script(&mut runtime, 1, "sleep 30 & printf 'spawned\\n'");
    assert_eq!(stdout_bytes(&events), b"spawned\n");
    assert!(matches!(events.last(), Some(Event::CleanupComplete { .. })));
}

#[test]
fn an_escaped_descendant_cannot_outlive_the_cleanup_barrier() {
    if !require_root() {
        return;
    }
    // The guest-wide barrier signals every process in the process table, so it
    // may run only where the agent owns that table. The script runs the test
    // binary as PID 1 in a fresh PID namespace.
    if std::process::id() != 1 {
        eprintln!(
            "skipping: the guest-wide cleanup barrier requires a PID namespace (run scripts/rfd3-phase2-runtime.sh)"
        );
        return;
    }
    let (root, _) = template("escaped");
    let mut runtime = Runtime::new(RuntimeConfig {
        template_root: root.0.join("template"),
        runtime_root: root.0.join("runtime"),
        limits: RuntimeLimits::default(),
        scope: MemberScope::Guest,
    })
    .unwrap();
    // The descendant calls setsid, so it escapes the invocation's process
    // group, and it retains the inherited standard output pipe. The barrier can
    // only complete once the guest-wide sweep kills it.
    let events = run_script(&mut runtime, 1, "(setsid sleep 30 &) ; printf 'escaped\\n'");
    assert_eq!(stdout_bytes(&events), b"escaped\n");
    assert!(matches!(events.last(), Some(Event::CleanupComplete { .. })));
}

#[test]
fn a_missing_executable_is_a_typed_launch_failure() {
    if !require_root() {
        return;
    }
    let (root, _) = template("missing");
    let mut runtime = runtime(&root);
    let mut launch = launch("printf 'unused\\n'");
    launch.executable = "/bin/missing".into();
    launch.arguments = vec!["/bin/missing".into()];
    let events = runtime.start(1, &launch);
    assert!(matches!(
        events[0],
        Event::LaunchFailed {
            failure: LaunchFailure::Executable,
            ..
        }
    ));
    assert!(!runtime.is_active());
}

#[test]
fn an_overlay_collision_is_rejected_before_any_invocation() {
    if !require_root() {
        return;
    }
    let (root, _) = template("collision");
    let template_root = root.0.join("template");
    fs::remove_dir(template_root.join("tmp")).unwrap();
    fs::write(template_root.join("tmp"), b"collision").unwrap();
    let error = Runtime::new(RuntimeConfig {
        template_root: root.0.join("template"),
        runtime_root: root.0.join("runtime"),
        limits: RuntimeLimits::default(),
        scope: MemberScope::ProcessGroup,
    })
    .err()
    .expect("an overlay collision must be rejected");
    assert!(error.to_string().contains("collides"), "{error}");
    assert!(!root.0.join("runtime").exists());
}

#[test]
fn the_agent_drives_the_runtime_over_the_serial_control_channel() {
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;

    use simferret::protocol::{
        Command, CommandFrame, PROTOCOL_VERSION, SERIAL_ACK, write_line_frame,
    };

    if !require_root() {
        return;
    }
    let (root, _) = template("agent");
    let runtime = runtime(&root);

    let (command_read, command_write) = pipe();
    let (event_read, event_write) = pipe();
    let mut input = unsafe { fs::File::from_raw_fd(command_read) };
    let mut output = unsafe { fs::File::from_raw_fd(event_write) };
    let agent = std::thread::spawn(move || {
        simferret::agent::run_serial_with_runtime(&mut input, &mut output, Some(runtime))
    });

    let mut commands = unsafe { fs::File::from_raw_fd(command_write) };
    let mut command_id = 0_u64;
    let mut send = |commands: &mut fs::File, command: Command| {
        command_id += 1;
        write_line_frame(
            commands,
            &CommandFrame {
                protocol_version: PROTOCOL_VERSION,
                command_id,
                command,
            },
        )
        .unwrap();
        commands.flush().unwrap();
        command_id
    };
    let start_id = send(
        &mut commands,
        Command::Start {
            invocation: 1,
            launch: launch("while IFS= read -r line; do printf 'got:%s\\n' \"$line\"; done"),
        },
    );
    std::thread::sleep(Duration::from_millis(300));
    let write_id = send(
        &mut commands,
        Command::StdinWrite {
            invocation: 1,
            offset: 0,
            bytes: encode_bytes(b"live\n"),
        },
    );
    std::thread::sleep(Duration::from_millis(300));
    let eof_id = send(&mut commands, Command::StdinEof { invocation: 1 });
    std::thread::sleep(Duration::from_millis(300));
    let shutdown_id = send(&mut commands, Command::Shutdown {});
    drop(commands);

    let status = agent.join().unwrap().unwrap();
    assert_eq!(status, 0);
    let mut bytes = Vec::new();
    unsafe { fs::File::from_raw_fd(event_read) }
        .read_to_end(&mut bytes)
        .unwrap();
    let events = decode_serial_events(&bytes);
    assert!(
        events.iter().any(|frame| matches!(
            &frame.event,
            simferret::protocol::Event::WorkloadStarted { .. }
        ) && frame.command_id == start_id),
        "{events:#?}"
    );
    assert!(events.iter().any(|frame| matches!(
        &frame.event,
        simferret::protocol::Event::InputAccepted { eof: false, .. }
    ) && frame.command_id == write_id));
    // Live output is attributed to the command that was being handled while the
    // workload ran, not to the later shutdown command.
    let output_frame = events
        .iter()
        .find(|frame| {
            matches!(
                &frame.event,
                simferret::protocol::Event::WorkloadOutput {
                    stream: OutputStream::Stdout,
                    ..
                }
            )
        })
        .expect("a live output frame must be emitted");
    assert!(output_frame.command_id <= eof_id, "{events:#?}");
    assert_eq!(
        decode_output(&events),
        b"got:live\n",
        "output must be exact"
    );
    assert!(events.iter().any(|frame| matches!(
        &frame.event,
        simferret::protocol::Event::CleanupComplete { .. }
    )));
    assert!(events.iter().any(|frame| matches!(
        &frame.event,
        simferret::protocol::Event::AgentStopped {}
    ) && frame.command_id == shutdown_id));
    // Every command byte was acknowledged.
    assert!(bytes.contains(&SERIAL_ACK));
}

fn pipe() -> (i32, i32) {
    let mut descriptors = [0_i32; 2];
    // SAFETY: `descriptors` is a writable two-element array.
    assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
    (descriptors[0], descriptors[1])
}

fn decode_serial_events(bytes: &[u8]) -> Vec<simferret::protocol::EventFrame> {
    let mut events = Vec::new();
    let mut body = Vec::new();
    for byte in bytes {
        if *byte == simferret::protocol::SERIAL_ACK {
            continue;
        }
        if *byte == b'\n' {
            if !body.is_empty() {
                events.push(serde_json::from_slice(&body).unwrap());
                body.clear();
            }
            continue;
        }
        body.push(*byte);
    }
    events
}

fn decode_output(events: &[simferret::protocol::EventFrame]) -> Vec<u8> {
    let mut output = Vec::new();
    for frame in events {
        if let simferret::protocol::Event::WorkloadOutput {
            stream: OutputStream::Stdout,
            bytes,
            ..
        } = &frame.event
        {
            output.extend_from_slice(&simferret::protocol::decode_bytes(bytes, 4096).unwrap());
        }
    }
    output
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(data) {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}
