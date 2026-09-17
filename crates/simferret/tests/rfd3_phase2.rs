// The guest process runtime is Linux-only, so this whole target is compiled
// only there. The checked-in script runs it as PID 1 in a fresh PID namespace.
#![cfg(target_os = "linux")]

//! RFD 3 Phase 2 acceptance: the guest process runtime.
//!
//! The runtime changes the child root, drops to nonzero credentials, and
//! creates the overlay device nodes, so these tests require root. They skip
//! with an explicit diagnostic when the effective user is not root.
//!
//! The checked-in acceptance path is `scripts/rfd3-phase2-runtime.sh`, which
//! runs this binary as PID 1 in a fresh PID namespace. The guest-wide cleanup
//! barrier signals the whole process table, so it is only meaningful where the
//! agent owns that table; the namespace gives it one without reaching the host.
//! The same binary is what the guest image carries, but a recorded QEMU
//! acceptance of the phase 2 runtime is Phase 3 work and is not claimed here.
//!
//! The fixture is the pinned static busybox, copied into the template and
//! executed as the workload. It is ordinary Linux software with no SimFerret
//! library dependency, so the runtime supervises exactly what a packaged
//! workload would be.

use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
        // A previous run in the same PID namespace can leave this path behind.
        let _ = fs::remove_dir_all(&path);
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
    // The descendant fixtures block in `sleep`, which is an applet as well: a
    // missing applet would make them exit immediately and pass vacuously.
    std::os::unix::fs::symlink("sh", bin.join("sleep")).unwrap();
    // The removal fixtures build a deep directory tree to exhaust the
    // descriptor budget that recursive removal needs.
    std::os::unix::fs::symlink("sh", bin.join("mkdir")).unwrap();
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

fn exit_record(events: &[Event]) -> ProcessExit {
    events
        .iter()
        .find_map(|event| match event {
            Event::WorkloadExited { exit, .. } => Some(*exit),
            _ => None,
        })
        .expect("the invocation must report an exit record")
}

/// Raise the descriptor limit so a descriptor can be allocated above the scan
/// cap the runtime used to stop at, and return the previous soft limit.
fn raise_descriptor_limit(target: u64) -> Option<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is writable and the call has no other effects.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return None;
    }
    let previous = limit.rlim_cur;
    if limit.rlim_cur < target {
        let next = libc::rlimit {
            rlim_cur: target,
            rlim_max: limit.rlim_max.max(target),
        };
        // SAFETY: `next` is a valid limit the caller is allowed to set.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &next) } != 0 {
            return None;
        }
    }
    Some(previous)
}

/// Lower the descriptor limit for the duration of a test and restore it on drop.
struct DescriptorLimit(u64);

impl DescriptorLimit {
    fn lower_to(target: u64) -> Option<Self> {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is writable and the call has no other effects.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
            return None;
        }
        let previous = limit.rlim_cur;
        if previous <= target {
            return None;
        }
        let next = libc::rlimit {
            rlim_cur: target,
            rlim_max: limit.rlim_max,
        };
        // SAFETY: `next` is a valid limit the caller is allowed to set.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &next) } != 0 {
            return None;
        }
        Some(Self(previous))
    }
}

impl Drop for DescriptorLimit {
    fn drop(&mut self) {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is writable and the call has no other effects.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
            return;
        }
        limit.rlim_cur = self.0;
        // SAFETY: `limit` keeps the current hard limit and only raises the soft one.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
    }
}

fn restore_descriptor_limit(previous: u64) {
    let mut limit = libc::rlimit {
        rlim_cur: previous,
        rlim_max: 0,
    };
    // SAFETY: `limit` is writable and the call has no other effects.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return;
    }
    limit.rlim_cur = previous;
    // SAFETY: `limit` keeps the current hard limit and only lowers the soft one.
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
}

#[test]
fn output_frames_are_contiguous_per_stream_and_sequenced() {
    if !require_root() {
        return;
    }
    let (root, _) = template("output");
    let mut runtime = runtime(&root);
    let events = run_script(&mut runtime, 1, "printf 'first\\n'; printf 'err\\n' 1>&2");
    assert_eq!(stdout_bytes(&events), b"first\n");

    // The contract is per stream, not per frame: offsets start at zero and are
    // contiguous within a stream, sequence numbers are contiguous across the
    // whole series of frames, and the concatenated bytes are exact. How the
    // bytes are split into frames is not part of the contract.
    let mut stdout_offset = 0_u64;
    let mut stderr_offset = 0_u64;
    let mut sequences = Vec::new();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    for event in &events {
        let Event::WorkloadOutput {
            stream,
            offset,
            sequence,
            bytes,
            ..
        } = event
        else {
            continue;
        };
        let decoded = simferret::protocol::decode_bytes(bytes, 4096).unwrap();
        match stream {
            OutputStream::Stdout => {
                assert_eq!(
                    *offset, stdout_offset,
                    "offsets must be contiguous per stream"
                );
                stdout_offset += decoded.len() as u64;
                stdout.extend_from_slice(&decoded);
            }
            OutputStream::Stderr => {
                assert_eq!(
                    *offset, stderr_offset,
                    "offsets must be contiguous per stream"
                );
                stderr_offset += decoded.len() as u64;
                stderr.extend_from_slice(&decoded);
            }
        }
        sequences.push(*sequence);
    }
    assert_eq!(
        sequences,
        (1..=sequences.len() as u64).collect::<Vec<_>>(),
        "sequence numbers must be contiguous and start at one"
    );
    assert_eq!(stdout, b"first\n");
    assert_eq!(stderr, b"err\n");

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
fn a_package_directory_below_the_overlay_does_not_block_the_launch() {
    if !require_root() {
        return;
    }
    let (root, _) = template("overlay-descendant");
    let template_root = root.0.join("template");
    // An empty directory tree below an overlay path is legal, but the overlay
    // replaces the subtree instead of merging with it.
    fs::create_dir_all(template_root.join("tmp/nested")).unwrap();
    // A directory named `/dev/null` is legal input, and it must not make the
    // overlay fail when it installs the character device.
    fs::create_dir_all(template_root.join("dev/null")).unwrap();
    let mut runtime = runtime(&root);
    let events = run_script(
        &mut runtime,
        1,
        "if [ -c /dev/null ]; then printf 'null=char\\n'; else printf 'null=other\\n'; fi; \
         if [ -d /tmp/nested ]; then printf 'nested=kept\\n'; else printf 'nested=replaced\\n'; fi",
    );
    assert_eq!(
        String::from_utf8_lossy(&stdout_bytes(&events)),
        "null=char\nnested=replaced\n"
    );
    assert!(matches!(events.last(), Some(Event::CleanupComplete { .. })));
}

/// OCI normalization canonicalizes the executable while preserving the caller's
/// argument vector, so the runtime must accept a first argument that differs
/// from the executed path.
#[test]
fn an_oci_normalized_launch_identity_runs() {
    if !require_root() {
        return;
    }
    let (root, _) = template("oci-normalized");
    let mut runtime = runtime(&root);
    let mut identity = launch("printf 'normalized\\n'");
    identity.executable = "/bin/sh".into();
    identity.arguments = vec![
        "/bin/./sh".into(),
        "-c".into(),
        "printf 'normalized\\n'".into(),
    ];
    let mut events = runtime.start(1, &identity);
    poll_until_cleanup(&mut runtime, &mut events);
    assert_eq!(stdout_bytes(&events), b"normalized\n");
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
    // The descendant calls `setsid`, so it escapes the invocation's process
    // group, and it retains the inherited standard output pipe. The barrier can
    // only complete once the guest-wide sweep kills it.
    //
    // The descendant publishes its own identifier after `setsid`, and the test
    // confirms from the host that the descendant really became its own process
    // group leader before it terminates the primary. Without that handshake the
    // test would pass even if `setsid` had failed, because the group sweep would
    // have killed the descendant anyway.
    let mut events = runtime.start(
        1,
        &launch("(setsid sh -c 'printf %s $$ > /tmp/descendant.pid; sleep 30' &) ; printf 'escaped\\n'; sleep 30"),
    );
    let published = root.0.join("runtime/invocation-1/tmp/descendant.pid");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let descendant = loop {
        events.extend(runtime.poll(Duration::from_millis(20)).unwrap());
        if let Ok(contents) = fs::read_to_string(&published)
            && let Ok(pid) = contents.trim().parse::<libc::pid_t>()
        {
            break pid;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the escaped descendant never published its identifier: {:?} {:?}",
            fs::read_dir(root.0.join("runtime/invocation-1")).map(|entries| entries
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>()),
            fs::read_dir(root.0.join("runtime/invocation-1/tmp")).map(|entries| entries
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>())
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let stat = fs::read_to_string(format!("/proc/{descendant}/stat"))
        .expect("the escaped descendant must be visible in the process table");
    let fields: Vec<&str> = stat
        .rsplit_once(')')
        .expect("a stat line has a command terminator")
        .1
        .split_whitespace()
        .collect();
    // Fields after the command name start at the state, so the process group is
    // at index 2 and the session at index 3.
    assert_eq!(
        fields[2].parse::<libc::pid_t>().unwrap(),
        descendant,
        "the descendant must lead its own process group: {stat}"
    );
    assert_eq!(
        fields[3].parse::<libc::pid_t>().unwrap(),
        descendant,
        "the descendant must lead its own session: {stat}"
    );

    events.extend(runtime.terminate(1).unwrap());
    poll_until_cleanup(&mut runtime, &mut events);
    assert_eq!(stdout_bytes(&events), b"escaped\n");
    assert!(matches!(events.last(), Some(Event::CleanupComplete { .. })));
    assert!(
        !std::path::Path::new(&format!("/proc/{descendant}")).exists(),
        "the escaped descendant must not outlive the cleanup barrier"
    );
}

#[test]
fn an_invocation_does_not_steal_an_unrelated_child() {
    if !require_root() {
        return;
    }
    // A host test shares the agent's process table, so an unrelated child is a
    // zombie by the time the invocation runs. A reap of the whole table would
    // consume it, and this test would no longer be able to observe its status.
    let mut unrelated = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("exit 7")
        .spawn()
        .expect("the unrelated child must spawn");
    // `waitid` with `WNOWAIT` blocks until the child has exited and leaves the
    // status unconsumed, so the test cannot race a sleep and the zombie is
    // guaranteed to exist before the invocation starts.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        // SAFETY: `info` is writable and `pid` is the live child.
        unsafe {
            libc::waitid(
                libc::P_PID,
                unrelated.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        },
        0,
        "waitid must report the unrelated child's exit"
    );
    // SAFETY: `info` was filled by the successful `waitid` above.
    assert_eq!(unsafe { info.si_pid() }, unrelated.id() as libc::pid_t);

    let (root, _) = template("scoped-reap");
    let mut runtime = runtime(&root);
    let events = run_script(&mut runtime, 1, "printf 'done\\n'");
    assert_eq!(stdout_bytes(&events), b"done\n");
    assert!(matches!(events.last(), Some(Event::CleanupComplete { .. })));

    let status = unrelated
        .wait()
        .expect("the invocation must not reap an unrelated child");
    assert_eq!(status.code(), Some(7));
}

#[test]
fn an_inherited_descriptor_above_the_scan_cap_does_not_leak() {
    if !require_root() {
        return;
    }
    const HIGH: i32 = 70_000;
    let Some(previous) = raise_descriptor_limit(HIGH as u64 + 1) else {
        eprintln!("skipping: cannot raise the descriptor limit");
        return;
    };
    let (root, _) = template("descriptor-leak");
    // The descriptor must be writable, or the probe would fail for the wrong
    // reason. `F_DUPFD` deliberately does not set close-on-exec, so the
    // descriptor is inherited by every child that does not close it.
    let scratch = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(root.0.join("scratch"))
        .unwrap();
    let high = unsafe { libc::fcntl(scratch.as_raw_fd(), libc::F_DUPFD, HIGH) };
    if high < 0 {
        restore_descriptor_limit(previous);
        eprintln!("skipping: cannot allocate a descriptor above the scan cap");
        return;
    }

    let mut runtime = runtime(&root);
    let identity = launch(&format!(
        "if printf 'leak' >&{HIGH} 2>/dev/null; then printf 'leaked\\n'; else printf 'closed\\n'; fi"
    ));
    let mut events = runtime.start(1, &identity);
    poll_until_cleanup(&mut runtime, &mut events);

    // SAFETY: the descriptor was just created and is owned by this test.
    unsafe { libc::close(high) };
    restore_descriptor_limit(previous);

    assert_eq!(stdout_bytes(&events), b"closed\n");
}

/// The child's standard input pipe only lands on descriptor 0 when the agent's
/// own descriptor 0 is closed. `dup2(0, 0)` is a no-op that does not clear
/// close-on-exec, so the descriptor must be made inheritable explicitly.
#[test]
fn a_standard_pipe_that_lands_on_descriptor_zero_survives_exec() {
    if !require_root() {
        return;
    }
    // SAFETY: `dup` and `close` operate on the live standard input descriptor.
    let saved = unsafe { libc::dup(libc::STDIN_FILENO) };
    if saved < 0 {
        eprintln!("skipping: the test process has no standard input to save");
        return;
    }

    struct Restore(i32);

    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: the descriptor was saved by `dup` above.
            unsafe {
                libc::dup2(self.0, libc::STDIN_FILENO);
                libc::close(self.0);
            }
        }
    }

    let _restore = Restore(saved);
    // SAFETY: descriptor 0 is saved and restored by the guard above.
    unsafe { libc::close(libc::STDIN_FILENO) };

    let (root, _) = template("descriptor-zero");
    let mut runtime = runtime(&root);
    let mut events = runtime.start(
        1,
        &launch("IFS= read -r line; printf 'got:%s\\n' \"$line\""),
    );
    events.extend(
        runtime
            .stdin_write(1, 0, &encode_bytes(b"alpha\n"))
            .unwrap(),
    );
    events.extend(runtime.stdin_eof(1).unwrap());
    poll_until_cleanup(&mut runtime, &mut events);
    assert_eq!(stdout_bytes(&events), b"got:alpha\n");
}

/// Rust ignores `SIGPIPE` process-wide, and an ignored disposition survives
/// `execve`, so the workload must be given the default disposition back.
#[test]
fn the_workload_starts_with_the_default_sigpipe_disposition() {
    if !require_root() {
        return;
    }
    let (root, _) = template("sigpipe");
    let mut runtime = runtime(&root);
    // An ignored `SIGPIPE` lets the shell survive its own signal and print;
    // the default disposition kills it.
    let events = run_script(&mut runtime, 1, "kill -PIPE $$; printf 'alive\\n'");
    assert!(
        stdout_bytes(&events).is_empty(),
        "the workload kept an inherited SIGPIPE disposition: {events:#?}"
    );
    assert_eq!(
        exit_record(&events),
        ProcessExit::Signaled {
            signal: libc::SIGPIPE
        }
    );
}

#[test]
fn terminating_an_invocation_with_queued_input_is_not_an_infrastructure_error() {
    if !require_root() {
        return;
    }
    let (root, _) = template("terminate-queued-input");
    let mut runtime = runtime(&root);
    // The workload never reads its standard input, so the pipe fills and the
    // remainder stays in the bounded queue.
    let mut events = runtime.start(1, &launch("sleep 30"));
    let chunk = vec![b'x'; 4096];
    let mut offset = 0_u64;
    let mut queued = 0_usize;
    for _ in 0..32 {
        match runtime.stdin_write(1, offset, &encode_bytes(&chunk)) {
            Ok(accepted) => {
                events.extend(accepted);
                offset += chunk.len() as u64;
                queued += chunk.len();
            }
            Err(_) => break,
        }
    }
    assert!(queued > 64 * 1024, "the queue must hold more than the pipe");

    events.extend(runtime.terminate(1).unwrap());
    // Wait until the killed readers are gone, so the queued input has nowhere
    // to go. A poll that flushed it first would report a broken pipe as an
    // infrastructure failure instead of the requested termination.
    std::thread::sleep(Duration::from_millis(300));
    poll_until_cleanup(&mut runtime, &mut events);
    assert!(matches!(events.last(), Some(Event::CleanupComplete { .. })));
    assert!(
        events.iter().any(|event| matches!(
            event,
            Event::WorkloadExited {
                exit: ProcessExit::Signaled { .. },
                ..
            }
        )),
        "{events:#?}"
    );
}

#[test]
fn a_continuously_ready_stream_does_not_starve_the_other() {
    if !require_root() {
        return;
    }
    let (root, _) = template("fairness");
    let mut runtime = runtime(&root);
    // The filler keeps standard output continuously readable, so a batch that
    // serves one stream to exhaustion would never reach the other.
    let filler = "x".repeat(1024);
    let mut events = runtime.start(
        1,
        &launch(&format!(
            "printf 'err\\n' 1>&2; while :; do printf '%s' '{filler}'; done"
        )),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut stderr_seen = false;
    while !stderr_seen && std::time::Instant::now() < deadline {
        events.extend(runtime.poll(Duration::from_millis(20)).unwrap());
        stderr_seen = events.iter().any(|event| {
            matches!(
                event,
                Event::WorkloadOutput {
                    stream: OutputStream::Stderr,
                    ..
                }
            )
        });
    }
    assert!(
        stderr_seen,
        "standard error was starved by a continuously ready standard output"
    );
    events.extend(runtime.terminate(1).unwrap());
    poll_until_cleanup(&mut runtime, &mut events);
}

#[test]
fn output_offsets_advance_across_multiple_frames_per_stream() {
    if !require_root() {
        return;
    }
    let (root, _) = template("offset-advance");
    // A frame limit smaller than either stream forces every stream to split, so
    // an implementation that always reports offset zero cannot pass.
    let mut runtime = Runtime::new(RuntimeConfig {
        template_root: root.0.join("template"),
        runtime_root: root.0.join("runtime"),
        limits: RuntimeLimits {
            output_frame_bytes: 4,
            ..RuntimeLimits::default()
        },
        scope: MemberScope::ProcessGroup,
    })
    .unwrap();
    let events = run_script(&mut runtime, 1, "printf 'abcdefgh'; printf 'ijklmnop' 1>&2");

    let mut stdout_offsets = Vec::new();
    let mut stderr_offsets = Vec::new();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut frames = 0_u64;
    for event in &events {
        let Event::WorkloadOutput {
            stream,
            offset,
            bytes,
            ..
        } = event
        else {
            continue;
        };
        frames += 1;
        let decoded = simferret::protocol::decode_bytes(bytes, 4096).unwrap();
        match stream {
            OutputStream::Stdout => {
                stdout_offsets.push(*offset);
                stdout.extend_from_slice(&decoded);
            }
            OutputStream::Stderr => {
                stderr_offsets.push(*offset);
                stderr.extend_from_slice(&decoded);
            }
        }
    }
    assert_eq!(stdout_offsets, vec![0, 4], "stdout offsets must advance");
    assert_eq!(stderr_offsets, vec![0, 4], "stderr offsets must advance");
    assert_eq!(stdout, b"abcdefgh");
    assert_eq!(stderr, b"ijklmnop");
    let reported = events
        .iter()
        .find_map(|event| match event {
            Event::WorkloadExited { frames, .. } => Some(*frames),
            _ => None,
        })
        .expect("the invocation must report an exit record");
    assert_eq!(
        reported, frames,
        "the exit record must count the frames that were emitted"
    );
}

/// A failed start whose root cannot be removed must report the removal failure,
/// refuse the next start while the root is still on disk, and recover once the
/// root can be removed.
#[test]
fn a_failed_start_reports_a_root_that_cannot_be_removed_and_refuses_the_next_start() {
    if !require_root() {
        return;
    }
    let (root, _) = template("failed-start-removal");
    // The template is deeper than the descriptor budget the test installs, so
    // both copying and removing the root exhaust the table.
    let mut deep = root.0.join("template/deep");
    fs::create_dir(&deep).unwrap();
    for _ in 0..200 {
        deep.push("d");
        fs::create_dir(&deep).unwrap();
    }

    let mut runtime = runtime(&root);
    let Some(limit) = DescriptorLimit::lower_to(64) else {
        eprintln!("skipping: cannot lower the descriptor limit");
        return;
    };

    let mut missing = launch("printf 'unused\\n'");
    missing.executable = "/bin/missing".into();
    missing.arguments = vec!["/bin/missing".into()];
    let events = runtime.start(1, &missing);
    let detail = match &events[0] {
        Event::LaunchFailed {
            failure: LaunchFailure::Materialization,
            detail,
            ..
        } => detail.clone(),
        other => panic!("expected a materialization failure: {other:?}"),
    };
    assert!(
        detail.contains("invocation root"),
        "the removal failure must be reported with the launch failure: {detail}"
    );

    // The root is still on disk, so the next start must be refused.
    let events = runtime.start(2, &launch("printf 'unused\\n'"));
    assert!(
        matches!(
            events[0],
            Event::LaunchFailed {
                failure: LaunchFailure::Materialization,
                ..
            }
        ),
        "a start on top of an unremoved root must be refused: {events:#?}"
    );

    // Once the root can be removed again the runtime recovers.
    drop(limit);
    let mut events = runtime.start(3, &launch("printf 'recovered\\n'"));
    assert!(
        matches!(events[0], Event::WorkloadStarted { .. }),
        "{events:#?}"
    );
    poll_until_cleanup(&mut runtime, &mut events);
    assert_eq!(stdout_bytes(&events), b"recovered\n");
}

/// A completed invocation whose root cannot be removed must not report a
/// completed barrier or release the single-workload slot.
#[test]
fn a_completed_invocation_reports_a_root_that_cannot_be_removed() {
    if !require_root() {
        return;
    }
    let (root, _) = template("completed-removal");
    let mut runtime = runtime(&root);
    let Some(limit) = DescriptorLimit::lower_to(64) else {
        eprintln!("skipping: cannot lower the descriptor limit");
        return;
    };
    // The workload builds a tree deeper than the descriptor budget, so the
    // barrier's root removal exhausts the table.
    let mut events = runtime.start(
        1,
        &launch(
            "cd /tmp; i=0; while [ $i -lt 200 ]; do mkdir d; cd d; i=$((i+1)); done; printf 'deep\\n'",
        ),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let failure = loop {
        match runtime.poll(Duration::from_millis(50)) {
            Ok(more) => events.extend(more),
            Err(error) => break error,
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the barrier must report the removal failure: {events:#?}"
        );
    };
    assert!(failure.to_string().contains("invocation root"), "{failure}");
    // The barrier did not complete and the slot is still occupied.
    assert!(runtime.is_active());
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::CleanupComplete { .. }))
    );
    let events = runtime.start(2, &launch("printf 'unused\\n'"));
    assert!(
        matches!(
            events[0],
            Event::LaunchFailed {
                failure: LaunchFailure::InvocationActive,
                ..
            }
        ),
        "{events:#?}"
    );
    drop(limit);
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
fn a_full_stdin_pipe_does_not_block_the_control_loop() {
    if !require_root() {
        return;
    }
    let (root, _) = template("stdin-full");
    let mut runtime = runtime(&root);
    // The shell itself never reads stdin, so its pipe fills and stays full.
    let mut events = runtime.start(1, &launch("while :; do sleep 1; done"));
    assert!(matches!(events[0], Event::WorkloadStarted { .. }));
    // The child never reads stdin, so its pipe fills after about 64 KiB. Every
    // frame must still be accepted into the bounded queue instead of blocking
    // the control loop, which would also block `terminate`.
    let frame = vec![b'x'; 4096];
    let mut offset = 0_u64;
    // SAFETY: installing a SIGALRM handler has no other effect and `alarm` only
    // schedules the signal. The handler exits explicitly, because PID 1 in a
    // fresh PID namespace ignores a signal whose disposition is the default.
    let handler = watchdog_expired as *const () as libc::sighandler_t;
    let previous = unsafe { libc::signal(libc::SIGALRM, handler) };
    unsafe { libc::alarm(15) };
    for _ in 0..32 {
        let accepted = runtime.stdin_write(1, offset, &encode_bytes(&frame));
        assert!(
            accepted.is_ok(),
            "a full stdin pipe must not block: {accepted:?}"
        );
        offset += frame.len() as u64;
    }
    unsafe { libc::alarm(0) };
    unsafe { libc::signal(libc::SIGALRM, previous) };
    // Termination must still be reachable while input remains queued.
    events.extend(runtime.terminate(1).unwrap());
    poll_until_cleanup(&mut runtime, &mut events);
}

#[test]
fn an_invocation_identifier_cannot_be_reused() {
    if !require_root() {
        return;
    }
    let (root, _) = template("identifier");
    let mut runtime = runtime(&root);
    let events = run_script(&mut runtime, 1, "printf 'first\\n'");
    assert_eq!(stdout_bytes(&events), b"first\n");
    let repeated = runtime.start(1, &launch("printf 'second\\n'"));
    assert!(matches!(
        repeated[0],
        Event::LaunchFailed {
            failure: LaunchFailure::InvocationRepeated,
            ..
        }
    ));
    assert!(!runtime.is_active());
    let mut events = runtime.start(2, &launch("printf 'second\\n'"));
    assert!(matches!(events[0], Event::WorkloadStarted { .. }));
    poll_until_cleanup(&mut runtime, &mut events);
    assert_eq!(stdout_bytes(&events), b"second\n");
}

#[test]
fn a_failed_materialization_leaves_no_partial_root() {
    if !require_root() {
        return;
    }
    let (root, _) = template("partial");
    // A file larger than the canonical file bound fails during materialization,
    // after the root and some of its entries already exist.
    fs::write(root.0.join("template/bin/large"), vec![0_u8; 8192]).unwrap();
    let mut runtime = Runtime::new(RuntimeConfig {
        template_root: root.0.join("template"),
        runtime_root: root.0.join("runtime"),
        limits: RuntimeLimits {
            file_bytes: 4096,
            ..RuntimeLimits::default()
        },
        scope: MemberScope::ProcessGroup,
    })
    .unwrap();
    let events = runtime.start(1, &launch("printf 'unused\\n'"));
    assert!(matches!(
        events[0],
        Event::LaunchFailed {
            failure: LaunchFailure::Materialization,
            ..
        }
    ));
    let entries = fs::read_dir(root.0.join("runtime"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert!(entries.is_empty(), "a partial root survived: {entries:?}");
}

#[test]
fn an_unexecutable_file_reports_a_typed_launch_failure() {
    if !require_root() {
        return;
    }
    let (root, _) = template("unexecutable");
    // A regular file with an execute bit that is not a valid executable image:
    // pre-fork validation passes, so this exercises the child setup pipe and
    // the post-fork ownership path.
    let path = root.0.join("template/bin/not-an-executable");
    fs::write(&path, b"this is not an executable image\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let mut runtime = runtime(&root);
    let mut launch = launch("unused");
    launch.executable = "/bin/not-an-executable".into();
    launch.arguments = vec!["/bin/not-an-executable".into()];
    let events = runtime.start(1, &launch);
    assert!(matches!(
        events[0],
        Event::LaunchFailed {
            failure: LaunchFailure::Executable,
            ..
        }
    ));
    assert!(!runtime.is_active());
    assert!(
        fs::read_dir(root.0.join("runtime"))
            .unwrap()
            .next()
            .is_none(),
        "a partial root survived"
    );
}

#[test]
fn shutdown_reports_the_real_primary_exit_status() {
    if !require_root() {
        return;
    }
    let (root, _) = template("exit-status");
    let mut runtime = runtime(&root);
    let events = runtime.start(1, &launch("exit 7"));
    assert!(matches!(events[0], Event::WorkloadStarted { .. }));
    // Let the primary exit without observing it, then shut down: the barrier
    // must report the real status instead of a fabricated termination signal.
    std::thread::sleep(Duration::from_millis(500));
    let events = runtime.shutdown().unwrap();
    let exit = events
        .iter()
        .find_map(|event| match event {
            Event::WorkloadExited { exit, .. } => Some(*exit),
            _ => None,
        })
        .expect("the barrier must report an exit record");
    assert_eq!(exit, ProcessExit::Exited { code: 7 });
}

#[test]
fn a_member_that_closes_its_output_descriptors_is_still_reaped() {
    if !require_root() {
        return;
    }
    if std::process::id() != 1 {
        eprintln!(
            "skipping: the guest-wide cleanup barrier requires a PID namespace (run scripts/rfd3-phase2-runtime.sh)"
        );
        return;
    }
    let (root, _) = template("closed-output");
    let mut runtime = Runtime::new(RuntimeConfig {
        template_root: root.0.join("template"),
        runtime_root: root.0.join("runtime"),
        limits: RuntimeLimits::default(),
        scope: MemberScope::Guest,
    })
    .unwrap();
    // The descendant escapes the process group, closes its output descriptors,
    // and keeps running. The pipes reach end of file immediately, so the
    // barrier must still kill and reap the descendant before completing.
    let events = run_script(
        &mut runtime,
        1,
        "(setsid sh -c 'exec 1>&- 2>&-; sleep 30' &) ; printf 'closed\\n'",
    );
    assert_eq!(stdout_bytes(&events), b"closed\n");
    let reaped = events
        .iter()
        .find_map(|event| match event {
            Event::CleanupComplete { reaped, .. } => Some(*reaped),
            _ => None,
        })
        .expect("the barrier must complete");
    assert!(reaped >= 2, "the descendant must be reaped too: {reaped}");
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

    // Read the event channel while the agent runs. Every step below then waits
    // for the agent to report the state it just reached, so the test never
    // guesses with a sleep and never joins before the output is drained.
    let collected = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&collected);
    let reader = std::thread::spawn(move || {
        let mut events = unsafe { fs::File::from_raw_fd(event_read) };
        let mut buffer = [0_u8; 4096];
        loop {
            match events.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => sink.lock().unwrap().extend_from_slice(&buffer[..read]),
            }
        }
    });

    let mut commands = unsafe { fs::File::from_raw_fd(command_write) };
    let mut command_id = 0_u64;
    let mut acknowledged = 0_usize;
    let mut send = |commands: &mut fs::File, command: Command| {
        command_id += 1;
        let mut line = Vec::new();
        write_line_frame(
            &mut line,
            &CommandFrame {
                protocol_version: PROTOCOL_VERSION,
                command_id,
                command,
            },
        )
        .unwrap();
        // The protocol acknowledges every byte of the command line, so the
        // expected acknowledgement count is the number of bytes written.
        acknowledged += line.len();
        commands.write_all(&line).unwrap();
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
    wait_for_frame(&collected, |frame| {
        frame.command_id == start_id
            && matches!(
                frame.event,
                simferret::protocol::Event::WorkloadStarted { .. }
            )
    });
    let write_id = send(
        &mut commands,
        Command::StdinWrite {
            invocation: 1,
            offset: 0,
            bytes: encode_bytes(b"live\n"),
        },
    );
    wait_for_frame(&collected, |frame| {
        frame.command_id == write_id
            && matches!(
                frame.event,
                simferret::protocol::Event::InputAccepted { eof: false, .. }
            )
    });
    // The response must be delivered while the shell is still blocked waiting
    // for another input line, so an implementation that buffers all output
    // until process exit cannot pass.
    wait_for_frame(&collected, |frame| match &frame.event {
        simferret::protocol::Event::WorkloadOutput {
            stream: OutputStream::Stdout,
            bytes,
            ..
        } => simferret::protocol::decode_bytes(bytes, 4096).unwrap() == b"got:live\n",
        _ => false,
    });
    let eof_id = send(&mut commands, Command::StdinEof { invocation: 1 });
    wait_for_frame(&collected, |frame| {
        frame.command_id == eof_id
            && matches!(
                frame.event,
                simferret::protocol::Event::InputAccepted { eof: true, .. }
            )
    });
    wait_for_frame(&collected, |frame| {
        matches!(
            frame.event,
            simferret::protocol::Event::CleanupComplete { .. }
        )
    });
    let shutdown_id = send(&mut commands, Command::Shutdown {});
    wait_for_frame(&collected, |frame| {
        frame.command_id == shutdown_id
            && matches!(frame.event, simferret::protocol::Event::AgentStopped {})
    });
    drop(commands);

    let status = agent.join().unwrap().unwrap();
    assert_eq!(status, 0);
    reader.join().unwrap();
    let bytes = collected.lock().unwrap().clone();
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
    assert_eq!(
        output_frame.command_id, write_id,
        "live output must be attributed to the command in flight: {events:#?}"
    );
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
    // Every command byte was acknowledged exactly once, so no acknowledgement
    // is lost, duplicated, or coalesced.
    assert_eq!(
        bytes.iter().filter(|byte| **byte == SERIAL_ACK).count(),
        acknowledged,
        "each of the {acknowledged} command bytes must be acknowledged exactly once"
    );
}

/// Wait until the agent reports a frame matching `predicate`.
fn wait_for_frame<F>(collected: &Arc<Mutex<Vec<u8>>>, predicate: F)
where
    F: Fn(&simferret::protocol::EventFrame) -> bool,
{
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let frames = decode_serial_events(&collected.lock().unwrap());
        if frames.iter().any(&predicate) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the agent did not report the expected state: {frames:#?}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
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

/// Bounds a regression that would otherwise hang the suite. PID 1 in a fresh
/// PID namespace ignores a signal whose disposition is the default, so the
/// handler exits explicitly.
extern "C" fn watchdog_expired(_: libc::c_int) {
    // SAFETY: `_exit` is async-signal-safe.
    unsafe { libc::_exit(99) };
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(data) {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}
