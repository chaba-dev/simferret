//! RFD 3 Phase 3: the host-side workload scenario checker.
//!
//! The guest runtime reports process and byte facts only. This module owns the
//! application meaning of the recorded output frames: it reconstructs each
//! invocation's streams from the frames, checks them against the exit record's
//! independently reported totals and digests, matches the ordered response lines
//! to the recorded input commands, and evaluates the structured process,
//! response-integrity, outage, and recovery properties.
//!
//! Passive replay recomputes this report from the recorded events and requires
//! it to match byte for byte, so no application meaning is recovered at replay
//! time from a live source.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::assertions::{AssertionName, AssertionReport, AssertionResult};
use crate::protocol::{
    Event, EventFrame, LaunchFailure, OutputStream, ProcessExit, RequestPhase, TERMINATION_SIGNAL,
};
use crate::scenario::{PlannedRequest, WorkloadChoicePlan, WorkloadScenario};
use crate::workload::LaunchIdentity;

/// The largest single response line the acceptance fixture may emit.
pub const MAX_RESPONSE_LINE_BYTES: usize = 1024;
/// The fixed startup line every fixture invocation emits before reading input.
pub const READY_LINE: &str = "ready version=1";
/// The fixed line the fixture emits after creating its `/tmp` marker and
/// reporting the mode of its own executable. Both witnesses must be fresh: the
/// marker proves the writable overlay was recreated, and the executable mode
/// proves a mutation outside the overlay did not survive either.
pub const FRESH_STATE_LINE: &str = "state value=fresh root=fresh";
/// The prefix every state line shares, so a stale witness fails with a precise
/// message rather than an unexplained line-count mismatch.
pub const STATE_LINE_PREFIX: &str = "state value=";
/// The fixed line the fixture emits once its escaped descendant is ready.
pub const ESCAPED_DESCENDANT_LINE: &str = "descendant state=escaped";
/// The fixed private interface the acceptance profile configures.
pub const NETWORK_INTERFACE: &str = "eth0";
/// The fixed guest address the acceptance profile configures.
pub const GUEST_CIDR: &str = "10.0.2.15/24";
/// The fixed private peer the acceptance profile configures and faults.
pub const FIXTURE_PEER: &str = "10.0.2.2";

/// The deterministic echo token for one invocation. The host checker derives the
/// expected response from the recorded input, so a workload that answers with
/// anything else fails response integrity.
pub fn echo_token(seed: u64, invocation: u64) -> String {
    format!("echo-{invocation}-{seed:016x}")
}

/// The phase one request belongs to, given the seeded fault transitions.
pub fn request_phase(index: usize, activation: usize, restoration: usize) -> RequestPhase {
    if index < activation {
        RequestPhase::PreOutage
    } else if index < restoration {
        RequestPhase::Outage
    } else {
        RequestPhase::Recovery
    }
}

/// The exact response line the fixture emits for one planned request in one
/// phase.
pub fn expected_network_line(request: &PlannedRequest, phase: RequestPhase) -> String {
    match phase {
        RequestPhase::Outage => format!(
            "network state=unavailable request={} errno={}",
            request.request_id,
            libc::EACCES
        ),
        RequestPhase::PreOutage | RequestPhase::Recovery => {
            format!("network state=ok request={}", request.request_id)
        }
    }
}

/// One complete output line, the event that completed it, and the event that
/// carried its first byte. A line may complete in a later frame than it started,
/// so the first byte is what must follow the command that produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompletedLine {
    text: String,
    event_id: u64,
    first_event_id: u64,
}

#[derive(Debug, Default)]
struct InvocationStreams {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    /// Bytes since the last complete line, kept only for line splitting so the
    /// full stream stays available for the exit-record totals and digests.
    stdout_pending: Vec<u8>,
    stderr_pending: Vec<u8>,
    stdout_lines: Vec<CompletedLine>,
    stderr_lines: Vec<CompletedLine>,
    /// The event that carried the first byte of the current stdout line, while
    /// that line is still incomplete.
    stdout_line_event: Option<u64>,
    /// The event that carried the first byte of the current stderr line.
    stderr_line_event: Option<u64>,
    stdout_offset: u64,
    stderr_offset: u64,
    /// Whether the current stdout line has already exceeded the response bound.
    stdout_over_bound: bool,
    /// Whether any stdout line has exceeded the response bound. The failure is
    /// permanent: completing the offending line cannot make the invocation
    /// healthy again.
    stdout_over_bound_seen: bool,
    /// The accepted input offset after the last `input-accepted` event.
    input_offset: u64,
    /// The command identifiers of the accepted inputs, in arrival order.
    input_commands: Vec<u64>,
    /// Data acknowledgements, which must correspond one to one with the
    /// responses the invocation produced. The event identifiers are retained so
    /// a response can be required to follow the command it answers.
    data_input_events: Vec<u64>,
    /// End-of-input acknowledgements, of which there must be exactly one and it
    /// must be the last accepted input.
    eof_inputs: u64,
    input_eof: bool,
    sequence: u64,
    frames: u64,
    violations: Vec<String>,
}

impl InvocationStreams {
    fn push(
        &mut self,
        frame: &EventFrame,
        invocation: u64,
        stream: OutputStream,
        offset: u64,
        sequence: u64,
        data: &[u8],
    ) {
        if self.sequence.checked_add(1) != Some(sequence) {
            self.violations.push(format!(
                "invocation {invocation} sequence jumped from {} to {sequence} at event {}",
                self.sequence, frame.event_id
            ));
        }
        self.sequence = sequence;
        self.frames += 1;
        let (stream_bytes, pending, lines, current_offset, line_event) = match stream {
            OutputStream::Stdout => (
                &mut self.stdout,
                &mut self.stdout_pending,
                &mut self.stdout_lines,
                &mut self.stdout_offset,
                &mut self.stdout_line_event,
            ),
            OutputStream::Stderr => (
                &mut self.stderr,
                &mut self.stderr_pending,
                &mut self.stderr_lines,
                &mut self.stderr_offset,
                &mut self.stderr_line_event,
            ),
        };
        if offset != *current_offset {
            self.violations.push(format!(
                "invocation {invocation} {} offset {offset} is not contiguous with {current_offset}",
                stream.name()
            ));
        }
        *current_offset = offset.saturating_add(data.len() as u64);
        stream_bytes.extend_from_slice(data);
        if pending.is_empty() && !data.is_empty() {
            *line_event = Some(frame.event_id);
        }
        pending.extend_from_slice(data);
        while let Some(index) = pending.iter().position(|byte| *byte == b'\n') {
            let line = pending.drain(..=index).collect::<Vec<u8>>();
            let text = String::from_utf8_lossy(&line[..line.len() - 1]).into_owned();
            if text.len() > MAX_RESPONSE_LINE_BYTES {
                self.violations.push(format!(
                    "invocation {invocation} {} line exceeds the response bound",
                    stream.name()
                ));
                if stream == OutputStream::Stdout {
                    self.stdout_over_bound_seen = true;
                }
            }
            lines.push(CompletedLine {
                text,
                event_id: frame.event_id,
                first_event_id: line_event.take().unwrap_or(frame.event_id),
            });
            if stream == OutputStream::Stdout {
                self.stdout_over_bound = false;
            }
            if !pending.is_empty() {
                // The rest of this frame belongs to the next line.
                *line_event = Some(frame.event_id);
            }
        }
        // A line that already exceeds the bound without a newline is a failing
        // response too, and waiting for the newline would only reach the VM
        // deadline, so it is recorded as soon as it is observed.
        if stream == OutputStream::Stdout
            && !self.stdout_over_bound
            && pending.len() > MAX_RESPONSE_LINE_BYTES
        {
            self.stdout_over_bound = true;
            self.stdout_over_bound_seen = true;
            self.violations.push(format!(
                "invocation {invocation} stdout line exceeds the response bound before its newline"
            ));
        }
    }

    /// Fold one `input-accepted` event. The guest reports the cumulative accepted
    /// offset after each command, so the offset must advance by exactly the
    /// accepted byte count, every accepted command must be a distinct later
    /// command, an end-of-input must carry no bytes and be the last accepted
    /// input, and a data input must carry bytes, so a dropped, replayed, or empty
    /// input command cannot pass.
    fn push_input(
        &mut self,
        invocation: u64,
        event_id: u64,
        command_id: u64,
        offset: u64,
        bytes: u64,
        eof: bool,
    ) {
        let expected = self.input_offset.saturating_add(bytes);
        if offset != expected {
            self.violations.push(format!(
                "invocation {invocation} input offset {offset} is not the expected end {expected} at event {event_id}"
            ));
        }
        if eof && bytes != 0 {
            self.violations.push(format!(
                "invocation {invocation} accepted an end-of-input with {bytes} bytes at event {event_id}"
            ));
        }
        if !eof && bytes == 0 {
            self.violations.push(format!(
                "invocation {invocation} accepted an empty input command at event {event_id}"
            ));
        }
        if eof && self.input_eof {
            self.violations.push(format!(
                "invocation {invocation} accepted a second end-of-input at event {event_id}"
            ));
        }
        if !eof && self.input_eof {
            self.violations.push(format!(
                "invocation {invocation} accepted an input command after the end of input at event {event_id}"
            ));
        }
        if let Some(previous) = self.input_commands.last()
            && command_id <= *previous
        {
            self.violations.push(format!(
                "invocation {invocation} input command {command_id} does not advance past {previous} at event {event_id}"
            ));
        }
        self.input_commands.push(command_id);
        self.input_offset = offset;
        if eof {
            self.eof_inputs += 1;
            self.input_eof = true;
        } else {
            self.data_input_events.push(event_id);
        }
    }
}

#[derive(Debug, Clone)]
struct StartRecord {
    invocation: u64,
    launch: LaunchIdentity,
    event_id: u64,
}

#[derive(Debug, Clone)]
struct ExitRecord {
    invocation: u64,
    exit: ProcessExit,
    stdout_bytes: u64,
    stdout_sha256: String,
    stderr_bytes: u64,
    stderr_sha256: String,
    frames: u64,
    event_id: u64,
}

#[derive(Debug, Clone)]
struct TerminationRecord {
    invocation: u64,
    signal: i32,
    event_id: u64,
}

#[derive(Debug, Clone)]
struct CleanupRecord {
    invocation: u64,
    reaped: u64,
    event_id: u64,
}

#[derive(Debug, Clone)]
struct LaunchFailureRecord {
    invocation: u64,
    failure: LaunchFailure,
}

/// The one network configuration an acceptance run records.
#[derive(Debug, Clone)]
struct ConfiguredRecord {
    gateway: String,
    event_id: u64,
}

/// The process and byte facts one workload run records, reconstructed from the
/// normalized event stream alone.
#[derive(Debug, Default)]
pub struct WorkloadTrace {
    starts: Vec<StartRecord>,
    exits: Vec<ExitRecord>,
    terminations: Vec<TerminationRecord>,
    cleanups: Vec<CleanupRecord>,
    launch_failures: Vec<LaunchFailureRecord>,
    activations: Vec<(String, u64)>,
    restorations: Vec<(String, u64)>,
    configured: Option<ConfiguredRecord>,
    invocations: BTreeMap<u64, InvocationStreams>,
    violations: Vec<String>,
}

impl WorkloadTrace {
    /// Fold one received frame into the trace. An output frame for an invocation
    /// that never started is a structural violation rather than untracked bytes.
    ///
    /// Events that arrive outside a synchronous acknowledgement wait — output,
    /// lifecycle, and network events — are validated here, because the driver
    /// folds them without an expectation of its own.
    pub fn push(&mut self, frame: &EventFrame) {
        let event_id = frame.event_id;
        match &frame.event {
            Event::WorkloadStarted { invocation, launch } => {
                if self
                    .starts
                    .iter()
                    .any(|start| start.invocation == *invocation)
                {
                    self.violations.push(format!(
                        "invocation {invocation} started twice, the second time at event {event_id}"
                    ));
                }
                self.starts.push(StartRecord {
                    invocation: *invocation,
                    launch: launch.clone(),
                    event_id,
                })
            }
            Event::WorkloadExited {
                invocation,
                exit,
                stdout_bytes,
                stdout_sha256,
                stderr_bytes,
                stderr_sha256,
                frames,
            } => {
                if !self.started(*invocation) {
                    self.violations.push(format!(
                        "workload-exited at event {event_id} names invocation {invocation} before it started"
                    ));
                    return;
                }
                if self.exited(*invocation) {
                    self.violations.push(format!(
                        "invocation {invocation} exited twice, the second time at event {event_id}"
                    ));
                    return;
                }
                self.exits.push(ExitRecord {
                    invocation: *invocation,
                    exit: *exit,
                    stdout_bytes: *stdout_bytes,
                    stdout_sha256: stdout_sha256.clone(),
                    stderr_bytes: *stderr_bytes,
                    stderr_sha256: stderr_sha256.clone(),
                    frames: *frames,
                    event_id,
                })
            }
            Event::TerminationRequested { invocation, signal } => {
                if !self.started(*invocation) {
                    self.violations.push(format!(
                        "termination-requested at event {event_id} names invocation {invocation} before it started"
                    ));
                    return;
                }
                if self.exited(*invocation) {
                    self.violations.push(format!(
                        "termination-requested at event {event_id} names invocation {invocation} after it exited"
                    ));
                    return;
                }
                if self
                    .terminations
                    .iter()
                    .any(|termination| termination.invocation == *invocation)
                {
                    self.violations.push(format!(
                        "invocation {invocation} was terminated twice, the second time at event {event_id}"
                    ));
                    return;
                }
                self.terminations.push(TerminationRecord {
                    invocation: *invocation,
                    signal: *signal,
                    event_id,
                })
            }
            Event::CleanupComplete { invocation, reaped } => {
                if !self.started(*invocation) {
                    self.violations.push(format!(
                        "cleanup-complete at event {event_id} names invocation {invocation} before it started"
                    ));
                    return;
                }
                if self
                    .cleanups
                    .iter()
                    .any(|cleanup| cleanup.invocation == *invocation)
                {
                    self.violations.push(format!(
                        "invocation {invocation} completed cleanup twice, the second time at event {event_id}"
                    ));
                    return;
                }
                let Some(exit) = self
                    .exits
                    .iter()
                    .find(|exit| exit.invocation == *invocation)
                else {
                    self.violations.push(format!(
                        "invocation {invocation} completed cleanup at event {event_id} before it exited"
                    ));
                    return;
                };
                if exit.event_id > event_id {
                    self.violations.push(format!(
                        "invocation {invocation} completed cleanup at event {event_id} before its exit record"
                    ));
                    return;
                }
                if *reaped == 0 {
                    self.violations.push(format!(
                        "invocation {invocation} completed cleanup at event {event_id} without reaping a process"
                    ));
                    return;
                }
                self.cleanups.push(CleanupRecord {
                    invocation: *invocation,
                    reaped: *reaped,
                    event_id,
                })
            }
            Event::LaunchFailed {
                invocation,
                failure,
                ..
            } => {
                // An unsuccessful start reports the typed failure instead of a
                // start record, so a launch failure does not require one. It is
                // still a single outcome of one invocation: it cannot repeat, and
                // it cannot arrive for an invocation that already exited.
                if self.launch_failed(*invocation) {
                    self.violations.push(format!(
                        "invocation {invocation} reported a launch failure twice, the second time at event {event_id}"
                    ));
                    return;
                }
                if self.exited(*invocation) {
                    self.violations.push(format!(
                        "invocation {invocation} reported a launch failure at event {event_id} after it exited"
                    ));
                    return;
                }
                self.launch_failures.push(LaunchFailureRecord {
                    invocation: *invocation,
                    failure: *failure,
                })
            }
            Event::NetworkConfigured {
                interface,
                guest_cidr,
                gateway,
            } => {
                if let Some(configured) = &self.configured {
                    self.violations.push(format!(
                        "a second network configuration arrived at event {event_id} after event {}",
                        configured.event_id
                    ));
                    return;
                }
                if interface != NETWORK_INTERFACE
                    || guest_cidr != GUEST_CIDR
                    || gateway != FIXTURE_PEER
                {
                    self.violations.push(format!(
                        "the network configuration at event {event_id} is not the fixed private profile"
                    ));
                    return;
                }
                self.configured = Some(ConfiguredRecord {
                    gateway: gateway.clone(),
                    event_id,
                });
            }
            Event::OutageActivated { peer_cidr, rule } => {
                if let Some((_, activation_id)) = self.activations.first() {
                    let activation_id = *activation_id;
                    self.violations.push(format!(
                        "a second outage activation arrived at event {event_id} after event {activation_id}"
                    ));
                    return;
                }
                if rule != &format!("prohibit {peer_cidr}") {
                    self.violations.push(format!(
                        "the outage activation at event {event_id} does not name its prohibition rule"
                    ));
                    return;
                }
                self.activations.push((peer_cidr.clone(), event_id));
            }
            Event::NetworkRestored { peer_cidr } => {
                if let Some((_, restoration_id)) = self.restorations.first() {
                    self.violations.push(format!(
                        "a second network restoration arrived at event {event_id} after event {restoration_id}"
                    ));
                    return;
                }
                self.restorations.push((peer_cidr.clone(), event_id));
            }
            Event::WorkloadOutput {
                invocation,
                stream,
                offset,
                sequence,
                bytes,
            } => {
                if !self.started(*invocation) {
                    self.violations.push(format!(
                        "output frame at event {event_id} names invocation {invocation} before it started"
                    ));
                    return;
                }
                if self.exited(*invocation) {
                    self.violations.push(format!(
                        "output frame at event {event_id} names invocation {invocation} after it exited"
                    ));
                    return;
                }
                let Ok(data) =
                    crate::protocol::decode_bytes(bytes, crate::protocol::MAX_OUTPUT_FRAME_BYTES)
                else {
                    self.violations.push(format!(
                        "invocation {invocation} emitted an unreadable output frame at event {event_id}"
                    ));
                    return;
                };
                self.invocations.entry(*invocation).or_default().push(
                    frame,
                    *invocation,
                    *stream,
                    *offset,
                    *sequence,
                    &data,
                );
            }
            Event::InputAccepted {
                invocation,
                offset,
                bytes,
                eof,
            } => {
                if !self.started(*invocation) {
                    self.violations.push(format!(
                        "input-accepted at event {event_id} names invocation {invocation} before it started"
                    ));
                    return;
                }
                if self.exited(*invocation) {
                    self.violations.push(format!(
                        "input-accepted at event {event_id} names invocation {invocation} after it exited"
                    ));
                    return;
                }
                if self
                    .terminations
                    .iter()
                    .any(|termination| termination.invocation == *invocation)
                {
                    // The runtime refuses input, including end of input, once the
                    // invocation is being terminated.
                    self.violations.push(format!(
                        "input-accepted at event {event_id} names invocation {invocation} after it was terminated"
                    ));
                    return;
                }
                self.invocations.entry(*invocation).or_default().push_input(
                    *invocation,
                    event_id,
                    frame.command_id,
                    *offset,
                    *bytes,
                    *eof,
                );
            }
            _ => {}
        }
    }

    /// Whether one invocation has a start record.
    fn started(&self, invocation: u64) -> bool {
        self.starts
            .iter()
            .any(|start| start.invocation == invocation)
    }

    /// Every stream-structure violation, including the per-invocation offset,
    /// sequence, and input-stream violations that have no trace-level slot.
    fn all_violations(&self) -> Vec<&String> {
        let mut violations = self.violations.iter().collect::<Vec<_>>();
        for streams in self.invocations.values() {
            violations.extend(streams.violations.iter());
        }
        violations
    }

    /// The number of complete stdout lines observed for one invocation.
    pub fn stdout_line_count(&self, invocation: u64) -> usize {
        self.invocations
            .get(&invocation)
            .map_or(0, |streams| streams.stdout_lines.len())
    }

    /// One complete stdout line, by index.
    pub fn stdout_line(&self, invocation: u64, index: usize) -> Option<&str> {
        self.invocations
            .get(&invocation)?
            .stdout_lines
            .get(index)
            .map(|line| line.text.as_str())
    }

    /// Whether one invocation has an exit record.
    pub fn exited(&self, invocation: u64) -> bool {
        self.exits.iter().any(|exit| exit.invocation == invocation)
    }

    /// Whether one invocation reported a typed launch failure.
    pub fn launch_failed(&self, invocation: u64) -> bool {
        self.launch_failures
            .iter()
            .any(|failure| failure.invocation == invocation)
    }

    /// The number of stderr bytes one invocation has written. The pinned fixture
    /// writes to stderr only when it is failing, so the driver stops waiting for a
    /// response line once any stderr byte is observed and lets the checker report
    /// the application failure.
    pub fn stderr_bytes(&self, invocation: u64) -> usize {
        self.invocations.get(&invocation).map_or(0, |streams| {
            streams.stderr.len() + streams.stderr_pending.len()
        })
    }

    /// Whether one invocation's stdout has exceeded the response bound, either on
    /// its current unfinished line or on a line that has already completed. The
    /// driver stops waiting for a line that can no longer be valid instead of
    /// reaching the VM deadline.
    pub fn over_bound_line(&self, invocation: u64) -> bool {
        self.invocations
            .get(&invocation)
            .is_some_and(|streams| streams.stdout_over_bound || streams.stdout_over_bound_seen)
    }

    /// Whether one invocation's stdout has bytes that have not yet completed a
    /// line. The driver stops waiting for an exit on a pending byte as well,
    /// because every expected response is already complete and consumed by then.
    pub fn stdout_pending(&self, invocation: u64) -> bool {
        self.invocations
            .get(&invocation)
            .is_some_and(|streams| !streams.stdout_pending.is_empty())
    }

    fn stdout_lines(&self, invocation: u64) -> &[CompletedLine] {
        self.invocations
            .get(&invocation)
            .map_or(&[], |streams| streams.stdout_lines.as_slice())
    }

    fn stderr_lines(&self, invocation: u64) -> &[CompletedLine] {
        self.invocations
            .get(&invocation)
            .map_or(&[], |streams| streams.stderr_lines.as_slice())
    }

    fn any_stdout_line(&self, wanted: &str) -> Option<&CompletedLine> {
        self.invocations
            .values()
            .flat_map(|streams| streams.stdout_lines.iter())
            .find(|line| line.text == wanted)
    }

    /// One complete stdout line, by text, together with the event identifier of
    /// the data acknowledgement that answers it. The startup line answers no
    /// command, so it is never returned.
    fn stdout_line_with_ack(&self, wanted: &str) -> Option<(&CompletedLine, u64)> {
        for streams in self.invocations.values() {
            for (index, line) in streams.stdout_lines.iter().enumerate() {
                if line.text != wanted {
                    continue;
                }
                let Some(acknowledged) = index
                    .checked_sub(1)
                    .and_then(|position| streams.data_input_events.get(position))
                else {
                    continue;
                };
                return Some((line, *acknowledged));
            }
        }
        None
    }
}

/// Evaluate the structured process, response-integrity, outage, and recovery
/// properties of one workload run.
pub fn evaluate_workload(
    events: &[EventFrame],
    scenario: &WorkloadScenario,
    choices: &WorkloadChoicePlan,
    launch: &LaunchIdentity,
) -> AssertionReport {
    let mut trace = WorkloadTrace::default();
    for frame in events {
        trace.push(frame);
    }
    let (controlled_outage, restoration, bounded_recovery) =
        fault_properties(&trace, scenario, choices);
    let assertions = vec![
        process_safety(&trace, choices, launch),
        response_integrity(&trace, choices),
        controlled_outage,
        restoration,
        bounded_recovery,
    ];
    AssertionReport {
        passed: assertions.iter().all(|assertion| assertion.passed),
        assertions,
    }
}

fn process_safety(
    trace: &WorkloadTrace,
    choices: &WorkloadChoicePlan,
    launch: &LaunchIdentity,
) -> AssertionResult {
    if let Some(violation) = trace.all_violations().first() {
        return failed(
            AssertionName::ProcessSafety,
            format!("stream structure violation: {violation}"),
        );
    }
    if let Some(failure) = trace.launch_failures.first() {
        return failed(
            AssertionName::ProcessSafety,
            format!(
                "invocation {} reported launch failure {:?}",
                failure.invocation, failure.failure
            ),
        );
    }
    if trace.starts.len() != 2 {
        return failed(
            AssertionName::ProcessSafety,
            format!(
                "expected exactly two workload starts, observed {}",
                trace.starts.len()
            ),
        );
    }
    if trace.starts[0].invocation != 1
        || trace.starts[0].launch != *launch
        || trace.starts[1].invocation != 2
        || trace.starts[1].launch != *launch
    {
        return failed(
            AssertionName::ProcessSafety,
            "the started invocation identities do not match the materialized workload",
        );
    }
    // The acceptance profile terminates exactly the first invocation, so a
    // second termination record anywhere is not a passing process history.
    if trace.terminations.len() != 1 {
        return failed(
            AssertionName::ProcessSafety,
            format!(
                "expected exactly one termination record, observed {}",
                trace.terminations.len()
            ),
        );
    }
    let Some(terminated) = trace
        .terminations
        .iter()
        .find(|termination| termination.invocation == 1)
    else {
        return failed(
            AssertionName::ProcessSafety,
            "the first invocation was never terminated",
        );
    };
    if terminated.signal != TERMINATION_SIGNAL {
        return failed(
            AssertionName::ProcessSafety,
            format!(
                "termination signal {} is not the fixed SIGKILL",
                terminated.signal
            ),
        );
    }
    let Some(first_exit) = trace.exits.iter().find(|exit| exit.invocation == 1) else {
        return failed(
            AssertionName::ProcessSafety,
            "the first invocation has no exit record",
        );
    };
    if !matches!(first_exit.exit, ProcessExit::Signaled { signal } if signal == TERMINATION_SIGNAL)
    {
        return failed(
            AssertionName::ProcessSafety,
            format!(
                "the first invocation did not report SIGKILL: {:?}",
                first_exit.exit
            ),
        );
    }
    let Some(first_cleanup) = trace
        .cleanups
        .iter()
        .find(|cleanup| cleanup.invocation == 1)
    else {
        return failed(
            AssertionName::ProcessSafety,
            "the first invocation has no cleanup-complete barrier",
        );
    };
    if !(terminated.event_id < first_exit.event_id && first_exit.event_id < first_cleanup.event_id)
    {
        return failed(
            AssertionName::ProcessSafety,
            "the termination, exit, and cleanup barrier for the first invocation are out of order",
        );
    }
    // The runtime reaps the terminated primary and the escaped descendant the
    // fixture left behind, so a barrier that reports fewer than two processes
    // did not prove the descendant was killed.
    if first_cleanup.reaped < 2 {
        return failed(
            AssertionName::ProcessSafety,
            format!(
                "the cleanup barrier reaped {} process(es), so the escaped descendant was not confirmed killed",
                first_cleanup.reaped
            ),
        );
    }
    if trace.starts[1].event_id <= first_cleanup.event_id {
        return failed(
            AssertionName::ProcessSafety,
            "the second invocation started before the first cleanup barrier completed",
        );
    }
    let Some(escaped) = trace.any_stdout_line(ESCAPED_DESCENDANT_LINE) else {
        return failed(
            AssertionName::ProcessSafety,
            "the first invocation never reported an escaped descendant",
        );
    };
    if escaped.event_id > terminated.event_id {
        return failed(
            AssertionName::ProcessSafety,
            "the escaped descendant was reported after the termination was requested",
        );
    }
    let Some(second_exit) = trace.exits.iter().find(|exit| exit.invocation == 2) else {
        return failed(
            AssertionName::ProcessSafety,
            "the second invocation has no exit record",
        );
    };
    if second_exit.exit != (ProcessExit::Exited { code: 0 }) {
        return failed(
            AssertionName::ProcessSafety,
            format!(
                "the second invocation did not exit cleanly: {:?}",
                second_exit.exit
            ),
        );
    }
    if !trace.cleanups.iter().any(|cleanup| cleanup.invocation == 2) {
        return failed(
            AssertionName::ProcessSafety,
            "the second invocation has no cleanup-complete barrier",
        );
    }
    let fresh_one = trace
        .stdout_lines(1)
        .iter()
        .filter(|line| line.text == FRESH_STATE_LINE)
        .count();
    let fresh_two = trace
        .stdout_lines(2)
        .iter()
        .filter(|line| line.text == FRESH_STATE_LINE)
        .count();
    let stale = trace
        .stdout_lines(1)
        .iter()
        .chain(trace.stdout_lines(2).iter())
        .find(|line| line.text.starts_with(STATE_LINE_PREFIX) && line.text != FRESH_STATE_LINE);
    if let Some(stale) = stale {
        return failed(
            AssertionName::ProcessSafety,
            format!(
                "an invocation observed the first invocation's root mutation at event {}",
                stale.event_id
            ),
        );
    }
    if fresh_one != 1 || fresh_two != 1 {
        return failed(
            AssertionName::ProcessSafety,
            format!(
                "each invocation must report a fresh root once, observed {fresh_one} and {fresh_two}"
            ),
        );
    }
    let fault_index = choices.process_fault_request_index;
    if fault_index == 0 {
        return failed(
            AssertionName::ProcessSafety,
            "the process fault must follow at least one recorded request",
        );
    }
    passed(
        AssertionName::ProcessSafety,
        format!(
            "invocation 1 was killed and cleaned up before invocation 2 started fresh at request {fault_index}"
        ),
    )
}

fn response_integrity(trace: &WorkloadTrace, choices: &WorkloadChoicePlan) -> AssertionResult {
    let fault_index = choices.process_fault_request_index;
    let activation = choices.outage_activation_request_index;
    let restoration = choices.restoration_request_index;
    let network_lines = (0..choices.requests.len())
        .map(|index| {
            expected_network_line(
                &choices.requests[index],
                request_phase(index, activation, restoration),
            )
        })
        .collect::<Vec<_>>();

    for invocation in [1_u64, 2] {
        let mut expected = vec![
            READY_LINE.to_owned(),
            format!("echo value={}", echo_token(choices.seed, invocation)),
            FRESH_STATE_LINE.to_owned(),
        ];
        if invocation == 1 {
            expected.extend(network_lines[..fault_index].iter().cloned());
            expected.push(ESCAPED_DESCENDANT_LINE.to_owned());
        } else {
            expected.extend(network_lines[fault_index..].iter().cloned());
        }
        let actual = trace.stdout_lines(invocation);
        if actual.len() != expected.len() {
            return failed(
                AssertionName::ResponseIntegrity,
                format!(
                    "invocation {invocation} produced {} response lines; expected {}",
                    actual.len(),
                    expected.len()
                ),
            );
        }
        for (index, (line, wanted)) in actual.iter().zip(expected.iter()).enumerate() {
            if &line.text != wanted {
                return failed(
                    AssertionName::ResponseIntegrity,
                    format!(
                        "invocation {invocation} response line {index} does not match its command"
                    ),
                );
            }
        }
        // Every response line but the startup line answers one accepted input
        // command, and an invocation that reached its end of input acknowledged
        // it exactly once and last, so a recording cannot drop or duplicate the
        // acknowledgements of the commands whose responses it produced. The
        // acceptance contract ends the surviving invocation's input, so its end
        // of input is required, not merely permitted: a recording that omits it
        // has not exercised the scenario.
        let (data_input_events, eof_inputs) = trace
            .invocations
            .get(&invocation)
            .map_or((&[][..], 0), |streams| {
                (streams.data_input_events.as_slice(), streams.eof_inputs)
            });
        let expected_inputs = (expected.len() - 1) as u64;
        let expected_eofs = u64::from(invocation == 2);
        if data_input_events.len() as u64 != expected_inputs || eof_inputs != expected_eofs {
            return failed(
                AssertionName::ResponseIntegrity,
                format!(
                    "invocation {invocation} acknowledged {} input command(s) and {eof_inputs} end(s) of input; expected {expected_inputs} and {expected_eofs}",
                    data_input_events.len()
                ),
            );
        }
        // A response cannot answer a command the invocation had not accepted
        // yet, so each response line must begin after the acknowledgement it
        // answers. The line's first byte is what must follow the
        // acknowledgement, because a line may complete in a later frame than the
        // one that started it.
        for (index, acknowledged) in data_input_events.iter().enumerate() {
            if actual[index + 1].first_event_id <= *acknowledged {
                return failed(
                    AssertionName::ResponseIntegrity,
                    format!(
                        "invocation {invocation} response line {index} was recorded before the input command it answers"
                    ),
                );
            }
        }
    }
    let application_error = trace
        .stderr_lines(1)
        .first()
        .or_else(|| trace.stderr_lines(2).first());
    if let Some(error) = application_error {
        return failed(
            AssertionName::ResponseIntegrity,
            format!(
                "the workload reported an application error at event {}",
                error.event_id
            ),
        );
    }
    for exit in &trace.exits {
        let streams = trace.invocations.get(&exit.invocation);
        let (stdout, stderr) = match streams {
            Some(streams) => (streams.stdout.as_slice(), streams.stderr.as_slice()),
            None => (&[][..], &[][..]),
        };
        // Each invocation's output is a sequence of complete lines, so an exit
        // record with bytes after the last newline is an unterminated line. The
        // pinned fixture never writes to stderr, so any stderr byte is an
        // application failure.
        if let Some(streams) = streams {
            if !streams.stdout_pending.is_empty() {
                return failed(
                    AssertionName::ResponseIntegrity,
                    format!(
                        "invocation {} ended with {} byte(s) after its last complete line",
                        exit.invocation,
                        streams.stdout_pending.len()
                    ),
                );
            }
            if !streams.stderr_pending.is_empty() || !streams.stderr.is_empty() {
                return failed(
                    AssertionName::ResponseIntegrity,
                    format!(
                        "invocation {} wrote {} stderr byte(s)",
                        exit.invocation,
                        streams.stderr.len() + streams.stderr_pending.len()
                    ),
                );
            }
        }
        if exit.stdout_bytes != stdout.len() as u64
            || exit.stderr_bytes != stderr.len() as u64
            || exit.frames != streams.map_or(0, |streams| streams.frames)
        {
            return failed(
                AssertionName::ResponseIntegrity,
                format!(
                    "invocation {} exit totals do not match the recorded output frames",
                    exit.invocation
                ),
            );
        }
        if exit.stdout_sha256 != sha256(stdout) || exit.stderr_sha256 != sha256(stderr) {
            return failed(
                AssertionName::ResponseIntegrity,
                format!(
                    "invocation {} exit digests do not match the recorded output frames",
                    exit.invocation
                ),
            );
        }
    }
    if let Some(violation) = trace.all_violations().first() {
        return failed(
            AssertionName::ResponseIntegrity,
            format!("stream structure violation: {violation}"),
        );
    }
    passed(
        AssertionName::ResponseIntegrity,
        format!(
            "all {} responses matched the recorded input",
            choices.requests.len()
        ),
    )
}

type FaultProperties = (AssertionResult, AssertionResult, AssertionResult);

fn fault_properties(
    trace: &WorkloadTrace,
    scenario: &WorkloadScenario,
    choices: &WorkloadChoicePlan,
) -> FaultProperties {
    let peer = format!("{}/32", scenario.fixture_peer);
    // The configured gateway is part of the fixed private profile, so the
    // activation must follow a configuration that reported it and must name the
    // scenario's peer. Deriving the expected peer from the scenario, rather than
    // from whatever the guest reported, keeps the property independent of the
    // event it is checking.
    let activation = trace
        .configured
        .as_ref()
        .filter(|configured| configured.gateway == scenario.fixture_peer)
        .and_then(|configured| {
            trace
                .activations
                .iter()
                .find(|(peer_cidr, event_id)| peer_cidr == &peer && *event_id > configured.event_id)
        });
    let restoration = activation.and_then(|(activated_peer, activation_id)| {
        trace
            .restorations
            .iter()
            .find(|(peer_cidr, event_id)| peer_cidr == activated_peer && event_id > activation_id)
    });

    let outage = activation.and_then(|(_, activation_id)| {
        let index = (0..choices.requests.len()).find(|index| {
            request_phase(
                *index,
                choices.outage_activation_request_index,
                choices.restoration_request_index,
            ) == RequestPhase::Outage
        })?;
        let wanted = expected_network_line(&choices.requests[index], RequestPhase::Outage);
        let (line, acknowledged) = trace.stdout_line_with_ack(&wanted)?;
        // The prohibited request must have been accepted while the outage was in
        // force, so neither its acknowledgement nor its response may precede the
        // activation, and it cannot be satisfied by a response that only arrived
        // after the network was restored.
        let before_restoration =
            restoration.is_none_or(|(_, restoration_id)| line.event_id < *restoration_id);
        (acknowledged > *activation_id
            && line.event_id > *activation_id
            && before_restoration
            && line.event_id - activation_id <= scenario.outage_event_bound)
            .then_some((line.event_id, line.event_id - activation_id))
    });
    let controlled_outage = match outage {
        Some((event_id, distance)) => passed(
            AssertionName::ControlledOutage,
            format!(
                "the workload observed the administrative prohibition at event {event_id} after {distance} event(s)"
            ),
        ),
        None => failed(
            AssertionName::ControlledOutage,
            format!(
                "no workload request reported EACCES within {} event(s) of activation",
                scenario.outage_event_bound
            ),
        ),
    };

    let restoration_result = match restoration {
        Some((_, event_id)) => passed(
            AssertionName::Restoration,
            format!("network restoration of {peer} was confirmed at event {event_id}"),
        ),
        None => failed(
            AssertionName::Restoration,
            format!("network restoration of {peer} was not confirmed after activation"),
        ),
    };

    let recovery = restoration.and_then(|(_, restoration_id)| {
        let index = (0..choices.requests.len()).find(|index| {
            request_phase(
                *index,
                choices.outage_activation_request_index,
                choices.restoration_request_index,
            ) == RequestPhase::Recovery
        })?;
        let wanted = expected_network_line(&choices.requests[index], RequestPhase::Recovery);
        let (line, acknowledged) = trace.stdout_line_with_ack(&wanted)?;
        // The recovery request must have been accepted after the restoration, so
        // a response whose command preceded it cannot satisfy the property.
        (acknowledged > *restoration_id
            && line.event_id > *restoration_id
            && line.event_id - restoration_id <= scenario.liveness_event_bound)
            .then_some((line.event_id, line.event_id - restoration_id))
    });
    // A restart is only a recovery if the restarted invocation answers inside the
    // same liveness bound. Measuring from the second start event, rather than
    // accepting any recovery, prevents the first invocation's responses from
    // satisfying the property.
    let restart = trace
        .starts
        .iter()
        .find(|start| start.invocation == 2)
        .and_then(|start| {
            let wanted = format!("echo value={}", echo_token(choices.seed, 2));
            let line = trace
                .stdout_lines(2)
                .iter()
                .find(|line| line.text == wanted)?;
            (line.event_id > start.event_id
                && line.event_id - start.event_id <= scenario.liveness_event_bound)
                .then_some((line.event_id, line.event_id - start.event_id))
        });
    let bounded_recovery = match (recovery, restart) {
        (Some((event_id, distance)), Some((restart_id, restart_distance))) => passed(
            AssertionName::BoundedRecovery,
            format!(
                "the workload recovered at event {event_id} after {distance} event(s) and the restarted invocation answered at event {restart_id} after {restart_distance} event(s)"
            ),
        ),
        (None, _) => failed(
            AssertionName::BoundedRecovery,
            format!(
                "no matching workload response arrived within {} event(s) of restoration",
                scenario.liveness_event_bound
            ),
        ),
        (Some(_), None) => failed(
            AssertionName::BoundedRecovery,
            format!(
                "the restarted invocation did not answer within {} event(s) of its start",
                scenario.liveness_event_bound
            ),
        ),
    };
    (controlled_outage, restoration_result, bounded_recovery)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn passed(name: AssertionName, detail: impl Into<String>) -> AssertionResult {
    AssertionResult {
        name,
        passed: true,
        detail: detail.into(),
    }
}

fn failed(name: AssertionName, detail: impl Into<String>) -> AssertionResult {
    AssertionResult {
        name,
        passed: false,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::protocol::{DiagnosticFields, PROTOCOL_VERSION};

    use super::*;

    fn launch() -> LaunchIdentity {
        LaunchIdentity {
            executable: "/bin/simferret-workload-fixture".into(),
            arguments: vec!["/bin/simferret-workload-fixture".into()],
            environment: vec!["MODE=acceptance".into()],
            working_directory: "/".into(),
            uid: 65534,
            gid: 65534,
        }
    }

    fn scenario() -> WorkloadScenario {
        WorkloadScenario {
            version: crate::scenario::WORKLOAD_SCENARIO_VERSION,
            name: "workload-network-outage".into(),
            request_count: 4,
            payload_bytes: 2,
            fixture_peer: "10.0.2.2".into(),
            outage_event_bound: 8,
            liveness_event_bound: 8,
            corrupt_responses: false,
        }
    }

    /// The seeded plan the passing fixture is built around: the fault is at
    /// request 2, activation at 1, and restoration at 3, so the requests are
    /// pre-outage, outage, recovery, recovery.
    fn fixed_choices() -> WorkloadChoicePlan {
        WorkloadChoicePlan {
            version: crate::scenario::WORKLOAD_CHOICE_PLAN_VERSION,
            seed: 7,
            process_fault_request_index: 2,
            outage_activation_request_index: 1,
            restoration_request_index: 3,
            requests: (0..4)
                .map(|index| PlannedRequest {
                    request_id: format!("request-{index:04}"),
                    payload: "ab".into(),
                })
                .collect(),
        }
    }

    #[derive(Default)]
    struct Builder {
        events: Vec<EventFrame>,
        next_event: u64,
        next_command: u64,
        sequences: BTreeMap<u64, u64>,
        stdout_offsets: BTreeMap<u64, u64>,
        input_offsets: BTreeMap<u64, u64>,
    }

    impl Builder {
        fn new() -> Self {
            Self {
                next_event: 1,
                next_command: 1,
                ..Self::default()
            }
        }

        fn event(&mut self, event: Event) {
            self.events.push(EventFrame {
                protocol_version: PROTOCOL_VERSION,
                event_id: self.next_event,
                command_id: self.next_command,
                event,
                diagnostics: DiagnosticFields::default(),
            });
            self.next_event += 1;
        }

        /// Start a new command group, as the host driver does for every command.
        fn begin_command(&mut self) {
            self.next_command += 1;
        }

        fn configure(&mut self) {
            self.begin_command();
            self.event(Event::NetworkConfigured {
                interface: "eth0".into(),
                guest_cidr: "10.0.2.15/24".into(),
                gateway: "10.0.2.2".into(),
            });
        }

        fn activate(&mut self) {
            self.begin_command();
            self.event(Event::OutageActivated {
                peer_cidr: "10.0.2.2/32".into(),
                rule: "prohibit 10.0.2.2/32".into(),
            });
        }

        fn restore(&mut self) {
            self.begin_command();
            self.event(Event::NetworkRestored {
                peer_cidr: "10.0.2.2/32".into(),
            });
        }

        fn output(&mut self, invocation: u64, text: &str) {
            let sequence = self.sequences.entry(invocation).or_default();
            *sequence += 1;
            let sequence = *sequence;
            let offset = self.stdout_offsets.entry(invocation).or_default();
            let start = *offset;
            *offset += text.len() as u64;
            self.event(Event::WorkloadOutput {
                invocation,
                stream: OutputStream::Stdout,
                offset: start,
                sequence,
                bytes: crate::protocol::encode_bytes(text.as_bytes()),
            });
        }

        /// Accept one input command and answer it with one response line. The
        /// guest reports the cumulative accepted offset, exactly as the runtime
        /// does.
        fn command(&mut self, invocation: u64, response: &str) {
            self.begin_command();
            let offset = {
                let offset = self.input_offsets.entry(invocation).or_default();
                *offset += 8;
                *offset
            };
            self.event(Event::InputAccepted {
                invocation,
                offset,
                bytes: 8,
                eof: false,
            });
            self.output(invocation, response);
        }

        fn start(&mut self, invocation: u64) {
            self.begin_command();
            self.event(Event::WorkloadStarted {
                invocation,
                launch: launch(),
            });
            self.output(invocation, &format!("{READY_LINE}\n"));
        }

        fn terminate(&mut self, invocation: u64, reaped: u64) {
            self.begin_command();
            self.event(Event::TerminationRequested {
                invocation,
                signal: TERMINATION_SIGNAL,
            });
            self.exit(
                invocation,
                ProcessExit::Signaled {
                    signal: TERMINATION_SIGNAL,
                },
                reaped,
            );
        }

        fn input_eof(&mut self, invocation: u64, reaped: u64) {
            self.begin_command();
            let offset = self.input_offsets.get(&invocation).copied().unwrap_or(0);
            self.event(Event::InputAccepted {
                invocation,
                offset,
                bytes: 0,
                eof: true,
            });
            self.exit(invocation, ProcessExit::Exited { code: 0 }, reaped);
        }

        fn exit(&mut self, invocation: u64, exit: ProcessExit, reaped: u64) {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let mut frames = 0_u64;
            for frame in &self.events {
                if let Event::WorkloadOutput {
                    invocation: existing,
                    stream,
                    bytes,
                    ..
                } = &frame.event
                    && *existing == invocation
                {
                    frames += 1;
                    let data = crate::protocol::decode_bytes(bytes, 1024).unwrap();
                    match stream {
                        OutputStream::Stdout => stdout.extend_from_slice(&data),
                        OutputStream::Stderr => stderr.extend_from_slice(&data),
                    }
                }
            }
            self.event(Event::WorkloadExited {
                invocation,
                exit,
                stdout_bytes: stdout.len() as u64,
                stdout_sha256: sha256(&stdout),
                stderr_bytes: stderr.len() as u64,
                stderr_sha256: sha256(&stderr),
                frames,
            });
            self.event(Event::CleanupComplete { invocation, reaped });
        }
    }

    fn passing_events(choices: &WorkloadChoicePlan) -> Vec<EventFrame> {
        passing_events_with(choices, false)
    }

    /// The passing fixture. When `restore_early` is set the network is restored
    /// immediately after activation, so both outage responses arrive after the
    /// restoration and the controlled-outage property must fail.
    fn passing_events_with(choices: &WorkloadChoicePlan, restore_early: bool) -> Vec<EventFrame> {
        let mut builder = Builder::new();
        builder.configure();
        builder.start(1);
        builder.command(1, &format!("echo value={}\n", echo_token(choices.seed, 1)));
        builder.command(1, &format!("{FRESH_STATE_LINE}\n"));
        builder.command(
            1,
            &format!(
                "{}\n",
                expected_network_line(&choices.requests[0], RequestPhase::PreOutage)
            ),
        );
        builder.activate();
        if restore_early {
            builder.restore();
        }
        builder.command(
            1,
            &format!(
                "{}\n",
                expected_network_line(&choices.requests[1], RequestPhase::Outage)
            ),
        );
        builder.command(1, &format!("{ESCAPED_DESCENDANT_LINE}\n"));
        builder.terminate(1, 2);
        builder.start(2);
        builder.command(2, &format!("echo value={}\n", echo_token(choices.seed, 2)));
        builder.command(2, &format!("{FRESH_STATE_LINE}\n"));
        builder.command(
            2,
            &format!(
                "{}\n",
                expected_network_line(&choices.requests[2], RequestPhase::Outage)
            ),
        );
        if !restore_early {
            builder.restore();
        }
        builder.command(
            2,
            &format!(
                "{}\n",
                expected_network_line(&choices.requests[3], RequestPhase::Recovery)
            ),
        );
        builder.input_eof(2, 1);
        builder.events
    }

    /// Recompute one invocation's exit record from its recorded output frames, so
    /// a test can change the frames without tripping the totals check first.
    fn recompute_exit(events: &mut [EventFrame], invocation: u64) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut frames = 0_u64;
        for frame in events.iter() {
            if let Event::WorkloadOutput {
                invocation: existing,
                stream,
                bytes,
                ..
            } = &frame.event
                && *existing == invocation
            {
                frames += 1;
                let data = crate::protocol::decode_bytes(bytes, 1024).unwrap();
                match stream {
                    OutputStream::Stdout => stdout.extend_from_slice(&data),
                    OutputStream::Stderr => stderr.extend_from_slice(&data),
                }
            }
        }
        let frame = events
            .iter_mut()
            .find(|frame| matches!(frame.event, Event::WorkloadExited { invocation: existing, .. } if existing == invocation))
            .expect("the invocation has an exit record");
        if let Event::WorkloadExited {
            stdout_bytes,
            stdout_sha256,
            stderr_bytes,
            stderr_sha256,
            frames: recorded,
            ..
        } = &mut frame.event
        {
            *stdout_bytes = stdout.len() as u64;
            *stdout_sha256 = sha256(&stdout);
            *stderr_bytes = stderr.len() as u64;
            *stderr_sha256 = sha256(&stderr);
            *recorded = frames;
        }
    }

    /// Rewrite the first output frame whose decoded bytes equal `from`.
    fn rewrite(events: &mut [EventFrame], from: &[u8], to: &[u8]) {
        let frame = events
            .iter_mut()
            .find(|frame| {
                matches!(
                    &frame.event,
                    Event::WorkloadOutput { bytes, .. }
                        if crate::protocol::decode_bytes(bytes, 1024).unwrap() == from
                )
            })
            .expect("the fixture emits the rewritten line");
        if let Event::WorkloadOutput { bytes, .. } = &mut frame.event {
            *bytes = crate::protocol::encode_bytes(to);
        }
    }

    /// Insert one frame before `index`, keeping event identifiers increasing.
    fn insert_event(events: &mut Vec<EventFrame>, index: usize, event: Event, command_id: u64) {
        for later in events[index..].iter_mut() {
            later.event_id += 1;
        }
        let event_id = events[index].event_id - 1;
        events.insert(
            index,
            EventFrame {
                protocol_version: PROTOCOL_VERSION,
                event_id,
                command_id,
                event,
                diagnostics: DiagnosticFields::default(),
            },
        );
    }

    /// Swap two adjacent frames and their identifiers, so the frame that moves
    /// earlier keeps the smaller identifier and the trace stays ordered.
    fn swap_and_renumber(events: &mut [EventFrame], index: usize) {
        events.swap(index, index + 1);
        let earlier = events[index + 1].event_id;
        let later = events[index].event_id;
        events[index].event_id = earlier;
        events[index + 1].event_id = later;
    }

    /// The frame index of one invocation's exit record.
    fn exit_index(events: &[EventFrame], invocation: u64) -> usize {
        events
            .iter()
            .position(|frame| {
                matches!(frame.event, Event::WorkloadExited { invocation: existing, .. } if existing == invocation)
            })
            .expect("the invocation has an exit record")
    }

    #[test]
    fn a_termination_after_cleanup_fails_process_safety() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        // A termination for an invocation that has already exited and completed
        // its cleanup cannot be part of a passing process history.
        let event_id = events.last().expect("the fixture has events").event_id + 1;
        events.push(EventFrame {
            protocol_version: PROTOCOL_VERSION,
            event_id,
            command_id: 1,
            event: Event::TerminationRequested {
                invocation: 2,
                signal: TERMINATION_SIGNAL,
            },
            diagnostics: DiagnosticFields::default(),
        });
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[0].passed, "{:#?}", report.assertions);
    }

    #[test]
    fn an_input_acknowledgement_after_termination_fails_process_safety() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        // The runtime refuses input, including end of input, once an invocation
        // is being terminated.
        let index = exit_index(&events, 1);
        insert_event(
            &mut events,
            index,
            Event::InputAccepted {
                invocation: 1,
                offset: 24,
                bytes: 0,
                eof: true,
            },
            1,
        );
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[0].passed, "{:#?}", report.assertions);
    }

    #[test]
    fn a_response_recorded_before_its_input_acknowledgement_fails_response_integrity() {
        // A response cannot answer a command the guest had not accepted yet, even
        // though moving it earlier leaves the ordered lines and the aggregate
        // acknowledgement counts unchanged.
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        let wanted = format!("{FRESH_STATE_LINE}\n");
        let index = events
            .iter()
            .position(|frame| {
                matches!(
                    &frame.event,
                    Event::WorkloadOutput { invocation: 1, bytes, .. }
                        if crate::protocol::decode_bytes(bytes, 1024).unwrap() == wanted.as_bytes()
                )
            })
            .expect("the fixture reports the first invocation's fresh state");
        assert!(
            matches!(events[index - 1].event, Event::InputAccepted { .. }),
            "{:?}",
            events[index - 1]
        );
        events.swap(index - 1, index);
        // Keep the identifiers increasing: the response keeps the earlier one.
        let earlier = events[index].event_id;
        let later = events[index - 1].event_id;
        events[index - 1].event_id = earlier;
        events[index].event_id = later;
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[1].passed, "{:#?}", report.assertions);
        assert!(
            report.assertions[1]
                .detail
                .contains("before the input command"),
            "{}",
            report.assertions[1].detail
        );
    }

    #[test]
    fn a_witness_acknowledged_before_its_transition_fails_controlled_outage() {
        // A response cannot count as an outage observation when its request was
        // accepted before the prohibition was in force, even though the response
        // line itself completed after the activation.
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        let index = events
            .iter()
            .position(|frame| matches!(frame.event, Event::OutageActivated { .. }))
            .expect("the fixture activates the outage");
        assert!(
            matches!(events[index + 1].event, Event::InputAccepted { .. }),
            "{:?}",
            events[index + 1]
        );
        swap_and_renumber(&mut events, index);
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[2].passed, "{:#?}", report.assertions);
        assert!(
            report.assertions[2].detail.contains("within"),
            "{}",
            report.assertions[2].detail
        );
    }

    #[test]
    fn a_witness_acknowledged_before_its_transition_fails_bounded_recovery() {
        // The same holds for restoration: the recovery request must have been
        // accepted after the network was restored, not merely completed after it.
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        let index = events
            .iter()
            .position(|frame| matches!(frame.event, Event::NetworkRestored { .. }))
            .expect("the fixture restores the network");
        assert!(
            matches!(events[index + 1].event, Event::InputAccepted { .. }),
            "{:?}",
            events[index + 1]
        );
        swap_and_renumber(&mut events, index);
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[4].passed, "{:#?}", report.assertions);
        assert!(
            report.assertions[4].detail.contains("within"),
            "{}",
            report.assertions[4].detail
        );
    }

    #[test]
    fn a_missing_end_of_input_fails_response_integrity() {
        // The acceptance contract ends the surviving invocation's input before it
        // stops, so a recording that omits the acknowledgement has not exercised
        // the scenario even when every response line and root witness is intact.
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        let index = events
            .iter()
            .position(|frame| {
                matches!(
                    frame.event,
                    Event::InputAccepted {
                        invocation: 2,
                        eof: true,
                        ..
                    }
                )
            })
            .expect("the fixture acknowledges invocation 2's end of input");
        events.remove(index);
        for later in events[index..].iter_mut() {
            later.event_id -= 1;
        }
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[1].passed, "{:#?}", report.assertions);
        assert!(
            report.assertions[1].detail.contains("end(s) of input"),
            "{}",
            report.assertions[1].detail
        );
    }

    #[test]
    fn a_duplicated_termination_fails_process_safety() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        let index = exit_index(&events, 1);
        insert_event(
            &mut events,
            index,
            Event::TerminationRequested {
                invocation: 1,
                signal: TERMINATION_SIGNAL,
            },
            1,
        );
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[0].passed, "{:#?}", report.assertions);
    }

    #[test]
    fn a_lifecycle_event_for_an_unknown_invocation_fails_process_safety() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        let index = exit_index(&events, 2);
        insert_event(
            &mut events,
            index,
            Event::CleanupComplete {
                invocation: 99,
                reaped: 0,
            },
            1,
        );
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[0].passed, "{:#?}", report.assertions);
    }

    #[test]
    fn a_duplicated_cleanup_barrier_fails_process_safety() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        let index = exit_index(&events, 2);
        insert_event(
            &mut events,
            index,
            Event::CleanupComplete {
                invocation: 1,
                reaped: 2,
            },
            1,
        );
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[0].passed, "{:#?}", report.assertions);
    }

    #[test]
    fn a_second_network_configuration_fails_process_safety() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        let index = events
            .iter()
            .position(|frame| matches!(frame.event, Event::WorkloadStarted { invocation: 1, .. }))
            .expect("the first invocation starts");
        insert_event(
            &mut events,
            index,
            Event::NetworkConfigured {
                interface: "lo".into(),
                guest_cidr: "10.0.2.15/24".into(),
                gateway: "10.0.2.2".into(),
            },
            1,
        );
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[0].passed, "{:#?}", report.assertions);
    }

    #[test]
    fn a_cleanup_that_reaped_nothing_fails_process_safety() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        let frame = events
            .iter_mut()
            .find(|frame| matches!(frame.event, Event::CleanupComplete { invocation: 2, .. }))
            .expect("the second invocation completes cleanup");
        if let Event::CleanupComplete { reaped, .. } = &mut frame.event {
            *reaped = 0;
        }
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[0].passed, "{:#?}", report.assertions);
    }

    #[test]
    fn a_structured_workload_run_passes_every_property() {
        let choices = fixed_choices();
        let report = evaluate_workload(&passing_events(&choices), &scenario(), &choices, &launch());
        assert!(report.passed, "{report:#?}");
        assert_eq!(
            report
                .assertions
                .iter()
                .map(|assertion| assertion.name)
                .collect::<Vec<_>>(),
            AssertionName::WORKLOAD_PROFILE
        );
    }

    #[test]
    fn a_reused_root_fails_process_safety() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        // The /tmp marker is fresh, but the first invocation's mutation of its
        // own executable survived, which only a reused workload root explains.
        rewrite(
            &mut events,
            format!("{FRESH_STATE_LINE}\n").as_bytes(),
            b"state value=fresh root=stale\n",
        );
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[0].passed);
    }

    #[test]
    fn a_corrupted_response_fails_response_integrity() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        rewrite(
            &mut events,
            b"network state=ok request=request-0003\n",
            b"network state=ok request=request-0099\n",
        );
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[1].passed);
    }

    #[test]
    fn a_descendant_that_was_not_reaped_fails_process_safety() {
        let choices = fixed_choices();
        for reaped in [0_u64, 1] {
            let mut events = passing_events(&choices);
            let frame = events
                .iter_mut()
                .find(|frame| matches!(frame.event, Event::CleanupComplete { invocation: 1, .. }))
                .expect("the first invocation completes cleanup");
            if let Event::CleanupComplete {
                reaped: recorded, ..
            } = &mut frame.event
            {
                *recorded = reaped;
            }
            let report = evaluate_workload(&events, &scenario(), &choices, &launch());
            assert!(!report.assertions[0].passed, "reaped = {reaped}");
        }
    }

    #[test]
    fn a_missing_restoration_fails_the_restoration_and_recovery_properties() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        events.retain(|frame| !matches!(frame.event, Event::NetworkRestored { .. }));
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[3].passed);
        assert!(!report.assertions[4].passed);
    }

    #[test]
    fn exit_totals_must_match_the_recorded_frames() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        let frame = events
            .iter_mut()
            .find(|frame| matches!(frame.event, Event::WorkloadExited { invocation: 2, .. }))
            .expect("the second invocation has an exit record");
        if let Event::WorkloadExited { stdout_bytes, .. } = &mut frame.event {
            *stdout_bytes += 1;
        }
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[1].passed);
    }

    #[test]
    fn a_launch_failure_cannot_satisfy_a_workload_property() {
        let choices = fixed_choices();
        let mut builder = Builder::new();
        builder.configure();
        builder.begin_command();
        builder.event(Event::LaunchFailed {
            invocation: 1,
            failure: LaunchFailure::Executable,
            detail: "could not execute the workload".into(),
        });
        let report = evaluate_workload(&builder.events, &scenario(), &choices, &launch());
        assert!(!report.passed);
        assert!(!report.assertions[0].passed, "{:#?}", report.assertions);
        assert!(
            report.assertions[0].detail.contains("launch failure"),
            "{}",
            report.assertions[0].detail
        );
    }

    /// Mutate the first invocation-1 output frame that satisfies `predicate`.
    fn mutate_output(
        events: &mut [EventFrame],
        invocation: u64,
        last: bool,
        mutate: impl Fn(&mut u64, &mut u64, &mut u64),
    ) {
        let matching = events
            .iter()
            .enumerate()
            .filter(|(_, frame)| {
                matches!(
                    &frame.event,
                    Event::WorkloadOutput { invocation: existing, .. } if *existing == invocation
                )
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let index = if last {
            *matching.last().expect("the invocation produced output")
        } else {
            matching[0]
        };
        if let Event::WorkloadOutput {
            offset, sequence, ..
        } = &mut events[index].event
        {
            mutate(offset, sequence, &mut events[index].event_id);
        }
    }

    #[test]
    fn a_sequence_that_does_not_start_at_one_fails_process_safety() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        mutate_output(&mut events, 1, false, |_, sequence, _| *sequence = 2);
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[0].passed);
    }

    #[test]
    fn a_sequence_gap_fails_process_safety() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        mutate_output(&mut events, 2, true, |_, sequence, _| *sequence = 99);
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[0].passed);
    }

    #[test]
    fn a_maximal_sequence_does_not_overflow_the_next_frame() {
        // The rejected value is retained, so the comparison against the next
        // frame cannot add to the maximum and panic instead of reporting the
        // structural violation.
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        mutate_output(&mut events, 1, false, |_, sequence, _| *sequence = u64::MAX);
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[0].passed, "{:#?}", report.assertions);
        assert!(
            report.assertions[0].detail.contains("sequence"),
            "{}",
            report.assertions[0].detail
        );
    }

    #[test]
    fn a_non_contiguous_output_offset_fails_process_safety() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        mutate_output(&mut events, 1, true, |offset, _, _| *offset += 1);
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[0].passed);
    }

    #[test]
    fn a_non_contiguous_input_offset_fails_process_safety() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        let frame = events
            .iter_mut()
            .find(|frame| {
                matches!(
                    frame.event,
                    Event::InputAccepted {
                        invocation: 2,
                        eof: false,
                        ..
                    }
                )
            })
            .expect("the second invocation accepts input");
        if let Event::InputAccepted { offset, .. } = &mut frame.event {
            *offset += 1;
        }
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[0].passed);
    }

    #[test]
    fn a_replayed_input_command_fails_process_safety() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        let commands = events
            .iter()
            .filter_map(|frame| match frame.event {
                Event::InputAccepted {
                    invocation: 1,
                    eof: false,
                    ..
                } => Some(frame.command_id),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(commands.len() >= 2);
        let replayed = commands[1];
        let frame = events
            .iter_mut()
            .find(|frame| {
                frame.command_id == replayed
                    && matches!(
                        frame.event,
                        Event::InputAccepted {
                            invocation: 1,
                            eof: false,
                            ..
                        }
                    )
            })
            .expect("the first invocation has a second input command");
        frame.command_id = commands[0];
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[0].passed);
    }

    #[test]
    fn an_unterminated_stdout_line_fails_response_integrity() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        // A complete expected line followed by a partial line: the line count is
        // unchanged, so only the pending-byte check can catch it.
        let recovery = expected_network_line(&choices.requests[3], RequestPhase::Recovery);
        rewrite(
            &mut events,
            format!("{recovery}\n").as_bytes(),
            format!("{recovery}\npartial").as_bytes(),
        );
        recompute_exit(&mut events, 2);
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[1].passed, "{report:#?}");
        assert!(
            report.assertions[1]
                .detail
                .contains("after its last complete line"),
            "{}",
            report.assertions[1].detail
        );
    }

    #[test]
    fn stderr_output_fails_response_integrity() {
        let choices = fixed_choices();
        let mut events = passing_events(&choices);
        let index = events
            .iter()
            .position(|frame| matches!(frame.event, Event::WorkloadExited { invocation: 2, .. }))
            .expect("the second invocation exits");
        let next_sequence = events
            .iter()
            .filter(|frame| matches!(&frame.event, Event::WorkloadOutput { invocation: 2, .. }))
            .count() as u64
            + 1;
        for later in events[index..].iter_mut() {
            later.event_id += 1;
        }
        let event_id = events[index].event_id - 1;
        events.insert(
            index,
            EventFrame {
                protocol_version: PROTOCOL_VERSION,
                event_id,
                command_id: events[index].command_id,
                event: Event::WorkloadOutput {
                    invocation: 2,
                    stream: OutputStream::Stderr,
                    offset: 0,
                    sequence: next_sequence,
                    bytes: crate::protocol::encode_bytes(b"fixture: truncated"),
                },
                diagnostics: DiagnosticFields::default(),
            },
        );
        recompute_exit(&mut events, 2);
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[1].passed, "{report:#?}");
        assert!(
            report.assertions[1].detail.contains("stderr byte(s)"),
            "{}",
            report.assertions[1].detail
        );
    }

    #[test]
    fn a_slow_restart_fails_bounded_recovery() {
        let choices = fixed_choices();
        // The events are the passing fixture, but the restarted invocation's first
        // answer is three events after its start, so a two-event liveness bound
        // must reject it even though the network recovery is still in bounds.
        let mut scenario = scenario();
        scenario.liveness_event_bound = 2;
        let events = passing_events(&choices);
        let report = evaluate_workload(&events, &scenario, &choices, &launch());
        assert!(report.assertions[1].passed, "{report:#?}");
        assert!(report.assertions[3].passed, "{report:#?}");
        assert!(!report.assertions[4].passed, "{report:#?}");
        assert!(
            report.assertions[4].detail.contains("restarted invocation"),
            "{}",
            report.assertions[4].detail
        );
    }

    #[test]
    fn an_outage_observed_after_restoration_fails_controlled_outage() {
        let choices = fixed_choices();
        let events = passing_events_with(&choices, true);
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(report.assertions[1].passed, "{report:#?}");
        assert!(!report.assertions[2].passed, "{report:#?}");
    }
}
