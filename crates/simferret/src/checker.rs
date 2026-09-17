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
/// The fixed line the fixture emits after creating its fresh-root marker.
pub const FRESH_STATE_LINE: &str = "state value=fresh";
/// The fixed line the fixture emits if a previous invocation's root survived.
pub const STALE_STATE_LINE: &str = "state value=stale";
/// The fixed line the fixture emits once its escaped descendant is ready.
pub const ESCAPED_DESCENDANT_LINE: &str = "descendant state=escaped";

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

/// One complete output line and the event that completed it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompletedLine {
    text: String,
    event_id: u64,
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
    stdout_offset: u64,
    stderr_offset: u64,
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
        if self.frames != 0 && sequence != self.sequence + 1 {
            self.violations.push(format!(
                "invocation {invocation} sequence jumped from {} to {sequence} at event {}",
                self.sequence, frame.event_id
            ));
        }
        self.sequence = sequence;
        self.frames += 1;
        let (stream_bytes, pending, lines, current_offset) = match stream {
            OutputStream::Stdout => (
                &mut self.stdout,
                &mut self.stdout_pending,
                &mut self.stdout_lines,
                &mut self.stdout_offset,
            ),
            OutputStream::Stderr => (
                &mut self.stderr,
                &mut self.stderr_pending,
                &mut self.stderr_lines,
                &mut self.stderr_offset,
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
        pending.extend_from_slice(data);
        while let Some(index) = pending.iter().position(|byte| *byte == b'\n') {
            let line = pending.drain(..=index).collect::<Vec<u8>>();
            let text = String::from_utf8_lossy(&line[..line.len() - 1]).into_owned();
            if text.len() > MAX_RESPONSE_LINE_BYTES {
                self.violations.push(format!(
                    "invocation {invocation} {} line exceeds the response bound",
                    stream.name()
                ));
            }
            lines.push(CompletedLine {
                text,
                event_id: frame.event_id,
            });
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
}

#[derive(Debug, Clone)]
struct TerminationRecord {
    invocation: u64,
    signal: i32,
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
    configured: Option<(String, u64)>,
    invocations: BTreeMap<u64, InvocationStreams>,
    violations: Vec<String>,
}

impl WorkloadTrace {
    /// Fold one received frame into the trace. An output frame for an invocation
    /// that never started is a structural violation rather than untracked bytes.
    pub fn push(&mut self, frame: &EventFrame) {
        let event_id = frame.event_id;
        match &frame.event {
            Event::WorkloadStarted { invocation, launch } => self.starts.push(StartRecord {
                invocation: *invocation,
                launch: launch.clone(),
                event_id,
            }),
            Event::WorkloadExited {
                invocation,
                exit,
                stdout_bytes,
                stdout_sha256,
                stderr_bytes,
                stderr_sha256,
                frames,
            } => self.exits.push(ExitRecord {
                invocation: *invocation,
                exit: *exit,
                stdout_bytes: *stdout_bytes,
                stdout_sha256: stdout_sha256.clone(),
                stderr_bytes: *stderr_bytes,
                stderr_sha256: stderr_sha256.clone(),
                frames: *frames,
            }),
            Event::TerminationRequested { invocation, signal } => {
                self.terminations.push(TerminationRecord {
                    invocation: *invocation,
                    signal: *signal,
                })
            }
            Event::CleanupComplete { invocation, reaped } => self.cleanups.push(CleanupRecord {
                invocation: *invocation,
                reaped: *reaped,
                event_id,
            }),
            Event::LaunchFailed {
                invocation,
                failure,
                ..
            } => self.launch_failures.push(LaunchFailureRecord {
                invocation: *invocation,
                failure: *failure,
            }),
            Event::NetworkConfigured { gateway, .. } => {
                self.configured = Some((gateway.clone(), event_id));
            }
            Event::OutageActivated { peer_cidr, .. } => {
                self.activations.push((peer_cidr.clone(), event_id));
            }
            Event::NetworkRestored { peer_cidr } => {
                self.restorations.push((peer_cidr.clone(), event_id));
            }
            Event::WorkloadOutput {
                invocation,
                stream,
                offset,
                sequence,
                bytes,
            } => {
                let started = self
                    .starts
                    .iter()
                    .any(|start| start.invocation == *invocation);
                if !started {
                    self.violations.push(format!(
                        "output frame at event {event_id} names invocation {invocation} before it started"
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
            _ => {}
        }
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
    if let Some(violation) = trace.violations.first() {
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
    if first_cleanup.reaped == 0 {
        return failed(
            AssertionName::ProcessSafety,
            "the cleanup barrier reaped no process, so no escaped descendant was killed",
        );
    }
    if trace.starts[1].event_id <= first_cleanup.event_id {
        return failed(
            AssertionName::ProcessSafety,
            "the second invocation started before the first cleanup barrier completed",
        );
    }
    if trace.any_stdout_line(ESCAPED_DESCENDANT_LINE).is_none() {
        return failed(
            AssertionName::ProcessSafety,
            "the first invocation never reported an escaped descendant",
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
        .any(|line| line.text == STALE_STATE_LINE);
    if stale {
        return failed(
            AssertionName::ProcessSafety,
            "a restarted invocation observed the first invocation's root mutation",
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
    if let Some(violation) = trace.violations.first() {
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
    let activation = trace
        .configured
        .as_ref()
        .and_then(|(gateway, configured_id)| {
            let expected = format!("{gateway}/32");
            trace
                .activations
                .iter()
                .find(|(peer_cidr, event_id)| peer_cidr == &expected && *event_id > *configured_id)
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
        let line = trace.any_stdout_line(&wanted)?;
        (line.event_id > *activation_id
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
        Some((peer_cidr, event_id)) => passed(
            AssertionName::Restoration,
            format!("network restoration of {peer_cidr} was confirmed at event {event_id}"),
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
        let line = trace.any_stdout_line(&wanted)?;
        (line.event_id > *restoration_id
            && line.event_id - restoration_id <= scenario.liveness_event_bound)
            .then_some((line.event_id, line.event_id - restoration_id))
    });
    let bounded_recovery = match recovery {
        Some((event_id, distance)) => passed(
            AssertionName::BoundedRecovery,
            format!("the workload recovered at event {event_id} after {distance} event(s)"),
        ),
        None => failed(
            AssertionName::BoundedRecovery,
            format!(
                "no matching workload response arrived within {} event(s) of restoration",
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
        sequences: BTreeMap<u64, u64>,
    }

    impl Builder {
        fn new() -> Self {
            Self {
                next_event: 1,
                ..Self::default()
            }
        }

        fn event(&mut self, event: Event) {
            self.events.push(EventFrame {
                protocol_version: PROTOCOL_VERSION,
                event_id: self.next_event,
                command_id: 1,
                event,
                diagnostics: DiagnosticFields::default(),
            });
            self.next_event += 1;
        }

        fn output(&mut self, invocation: u64, text: &str) {
            let sequence = self.sequences.entry(invocation).or_default();
            *sequence += 1;
            let sequence = *sequence;
            let offset = self
                .events
                .iter()
                .filter_map(|frame| match &frame.event {
                    Event::WorkloadOutput {
                        invocation: existing,
                        stream: OutputStream::Stdout,
                        bytes,
                        ..
                    } if *existing == invocation => {
                        Some(crate::protocol::decode_bytes(bytes, 1024).unwrap().len())
                    }
                    _ => None,
                })
                .sum::<usize>();
            self.event(Event::WorkloadOutput {
                invocation,
                stream: OutputStream::Stdout,
                offset: offset as u64,
                sequence,
                bytes: crate::protocol::encode_bytes(text.as_bytes()),
            });
        }

        fn start(&mut self, invocation: u64) {
            self.event(Event::WorkloadStarted {
                invocation,
                launch: launch(),
            });
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
        let mut builder = Builder::new();
        builder.event(Event::NetworkConfigured {
            interface: "eth0".into(),
            guest_cidr: "10.0.2.15/24".into(),
            gateway: "10.0.2.2".into(),
        });
        builder.start(1);
        builder.output(1, &format!("{READY_LINE}\n"));
        builder.output(1, &format!("echo value={}\n", echo_token(choices.seed, 1)));
        builder.output(1, &format!("{FRESH_STATE_LINE}\n"));
        builder.event(Event::OutageActivated {
            peer_cidr: "10.0.2.2/32".into(),
            rule: "prohibit 10.0.2.2/32".into(),
        });
        builder.output(
            1,
            &format!(
                "{}\n",
                expected_network_line(&choices.requests[0], RequestPhase::PreOutage)
            ),
        );
        builder.output(
            1,
            &format!(
                "{}\n",
                expected_network_line(&choices.requests[1], RequestPhase::Outage)
            ),
        );
        builder.output(1, &format!("{ESCAPED_DESCENDANT_LINE}\n"));
        builder.event(Event::TerminationRequested {
            invocation: 1,
            signal: TERMINATION_SIGNAL,
        });
        builder.exit(
            1,
            ProcessExit::Signaled {
                signal: TERMINATION_SIGNAL,
            },
            2,
        );
        builder.start(2);
        builder.output(2, &format!("{READY_LINE}\n"));
        builder.output(2, &format!("echo value={}\n", echo_token(choices.seed, 2)));
        builder.output(2, &format!("{FRESH_STATE_LINE}\n"));
        builder.output(
            2,
            &format!(
                "{}\n",
                expected_network_line(&choices.requests[2], RequestPhase::Outage)
            ),
        );
        builder.event(Event::NetworkRestored {
            peer_cidr: "10.0.2.2/32".into(),
        });
        builder.output(
            2,
            &format!(
                "{}\n",
                expected_network_line(&choices.requests[3], RequestPhase::Recovery)
            ),
        );
        builder.exit(2, ProcessExit::Exited { code: 0 }, 1);
        builder.events
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
        rewrite(&mut events, b"state value=fresh\n", b"state value=stale\n");
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
        let mut events = passing_events(&choices);
        let frame = events
            .iter_mut()
            .find(|frame| matches!(frame.event, Event::CleanupComplete { invocation: 1, .. }))
            .expect("the first invocation completes cleanup");
        if let Event::CleanupComplete { reaped, .. } = &mut frame.event {
            *reaped = 0;
        }
        let report = evaluate_workload(&events, &scenario(), &choices, &launch());
        assert!(!report.assertions[0].passed);
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
        builder.event(Event::NetworkConfigured {
            interface: "eth0".into(),
            guest_cidr: "10.0.2.15/24".into(),
            gateway: "10.0.2.2".into(),
        });
        builder.event(Event::LaunchFailed {
            invocation: 1,
            failure: LaunchFailure::Executable,
            detail: "could not execute the workload".into(),
        });
        let report = evaluate_workload(&builder.events, &scenario(), &choices, &launch());
        assert!(!report.passed);
    }
}
