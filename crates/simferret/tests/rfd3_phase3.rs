//! RFD 3 Phase 3 acceptance: the workload-driven scenario and the host checker.
//!
//! The complete record and passive-replay pipeline is exercised end to end in
//! `run.rs`'s unit tests against a deterministic fake VM, and the checked-in
//! QEMU acceptance is `scripts/rfd3-phase3-acceptance.sh`. These tests pin the
//! public contracts both paths share: the versioned workload scenario, the
//! seeded choice plan, and the host-side checker that owns every application
//! assertion.

use simferret::assertions::AssertionName;
use simferret::checker::{evaluate_workload, expected_network_line, request_phase};
use simferret::protocol::{
    DiagnosticFields, Event, EventFrame, LaunchFailure, OutputStream, PROTOCOL_VERSION,
    RequestPhase,
};
use simferret::scenario::{
    MIN_WORKLOAD_REQUEST_COUNT, WORKLOAD_CHOICE_PLAN_VERSION, WORKLOAD_SCENARIO_VERSION,
    WorkloadScenario,
};
use simferret::workload::LaunchIdentity;

const SCENARIO: &str = "version = 1\nname = \"workload-network-outage\"\nrequest_count = 6\npayload_bytes = 8\nfixture_peer = \"10.0.2.2\"\noutage_event_bound = 8\nliveness_event_bound = 8\ncorrupt_responses = false\n";

fn scenario() -> WorkloadScenario {
    WorkloadScenario::parse(SCENARIO.as_bytes().to_vec())
        .unwrap()
        .0
}

fn launch() -> LaunchIdentity {
    LaunchIdentity {
        executable: "/bin/simferret-workload".into(),
        arguments: vec!["/bin/simferret-workload".into()],
        environment: vec!["MODE=acceptance".into()],
        working_directory: "/".into(),
        uid: 65534,
        gid: 65534,
    }
}

fn frame(event_id: u64, command_id: u64, event: Event) -> EventFrame {
    EventFrame {
        protocol_version: PROTOCOL_VERSION,
        event_id,
        command_id,
        event,
        diagnostics: DiagnosticFields::default(),
    }
}

#[test]
fn the_workload_scenario_is_versioned_strict_and_deterministically_seeded() {
    let scenario = scenario();
    assert_eq!(scenario.version, WORKLOAD_SCENARIO_VERSION);
    // Unknown fields, an out-of-range request count, and a foreign peer are all
    // refused before a run starts.
    assert!(WorkloadScenario::parse(format!("{SCENARIO}unknown = 1\n").into_bytes()).is_err());
    assert!(
        WorkloadScenario::parse(
            SCENARIO
                .replace("request_count = 6", "request_count = 3")
                .into_bytes()
        )
        .is_err()
    );
    assert!(
        WorkloadScenario::parse(SCENARIO.replace("10.0.2.2", "127.0.0.1").into_bytes()).is_err()
    );
    assert!(MIN_WORKLOAD_REQUEST_COUNT <= scenario.request_count);

    for seed in 0..64 {
        let plan = scenario.choices(seed);
        assert_eq!(plan.version, WORKLOAD_CHOICE_PLAN_VERSION);
        assert_eq!(plan.seed, seed);
        assert_eq!(plan.requests.len(), scenario.request_count);
        assert!((1..scenario.request_count).contains(&plan.process_fault_request_index));
        assert_ne!(
            plan.process_fault_request_index,
            plan.outage_activation_request_index
        );
        assert_ne!(
            plan.process_fault_request_index,
            plan.restoration_request_index
        );
        assert!(plan.outage_activation_request_index < plan.restoration_request_index);
    }
    assert_eq!(scenario.choices(42), scenario.choices(42));
    assert_ne!(scenario.choices(42), scenario.choices(43));
}

#[test]
fn the_request_phase_and_expected_response_follow_the_seeded_plan() {
    let scenario = scenario();
    let plan = scenario.choices(42);
    let activation = plan.outage_activation_request_index;
    let restoration = plan.restoration_request_index;
    for index in 0..plan.requests.len() {
        let phase = request_phase(index, activation, restoration);
        let expected = expected_network_line(&plan.requests[index], phase);
        assert!(expected.contains(&plan.requests[index].request_id));
        match phase {
            RequestPhase::Outage => {
                assert!(expected.starts_with("network state=unavailable"));
                assert!(expected.ends_with(&format!("errno={}", libc::EACCES)));
            }
            RequestPhase::PreOutage | RequestPhase::Recovery => {
                assert!(expected.starts_with("network state=ok"));
            }
        }
    }
}

#[test]
fn an_incomplete_workload_run_cannot_satisfy_any_property() {
    let scenario = scenario();
    let plan = scenario.choices(42);
    // No events at all.
    let empty = evaluate_workload(&[], &scenario, &plan, &launch());
    assert!(!empty.passed);
    assert_eq!(
        empty
            .assertions
            .iter()
            .map(|assertion| assertion.name)
            .collect::<Vec<_>>(),
        AssertionName::WORKLOAD_PROFILE
    );
    assert!(empty.assertions.iter().all(|assertion| !assertion.passed));

    // A typed launch failure is an infrastructure result, never a workload
    // property.
    let failed = evaluate_workload(
        &[frame(
            1,
            1,
            Event::LaunchFailed {
                invocation: 1,
                failure: LaunchFailure::Executable,
                detail: "could not execute the workload".into(),
            },
        )],
        &scenario,
        &plan,
        &launch(),
    );
    assert!(!failed.passed);

    // An output frame for an invocation that never started is a structural
    // violation rather than untracked bytes.
    let orphan = evaluate_workload(
        &[frame(
            1,
            1,
            Event::WorkloadOutput {
                invocation: 1,
                stream: OutputStream::Stdout,
                offset: 0,
                sequence: 1,
                bytes: simferret::protocol::encode_bytes(b"ready version=1\n"),
            },
        )],
        &scenario,
        &plan,
        &launch(),
    );
    assert!(!orphan.assertions[0].passed);
    assert!(!orphan.assertions[1].passed);
}
