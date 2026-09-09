use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::{Compression, GzBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::assertions::{AssertionReport, evaluate};
use crate::protocol::{
    Command, CommandFrame, Event, EventFrame, NormalizedEvent, PROTOCOL_VERSION, RequestPhase,
};
use crate::scenario::{ChoicePlan, MAX_SCENARIO_SOURCE_BYTES, Scenario};
use crate::vm::{
    NetworkConfig, NetworkIdentity, QemuAdapter, RecordConfig, RunningVm, VmAdapter, VmIdentity,
    digest_fixture_entries, sha256_file, validate_replay_network_identity,
};

const MANIFEST_VERSION: u16 = 1;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_SEMANTIC_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
const MAX_DIAGNOSTIC_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
const MAX_FAILURE_LOG_BYTES: usize = 64 * 1024;
const MAX_FAILURE_TEXT_BYTES: usize = 64 * 1024;
const MAX_REPLAY_LOG_BYTES: usize = 1024 * 1024 * 1024;
const ARTIFACT_NAMES: [&str; 7] = [
    "scenario.toml",
    "choices.json",
    "replay.bin",
    "events.jsonl",
    "assertions.json",
    "logs/qemu.log",
    "logs/serial.log",
];
static IMAGE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
static RUNTIME_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct RunOptions {
    pub scenario: PathBuf,
    pub seed: u64,
    pub runs_directory: PathBuf,
    pub kernel: PathBuf,
    pub executable: PathBuf,
}

pub struct ReplayOptions {
    pub directory: PathBuf,
    pub kernel: PathBuf,
    pub executable: PathBuf,
}

#[derive(Debug)]
pub struct RunResult {
    pub run_id: String,
    pub directory: PathBuf,
    pub assertions: AssertionReport,
}

impl RunResult {
    pub fn exit_code(&self) -> i32 {
        self.assertions.exit_code()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReplayResult {
    pub run_id: String,
    pub event_count: usize,
    pub semantic_outcome_sha256: String,
    pub assertions: AssertionReport,
}

impl ReplayResult {
    pub fn exit_code(&self) -> i32 {
        self.assertions.exit_code()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u16,
    run_id: String,
    scenario_name: String,
    seed: u64,
    simferret_version: String,
    simferret_path: String,
    simferret_sha256: String,
    vm: VmIdentity,
    initial_state_sha256: String,
    semantic_outcome_sha256: String,
    artifacts: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct FailureDiagnostics {
    operation: String,
    stage: String,
    backend_mode: String,
    fixture_mode: String,
    network_status: &'static str,
    network: Option<NetworkIdentity>,
    fault_transitions: Vec<FaultTransitionDiagnostic>,
    traffic: TrafficDiagnostics,
    packet_counters: PacketCounterDiagnostics,
}

#[derive(Debug, Serialize)]
struct FaultTransitionDiagnostic {
    event_id: u64,
    transition: &'static str,
    peer_cidr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<String>,
}

#[derive(Debug, Default, Serialize)]
struct TrafficDiagnostics {
    requests_attempted: u64,
    requests_succeeded: u64,
    requests_unavailable: u64,
}

#[derive(Debug, Serialize)]
struct PacketCounterDiagnostics {
    available: bool,
    incoming: Option<u64>,
    outgoing: Option<u64>,
    reason: &'static str,
}

#[derive(Serialize)]
struct FailureReport<'a> {
    version: u16,
    error_kind: &'a str,
    error: &'a str,
    diagnostics: &'a FailureDiagnostics,
}

impl FailureDiagnostics {
    fn new(operation: &str) -> Self {
        Self {
            operation: operation.into(),
            stage: "launch".into(),
            backend_mode: operation.into(),
            fixture_mode: if operation == "record" {
                "controlled-content".into()
            } else {
                "empty-passive".into()
            },
            network_status: "not-yet-validated",
            network: None,
            fault_transitions: Vec::new(),
            traffic: TrafficDiagnostics::default(),
            packet_counters: PacketCounterDiagnostics {
                available: false,
                incoming: None,
                outgoing: None,
                reason: "the selected QEMU user backend and replay filter expose no packet-counter API",
            },
        }
    }

    fn set_network(&mut self, network: &NetworkIdentity) {
        self.network_status = "validated-local-profile";
        self.network = Some(network.clone());
    }

    fn observe(&mut self, event: &NormalizedEvent) {
        match &event.event {
            Event::OutageActivated { peer_cidr, rule } => {
                self.fault_transitions.push(FaultTransitionDiagnostic {
                    event_id: event.event_id,
                    transition: "activated",
                    peer_cidr: peer_cidr.clone(),
                    rule: Some(rule.clone()),
                });
            }
            Event::NetworkRestored { peer_cidr } => {
                self.fault_transitions.push(FaultTransitionDiagnostic {
                    event_id: event.event_id,
                    transition: "restored",
                    peer_cidr: peer_cidr.clone(),
                    rule: None,
                });
            }
            Event::RequestAttempted { .. } => self.traffic.requests_attempted += 1,
            Event::RequestSucceeded { .. } => self.traffic.requests_succeeded += 1,
            Event::RequestUnavailable { .. } => self.traffic.requests_unavailable += 1,
            _ => {}
        }
    }
}

pub fn record(options: &RunOptions) -> io::Result<RunResult> {
    if std::env::consts::OS != "linux" || std::env::consts::ARCH != "x86_64" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "record mode supports x86-64 Linux only",
        ));
    }
    let adapter = QemuAdapter::from_environment()
        .map_err(|error| dependency_failure(error, &options.runs_directory, "record"))?;
    record_with_adapter(options, &adapter)
}

pub fn replay(options: &ReplayOptions) -> io::Result<ReplayResult> {
    if std::env::consts::OS != "linux" || std::env::consts::ARCH != "x86_64" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "replay mode supports x86-64 Linux only",
        ));
    }
    let adapter = QemuAdapter::from_environment()
        .map_err(|error| replay_dependency_failure(error, options))?;
    replay_with_adapter(options, &adapter)
}

pub fn record_with_adapter(options: &RunOptions, adapter: &dyn VmAdapter) -> io::Result<RunResult> {
    record_with_adapter_and_asset_loader(options, adapter, GuestImageAssets::load)
}

fn record_with_adapter_and_asset_loader(
    options: &RunOptions,
    adapter: &dyn VmAdapter,
    load_assets: impl FnOnce() -> io::Result<GuestImageAssets>,
) -> io::Result<RunResult> {
    let assets = load_assets()
        .map_err(|error| dependency_failure(error, &options.runs_directory, "record"))?;
    record_with_adapter_and_assets(options, adapter, &assets)
}

fn record_with_adapter_and_assets(
    options: &RunOptions,
    adapter: &dyn VmAdapter,
    assets: &GuestImageAssets,
) -> io::Result<RunResult> {
    let run_id = new_run_id(options.seed)?;
    let mut staging = StagingDirectory::create(&options.runs_directory, &run_id)?;
    let mut diagnostics = FailureDiagnostics::new("record");
    diagnostics.stage = "preparation".into();
    let qmp = QmpDirectory::create(&run_id).map_err(|error| {
        failure_with_bundle(
            error,
            staging.destination.parent().expect("run root is present"),
            &run_id,
            None,
            None,
            &diagnostics,
        )
    })?;
    let attempt = (|| {
        let (scenario, scenario_source) = Scenario::read(&options.scenario)?;
        let choices = scenario.choices(options.seed);
        let image =
            build_guest_image_with_assets(&options.executable, &options.runs_directory, assets)?;
        fs::create_dir(staging.path.join("logs"))?;
        fs::write(staging.path.join("scenario.toml"), scenario_source)?;
        write_json(staging.path.join("choices.json"), &choices)?;
        let fixture_directory = staging.path.join("fixture");
        let fixture_entries = fixture_entries(&choices, scenario.corrupt_responses);
        materialize_fixture(&fixture_directory, &fixture_entries)?;
        let network = NetworkConfig::restricted_tftp_record_with_tool_digest(
            fixture_directory.clone(),
            sha256_bytes(&assets.busybox),
        )?;
        diagnostics.set_network(&network.identity);
        let config = RecordConfig {
            kernel: fs::canonicalize(&options.kernel)?,
            initramfs: image.path,
            replay_log: staging.path.join("replay.bin"),
            qmp_socket: qmp.path.join("qmp.sock"),
            serial_log: staging.path.join("logs/serial.log"),
            qemu_log: staging.path.join("logs/qemu.log"),
            network: Some(network),
        };
        diagnostics.stage = "launch".into();
        let mut vm = adapter.launch_record(&config)?;
        diagnostics.stage = "execution".into();
        let identity = vm.identity().clone();
        let (events, assertions) =
            drive_scenario(&scenario, &choices, vm.as_mut(), &mut diagnostics)?;
        diagnostics.stage = "shutdown".into();
        let status = vm.wait()?;
        if !status.success() {
            return Err(io::Error::other(format!("QEMU exited with {status}")));
        }
        diagnostics.stage = "publication".into();
        fs::remove_dir_all(fixture_directory)?;
        let event_bytes = encode_events(&events)?;
        fs::write(staging.path.join("events.jsonl"), &event_bytes)?;
        let assertion_bytes = json_bytes(&assertions)?;
        fs::write(staging.path.join("assertions.json"), &assertion_bytes)?;
        let choice_bytes = fs::read(staging.path.join("choices.json"))?;
        let scenario_bytes = fs::read(staging.path.join("scenario.toml"))?;
        let semantic_outcome_sha256 = digest_parts([
            scenario_bytes.as_slice(),
            choice_bytes.as_slice(),
            event_bytes.as_slice(),
            assertion_bytes.as_slice(),
        ]);
        let artifacts = artifact_digests(&staging.path)?;
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            run_id: run_id.clone(),
            scenario_name: scenario.name,
            seed: options.seed,
            simferret_version: env!("CARGO_PKG_VERSION").into(),
            simferret_path: options
                .executable
                .to_str()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "executable path is not UTF-8")
                })?
                .into(),
            simferret_sha256: image.executable_sha256,
            initial_state_sha256: identity.initramfs_sha256.clone(),
            semantic_outcome_sha256,
            vm: identity,
            artifacts,
        };
        write_json(staging.path.join("manifest.json"), &manifest)?;
        let directory = staging.publish()?;
        Ok(RunResult {
            run_id: run_id.clone(),
            directory,
            assertions,
        })
    })();
    attempt.map_err(|error| {
        failure_with_bundle(
            error,
            staging.destination.parent().expect("run root is present"),
            &run_id,
            Some(&staging.path),
            Some(&qmp.path),
            &diagnostics,
        )
    })
}

pub fn replay_with_adapter(
    options: &ReplayOptions,
    adapter: &dyn VmAdapter,
) -> io::Result<ReplayResult> {
    let assets =
        GuestImageAssets::load().map_err(|error| replay_dependency_failure(error, options))?;
    replay_with_adapter_and_assets(options, adapter, &assets)
}

fn replay_with_adapter_and_assets(
    options: &ReplayOptions,
    adapter: &dyn VmAdapter,
    assets: &GuestImageAssets,
) -> io::Result<ReplayResult> {
    let directory = fs::canonicalize(&options.directory)?;
    let runs_directory = directory
        .parent()
        .ok_or_else(|| invalid_data("run directory has no parent"))?;
    let bundle_id = new_failure_bundle_id("replay", "attempt");
    let mut diagnostics = FailureDiagnostics::new("replay");
    diagnostics.stage = "preflight".into();
    let runtime = QmpDirectory::create("replay-attempt").map_err(|error| {
        failure_with_bundle(error, runs_directory, &bundle_id, None, None, &diagnostics)
    })?;
    let attempt = (|| {
        fs::create_dir(runtime.path.join("logs"))?;
        let manifest: Manifest = read_json(&directory.join("manifest.json"), MAX_MANIFEST_BYTES)?;
        validate_manifest(&directory, &manifest)?;
        validate_artifacts(&directory, &manifest.artifacts)?;

        let scenario_bytes =
            read_bounded(&directory.join("scenario.toml"), MAX_SCENARIO_SOURCE_BYTES)?;
        let (scenario, scenario_bytes) = Scenario::parse(scenario_bytes)?;
        if scenario.name != manifest.scenario_name {
            return Err(invalid_data(format!(
                "scenario name differs from manifest: expected {:?}, found {:?}",
                manifest.scenario_name, scenario.name
            )));
        }
        let materialized_choices = scenario.choices(manifest.seed);
        let network = NetworkConfig::restricted_tftp_replay(
            digest_fixture_entries(&fixture_entries(
                &materialized_choices,
                scenario.corrupt_responses,
            )),
            sha256_bytes(&assets.busybox),
        );
        diagnostics.set_network(&network.identity);
        let choice_bytes =
            read_bounded(&directory.join("choices.json"), MAX_SEMANTIC_ARTIFACT_BYTES)?;
        let choices: ChoicePlan = serde_json::from_slice(&choice_bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if choices != materialized_choices {
            return Err(invalid_data(
                "recorded choice plan does not match the scenario and seed",
            ));
        }
        let expected_event_bytes =
            read_bounded(&directory.join("events.jsonl"), MAX_SEMANTIC_ARTIFACT_BYTES)?;
        let expected_events = decode_events(&expected_event_bytes)?;
        let expected_event_count = scenario
            .request_count
            .checked_mul(2)
            .and_then(|count| count.checked_add(5))
            .ok_or_else(|| invalid_data("expected event count overflowed"))?;
        if expected_events.len() != expected_event_count {
            return Err(invalid_data(format!(
                "recorded event count is inconsistent with scenario: expected {expected_event_count}, found {}",
                expected_events.len()
            )));
        }
        for (index, event) in expected_events.iter().enumerate() {
            if event.protocol_version != PROTOCOL_VERSION || event.event_id != index as u64 + 1 {
                return Err(invalid_data(format!(
                    "recorded event envelope is invalid at index {index}: {event:#?}"
                )));
            }
        }
        let expected_assertion_bytes = read_bounded(
            &directory.join("assertions.json"),
            MAX_SEMANTIC_ARTIFACT_BYTES,
        )?;
        let expected_assertions: AssertionReport =
            serde_json::from_slice(&expected_assertion_bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if !valid_report(&expected_assertions) {
            return Err(invalid_data(
                "recorded assertion report has an invalid shape",
            ));
        }
        let expected_frames = expected_events
            .iter()
            .map(|event| EventFrame {
                protocol_version: event.protocol_version,
                event_id: event.event_id,
                command_id: event.command_id,
                event: event.event.clone(),
                diagnostics: Default::default(),
            })
            .collect::<Vec<_>>();
        let evaluated_assertions = evaluate(
            &expected_frames,
            scenario.outage_event_bound,
            scenario.liveness_event_bound,
        );
        if expected_assertions != evaluated_assertions {
            return Err(invalid_data(
                "recorded assertion report does not match recorded events",
            ));
        }
        let recorded_semantic_digest = digest_parts([
            scenario_bytes.as_slice(),
            choice_bytes.as_slice(),
            expected_event_bytes.as_slice(),
            expected_assertion_bytes.as_slice(),
        ]);
        if recorded_semantic_digest != manifest.semantic_outcome_sha256 {
            return Err(invalid_data(format!(
                "recorded semantic outcome digest mismatch: expected {}, found {recorded_semantic_digest}",
                manifest.semantic_outcome_sha256
            )));
        }

        let image = build_guest_image_with_assets(&options.executable, runs_directory, assets)?;
        if image.executable_sha256 != manifest.simferret_sha256 {
            return Err(invalid_data(format!(
                "SimFerret executable digest differs from recording: expected {}, found {}",
                manifest.simferret_sha256, image.executable_sha256
            )));
        }
        if sha256_file(&image.path)? != manifest.initial_state_sha256 {
            return Err(invalid_data(
                "rebuilt initial state digest differs from recording",
            ));
        }

        let replay_log = runtime.path.join("replay.bin");
        copy_regular_file(
            &directory.join("replay.bin"),
            &replay_log,
            MAX_REPLAY_LOG_BYTES,
        )?;
        let expected_replay_digest = &manifest.artifacts["replay.bin"];
        let copied_replay_digest = sha256_file(&replay_log)?;
        if &copied_replay_digest != expected_replay_digest {
            return Err(invalid_data(format!(
                "replay log changed while preparing replay: expected {expected_replay_digest}, found {copied_replay_digest}"
            )));
        }
        if manifest.vm.network.is_none() {
            return Err(invalid_data("recording has no network identity"));
        }
        validate_replay_network_identity(&manifest.vm, Some(&network.identity))?;
        let config = RecordConfig {
            kernel: fs::canonicalize(&options.kernel)?,
            initramfs: image.path,
            replay_log,
            qmp_socket: runtime.path.join("qmp.sock"),
            serial_log: runtime.path.join("logs/serial.log"),
            qemu_log: runtime.path.join("logs/qemu.log"),
            network: Some(network),
        };
        diagnostics.stage = "launch".into();
        let mut vm = adapter.launch_replay(&config, &manifest.vm)?;
        diagnostics.stage = "execution".into();
        let (events, assertions) = drive_replay_scenario(
            &scenario,
            &choices,
            &expected_events,
            vm.as_mut(),
            &mut diagnostics,
        )?;
        diagnostics.stage = "shutdown".into();
        let status = vm.wait()?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "QEMU replay exited with {status}"
            )));
        }
        diagnostics.stage = "replay-validation".into();
        compare_events(&expected_events, &events)?;
        if assertions != expected_assertions {
            return Err(invalid_data(format!(
                "replayed assertion report diverged\nexpected: {expected_assertions:#?}\nactual: {assertions:#?}"
            )));
        }
        let event_bytes = encode_events(&events)?;
        if event_bytes != expected_event_bytes {
            return Err(invalid_data(
                "replayed normalized event encoding is not byte-identical",
            ));
        }
        let assertion_bytes = json_bytes(&assertions)?;
        if assertion_bytes != expected_assertion_bytes {
            return Err(invalid_data(
                "replayed assertion encoding is not byte-identical",
            ));
        }
        let semantic_outcome_sha256 = digest_parts([
            scenario_bytes.as_slice(),
            choice_bytes.as_slice(),
            event_bytes.as_slice(),
            assertion_bytes.as_slice(),
        ]);
        if semantic_outcome_sha256 != manifest.semantic_outcome_sha256 {
            return Err(invalid_data(format!(
                "semantic outcome digest diverged: expected {}, found {semantic_outcome_sha256}",
                manifest.semantic_outcome_sha256
            )));
        }
        Ok(ReplayResult {
            run_id: manifest.run_id.clone(),
            event_count: events.len(),
            semantic_outcome_sha256,
            assertions,
        })
    })();
    attempt.map_err(|error| {
        failure_with_bundle(
            error,
            runs_directory,
            &bundle_id,
            Some(&runtime.path),
            Some(&runtime.path),
            &diagnostics,
        )
    })
}

fn drive_scenario(
    scenario: &Scenario,
    choices: &ChoicePlan,
    vm: &mut dyn RunningVm,
    diagnostics: &mut FailureDiagnostics,
) -> io::Result<(Vec<NormalizedEvent>, AssertionReport)> {
    drive_scenario_inner(scenario, choices, vm, true, None, diagnostics)
}

fn drive_replay_scenario(
    scenario: &Scenario,
    choices: &ChoicePlan,
    expected_events: &[NormalizedEvent],
    vm: &mut dyn RunningVm,
    diagnostics: &mut FailureDiagnostics,
) -> io::Result<(Vec<NormalizedEvent>, AssertionReport)> {
    drive_scenario_inner(
        scenario,
        choices,
        vm,
        false,
        Some(expected_events),
        diagnostics,
    )
}

fn drive_scenario_inner(
    scenario: &Scenario,
    choices: &ChoicePlan,
    vm: &mut dyn RunningVm,
    send_commands: bool,
    expected_events: Option<&[NormalizedEvent]>,
    diagnostics: &mut FailureDiagnostics,
) -> io::Result<(Vec<NormalizedEvent>, AssertionReport)> {
    let mut controller = Controller::new(vm, send_commands, expected_events, diagnostics);
    controller.issue(Command::ConfigureNetwork {
        interface: "eth0".into(),
        guest_cidr: "10.0.2.15/24".into(),
        gateway: scenario.fixture_peer.clone(),
    })?;
    for (index, request) in choices.requests.iter().enumerate() {
        if index == choices.outage_activation_request_index {
            controller.issue(Command::ActivateOutage {
                peer_cidr: format!("{}/32", scenario.fixture_peer),
            })?;
        }
        if index == choices.restoration_request_index {
            controller.issue(Command::RestoreNetwork {
                peer_cidr: format!("{}/32", scenario.fixture_peer),
            })?;
        }
        let phase = if index < choices.outage_activation_request_index {
            RequestPhase::PreOutage
        } else if index < choices.restoration_request_index {
            RequestPhase::Outage
        } else {
            RequestPhase::Recovery
        };
        controller.issue(Command::Request {
            request_id: request.request_id.clone(),
            payload: request.payload.clone(),
            phase,
        })?;
    }
    let host_assertions = evaluate(
        &controller.raw_events,
        scenario.outage_event_bound,
        scenario.liveness_event_bound,
    );
    let check_events = controller.issue(Command::Check {
        outage_event_bound: scenario.outage_event_bound,
        liveness_event_bound: scenario.liveness_event_bound,
    })?;
    let guest_assertions = match &check_events[0].event {
        Event::AssertionsEvaluated { report } => report.clone(),
        event => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected assertion report, received {event:?}"),
            ));
        }
    };
    if guest_assertions != host_assertions {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "guest assertion report does not match host evaluation",
        ));
    }
    controller.issue(Command::Shutdown {})?;
    controller.vm.finish_events()?;
    if let Some(expected) = &controller.expected_events
        && controller.events.len() != expected.len()
    {
        return Err(invalid_data(format!(
            "replay ended after {} normalized events; expected {}",
            controller.events.len(),
            expected.len()
        )));
    }
    Ok((controller.events, host_assertions))
}

struct Controller<'a> {
    vm: &'a mut dyn RunningVm,
    diagnostics: &'a mut FailureDiagnostics,
    next_command_id: u64,
    next_event_id: u64,
    send_commands: bool,
    expected_events: Option<Vec<NormalizedEvent>>,
    raw_events: Vec<EventFrame>,
    events: Vec<NormalizedEvent>,
}

impl<'a> Controller<'a> {
    fn new(
        vm: &'a mut dyn RunningVm,
        send_commands: bool,
        expected_events: Option<&[NormalizedEvent]>,
        diagnostics: &'a mut FailureDiagnostics,
    ) -> Self {
        Self {
            vm,
            diagnostics,
            next_command_id: 1,
            next_event_id: 1,
            send_commands,
            expected_events: expected_events.map(<[NormalizedEvent]>::to_vec),
            raw_events: Vec::new(),
            events: Vec::new(),
        }
    }

    fn issue(&mut self, command: Command) -> io::Result<Vec<EventFrame>> {
        let command_id = self.next_command_id;
        self.next_command_id += 1;
        if self.send_commands {
            self.vm.send(&CommandFrame {
                protocol_version: PROTOCOL_VERSION,
                command_id,
                command: command.clone(),
            })?;
        }
        let expected_events = if matches!(command, Command::Request { .. }) {
            2
        } else {
            1
        };
        let mut received = Vec::with_capacity(expected_events);
        for event_index in 0..expected_events {
            let event = self.vm.receive().map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "failed receiving event {}/{} for command {command_id} ({command:?}): {error}",
                        event_index + 1,
                        expected_events
                    ),
                )
            })?;
            if event.protocol_version != PROTOCOL_VERSION
                || event.command_id != command_id
                || event.event_id != self.next_event_id
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unexpected event envelope: version={}, event_id={}, command_id={}",
                        event.protocol_version, event.event_id, event.command_id
                    ),
                ));
            }
            self.next_event_id += 1;
            validate_response(&command, event_index, &event)?;
            let normalized = event.normalize();
            self.diagnostics.observe(&normalized);
            if let Some(expected) = &self.expected_events {
                let index = self.events.len();
                match expected.get(index) {
                    Some(expected) if expected == &normalized => {}
                    Some(expected) => {
                        return Err(invalid_data(format!(
                            "normalized event divergence at index {index}\nexpected: {expected:#?}\nactual: {normalized:#?}"
                        )));
                    }
                    None => {
                        return Err(invalid_data(format!(
                            "replay produced surplus normalized event at index {index}\nactual: {normalized:#?}"
                        )));
                    }
                }
            }
            self.raw_events.push(event.clone());
            self.events.push(normalized);
            received.push(event);
        }
        Ok(received)
    }
}

fn validate_response(command: &Command, event_index: usize, frame: &EventFrame) -> io::Result<()> {
    let valid = match (command, event_index) {
        (
            Command::ConfigureNetwork {
                interface,
                guest_cidr,
                gateway,
            },
            0,
        ) => matches!(
            &frame.event,
            Event::NetworkConfigured { interface: actual_interface, guest_cidr: actual_cidr, gateway: actual_gateway }
                if actual_interface == interface && actual_cidr == guest_cidr && actual_gateway == gateway
        ),
        (Command::ActivateOutage { peer_cidr }, 0) => matches!(
            &frame.event,
            Event::OutageActivated { peer_cidr: actual, rule }
                if actual == peer_cidr && rule == &format!("prohibit {peer_cidr}")
        ),
        (Command::RestoreNetwork { peer_cidr }, 0) => matches!(
            &frame.event,
            Event::NetworkRestored { peer_cidr: actual } if actual == peer_cidr
        ),
        (
            Command::Request {
                request_id,
                payload,
                phase,
            },
            0,
        ) => matches!(&frame.event, Event::RequestAttempted {
                request_id: actual_id, payload: actual_payload, phase: actual_phase,
            } if actual_id == request_id && actual_payload == payload && actual_phase == phase),
        (
            Command::Request {
                request_id,
                payload,
                phase,
            },
            1,
        ) => {
            matches!(&frame.event,
            Event::RequestSucceeded { request_id: actual_id, request_payload, phase: actual_phase, .. }
                if actual_id == request_id && request_payload == payload && actual_phase == phase)
                || matches!(&frame.event,
            Event::RequestUnavailable { request_id: actual_id, phase: actual_phase, .. }
                if actual_id == request_id && actual_phase == phase)
        }
        (Command::Check { .. }, 0) => {
            matches!(&frame.event, Event::AssertionsEvaluated { report } if valid_report(report))
        }
        (Command::Shutdown {}, 0) => matches!(frame.event, Event::AgentStopped {}),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "event {} does not match command {command:?}: {frame:?}",
                event_index + 1
            ),
        ))
    }
}

fn valid_report(report: &AssertionReport) -> bool {
    use crate::assertions::AssertionName;

    let mut seen = [false; 4];
    for assertion in &report.assertions {
        let index = match assertion.name {
            AssertionName::Safety => 0,
            AssertionName::ControlledOutage => 1,
            AssertionName::Restoration => 2,
            AssertionName::BoundedRecovery => 3,
        };
        if seen[index] {
            return false;
        }
        seen[index] = true;
    }
    seen.into_iter().all(|value| value)
        && report.passed == report.assertions.iter().all(|assertion| assertion.passed)
}

struct StagingDirectory {
    path: PathBuf,
    destination: PathBuf,
    published: bool,
}

impl StagingDirectory {
    fn create(root: &Path, run_id: &str) -> io::Result<Self> {
        fs::create_dir_all(root)?;
        let root = fs::canonicalize(root)?;
        let destination = root.join(run_id);
        let path = root.join(format!(".{run_id}.tmp-{}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(Self {
            path,
            destination,
            published: false,
        })
    }

    fn publish(&mut self) -> io::Result<PathBuf> {
        fs::rename(&self.path, &self.destination)?;
        self.published = true;
        Ok(self.destination.clone())
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

struct QmpDirectory {
    path: PathBuf,
}

impl QmpDirectory {
    fn create(run_id: &str) -> io::Result<Self> {
        let digest = sha256_bytes(run_id.as_bytes());
        let suffix = &digest[..16];
        let counter = RUNTIME_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = Path::new("/tmp").join(format!("sf-{}-{counter}-{suffix}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self { path })
    }
}

impl Drop for QmpDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Debug)]
struct GuestImage {
    path: PathBuf,
    executable_sha256: String,
}

struct GuestImageAssets {
    busybox: Vec<u8>,
    mii: Vec<u8>,
    rtl8139cp: Vec<u8>,
}

impl GuestImageAssets {
    fn load() -> io::Result<Self> {
        let busybox = required_environment_path("SIMFERRET_BUSYBOX")?;
        let kernel_modules = required_environment_path("SIMFERRET_KERNEL_MODULES")?;
        Ok(Self {
            busybox: fs::read(busybox)?,
            mii: decompress_kernel_module(&find_kernel_module(&kernel_modules, "mii.ko.xz")?)?,
            rtl8139cp: decompress_kernel_module(&find_kernel_module(
                &kernel_modules,
                "8139cp.ko.xz",
            )?)?,
        })
    }
}

fn build_guest_image_with_assets(
    executable: &Path,
    runs_directory: &Path,
    assets: &GuestImageAssets,
) -> io::Result<GuestImage> {
    let executable_bytes = fs::read(executable)?;
    let executable_sha256 = sha256_bytes(&executable_bytes);
    if elf_has_interpreter(&executable_bytes)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "simferret must be a statically linked x86_64 Linux executable for record mode",
        ));
    }
    let mut archive = Vec::new();
    append_cpio(&mut archive, ".", 0o040755, &[])?;
    append_cpio(&mut archive, "bin", 0o040755, &[])?;
    append_cpio(&mut archive, "dev", 0o040755, &[])?;
    append_cpio(&mut archive, "modules", 0o040755, &[])?;
    append_cpio(&mut archive, "proc", 0o040755, &[])?;
    append_cpio(&mut archive, "sys", 0o040755, &[])?;
    append_cpio(&mut archive, "tmp", 0o040755, &[])?;
    append_cpio(&mut archive, "bin/busybox", 0o100755, &assets.busybox)?;
    append_cpio(&mut archive, "modules/mii.ko", 0o100644, &assets.mii)?;
    append_cpio(
        &mut archive,
        "modules/8139cp.ko",
        0o100644,
        &assets.rtl8139cp,
    )?;
    append_cpio(&mut archive, "init", 0o100755, &executable_bytes)?;
    append_cpio(&mut archive, "TRAILER!!!", 0, &[])?;

    let mut compressor = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    compressor.write_all(&archive)?;
    let compressed = compressor.finish()?;
    let digest = sha256_bytes(&compressed);
    let cache = runs_directory.join(".images");
    fs::create_dir_all(&cache)?;
    let image = cache.join(format!("{digest}.cpio.gz"));
    if image.exists() {
        if sha256_file(&image)? != digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "cached guest image failed digest verification: {}",
                    image.display()
                ),
            ));
        }
    } else {
        let temporary = cache.join(format!(
            ".{digest}.tmp-{}-{}",
            std::process::id(),
            IMAGE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut temporary_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        if let Err(error) = temporary_file
            .write_all(&compressed)
            .and_then(|()| temporary_file.sync_all())
        {
            drop(temporary_file);
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        drop(temporary_file);
        match fs::rename(&temporary, &image) {
            Ok(()) => {
                if sha256_file(&image)? != digest {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "published guest image has the wrong digest",
                    ));
                }
            }
            Err(error) if image.exists() => {
                let _ = fs::remove_file(temporary);
                if sha256_file(&image)? != digest {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "concurrent guest image cache entry has the wrong digest",
                    ));
                }
                drop(error);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(GuestImage {
        path: fs::canonicalize(image)?,
        executable_sha256,
    })
}

fn required_environment_path(name: &str) -> io::Result<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name} is not set")))
}

fn find_kernel_module(root: &Path, filename: &str) -> io::Result<PathBuf> {
    fn visit(directory: &Path, filename: &str, matches: &mut Vec<PathBuf>) -> io::Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                visit(&entry.path(), filename, matches)?;
            } else if file_type.is_file() && entry.file_name() == filename {
                matches.push(entry.path());
            }
        }
        Ok(())
    }
    let modules = root.join("lib/modules");
    let mut matches = Vec::new();
    visit(&modules, filename, &mut matches)?;
    if matches.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "expected exactly one {filename} under {}",
                modules.display()
            ),
        ));
    }
    Ok(matches.pop().unwrap())
}

fn decompress_kernel_module(path: &Path) -> io::Result<Vec<u8>> {
    let output = ProcessCommand::new("xz")
        .args(["--decompress", "--stdout"])
        .arg(path)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "could not decompress kernel module {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    if output.stdout.is_empty() || output.stdout.len() > 16 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "decompressed kernel module has an invalid size: {}",
                path.display()
            ),
        ));
    }
    Ok(output.stdout)
}

fn fixture_entries(choices: &ChoicePlan, corrupt_responses: bool) -> Vec<(String, Vec<u8>)> {
    choices
        .requests
        .iter()
        .enumerate()
        .map(|(index, request)| {
            let payload = if corrupt_responses && index == 0 {
                format!("{}-corrupted", request.payload)
            } else {
                request.payload.clone()
            };
            (
                request.request_id.clone(),
                format!("request_id={}\npayload={payload}\n", request.request_id).into_bytes(),
            )
        })
        .collect()
}

fn materialize_fixture(directory: &Path, entries: &[(String, Vec<u8>)]) -> io::Result<()> {
    fs::create_dir(directory)?;
    for (name, contents) in entries {
        fs::write(directory.join(name), contents)?;
    }
    Ok(())
}

fn elf_has_interpreter(bytes: &[u8]) -> io::Result<bool> {
    if bytes.len() < 64
        || &bytes[..4] != b"\x7fELF"
        || bytes[4] != 2
        || bytes[5] != 1
        || read_u16(bytes, 18)? != 62
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guest executable must be a little-endian x86-64 ELF binary",
        ));
    }
    let table_offset = usize::try_from(read_u64(bytes, 32)?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid ELF program table"))?;
    let entry_size = usize::from(read_u16(bytes, 54)?);
    let entry_count = usize::from(read_u16(bytes, 56)?);
    if entry_size < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid ELF program header size",
        ));
    }
    for index in 0..entry_count {
        let offset = table_offset
            .checked_add(index.checked_mul(entry_size).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid ELF program table")
            })?)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid ELF program table")
            })?;
        if read_u32(bytes, offset)? == 3 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_u16(bytes: &[u8], offset: usize) -> io::Result<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "truncated ELF binary"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "truncated ELF binary"))?;
    Ok(u32::from_le_bytes(
        value.try_into().expect("four-byte slice"),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> io::Result<u64> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "truncated ELF binary"))?;
    Ok(u64::from_le_bytes(
        value.try_into().expect("eight-byte slice"),
    ))
}

fn append_cpio(output: &mut Vec<u8>, name: &str, mode: u32, contents: &[u8]) -> io::Result<()> {
    let name_size = name.len() + 1;
    let fields = [
        1_u32,
        mode,
        0,
        0,
        1,
        0,
        u32::try_from(contents.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "initramfs file too large"))?,
        0,
        0,
        0,
        0,
        u32::try_from(name_size)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "cpio name too large"))?,
        0,
    ];
    output.extend_from_slice(b"070701");
    for field in fields {
        write!(output, "{field:08x}")?;
    }
    output.extend_from_slice(name.as_bytes());
    output.push(0);
    pad_four(output);
    output.extend_from_slice(contents);
    pad_four(output);
    Ok(())
}

fn pad_four(output: &mut Vec<u8>) {
    while !output.len().is_multiple_of(4) {
        output.push(0);
    }
}

fn artifact_digests(root: &Path) -> io::Result<BTreeMap<String, String>> {
    ARTIFACT_NAMES
        .into_iter()
        .map(|name| Ok((name.into(), sha256_file(&root.join(name))?)))
        .collect()
}

fn validate_manifest(directory: &Path, manifest: &Manifest) -> io::Result<()> {
    if manifest.version != MANIFEST_VERSION {
        return Err(invalid_data(format!(
            "unsupported manifest version {}",
            manifest.version
        )));
    }
    if !valid_run_id(&manifest.run_id) {
        return Err(invalid_data("manifest contains an invalid run ID"));
    }
    if directory.file_name() != Some(std::ffi::OsStr::new(&manifest.run_id)) {
        return Err(invalid_data(
            "manifest run ID does not match the run directory name",
        ));
    }
    if manifest.simferret_version != env!("CARGO_PKG_VERSION") {
        return Err(invalid_data(format!(
            "SimFerret version differs from recording: expected {}, found {}",
            manifest.simferret_version,
            env!("CARGO_PKG_VERSION")
        )));
    }
    if manifest.initial_state_sha256 != manifest.vm.initramfs_sha256 {
        return Err(invalid_data(
            "manifest initial state does not match VM initramfs identity",
        ));
    }
    for digest in [
        &manifest.simferret_sha256,
        &manifest.initial_state_sha256,
        &manifest.semantic_outcome_sha256,
    ] {
        if !valid_sha256(digest) {
            return Err(invalid_data("manifest contains an invalid SHA-256 digest"));
        }
    }
    Ok(())
}

fn valid_run_id(run_id: &str) -> bool {
    let Some((timestamp, seed)) = run_id
        .strip_prefix("run-")
        .and_then(|body| body.split_once('-'))
    else {
        return false;
    };
    timestamp.len() == 32
        && seed.len() == 16
        && timestamp
            .bytes()
            .chain(seed.bytes())
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_artifacts(directory: &Path, expected: &BTreeMap<String, String>) -> io::Result<()> {
    if expected.len() != ARTIFACT_NAMES.len()
        || !ARTIFACT_NAMES
            .into_iter()
            .all(|name| expected.contains_key(name))
    {
        return Err(invalid_data(
            "manifest artifact set does not match the replay contract",
        ));
    }
    for (name, digest) in expected {
        if !valid_sha256(digest) {
            return Err(invalid_data(format!(
                "manifest has an invalid digest for {name}"
            )));
        }
        let actual = sha256_regular_file(&directory.join(name), artifact_limit(name))?;
        if &actual != digest {
            return Err(invalid_data(format!(
                "artifact digest mismatch for {name}: expected {digest}, found {actual}"
            )));
        }
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, limit: usize) -> io::Result<T> {
    let bytes = read_bounded(path, limit)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn read_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    open_regular(path, limit)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        Err(invalid_data(format!(
            "artifact exceeds {limit} byte validation limit: {}",
            path.display()
        )))
    } else {
        Ok(bytes)
    }
}

fn artifact_limit(name: &str) -> usize {
    match name {
        "scenario.toml" => MAX_SCENARIO_SOURCE_BYTES,
        "choices.json" | "events.jsonl" | "assertions.json" => MAX_SEMANTIC_ARTIFACT_BYTES,
        "logs/qemu.log" | "logs/serial.log" => MAX_DIAGNOSTIC_ARTIFACT_BYTES,
        "replay.bin" => MAX_REPLAY_LOG_BYTES,
        _ => 0,
    }
}

fn open_regular(path: &Path, limit: usize) -> io::Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(invalid_data(format!(
            "replay input is not a regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > limit as u64 {
        return Err(invalid_data(format!(
            "replay input exceeds {limit} byte limit: {}",
            path.display()
        )));
    }
    Ok(file)
}

fn sha256_regular_file(path: &Path, limit: usize) -> io::Result<String> {
    let mut file = open_regular(path, limit)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_usize;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read)
            .ok_or_else(|| invalid_data("replay input size overflowed"))?;
        if total > limit {
            return Err(invalid_data(format!(
                "replay input exceeds {limit} byte limit: {}",
                path.display()
            )));
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn copy_regular_file(source: &Path, destination: &Path, limit: usize) -> io::Result<()> {
    let source_path = source;
    let source = open_regular(source_path, limit)?;
    let mut destination = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let copied = io::copy(&mut source.take(limit as u64 + 1), &mut destination)?;
    if copied > limit as u64 {
        return Err(invalid_data(format!(
            "replay input exceeds {limit} byte limit: {}",
            source_path.display()
        )));
    }
    destination.sync_all()
}

fn decode_events(bytes: &[u8]) -> io::Result<Vec<NormalizedEvent>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    text.lines()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line).map_err(|error| {
                invalid_data(format!(
                    "invalid normalized event at line {}: {error}",
                    index + 1
                ))
            })
        })
        .collect()
}

fn compare_events(expected: &[NormalizedEvent], actual: &[NormalizedEvent]) -> io::Result<()> {
    for index in 0..expected.len().max(actual.len()) {
        match (expected.get(index), actual.get(index)) {
            (Some(expected), Some(actual)) if expected == actual => {}
            (Some(expected), Some(actual)) => {
                return Err(invalid_data(format!(
                    "normalized event divergence at index {index}\nexpected: {expected:#?}\nactual: {actual:#?}"
                )));
            }
            (Some(expected), None) => {
                return Err(invalid_data(format!(
                    "replay ended before normalized event index {index}\nexpected: {expected:#?}"
                )));
            }
            (None, Some(actual)) => {
                return Err(invalid_data(format!(
                    "replay produced surplus normalized event at index {index}\nactual: {actual:#?}"
                )));
            }
            (None, None) => unreachable!(),
        }
    }
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn write_json(path: PathBuf, value: &impl Serialize) -> io::Result<()> {
    fs::write(path, json_bytes(value)?)
}

fn json_bytes(value: &impl Serialize) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn encode_events(events: &[NormalizedEvent]) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    for event in events {
        serde_json::to_writer(&mut output, event).map_err(io::Error::other)?;
        output.push(b'\n');
    }
    Ok(output)
}

fn digest_parts<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    format!("{:x}", digest.finalize())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn dependency_failure(error: io::Error, runs_directory: &Path, operation: &str) -> io::Error {
    let mut diagnostics = FailureDiagnostics::new(operation);
    diagnostics.stage = "dependency-initialization".into();
    failure_with_bundle(
        error,
        runs_directory,
        &new_failure_bundle_id(operation, "dependency"),
        None,
        None,
        &diagnostics,
    )
}

fn replay_dependency_failure(error: io::Error, options: &ReplayOptions) -> io::Error {
    let Ok(directory) = fs::canonicalize(&options.directory) else {
        return error;
    };
    let Some(runs_directory) = directory.parent() else {
        return error;
    };
    dependency_failure(error, runs_directory, "replay")
}

fn failure_with_bundle(
    error: io::Error,
    runs_directory: &Path,
    bundle_id: &str,
    diagnostic_source: Option<&Path>,
    runtime_directory: Option<&Path>,
    diagnostics: &FailureDiagnostics,
) -> io::Error {
    let kind = error.kind();
    let error_text = error.to_string();
    let detailed = match diagnostic_source {
        Some(source) => error_with_diagnostics(error, source),
        None => error,
    };
    let report = FailureReport {
        version: 1,
        error_kind: error_kind_name(kind),
        error: &error_text,
        diagnostics,
    };
    let mut message = detailed.to_string();
    match retain_failure_bundle(
        runs_directory,
        bundle_id,
        diagnostic_source,
        runtime_directory,
        &report,
    ) {
        Ok(path) => message.push_str(&format!("\nfailure bundle: {}", path.display())),
        Err(bundle_error) => {
            message.push_str(&format!(
                "\nfailed to retain failure bundle: {bundle_error}"
            ));
        }
    }
    io::Error::new(kind, message)
}

fn retain_failure_bundle(
    runs_directory: &Path,
    bundle_id: &str,
    diagnostic_source: Option<&Path>,
    runtime_directory: Option<&Path>,
    report: &FailureReport<'_>,
) -> io::Result<PathBuf> {
    let root = runs_directory.join("failures");
    fs::create_dir_all(&root)?;
    let destination = root.join(bundle_id);
    let temporary = root.join(format!(".{bundle_id}.tmp-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&temporary)?;
    let result = (|| {
        let private_paths = diagnostic_source
            .into_iter()
            .chain(runtime_directory)
            .collect::<Vec<_>>();
        let error = String::from_utf8(sanitize_diagnostic_log(
            report.error.as_bytes(),
            &private_paths,
        ))
        .expect("sanitized diagnostic text is UTF-8");
        write_json(
            temporary.join("failure.json"),
            &FailureReport {
                version: report.version,
                error_kind: report.error_kind,
                error: &error,
                diagnostics: report.diagnostics,
            },
        )?;
        let log_directory = temporary.join("logs");
        fs::create_dir(&log_directory)?;
        if let Some(diagnostic_source) = diagnostic_source {
            for name in ["qemu.log", "serial.log"] {
                let source = diagnostic_source.join("logs").join(name);
                if let Ok(bytes) = read_sanitized_log_tail(&source, &private_paths) {
                    fs::write(log_directory.join(name), bytes)?;
                }
            }
        }
        fs::rename(&temporary, &destination)?;
        Ok(destination.clone())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

fn read_sanitized_log_tail(path: &Path, private_paths: &[&Path]) -> io::Result<Vec<u8>> {
    let overlap = private_paths
        .iter()
        .filter_map(|path| path.to_str())
        .map(|path| qemu_escape_path(path).len())
        .max()
        .unwrap_or(0);
    let limit = MAX_FAILURE_LOG_BYTES
        .saturating_add(overlap)
        .saturating_add(1);
    let length = fs::metadata(path)?.len();
    let mut bytes = read_tail(path, limit)?;
    if length > bytes.len() as u64 {
        discard_partial_private_path(&mut bytes, private_paths);
    }
    Ok(sanitize_diagnostic_log(&bytes, private_paths))
}

fn discard_partial_private_path(bytes: &mut Vec<u8>, private_paths: &[&Path]) {
    let mut discard = 0;
    for path in private_paths.iter().filter_map(|path| path.to_str()) {
        for representation in [path.to_owned(), qemu_escape_path(path)] {
            for start in 0..representation.len() {
                let suffix = &representation.as_bytes()[start..];
                if bytes.starts_with(suffix) {
                    discard = discard.max(suffix.len());
                }
            }
        }
    }
    if discard > 0 && bytes.get(discard) == Some(&b'\n') {
        discard += 1;
    }
    bytes.drain(..discard);
}

fn sanitize_diagnostic_log(bytes: &[u8], private_paths: &[&Path]) -> Vec<u8> {
    let mut log = String::from_utf8_lossy(bytes).into_owned();
    for path in private_paths {
        if let Some(path) = path.to_str()
            && !path.is_empty()
        {
            log = log.replace(&qemu_escape_path(path), "<runtime-directory>");
            log = log.replace(path, "<runtime-directory>");
        }
    }
    if log.len() <= MAX_FAILURE_TEXT_BYTES {
        return log.into_bytes();
    }
    let mut start = log.len() - MAX_FAILURE_TEXT_BYTES;
    while !log.is_char_boundary(start) {
        start += 1;
    }
    log.as_bytes()[start..].to_vec()
}

fn qemu_escape_path(path: &str) -> String {
    path.replace(',', ",,")
}

fn error_kind_name(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::TimedOut => "watchdog",
        io::ErrorKind::InvalidData => "invalid-data",
        io::ErrorKind::UnexpectedEof => "early-termination",
        io::ErrorKind::BrokenPipe => "channel-failure",
        io::ErrorKind::NotFound => "not-found",
        io::ErrorKind::PermissionDenied => "permission-denied",
        _ => "infrastructure",
    }
}

fn new_failure_bundle_id(operation: &str, run_id: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("{operation}-{run_id}-{nanos:032x}")
}

fn error_with_diagnostics(error: io::Error, staging: &Path) -> io::Error {
    let mut message = error.to_string();
    for (label, path) in [
        ("qemu", staging.join("logs/qemu.log")),
        ("serial", staging.join("logs/serial.log")),
    ] {
        if let Ok(bytes) = read_tail(&path, 8 * 1024) {
            let diagnostic = String::from_utf8_lossy(&bytes);
            if !diagnostic.is_empty() {
                message.push_str(&format!("\n{label} diagnostics:\n{diagnostic}"));
            }
        }
    }
    io::Error::new(error.kind(), message)
}

fn read_tail(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let length = file.metadata()?.len();
    let start = length.saturating_sub(limit as u64);
    file.seek(SeekFrom::Start(start))?;
    let mut output = Vec::with_capacity(usize::try_from(length - start).unwrap_or(limit));
    file.take(limit as u64).read_to_end(&mut output)?;
    Ok(output)
}

fn new_run_id(seed: u64) -> io::Result<String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    Ok(format!("run-{nanos:032x}-{seed:016x}"))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::protocol::DiagnosticFields;

    struct FakeVm {
        identity: VmIdentity,
        queued: VecDeque<EventFrame>,
        history: Vec<EventFrame>,
        next_event_id: u64,
        corrupt: bool,
        running: bool,
        mismatch_request: bool,
        force_unavailable: bool,
        forged_assertions: bool,
        extra_after_shutdown: bool,
        malformed_after_shutdown: bool,
        recorded_events: Option<Arc<Mutex<Vec<EventFrame>>>>,
        playback: bool,
    }

    struct FakeAdapter {
        identity: Mutex<VmIdentity>,
        replace_executable: Option<PathBuf>,
        mismatch_request: bool,
        force_unavailable: bool,
        forged_assertions: bool,
        extra_after_shutdown: bool,
        malformed_after_shutdown: bool,
        corrupt: bool,
        recorded_events: Arc<Mutex<Vec<EventFrame>>>,
    }

    struct FailingAdapter;

    struct ArtifactFailingAdapter(FakeAdapter);

    fn synthetic_assets() -> GuestImageAssets {
        GuestImageAssets {
            busybox: b"synthetic busybox".to_vec(),
            mii: b"synthetic mii module".to_vec(),
            rtl8139cp: b"synthetic rtl8139cp module".to_vec(),
        }
    }

    fn record_with_adapter(options: &RunOptions, adapter: &dyn VmAdapter) -> io::Result<RunResult> {
        record_with_adapter_and_assets(options, adapter, &synthetic_assets())
    }

    fn replay_with_adapter(
        options: &ReplayOptions,
        adapter: &dyn VmAdapter,
    ) -> io::Result<ReplayResult> {
        replay_with_adapter_and_assets(options, adapter, &synthetic_assets())
    }

    fn build_guest_image(executable: &Path, runs_directory: &Path) -> io::Result<GuestImage> {
        build_guest_image_with_assets(executable, runs_directory, &synthetic_assets())
    }

    impl FakeAdapter {
        fn vm(&self, config: &RecordConfig, playback: bool) -> io::Result<FakeVm> {
            fs::write(&config.serial_log, b"serial diagnostics")?;
            fs::write(&config.qemu_log, b"qemu diagnostics")?;
            let mut identity = self.identity.lock().unwrap().clone();
            identity.initramfs_sha256 = sha256_file(&config.initramfs)?;
            identity.kernel.sha256 = sha256_file(&config.kernel)?;
            identity.network = config
                .network
                .as_ref()
                .map(|network| network.identity.clone());
            Ok(FakeVm {
                identity,
                queued: VecDeque::new(),
                history: Vec::new(),
                next_event_id: 1,
                corrupt: self.corrupt,
                running: false,
                mismatch_request: self.mismatch_request,
                force_unavailable: self.force_unavailable,
                forged_assertions: self.forged_assertions,
                extra_after_shutdown: self.extra_after_shutdown,
                malformed_after_shutdown: self.malformed_after_shutdown,
                recorded_events: (!playback).then(|| Arc::clone(&self.recorded_events)),
                playback,
            })
        }
    }

    impl VmAdapter for FailingAdapter {
        fn launch_record(&self, config: &RecordConfig) -> io::Result<Box<dyn RunningVm>> {
            fs::write(
                &config.qemu_log,
                format!(
                    "{}\ndistinctive startup failure",
                    config.qmp_socket.display()
                ),
            )?;
            fs::write(&config.serial_log, b"guest boot failed")?;
            Err(io::Error::other("adapter failed"))
        }

        fn launch_replay(
            &self,
            config: &RecordConfig,
            _expected_identity: &VmIdentity,
        ) -> io::Result<Box<dyn RunningVm>> {
            fs::write(
                &config.qemu_log,
                format!(
                    "{}\ndistinctive replay failure",
                    config.qmp_socket.display()
                ),
            )?;
            fs::write(&config.serial_log, b"replayed guest failed")?;
            Err(io::Error::other("replay adapter failed"))
        }
    }

    impl VmAdapter for ArtifactFailingAdapter {
        fn launch_record(&self, config: &RecordConfig) -> io::Result<Box<dyn RunningVm>> {
            fs::create_dir(config.replay_log.parent().unwrap().join("events.jsonl"))?;
            self.0.launch_record(config)
        }
    }

    impl VmAdapter for FakeAdapter {
        fn launch_record(&self, config: &RecordConfig) -> io::Result<Box<dyn RunningVm>> {
            fs::write(&config.replay_log, b"replay")?;
            if let Some(path) = &self.replace_executable {
                fs::write(path, b"replacement executable")?;
            }
            Ok(Box::new(self.vm(config, false)?))
        }

        fn launch_replay(
            &self,
            config: &RecordConfig,
            expected_identity: &VmIdentity,
        ) -> io::Result<Box<dyn RunningVm>> {
            let mut vm = self.vm(config, true)?;
            if &vm.identity != expected_identity {
                return Err(invalid_data("fake replay environment identity differs"));
            }
            let mut events = self.recorded_events.lock().unwrap().clone();
            if self.force_unavailable {
                let (request_id, phase) = match &events[2].event {
                    Event::RequestSucceeded {
                        request_id, phase, ..
                    } => (request_id.clone(), *phase),
                    event => panic!("unexpected fake event for divergence: {event:?}"),
                };
                events[2].event = Event::RequestUnavailable {
                    request_id,
                    phase,
                    error: crate::protocol::RequestError::Transport,
                    errno: None,
                };
                let report = evaluate(&events, 1, 2);
                let assertion = events
                    .iter_mut()
                    .find(|frame| matches!(frame.event, Event::AssertionsEvaluated { .. }))
                    .expect("fake recording contains assertion event");
                assertion.event = Event::AssertionsEvaluated { report };
            }
            if self.extra_after_shutdown {
                let mut extra = events.last().expect("fake recording has events").clone();
                extra.event_id += 1;
                events.push(extra);
            }
            vm.queued = events.into();
            Ok(Box::new(vm))
        }
    }

    impl FakeVm {
        fn event(&mut self, command_id: u64, event: Event) {
            let frame = EventFrame {
                protocol_version: PROTOCOL_VERSION,
                event_id: self.next_event_id,
                command_id,
                event,
                diagnostics: DiagnosticFields::default(),
            };
            self.next_event_id += 1;
            self.history.push(frame.clone());
            if let Some(recorded_events) = &self.recorded_events {
                recorded_events.lock().unwrap().push(frame.clone());
            }
            self.queued.push_back(frame);
        }
    }

    impl RunningVm for FakeVm {
        fn identity(&self) -> &VmIdentity {
            &self.identity
        }

        fn send(&mut self, frame: &CommandFrame) -> io::Result<()> {
            if self.playback {
                return Err(io::Error::other("replay wrote a live command"));
            }
            match &frame.command {
                Command::ConfigureNetwork {
                    interface,
                    guest_cidr,
                    gateway,
                } => {
                    self.running = true;
                    self.event(
                        frame.command_id,
                        Event::NetworkConfigured {
                            interface: interface.clone(),
                            guest_cidr: guest_cidr.clone(),
                            gateway: gateway.clone(),
                        },
                    );
                }
                Command::ActivateOutage { peer_cidr } => {
                    self.running = false;
                    self.event(
                        frame.command_id,
                        Event::OutageActivated {
                            peer_cidr: peer_cidr.clone(),
                            rule: format!("prohibit {peer_cidr}"),
                        },
                    );
                }
                Command::RestoreNetwork { peer_cidr } => {
                    self.running = true;
                    self.event(
                        frame.command_id,
                        Event::NetworkRestored {
                            peer_cidr: peer_cidr.clone(),
                        },
                    );
                }
                Command::Request {
                    request_id,
                    payload,
                    phase,
                } => {
                    self.event(
                        frame.command_id,
                        Event::RequestAttempted {
                            request_id: if self.mismatch_request {
                                "wrong-request".into()
                            } else {
                                request_id.clone()
                            },
                            payload: payload.clone(),
                            phase: *phase,
                        },
                    );
                    let result = if self.running && !self.force_unavailable {
                        Event::RequestSucceeded {
                            request_id: request_id.clone(),
                            request_payload: payload.clone(),
                            response_id: request_id.clone(),
                            response_payload: if self.corrupt {
                                format!("{payload}-corrupted")
                            } else {
                                payload.clone()
                            },
                            phase: *phase,
                        }
                    } else {
                        Event::RequestUnavailable {
                            request_id: request_id.clone(),
                            phase: *phase,
                            error: crate::protocol::RequestError::AdministrativeProhibited,
                            errno: Some(libc::EACCES),
                        }
                    };
                    self.event(frame.command_id, result);
                }
                Command::Check {
                    outage_event_bound,
                    liveness_event_bound,
                } => {
                    let mut report = crate::assertions::evaluate(
                        &self.history,
                        *outage_event_bound,
                        *liveness_event_bound,
                    );
                    if self.forged_assertions {
                        report.passed = true;
                        for assertion in &mut report.assertions {
                            assertion.passed = true;
                        }
                    }
                    self.event(frame.command_id, Event::AssertionsEvaluated { report });
                }
                Command::Shutdown {} => {
                    self.event(frame.command_id, Event::AgentStopped {});
                    if self.extra_after_shutdown {
                        self.event(frame.command_id, Event::AgentStopped {});
                    }
                }
            }
            Ok(())
        }

        fn receive(&mut self) -> io::Result<EventFrame> {
            self.queued
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no fake event"))
        }

        fn finish_events(&mut self) -> io::Result<()> {
            if self.malformed_after_shutdown {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed trailing frame",
                ))
            } else if self.queued.is_empty() {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "surplus fake event",
                ))
            }
        }

        fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
            Ok(std::process::ExitStatus::from_raw(0))
        }
    }

    #[test]
    fn poc_formats_remain_version_one() {
        assert_eq!(MANIFEST_VERSION, 1);
        assert_eq!(crate::protocol::PROTOCOL_VERSION, 1);
        assert_eq!(crate::scenario::SCENARIO_VERSION, 1);
        assert_eq!(crate::scenario::CHOICE_PLAN_VERSION, 1);
    }

    #[test]
    fn controller_stops_at_materialized_choice_and_checks_results() {
        let scenario = Scenario {
            version: crate::scenario::SCENARIO_VERSION,
            name: "test".into(),
            request_count: 4,
            payload_bytes: 2,
            fixture_peer: "10.0.2.2".into(),
            outage_event_bound: 1,
            liveness_event_bound: 2,
            corrupt_responses: false,
        };
        let choices = scenario.choices(42);
        let mut vm = FakeVm {
            identity: identity(),
            queued: VecDeque::new(),
            history: Vec::new(),
            next_event_id: 1,
            corrupt: false,
            running: false,
            mismatch_request: false,
            force_unavailable: false,
            forged_assertions: false,
            extra_after_shutdown: false,
            malformed_after_shutdown: false,
            recorded_events: None,
            playback: false,
        };
        let mut diagnostics = failure_diagnostics("record");
        let (events, report) =
            drive_scenario(&scenario, &choices, &mut vm, &mut diagnostics).unwrap();
        assert!(report.passed);
        assert_eq!(diagnostics.fault_transitions.len(), 2);
        assert_eq!(diagnostics.traffic.requests_attempted, 4);
        assert_eq!(
            diagnostics.traffic.requests_succeeded + diagnostics.traffic.requests_unavailable,
            4
        );
        assert!(events.iter().any(|frame| matches!(
            frame.event,
            Event::RequestUnavailable {
                phase: RequestPhase::Outage,
                ..
            }
        )));
    }

    #[test]
    fn successful_record_atomically_publishes_complete_verified_artifacts() {
        let root = std::env::temp_dir().join(format!(
            "simferret-record-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let scenario_path = root.join("scenario.toml");
        fs::write(
            &scenario_path,
            "version = 1\nname = \"test\"\nrequest_count = 4\npayload_bytes = 2\nfixture_peer = \"10.0.2.2\"\noutage_event_bound = 1\nliveness_event_bound = 2\ncorrupt_responses = false\n",
        )
        .unwrap();
        let kernel = root.join("kernel");
        fs::write(&kernel, b"kernel").unwrap();
        let executable = root.join("simferret");
        let mut elf = vec![0_u8; 64];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        fs::write(&executable, elf).unwrap();
        let captured_executable_digest = sha256_file(&executable).unwrap();
        let runs_directory = root.join("runs");
        let adapter = FakeAdapter {
            identity: Mutex::new(identity()),
            replace_executable: Some(executable.clone()),
            mismatch_request: false,
            force_unavailable: false,
            forged_assertions: false,
            extra_after_shutdown: false,
            malformed_after_shutdown: false,
            corrupt: false,
            recorded_events: Arc::new(Mutex::new(Vec::new())),
        };
        let result = record_with_adapter(
            &RunOptions {
                scenario: scenario_path,
                seed: 42,
                runs_directory: runs_directory.clone(),
                kernel,
                executable: executable.clone(),
            },
            &adapter,
        )
        .unwrap();

        assert!(result.assertions.passed);
        let manifest: Manifest =
            serde_json::from_slice(&fs::read(result.directory.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest.simferret_sha256, captured_executable_digest);
        assert_ne!(manifest.simferret_sha256, sha256_file(&executable).unwrap());
        assert!(!result.directory.join("fixture").exists());
        assert_eq!(manifest.artifacts.len(), 7);
        for (name, expected_digest) in manifest.artifacts {
            assert_eq!(
                sha256_file(&result.directory.join(name)).unwrap(),
                expected_digest
            );
        }
        assert_eq!(
            fs::read_dir(&runs_directory)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
                .count(),
            0
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn two_replays_verify_identical_semantic_artifacts() {
        let root = temporary_root("two-replays");
        let options = test_options(&root, false);
        let adapter = fake_adapter(None);
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        let replay_options = ReplayOptions {
            directory: recorded.directory.clone(),
            kernel: options.kernel.clone(),
            executable: options.executable.clone(),
        };
        let replay_log_digest = sha256_file(&recorded.directory.join("replay.bin")).unwrap();
        let first = replay_with_adapter(&replay_options, &adapter).unwrap();
        let second = replay_with_adapter(&replay_options, &adapter).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.event_count, 13);
        assert_eq!(
            first.semantic_outcome_sha256,
            serde_json::from_slice::<Manifest>(
                &fs::read(recorded.directory.join("manifest.json")).unwrap()
            )
            .unwrap()
            .semantic_outcome_sha256
        );
        assert_eq!(
            sha256_file(&recorded.directory.join("replay.bin")).unwrap(),
            replay_log_digest
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replay_rejects_every_tampered_artifact_before_launch() {
        let root = temporary_root("tampered-artifacts");
        let options = test_options(&root, false);
        let adapter = fake_adapter(None);
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        let manifest: Manifest = read_json(
            &recorded.directory.join("manifest.json"),
            MAX_MANIFEST_BYTES,
        )
        .unwrap();
        for name in ARTIFACT_NAMES {
            let path = recorded.directory.join(name);
            let original = fs::read(&path).unwrap();
            fs::write(&path, [original.as_slice(), b"tampered"].concat()).unwrap();
            let error = validate_artifacts(&recorded.directory, &manifest.artifacts).unwrap_err();
            assert!(error.to_string().contains(name), "{error}");
            fs::write(path, original).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replay_rejects_self_consistent_digests_for_inconsistent_semantics() {
        let root = temporary_root("inconsistent-semantics");
        let options = test_options(&root, false);
        let adapter = fake_adapter(None);
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        let mut manifest: Manifest = read_json(
            &recorded.directory.join("manifest.json"),
            MAX_MANIFEST_BYTES,
        )
        .unwrap();
        let mut assertions: AssertionReport = read_json(
            &recorded.directory.join("assertions.json"),
            MAX_SEMANTIC_ARTIFACT_BYTES,
        )
        .unwrap();
        assertions.passed = false;
        assertions.assertions[0].passed = false;
        assertions.assertions[0].detail = "forged failure".into();
        let assertion_bytes = json_bytes(&assertions).unwrap();
        fs::write(recorded.directory.join("assertions.json"), &assertion_bytes).unwrap();
        manifest
            .artifacts
            .insert("assertions.json".into(), sha256_bytes(&assertion_bytes));
        let scenario_bytes = fs::read(recorded.directory.join("scenario.toml")).unwrap();
        let choice_bytes = fs::read(recorded.directory.join("choices.json")).unwrap();
        let event_bytes = fs::read(recorded.directory.join("events.jsonl")).unwrap();
        manifest.semantic_outcome_sha256 = digest_parts([
            scenario_bytes.as_slice(),
            choice_bytes.as_slice(),
            event_bytes.as_slice(),
            assertion_bytes.as_slice(),
        ]);
        write_json(recorded.directory.join("manifest.json"), &manifest).unwrap();

        let error = replay_with_adapter(
            &ReplayOptions {
                directory: recorded.directory,
                kernel: options.kernel.clone(),
                executable: options.executable.clone(),
            },
            &adapter,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("assertion report does not match recorded events"),
            "{error}"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replay_reports_first_event_divergence() {
        let root = temporary_root("event-divergence");
        let options = test_options(&root, false);
        let mut adapter = fake_adapter(None);
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        adapter.force_unavailable = true;
        let error = replay_with_adapter(
            &ReplayOptions {
                directory: recorded.directory,
                kernel: options.kernel.clone(),
                executable: options.executable.clone(),
            },
            &adapter,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("normalized event divergence at index 2"),
            "{error}"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn first_replay_divergence_is_not_masked_by_surplus_output() {
        let root = temporary_root("divergence-before-surplus");
        let options = test_options(&root, false);
        let mut adapter = fake_adapter(None);
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        adapter.force_unavailable = true;
        adapter.extra_after_shutdown = true;
        let error = replay_with_adapter(
            &ReplayOptions {
                directory: recorded.directory,
                kernel: options.kernel.clone(),
                executable: options.executable.clone(),
            },
            &adapter,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("normalized event divergence at index 2"),
            "{error}"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn first_request_event_divergence_is_not_masked_by_missing_second_event() {
        let command = Command::Request {
            request_id: "request".into(),
            payload: "actual".into(),
            phase: RequestPhase::PreOutage,
        };
        let actual = EventFrame {
            protocol_version: PROTOCOL_VERSION,
            event_id: 1,
            command_id: 1,
            event: Event::RequestAttempted {
                request_id: "request".into(),
                payload: "actual".into(),
                phase: RequestPhase::PreOutage,
            },
            diagnostics: DiagnosticFields::default(),
        };
        let mut expected = actual.normalize();
        let Event::RequestAttempted { payload, .. } = &mut expected.event else {
            unreachable!();
        };
        *payload = "recorded-alternate".into();
        let mut vm = fake_vm(false, false, false);
        vm.playback = true;
        vm.queued.push_back(actual);
        let mut diagnostics = failure_diagnostics("replay");
        let mut controller = Controller::new(&mut vm, false, Some(&[expected]), &mut diagnostics);
        let error = controller.issue(command).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("normalized event divergence at index 0"),
            "{error}"
        );
    }

    #[test]
    fn replay_rejects_fifo_and_device_symlink_inputs_without_blocking() {
        let fifo_root = temporary_root("fifo-manifest");
        let fifo_options = test_options(&fifo_root, false);
        let fifo_adapter = fake_adapter(None);
        let fifo_recorded = record_with_adapter(&fifo_options, &fifo_adapter).unwrap();
        let manifest_path = fifo_recorded.directory.join("manifest.json");
        fs::remove_file(&manifest_path).unwrap();
        let manifest_c = std::ffi::CString::new(manifest_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(manifest_c.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();
        let error = replay_with_adapter(
            &ReplayOptions {
                directory: fifo_recorded.directory,
                kernel: fifo_options.kernel.clone(),
                executable: fifo_options.executable.clone(),
            },
            &FailingAdapter,
        )
        .unwrap_err();
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        assert!(error.to_string().contains("not a regular file"), "{error}");
        fs::remove_dir_all(fifo_root).unwrap();

        let symlink_root = temporary_root("device-symlink");
        let symlink_options = test_options(&symlink_root, false);
        let symlink_adapter = fake_adapter(None);
        let symlink_recorded = record_with_adapter(&symlink_options, &symlink_adapter).unwrap();
        let replay_log = symlink_recorded.directory.join("replay.bin");
        fs::remove_file(&replay_log).unwrap();
        std::os::unix::fs::symlink("/dev/zero", &replay_log).unwrap();
        let started = std::time::Instant::now();
        let error = replay_with_adapter(
            &ReplayOptions {
                directory: symlink_recorded.directory,
                kernel: symlink_options.kernel.clone(),
                executable: symlink_options.executable.clone(),
            },
            &FailingAdapter,
        )
        .unwrap_err();
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        assert_ne!(error.to_string(), "replay adapter failed");
        fs::remove_dir_all(symlink_root).unwrap();
    }

    #[test]
    fn replay_errors_retain_qemu_and_serial_diagnostics() {
        let root = temporary_root("replay-diagnostics");
        let options = test_options(&root, false);
        let adapter = fake_adapter(None);
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        let error = replay_with_adapter(
            &ReplayOptions {
                directory: recorded.directory,
                kernel: options.kernel.clone(),
                executable: options.executable.clone(),
            },
            &FailingAdapter,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("distinctive replay failure"), "{message}");
        assert!(message.contains("replayed guest failed"), "{message}");
        let bundle = only_failure_bundle(&root.join("runs"));
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(bundle.join("failure.json")).unwrap()).unwrap();
        assert_eq!(report["error_kind"], "infrastructure");
        assert_eq!(report["diagnostics"]["operation"], "replay");
        assert_eq!(report["diagnostics"]["stage"], "launch");
        assert_eq!(report["diagnostics"]["backend_mode"], "replay");
        assert_eq!(report["diagnostics"]["fixture_mode"], "empty-passive");
        assert_eq!(report["diagnostics"]["packet_counters"]["available"], false);
        assert!(report["diagnostics"]["network"]["replay_filter"].is_object());
        let qemu_log = fs::read_to_string(bundle.join("logs/qemu.log")).unwrap();
        assert!(qemu_log.contains("distinctive replay failure"));
        assert!(qemu_log.contains("<runtime-directory>/qmp.sock"));
        assert!(!qemu_log.contains("/tmp/sf-"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replay_encoding_errors_retain_qemu_and_serial_diagnostics() {
        let root = temporary_root("replay-encoding-diagnostics");
        let options = test_options(&root, false);
        let adapter = fake_adapter(None);
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        let event_path = recorded.directory.join("events.jsonl");
        let event_bytes = fs::read(&event_path).unwrap();
        let reformatted_events = event_bytes
            .split_inclusive(|byte| *byte == b'\n')
            .flat_map(|line| {
                let mut line = line.to_vec();
                line.insert(line.len() - 1, b' ');
                line
            })
            .collect::<Vec<_>>();
        fs::write(&event_path, &reformatted_events).unwrap();

        let mut manifest: Manifest = read_json(
            &recorded.directory.join("manifest.json"),
            MAX_MANIFEST_BYTES,
        )
        .unwrap();
        manifest
            .artifacts
            .insert("events.jsonl".into(), sha256_bytes(&reformatted_events));
        let scenario_bytes = fs::read(recorded.directory.join("scenario.toml")).unwrap();
        let choice_bytes = fs::read(recorded.directory.join("choices.json")).unwrap();
        let assertion_bytes = fs::read(recorded.directory.join("assertions.json")).unwrap();
        manifest.semantic_outcome_sha256 = digest_parts([
            scenario_bytes.as_slice(),
            choice_bytes.as_slice(),
            reformatted_events.as_slice(),
            assertion_bytes.as_slice(),
        ]);
        write_json(recorded.directory.join("manifest.json"), &manifest).unwrap();

        let error = replay_with_adapter(
            &ReplayOptions {
                directory: recorded.directory,
                kernel: options.kernel.clone(),
                executable: options.executable.clone(),
            },
            &adapter,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("encoding is not byte-identical"),
            "{message}"
        );
        assert!(message.contains("qemu diagnostics"), "{message}");
        assert!(message.contains("serial diagnostics"), "{message}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replay_rejects_unicode_manifest_run_id_without_panicking() {
        let root = temporary_root("unicode-run-id");
        let options = test_options(&root, false);
        let adapter = fake_adapter(None);
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        let mut manifest: Manifest = read_json(
            &recorded.directory.join("manifest.json"),
            MAX_MANIFEST_BYTES,
        )
        .unwrap();
        manifest.run_id = "éaaaaaaaaaaaaaaa-0".into();
        let renamed = recorded.directory.parent().unwrap().join(&manifest.run_id);
        fs::rename(&recorded.directory, &renamed).unwrap();
        write_json(renamed.join("manifest.json"), &manifest).unwrap();
        let error = replay_with_adapter(
            &ReplayOptions {
                directory: renamed,
                kernel: options.kernel.clone(),
                executable: options.executable.clone(),
            },
            &adapter,
        )
        .unwrap_err();
        assert!(error.to_string().contains("invalid run ID"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replay_rejects_environment_identity_mismatch() {
        let root = temporary_root("identity-mismatch");
        let options = test_options(&root, false);
        let adapter = fake_adapter(None);
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        adapter.identity.lock().unwrap().qemu_version = "different QEMU".into();
        let error = replay_with_adapter(
            &ReplayOptions {
                directory: recorded.directory,
                kernel: options.kernel.clone(),
                executable: options.executable.clone(),
            },
            &adapter,
        )
        .unwrap_err();
        assert!(error.to_string().contains("environment identity differs"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replay_rejects_manifest_only_network_digest_tampering_before_launch() {
        let root = temporary_root("network-digest-tampering");
        let options = test_options(&root, false);
        let adapter = fake_adapter(None);
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        let manifest_path = recorded.directory.join("manifest.json");
        let original = fs::read(&manifest_path).unwrap();

        for field in ["fixture", "tool"] {
            let mut manifest: Manifest = serde_json::from_slice(&original).unwrap();
            let network = manifest.vm.network.as_mut().unwrap();
            if field == "fixture" {
                network.fixture.content_sha256 = "a".repeat(64);
            } else {
                network.fault.tool.sha256 = "b".repeat(64);
            }
            write_json(manifest_path.clone(), &manifest).unwrap();
            let error = replay_with_adapter(
                &ReplayOptions {
                    directory: recorded.directory.clone(),
                    kernel: options.kernel.clone(),
                    executable: options.executable.clone(),
                },
                &FailingAdapter,
            )
            .unwrap_err();
            assert!(
                !error.to_string().contains("replay adapter failed"),
                "{field} digest reached VM launch: {error}"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replay_rejects_missing_filter_and_malformed_fault_plan_before_launch() {
        let root = temporary_root("network-replay-preflight");
        let options = test_options(&root, false);
        let adapter = fake_adapter(None);
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        let manifest_path = recorded.directory.join("manifest.json");
        let original_manifest = fs::read(&manifest_path).unwrap();

        let mut manifest: Manifest = serde_json::from_slice(&original_manifest).unwrap();
        manifest.vm.network.as_mut().unwrap().replay_filter = None;
        write_json(manifest_path.clone(), &manifest).unwrap();
        let replay_options = ReplayOptions {
            directory: recorded.directory.clone(),
            kernel: options.kernel.clone(),
            executable: options.executable.clone(),
        };
        let error = replay_with_adapter(&replay_options, &FailingAdapter).unwrap_err();
        assert!(error.to_string().contains("replay_filter"), "{error}");
        assert!(!error.to_string().contains("replay adapter failed"));
        assert_eq!(failure_bundles(&options.runs_directory).len(), 1);

        fs::write(&manifest_path, original_manifest).unwrap();
        let choices_path = recorded.directory.join("choices.json");
        let mut choices: ChoicePlan =
            read_json(&choices_path, MAX_SEMANTIC_ARTIFACT_BYTES).unwrap();
        choices.restoration_request_index = choices.outage_activation_request_index;
        let choice_bytes = json_bytes(&choices).unwrap();
        fs::write(&choices_path, &choice_bytes).unwrap();
        let mut manifest: Manifest = read_json(&manifest_path, MAX_MANIFEST_BYTES).unwrap();
        manifest
            .artifacts
            .insert("choices.json".into(), sha256_bytes(&choice_bytes));
        write_json(manifest_path, &manifest).unwrap();
        let error = replay_with_adapter(&replay_options, &FailingAdapter).unwrap_err();
        assert!(error.to_string().contains("choice plan"), "{error}");
        assert!(!error.to_string().contains("replay adapter failed"));
        assert_eq!(failure_bundles(&options.runs_directory).len(), 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn record_rejects_mismatched_and_trailing_protocol_events() {
        let scenario = test_scenario(false);
        let choices = scenario.choices(42);
        for (mismatch_request, extra_after_shutdown, malformed_after_shutdown) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            let mut vm = fake_vm(
                mismatch_request,
                extra_after_shutdown,
                malformed_after_shutdown,
            );
            let mut diagnostics = failure_diagnostics("record");
            let error = drive_scenario(&scenario, &choices, &mut vm, &mut diagnostics).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn assertion_failure_is_published_and_produces_nonzero_status() {
        let root = temporary_root("assertion-failure");
        let options = test_options(&root, true);
        let mut adapter = fake_adapter(None);
        adapter.corrupt = true;
        let result = record_with_adapter(&options, &adapter).unwrap();
        assert!(!result.assertions.passed);
        assert_eq!(result.exit_code(), 1);
        assert!(result.directory.join("manifest.json").is_file());
        assert!(result.directory.join("assertions.json").is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn forged_guest_assertions_are_rejected_without_publishing() {
        let root = temporary_root("forged-assertions");
        let options = test_options(&root, true);
        let mut adapter = fake_adapter(None);
        adapter.corrupt = true;
        adapter.forged_assertions = true;
        let error = record_with_adapter(&options, &adapter).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("does not match host evaluation"));
        assert_eq!(
            fs::read_dir(&options.runs_directory)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("run-"))
                .count(),
            0
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn infrastructure_failure_reports_diagnostics_without_publishing_run() {
        let root = temporary_root("infrastructure-failure");
        let options = test_options(&root, false);
        let error = record_with_adapter(&options, &FailingAdapter).unwrap_err();
        assert!(error.to_string().contains("distinctive startup failure"));
        let bundle = only_failure_bundle(&options.runs_directory);
        assert!(error.to_string().contains(&bundle.display().to_string()));
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(bundle.join("failure.json")).unwrap()).unwrap();
        assert_eq!(report["diagnostics"]["operation"], "record");
        assert_eq!(report["diagnostics"]["backend_mode"], "record");
        assert_eq!(report["diagnostics"]["fixture_mode"], "controlled-content");
        assert_eq!(
            report["diagnostics"]["fault_transitions"],
            serde_json::json!([])
        );
        assert!(bundle.join("logs/qemu.log").is_file());
        assert!(bundle.join("logs/serial.log").is_file());
        let runs = fs::read_dir(root.join("runs")).unwrap();
        assert_eq!(
            runs.filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("run-"))
                .count(),
            0
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn execution_failure_bundle_retains_fault_transitions_and_traffic_counts() {
        let root = temporary_root("execution-failure");
        let options = test_options(&root, false);
        let mut adapter = fake_adapter(None);
        adapter.malformed_after_shutdown = true;
        let error = record_with_adapter(&options, &adapter).unwrap_err();
        assert!(error.to_string().contains("malformed trailing frame"));

        let bundle = only_failure_bundle(&options.runs_directory);
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(bundle.join("failure.json")).unwrap()).unwrap();
        assert_eq!(report["diagnostics"]["stage"], "execution");
        assert_eq!(
            report["diagnostics"]["fault_transitions"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(report["diagnostics"]["traffic"]["requests_attempted"], 4);
        assert_eq!(
            report["diagnostics"]["traffic"]["requests_succeeded"]
                .as_u64()
                .unwrap()
                + report["diagnostics"]["traffic"]["requests_unavailable"]
                    .as_u64()
                    .unwrap(),
            4
        );
        assert!(
            !options
                .runs_directory
                .join(bundle.file_name().unwrap())
                .exists()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn post_execution_artifact_failure_retains_a_bundle() {
        let root = temporary_root("artifact-publication-failure");
        let options = test_options(&root, false);
        let adapter = ArtifactFailingAdapter(fake_adapter(None));
        let error = record_with_adapter(&options, &adapter).unwrap_err();
        assert!(error.to_string().contains("Is a directory"), "{error}");
        let bundle = only_failure_bundle(&options.runs_directory);
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(bundle.join("failure.json")).unwrap()).unwrap();
        assert_eq!(report["diagnostics"]["stage"], "publication");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failure_bundle_sanitizes_escaped_and_split_paths_and_enforces_size_limits() {
        let root = temporary_root("private,name");
        let source = root.join("runtime,private");
        fs::create_dir_all(source.join("logs")).unwrap();
        let escaped = source.to_string_lossy().replace(',', ",,");
        fs::write(source.join("logs/qemu.log"), format!("path={escaped}\n")).unwrap();
        let literal = source.to_string_lossy();
        let serial_log = format!("{literal}\n").repeat(2_000);
        fs::write(source.join("logs/serial.log"), serial_log).unwrap();

        let diagnostics = failure_diagnostics("replay");
        let oversized_error = "error ".repeat(MAX_FAILURE_LOG_BYTES);
        let report = FailureReport {
            version: 1,
            error_kind: "invalid-data",
            error: &oversized_error,
            diagnostics: &diagnostics,
        };
        let bundle = retain_failure_bundle(
            &root.join("runs"),
            "bounded",
            Some(&source),
            Some(&source),
            &report,
        )
        .unwrap();
        let retained_log = fs::read(bundle.join("logs/qemu.log")).unwrap();
        assert!(retained_log.len() <= MAX_FAILURE_LOG_BYTES);
        assert!(!String::from_utf8_lossy(&retained_log).contains(&escaped));
        let retained_serial = fs::read_to_string(bundle.join("logs/serial.log")).unwrap();
        assert!(
            retained_serial
                .lines()
                .all(|line| line == "<runtime-directory>"),
            "{retained_serial}"
        );
        let expanded = sanitize_diagnostic_log(&vec![0xff; MAX_FAILURE_LOG_BYTES], &[]);
        assert!(expanded.len() <= MAX_FAILURE_LOG_BYTES);

        let multiline_path = Path::new("/tmp/private\nsecret/runtime");
        let multiline_log = format!("{}\n", multiline_path.display()).repeat(3_000);
        let multiline_log_path = source.join("logs/multiline.log");
        fs::write(&multiline_log_path, multiline_log).unwrap();
        let retained_multiline =
            read_sanitized_log_tail(&multiline_log_path, &[multiline_path]).unwrap();
        let retained_multiline = String::from_utf8(retained_multiline).unwrap();
        assert!(!retained_multiline.starts_with("secret/runtime"));
        assert!(!retained_multiline.contains("/tmp/private"));

        let retained_report = fs::read(bundle.join("failure.json")).unwrap();
        let retained_report: serde_json::Value = serde_json::from_slice(&retained_report).unwrap();
        assert!(retained_report["error"].as_str().unwrap().len() <= MAX_FAILURE_LOG_BYTES);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn report_only_bundle_does_not_read_unvalidated_recording_logs() {
        let root = temporary_root("unvalidated-replay-logs");
        let recording = root.join("recording");
        fs::create_dir_all(recording.join("logs")).unwrap();
        let fifo = recording.join("logs/qemu.log");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        std::os::unix::fs::symlink("/etc/passwd", recording.join("logs/serial.log")).unwrap();

        let diagnostics = FailureDiagnostics::new("replay");
        let report = FailureReport {
            version: 1,
            error_kind: "infrastructure",
            error: "runtime creation failed",
            diagnostics: &diagnostics,
        };
        let started = std::time::Instant::now();
        let bundle =
            retain_failure_bundle(&root.join("runs"), "report-only", None, None, &report).unwrap();
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        assert_eq!(fs::read_dir(bundle.join("logs")).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dependency_initialization_failure_retains_a_report_only_bundle() {
        let root = temporary_root("dependency-failure");
        let options = test_options(&root, false);
        let error = record_with_adapter_and_asset_loader(&options, &FailingAdapter, || {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "guest assets unavailable",
            ))
        })
        .unwrap_err();
        assert!(error.to_string().contains("guest assets unavailable"));
        let bundle = only_failure_bundle(&options.runs_directory);
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(bundle.join("failure.json")).unwrap()).unwrap();
        assert_eq!(report["diagnostics"]["stage"], "dependency-initialization");
        assert_eq!(report["diagnostics"]["network_status"], "not-yet-validated");
        assert!(report["diagnostics"]["network"].is_null());
        assert_eq!(fs::read_dir(bundle.join("logs")).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn image_cache_key_matches_content_and_corruption_is_rejected() {
        let root = temporary_root("image-cache");
        let options = test_options(&root, false);
        let image = build_guest_image(&options.executable, &options.runs_directory).unwrap();
        let digest = sha256_file(&image.path).unwrap();
        assert_eq!(
            image.path.file_stem().unwrap().to_string_lossy(),
            format!("{digest}.cpio")
        );
        fs::write(&image.path, b"corrupted cache entry").unwrap();
        assert_eq!(
            build_guest_image(&options.executable, &options.runs_directory)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn qmp_directories_are_private_and_unique() {
        let first = QmpDirectory::create("run-00000000000000001111111111111111-0000").unwrap();
        let second = QmpDirectory::create("run-00000000000000002222222222222222-0000").unwrap();
        assert_ne!(first.path, second.path);
        assert_eq!(
            fs::metadata(&first.path).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn invalid_assertion_report_shapes_are_rejected() {
        use crate::assertions::{AssertionName, AssertionResult};

        let assertion = |name, passed| AssertionResult {
            name,
            passed,
            detail: "detail".into(),
        };
        let duplicate = AssertionReport {
            passed: true,
            assertions: vec![
                assertion(AssertionName::Safety, true),
                assertion(AssertionName::Safety, true),
                assertion(AssertionName::Restoration, true),
                assertion(AssertionName::BoundedRecovery, true),
            ],
        };
        assert!(!valid_report(&duplicate));
        let inconsistent = AssertionReport {
            passed: true,
            assertions: vec![
                assertion(AssertionName::Safety, false),
                assertion(AssertionName::ControlledOutage, true),
                assertion(AssertionName::Restoration, true),
                assertion(AssertionName::BoundedRecovery, true),
            ],
        };
        assert!(!valid_report(&inconsistent));
    }

    #[test]
    fn diagnostic_reader_reads_only_the_file_tail() {
        let root = temporary_root("diagnostic-tail");
        let path = root.join("large.log");
        let mut file = fs::File::create(&path).unwrap();
        file.set_len(64 * 1024 * 1024).unwrap();
        file.seek(SeekFrom::End(-4)).unwrap();
        file.write_all(b"TAIL").unwrap();
        drop(file);
        let tail = read_tail(&path, 1024).unwrap();
        assert_eq!(tail.len(), 1024);
        assert_eq!(&tail[tail.len() - 4..], b"TAIL");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_image_builders_publish_immutable_verified_content() {
        let root = temporary_root("concurrent-images");
        let options = test_options(&root, false);
        let threads = (0..8)
            .map(|_| {
                let executable = options.executable.clone();
                let runs_directory = options.runs_directory.clone();
                std::thread::spawn(move || build_guest_image(&executable, &runs_directory).unwrap())
            })
            .collect::<Vec<_>>();
        let images = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        let expected = sha256_file(&images[0].path).unwrap();
        for image in &images {
            assert_eq!(image.path, images[0].path);
            assert_eq!(sha256_file(&image.path).unwrap(), expected);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(sha256_file(&images[0].path).unwrap(), expected);
        fs::remove_dir_all(root).unwrap();
    }

    fn temporary_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "simferret-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        root
    }

    fn test_options(root: &Path, corrupt: bool) -> RunOptions {
        let scenario = root.join("scenario.toml");
        fs::write(
            &scenario,
            format!(
                "version = 1\nname = \"test\"\nrequest_count = 4\npayload_bytes = 2\nfixture_peer = \"10.0.2.2\"\noutage_event_bound = 1\nliveness_event_bound = 2\ncorrupt_responses = {corrupt}\n"
            ),
        )
        .unwrap();
        let executable = root.join("simferret");
        let mut elf = vec![0_u8; 64];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        fs::write(&executable, elf).unwrap();
        let kernel = root.join("kernel");
        fs::write(&kernel, b"kernel").unwrap();
        RunOptions {
            scenario,
            seed: 42,
            runs_directory: root.join("runs"),
            kernel,
            executable,
        }
    }

    fn fake_adapter(replace_executable: Option<PathBuf>) -> FakeAdapter {
        FakeAdapter {
            identity: Mutex::new(identity()),
            replace_executable,
            mismatch_request: false,
            force_unavailable: false,
            forged_assertions: false,
            extra_after_shutdown: false,
            malformed_after_shutdown: false,
            corrupt: false,
            recorded_events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn failure_diagnostics(operation: &str) -> FailureDiagnostics {
        let network = NetworkConfig::restricted_tftp_replay("0".repeat(64), "1".repeat(64));
        let mut diagnostics = FailureDiagnostics::new(operation);
        diagnostics.set_network(&network.identity);
        diagnostics
    }

    fn only_failure_bundle(runs_directory: &Path) -> PathBuf {
        let bundles = failure_bundles(runs_directory);
        assert_eq!(bundles.len(), 1);
        bundles.into_iter().next().unwrap()
    }

    fn failure_bundles(runs_directory: &Path) -> Vec<PathBuf> {
        fs::read_dir(runs_directory.join("failures"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect()
    }

    fn test_scenario(corrupt: bool) -> Scenario {
        Scenario {
            version: crate::scenario::SCENARIO_VERSION,
            name: "test".into(),
            request_count: 4,
            payload_bytes: 2,
            fixture_peer: "10.0.2.2".into(),
            outage_event_bound: 1,
            liveness_event_bound: 2,
            corrupt_responses: corrupt,
        }
    }

    fn fake_vm(mismatch: bool, extra: bool, malformed: bool) -> FakeVm {
        FakeVm {
            identity: identity(),
            queued: VecDeque::new(),
            history: Vec::new(),
            next_event_id: 1,
            corrupt: false,
            running: false,
            mismatch_request: mismatch,
            force_unavailable: false,
            forged_assertions: false,
            extra_after_shutdown: extra,
            malformed_after_shutdown: malformed,
            recorded_events: None,
            playback: false,
        }
    }

    fn identity() -> VmIdentity {
        VmIdentity {
            qemu: crate::vm::FileIdentity {
                path: "qemu".into(),
                sha256: "0".repeat(64),
            },
            qemu_version: "test".into(),
            kernel: crate::vm::FileIdentity {
                path: "kernel".into(),
                sha256: "1".repeat(64),
            },
            initramfs_sha256: "2".repeat(64),
            machine: "pc-i440fx-9.2".into(),
            cpu: "qemu64".into(),
            memory_mib: 128,
            vcpus: 1,
            accelerator: "tcg".into(),
            firmware: vec![
                crate::vm::FileIdentity {
                    path: "bios".into(),
                    sha256: "3".repeat(64),
                },
                crate::vm::FileIdentity {
                    path: "linuxboot".into(),
                    sha256: "4".repeat(64),
                },
            ],
            devices: vec!["virtio-serial-pci".into()],
            network: None,
        }
    }
}
