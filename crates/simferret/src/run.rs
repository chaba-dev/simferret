use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::{Compression, GzBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::assertions::{AssertionReport, evaluate};
use crate::checker::{
    ESCAPED_DESCENDANT_LINE, FRESH_STATE_LINE, READY_LINE, WorkloadTrace, echo_token,
    evaluate_workload, expected_network_line, request_phase,
};
use crate::protocol::{
    Command, CommandFrame, Event, EventFrame, MAX_FRAME_LENGTH, MAX_STDIN_FRAME_BYTES,
    NormalizedEvent, PROTOCOL_VERSION, RequestPhase, encode_bytes,
};
use crate::scenario::{
    ChoicePlan, MAX_SCENARIO_SOURCE_BYTES, PlannedRequest, Scenario, WorkloadChoicePlan,
    WorkloadScenario,
};
use crate::vm::{
    NetworkConfig, NetworkIdentity, QemuAdapter, RecordConfig, RunningVm, VmAdapter, VmIdentity,
    digest_fixture_entries, sha256_file, validate_replay_network_identity,
};
use crate::workload::{LaunchIdentity, SourceKind};

const MANIFEST_VERSION: u16 = 1;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_SEMANTIC_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
const MAX_DIAGNOSTIC_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
const MAX_FAILURE_LOG_BYTES: usize = 64 * 1024;
const MAX_FAILURE_TEXT_BYTES: usize = 64 * 1024;
const MAX_REPLAY_LOG_BYTES: usize = 1024 * 1024 * 1024;
/// The version of the private workload lock artifact.
const WORKLOAD_LOCK_VERSION: u16 = 1;
/// The private workload lock artifact name, which is present only for a
/// workload-driven run.
const WORKLOAD_LOCK_PATH: &str = "workload.lock";
const MAX_WORKLOAD_LOCK_BYTES: usize = 1024 * 1024;
/// The single path component naming the content-addressed workload store. The
/// store lives in the runs directory so a recording and its passive replays
/// share one raw and derived closure without copying it into every run.
const WORKLOAD_STORE_NAME: &str = ".workload-store";
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
    /// The workload specification. When present the scenario is parsed as a
    /// workload-driven acceptance scenario and the packaged workload originates
    /// the recorded requests.
    pub workload: Option<PathBuf>,
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
    /// The normalized workload identity, present only for a workload-driven run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workload: Option<WorkloadIdentity>,
}

/// The normalized workload identity a run manifest records. It is derived from
/// the verified raw closure at assembly time and re-derived independently on
/// replay.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentity {
    pub source_kind: SourceKind,
    pub closure_sha256: String,
    pub canonical_digest: String,
    pub template_sha256: String,
    pub launch: LaunchIdentity,
}

/// The private workload lock artifact. It names the shared content store and the
/// complete workload identity the run was recorded with, so replay can locate
/// the raw closure without consulting a live source.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkloadLock {
    version: u16,
    store: String,
    workload: WorkloadIdentity,
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
    /// The validated peer of the run's fixed network profile. The event's own
    /// string is never copied: a diverging frame can carry any bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_cidr: Option<String>,
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
        // A fault transition is reported from the validated network profile the
        // run configured, never from the strings the guest reported: a diverging
        // frame can carry any bytes in its peer or rule field.
        let fault = self.network.as_ref().map(|network| &network.fault);
        match &event.event {
            Event::OutageActivated { .. } => {
                self.fault_transitions.push(FaultTransitionDiagnostic {
                    event_id: event.event_id,
                    transition: "activated",
                    peer_cidr: fault.map(|fault| fault.peer_cidr.clone()),
                    rule: fault.map(|fault| fault.rule.clone()),
                });
            }
            Event::NetworkRestored { .. } => {
                self.fault_transitions.push(FaultTransitionDiagnostic {
                    event_id: event.event_id,
                    transition: "restored",
                    peer_cidr: fault.map(|fault| fault.peer_cidr.clone()),
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
        let outcome = match &options.workload {
            Some(specification) => record_workload_scenario(
                options,
                adapter,
                assets,
                &staging,
                &qmp,
                &mut diagnostics,
                specification,
            )?,
            None => {
                record_network_scenario(options, adapter, assets, &staging, &qmp, &mut diagnostics)?
            }
        };
        let RecordOutcome {
            scenario_name,
            image,
            identity,
            events,
            assertions,
            workload,
        } = outcome;
        diagnostics.stage = "publication".into();
        // A published run must be replayable, so the event stream is required to
        // fit the replay artifact limit before anything is written.
        let event_bytes = encode_events(&events)?;
        if event_bytes.len() > MAX_SEMANTIC_ARTIFACT_BYTES {
            return Err(invalid_data(format!(
                "the recorded event stream is {} bytes, which exceeds the {MAX_SEMANTIC_ARTIFACT_BYTES}-byte replay limit, so the run would not be replayable",
                event_bytes.len()
            )));
        }
        write_private(staging.path.join("events.jsonl"), &event_bytes)?;
        let assertion_bytes = json_bytes(&assertions)?;
        if assertion_bytes.len() > MAX_SEMANTIC_ARTIFACT_BYTES {
            return Err(invalid_data(format!(
                "the assertion report is {} bytes, which exceeds the {MAX_SEMANTIC_ARTIFACT_BYTES}-byte replay limit",
                assertion_bytes.len()
            )));
        }
        write_private(staging.path.join("assertions.json"), &assertion_bytes)?;
        let choice_bytes = fs::read(staging.path.join("choices.json"))?;
        let scenario_bytes = fs::read(staging.path.join("scenario.toml"))?;
        let semantic_outcome_sha256 = digest_parts([
            scenario_bytes.as_slice(),
            choice_bytes.as_slice(),
            event_bytes.as_slice(),
            assertion_bytes.as_slice(),
        ]);
        let artifacts = artifact_digests(&staging.path, workload.is_some())?;
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            run_id: run_id.clone(),
            scenario_name,
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
            workload,
        };
        write_private_bounded_json(
            staging.path.join("manifest.json"),
            &manifest,
            MAX_MANIFEST_BYTES,
            "the run manifest",
        )?;
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

/// Everything the shared publication tail needs from one record attempt.
struct RecordOutcome {
    scenario_name: String,
    image: GuestImage,
    identity: VmIdentity,
    events: Vec<NormalizedEvent>,
    assertions: AssertionReport,
    workload: Option<WorkloadIdentity>,
}

/// The Phase 4 network-fixture record path. The agent originates every request.
fn record_network_scenario(
    options: &RunOptions,
    adapter: &dyn VmAdapter,
    assets: &GuestImageAssets,
    staging: &StagingDirectory,
    qmp: &QmpDirectory,
    diagnostics: &mut FailureDiagnostics,
) -> io::Result<RecordOutcome> {
    let (scenario, scenario_source) = Scenario::read(&options.scenario)?;
    let choices = scenario.choices(options.seed);
    let image =
        build_guest_image_with_assets(&options.executable, &options.runs_directory, assets, None)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(staging.path.join("logs"))?;
    write_private(staging.path.join("scenario.toml"), &scenario_source)?;
    write_private_json(staging.path.join("choices.json"), &choices)?;
    let fixture_directory = staging.path.join("fixture");
    let fixture_entries = fixture_entries(&choices.requests, scenario.corrupt_responses);
    materialize_fixture(&fixture_directory, &fixture_entries)?;
    let network = NetworkConfig::restricted_tftp_record_with_tool_digest(
        fixture_directory.clone(),
        sha256_bytes(&assets.busybox),
    )?;
    diagnostics.set_network(&network.identity);
    let config = RecordConfig {
        kernel: fs::canonicalize(&options.kernel)?,
        initramfs: image.path.clone(),
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
    let (events, assertions) = drive_scenario(&scenario, &choices, vm.as_mut(), diagnostics)?;
    diagnostics.stage = "shutdown".into();
    let status = vm.wait()?;
    if !status.success() {
        return Err(io::Error::other(format!("QEMU exited with {status}")));
    }
    fs::remove_dir_all(fixture_directory)?;
    Ok(RecordOutcome {
        scenario_name: scenario.name,
        image,
        identity,
        events,
        assertions,
        workload: None,
    })
}

/// The Phase 3 workload record path. The packaged workload originates every
/// request through recorded input commands, and its raw and derived closure is
/// published to the shared content store before QEMU starts.
fn record_workload_scenario(
    options: &RunOptions,
    adapter: &dyn VmAdapter,
    assets: &GuestImageAssets,
    staging: &StagingDirectory,
    qmp: &QmpDirectory,
    diagnostics: &mut FailureDiagnostics,
    specification: &Path,
) -> io::Result<RecordOutcome> {
    let (scenario, scenario_source) = WorkloadScenario::read(&options.scenario)?;
    let choices = scenario.choices(options.seed);
    let store = options.runs_directory.join(WORKLOAD_STORE_NAME);
    let assembled = crate::workload::assemble(specification, &store)?;
    // Re-derive the workload from the raw closure that was just published, so
    // the identity the run records is the verified one rather than an assembly
    // summary.
    let loaded = crate::workload::load(&store)?;
    let template_sha256 = sha256_bytes(&loaded.template);
    if assembled.source_kind != loaded.source_kind
        || assembled.closure_sha256 != loaded.closure_sha256
        || assembled.canonical_digest != loaded.canonical_digest
        || assembled.template_sha256 != template_sha256
        || assembled.launch != loaded.launch
    {
        return Err(invalid_data(
            "workload assembly and independent verification disagreed",
        ));
    }
    let workload = WorkloadIdentity {
        source_kind: loaded.source_kind,
        closure_sha256: loaded.closure_sha256.clone(),
        canonical_digest: loaded.canonical_digest.clone(),
        template_sha256,
        launch: loaded.launch.clone(),
    };
    validate_workload_control_frames(&loaded.launch, &choices)?;
    let image = build_guest_image_with_assets(
        &options.executable,
        &options.runs_directory,
        assets,
        Some(&loaded.template),
    )?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(staging.path.join("logs"))?;
    write_private(staging.path.join("scenario.toml"), &scenario_source)?;
    write_private_json(staging.path.join("choices.json"), &choices)?;
    write_private_bounded_json(
        staging.path.join(WORKLOAD_LOCK_PATH),
        &WorkloadLock {
            version: WORKLOAD_LOCK_VERSION,
            store: WORKLOAD_STORE_NAME.into(),
            workload: workload.clone(),
        },
        MAX_WORKLOAD_LOCK_BYTES,
        "the workload lock",
    )?;
    let fixture_directory = staging.path.join("fixture");
    let fixture_entries = fixture_entries(&choices.requests, scenario.corrupt_responses);
    materialize_fixture(&fixture_directory, &fixture_entries)?;
    let network = NetworkConfig::restricted_tftp_record_with_tool_digest(
        fixture_directory.clone(),
        sha256_bytes(&assets.busybox),
    )?;
    diagnostics.set_network(&network.identity);
    let config = RecordConfig {
        kernel: fs::canonicalize(&options.kernel)?,
        initramfs: image.path.clone(),
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
    let (events, assertions) = drive_workload_scenario(
        &scenario,
        &choices,
        &loaded.launch,
        vm.as_mut(),
        diagnostics,
    )?;
    diagnostics.stage = "shutdown".into();
    let status = vm.wait()?;
    if !status.success() {
        return Err(io::Error::other(format!("QEMU exited with {status}")));
    }
    fs::remove_dir_all(fixture_directory)?;
    Ok(RecordOutcome {
        scenario_name: scenario.name,
        image,
        identity,
        events,
        assertions,
        workload: Some(workload),
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
        if manifest.workload.is_some() != manifest.artifacts.contains_key(WORKLOAD_LOCK_PATH) {
            return Err(invalid_data(
                "the manifest workload identity and lock artifact disagree",
            ));
        }
        if manifest.workload.is_some() {
            let context = ReplayContext {
                directory: &directory,
                runs_directory,
                runtime: &runtime,
                manifest: &manifest,
            };
            return replay_workload_scenario(options, adapter, assets, &context, &mut diagnostics);
        }

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
                &materialized_choices.requests,
                scenario.corrupt_responses,
            )),
            sha256_bytes(&assets.busybox),
        );
        diagnostics.set_network(&network.identity);
        let choice_bytes =
            read_bounded(&directory.join("choices.json"), MAX_SEMANTIC_ARTIFACT_BYTES)?;
        let choices: ChoicePlan = serde_json::from_slice(&choice_bytes).map_err(|error| {
            crate::diagnostics::json_error("malformed recorded choices", &error)
        })?;
        if choices != materialized_choices {
            return Err(invalid_data(
                "recorded choice plan does not match the scenario and seed",
            ));
        }
        let (expected_events, expected_event_bytes) = read_recorded_events(&directory)?;
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
        let (expected_assertions, expected_assertion_bytes) = read_recorded_assertions(&directory)?;
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

        let image =
            build_guest_image_with_assets(&options.executable, runs_directory, assets, None)?;
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

        let replay_log = copy_replay_log(&directory, &runtime, &manifest)?;
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

/// The paths and recorded manifest one replay attempt shares.
struct ReplayContext<'a> {
    directory: &'a Path,
    runs_directory: &'a Path,
    runtime: &'a QmpDirectory,
    manifest: &'a Manifest,
}

/// The passive replay of a workload-driven recording. It re-derives the complete
/// workload from the verified raw closure, requires the raw evidence even when a
/// derived cache entry exists, rechecks the recorded scenario, choice plan, event
/// stream, and assertion report, and only then launches QEMU.
fn replay_workload_scenario(
    options: &ReplayOptions,
    adapter: &dyn VmAdapter,
    assets: &GuestImageAssets,
    context: &ReplayContext<'_>,
    diagnostics: &mut FailureDiagnostics,
) -> io::Result<ReplayResult> {
    let ReplayContext {
        directory,
        runs_directory,
        runtime,
        manifest,
    } = context;
    let recorded = manifest
        .workload
        .clone()
        .ok_or_else(|| invalid_data("recording has no workload identity"))?;
    let lock: WorkloadLock =
        read_json(&directory.join(WORKLOAD_LOCK_PATH), MAX_WORKLOAD_LOCK_BYTES)?;
    if lock.version != WORKLOAD_LOCK_VERSION {
        return Err(invalid_data(format!(
            "unsupported workload lock version {}",
            lock.version
        )));
    }
    if lock.store != WORKLOAD_STORE_NAME {
        return Err(invalid_data(
            "the workload lock names an unsupported content store",
        ));
    }
    if lock.workload != recorded {
        return Err(invalid_data(
            "the workload lock identity differs from the manifest",
        ));
    }
    // The complete raw closure is required. `load` verifies every raw object
    // against its digest, rechecks the stored-layer-to-DiffID relationships,
    // re-derives the canonical tree and template, and verifies the derived cache
    // entry against those independently computed identities.
    let store = runs_directory.join(&lock.store);
    let loaded = crate::workload::load(&store)?;
    if loaded.source_kind != recorded.source_kind
        || loaded.closure_sha256 != recorded.closure_sha256
        || loaded.canonical_digest != recorded.canonical_digest
        || loaded.launch != recorded.launch
        || sha256_bytes(&loaded.template) != recorded.template_sha256
    {
        return Err(invalid_data(
            "the re-derived workload identity differs from the recording",
        ));
    }

    let (scenario, scenario_bytes) = WorkloadScenario::parse(read_bounded(
        &directory.join("scenario.toml"),
        MAX_SCENARIO_SOURCE_BYTES,
    )?)?;
    if scenario.name != manifest.scenario_name {
        return Err(invalid_data(format!(
            "scenario name differs from manifest: expected {:?}, found {:?}",
            manifest.scenario_name, scenario.name
        )));
    }
    let materialized_choices = scenario.choices(manifest.seed);
    let network = NetworkConfig::restricted_tftp_replay(
        digest_fixture_entries(&fixture_entries(
            &materialized_choices.requests,
            scenario.corrupt_responses,
        )),
        sha256_bytes(&assets.busybox),
    );
    diagnostics.set_network(&network.identity);
    let choice_bytes = read_bounded(&directory.join("choices.json"), MAX_SEMANTIC_ARTIFACT_BYTES)?;
    let choices: WorkloadChoicePlan = serde_json::from_slice(&choice_bytes)
        .map_err(|error| crate::diagnostics::json_error("malformed recorded choices", &error))?;
    if choices != materialized_choices {
        return Err(invalid_data(
            "recorded choice plan does not match the scenario and seed",
        ));
    }
    validate_workload_control_frames(&loaded.launch, &choices)?;
    let (expected_events, expected_event_bytes) = read_recorded_events(directory)?;
    let (expected_assertions, expected_assertion_bytes) = read_recorded_assertions(directory)?;
    if !valid_profile(
        &expected_assertions,
        &crate::assertions::AssertionName::WORKLOAD_PROFILE,
    ) {
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
    let evaluated_assertions =
        evaluate_workload(&expected_frames, &scenario, &choices, &loaded.launch);
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

    let image = build_guest_image_with_assets(
        &options.executable,
        runs_directory,
        assets,
        Some(&loaded.template),
    )?;
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

    let replay_log = copy_replay_log(directory, runtime, manifest)?;
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
    let frames = replay_workload_events(&expected_events, vm.as_mut(), diagnostics)?;
    let events = frames
        .iter()
        .map(EventFrame::normalize)
        .collect::<Vec<NormalizedEvent>>();
    let assertions = evaluate_workload(&frames, &scenario, &choices, &loaded.launch);
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
}

/// Read and envelope-check the recorded normalized event stream.
fn read_recorded_events(directory: &Path) -> io::Result<(Vec<NormalizedEvent>, Vec<u8>)> {
    let expected_event_bytes =
        read_bounded(&directory.join("events.jsonl"), MAX_SEMANTIC_ARTIFACT_BYTES)?;
    let expected_events = decode_events(&expected_event_bytes)?;
    for (index, event) in expected_events.iter().enumerate() {
        if event.protocol_version != PROTOCOL_VERSION || event.event_id != index as u64 + 1 {
            return Err(invalid_data(format!(
                "recorded event envelope is invalid at index {index}: {} at event {}",
                event.event.describe(),
                event.event_id
            )));
        }
    }
    Ok((expected_events, expected_event_bytes))
}

/// Read the recorded assertion report and its exact bytes.
fn read_recorded_assertions(directory: &Path) -> io::Result<(AssertionReport, Vec<u8>)> {
    let expected_assertion_bytes = read_bounded(
        &directory.join("assertions.json"),
        MAX_SEMANTIC_ARTIFACT_BYTES,
    )?;
    let expected_assertions: AssertionReport = serde_json::from_slice(&expected_assertion_bytes)
        .map_err(|error| crate::diagnostics::json_error("malformed recorded assertions", &error))?;
    Ok((expected_assertions, expected_assertion_bytes))
}

/// Copy the recorded replay log into the attempt directory and require it to
/// still match the manifest digest.
fn copy_replay_log(
    directory: &Path,
    runtime: &QmpDirectory,
    manifest: &Manifest,
) -> io::Result<PathBuf> {
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
    Ok(replay_log)
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
                format!(
                    "expected an assertions-evaluated report, received {}",
                    event.describe()
                ),
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
                        "failed receiving event {}/{} for the {} command: {error}",
                        event_index + 1,
                        expected_events,
                        command.kind()
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
                "event {} ({}) does not match the {} command",
                event_index + 1,
                frame.event.describe(),
                command.kind()
            ),
        ))
    }
}

fn valid_report(report: &AssertionReport) -> bool {
    valid_profile(report, &crate::assertions::AssertionName::NETWORK_PROFILE)
}

/// Require exactly the profile's assertion names, each once, and a summary that
/// agrees with them.
fn valid_profile(report: &AssertionReport, profile: &[crate::assertions::AssertionName]) -> bool {
    let mut seen = vec![false; profile.len()];
    for assertion in &report.assertions {
        let Some(index) = profile.iter().position(|name| *name == assertion.name) else {
            return false;
        };
        if seen[index] {
            return false;
        }
        seen[index] = true;
    }
    seen.into_iter().all(|value| value)
        && report.passed == report.assertions.iter().all(|assertion| assertion.passed)
}

/// One logical step of the workload acceptance sequence. The plan is derived
/// from the seeded choice plan before any command is sent, so a recording and
/// its passive replays execute exactly the same steps and diverge only if the
/// guest does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkloadStep {
    Echo(u64),
    State(u64),
    SpawnDescendant(u64),
    Start(u64),
    Terminate(u64),
    Activate,
    Restore,
    Request { invocation: u64, index: usize },
    StdinEof(u64),
}

fn workload_steps(choices: &WorkloadChoicePlan) -> Vec<WorkloadStep> {
    let mut steps = vec![
        WorkloadStep::Start(1),
        WorkloadStep::Echo(1),
        WorkloadStep::State(1),
    ];
    let mut invocation = 1_u64;
    for index in 0..choices.requests.len() {
        if index == choices.process_fault_request_index {
            steps.push(WorkloadStep::SpawnDescendant(invocation));
            steps.push(WorkloadStep::Terminate(invocation));
            invocation += 1;
            steps.push(WorkloadStep::Start(invocation));
            steps.push(WorkloadStep::Echo(invocation));
            steps.push(WorkloadStep::State(invocation));
        }
        if index == choices.outage_activation_request_index {
            steps.push(WorkloadStep::Activate);
        }
        if index == choices.restoration_request_index {
            steps.push(WorkloadStep::Restore);
        }
        steps.push(WorkloadStep::Request { invocation, index });
    }
    steps.push(WorkloadStep::StdinEof(invocation));
    steps
}

/// Preflight the control frames a workload run serializes before QEMU starts.
///
/// The launch identity is the largest command the host sends, and each planned
/// input line must fit the runtime's decoded input bound, so an identity or
/// payload that cannot be delivered is rejected during preparation rather than
/// after a successful launch.
fn validate_workload_control_frames(
    launch: &LaunchIdentity,
    choices: &WorkloadChoicePlan,
) -> io::Result<()> {
    fn frame_bytes(command: Command) -> io::Result<usize> {
        let frame = CommandFrame {
            protocol_version: PROTOCOL_VERSION,
            command_id: u64::MAX,
            command,
        };
        Ok(serde_json::to_vec(&frame).map_err(io::Error::other)?.len())
    }

    let start = frame_bytes(Command::Start {
        invocation: 1,
        launch: launch.clone(),
    })?;
    if start > MAX_FRAME_LENGTH {
        return Err(invalid_data(format!(
            "the materialized launch identity needs a {start}-byte start command, which exceeds the {MAX_FRAME_LENGTH}-byte control frame limit"
        )));
    }
    // The guest serializes the same identity in its start event, whose envelope
    // is not the command's, so the response frame is preflighted too.
    let started = serde_json::to_vec(&EventFrame {
        protocol_version: PROTOCOL_VERSION,
        event_id: u64::MAX,
        command_id: u64::MAX,
        event: Event::WorkloadStarted {
            invocation: u64::MAX,
            launch: launch.clone(),
        },
        diagnostics: Default::default(),
    })
    .map_err(io::Error::other)?;
    if started.len() > MAX_FRAME_LENGTH {
        return Err(invalid_data(format!(
            "the materialized launch identity needs a {}-byte workload-started event, which exceeds the {MAX_FRAME_LENGTH}-byte control frame limit",
            started.len()
        )));
    }
    let mut widest = 0;
    let mut widest_request = "";
    for request in &choices.requests {
        let text = format!("fetch {} {}\n", request.request_id, request.payload);
        if text.len() > MAX_STDIN_FRAME_BYTES {
            return Err(invalid_data(format!(
                "the planned input for {} is {} bytes, which exceeds the {MAX_STDIN_FRAME_BYTES}-byte input limit",
                request.request_id,
                text.len()
            )));
        }
        if text.len() > widest {
            widest = text.len();
            widest_request = &request.request_id;
        }
    }
    let input = frame_bytes(Command::StdinWrite {
        invocation: u64::MAX,
        offset: u64::MAX,
        bytes: encode_bytes(&vec![0_u8; widest]),
    })?;
    if input > MAX_FRAME_LENGTH {
        return Err(invalid_data(format!(
            "the planned input for {widest_request} needs a {input}-byte command frame, which exceeds the {MAX_FRAME_LENGTH}-byte control frame limit"
        )));
    }
    Ok(())
}

/// Whether an event reports the end of a workload invocation. The runtime
/// serializes an exit and its cleanup barrier as separate frames, so a network
/// command that follows a stopped invocation can be acknowledged after them.
fn is_terminal_workload_event(event: &Event) -> bool {
    matches!(
        event,
        Event::TerminationRequested { .. }
            | Event::WorkloadExited { .. }
            | Event::LaunchFailed { .. }
            | Event::CleanupComplete { .. }
    )
}

/// Consume and compare the recorded workload event stream.
///
/// A replayed guest reproduces the recorded execution, including the input it
/// received, so the host sends nothing and must not re-decide the command
/// schedule from its own queue timing: it reads exactly the recorded events,
/// requires each to match byte for byte, and then lets the checker recompute the
/// report from them.
fn replay_workload_events(
    expected: &[NormalizedEvent],
    vm: &mut dyn RunningVm,
    diagnostics: &mut FailureDiagnostics,
) -> io::Result<Vec<EventFrame>> {
    let Some(last) = expected.last() else {
        return Err(invalid_data("the recording has no normalized events"));
    };
    if !matches!(last.event, Event::AgentStopped {}) {
        return Err(invalid_data(
            "the recorded event stream does not end with agent-stopped",
        ));
    }
    let mut frames = Vec::with_capacity(expected.len());
    for (index, expected) in expected.iter().enumerate() {
        let frame = vm.receive()?;
        if frame.protocol_version != PROTOCOL_VERSION || frame.event_id != expected.event_id {
            return Err(invalid_data(format!(
                "unexpected event envelope at index {index}: version={}, event_id={} (expected event {})",
                frame.protocol_version, frame.event_id, expected.event_id
            )));
        }
        let normalized = frame.normalize();
        if &normalized != expected {
            return Err(invalid_data(format!(
                "normalized event divergence at index {index}: expected {} at event {}, found {} at event {}",
                expected.event.describe(),
                expected.event_id,
                normalized.event.describe(),
                normalized.event_id
            )));
        }
        diagnostics.observe(&normalized);
        frames.push(frame);
    }
    vm.finish_events()?;
    Ok(frames)
}

/// The workload control loop. Unlike the network controller, responses to a
/// command are interleaved with live output frames, so it reads until the
/// expected typed event or response line appears and folds every frame into the
/// host checker's trace.
struct WorkloadController<'a> {
    vm: &'a mut dyn RunningVm,
    diagnostics: &'a mut FailureDiagnostics,
    next_command_id: u64,
    next_event_id: u64,
    raw_events: Vec<EventFrame>,
    events: Vec<NormalizedEvent>,
    trace: WorkloadTrace,
    consumed_lines: BTreeMap<u64, usize>,
}

impl<'a> WorkloadController<'a> {
    fn new(vm: &'a mut dyn RunningVm, diagnostics: &'a mut FailureDiagnostics) -> Self {
        Self {
            vm,
            diagnostics,
            next_command_id: 1,
            next_event_id: 1,
            raw_events: Vec::new(),
            events: Vec::new(),
            trace: WorkloadTrace::default(),
            consumed_lines: BTreeMap::new(),
        }
    }

    /// Assign a command identifier and send the command.
    fn issue(&mut self, command: Command) -> io::Result<u64> {
        let command_id = self.next_command_id;
        self.next_command_id += 1;
        self.vm.send(&CommandFrame {
            protocol_version: PROTOCOL_VERSION,
            command_id,
            command,
        })?;
        Ok(command_id)
    }

    /// Fold one received frame into the trace. The command identifier must name a
    /// command that was actually issued, and the event identifier must continue
    /// the stream.
    fn absorb(&mut self, frame: EventFrame) -> io::Result<EventFrame> {
        if frame.protocol_version != PROTOCOL_VERSION
            || frame.event_id != self.next_event_id
            || frame.command_id == 0
            || frame.command_id >= self.next_command_id
        {
            return Err(invalid_data(format!(
                "unexpected event envelope: version={}, event_id={}, command_id={} (last issued command {})",
                frame.protocol_version,
                frame.event_id,
                frame.command_id,
                self.next_command_id.saturating_sub(1)
            )));
        }
        self.next_event_id += 1;
        let normalized = frame.normalize();
        self.diagnostics.observe(&normalized);
        self.trace.push(&frame);
        self.raw_events.push(frame.clone());
        self.events.push(normalized);
        Ok(frame)
    }

    fn receive_one(&mut self) -> io::Result<EventFrame> {
        let frame = self.vm.receive()?;
        self.absorb(frame)
    }

    /// Fold every already-queued event into the trace without waiting. A live
    /// recording cannot see an event for a command it has not sent, so an event
    /// whose command has not been issued is an envelope violation. A closed
    /// channel is still an error: the guest ended without its shutdown handshake.
    fn drain(&mut self) -> io::Result<()> {
        while let Some(frame) = self.vm.try_receive()? {
            self.absorb(frame)?;
        }
        Ok(())
    }

    /// Read until the expected typed event for the just-issued command arrives,
    /// folding live output frames into the trace. An output frame is
    /// asynchronous and may still be attributed to an earlier command, but every
    /// other event must name the command that is being awaited.
    ///
    /// `allow_terminal` additionally folds the lifecycle events of a workload
    /// invocation: the runtime serializes an exit and its cleanup barrier as
    /// separate frames, so a network command issued after an invocation stopped
    /// can legitimately be acknowledged after those frames. The trace keeps them,
    /// and the checker reports them.
    fn expect(
        &mut self,
        command_id: u64,
        description: &str,
        allow_terminal: bool,
        predicate: impl Fn(&Event) -> bool,
    ) -> io::Result<EventFrame> {
        loop {
            let frame = self.receive_one()?;
            if predicate(&frame.event) {
                if frame.command_id != command_id {
                    return Err(invalid_data(format!(
                        "the {} response carries command {} instead of {command_id}",
                        frame.event.kind(),
                        frame.command_id
                    )));
                }
                return Ok(frame);
            }
            if frame.command_id > command_id {
                return Err(invalid_data(format!(
                    "an event for command {} arrived while waiting for {description}",
                    frame.command_id
                )));
            }
            if !matches!(frame.event, Event::WorkloadOutput { .. })
                && !(allow_terminal && is_terminal_workload_event(&frame.event))
            {
                return Err(invalid_data(format!(
                    "unexpected {} while waiting for {description}",
                    frame.event.describe()
                )));
            }
        }
    }

    /// Read until the acknowledgement of the just-issued input command, or until
    /// the invocation ends first. The acknowledgement must name the same
    /// invocation, carry the exact number of bytes that were sent, and end at the
    /// expected offset.
    fn await_input_accepted(
        &mut self,
        command_id: u64,
        invocation: u64,
        expected_start: u64,
        sent: u64,
    ) -> io::Result<bool> {
        loop {
            let frame = self.receive_one()?;
            match &frame.event {
                Event::InputAccepted {
                    invocation: actual,
                    offset,
                    bytes,
                    eof,
                } => {
                    if frame.command_id != command_id {
                        return Err(invalid_data(format!(
                            "the input-accepted response carries command {} instead of {command_id}",
                            frame.command_id
                        )));
                    }
                    if *actual != invocation
                        || *eof
                        || *offset != expected_start + sent
                        || *bytes != sent
                    {
                        return Err(invalid_data(format!(
                            "unexpected {} while waiting for input-accepted",
                            frame.event.describe()
                        )));
                    }
                    return Ok(true);
                }
                Event::WorkloadExited {
                    invocation: actual, ..
                }
                | Event::LaunchFailed {
                    invocation: actual, ..
                } if *actual == invocation => return Ok(false),
                Event::WorkloadOutput { .. } => {}
                event => {
                    return Err(invalid_data(format!(
                        "unexpected {} while waiting for input-accepted",
                        event.describe()
                    )));
                }
            }
        }
    }

    /// Read until the invocation exits, or until an already-observed response
    /// failure means the run must stop instead of waiting for an exit that may
    /// never come. Output frames are folded as they arrive, so a stderr byte or an
    /// over-bound unfinished line ends the wait as soon as it is observed.
    fn await_exit(&mut self, command_id: u64, invocation: u64) -> io::Result<bool> {
        // The acknowledgement that was awaited before this call can fold a
        // failing output frame, so an already-observed failure must end the wait
        // before the first blocking receive rather than after the next one.
        if !self.healthy(invocation) {
            return Ok(false);
        }
        loop {
            let frame = self.receive_one()?;
            match &frame.event {
                Event::WorkloadExited {
                    invocation: actual, ..
                } if *actual == invocation => {
                    if frame.command_id != command_id {
                        return Err(invalid_data(format!(
                            "the workload-exited response carries command {} instead of {command_id}",
                            frame.command_id
                        )));
                    }
                    return Ok(true);
                }
                Event::WorkloadOutput { .. } => {
                    if !self.healthy(invocation) {
                        return Ok(false);
                    }
                }
                event if is_terminal_workload_event(event) => {}
                event => {
                    return Err(invalid_data(format!(
                        "unexpected {} while waiting for workload-exited",
                        event.describe()
                    )));
                }
            }
        }
    }

    /// Whether the invocation is still live after folding every queued event.
    /// A process command for a released invocation is an infrastructure error, so
    /// the driver checks liveness before issuing one.
    fn live(&mut self, invocation: u64) -> io::Result<bool> {
        self.drain()?;
        Ok(!(self.trace.exited(invocation) || self.trace.launch_failed(invocation)))
    }

    /// Whether the invocation is live and has not already produced a response
    /// that the checker must reject. The pinned fixture writes to stderr only
    /// when it is failing and a line over the response bound can never be valid,
    /// so neither state can be followed by an orderly completion.
    fn healthy(&self, invocation: u64) -> bool {
        !self.trace.exited(invocation)
            && !self.trace.launch_failed(invocation)
            && self.trace.stderr_bytes(invocation) == 0
            && !self.trace.over_bound_line(invocation)
    }

    /// Send one bounded input line to a live invocation. Returns `false` when
    /// the invocation has already exited or failed to start, so the driver stops
    /// issuing workload commands and lets the checker report the failure.
    ///
    /// Queued events are folded in first, so a process that exited before this
    /// command is observed rather than raced. The residual window is the interval
    /// between that drain and the guest reading the command: if the invocation is
    /// released inside it, the guest reports the exit as an unexpected
    /// acknowledgement and the run fails as an infrastructure error.
    fn write_stdin(&mut self, invocation: u64, offset: &mut u64, text: &str) -> io::Result<bool> {
        self.drain()?;
        if !self.healthy(invocation) {
            return Ok(false);
        }
        let expected = *offset;
        let command_id = self.issue(Command::StdinWrite {
            invocation,
            offset: expected,
            bytes: encode_bytes(text.as_bytes()),
        })?;
        if !self.await_input_accepted(command_id, invocation, expected, text.len() as u64)? {
            return Ok(false);
        }
        *offset = expected + text.len() as u64;
        Ok(true)
    }

    /// Read until one invocation's next response line is exactly `expected`.
    ///
    /// The line must be the *next* complete line of that invocation, so a wrong
    /// response fails the run through the checker instead of being skipped over
    /// until the VM deadline. Returns `false` when the invocation exits first,
    /// writes to stderr, produces a line that already exceeds the response bound,
    /// or answers with a different line.
    fn wait_for_line(&mut self, invocation: u64, expected: &str) -> io::Result<bool> {
        loop {
            // An observed failure takes precedence over a matching line: a
            // response that is already known to be failing must fail the run
            // rather than be consumed and followed into the next wait.
            if !self.healthy(invocation) {
                return Ok(false);
            }
            let consumed = self.consumed_lines.get(&invocation).copied().unwrap_or(0);
            if consumed < self.trace.stdout_line_count(invocation) {
                let matched = self.trace.stdout_line(invocation, consumed) == Some(expected);
                self.consumed_lines.insert(invocation, consumed + 1);
                if !self.healthy(invocation) {
                    return Ok(false);
                }
                return Ok(matched);
            }
            if self.trace.exited(invocation) || self.trace.launch_failed(invocation) {
                return Ok(false);
            }
            self.receive_one()?;
        }
    }
}

fn drive_workload_scenario(
    scenario: &WorkloadScenario,
    choices: &WorkloadChoicePlan,
    launch: &LaunchIdentity,
    vm: &mut dyn RunningVm,
    diagnostics: &mut FailureDiagnostics,
) -> io::Result<(Vec<NormalizedEvent>, AssertionReport)> {
    let mut controller = WorkloadController::new(vm, diagnostics);
    let interface = "eth0".to_owned();
    let guest_cidr = "10.0.2.15/24".to_owned();
    let configure = controller.issue(Command::ConfigureNetwork {
        interface: interface.clone(),
        guest_cidr: guest_cidr.clone(),
        gateway: scenario.fixture_peer.clone(),
    })?;
    controller.expect(configure, "network-configured", true, |event| {
        matches!(
            event,
            Event::NetworkConfigured {
                interface: actual_interface,
                guest_cidr: actual_cidr,
                gateway: actual_gateway,
            } if actual_interface == &interface
                && actual_cidr == &guest_cidr
                && actual_gateway == &scenario.fixture_peer
        )
    })?;
    let peer_cidr = format!("{}/32", scenario.fixture_peer);
    let mut offsets = BTreeMap::<u64, u64>::new();
    let mut outage_active = false;
    let mut stopped = false;
    for step in workload_steps(choices) {
        if stopped {
            break;
        }
        match step {
            WorkloadStep::Echo(invocation) => {
                let token = echo_token(choices.seed, invocation);
                let offset = offsets.entry(invocation).or_default();
                if !controller.write_stdin(invocation, offset, &format!("echo {token}\n"))?
                    || !controller.wait_for_line(invocation, &format!("echo value={token}"))?
                {
                    stopped = true;
                }
            }
            WorkloadStep::State(invocation) => {
                let offset = offsets.entry(invocation).or_default();
                if !controller.write_stdin(invocation, offset, "state\n")?
                    || !controller.wait_for_line(invocation, FRESH_STATE_LINE)?
                {
                    stopped = true;
                }
            }
            WorkloadStep::SpawnDescendant(invocation) => {
                let offset = offsets.entry(invocation).or_default();
                if !controller.write_stdin(invocation, offset, "spawn-descendant\n")?
                    || !controller.wait_for_line(invocation, ESCAPED_DESCENDANT_LINE)?
                {
                    stopped = true;
                }
            }
            WorkloadStep::Request { invocation, index } => {
                let request = &choices.requests[index];
                let offset = offsets.entry(invocation).or_default();
                let line = expected_network_line(
                    request,
                    request_phase(
                        index,
                        choices.outage_activation_request_index,
                        choices.restoration_request_index,
                    ),
                );
                if !controller.write_stdin(
                    invocation,
                    offset,
                    &format!("fetch {} {}\n", request.request_id, request.payload),
                )? || !controller.wait_for_line(invocation, &line)?
                {
                    stopped = true;
                }
            }
            WorkloadStep::Activate => {
                let command = controller.issue(Command::ActivateOutage {
                    peer_cidr: peer_cidr.clone(),
                })?;
                controller.expect(command, "outage-activated", true, |event| {
                    matches!(
                        event,
                        Event::OutageActivated { peer_cidr: actual, rule }
                            if actual == &peer_cidr && rule == &format!("prohibit {peer_cidr}")
                    )
                })?;
                outage_active = true;
            }
            WorkloadStep::Restore => {
                let command = controller.issue(Command::RestoreNetwork {
                    peer_cidr: peer_cidr.clone(),
                })?;
                controller.expect(command, "network-restored", true, |event| {
                    matches!(
                        event,
                        Event::NetworkRestored { peer_cidr: actual } if actual == &peer_cidr
                    )
                })?;
                outage_active = false;
            }
            WorkloadStep::Start(invocation) => {
                let command = controller.issue(Command::Start {
                    invocation,
                    launch: launch.clone(),
                })?;
                controller.expect(command, "workload-started", false, |event| {
                    matches!(
                        event,
                        Event::WorkloadStarted { .. } | Event::LaunchFailed { .. }
                    )
                })?;
                // The first command is only sent once the invocation reports that
                // it is reading input, so a workload that exits immediately after
                // exec is observed as an ended invocation rather than raced.
                if !controller.wait_for_line(invocation, READY_LINE)? {
                    stopped = true;
                }
            }
            WorkloadStep::Terminate(invocation) => {
                if !controller.live(invocation)? || !controller.healthy(invocation) {
                    stopped = true;
                    continue;
                }
                let command = controller.issue(Command::Terminate { invocation })?;
                controller.expect(command, "termination-requested", false, |event| {
                    matches!(event, Event::TerminationRequested { .. })
                })?;
                if !controller.await_exit(command, invocation)? {
                    stopped = true;
                    continue;
                }
                controller.expect(command, "cleanup-complete", false, |event| {
                    matches!(event, Event::CleanupComplete { .. })
                })?;
            }
            WorkloadStep::StdinEof(invocation) => {
                if !controller.live(invocation)? || !controller.healthy(invocation) {
                    stopped = true;
                    continue;
                }
                let expected_end = offsets.get(&invocation).copied().unwrap_or(0);
                let command = controller.issue(Command::StdinEof { invocation })?;
                controller.expect(command, "input-accepted", false, move |event| {
                    matches!(
                        event,
                        Event::InputAccepted { invocation: actual, offset, bytes: 0, eof: true }
                            if *actual == invocation && *offset == expected_end
                    )
                })?;
                if !controller.await_exit(command, invocation)? {
                    stopped = true;
                    continue;
                }
                controller.expect(command, "cleanup-complete", false, |event| {
                    matches!(event, Event::CleanupComplete { .. })
                })?;
            }
        }
    }
    // An early stop can leave the administrative outage in force. The agent
    // refuses to stop while an outage is active, and leaving the fault in place
    // would turn an application failure into an infrastructure failure, so the
    // network is restored before the shutdown handshake. Passive replay derives
    // the same stop point from the same recorded events and therefore issues the
    // same command.
    if stopped && outage_active {
        // The stopped invocation may still be finishing its cleanup barrier, so
        // every queued event is folded in before the next command.
        controller.drain()?;
        let command = controller.issue(Command::RestoreNetwork {
            peer_cidr: peer_cidr.clone(),
        })?;
        controller.expect(command, "network-restored", true, |event| {
            matches!(
                event,
                Event::NetworkRestored { peer_cidr: actual } if actual == &peer_cidr
            )
        })?;
    }
    // The runtime may still be finishing a barrier when the agent stops, so
    // drain every remaining workload event until the agent reports it stopped.
    // Nothing else can arrive: every other command was acknowledged in order.
    let shutdown = controller.issue(Command::Shutdown {})?;
    loop {
        let frame = controller.receive_one()?;
        if frame.command_id > shutdown {
            return Err(invalid_data(
                "an event for a later command arrived while waiting for agent-stopped",
            ));
        }
        if matches!(frame.event, Event::AgentStopped {}) {
            if frame.command_id != shutdown {
                return Err(invalid_data(format!(
                    "the agent-stopped response carries command {} instead of {shutdown}",
                    frame.command_id
                )));
            }
            break;
        }
        if !matches!(
            frame.event,
            Event::WorkloadOutput { .. } | Event::InputAccepted { .. }
        ) && !is_terminal_workload_event(&frame.event)
        {
            return Err(invalid_data(format!(
                "unexpected {} while waiting for agent-stopped",
                frame.event.describe()
            )));
        }
    }
    controller.vm.finish_events()?;
    let report = evaluate_workload(&controller.raw_events, scenario, choices, launch);
    Ok((controller.events, report))
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
        // The run directory carries the private replay closure, the exact
        // workload streams, and the recorded launch environment, so it is
        // owner-only. The shareable failure bundle is a separate directory.
        fs::DirBuilder::new().mode(0o700).create(&path)?;
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
    workload_template: Option<&[u8]>,
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
    // The immutable workload template is assembled below its reserved root,
    // outside the PID-1 agent, its tools, and the runtime scratch space. Its
    // entries carry no trailing marker so the whole image stays one archive.
    if let Some(template) = workload_template {
        archive.extend_from_slice(template);
    }
    append_cpio(&mut archive, "TRAILER!!!", 0, &[])?;

    let mut compressor = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    compressor.write_all(&archive)?;
    let compressed = compressor.finish()?;
    let digest = sha256_bytes(&compressed);
    let cache = runs_directory.join(".images");
    // A workload image embeds the packaged workload template, so the cache is
    // owner-only: the directory, the temporary file, and the published entry.
    fs::create_dir_all(runs_directory)?;
    match fs::DirBuilder::new().mode(0o700).create(&cache) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    require_private_cache(&cache, 0o700, true)?;
    let image = cache.join(format!("{digest}.cpio.gz"));
    if image.exists() {
        // An entry published by an earlier build may be world-readable or of the
        // wrong type, so a reused image is validated and repaired before it is
        // opened: hashing a FIFO would block before any check could reject it.
        require_private_cache(&image, 0o600, false)?;
        if sha256_regular_file(&image, compressed.len())? != digest {
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
            .mode(0o600)
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
                require_private_cache(&image, 0o600, false)?;
                if sha256_regular_file(&image, compressed.len())? != digest {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "published guest image has the wrong digest",
                    ));
                }
            }
            Err(error) if image.exists() => {
                let _ = fs::remove_file(temporary);
                require_private_cache(&image, 0o600, false)?;
                if sha256_regular_file(&image, compressed.len())? != digest {
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

/// Require one cached guest image entry to be owned by the current user with an
/// owner-only mode, repairing the mode of an entry published by an earlier
/// build. A world-readable workload image would expose the packaged workload.
fn require_private_cache(path: &Path, mode: u32, directory: bool) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let file_type = metadata.file_type();
    let expected = if directory {
        file_type.is_dir()
    } else {
        file_type.is_file()
    };
    if !expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "cached guest image entry has an unexpected file type: {}",
                path.display()
            ),
        ));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "cached guest image entry is not owned by the current user: {}",
                path.display()
            ),
        ));
    }
    if metadata.permissions().mode() & 0o777 != mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        let repaired = fs::symlink_metadata(path)?;
        if repaired.permissions().mode() & 0o777 != mode {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "cached guest image entry could not be made owner-only: {}",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
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

fn fixture_entries(requests: &[PlannedRequest], corrupt_responses: bool) -> Vec<(String, Vec<u8>)> {
    requests
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

fn artifact_digests(root: &Path, workload: bool) -> io::Result<BTreeMap<String, String>> {
    let mut names = ARTIFACT_NAMES.to_vec();
    if workload {
        names.push(WORKLOAD_LOCK_PATH);
    }
    // Each artifact is hashed through the same reader the replay path uses, so a
    // run that exceeds any replay limit is refused before it is published rather
    // than published and then rejected on replay.
    names
        .into_iter()
        .map(|name| {
            Ok((
                name.into(),
                sha256_regular_file(&root.join(name), artifact_limit(name))?,
            ))
        })
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
    if let Some(workload) = &manifest.workload {
        for digest in [
            &workload.closure_sha256,
            &workload.canonical_digest,
            &workload.template_sha256,
        ] {
            if !valid_sha256(digest) {
                return Err(invalid_data(
                    "manifest workload identity contains an invalid SHA-256 digest",
                ));
            }
        }
        crate::workload::validate_launch_identity(&workload.launch).map_err(|error| {
            invalid_data(format!("manifest workload launch is invalid: {error}"))
        })?;
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
    if !ARTIFACT_NAMES
        .into_iter()
        .all(|name| expected.contains_key(name))
        || expected
            .keys()
            .any(|name| name != WORKLOAD_LOCK_PATH && !ARTIFACT_NAMES.contains(&name.as_str()))
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
        .map_err(|error| crate::diagnostics::json_error("malformed recorded artifact", &error))
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
        WORKLOAD_LOCK_PATH => MAX_WORKLOAD_LOCK_BYTES,
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
                crate::diagnostics::json_error(
                    &format!("invalid normalized event at line {}", index + 1),
                    &error,
                )
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
                    "normalized event divergence at index {index}: expected {} at event {}, found {} at event {}",
                    expected.event.describe(),
                    expected.event_id,
                    actual.event.describe(),
                    actual.event_id
                )));
            }
            (Some(expected), None) => {
                return Err(invalid_data(format!(
                    "replay ended before normalized event index {index}: expected {} at event {}",
                    expected.event.describe(),
                    expected.event_id
                )));
            }
            (None, Some(actual)) => {
                return Err(invalid_data(format!(
                    "replay produced surplus normalized event at index {index}: {} at event {}",
                    actual.event.describe(),
                    actual.event_id
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

/// Write one private run artifact with owner-only permissions. These artifacts
/// may carry the recorded launch environment or exact workload stream bytes, so
/// they are never world-readable even inside the owner-only run directory.
fn write_private(path: PathBuf, bytes: &[u8]) -> io::Result<()> {
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?
        .write_all(bytes)
}

fn write_private_json(path: PathBuf, value: &impl Serialize) -> io::Result<()> {
    write_private(path, &json_bytes(value)?)
}

/// Write one private JSON artifact and require it to fit the limit its reader
/// enforces, so a published run cannot be unreplayable.
fn write_private_bounded_json(
    path: PathBuf,
    value: &impl Serialize,
    limit: usize,
    what: &str,
) -> io::Result<()> {
    let bytes = json_bytes(value)?;
    if bytes.len() > limit {
        return Err(invalid_data(format!(
            "{what} is {} bytes, which exceeds the {limit}-byte replay limit",
            bytes.len()
        )));
    }
    write_private(path, &bytes)
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
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::{Arc, Mutex};

    use std::collections::VecDeque;

    use super::*;
    use crate::checker::MAX_RESPONSE_LINE_BYTES;
    use crate::protocol::{DiagnosticFields, OutputStream, ProcessExit};

    /// A deterministic model of the pinned acceptance fixture's line protocol,
    /// so the workload driver and host checker can be exercised without QEMU.
    #[derive(Default)]
    struct FakeWorkload {
        network_up: bool,
        fetched: usize,
        descendant: bool,
        live: Option<u64>,
        duplicated: bool,
        sequences: BTreeMap<u64, u64>,
        input_offsets: BTreeMap<u64, u64>,
        stdout: BTreeMap<u64, Vec<u8>>,
        stderr: BTreeMap<u64, Vec<u8>>,
        frames: BTreeMap<u64, u64>,
    }

    /// A failing tail the fake guest writes while the host is waiting for the
    /// end-of-input acknowledgement, so the driver has already observed the
    /// failure when it starts waiting for an exit that never comes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FailingTail {
        Stderr,
        OverBound,
    }

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
        workload: FakeWorkload,
        /// The administrative outage is active, exactly as the guest agent tracks
        /// it: the fake refuses to shut down while it is set, so a driver that
        /// stops during an outage must restore the network first.
        outage_active: bool,
        /// Fail the live invocation on its first request while the outage is in
        /// force, so an application failure lands inside the outage window.
        exit_on_outage: bool,
        /// Report a stale root witness, as a reused workload root would.
        stale_root: bool,
        /// Exit the invocation immediately after its startup line, before any
        /// input is read.
        exit_after_start: bool,
        /// Emit one duplicated input acknowledgement for the first input command.
        duplicate_input_accept: bool,
        /// Report a different gateway than the one the host configured.
        mismatched_network: bool,
        /// Report the agent-stopped acknowledgement with an older command.
        late_agent_stopped: bool,
        /// Emit one event that belongs to a command the host has not issued.
        future_command_event: bool,
        /// A cleanup barrier the runtime has not delivered yet, because it
        /// finishes the barrier after the host has already read the exit record.
        pending_cleanup: Option<(u64, u64)>,
        /// Write to stderr without exiting, so only the driver's stderr check can
        /// end the wait for a response line.
        stderr_without_exit: bool,
        /// Write a stdout line that already exceeds the response bound, without a
        /// newline and without exiting.
        over_bound_line_without_exit: bool,
        /// Write the expected response and then an over-bound unfinished tail,
        /// without exiting.
        over_bound_tail_after_response: bool,
        /// Withhold the over-bound tail until the next command is processed, so
        /// the recording observes it later than a replay does.
        late_tail_after_response: bool,
        /// Write a failing tail while the host waits for the end-of-input
        /// acknowledgement, then acknowledge it and stay alive.
        failing_tail_before_eof: Option<FailingTail>,
        /// Report an outage activation whose peer and rule carry a marker, as a
        /// diverging guest would.
        forged_outage_activation: bool,
        /// Exit cleanly once the current invocation has answered this many
        /// requests, before the host can end its input.
        exit_after_fetch: Option<u64>,
        pending_tail: Option<u64>,
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
        exit_on_outage: bool,
        divergent_workload_launch: bool,
        late_tail_after_response: bool,
        forged_outage_activation: bool,
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
        build_guest_image_with_assets(executable, runs_directory, &synthetic_assets(), None)
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
                workload: FakeWorkload::default(),
                outage_active: false,
                exit_on_outage: self.exit_on_outage,
                stale_root: false,
                exit_after_start: false,
                duplicate_input_accept: false,
                mismatched_network: false,
                late_agent_stopped: false,
                future_command_event: false,
                pending_cleanup: None,
                stderr_without_exit: false,
                over_bound_line_without_exit: false,
                over_bound_tail_after_response: false,
                late_tail_after_response: self.late_tail_after_response,
                failing_tail_before_eof: None,
                forged_outage_activation: self.forged_outage_activation,
                exit_after_fetch: None,
                pending_tail: None,
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
            if self.divergent_workload_launch {
                // The replayed guest reports a different launch environment than
                // the recording, so the normalized stream diverges at the start.
                let start = events
                    .iter_mut()
                    .find(|frame| matches!(frame.event, Event::WorkloadStarted { .. }))
                    .expect("the recording starts a workload");
                if let Event::WorkloadStarted { launch, .. } = &mut start.event {
                    launch.environment.push("MODE=diverged".into());
                }
            }
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
        /// Refuse a process command for an invocation that is not active, exactly
        /// as the guest runtime does: a command for a released invocation is an
        /// infrastructure error, so the driver must check liveness first.
        fn require_live(&self, invocation: u64) -> io::Result<()> {
            if self.workload.live == Some(invocation) {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "fake guest: invocation {invocation} is not active"
                )))
            }
        }

        /// Emit one live output frame with the next sequence number and the
        /// current per-stream offset, exactly as the guest runtime does.
        fn emit_output(
            &mut self,
            command_id: u64,
            invocation: u64,
            stream: OutputStream,
            text: &str,
        ) {
            let sequence = {
                let sequence = self.workload.sequences.entry(invocation).or_default();
                *sequence += 1;
                *sequence
            };
            let bytes = text.as_bytes().to_vec();
            let offset = match stream {
                OutputStream::Stdout => self.workload.stdout.get(&invocation).map_or(0, Vec::len),
                OutputStream::Stderr => self.workload.stderr.get(&invocation).map_or(0, Vec::len),
            };
            match stream {
                OutputStream::Stdout => self
                    .workload
                    .stdout
                    .entry(invocation)
                    .or_default()
                    .extend_from_slice(&bytes),
                OutputStream::Stderr => self
                    .workload
                    .stderr
                    .entry(invocation)
                    .or_default()
                    .extend_from_slice(&bytes),
            }
            *self.workload.frames.entry(invocation).or_default() += 1;
            self.event(
                command_id,
                Event::WorkloadOutput {
                    invocation,
                    stream,
                    offset: offset as u64,
                    sequence,
                    bytes: crate::protocol::encode_bytes(&bytes),
                },
            );
        }

        /// Emit the independently computed exit record.
        fn emit_workload_exit_record(
            &mut self,
            command_id: u64,
            invocation: u64,
            exit: ProcessExit,
        ) {
            let stdout = self.workload.stdout.remove(&invocation).unwrap_or_default();
            let stderr = self.workload.stderr.remove(&invocation).unwrap_or_default();
            let frames = self.workload.frames.remove(&invocation).unwrap_or(0);
            self.workload.sequences.remove(&invocation);
            self.workload.live = None;
            self.event(
                command_id,
                Event::WorkloadExited {
                    invocation,
                    exit,
                    stdout_bytes: stdout.len() as u64,
                    stdout_sha256: sha256_bytes(&stdout),
                    stderr_bytes: stderr.len() as u64,
                    stderr_sha256: sha256_bytes(&stderr),
                    frames,
                },
            );
        }

        /// Emit the exit record and its cleanup barrier.
        fn emit_workload_exit(
            &mut self,
            command_id: u64,
            invocation: u64,
            exit: ProcessExit,
            reaped: u64,
        ) {
            self.emit_workload_exit_record(command_id, invocation, exit);
            self.event(command_id, Event::CleanupComplete { invocation, reaped });
        }

        /// Answer one recorded fixture command with the pinned fixture's exact
        /// response line.
        fn respond(&mut self, command_id: u64, invocation: u64, data: &[u8]) {
            let text = String::from_utf8_lossy(data);
            let line = text.trim_end_matches('\n');
            if let Some(token) = line.strip_prefix("echo ") {
                self.emit_output(
                    command_id,
                    invocation,
                    OutputStream::Stdout,
                    &format!("echo value={token}\n"),
                );
            } else if line == "state" {
                let response = if self.stale_root {
                    "state value=stale root=stale\n".to_owned()
                } else {
                    format!("{FRESH_STATE_LINE}\n")
                };
                self.emit_output(command_id, invocation, OutputStream::Stdout, &response);
            } else if line == "spawn-descendant" {
                self.workload.descendant = true;
                self.emit_output(
                    command_id,
                    invocation,
                    OutputStream::Stdout,
                    "descendant state=escaped\n",
                );
            } else if let Some(rest) = line.strip_prefix("fetch ") {
                let mut parts = rest.split(' ');
                let request_id = parts.next().unwrap_or_default();
                self.workload.fetched += 1;
                if self.exit_on_outage && !self.workload.network_up {
                    // An application failure that happens while the outage is in
                    // force, so the driver has to restore before it can stop.
                    self.emit_output(
                        command_id,
                        invocation,
                        OutputStream::Stderr,
                        "fixture: injected application failure\n",
                    );
                    self.emit_workload_exit_record(
                        command_id,
                        invocation,
                        ProcessExit::Exited { code: 1 },
                    );
                    // The barrier is serialized separately, so the host reads it
                    // only with the command that follows the exit record.
                    self.pending_cleanup = Some((invocation, 1));
                } else if self.late_tail_after_response && self.workload.fetched == 1 {
                    // The tail is serialized later, so the recording observes it
                    // only after it has already issued the next command.
                    self.pending_tail = Some(invocation);
                    self.emit_output(
                        command_id,
                        invocation,
                        OutputStream::Stdout,
                        &format!("network state=ok request={request_id}\n"),
                    );
                } else if self.over_bound_tail_after_response && self.workload.fetched == 1 {
                    // The expected response is valid, but the unfinished tail that
                    // follows it can never be, and the invocation stays alive.
                    self.emit_output(
                        command_id,
                        invocation,
                        OutputStream::Stdout,
                        &format!("network state=ok request={request_id}\n"),
                    );
                    self.emit_output(
                        command_id,
                        invocation,
                        OutputStream::Stdout,
                        &"x".repeat(MAX_RESPONSE_LINE_BYTES + 1),
                    );
                } else if self.over_bound_line_without_exit && self.workload.fetched == 1 {
                    // A response line that can never be valid, without a newline:
                    // only the response bound can end the wait.
                    self.emit_output(
                        command_id,
                        invocation,
                        OutputStream::Stdout,
                        &"x".repeat(MAX_RESPONSE_LINE_BYTES + 1),
                    );
                } else if self.stderr_without_exit && self.workload.fetched == 1 {
                    // A failing application that stays alive: only the driver's
                    // stderr check can end the wait for its response line.
                    self.emit_output(
                        command_id,
                        invocation,
                        OutputStream::Stderr,
                        "fixture: injected application failure\n",
                    );
                } else if self.corrupt && self.workload.fetched == 1 {
                    self.emit_output(
                        command_id,
                        invocation,
                        OutputStream::Stderr,
                        "fixture: response content mismatch\n",
                    );
                    self.emit_workload_exit(
                        command_id,
                        invocation,
                        ProcessExit::Exited { code: 1 },
                        1,
                    );
                } else if self.workload.network_up {
                    self.emit_output(
                        command_id,
                        invocation,
                        OutputStream::Stdout,
                        &format!("network state=ok request={request_id}\n"),
                    );
                } else {
                    self.emit_output(
                        command_id,
                        invocation,
                        OutputStream::Stdout,
                        &format!(
                            "network state=unavailable request={request_id} errno={}\n",
                            libc::EACCES
                        ),
                    );
                }
                if self.exit_after_fetch == Some(self.workload.fetched as u64)
                    && self.workload.live == Some(invocation)
                {
                    // A workload can stop on its own after its last response, so
                    // the host observes the exit before it can end the input.
                    self.emit_workload_exit(
                        command_id,
                        invocation,
                        ProcessExit::Exited { code: 0 },
                        1,
                    );
                }
            }
        }

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
            if let Some((invocation, reaped)) = self.pending_cleanup.take() {
                self.event(
                    frame.command_id,
                    Event::CleanupComplete { invocation, reaped },
                );
            }
            if let Some(invocation) = self.pending_tail.take() {
                self.emit_output(
                    frame.command_id,
                    invocation,
                    OutputStream::Stdout,
                    &"x".repeat(MAX_RESPONSE_LINE_BYTES + 1),
                );
            }
            match &frame.command {
                Command::ConfigureNetwork {
                    interface,
                    guest_cidr,
                    gateway,
                } => {
                    self.running = true;
                    self.workload.network_up = true;
                    let gateway = if self.mismatched_network {
                        "10.0.2.3".to_owned()
                    } else {
                        gateway.clone()
                    };
                    self.event(
                        frame.command_id,
                        Event::NetworkConfigured {
                            interface: interface.clone(),
                            guest_cidr: guest_cidr.clone(),
                            gateway,
                        },
                    );
                }
                Command::ActivateOutage { peer_cidr } => {
                    self.running = false;
                    self.workload.network_up = false;
                    self.outage_active = true;
                    let (peer_cidr, rule) = if self.forged_outage_activation {
                        // A diverging guest can put any bytes in these fields.
                        (
                            "TOKEN=CANARY/32".to_owned(),
                            "prohibit TOKEN=CANARY/32".to_owned(),
                        )
                    } else {
                        (peer_cidr.clone(), format!("prohibit {peer_cidr}"))
                    };
                    self.event(frame.command_id, Event::OutageActivated { peer_cidr, rule });
                }
                Command::RestoreNetwork { peer_cidr } => {
                    self.running = true;
                    self.workload.network_up = true;
                    self.outage_active = false;
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
                    if self.outage_active {
                        return Err(io::Error::other(
                            "fake guest refuses to stop while the outage is active",
                        ));
                    }
                    let acknowledged = if self.late_agent_stopped {
                        frame.command_id - 1
                    } else {
                        frame.command_id
                    };
                    self.event(acknowledged, Event::AgentStopped {});
                    if self.extra_after_shutdown {
                        self.event(acknowledged, Event::AgentStopped {});
                    }
                }
                Command::Start { invocation, launch } => {
                    self.workload.live = Some(*invocation);
                    self.workload.descendant = false;
                    self.workload.fetched = 0;
                    self.event(
                        frame.command_id,
                        Event::WorkloadStarted {
                            invocation: *invocation,
                            launch: launch.clone(),
                        },
                    );
                    self.emit_output(
                        frame.command_id,
                        *invocation,
                        OutputStream::Stdout,
                        &format!("{READY_LINE}\n"),
                    );
                    if self.future_command_event {
                        // An event that belongs to a command the host has not
                        // issued: only a replayed guest can run ahead.
                        self.event(frame.command_id + 1, Event::AgentReady {});
                    }
                    if self.exit_after_start {
                        self.emit_workload_exit(
                            frame.command_id,
                            *invocation,
                            ProcessExit::Exited { code: 0 },
                            1,
                        );
                    }
                }
                Command::StdinWrite {
                    invocation,
                    offset,
                    bytes,
                } => {
                    self.require_live(*invocation)?;
                    let data = crate::protocol::decode_bytes(
                        bytes,
                        crate::protocol::MAX_STDIN_FRAME_BYTES,
                    )
                    .expect("the driver sends bounded input");
                    let end = offset + data.len() as u64;
                    self.workload.input_offsets.insert(*invocation, end);
                    self.event(
                        frame.command_id,
                        Event::InputAccepted {
                            invocation: *invocation,
                            offset: end,
                            bytes: data.len() as u64,
                            eof: false,
                        },
                    );
                    if self.duplicate_input_accept && !self.workload.duplicated {
                        self.workload.duplicated = true;
                        self.event(
                            frame.command_id,
                            Event::InputAccepted {
                                invocation: *invocation,
                                offset: end,
                                bytes: data.len() as u64,
                                eof: false,
                            },
                        );
                    }
                    self.respond(frame.command_id, *invocation, &data);
                }
                Command::StdinEof { invocation } => {
                    self.require_live(*invocation)?;
                    let offset = self
                        .workload
                        .input_offsets
                        .get(invocation)
                        .copied()
                        .unwrap_or(0);
                    if let Some(tail) = self.failing_tail_before_eof {
                        // A failing invocation can still acknowledge the end of
                        // input, so the host observes the failure before it waits
                        // for an exit that never comes.
                        let (stream, data) = match tail {
                            FailingTail::Stderr => (
                                OutputStream::Stderr,
                                "fixture: injected application failure\n".to_owned(),
                            ),
                            FailingTail::OverBound => (
                                OutputStream::Stdout,
                                "x".repeat(MAX_RESPONSE_LINE_BYTES + 1),
                            ),
                        };
                        self.emit_output(frame.command_id, *invocation, stream, &data);
                    }
                    self.event(
                        frame.command_id,
                        Event::InputAccepted {
                            invocation: *invocation,
                            offset,
                            bytes: 0,
                            eof: true,
                        },
                    );
                    if self.failing_tail_before_eof.is_none() {
                        self.emit_workload_exit(
                            frame.command_id,
                            *invocation,
                            ProcessExit::Exited { code: 0 },
                            1,
                        );
                    }
                }
                Command::Terminate { invocation } => {
                    self.require_live(*invocation)?;
                    self.event(
                        frame.command_id,
                        Event::TerminationRequested {
                            invocation: *invocation,
                            signal: crate::protocol::TERMINATION_SIGNAL,
                        },
                    );
                    let reaped = if self.workload.descendant { 2 } else { 1 };
                    self.emit_workload_exit(
                        frame.command_id,
                        *invocation,
                        ProcessExit::Signaled {
                            signal: crate::protocol::TERMINATION_SIGNAL,
                        },
                        reaped,
                    );
                }
            }
            Ok(())
        }

        fn receive(&mut self) -> io::Result<EventFrame> {
            self.queued
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no fake event"))
        }

        fn try_receive(&mut self) -> io::Result<Option<EventFrame>> {
            Ok(self.queued.pop_front())
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
            workload: FakeWorkload::default(),
            outage_active: false,
            exit_on_outage: false,
            stale_root: false,
            exit_after_start: false,
            duplicate_input_accept: false,
            mismatched_network: false,
            late_agent_stopped: false,
            future_command_event: false,
            pending_cleanup: None,
            stderr_without_exit: false,
            over_bound_line_without_exit: false,
            over_bound_tail_after_response: false,
            late_tail_after_response: false,
            failing_tail_before_eof: None,
            forged_outage_activation: false,
            exit_after_fetch: None,
            pending_tail: None,
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
            exit_on_outage: false,
            divergent_workload_launch: false,
            late_tail_after_response: false,
            forged_outage_activation: false,
            recorded_events: Arc::new(Mutex::new(Vec::new())),
        };
        let result = record_with_adapter(
            &RunOptions {
                scenario: scenario_path,
                seed: 42,
                runs_directory: runs_directory.clone(),
                kernel,
                executable: executable.clone(),
                workload: None,
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
    fn the_guest_image_assembles_the_workload_below_its_reserved_root() {
        use crate::workload::{Entry, Tree};

        let root = temporary_root("workload-image");
        let options = test_options(&root, false);
        let mut tree = Tree::new();
        tree.insert_default_directory(b".");
        tree.insert_default_directory(b"bin");
        tree.insert(
            b"bin/app".to_vec(),
            Entry::file(b"payload".to_vec(), 0o755, 65534, 65534, 0),
        );
        let template = tree.template_entries("workload").unwrap();
        let image = build_guest_image_with_assets(
            &options.executable,
            &options.runs_directory,
            &synthetic_assets(),
            Some(&template),
        )
        .unwrap();
        let compressed = fs::read(&image.path).unwrap();
        let mut archive = Vec::new();
        flate2::read::GzDecoder::new(&compressed[..])
            .read_to_end(&mut archive)
            .unwrap();
        let names = cpio_names(&archive);
        // The workload template is present below its reserved root.
        assert!(names.iter().any(|name| name == "workload"));
        assert!(names.iter().any(|name| name == "workload/bin/app"));
        // The agent and its tools stay outside the reserved root.
        assert!(names.iter().any(|name| name == "init"));
        assert!(names.iter().any(|name| name == "bin/busybox"));
        assert!(names.iter().any(|name| name == "modules/mii.ko"));
        assert!(
            !names
                .iter()
                .any(|name| name.starts_with("workload/") && name.contains("busybox")),
            "{names:#?}"
        );
        // The concatenation must remain one archive with exactly one trailer.
        assert_eq!(names.iter().filter(|name| *name == "TRAILER!!!").count(), 1);
        assert_eq!(names.last().unwrap(), "TRAILER!!!");
        fs::remove_dir_all(root).unwrap();
    }

    fn cpio_names(archive: &[u8]) -> Vec<String> {
        let mut names = Vec::new();
        let mut offset = 0;
        while offset + 110 <= archive.len() {
            let header = &archive[offset..offset + 110];
            assert_eq!(
                &header[..6],
                b"070701",
                "bad header at offset {offset} of {}",
                archive.len()
            );
            let field = |index: usize| -> usize {
                let start = 6 + index * 8;
                usize::from_str_radix(std::str::from_utf8(&header[start..start + 8]).unwrap(), 16)
                    .unwrap()
            };
            let file_size = field(6);
            let name_size = field(11);
            let name_start = offset + 110;
            let name = &archive[name_start..name_start + name_size - 1];
            names.push(String::from_utf8_lossy(name).into_owned());
            // The 110-byte header is not a multiple of four, so padding is
            // computed from the running archive offset, not the field length.
            let contents_start = (name_start + name_size + 3) & !3;
            offset = (contents_start + file_size + 3) & !3;
        }
        names
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
            workload: None,
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
            exit_on_outage: false,
            divergent_workload_launch: false,
            late_tail_after_response: false,
            forged_outage_activation: false,
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

    /// A minimal but strictly valid fixed-address static x86-64 ELF. The
    /// assembler validates the header, the program table, and each loadable
    /// segment, so a placeholder cannot be used.
    fn workload_elf() -> Vec<u8> {
        let mut elf = vec![0_u8; 128];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x40_0000_u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
        // One PT_LOAD segment covering the whole file at 0x400000.
        elf[64..68].copy_from_slice(&1_u32.to_le_bytes());
        elf[72..80].copy_from_slice(&0_u64.to_le_bytes());
        elf[80..88].copy_from_slice(&0x40_0000_u64.to_le_bytes());
        elf[88..96].copy_from_slice(&0x40_0000_u64.to_le_bytes());
        elf[96..104].copy_from_slice(&128_u64.to_le_bytes());
        elf[104..112].copy_from_slice(&128_u64.to_le_bytes());
        elf[112..120].copy_from_slice(&0x1000_u64.to_le_bytes());
        elf
    }

    fn workload_options(root: &Path, corrupt: bool) -> RunOptions {
        let scenario = root.join("scenario.toml");
        fs::write(
            &scenario,
            format!(
                "version = 1\nname = \"workload-network-outage\"\nrequest_count = 4\npayload_bytes = 2\nfixture_peer = \"10.0.2.2\"\noutage_event_bound = 8\nliveness_event_bound = 8\ncorrupt_responses = {corrupt}\n"
            ),
        )
        .unwrap();
        let specification = root.join("workload.toml");
        fs::write(
            &specification,
            "version = 1\nkind = \"binary\"\npath = \"app\"\nargs = []\nenv = [\"MODE=acceptance\"]\nworking_directory = \"/\"\nuser = \"65534:65534\"\n",
        )
        .unwrap();
        fs::write(root.join("app"), workload_elf()).unwrap();
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
            workload: Some(specification),
        }
    }

    fn replay_options(options: &RunOptions, directory: PathBuf) -> ReplayOptions {
        ReplayOptions {
            directory,
            kernel: options.kernel.clone(),
            executable: options.executable.clone(),
        }
    }

    #[test]
    fn a_workload_records_and_passively_replays_from_raw_evidence_alone() {
        let root = temporary_root("workload-replay");
        let options = workload_options(&root, false);
        let adapter = fake_adapter(None);
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        assert!(recorded.assertions.passed, "{:#?}", recorded.assertions);
        let manifest: Manifest =
            serde_json::from_slice(&fs::read(recorded.directory.join("manifest.json")).unwrap())
                .unwrap();
        let identity = manifest
            .workload
            .clone()
            .expect("the run manifest records the workload identity");
        assert_eq!(identity.source_kind, SourceKind::Binary);
        assert_eq!(manifest.artifacts.len(), 8);
        let lock: WorkloadLock =
            serde_json::from_slice(&fs::read(recorded.directory.join(WORKLOAD_LOCK_PATH)).unwrap())
                .unwrap();
        assert_eq!(lock.version, WORKLOAD_LOCK_VERSION);
        assert_eq!(lock.store, WORKLOAD_STORE_NAME);
        assert_eq!(lock.workload, identity);
        let store = options.runs_directory.join(WORKLOAD_STORE_NAME);
        assert!(store.join("raw/closure.json").is_file());
        assert!(store.join("derived").is_dir());

        // The live source is not part of the replay closure.
        fs::remove_file(root.join("app")).unwrap();
        fs::remove_file(options.workload.clone().unwrap()).unwrap();

        let replay_options = replay_options(&options, recorded.directory.clone());
        let first = replay_with_adapter(&replay_options, &adapter).unwrap();
        let second = replay_with_adapter(&replay_options, &adapter).unwrap();
        assert_eq!(first, second);
        assert!(first.assertions.passed);
        assert_eq!(
            first.semantic_outcome_sha256,
            manifest.semantic_outcome_sha256
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replay_rejects_every_independently_changed_workload_identity() {
        let root = temporary_root("workload-tamper");
        let options = workload_options(&root, false);
        let adapter = fake_adapter(None);
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        let replay_options = replay_options(&options, recorded.directory.clone());
        let store = options.runs_directory.join(WORKLOAD_STORE_NAME);

        // A self-consistently changed lock, whose artifact digest in the
        // manifest is updated too, still disagrees with the recorded identity.
        let lock_path = recorded.directory.join(WORKLOAD_LOCK_PATH);
        let original_lock = fs::read(&lock_path).unwrap();
        let mut lock: serde_json::Value = serde_json::from_slice(&original_lock).unwrap();
        lock["workload"]["canonical_digest"] = serde_json::Value::String("0".repeat(64));
        let tampered_lock = serde_json::to_vec_pretty(&lock).unwrap();
        fs::write(&lock_path, &tampered_lock).unwrap();
        let manifest_path = recorded.directory.join("manifest.json");
        let original_manifest = fs::read(&manifest_path).unwrap();
        let mut manifest: serde_json::Value = serde_json::from_slice(&original_manifest).unwrap();
        manifest["artifacts"][WORKLOAD_LOCK_PATH] =
            serde_json::Value::String(sha256_bytes(&tampered_lock));
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let error = replay_with_adapter(&replay_options, &adapter).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("the workload lock identity differs from the manifest"),
            "{error}"
        );
        fs::write(&lock_path, &original_lock).unwrap();
        fs::write(&manifest_path, &original_manifest).unwrap();

        // An independently changed launch identity is rejected before launch.
        let mut manifest: serde_json::Value = serde_json::from_slice(&original_manifest).unwrap();
        manifest["workload"]["launch"]["uid"] = serde_json::Value::from(1234);
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let error = replay_with_adapter(&replay_options, &adapter).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("the workload lock identity differs from the manifest"),
            "{error}"
        );
        fs::write(&manifest_path, &original_manifest).unwrap();

        // Missing raw evidence fails even though the derived entry still exists,
        // and the diagnostic names the missing raw closure.
        let closure_path = store.join("raw/closure.json");
        let closure = fs::read(&closure_path).unwrap();
        fs::remove_file(&closure_path).unwrap();
        assert!(store.join("derived").is_dir());
        let error = replay_with_adapter(&replay_options, &adapter).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("raw closure raw/closure.json is missing"),
            "{error}"
        );
        fs::write(&closure_path, &closure).unwrap();

        // A raw object that the closure still references must be present too.
        let closure: serde_json::Value = serde_json::from_slice(&closure).unwrap();
        let digest = closure["objects"][0]["digest"].as_str().unwrap();
        let object_path = store.join(format!("raw/sha256/{}", &digest["sha256:".len()..]));
        let object = fs::read(&object_path).unwrap();
        fs::remove_file(&object_path).unwrap();
        let error = replay_with_adapter(&replay_options, &adapter).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("raw object {digest} is missing")),
            "{error}"
        );
        fs::write(&object_path, &object).unwrap();

        // A changed raw object fails digest verification.
        fs::write(&object_path, b"tampered object").unwrap();
        let error = replay_with_adapter(&replay_options, &adapter).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match its recorded identity"),
            "{error}"
        );
        fs::write(&object_path, &object).unwrap();

        // A changed derived template fails independent verification.
        let template = store
            .join("derived")
            .join(closure["canonical_digest"].as_str().unwrap())
            .join("template.cpio");
        let bytes = fs::read(&template).unwrap();
        fs::write(&template, b"tampered template").unwrap();
        let error = replay_with_adapter(&replay_options, &adapter).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("derived guest template does not match the raw closure"),
            "{error}"
        );
        fs::write(&template, &bytes).unwrap();

        // The recorded scenario is a digested artifact and cannot change.
        let scenario_path = recorded.directory.join("scenario.toml");
        let scenario = fs::read(&scenario_path).unwrap();
        let changed = String::from_utf8(scenario.clone())
            .unwrap()
            .replace("payload_bytes = 2", "payload_bytes = 3");
        fs::write(&scenario_path, changed).unwrap();
        let error = replay_with_adapter(&replay_options, &adapter).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("artifact digest mismatch for scenario.toml"),
            "{error}"
        );
        fs::write(&scenario_path, &scenario).unwrap();

        // The untouched recording still replays.
        assert!(
            replay_with_adapter(&replay_options, &adapter)
                .unwrap()
                .assertions
                .passed
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_corrupted_workload_response_fails_safety_without_an_infrastructure_error() {
        let root = temporary_root("workload-corrupt");
        let options = workload_options(&root, true);
        let mut adapter = fake_adapter(None);
        adapter.corrupt = true;
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        assert!(!recorded.assertions.passed);
        assert_eq!(recorded.exit_code(), 1);
        let failed = recorded
            .assertions
            .assertions
            .iter()
            .filter(|assertion| !assertion.passed)
            .map(|assertion| assertion.name)
            .collect::<Vec<_>>();
        assert!(failed.contains(&crate::assertions::AssertionName::ProcessSafety));
        assert!(failed.contains(&crate::assertions::AssertionName::ResponseIntegrity));
        // The failing run is still published with a complete artifact set, and
        // its replays reproduce the same failure.
        let manifest: Manifest =
            serde_json::from_slice(&fs::read(recorded.directory.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest.artifacts.len(), 8);
        let replay_options = replay_options(&options, recorded.directory.clone());
        let replay = replay_with_adapter(&replay_options, &adapter).unwrap();
        assert_eq!(replay.assertions, recorded.assertions);
        assert_eq!(replay.exit_code(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    /// Every byte of every file below one directory, for leak assertions.
    fn bundle_bytes(root: &Path) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(directory) = stack.pop() {
            for entry in fs::read_dir(&directory).unwrap() {
                let entry = entry.unwrap();
                let file_type = entry.file_type().unwrap();
                if file_type.is_dir() {
                    stack.push(entry.path());
                } else if file_type.is_file() {
                    bytes.extend_from_slice(&fs::read(entry.path()).unwrap());
                }
            }
        }
        bytes
    }

    #[test]
    fn private_run_artifacts_are_owner_only_and_failures_exclude_workload_data() {
        let root = temporary_root("workload-classification");
        let options = workload_options(&root, false);
        // A distinctive environment value that must never reach the shareable
        // failure metadata.
        let specification = options.workload.clone().unwrap();
        let specification_text = fs::read_to_string(&specification)
            .unwrap()
            .replace("MODE=acceptance", "SECRET=classification-marker");
        fs::write(&specification, specification_text).unwrap();
        let adapter = fake_adapter(None);
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        assert!(recorded.assertions.passed, "{:#?}", recorded.assertions);

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&recorded.directory), 0o700);
        for name in [
            "scenario.toml",
            "choices.json",
            "events.jsonl",
            "assertions.json",
            "manifest.json",
            WORKLOAD_LOCK_PATH,
        ] {
            assert_eq!(mode(&recorded.directory.join(name)), 0o600, "{name}");
        }

        // A private failure bundle never carries the environment value or the
        // exact workload stream bytes.
        let store = options.runs_directory.join(WORKLOAD_STORE_NAME);
        let closure = store.join("raw/closure.json");
        let saved = fs::read(&closure).unwrap();
        fs::remove_file(&closure).unwrap();
        let replay_options = replay_options(&options, recorded.directory.clone());
        let error = replay_with_adapter(&replay_options, &adapter).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("raw closure raw/closure.json is missing"),
            "{error}"
        );
        fs::write(&closure, saved).unwrap();

        let bundles = failure_bundles(&options.runs_directory);
        assert_eq!(bundles.len(), 1);
        let retained = bundle_bytes(&bundles[0]);
        let retained = String::from_utf8_lossy(&retained);
        assert!(!retained.contains("classification-marker"), "{retained}");
        assert!(!retained.contains("ready version=1"), "{retained}");
        assert!(retained.contains("\"error_kind\""), "{retained}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_semantic_launch_failure_never_quotes_the_launch_value() {
        // A correctly typed but invalid launch field is rejected by semantic
        // validation, whose diagnostic must not quote the value either.
        let root = temporary_root("launch-value-privacy");
        let options = workload_options(&root, false);
        let specification = options.workload.clone().unwrap();
        let base = fs::read_to_string(&specification).unwrap();
        let adapter = fake_adapter(None);
        for (from, to) in [
            ("user = \"65534:65534\"", "user = \"SECRET=launch-marker\""),
            (
                "working_directory = \"/\"",
                "working_directory = \"SECRET=launch-marker\"",
            ),
        ] {
            let text = base.replace(from, to);
            assert_ne!(text, base, "the specification contains {from}");
            fs::write(&specification, &text).unwrap();
            let error = record_with_adapter(&options, &adapter).unwrap_err();
            assert!(!error.to_string().contains("launch-marker"), "{error}");
            for bundle in failure_bundles(&options.runs_directory) {
                let retained = String::from_utf8_lossy(&bundle_bytes(&bundle)).into_owned();
                assert!(!retained.contains("launch-marker"), "{retained}");
            }
        }
        fs::write(&specification, &base).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_malformed_private_artifact_never_quotes_the_launch_environment() {
        let root = temporary_root("manifest-privacy");
        let options = workload_options(&root, false);
        let specification = options.workload.clone().unwrap();
        let text = fs::read_to_string(&specification)
            .unwrap()
            .replace("MODE=acceptance", "SECRET=manifest-marker");
        fs::write(&specification, text).unwrap();
        let adapter = fake_adapter(None);
        let recorded = record_with_adapter(&options, &adapter).unwrap();

        // A manifest whose launch field has the wrong type quotes its value in a
        // plain serde error, so the diagnostic must be value-free.
        let manifest_path = recorded.directory.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["workload"]["launch"]["uid"] =
            serde_json::Value::String("SECRET=manifest-marker".into());
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let error = replay_with_adapter(
            &replay_options(&options, recorded.directory.clone()),
            &adapter,
        )
        .unwrap_err();
        assert!(!error.to_string().contains("manifest-marker"), "{error}");
        assert!(
            error.to_string().contains("malformed recorded artifact"),
            "{error}"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_workload_replay_divergence_never_leaks_the_launch_environment() {
        let root = temporary_root("workload-divergence-privacy");
        let options = workload_options(&root, false);
        // The launch environment carries a marker that must never reach the
        // error text or the shareable failure bundle.
        let specification = options.workload.clone().unwrap();
        let text = fs::read_to_string(&specification)
            .unwrap()
            .replace("MODE=acceptance", "SECRET=divergence-marker");
        fs::write(&specification, text).unwrap();
        let mut adapter = fake_adapter(None);
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        assert!(recorded.assertions.passed, "{:#?}", recorded.assertions);

        adapter.divergent_workload_launch = true;
        let error = replay_with_adapter(
            &replay_options(&options, recorded.directory.clone()),
            &adapter,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("normalized event divergence"),
            "{error}"
        );
        assert!(!error.to_string().contains("divergence-marker"), "{error}");

        let bundles = failure_bundles(&options.runs_directory);
        assert_eq!(bundles.len(), 1);
        let retained = String::from_utf8_lossy(&bundle_bytes(&bundles[0])).into_owned();
        assert!(!retained.contains("divergence-marker"), "{retained}");
        assert!(!retained.contains("ready version=1"), "{retained}");
        assert!(!retained.contains("acceptance"), "{retained}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_guest_image_cache_is_owner_only_and_repaired() {
        let root = temporary_root("image-cache-privacy");
        let runs = root.join("runs");
        let executable = root.join("simferret");
        let mut elf = vec![0_u8; 64];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        fs::write(&executable, elf).unwrap();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let image = build_guest_image(&executable, &runs).unwrap();
        let cache = runs.join(".images");
        assert_eq!(mode(&cache), 0o700);
        assert_eq!(mode(&image.path), 0o600);

        // An entry left world-readable by an earlier build is repaired rather
        // than trusted.
        fs::set_permissions(&image.path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o755)).unwrap();
        let rebuilt = build_guest_image(&executable, &runs).unwrap();
        assert_eq!(rebuilt.path, image.path);
        assert_eq!(mode(&rebuilt.path), 0o600);
        assert_eq!(mode(&cache), 0o700);

        // A cached entry that is not a regular file is refused.
        fs::remove_file(&rebuilt.path).unwrap();
        fs::create_dir(&rebuilt.path).unwrap();
        assert!(build_guest_image(&executable, &runs).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_late_cleanup_barrier_does_not_turn_an_outage_failure_into_an_error() {
        // The runtime can finish the cleanup barrier after the host has read the
        // exit record, so a network command issued during the early stop can be
        // acknowledged after that barrier.
        let mut vm = fake_workload_vm();
        vm.exit_on_outage = true;
        let (events, report) = drive_fake_workload(&mut vm);
        assert!(!report.passed);
        let cleanup = events
            .iter()
            .position(|frame| matches!(frame.event, Event::CleanupComplete { .. }))
            .expect("the delayed barrier was folded in");
        let restoration = events
            .iter()
            .position(|frame| matches!(frame.event, Event::NetworkRestored { .. }))
            .expect("the driver restored the network");
        assert!(cleanup < restoration);
    }

    #[test]
    fn a_wrong_network_acknowledgement_is_rejected() {
        // The acknowledgement must name the values the host configured, not just
        // its variant.
        let scenario = workload_scenario_fixture();
        let choices = scenario.choices(42);
        let mut vm = fake_workload_vm();
        vm.mismatched_network = true;
        let mut diagnostics = failure_diagnostics("record");
        let error = drive_workload_scenario(
            &scenario,
            &choices,
            &workload_launch(),
            &mut vm,
            &mut diagnostics,
        )
        .unwrap_err();
        assert!(error.to_string().contains("network_configured"), "{error}");
    }

    #[test]
    fn a_late_agent_stopped_acknowledgement_is_rejected() {
        let scenario = workload_scenario_fixture();
        let choices = scenario.choices(42);
        let mut vm = fake_workload_vm();
        vm.late_agent_stopped = true;
        let mut diagnostics = failure_diagnostics("record");
        let error = drive_workload_scenario(
            &scenario,
            &choices,
            &workload_launch(),
            &mut vm,
            &mut diagnostics,
        )
        .unwrap_err();
        assert!(error.to_string().contains("agent-stopped"), "{error}");
    }

    #[test]
    fn a_record_rejects_a_future_command_event() {
        // Only a replayed guest can run ahead of the host, so a live recording
        // treats a future-command event as an envelope violation instead of
        // parking it.
        let scenario = workload_scenario_fixture();
        let choices = scenario.choices(42);
        let mut vm = fake_workload_vm();
        vm.future_command_event = true;
        let mut diagnostics = failure_diagnostics("record");
        let error = drive_workload_scenario(
            &scenario,
            &choices,
            &workload_launch(),
            &mut vm,
            &mut diagnostics,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("unexpected event envelope"),
            "{error}"
        );
    }

    #[test]
    fn a_stderr_failure_stops_the_wait_instead_of_timing_out() {
        // The fixture writes to stderr only when it is failing, so a live
        // application error must end the wait for a response line and publish a
        // failing run rather than exhausting the VM deadline.
        let mut vm = fake_workload_vm();
        vm.stderr_without_exit = true;
        let (events, report) = drive_fake_workload(&mut vm);
        assert!(!report.passed);
        assert!(!report.assertions[1].passed, "{:#?}", report.assertions);
        assert!(
            events
                .iter()
                .any(|frame| matches!(frame.event, Event::AgentStopped {}))
        );
    }

    #[test]
    fn the_workload_preflight_covers_the_launch_response_frame() {
        let scenario = workload_scenario_fixture();
        let choices = scenario.choices(42);
        // Grow the environment until the start *command* exactly fits one control
        // frame, then require the preflight to reject the identity because the
        // start *event* envelope is larger.
        let frame_bytes = |launch: &LaunchIdentity| -> usize {
            serde_json::to_vec(&CommandFrame {
                protocol_version: PROTOCOL_VERSION,
                command_id: u64::MAX,
                command: Command::Start {
                    invocation: 1,
                    launch: launch.clone(),
                },
            })
            .unwrap()
            .len()
        };
        let mut low = 0;
        let mut high = MAX_FRAME_LENGTH;
        while low < high {
            let middle = (low + high).div_ceil(2);
            let mut probe = workload_launch();
            probe.environment = vec![format!("BIG={}", "x".repeat(middle))];
            if frame_bytes(&probe) <= MAX_FRAME_LENGTH {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        let mut launch = workload_launch();
        launch.environment = vec![format!("BIG={}", "x".repeat(low))];
        assert!(frame_bytes(&launch) <= MAX_FRAME_LENGTH);
        let error = validate_workload_control_frames(&launch, &choices).unwrap_err();
        assert!(
            error.to_string().contains("workload-started event"),
            "{error}"
        );
    }

    #[test]
    fn the_guest_image_cache_rejects_a_non_regular_entry_without_blocking() {
        let root = temporary_root("image-cache-fifo");
        let runs = root.join("runs");
        let executable = root.join("simferret");
        let mut elf = vec![0_u8; 64];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        fs::write(&executable, elf).unwrap();

        let image = build_guest_image(&executable, &runs).unwrap();
        fs::remove_file(&image.path).unwrap();
        let path = std::ffi::CString::new(image.path.as_os_str().as_bytes()).unwrap();
        // A writer-less FIFO would block a hash, so the type check must run first.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let error = build_guest_image(&executable, &runs).unwrap_err();
        assert!(error.to_string().contains("file type"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_over_bound_unfinished_line_stops_the_wait_instead_of_timing_out() {
        // A response line that already exceeds the bound can never be valid, so
        // the driver must stop waiting for its newline.
        let mut vm = fake_workload_vm();
        vm.over_bound_line_without_exit = true;
        let (events, report) = drive_fake_workload(&mut vm);
        assert!(!report.passed);
        assert!(!report.assertions[0].passed, "{:#?}", report.assertions);
        assert!(
            report.assertions[0]
                .detail
                .contains("exceeds the response bound"),
            "{}",
            report.assertions[0].detail
        );
        assert!(
            events
                .iter()
                .any(|frame| matches!(frame.event, Event::AgentStopped {}))
        );
    }

    #[test]
    fn an_oversized_published_artifact_is_refused_before_publication() {
        let root = temporary_root("artifact-bounds");
        let staging = root.join("staging");
        fs::create_dir_all(staging.join("logs")).unwrap();
        for name in ARTIFACT_NAMES {
            fs::write(staging.join(name), b"x").unwrap();
        }
        // The diagnostic log exceeds the limit the replay path enforces, so the
        // run must be refused rather than published and then rejected on replay.
        fs::write(
            staging.join("logs/qemu.log"),
            vec![b'x'; MAX_DIAGNOSTIC_ARTIFACT_BYTES + 1],
        )
        .unwrap();
        let error = artifact_digests(&staging, false).unwrap_err();
        assert!(error.to_string().contains("qemu.log"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_malformed_canonical_specification_never_quotes_the_environment() {
        let root = temporary_root("canonical-specification-privacy");
        let options = workload_options(&root, false);
        let adapter = fake_adapter(None);
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        let store = options.runs_directory.join(WORKLOAD_STORE_NAME);

        // Rewrite the retained canonical specification so a launch field has the
        // wrong type and carries a marker, then make the raw closure agree with
        // the new object so the parser is reached.
        let closure_path = store.join("raw/closure.json");
        let mut closure: serde_json::Value =
            serde_json::from_slice(&fs::read(&closure_path).unwrap()).unwrap();
        let objects = closure["objects"].as_array_mut().unwrap();
        let record = objects
            .iter_mut()
            .find(|record| record["role"] == "workload-specification")
            .expect("the closure retains the canonical specification");
        let digest = record["digest"].as_str().unwrap().to_owned();
        let object_path = store.join(format!("raw/sha256/{}", &digest["sha256:".len()..]));
        let mut specification: serde_json::Value =
            serde_json::from_slice(&fs::read(&object_path).unwrap()).unwrap();
        specification["uid"] = serde_json::Value::String("SECRET=canonical-marker".into());
        let bytes = serde_json::to_vec(&specification).unwrap();
        let new_digest = format!("sha256:{}", sha256_bytes(&bytes));
        let new_path = store.join(format!("raw/sha256/{}", &new_digest["sha256:".len()..]));
        fs::write(&new_path, &bytes).unwrap();
        fs::remove_file(&object_path).unwrap();
        record["digest"] = serde_json::Value::String(new_digest);
        record["bytes"] = serde_json::Value::from(bytes.len());
        fs::write(&closure_path, serde_json::to_vec(&closure).unwrap()).unwrap();

        let error = replay_with_adapter(
            &replay_options(&options, recorded.directory.clone()),
            &adapter,
        )
        .unwrap_err();
        assert!(!error.to_string().contains("canonical-marker"), "{error}");
        assert!(
            error
                .to_string()
                .contains("malformed canonical specification"),
            "{error}"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_rejected_guest_fault_transition_never_reaches_the_failure_bundle() {
        // The guest's own event strings are unvalidated: a diverging activation
        // can carry any bytes. Neither the error text nor the retained bundle may
        // copy them, and the report still names the validated profile.
        let root = temporary_root("fault-transition-privacy");
        let options = workload_options(&root, false);
        let mut adapter = fake_adapter(None);
        adapter.forged_outage_activation = true;
        let error = record_with_adapter(&options, &adapter).unwrap_err();
        assert!(!error.to_string().contains("CANARY"), "{error}");
        assert!(error.to_string().contains("outage_activated"), "{error}");

        let bundle = only_failure_bundle(&options.runs_directory);
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(bundle.join("failure.json")).unwrap()).unwrap();
        let transitions = report["diagnostics"]["fault_transitions"]
            .as_array()
            .expect("the failure bundle retains the fault transition");
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0]["transition"], "activated");
        assert_eq!(transitions[0]["peer_cidr"], "10.0.2.2/32");
        assert_eq!(transitions[0]["rule"], "prohibit 10.0.2.2/32");
        assert!(
            !serde_json::to_string(&report).unwrap().contains("CANARY"),
            "{report}"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_over_bound_tail_after_a_matching_response_stops_the_run() {
        // The expected response is valid, but the unfinished tail that follows it
        // can never be, so the driver must stop rather than continue to the next
        // command and wait for an exit.
        let mut vm = fake_workload_vm();
        vm.over_bound_tail_after_response = true;
        let (events, report) = drive_fake_workload(&mut vm);
        assert!(!report.passed);
        assert!(!report.assertions[0].passed, "{:#?}", report.assertions);
        assert!(
            report.assertions[0]
                .detail
                .contains("exceeds the response bound"),
            "{}",
            report.assertions[0].detail
        );
        assert!(
            events
                .iter()
                .any(|frame| matches!(frame.event, Event::AgentStopped {}))
        );
        // The driver stopped at the first failing response: echo, state, and the
        // first request were acknowledged, and the end of input was never sent.
        let acknowledged = events
            .iter()
            .filter(|frame| {
                matches!(
                    frame.event,
                    Event::InputAccepted {
                        invocation: 1,
                        eof: false,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(acknowledged, 3);
        assert!(
            !events
                .iter()
                .any(|frame| matches!(frame.event, Event::InputAccepted { eof: true, .. }))
        );
    }

    #[test]
    fn a_recording_that_stops_on_a_late_tail_still_replays() {
        // The tail is serialized after the recording's pre-command drain, so the
        // recording stops one command later than a replay that can already see it.
        // Passive replay consumes and compares the recorded stream instead of
        // re-deciding the schedule, so the failing recording still replays.
        let root = temporary_root("late-tail-replay");
        let options = workload_options(&root, false);
        let mut adapter = fake_adapter(None);
        adapter.late_tail_after_response = true;
        let recorded = record_with_adapter(&options, &adapter).unwrap();
        assert!(!recorded.assertions.passed, "{:#?}", recorded.assertions);
        let replay = replay_with_adapter(
            &replay_options(&options, recorded.directory.clone()),
            &adapter,
        )
        .unwrap();
        assert_eq!(replay.assertions, recorded.assertions);
        assert_eq!(replay.exit_code(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_failure_before_the_end_of_input_acknowledgement_stops_the_run() {
        // The acknowledgement the host awaits can fold a failing tail, so the
        // failure is already observed when the driver starts waiting for the exit
        // that follows it. Waiting for one more output frame first would turn a
        // known application failure into a receive error.
        for tail in [FailingTail::Stderr, FailingTail::OverBound] {
            let mut vm = fake_workload_vm();
            vm.failing_tail_before_eof = Some(tail);
            let (events, report) = drive_fake_workload(&mut vm);
            assert!(!report.passed, "{tail:?}");
            assert!(
                !report.assertions[0].passed,
                "{tail:?} {:#?}",
                report.assertions
            );
            assert!(
                events
                    .iter()
                    .any(|frame| matches!(frame.event, Event::InputAccepted { eof: true, .. })),
                "{tail:?}"
            );
            assert!(
                events
                    .iter()
                    .any(|frame| matches!(frame.event, Event::AgentStopped {})),
                "{tail:?}"
            );
            if tail == FailingTail::Stderr {
                assert!(
                    report.assertions[1].detail.contains("application error"),
                    "{:#?}",
                    report.assertions
                );
            }
        }
    }

    /// A fake guest and scenario for driving the workload control loop directly,
    /// without a record or replay publication.
    fn workload_scenario_fixture() -> WorkloadScenario {
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

    fn workload_launch() -> LaunchIdentity {
        crate::workload::LaunchIdentity {
            executable: "/bin/simferret-workload".into(),
            arguments: vec!["/bin/simferret-workload".into()],
            environment: vec!["MODE=acceptance".into()],
            working_directory: "/".into(),
            uid: 65534,
            gid: 65534,
        }
    }

    fn fake_workload_vm() -> FakeVm {
        FakeVm {
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
            workload: FakeWorkload::default(),
            outage_active: false,
            exit_on_outage: false,
            stale_root: false,
            exit_after_start: false,
            duplicate_input_accept: false,
            mismatched_network: false,
            late_agent_stopped: false,
            future_command_event: false,
            pending_cleanup: None,
            stderr_without_exit: false,
            over_bound_line_without_exit: false,
            over_bound_tail_after_response: false,
            late_tail_after_response: false,
            failing_tail_before_eof: None,
            forged_outage_activation: false,
            exit_after_fetch: None,
            pending_tail: None,
        }
    }

    fn drive_fake_workload(vm: &mut FakeVm) -> (Vec<NormalizedEvent>, AssertionReport) {
        let scenario = workload_scenario_fixture();
        let choices = scenario.choices(42);
        drive_fake_workload_with(vm, &scenario, &choices)
    }

    fn drive_fake_workload_with(
        vm: &mut FakeVm,
        scenario: &WorkloadScenario,
        choices: &WorkloadChoicePlan,
    ) -> (Vec<NormalizedEvent>, AssertionReport) {
        let mut diagnostics = failure_diagnostics("record");
        drive_workload_scenario(scenario, choices, &workload_launch(), vm, &mut diagnostics)
            .expect("an application failure must not become an infrastructure failure")
    }

    #[test]
    fn a_clean_exit_before_the_end_of_input_fails_response_integrity() {
        // The driver stops issuing commands as soon as it observes an exit, so a
        // workload that stops on its own after its last response produces a
        // recording without the end-of-input acknowledgement. Every response line
        // and root witness is intact, so only the checker's input accounting can
        // reject the incomplete scenario.
        let scenario = workload_scenario_fixture();
        let choices = scenario.choices(42);
        let mut vm = fake_workload_vm();
        vm.exit_after_fetch =
            Some((choices.requests.len() - choices.process_fault_request_index) as u64);
        let (events, report) = drive_fake_workload_with(&mut vm, &scenario, &choices);
        assert!(!report.passed, "{:#?}", report.assertions);
        assert!(!report.assertions[1].passed, "{:#?}", report.assertions);
        assert!(
            !events
                .iter()
                .any(|frame| matches!(frame.event, Event::InputAccepted { eof: true, .. })),
            "the driver must not have ended the input"
        );
    }

    #[test]
    fn an_application_failure_during_an_outage_restores_the_network_before_shutdown() {
        // The guest refuses to stop while the outage is active, so a driver that
        // stops early inside the outage window must restore the network first.
        let mut vm = fake_workload_vm();
        vm.exit_on_outage = true;
        let (events, report) = drive_fake_workload(&mut vm);
        assert!(!report.passed);
        let activation = events
            .iter()
            .position(|frame| matches!(frame.event, Event::OutageActivated { .. }))
            .expect("the outage was activated");
        let restoration = events
            .iter()
            .rposition(|frame| matches!(frame.event, Event::NetworkRestored { .. }))
            .expect("the driver restored the network");
        assert!(restoration > activation);
    }

    #[test]
    fn a_wrong_response_line_fails_the_property_instead_of_the_run() {
        // A stale root witness must fail process safety, not block the driver
        // until the VM deadline. The run is still published with the guest
        // stopped, so the application failure stays an application failure.
        let mut vm = fake_workload_vm();
        vm.stale_root = true;
        let (events, report) = drive_fake_workload(&mut vm);
        assert!(!report.passed);
        assert!(!report.assertions[0].passed, "{:#?}", report.assertions);
        assert!(
            events.iter().any(|frame| match &frame.event {
                Event::WorkloadOutput { bytes, .. } => crate::protocol::decode_bytes(bytes, 1024)
                    .unwrap()
                    .windows(b"root=stale".len())
                    .any(|window| window == b"root=stale"),
                _ => false,
            }),
            "the driver observed the stale response"
        );
        assert!(
            events
                .iter()
                .any(|frame| matches!(frame.event, Event::AgentStopped {}))
        );
    }

    #[test]
    fn a_workload_that_exits_before_its_first_command_stops_cleanly() {
        // The invocation is gone before the driver sends any input; the queued
        // exit must be observed instead of racing a command against a released
        // invocation.
        let mut vm = fake_workload_vm();
        vm.exit_after_start = true;
        let (events, report) = drive_fake_workload(&mut vm);
        assert!(!report.passed);
        assert!(
            events
                .iter()
                .any(|frame| matches!(frame.event, Event::AgentStopped {}))
        );
        assert!(
            !events
                .iter()
                .any(|frame| matches!(frame.event, Event::TerminationRequested { .. }))
        );
    }

    #[test]
    fn a_duplicated_input_acknowledgement_fails_process_safety() {
        // A second acknowledgement for one command is a stream-structure
        // violation, so the run fails as a property rather than as an error.
        let mut vm = fake_workload_vm();
        vm.duplicate_input_accept = true;
        let (events, report) = drive_fake_workload(&mut vm);
        assert!(!report.passed);
        assert!(
            report.assertions[0].detail.contains("input"),
            "{}",
            report.assertions[0].detail
        );
        assert!(
            events
                .iter()
                .any(|frame| matches!(frame.event, Event::AgentStopped {}))
        );
    }

    #[test]
    fn the_workload_preflight_rejects_an_undeliverable_launch_or_payload() {
        let scenario = workload_scenario_fixture();
        let choices = scenario.choices(42);
        validate_workload_control_frames(&workload_launch(), &choices).unwrap();

        // A launch identity whose serialized start command cannot fit one control
        // frame is rejected before QEMU starts.
        let mut launch = workload_launch();
        launch.environment = vec![format!("BIG={}", "x".repeat(MAX_FRAME_LENGTH))];
        let error = validate_workload_control_frames(&launch, &choices).unwrap_err();
        assert!(error.to_string().contains("control frame limit"), "{error}");

        // A planned input that cannot fit the runtime's decoded input bound is
        // rejected too.
        let mut oversized = choices.clone();
        oversized.requests[0].payload = "a".repeat(MAX_STDIN_FRAME_BYTES);
        let error = validate_workload_control_frames(&workload_launch(), &oversized).unwrap_err();
        assert!(error.to_string().contains("input limit"), "{error}");
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
            workload: FakeWorkload::default(),
            outage_active: false,
            exit_on_outage: false,
            stale_root: false,
            exit_after_start: false,
            duplicate_input_accept: false,
            mismatched_network: false,
            late_agent_stopped: false,
            future_command_event: false,
            pending_cleanup: None,
            stderr_without_exit: false,
            over_bound_line_without_exit: false,
            over_bound_tail_after_response: false,
            late_tail_after_response: false,
            failing_tail_before_eof: None,
            forged_outage_activation: false,
            exit_after_fetch: None,
            pending_tail: None,
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
