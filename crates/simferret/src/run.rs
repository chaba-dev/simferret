use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::{Compression, GzBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::assertions::{AssertionReport, evaluate};
use crate::protocol::{
    Command, CommandFrame, Event, EventFrame, NormalizedEvent, PROTOCOL_VERSION, RequestPhase,
};
use crate::scenario::{ChoicePlan, Scenario};
use crate::vm::{QemuAdapter, RecordConfig, RunningVm, VmAdapter, VmIdentity, sha256_file};

const MANIFEST_VERSION: u16 = 1;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_SEMANTIC_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
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

pub fn record(options: &RunOptions) -> io::Result<RunResult> {
    if std::env::consts::OS != "linux" || std::env::consts::ARCH != "x86_64" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "record mode supports x86-64 Linux only",
        ));
    }
    let adapter = QemuAdapter::from_environment()?;
    record_with_adapter(options, &adapter)
}

pub fn replay(options: &ReplayOptions) -> io::Result<ReplayResult> {
    if std::env::consts::OS != "linux" || std::env::consts::ARCH != "x86_64" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "replay mode supports x86-64 Linux only",
        ));
    }
    let adapter = QemuAdapter::from_environment()?;
    replay_with_adapter(options, &adapter)
}

pub fn record_with_adapter(options: &RunOptions, adapter: &dyn VmAdapter) -> io::Result<RunResult> {
    let (scenario, scenario_source) = Scenario::read(&options.scenario)?;
    let choices = scenario.choices(options.seed);
    let image = build_guest_image(&options.executable, &options.runs_directory)?;
    let run_id = new_run_id(options.seed)?;
    let mut staging = StagingDirectory::create(&options.runs_directory, &run_id)?;
    fs::create_dir(staging.path.join("logs"))?;
    fs::write(staging.path.join("scenario.toml"), scenario_source)?;
    write_json(staging.path.join("choices.json"), &choices)?;

    let qmp = QmpDirectory::create(&run_id)?;
    let config = RecordConfig {
        kernel: fs::canonicalize(&options.kernel)?,
        initramfs: image.path,
        replay_log: staging.path.join("replay.bin"),
        qmp_socket: qmp.path.join("qmp.sock"),
        serial_log: staging.path.join("logs/serial.log"),
        qemu_log: staging.path.join("logs/qemu.log"),
    };
    let execution = (|| {
        let mut vm = adapter.launch_record(&config)?;
        let identity = vm.identity().clone();
        let (events, assertions) = drive_scenario(&scenario, &choices, vm.as_mut())?;
        let status = vm.wait()?;
        if !status.success() {
            return Err(io::Error::other(format!("QEMU exited with {status}")));
        }
        Ok((identity, events, assertions))
    })();
    let (identity, events, assertions) =
        execution.map_err(|error| error_with_diagnostics(error, &staging.path))?;

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
        run_id,
        directory,
        assertions,
    })
}

pub fn replay_with_adapter(
    options: &ReplayOptions,
    adapter: &dyn VmAdapter,
) -> io::Result<ReplayResult> {
    let directory = fs::canonicalize(&options.directory)?;
    let manifest: Manifest = read_json(&directory.join("manifest.json"), MAX_MANIFEST_BYTES)?;
    validate_manifest(&directory, &manifest)?;
    validate_artifacts(&directory, &manifest.artifacts)?;

    let (scenario, scenario_bytes) = Scenario::read(&directory.join("scenario.toml"))?;
    if scenario.name != manifest.scenario_name {
        return Err(invalid_data(format!(
            "scenario name differs from manifest: expected {:?}, found {:?}",
            manifest.scenario_name, scenario.name
        )));
    }
    let choice_bytes = read_bounded(&directory.join("choices.json"), MAX_SEMANTIC_ARTIFACT_BYTES)?;
    let choices: ChoicePlan = serde_json::from_slice(&choice_bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let materialized_choices = scenario.choices(manifest.seed);
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
    let expected_assertions: AssertionReport = serde_json::from_slice(&expected_assertion_bytes)
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

    let runs_directory = directory
        .parent()
        .ok_or_else(|| invalid_data("run directory has no parent"))?;
    let image = build_guest_image(&options.executable, runs_directory)?;
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

    let runtime = QmpDirectory::create(&format!("replay-{}", manifest.run_id))?;
    let replay_log = runtime.path.join("replay.bin");
    fs::copy(directory.join("replay.bin"), &replay_log)?;
    let expected_replay_digest = &manifest.artifacts["replay.bin"];
    let copied_replay_digest = sha256_file(&replay_log)?;
    if &copied_replay_digest != expected_replay_digest {
        return Err(invalid_data(format!(
            "replay log changed while preparing replay: expected {expected_replay_digest}, found {copied_replay_digest}"
        )));
    }
    let config = RecordConfig {
        kernel: fs::canonicalize(&options.kernel)?,
        initramfs: image.path,
        replay_log,
        qmp_socket: runtime.path.join("qmp.sock"),
        serial_log: runtime.path.join("serial.log"),
        qemu_log: runtime.path.join("qemu.log"),
    };
    let execution = (|| {
        let mut vm = adapter.launch_replay(&config, &manifest.vm)?;
        let (events, assertions) = drive_scenario(&scenario, &choices, vm.as_mut())?;
        let status = vm.wait()?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "QEMU replay exited with {status}"
            )));
        }
        Ok((events, assertions))
    })();
    let (events, assertions) =
        execution.map_err(|error| error_with_diagnostics(error, &runtime.path))?;

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
        run_id: manifest.run_id,
        event_count: events.len(),
        semantic_outcome_sha256,
        assertions,
    })
}

fn drive_scenario(
    scenario: &Scenario,
    choices: &ChoicePlan,
    vm: &mut dyn RunningVm,
) -> io::Result<(Vec<NormalizedEvent>, AssertionReport)> {
    let mut controller = Controller::new(vm);
    controller.issue(Command::StartServer {
        address: scenario.server_address.clone(),
        corrupt_responses: scenario.corrupt_responses,
    })?;
    for (index, request) in choices.requests.iter().enumerate() {
        if index == choices.fault_request_index {
            controller.issue(Command::StopServer {})?;
            controller.issue(Command::Request {
                request_id: request.request_id.clone(),
                payload: request.payload.clone(),
                phase: RequestPhase::Stopped,
            })?;
            controller.issue(Command::StartServer {
                address: scenario.server_address.clone(),
                corrupt_responses: false,
            })?;
        } else {
            let phase = if index < choices.fault_request_index {
                RequestPhase::Running
            } else {
                RequestPhase::Restarted
            };
            controller.issue(Command::Request {
                request_id: request.request_id.clone(),
                payload: request.payload.clone(),
                phase,
            })?;
        }
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
    Ok((controller.events, host_assertions))
}

struct Controller<'a> {
    vm: &'a mut dyn RunningVm,
    next_command_id: u64,
    next_event_id: u64,
    raw_events: Vec<EventFrame>,
    events: Vec<NormalizedEvent>,
}

impl<'a> Controller<'a> {
    fn new(vm: &'a mut dyn RunningVm) -> Self {
        Self {
            vm,
            next_command_id: 1,
            next_event_id: 1,
            raw_events: Vec::new(),
            events: Vec::new(),
        }
    }

    fn issue(&mut self, command: Command) -> io::Result<Vec<EventFrame>> {
        let command_id = self.next_command_id;
        self.next_command_id += 1;
        self.vm.send(&CommandFrame {
            protocol_version: PROTOCOL_VERSION,
            command_id,
            command: command.clone(),
        })?;
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
            self.raw_events.push(event.clone());
            self.events.push(event.normalize());
            received.push(event);
        }
        validate_responses(&command, &received)?;
        Ok(received)
    }
}

fn validate_responses(command: &Command, events: &[EventFrame]) -> io::Result<()> {
    let valid = match command {
        Command::StartServer {
            address,
            corrupt_responses,
        } => matches!(
            events,
            [EventFrame { event: Event::ServerStarted { address: actual_address, corrupt_responses: actual_corruption }, .. }]
                if socket_addresses_equal(actual_address, address) && actual_corruption == corrupt_responses
        ),
        Command::StopServer {} => matches!(
            events,
            [EventFrame {
                event: Event::ServerStopped {},
                ..
            }]
        ),
        Command::Request {
            request_id,
            payload,
            phase,
        } => {
            matches!(events.first().map(|frame| &frame.event), Some(Event::RequestAttempted {
                request_id: actual_id, payload: actual_payload, phase: actual_phase,
            }) if actual_id == request_id && actual_payload == payload && actual_phase == phase)
                && (matches!(events.get(1).map(|frame| &frame.event),
                    Some(Event::RequestSucceeded { request_id: actual_id, request_payload, phase: actual_phase, .. })
                        if actual_id == request_id && request_payload == payload && actual_phase == phase)
                    || matches!(events.get(1).map(|frame| &frame.event),
                    Some(Event::RequestUnavailable { request_id: actual_id, phase: actual_phase })
                        if actual_id == request_id && actual_phase == phase))
        }
        Command::Check { .. } => {
            matches!(events, [EventFrame { event: Event::AssertionsEvaluated { report }, .. }] if valid_report(report))
        }
        Command::Shutdown {} => matches!(
            events,
            [EventFrame {
                event: Event::AgentStopped {},
                ..
            }]
        ),
    };
    if valid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("events do not match command {command:?}: {events:?}"),
        ))
    }
}

fn socket_addresses_equal(left: &str, right: &str) -> bool {
    match (
        left.parse::<std::net::SocketAddr>(),
        right.parse::<std::net::SocketAddr>(),
    ) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn valid_report(report: &AssertionReport) -> bool {
    use crate::assertions::AssertionName;

    let mut seen = [false; 3];
    for assertion in &report.assertions {
        let index = match assertion.name {
            AssertionName::Safety => 0,
            AssertionName::ControlledOutage => 1,
            AssertionName::BoundedLiveness => 2,
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
        let suffix = run_id
            .rsplit_once('-')
            .map(|(prefix, _)| &prefix[prefix.len().saturating_sub(16)..])
            .unwrap_or(run_id);
        let path = Path::new("/tmp").join(format!("sf-{}-{suffix}", std::process::id()));
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

fn build_guest_image(executable: &Path, runs_directory: &Path) -> io::Result<GuestImage> {
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
    append_cpio(&mut archive, "dev", 0o040755, &[])?;
    append_cpio(&mut archive, "proc", 0o040755, &[])?;
    append_cpio(&mut archive, "sys", 0o040755, &[])?;
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
        let actual = sha256_file(&directory.join(name))?;
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
    fs::File::open(path)?
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
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::Mutex;

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
    }

    struct FakeAdapter {
        identity: Mutex<VmIdentity>,
        replace_executable: Option<PathBuf>,
        mismatch_request: bool,
        force_unavailable: bool,
        forged_assertions: bool,
        extra_after_shutdown: bool,
        malformed_after_shutdown: bool,
    }

    struct FailingAdapter;

    impl FakeAdapter {
        fn vm(&self, config: &RecordConfig) -> io::Result<FakeVm> {
            fs::write(&config.serial_log, b"serial diagnostics")?;
            fs::write(&config.qemu_log, b"qemu diagnostics")?;
            let mut identity = self.identity.lock().unwrap().clone();
            identity.initramfs_sha256 = sha256_file(&config.initramfs)?;
            identity.kernel.sha256 = sha256_file(&config.kernel)?;
            Ok(FakeVm {
                identity,
                queued: VecDeque::new(),
                history: Vec::new(),
                next_event_id: 1,
                corrupt: false,
                running: false,
                mismatch_request: self.mismatch_request,
                force_unavailable: self.force_unavailable,
                forged_assertions: self.forged_assertions,
                extra_after_shutdown: self.extra_after_shutdown,
                malformed_after_shutdown: self.malformed_after_shutdown,
            })
        }
    }

    impl VmAdapter for FailingAdapter {
        fn launch_record(&self, config: &RecordConfig) -> io::Result<Box<dyn RunningVm>> {
            fs::write(&config.qemu_log, b"distinctive startup failure")?;
            fs::write(&config.serial_log, b"guest boot failed")?;
            Err(io::Error::other("adapter failed"))
        }
    }

    impl VmAdapter for FakeAdapter {
        fn launch_record(&self, config: &RecordConfig) -> io::Result<Box<dyn RunningVm>> {
            fs::write(&config.replay_log, b"replay")?;
            if let Some(path) = &self.replace_executable {
                fs::write(path, b"replacement executable")?;
            }
            Ok(Box::new(self.vm(config)?))
        }

        fn launch_replay(
            &self,
            config: &RecordConfig,
            expected_identity: &VmIdentity,
        ) -> io::Result<Box<dyn RunningVm>> {
            let vm = self.vm(config)?;
            if &vm.identity != expected_identity {
                return Err(invalid_data("fake replay environment identity differs"));
            }
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
            self.queued.push_back(frame);
        }
    }

    impl RunningVm for FakeVm {
        fn identity(&self) -> &VmIdentity {
            &self.identity
        }

        fn send(&mut self, frame: &CommandFrame) -> io::Result<()> {
            match &frame.command {
                Command::StartServer {
                    address,
                    corrupt_responses,
                } => {
                    self.running = true;
                    self.corrupt = *corrupt_responses;
                    self.event(
                        frame.command_id,
                        Event::ServerStarted {
                            address: address.clone(),
                            corrupt_responses: *corrupt_responses,
                        },
                    );
                }
                Command::StopServer {} => {
                    self.running = false;
                    self.event(frame.command_id, Event::ServerStopped {});
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
    fn controller_stops_at_materialized_choice_and_checks_results() {
        let scenario = Scenario {
            version: 1,
            name: "test".into(),
            request_count: 4,
            payload_bytes: 2,
            server_address: "127.0.0.1:4000".into(),
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
        };
        let (events, report) = drive_scenario(&scenario, &choices, &mut vm).unwrap();
        assert!(report.passed);
        assert!(events.iter().any(|frame| matches!(
            frame.event,
            Event::RequestUnavailable {
                phase: RequestPhase::Stopped,
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
            "version = 1\nname = \"test\"\nrequest_count = 4\npayload_bytes = 2\nserver_address = \"127.0.0.1:4000\"\noutage_event_bound = 1\nliveness_event_bound = 2\ncorrupt_responses = false\n",
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
            let error = drive_scenario(&scenario, &choices, &mut vm).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn assertion_failure_is_published_and_produces_nonzero_status() {
        let root = temporary_root("assertion-failure");
        let options = test_options(&root, true);
        let result = record_with_adapter(&options, &fake_adapter(None)).unwrap();
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
    fn canonical_addresses_match_but_different_endpoints_do_not() {
        assert!(socket_addresses_equal(
            "[0:0:0:0:0:0:0:1]:4000",
            "[::1]:4000"
        ));
        assert!(!socket_addresses_equal("[::1]:4000", "[::1]:4001"));
        assert!(!socket_addresses_equal("invalid", "invalid"));
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
                assertion(AssertionName::BoundedLiveness, true),
            ],
        };
        assert!(!valid_report(&duplicate));
        let inconsistent = AssertionReport {
            passed: true,
            assertions: vec![
                assertion(AssertionName::Safety, false),
                assertion(AssertionName::ControlledOutage, true),
                assertion(AssertionName::BoundedLiveness, true),
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
                "version = 1\nname = \"test\"\nrequest_count = 4\npayload_bytes = 2\nserver_address = \"127.0.0.1:4000\"\noutage_event_bound = 1\nliveness_event_bound = 2\ncorrupt_responses = {corrupt}\n"
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
        }
    }

    fn test_scenario(corrupt: bool) -> Scenario {
        Scenario {
            version: 1,
            name: "test".into(),
            request_count: 4,
            payload_bytes: 2,
            server_address: "127.0.0.1:4000".into(),
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
        }
    }
}
