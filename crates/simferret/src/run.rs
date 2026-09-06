use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::assertions::AssertionReport;
use crate::protocol::{
    Command, CommandFrame, Event, EventFrame, NormalizedEvent, PROTOCOL_VERSION, RequestPhase,
};
use crate::scenario::{ChoicePlan, Scenario};
use crate::vm::{QemuAdapter, RecordConfig, RunningVm, VmAdapter, VmIdentity, sha256_file};

const MANIFEST_VERSION: u16 = 1;

pub struct RunOptions {
    pub scenario: PathBuf,
    pub seed: u64,
    pub runs_directory: PathBuf,
    pub kernel: PathBuf,
    pub executable: PathBuf,
}

pub struct RunResult {
    pub run_id: String,
    pub directory: PathBuf,
    pub assertions: AssertionReport,
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

pub fn record_with_adapter(options: &RunOptions, adapter: &dyn VmAdapter) -> io::Result<RunResult> {
    let (scenario, scenario_source) = Scenario::read(&options.scenario)?;
    let choices = scenario.choices(options.seed);
    let image = build_guest_image(&options.executable, &options.runs_directory)?;
    let run_id = new_run_id(options.seed)?;
    let mut staging = StagingDirectory::create(&options.runs_directory, &run_id)?;
    fs::create_dir(staging.path.join("logs"))?;
    fs::write(staging.path.join("scenario.toml"), scenario_source)?;
    write_json(staging.path.join("choices.json"), &choices)?;

    let config = RecordConfig {
        kernel: options.kernel.clone(),
        initramfs: image,
        replay_log: staging.path.join("replay.bin"),
        qmp_socket: std::env::temp_dir().join(format!(
            "simferret-qmp-{}-{}.sock",
            std::process::id(),
            &run_id[..16]
        )),
        serial_log: staging.path.join("logs/serial.log"),
        qemu_log: staging.path.join("logs/qemu.log"),
    };
    let mut vm = adapter.launch_record(&config)?;
    let identity = vm.identity().clone();
    let (events, assertions) = drive_scenario(&scenario, &choices, vm.as_mut())?;
    let status = vm.wait()?;
    if !status.success() {
        return Err(io::Error::other(format!("QEMU exited with {status}")));
    }

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
        simferret_path: options.executable.display().to_string(),
        simferret_sha256: sha256_file(&options.executable)?,
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

fn drive_scenario(
    scenario: &Scenario,
    choices: &ChoicePlan,
    vm: &mut dyn RunningVm,
) -> io::Result<(Vec<NormalizedEvent>, AssertionReport)> {
    let mut controller = Controller::new(vm);
    controller.issue(
        Command::StartServer {
            address: scenario.server_address.clone(),
            corrupt_responses: scenario.corrupt_responses,
        },
        1,
    )?;
    for (index, request) in choices.requests.iter().enumerate() {
        if index == choices.fault_request_index {
            controller.issue(Command::StopServer {}, 1)?;
            controller.issue(
                Command::Request {
                    request_id: request.request_id.clone(),
                    payload: request.payload.clone(),
                    phase: RequestPhase::Stopped,
                },
                2,
            )?;
            controller.issue(
                Command::StartServer {
                    address: scenario.server_address.clone(),
                    corrupt_responses: false,
                },
                1,
            )?;
        } else {
            let phase = if index < choices.fault_request_index {
                RequestPhase::Running
            } else {
                RequestPhase::Restarted
            };
            controller.issue(
                Command::Request {
                    request_id: request.request_id.clone(),
                    payload: request.payload.clone(),
                    phase,
                },
                2,
            )?;
        }
    }
    let check_events = controller.issue(
        Command::Check {
            outage_event_bound: scenario.outage_event_bound,
            liveness_event_bound: scenario.liveness_event_bound,
        },
        1,
    )?;
    let assertions = match &check_events[0].event {
        Event::AssertionsEvaluated { report } => report.clone(),
        event => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected assertion report, received {event:?}"),
            ));
        }
    };
    controller.issue(Command::Shutdown {}, 1)?;
    Ok((controller.events, assertions))
}

struct Controller<'a> {
    vm: &'a mut dyn RunningVm,
    next_command_id: u64,
    next_event_id: u64,
    events: Vec<NormalizedEvent>,
}

impl<'a> Controller<'a> {
    fn new(vm: &'a mut dyn RunningVm) -> Self {
        Self {
            vm,
            next_command_id: 1,
            next_event_id: 1,
            events: Vec::new(),
        }
    }

    fn issue(&mut self, command: Command, expected_events: usize) -> io::Result<Vec<EventFrame>> {
        let command_id = self.next_command_id;
        self.next_command_id += 1;
        self.vm.send(&CommandFrame {
            protocol_version: PROTOCOL_VERSION,
            command_id,
            command,
        })?;
        let mut received = Vec::with_capacity(expected_events);
        for _ in 0..expected_events {
            let event = self.vm.receive()?;
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
            self.events.push(event.normalize());
            received.push(event);
        }
        Ok(received)
    }
}

struct StagingDirectory {
    path: PathBuf,
    destination: PathBuf,
    published: bool,
}

impl StagingDirectory {
    fn create(root: &Path, run_id: &str) -> io::Result<Self> {
        fs::create_dir_all(root)?;
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

fn build_guest_image(executable: &Path, runs_directory: &Path) -> io::Result<PathBuf> {
    let executable_bytes = fs::read(executable)?;
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

    let mut gzip = ProcessCommand::new("gzip")
        .args(["-n", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut gzip_input = gzip.stdin.take().expect("gzip stdin was piped");
    let writer = thread::Builder::new()
        .name("initramfs-compressor-input".into())
        .spawn(move || gzip_input.write_all(&archive))?;
    let compressed = gzip.wait_with_output()?;
    writer
        .join()
        .map_err(|_| io::Error::other("initramfs compressor input thread panicked"))??;
    if !compressed.status.success() {
        return Err(io::Error::other(format!(
            "gzip failed with {}",
            compressed.status
        )));
    }
    let digest = digest_parts([compressed.stdout.as_slice()]);
    let cache = runs_directory.join(".images");
    fs::create_dir_all(&cache)?;
    let image = cache.join(format!("{digest}.cpio.gz"));
    if !image.exists() {
        let temporary = cache.join(format!(".{digest}.tmp-{}", std::process::id()));
        fs::write(&temporary, compressed.stdout)?;
        match fs::rename(&temporary, &image) {
            Ok(()) => {}
            Err(error) if image.exists() => {
                let _ = fs::remove_file(temporary);
                let _ = error;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(image)
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
    let artifacts = [
        "scenario.toml",
        "choices.json",
        "replay.bin",
        "events.jsonl",
        "assertions.json",
        "logs/qemu.log",
        "logs/serial.log",
    ];
    artifacts
        .into_iter()
        .map(|name| Ok((name.into(), sha256_file(&root.join(name))?)))
        .collect()
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
    }

    struct FakeAdapter {
        identity: Mutex<Option<VmIdentity>>,
    }

    impl VmAdapter for FakeAdapter {
        fn launch_record(&self, config: &RecordConfig) -> io::Result<Box<dyn RunningVm>> {
            fs::write(&config.replay_log, b"replay")?;
            fs::write(&config.serial_log, b"serial diagnostics")?;
            fs::write(&config.qemu_log, b"qemu diagnostics")?;
            let mut identity = self.identity.lock().unwrap().take().unwrap();
            identity.initramfs_sha256 = sha256_file(&config.initramfs)?;
            identity.kernel_sha256 = sha256_file(&config.kernel)?;
            Ok(Box::new(FakeVm {
                identity,
                queued: VecDeque::new(),
                history: Vec::new(),
                next_event_id: 1,
                corrupt: false,
                running: false,
            }))
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
                            request_id: request_id.clone(),
                            payload: payload.clone(),
                            phase: *phase,
                        },
                    );
                    let result = if self.running {
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
                    let report = crate::assertions::evaluate(
                        &self.history,
                        *outage_event_bound,
                        *liveness_event_bound,
                    );
                    self.event(frame.command_id, Event::AssertionsEvaluated { report });
                }
                Command::Shutdown {} => self.event(frame.command_id, Event::AgentStopped {}),
            }
            Ok(())
        }

        fn receive(&mut self) -> io::Result<EventFrame> {
            self.queued
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no fake event"))
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
        let runs_directory = root.join("runs");
        let adapter = FakeAdapter {
            identity: Mutex::new(Some(identity())),
        };
        let result = record_with_adapter(
            &RunOptions {
                scenario: scenario_path,
                seed: 42,
                runs_directory: runs_directory.clone(),
                kernel,
                executable,
            },
            &adapter,
        )
        .unwrap();

        assert!(result.assertions.passed);
        let manifest: Manifest =
            serde_json::from_slice(&fs::read(result.directory.join("manifest.json")).unwrap())
                .unwrap();
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

    fn identity() -> VmIdentity {
        VmIdentity {
            qemu_path: "qemu".into(),
            qemu_version: "test".into(),
            qemu_sha256: "0".repeat(64),
            kernel_path: "kernel".into(),
            kernel_sha256: "1".repeat(64),
            initramfs_sha256: "2".repeat(64),
            machine: "pc-i440fx-9.2".into(),
            cpu: "qemu64".into(),
            memory_mib: 128,
            vcpus: 1,
            accelerator: "tcg".into(),
            firmware: "none".into(),
            devices: vec!["virtio-serial-pci".into()],
        }
    }
}
