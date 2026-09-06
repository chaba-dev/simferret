use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, ExitStatus, Output, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::{CommandFrame, Event, EventFrame, PROTOCOL_VERSION, read_frame, write_frame};

const MACHINE: &str = "pc-i440fx-9.2";
const CPU: &str = "qemu64";
const MEMORY_MIB: u32 = 128;
const START_TIMEOUT: Duration = Duration::from_secs(10);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const EVENT_TIMEOUT: Duration = Duration::from_secs(180);
const EXIT_TIMEOUT: Duration = Duration::from_secs(180);
const QMP_MESSAGE_LIMIT: usize = 64 * 1024;
const PROBE_OUTPUT_LIMIT: usize = 64 * 1024;
const PROBE_READ_BUDGET: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct RecordConfig {
    pub kernel: PathBuf,
    pub initramfs: PathBuf,
    pub replay_log: PathBuf,
    pub qmp_socket: PathBuf,
    pub serial_log: PathBuf,
    pub qemu_log: PathBuf,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VmIdentity {
    pub qemu: FileIdentity,
    pub qemu_version: String,
    pub kernel: FileIdentity,
    pub initramfs_sha256: String,
    pub machine: String,
    pub cpu: String,
    pub memory_mib: u32,
    pub vcpus: u8,
    pub accelerator: String,
    pub firmware: Vec<FileIdentity>,
    pub devices: Vec<String>,
}

pub trait VmAdapter {
    fn launch_record(&self, config: &RecordConfig) -> io::Result<Box<dyn RunningVm>>;

    fn launch_replay(
        &self,
        _config: &RecordConfig,
        _expected_identity: &VmIdentity,
    ) -> io::Result<Box<dyn RunningVm>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "VM adapter does not support replay",
        ))
    }
}

pub trait RunningVm {
    fn identity(&self) -> &VmIdentity;
    fn send(&mut self, command: &CommandFrame) -> io::Result<()>;
    fn receive(&mut self) -> io::Result<EventFrame>;
    fn finish_events(&mut self) -> io::Result<()>;
    fn wait(&mut self) -> io::Result<ExitStatus>;
}

pub struct QemuAdapter {
    executable: PathBuf,
    data_directory: PathBuf,
    bios: PathBuf,
    linuxboot: PathBuf,
}

#[derive(Clone, Copy)]
enum ExecutionMode {
    Record,
    Replay,
}

impl ExecutionMode {
    fn qemu_value(self) -> &'static str {
        match self {
            Self::Record => "record",
            Self::Replay => "replay",
        }
    }
}

impl QemuAdapter {
    pub fn from_environment() -> io::Result<Self> {
        let executable = std::env::var_os("QEMU_SYSTEM_X86_64")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("qemu-system-x86_64"));
        Self::new(resolve_executable(&executable)?)
    }

    fn new(executable: PathBuf) -> io::Result<Self> {
        let prefix = executable
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid QEMU path"))?;
        let data_directory = prefix.join("share/qemu");
        let bios = data_directory.join("bios-256k.bin");
        let linuxboot = data_directory.join("linuxboot_dma.bin");
        for path in [&bios, &linuxboot] {
            if !path.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("required QEMU firmware is missing: {}", path.display()),
                ));
            }
        }
        Ok(Self {
            executable,
            data_directory,
            bios,
            linuxboot,
        })
    }

    fn identity(&self, config: &RecordConfig) -> io::Result<VmIdentity> {
        validate_utf8_paths(config)?;
        let output = bounded_output(&self.executable, &["--version"], START_TIMEOUT)?;
        if !output.status.success() {
            return Err(io::Error::other("qemu --version failed"));
        }
        let version = String::from_utf8(output.stdout)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(VmIdentity {
            qemu: file_identity(&self.executable)?,
            qemu_version: version.lines().next().unwrap_or_default().to_owned(),
            kernel: file_identity(&config.kernel)?,
            initramfs_sha256: sha256_file(&config.initramfs)?,
            machine: MACHINE.into(),
            cpu: CPU.into(),
            memory_mib: MEMORY_MIB,
            vcpus: 1,
            accelerator: "tcg".into(),
            firmware: vec![file_identity(&self.bios)?, file_identity(&self.linuxboot)?],
            devices: vec!["isa-serial".into()],
        })
    }

    fn arguments(&self, config: &RecordConfig, mode: ExecutionMode) -> io::Result<Vec<OsString>> {
        validate_utf8_paths(config)?;
        Ok(vec![
            "-machine".into(),
            format!("{MACHINE},accel=tcg").into(),
            "-cpu".into(),
            CPU.into(),
            "-smp".into(),
            "1".into(),
            "-m".into(),
            format!("{MEMORY_MIB}M").into(),
            "-nodefaults".into(),
            "-no-user-config".into(),
            "-display".into(),
            "none".into(),
            "-monitor".into(),
            "none".into(),
            "-L".into(),
            self.data_directory.as_os_str().into(),
            "-bios".into(),
            self.bios.as_os_str().into(),
            "-chardev".into(),
            option_path("file,id=diagnostics,path=", &config.serial_log, "")?,
            "-serial".into(),
            "chardev:diagnostics".into(),
            "-no-reboot".into(),
            "-net".into(),
            "none".into(),
            "-rtc".into(),
            "base=2000-01-01T00:00:00,clock=vm".into(),
            "-kernel".into(),
            config.kernel.as_os_str().into(),
            "-initrd".into(),
            config.initramfs.as_os_str().into(),
            "-append".into(),
            "console=ttyS0 quiet loglevel=0 panic=-1 nokaslr random.trust_cpu=off init=/init"
                .into(),
            "-chardev".into(),
            "stdio,id=agent,signal=off".into(),
            "-device".into(),
            "isa-serial,chardev=agent,index=1".into(),
            "-qmp".into(),
            option_path("unix:path=", &config.qmp_socket, ",server=on,wait=off")?,
            "-icount".into(),
            option_path(
                &format!("shift=auto,rr={},rrfile=", mode.qemu_value()),
                &config.replay_log,
                "",
            )?,
        ])
    }

    fn launch(
        &self,
        config: &RecordConfig,
        mode: ExecutionMode,
        expected_identity: Option<&VmIdentity>,
    ) -> io::Result<Box<dyn RunningVm>> {
        let mut stale_paths = vec![&config.qmp_socket];
        if matches!(mode, ExecutionMode::Record) {
            stale_paths.push(&config.replay_log);
        } else if !config.replay_log.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("replay log is missing: {}", config.replay_log.display()),
            ));
        }
        for path in stale_paths {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let identity = self.identity(config)?;
        if let Some(expected) = expected_identity
            && &identity != expected
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "replay environment identity differs from the recording\nexpected: {expected:#?}\nactual: {identity:#?}"
                ),
            ));
        }
        let qemu_log = File::create(&config.qemu_log)?;
        let mut command = ProcessCommand::new(&self.executable);
        command
            .args(self.arguments(config, mode)?)
            .current_dir(config.qmp_socket.parent().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "QMP socket has no parent")
            })?)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(qemu_log));
        configure_parent_death(&mut command)?;
        let mut child = command.spawn()?;
        if let Err(error) = qmp_negotiate(&mut child, &config.qmp_socket) {
            terminate(&mut child);
            let _ = fs::remove_file(&config.qmp_socket);
            return Err(error);
        }

        let input = child
            .stdin
            .take()
            .expect("qemu stdin was configured as piped");
        let mut output = child
            .stdout
            .take()
            .expect("qemu stdout was configured as piped");
        let writer = match CommandWriter::new(input, COMMAND_TIMEOUT) {
            Ok(writer) => writer,
            Err(error) => {
                terminate(&mut child);
                return Err(error);
            }
        };
        let (sender, events) = mpsc::channel();
        let event_reader = match thread::Builder::new()
            .name("qemu-agent-events".into())
            .spawn(move || {
                loop {
                    let event = read_frame(&mut output);
                    let finished = !matches!(event, Ok(Some(_)));
                    if sender.send(event).is_err() || finished {
                        break;
                    }
                }
            }) {
            Ok(reader) => reader,
            Err(error) => {
                terminate(&mut child);
                let _ = writer.join();
                return Err(error);
            }
        };
        let mut vm = QemuVm {
            child,
            writer: Some(writer),
            events,
            event_reader: Some(event_reader),
            identity,
            qmp_socket: config.qmp_socket.clone(),
            child_reaped: false,
        };
        let ready = vm.receive()?;
        if ready.protocol_version != PROTOCOL_VERSION
            || ready.event_id != 0
            || ready.command_id != 0
            || !matches!(ready.event, Event::AgentReady {})
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guest did not send the expected readiness event",
            ));
        }
        Ok(Box::new(vm))
    }
}

impl VmAdapter for QemuAdapter {
    fn launch_record(&self, config: &RecordConfig) -> io::Result<Box<dyn RunningVm>> {
        self.launch(config, ExecutionMode::Record, None)
    }

    fn launch_replay(
        &self,
        config: &RecordConfig,
        expected_identity: &VmIdentity,
    ) -> io::Result<Box<dyn RunningVm>> {
        self.launch(config, ExecutionMode::Replay, Some(expected_identity))
    }
}

type WriteRequest = (CommandFrame, mpsc::Sender<io::Result<()>>);

struct CommandWriter {
    requests: SyncSender<WriteRequest>,
    thread: Option<JoinHandle<()>>,
    timeout: Duration,
}

impl CommandWriter {
    fn new(mut output: impl Write + Send + 'static, timeout: Duration) -> io::Result<Self> {
        let (requests, receiver) = mpsc::sync_channel::<WriteRequest>(1);
        let thread = thread::Builder::new()
            .name("qemu-agent-commands".into())
            .spawn(move || {
                while let Ok((frame, completion)) = receiver.recv() {
                    let result = write_frame(&mut output, &frame);
                    let failed = result.is_err();
                    let _ = completion.send(result);
                    if failed {
                        return;
                    }
                }
            })?;
        Ok(Self {
            requests,
            thread: Some(thread),
            timeout,
        })
    }

    fn send(&self, frame: &CommandFrame) -> io::Result<()> {
        let (completion, result) = mpsc::channel();
        self.requests
            .send((frame.clone(), completion))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "command writer stopped"))?;
        match result.recv_timeout(self.timeout) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out writing command to guest",
            )),
            Err(RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "command writer disconnected",
            )),
        }
    }

    fn join(mut self) -> io::Result<()> {
        drop(self.requests);
        self.thread
            .take()
            .expect("writer thread is present")
            .join()
            .map_err(|_| io::Error::other("guest command writer panicked"))
    }
}

struct QemuVm {
    child: Child,
    writer: Option<CommandWriter>,
    events: Receiver<io::Result<Option<EventFrame>>>,
    event_reader: Option<JoinHandle<()>>,
    identity: VmIdentity,
    qmp_socket: PathBuf,
    child_reaped: bool,
}

impl RunningVm for QemuVm {
    fn identity(&self) -> &VmIdentity {
        &self.identity
    }

    fn send(&mut self, command: &CommandFrame) -> io::Result<()> {
        self.writer
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "VM input is closed"))?
            .send(command)
    }

    fn receive(&mut self) -> io::Result<EventFrame> {
        match self.events.recv_timeout(EVENT_TIMEOUT) {
            Ok(Ok(Some(event))) => Ok(event),
            Ok(Ok(None)) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "guest event channel closed",
            )),
            Ok(Err(error)) => Err(error),
            Err(RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for guest event",
            )),
            Err(RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "guest event reader disconnected",
            )),
        }
    }

    fn finish_events(&mut self) -> io::Result<()> {
        match self.events.recv_timeout(EVENT_TIMEOUT) {
            Ok(Ok(None)) => Ok(()),
            Ok(Ok(Some(event))) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected event after shutdown: {event:?}"),
            )),
            Ok(Err(error)) => Err(error),
            Err(RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "guest event channel did not close after shutdown",
            )),
            Err(RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "guest event reader disconnected without reporting EOF",
            )),
        }
    }

    fn wait(&mut self) -> io::Result<ExitStatus> {
        let deadline = Instant::now() + EXIT_TIMEOUT;
        loop {
            if child_exited(&mut self.child)? {
                let status = finish_exited_process_group(&mut self.child)?;
                self.child_reaped = true;
                if let Some(writer) = self.writer.take() {
                    writer.join()?;
                }
                if let Some(reader) = self.event_reader.take() {
                    reader
                        .join()
                        .map_err(|_| io::Error::other("guest event reader panicked"))?;
                }
                let _ = fs::remove_file(&self.qmp_socket);
                return Ok(status);
            }
            if Instant::now() >= deadline {
                terminate(&mut self.child);
                self.child_reaped = true;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for QEMU to exit",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for QemuVm {
    fn drop(&mut self) {
        if !self.child_reaped {
            terminate(&mut self.child);
            self.child_reaped = true;
        }
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
        if let Some(reader) = self.event_reader.take() {
            let _ = reader.join();
        }
        let _ = fs::remove_file(&self.qmp_socket);
    }
}

fn qmp_negotiate(child: &mut Child, socket: &Path) -> io::Result<()> {
    let deadline = Instant::now() + START_TIMEOUT;
    let stream = loop {
        match std::os::unix::net::UnixStream::connect(socket) {
            Ok(stream) => break stream,
            Err(error) if Instant::now() < deadline => {
                if child_exited(child)? {
                    return Err(io::Error::other("QEMU exited during startup"));
                }
                let _ = error;
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    };
    stream.set_nonblocking(true)?;
    let mut qmp = QmpConnection {
        stream,
        buffered: Vec::new(),
    };
    let greeting = qmp.read_message(deadline)?;
    if greeting.get("QMP").is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "QMP greeting is missing QMP capabilities",
        ));
    }
    qmp.execute("qmp_capabilities", 1, deadline)?;
    qmp.execute("query-status", 2, deadline)
}

struct QmpConnection {
    stream: std::os::unix::net::UnixStream,
    buffered: Vec<u8>,
}

impl QmpConnection {
    fn execute(&mut self, command: &str, id: u64, deadline: Instant) -> io::Result<()> {
        let mut request = serde_json::to_vec(&serde_json::json!({
            "execute": command,
            "id": id
        }))
        .map_err(io::Error::other)?;
        request.push(b'\n');
        self.write_all(&request, deadline)?;
        loop {
            let response = self.read_message(deadline)?;
            if response.get("id").and_then(serde_json::Value::as_u64) == Some(id) {
                if let Some(error) = response.get("error") {
                    return Err(io::Error::other(format!("QMP {command} failed: {error}")));
                }
                return Ok(());
            }
        }
    }

    fn write_all(&mut self, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
        while !bytes.is_empty() {
            match self.stream.write(bytes) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(written) => bytes = &bytes[written..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait_until(deadline, "QMP negotiation")?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn read_message(&mut self, deadline: Instant) -> io::Result<serde_json::Value> {
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out during QMP negotiation",
                ));
            }
            if let Some(end) = self.buffered.iter().position(|byte| *byte == b'\n') {
                let line: Vec<_> = self.buffered.drain(..=end).collect();
                return serde_json::from_slice(&line)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
            }
            if self.buffered.len() >= QMP_MESSAGE_LIMIT {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "QMP message exceeds maximum length",
                ));
            }
            let mut chunk = [0_u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "QMP channel closed",
                    ));
                }
                Ok(read) => self.buffered.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait_until(deadline, "QMP negotiation")?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

fn wait_until(deadline: Instant, operation: &str) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("timed out during {operation}"),
        ))
    } else {
        thread::sleep(Duration::from_millis(1));
        Ok(())
    }
}

fn bounded_output(executable: &Path, arguments: &[&str], timeout: Duration) -> io::Result<Output> {
    let (child, stdout, stderr) = spawn_probe(executable, arguments)?;
    collect_bounded_output(child, stdout, stderr, executable, timeout)
}

fn spawn_probe(
    executable: &Path,
    arguments: &[&str],
) -> io::Result<(Child, std::process::ChildStdout, std::process::ChildStderr)> {
    let mut command = ProcessCommand::new(executable);
    command
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_parent_death(&mut command)?;
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().expect("probe stdout was piped");
    let stderr = child.stderr.take().expect("probe stderr was piped");
    Ok((child, stdout, stderr))
}

fn collect_bounded_output(
    mut child: Child,
    mut stdout: std::process::ChildStdout,
    mut stderr: std::process::ChildStderr,
    executable: &Path,
    timeout: Duration,
) -> io::Result<Output> {
    if let Err(error) =
        set_nonblocking(stdout.as_raw_fd()).and_then(|()| set_nonblocking(stderr.as_raw_fd()))
    {
        terminate(&mut child);
        return Err(error);
    }
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let mut exited = false;
    let deadline = Instant::now() + timeout;
    loop {
        if let Err(error) =
            read_available(&mut stdout, &mut stdout_bytes, &mut stdout_eof, deadline).and_then(
                |()| read_available(&mut stderr, &mut stderr_bytes, &mut stderr_eof, deadline),
            )
        {
            terminate(&mut child);
            return Err(error);
        }
        if !exited {
            exited = match child_exited(&mut child) {
                Ok(exited) => exited,
                Err(error) => {
                    terminate(&mut child);
                    return Err(error);
                }
            };
        }
        if Instant::now() >= deadline {
            terminate(&mut child);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("timed out running {}", executable.display()),
            ));
        }
        if exited && stdout_eof && stderr_eof {
            let status = finish_exited_process_group(&mut child)?;
            return Ok(Output {
                status,
                stdout: stdout_bytes,
                stderr: stderr_bytes,
            });
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn set_nonblocking(fd: std::os::fd::RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn read_available(
    input: &mut impl Read,
    retained: &mut Vec<u8>,
    eof: &mut bool,
    deadline: Instant,
) -> io::Result<()> {
    let mut buffer = [0_u8; 4096];
    let mut total_read = 0;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out draining process output",
            ));
        }
        if total_read >= PROBE_READ_BUDGET {
            return Ok(());
        }
        match input.read(&mut buffer) {
            Ok(0) => {
                *eof = true;
                return Ok(());
            }
            Ok(read) => {
                total_read += read;
                let retained_bytes = (PROBE_OUTPUT_LIMIT - retained.len()).min(read);
                retained.extend_from_slice(&buffer[..retained_bytes]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(target_os = "linux")]
fn configure_parent_death(command: &mut ProcessCommand) -> io::Result<()> {
    use std::os::unix::process::CommandExt;

    let parent = unsafe { libc::getpid() };
    // SAFETY: only async-signal-safe libc calls are made between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                libc::raise(libc::SIGKILL);
            }
            Ok(())
        });
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn configure_parent_death(_command: &mut ProcessCommand) -> io::Result<()> {
    Ok(())
}

fn terminate(child: &mut Child) {
    terminate_process_group(child);
    let _ = child.wait();
}

#[cfg(target_os = "linux")]
fn child_exited(child: &mut Child) -> io::Result<bool> {
    let mut information = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            information.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let information = unsafe { information.assume_init() };
    Ok(unsafe { information.si_pid() } != 0)
}

#[cfg(not(target_os = "linux"))]
fn child_exited(child: &mut Child) -> io::Result<bool> {
    child.try_wait().map(|status| status.is_some())
}

#[cfg(target_os = "linux")]
fn finish_exited_process_group(child: &mut Child) -> io::Result<ExitStatus> {
    terminate_process_group(child);
    child.wait()
}

#[cfg(not(target_os = "linux"))]
fn finish_exited_process_group(child: &mut Child) -> io::Result<ExitStatus> {
    child.wait()
}

#[cfg(target_os = "linux")]
fn terminate_process_group(child: &mut Child) {
    unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
}

#[cfg(not(target_os = "linux"))]
fn terminate_process_group(child: &mut Child) {
    let _ = child.kill();
}

fn validate_utf8_paths(config: &RecordConfig) -> io::Result<()> {
    for path in [
        &config.kernel,
        &config.initramfs,
        &config.replay_log,
        &config.qmp_socket,
        &config.serial_log,
        &config.qemu_log,
    ] {
        if !path.is_absolute() || path.to_str().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QEMU paths must be absolute valid UTF-8",
            ));
        }
    }
    Ok(())
}

fn option_path(prefix: &str, path: &Path, suffix: &str) -> io::Result<OsString> {
    let path = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "QEMU path is not UTF-8"))?;
    Ok(format!("{prefix}{}{suffix}", path.replace(',', ",,")).into())
}

fn file_identity(path: &Path) -> io::Result<FileIdentity> {
    let path_string = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "identity path is not UTF-8"))?;
    Ok(FileIdentity {
        path: path_string.into(),
        sha256: sha256_file(path)?,
    })
}

fn resolve_executable(executable: &Path) -> io::Result<PathBuf> {
    if executable.components().count() > 1 {
        return fs::canonicalize(executable);
    }
    let path = std::env::var_os("PATH")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "PATH is not set"))?;
    resolve_from_path(executable, &path)
}

fn resolve_from_path(executable: &Path, path: &std::ffi::OsStr) -> io::Result<PathBuf> {
    std::env::split_paths(path)
        .map(|directory| directory.join(executable))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("executable not found: {}", executable.display()),
            )
        })
        .and_then(fs::canonicalize)
}

pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn config(root: &Path) -> RecordConfig {
        RecordConfig {
            kernel: root.join("kernel"),
            initramfs: root.join("initramfs"),
            replay_log: root.join("replay.bin"),
            qmp_socket: root.join("qmp.sock"),
            serial_log: root.join("serial.log"),
            qemu_log: root.join("qemu.log"),
        }
    }

    fn adapter(root: &Path) -> QemuAdapter {
        QemuAdapter {
            executable: root.join("bin/qemu-system-x86_64"),
            data_directory: root.join("share/qemu"),
            bios: root.join("share/qemu/bios-256k.bin"),
            linuxboot: root.join("share/qemu/linuxboot_dma.bin"),
        }
    }

    #[test]
    fn record_arguments_fix_identity_and_escape_option_paths() {
        let root = Path::new("/tmp/directory=with,comma");
        let arguments = adapter(root)
            .arguments(&config(root), ExecutionMode::Record)
            .unwrap();
        let arguments = arguments
            .iter()
            .map(|argument| argument.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        for required in [
            "pc-i440fx-9.2,accel=tcg",
            "-smp 1",
            "-net none",
            "-L /tmp/directory=with,comma/share/qemu",
            "-bios /tmp/directory=with,comma/share/qemu/bios-256k.bin",
            "rrfile=/tmp/directory=with,,comma/replay.bin",
            "unix:path=/tmp/directory=with,,comma/qmp.sock",
            "isa-serial,chardev=agent,index=1",
        ] {
            assert!(arguments.contains(required), "missing argument: {required}");
        }
    }

    #[test]
    fn replay_arguments_consume_the_existing_replay_log() {
        let root = Path::new("/tmp/replay");
        let arguments = adapter(root)
            .arguments(&config(root), ExecutionMode::Replay)
            .unwrap();
        assert!(
            arguments.iter().any(|argument| {
                argument == "shift=auto,rr=replay,rrfile=/tmp/replay/replay.bin"
            })
        );
    }

    #[test]
    fn non_utf8_qemu_path_is_rejected() {
        let mut config = config(Path::new("/tmp/root"));
        config.replay_log = PathBuf::from(OsString::from_vec(vec![0xff]));
        assert_eq!(
            validate_utf8_paths(&config).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn command_writer_times_out_when_transport_stalls() {
        let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
        let receive_buffer: libc::c_int = 1024;
        unsafe {
            libc::setsockopt(
                reader.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&receive_buffer as *const libc::c_int).cast(),
                std::mem::size_of_val(&receive_buffer) as libc::socklen_t,
            );
        }
        let command_writer = CommandWriter::new(writer, Duration::from_millis(20)).unwrap();
        let frame = CommandFrame {
            protocol_version: PROTOCOL_VERSION,
            command_id: 1,
            command: crate::protocol::Command::Request {
                request_id: "request".into(),
                payload: "x".repeat(crate::protocol::MAX_FRAME_LENGTH - 1024),
                phase: crate::protocol::RequestPhase::Running,
            },
        };
        assert_eq!(
            command_writer.send(&frame).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        drop(reader);
        command_writer.join().unwrap();
    }

    #[test]
    fn qmp_absolute_deadline_rejects_endless_unrelated_messages() {
        let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        let producer = thread::spawn(
            move || {
                while server.write_all(b"{\"event\":\"tick\"}\n").is_ok() {}
            },
        );
        let mut qmp = QmpConnection {
            stream: client,
            buffered: Vec::new(),
        };
        let error = qmp
            .execute(
                "query-status",
                7,
                Instant::now() + Duration::from_millis(20),
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(qmp);
        producer.join().unwrap();
    }

    #[test]
    fn bounded_process_probe_times_out() {
        let error =
            bounded_output(Path::new("sleep"), &["10"], Duration::from_millis(20)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn bounded_probe_drains_large_output_and_bounds_inherited_pipes() {
        let output = bounded_output(
            Path::new("sh"),
            &["-c", "head -c 100000 /dev/zero"],
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), PROBE_OUTPUT_LIMIT);

        let started = Instant::now();
        let error = bounded_output(
            Path::new("sh"),
            &["-c", "sleep 1 & exit 0"],
            Duration::from_millis(20),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(500));

        let started = Instant::now();
        let error = bounded_output(
            Path::new("sh"),
            &[
                "-c",
                "while :; do printf xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done",
            ],
            Duration::from_millis(20),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn relative_path_candidate_is_canonicalized() {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("relative-qemu-path-{}", std::process::id()));
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("bin/qemu-system-x86_64"), b"qemu").unwrap();
        let relative = root
            .strip_prefix(std::env::current_dir().unwrap())
            .unwrap()
            .join("bin");
        let resolved =
            resolve_from_path(Path::new("qemu-system-x86_64"), relative.as_os_str()).unwrap();
        assert!(resolved.is_absolute());
        assert_eq!(
            resolved,
            fs::canonicalize(root.join("bin/qemu-system-x86_64")).unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn observing_exit_keeps_process_waitable_until_group_cleanup() {
        let mut command = ProcessCommand::new("sh");
        command
            .args(["-c", "exit 7"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_parent_death(&mut command).unwrap();
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !child_exited(&mut child).unwrap() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(child_exited(&mut child).unwrap());
        assert_eq!(
            finish_exited_process_group(&mut child).unwrap().code(),
            Some(7)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn qmp_early_exit_remains_waitable_for_launch_cleanup() {
        let mut command = ProcessCommand::new("sh");
        command
            .args(["-c", "exit 9"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_parent_death(&mut command).unwrap();
        let mut child = command.spawn().unwrap();
        let socket = std::env::temp_dir().join(format!(
            "simferret-missing-qmp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let error = qmp_negotiate(&mut child, &socket).unwrap_err();
        assert!(error.to_string().contains("exited during startup"));
        assert!(child_exited(&mut child).unwrap());
        terminate(&mut child);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn timed_out_probe_terminates_its_process_group() {
        let root = std::env::temp_dir().join(format!(
            "simferret probe-'descendant-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let pid_file = root.join("descendant pid");
        let script =
            "sleep 30 & child=$!; printf %s \"$child\" > \"$1.tmp\"; mv \"$1.tmp\" \"$1\"; wait";
        let (mut probe, stdout, stderr) = spawn_probe(
            Path::new("sh"),
            &["-c", script, "simferret-probe", pid_file.to_str().unwrap()],
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !pid_file.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        let child_pid: libc::pid_t = match fs::read_to_string(&pid_file)
            .ok()
            .and_then(|value| value.parse().ok())
        {
            Some(pid) => pid,
            None => {
                terminate(&mut probe);
                panic!("probe did not publish a complete descendant PID");
            }
        };
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0) as libc::c_int };
        if pidfd < 0 {
            terminate(&mut probe);
            panic!("pidfd_open failed: {}", io::Error::last_os_error());
        }
        thread::sleep(Duration::from_millis(150));
        assert_eq!(
            collect_bounded_output(
                probe,
                stdout,
                stderr,
                Path::new("sh"),
                Duration::from_millis(100)
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut
        );
        let mut descriptor = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        let exited = unsafe { libc::poll(&mut descriptor, 1, 2000) };
        unsafe { libc::close(pidfd) };
        assert_eq!(exited, 1, "probe descendant was not terminated");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn firmware_identity_changes_with_firmware_content() {
        let root = std::env::temp_dir().join(format!("simferret-firmware-{}", std::process::id()));
        fs::create_dir_all(root.join("share/qemu")).unwrap();
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(
            root.join("bin/qemu-system-x86_64"),
            b"#!/bin/sh\necho QEMU test version\n",
        )
        .unwrap();
        fs::set_permissions(
            root.join("bin/qemu-system-x86_64"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(root.join("kernel"), b"kernel").unwrap();
        fs::write(root.join("initramfs"), b"initramfs").unwrap();
        fs::write(root.join("share/qemu/bios-256k.bin"), b"bios-a").unwrap();
        fs::write(root.join("share/qemu/linuxboot_dma.bin"), b"linuxboot").unwrap();
        let adapter = adapter(&root);
        let first = adapter.identity(&config(&root)).unwrap();
        assert_eq!(first.firmware.len(), 2);
        fs::write(root.join("share/qemu/bios-256k.bin"), b"bios-b").unwrap();
        let second = adapter.identity(&config(&root)).unwrap();
        assert_ne!(first.firmware[0].sha256, second.firmware[0].sha256);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn qemu_child_receives_parent_death_signal() {
        if let Some(pid_file) = std::env::var_os("SIMFERRET_PDEATH_HELPER") {
            let mut command = ProcessCommand::new("sleep");
            command.arg("30");
            configure_parent_death(&mut command).unwrap();
            let child = command.spawn().unwrap();
            let ready = PathBuf::from(pid_file);
            let temporary = ready.with_extension("tmp");
            fs::write(&temporary, child.id().to_string()).unwrap();
            fs::rename(temporary, ready).unwrap();
            std::mem::forget(child);
            loop {
                thread::sleep(Duration::from_secs(1));
            }
        }

        let pid_file = std::env::temp_dir().join(format!(
            "simferret-pdeath-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut parent = ProcessCommand::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "vm::tests::qemu_child_receives_parent_death_signal",
                "--nocapture",
            ])
            .env("SIMFERRET_PDEATH_HELPER", &pid_file)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !pid_file.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let child_pid: libc::pid_t = match fs::read_to_string(&pid_file)
            .ok()
            .and_then(|value| value.parse().ok())
        {
            Some(pid) => pid,
            None => {
                let _ = parent.kill();
                let _ = parent.wait();
                panic!("parent-death helper did not publish a complete PID");
            }
        };
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0) as libc::c_int };
        if pidfd < 0 {
            let _ = parent.kill();
            let _ = parent.wait();
            panic!("pidfd_open failed: {}", io::Error::last_os_error());
        }
        parent.kill().unwrap();
        parent.wait().unwrap();
        let mut descriptor = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        let exited = unsafe { libc::poll(&mut descriptor, 1, 5000) };
        unsafe { libc::close(pidfd) };
        assert_eq!(exited, 1, "child {child_pid} did not terminate");
        fs::remove_file(pid_file).unwrap();
    }
}
