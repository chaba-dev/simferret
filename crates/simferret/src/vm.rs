use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command as ProcessCommand, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::{CommandFrame, EventFrame, read_frame, write_frame};

const MACHINE: &str = "pc-i440fx-9.2";
const CPU: &str = "qemu64";
const MEMORY_MIB: u32 = 128;
const START_TIMEOUT: Duration = Duration::from_secs(10);
const EVENT_TIMEOUT: Duration = Duration::from_secs(10);
const EXIT_TIMEOUT: Duration = Duration::from_secs(60);

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
pub struct VmIdentity {
    pub qemu_path: String,
    pub qemu_version: String,
    pub qemu_sha256: String,
    pub kernel_path: String,
    pub kernel_sha256: String,
    pub initramfs_sha256: String,
    pub machine: String,
    pub cpu: String,
    pub memory_mib: u32,
    pub vcpus: u8,
    pub accelerator: String,
    pub firmware: String,
    pub devices: Vec<String>,
}

pub trait VmAdapter {
    fn launch_record(&self, config: &RecordConfig) -> io::Result<Box<dyn RunningVm>>;
}

pub trait RunningVm {
    fn identity(&self) -> &VmIdentity;
    fn send(&mut self, command: &CommandFrame) -> io::Result<()>;
    fn receive(&mut self) -> io::Result<EventFrame>;
    fn wait(&mut self) -> io::Result<ExitStatus>;
}

pub struct QemuAdapter {
    executable: PathBuf,
}

impl QemuAdapter {
    pub fn from_environment() -> io::Result<Self> {
        let executable = std::env::var_os("QEMU_SYSTEM_X86_64")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("qemu-system-x86_64"));
        Ok(Self {
            executable: resolve_executable(&executable)?,
        })
    }

    fn identity(&self, config: &RecordConfig) -> io::Result<VmIdentity> {
        let output = ProcessCommand::new(&self.executable)
            .arg("--version")
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other("qemu --version failed"));
        }
        let version = String::from_utf8(output.stdout)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(VmIdentity {
            qemu_path: self.executable.display().to_string(),
            qemu_version: version.lines().next().unwrap_or_default().to_owned(),
            qemu_sha256: sha256_file(&self.executable)?,
            kernel_path: config.kernel.display().to_string(),
            kernel_sha256: sha256_file(&config.kernel)?,
            initramfs_sha256: sha256_file(&config.initramfs)?,
            machine: MACHINE.into(),
            cpu: CPU.into(),
            memory_mib: MEMORY_MIB,
            vcpus: 1,
            accelerator: "tcg".into(),
            firmware: "none".into(),
            devices: vec!["isa-serial".into()],
        })
    }

    fn arguments(config: &RecordConfig) -> Vec<String> {
        vec![
            "-machine".into(),
            format!("{MACHINE},accel=tcg"),
            "-cpu".into(),
            CPU.into(),
            "-smp".into(),
            "1".into(),
            "-m".into(),
            format!("{MEMORY_MIB}M"),
            "-nodefaults".into(),
            "-no-user-config".into(),
            "-display".into(),
            "none".into(),
            "-monitor".into(),
            "none".into(),
            "-serial".into(),
            format!("file:{}", config.serial_log.display()),
            "-no-reboot".into(),
            "-net".into(),
            "none".into(),
            "-rtc".into(),
            "base=2000-01-01T00:00:00,clock=vm".into(),
            "-kernel".into(),
            config.kernel.display().to_string(),
            "-initrd".into(),
            config.initramfs.display().to_string(),
            "-append".into(),
            "console=ttyS0 quiet loglevel=0 panic=-1 nokaslr random.trust_cpu=off init=/init"
                .into(),
            "-chardev".into(),
            "stdio,id=agent,signal=off".into(),
            "-device".into(),
            "isa-serial,chardev=agent,index=1".into(),
            "-qmp".into(),
            format!("unix:{},server=on,wait=off", config.qmp_socket.display()),
            "-icount".into(),
            format!(
                "shift=auto,rr=record,rrfile={}",
                config.replay_log.display()
            ),
        ]
    }
}

impl VmAdapter for QemuAdapter {
    fn launch_record(&self, config: &RecordConfig) -> io::Result<Box<dyn RunningVm>> {
        for path in [&config.replay_log, &config.qmp_socket] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let identity = self.identity(config)?;
        let qemu_log = File::create(&config.qemu_log)?;
        let mut child = ProcessCommand::new(&self.executable)
            .args(Self::arguments(config))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(qemu_log))
            .spawn()?;
        if let Err(error) = qmp_negotiate(&mut child, &config.qmp_socket) {
            let _ = child.kill();
            let _ = child.wait();
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
                let _ = child.kill();
                let _ = child.wait();
                let _ = fs::remove_file(&config.qmp_socket);
                return Err(error);
            }
        };
        let mut vm = QemuVm {
            child,
            input: Some(input),
            events,
            event_reader: Some(event_reader),
            identity,
            qmp_socket: config.qmp_socket.clone(),
        };
        let ready = vm.receive()?;
        if ready.protocol_version != crate::protocol::PROTOCOL_VERSION
            || ready.event_id != 0
            || ready.command_id != 0
            || !matches!(ready.event, crate::protocol::Event::AgentReady {})
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guest did not send the expected readiness event",
            ));
        }
        Ok(Box::new(vm))
    }
}

struct QemuVm {
    child: Child,
    input: Option<ChildStdin>,
    events: Receiver<io::Result<Option<EventFrame>>>,
    event_reader: Option<JoinHandle<()>>,
    identity: VmIdentity,
    qmp_socket: PathBuf,
}

impl RunningVm for QemuVm {
    fn identity(&self) -> &VmIdentity {
        &self.identity
    }

    fn send(&mut self, command: &CommandFrame) -> io::Result<()> {
        write_frame(
            self.input
                .as_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "VM input is closed"))?,
            command,
        )
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

    fn wait(&mut self) -> io::Result<ExitStatus> {
        self.input.take();
        let deadline = Instant::now() + EXIT_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait()? {
                if let Some(reader) = self.event_reader.take() {
                    reader
                        .join()
                        .map_err(|_| io::Error::other("guest event reader panicked"))?;
                }
                let _ = fs::remove_file(&self.qmp_socket);
                return Ok(status);
            }
            if Instant::now() >= deadline {
                self.child.kill()?;
                self.child.wait()?;
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
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.input.take();
        if let Some(reader) = self.event_reader.take() {
            let _ = reader.join();
        }
        let _ = fs::remove_file(&self.qmp_socket);
    }
}

fn qmp_negotiate(child: &mut Child, socket: &Path) -> io::Result<()> {
    let deadline = Instant::now() + START_TIMEOUT;
    let stream = loop {
        match UnixStream::connect(socket) {
            Ok(stream) => break stream,
            Err(error) if Instant::now() < deadline => {
                if let Some(status) = child.try_wait()? {
                    return Err(io::Error::other(format!(
                        "QEMU exited during startup with {status}"
                    )));
                }
                let _ = error;
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    };
    stream.set_read_timeout(Some(START_TIMEOUT))?;
    stream.set_write_timeout(Some(START_TIMEOUT))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let greeting = read_qmp_message(&mut reader)?;
    if greeting.get("QMP").is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "QMP greeting is missing QMP capabilities",
        ));
    }
    let mut writer = stream;
    qmp_execute(&mut reader, &mut writer, "qmp_capabilities", 1)?;
    qmp_execute(&mut reader, &mut writer, "query-status", 2)?;
    Ok(())
}

fn qmp_execute(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    command: &str,
    id: u64,
) -> io::Result<()> {
    serde_json::to_writer(
        &mut *writer,
        &serde_json::json!({"execute": command, "id": id}),
    )
    .map_err(io::Error::other)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    loop {
        let response = read_qmp_message(reader)?;
        if response.get("id").and_then(serde_json::Value::as_u64) == Some(id) {
            if let Some(error) = response.get("error") {
                return Err(io::Error::other(format!("QMP {command} failed: {error}")));
            }
            return Ok(());
        }
    }
}

fn read_qmp_message(reader: &mut impl BufRead) -> io::Result<serde_json::Value> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "QMP channel closed",
        ));
    }
    serde_json::from_str(&line).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn resolve_executable(executable: &Path) -> io::Result<PathBuf> {
    if executable.components().count() > 1 {
        return fs::canonicalize(executable);
    }
    let path = std::env::var_os("PATH")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "PATH is not set"))?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(executable))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("executable not found: {}", executable.display()),
            )
        })
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
    use super::*;

    #[test]
    fn record_arguments_fix_the_determinism_boundary() {
        let config = RecordConfig {
            kernel: "kernel".into(),
            initramfs: "initramfs".into(),
            replay_log: "replay.bin".into(),
            qmp_socket: "qmp.sock".into(),
            serial_log: "serial.log".into(),
            qemu_log: "qemu.log".into(),
        };
        let arguments = QemuAdapter::arguments(&config).join(" ");
        for required in [
            "pc-i440fx-9.2,accel=tcg",
            "-smp 1",
            "-net none",
            "rr=record,rrfile=replay.bin",
            "isa-serial,chardev=agent,index=1",
        ] {
            assert!(arguments.contains(required), "missing argument: {required}");
        }
    }
}
