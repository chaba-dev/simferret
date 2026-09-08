use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, ExitStatus, Output, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::{
    CommandFrame, Event, EventFrame, MAX_FRAME_LENGTH, PROTOCOL_VERSION, SERIAL_ACK,
};

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
const MAX_FIXTURE_FILES: usize = 256;
const MAX_FIXTURE_FILE_BYTES: usize = 1024 * 1024;
const MAX_FIXTURE_BYTES: usize = 8 * 1024 * 1024;
static NETWORK_TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct RecordConfig {
    pub kernel: PathBuf,
    pub initramfs: PathBuf,
    pub replay_log: PathBuf,
    pub qmp_socket: PathBuf,
    pub serial_log: PathBuf,
    pub qemu_log: PathBuf,
    pub network: Option<NetworkConfig>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkIdentity>,
}

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub identity: NetworkIdentity,
    fixture_directory: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkIdentity {
    pub nic: NicIdentity,
    pub backend: BackendIdentity,
    pub replay_filter: Option<ReplayFilterIdentity>,
    pub addressing: AddressingIdentity,
    pub route: RouteIdentity,
    pub fixture: FixtureIdentity,
    pub fault: FaultIdentity,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NicIdentity {
    pub model: String,
    pub mac_address: String,
    pub bus: String,
    pub pci_address: String,
    pub option_rom: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendIdentity {
    pub kind: String,
    pub id: String,
    pub restricted: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayFilterIdentity {
    pub kind: String,
    pub id: String,
    pub backend_id: String,
    pub queue: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AddressingIdentity {
    pub guest_cidr: String,
    pub gateway: String,
    pub peer: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteIdentity {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureIdentity {
    pub transport: String,
    pub behavior: String,
    pub content_sha256: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FaultIdentity {
    pub mechanism: String,
    pub direction: String,
    pub peer_cidr: String,
    pub rule: String,
    pub tool: FileIdentity,
}

impl NetworkConfig {
    pub fn restricted_tftp_record(fixture_directory: PathBuf, busybox: &Path) -> io::Result<Self> {
        let busybox_sha256 = sha256_file(busybox)?;
        Self::restricted_tftp_record_with_tool_digest(fixture_directory, busybox_sha256)
    }

    pub(crate) fn restricted_tftp_record_with_tool_digest(
        fixture_directory: PathBuf,
        busybox_sha256: String,
    ) -> io::Result<Self> {
        let fixture_content_sha256 = fixture_digest(&fixture_directory)?;
        Ok(Self::restricted_tftp(
            Some(fixture_directory),
            fixture_content_sha256,
            busybox_sha256,
        ))
    }

    pub fn restricted_tftp_replay(fixture_content_sha256: String, busybox_sha256: String) -> Self {
        Self::restricted_tftp(None, fixture_content_sha256, busybox_sha256)
    }

    fn restricted_tftp(
        fixture_directory: Option<PathBuf>,
        fixture_content_sha256: String,
        busybox_sha256: String,
    ) -> Self {
        Self {
            identity: NetworkIdentity {
                nic: NicIdentity {
                    model: "rtl8139".into(),
                    mac_address: "52:54:00:12:34:56".into(),
                    bus: "pci.0".into(),
                    pci_address: "0x3".into(),
                    option_rom: false,
                },
                backend: BackendIdentity {
                    kind: "user".into(),
                    id: "simnet".into(),
                    restricted: true,
                },
                replay_filter: Some(ReplayFilterIdentity {
                    kind: "filter-replay".into(),
                    id: "simnet-replay".into(),
                    backend_id: "simnet".into(),
                    queue: "all".into(),
                }),
                addressing: AddressingIdentity {
                    guest_cidr: "10.0.2.15/24".into(),
                    gateway: "10.0.2.2".into(),
                    peer: "10.0.2.2".into(),
                },
                route: RouteIdentity {
                    destination: "0.0.0.0/0".into(),
                    gateway: "10.0.2.2".into(),
                    interface: "eth0".into(),
                },
                fixture: FixtureIdentity {
                    transport: "tftp".into(),
                    behavior: "immutable-files".into(),
                    content_sha256: fixture_content_sha256,
                },
                fault: FaultIdentity {
                    mechanism: "prohibit-route".into(),
                    direction: "outbound".into(),
                    peer_cidr: "10.0.2.2/32".into(),
                    rule: "prohibit 10.0.2.2/32".into(),
                    tool: FileIdentity {
                        path: "/bin/busybox".into(),
                        sha256: busybox_sha256,
                    },
                },
            },
            fixture_directory,
        }
    }

    fn validate(&self) -> io::Result<()> {
        self.identity.validate()
    }
}

impl NetworkIdentity {
    fn validate(&self) -> io::Result<()> {
        macro_rules! require {
            ($condition:expr, $message:literal) => {
                if !$condition {
                    return Err(invalid_network($message));
                }
            };
        }
        require!(
            self.nic.model == "rtl8139",
            "only the rtl8139 NIC is supported"
        );
        require!(
            self.nic.mac_address == "52:54:00:12:34:56",
            "the NIC MAC must match the proven fixed address"
        );
        require!(
            self.nic.bus == "pci.0" && self.nic.pci_address == "0x3",
            "the NIC must use the proven fixed PCI attachment"
        );
        require!(!self.nic.option_rom, "the NIC option ROM must be disabled");
        require!(
            self.backend.kind == "user",
            "TAP, bridge, socket, passthrough, and other network backends are not supported"
        );
        require!(
            self.backend.id == "simnet" && self.backend.restricted,
            "the user network backend must be restricted and use the fixed identifier"
        );
        let filter = self.replay_filter.as_ref().ok_or_else(|| {
            invalid_network("the replay filter is mandatory for every network backend")
        })?;
        require!(
            filter.kind == "filter-replay"
                && filter.id == "simnet-replay"
                && filter.backend_id == self.backend.id
                && filter.queue == "all",
            "the replay filter must use the proven backend attachment and all queues"
        );
        require!(
            self.addressing.guest_cidr == "10.0.2.15/24"
                && self.addressing.gateway == "10.0.2.2"
                && self.addressing.peer == "10.0.2.2",
            "guest addressing must match the proven private user-network profile"
        );
        require!(
            self.route.destination == "0.0.0.0/0"
                && self.route.gateway == self.addressing.gateway
                && self.route.interface == "eth0",
            "the guest route must match the proven private user-network profile"
        );
        require!(
            self.fixture.transport == "tftp" && self.fixture.behavior == "immutable-files",
            "only immutable content served by restricted TFTP is supported"
        );
        require!(
            valid_sha256(&self.fixture.content_sha256),
            "fixture content must have a lowercase SHA-256 identity"
        );
        require!(
            self.fault.mechanism == "prohibit-route"
                && self.fault.direction == "outbound"
                && self.fault.peer_cidr == "10.0.2.2/32"
                && self.fault.rule == "prohibit 10.0.2.2/32",
            "the fault must be the proven outbound peer-specific prohibit route"
        );
        require!(
            self.fault.tool.path == "/bin/busybox" && valid_sha256(&self.fault.tool.sha256),
            "the fault tool must be the digested /bin/busybox executable"
        );
        Ok(())
    }
}

fn invalid_network(message: impl Into<String>) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "unsafe or unsupported network configuration: {}",
            message.into()
        ),
    )
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn fixture_digest(directory: &Path) -> io::Result<String> {
    let entries = read_fixture_entries(directory)?;
    Ok(digest_fixture_entries(&entries))
}

fn read_fixture_entries(directory: &Path) -> io::Result<Vec<(String, Vec<u8>)>> {
    if !directory.is_absolute() || directory.to_str().is_none() {
        return Err(invalid_network(
            "record fixture must be an absolute UTF-8 directory and may not be a symlink",
        ));
    }
    let directory_handle = open_directory_without_symlinks(directory)?;
    read_fixture_entries_from_handle(&directory_handle)
}

fn read_fixture_entries_from_handle(directory_handle: &File) -> io::Result<Vec<(String, Vec<u8>)>> {
    let mut names = read_directory_names(directory_handle)?;
    names.sort_unstable();
    if names.is_empty() {
        return Err(invalid_network(format!(
            "record fixture must contain between 1 and {MAX_FIXTURE_FILES} regular files"
        )));
    }
    let mut total = 0_usize;
    names
        .into_iter()
        .map(|name| {
            let name_c = std::ffi::CString::new(name.as_bytes()).expect("validated filename");
            let descriptor = unsafe {
                libc::openat(
                    directory_handle.as_raw_fd(),
                    name_c.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                )
            };
            if descriptor < 0 {
                let error = io::Error::last_os_error();
                return Err(io::Error::new(
                    error.kind(),
                    format!("fixture entry is not a readable regular file: {name}: {error}"),
                ));
            }
            let mut file = unsafe { File::from_raw_fd(descriptor) };
            let metadata = file.metadata()?;
            if !metadata.file_type().is_file()
                || metadata.len() > MAX_FIXTURE_FILE_BYTES as u64
            {
                return Err(invalid_network(format!(
                    "fixture entry must be a regular file no larger than {MAX_FIXTURE_FILE_BYTES} bytes: {name}"
                )));
            }
            let mut contents = Vec::with_capacity(metadata.len() as usize);
            Read::by_ref(&mut file)
                .take(MAX_FIXTURE_FILE_BYTES as u64 + 1)
                .read_to_end(&mut contents)?;
            if contents.len() != metadata.len() as usize {
                return Err(invalid_network(format!(
                    "fixture entry changed while it was read: {name}"
                )));
            }
            total = total
                .checked_add(contents.len())
                .ok_or_else(|| invalid_network("fixture size overflowed"))?;
            if total > MAX_FIXTURE_BYTES {
                return Err(invalid_network(format!(
                    "fixture contents must not exceed {MAX_FIXTURE_BYTES} bytes"
                )));
            }
            Ok((name, contents))
        })
        .collect()
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}

fn read_directory_names(directory: &File) -> io::Result<Vec<String>> {
    let descriptor = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let pointer = unsafe { libc::fdopendir(descriptor) };
    if pointer.is_null() {
        let error = io::Error::last_os_error();
        unsafe { libc::close(descriptor) };
        return Err(error);
    }
    let stream = DirectoryStream(pointer);
    let mut names = Vec::new();
    loop {
        set_errno(0);
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = current_errno();
            if error == 0 {
                break;
            }
            return Err(io::Error::from_raw_os_error(error));
        }
        let name = unsafe {
            std::ffi::CStr::from_ptr((*entry).d_name.as_ptr().cast())
                .to_str()
                .map_err(|_| {
                    invalid_network("fixture filenames must be valid UTF-8 path components")
                })?
        };
        if name == "." || name == ".." {
            continue;
        }
        if names.len() == MAX_FIXTURE_FILES {
            return Err(invalid_network(format!(
                "record fixture must contain no more than {MAX_FIXTURE_FILES} regular files"
            )));
        }
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(invalid_network(
                "fixture filenames may contain only ASCII letters, digits, dot, underscore, and hyphen",
            ));
        }
        names.push(name.into());
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
fn errno_pointer() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

#[cfg(target_os = "macos")]
fn errno_pointer() -> *mut libc::c_int {
    unsafe { libc::__error() }
}

fn set_errno(value: libc::c_int) {
    unsafe { *errno_pointer() = value };
}

fn current_errno() -> libc::c_int {
    unsafe { *errno_pointer() }
}

fn open_directory_without_symlinks(path: &Path) -> io::Result<File> {
    let root = std::ffi::CString::new("/").expect("root contains no NUL");
    let components = path.components().collect::<Vec<_>>();
    #[cfg(target_os = "linux")]
    let root_access = if components.len() == 1 {
        libc::O_RDONLY
    } else {
        libc::O_PATH
    };
    // Network VM execution is Linux-only. The portable test implementation uses
    // readable ancestor handles on other Unix targets because O_PATH is Linux-specific.
    #[cfg(not(target_os = "linux"))]
    let root_access = libc::O_RDONLY;
    let descriptor = unsafe {
        libc::open(
            root.as_ptr(),
            root_access | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut directory = unsafe { File::from_raw_fd(descriptor) };
    for (index, component) in components.iter().enumerate() {
        use std::path::Component;
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => name,
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(invalid_network(
                    "fixture directory must be normalized and contain no dot components",
                ));
            }
        };
        let name = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| invalid_network("fixture directory contains a NUL byte"))?;
        let _final_component = index + 1 == components.len();
        #[cfg(target_os = "linux")]
        let access = if _final_component {
            libc::O_RDONLY
        } else {
            libc::O_PATH
        };
        #[cfg(not(target_os = "linux"))]
        let access = libc::O_RDONLY;
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                access | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "fixture directory component is not a real directory: {}: {error}",
                    name.to_string_lossy()
                ),
            ));
        }
        directory = unsafe { File::from_raw_fd(descriptor) };
    }
    Ok(directory)
}

pub(crate) fn digest_fixture_entries(entries: &[(String, Vec<u8>)]) -> String {
    let mut entries = entries.iter().collect::<Vec<_>>();
    entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
    let mut digest = Sha256::new();
    digest.update(b"simferret-tftp-fixture-v1\0");
    digest.update((entries.len() as u64).to_le_bytes());
    for (name, contents) in entries {
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update((contents.len() as u64).to_le_bytes());
        digest.update(contents);
    }
    format!("{:x}", digest.finalize())
}

#[derive(Debug)]
struct PreparedFixture {
    path: PathBuf,
}

impl PreparedFixture {
    fn create(network: &NetworkConfig, mode: ExecutionMode) -> io::Result<Self> {
        Self::create_in(network, mode, &absolute_temp_directory()?)
    }

    fn create_in(network: &NetworkConfig, mode: ExecutionMode, base: &Path) -> io::Result<Self> {
        let base = if base.is_absolute() {
            base.to_owned()
        } else {
            std::env::current_dir()?.join(base)
        };
        if base.to_str().is_none() {
            return Err(invalid_network(
                "temporary fixture base must be an absolute UTF-8 path",
            ));
        }
        let counter = NETWORK_TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = base.join(format!(
            "sf-network-{}-{counter}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        let prepared = Self { path };
        match (mode, &network.fixture_directory) {
            (ExecutionMode::Record, Some(source)) => {
                let entries = read_fixture_entries(source)?;
                let actual = digest_fixture_entries(&entries);
                if actual != network.identity.fixture.content_sha256 {
                    return Err(invalid_network(format!(
                        "fixture content changed after configuration: expected {}, actual {actual}",
                        network.identity.fixture.content_sha256
                    )));
                }
                for (name, contents) in entries {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(prepared.path.join(name))?;
                    file.write_all(&contents)?;
                }
            }
            (ExecutionMode::Record, None) => {
                return Err(invalid_network(
                    "record mode requires content-controlled fixture input",
                ));
            }
            (ExecutionMode::Replay, None) => {}
            (ExecutionMode::Replay, Some(_)) => {
                return Err(invalid_network(
                    "replay mode does not accept live fixture input",
                ));
            }
        }
        Ok(prepared)
    }
}

fn absolute_temp_directory() -> io::Result<PathBuf> {
    let directory = std::env::temp_dir();
    if directory.is_absolute() {
        Ok(directory)
    } else {
        Ok(std::env::current_dir()?.join(directory))
    }
}

impl Drop for PreparedFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn validate_identity_compatibility(expected: &VmIdentity, actual: &VmIdentity) -> io::Result<()> {
    if expected == actual {
        return Ok(());
    }
    let expected = serde_json::to_value(expected).map_err(io::Error::other)?;
    let actual = serde_json::to_value(actual).map_err(io::Error::other)?;
    let (field, expected, actual) = first_identity_difference("vm", &expected, &actual)
        .expect("unequal identities have a differing field");
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "replay environment identity differs at {field}: expected {expected}, actual {actual}"
        ),
    ))
}

pub(crate) fn validate_replay_network_identity(
    expected: &VmIdentity,
    actual: Option<&NetworkIdentity>,
) -> io::Result<()> {
    if expected.network.as_ref() == actual {
        return Ok(());
    }
    let expected = serde_json::to_value(&expected.network).map_err(io::Error::other)?;
    let actual = serde_json::to_value(actual).map_err(io::Error::other)?;
    let (field, expected, actual) = first_identity_difference("vm.network", &expected, &actual)
        .expect("unequal network identities have a differing field");
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "replay environment identity differs at {field}: expected {expected}, actual {actual}"
        ),
    ))
}

fn first_identity_difference(
    path: &str,
    expected: &serde_json::Value,
    actual: &serde_json::Value,
) -> Option<(String, String, String)> {
    match (expected, actual) {
        (serde_json::Value::Object(expected), serde_json::Value::Object(actual)) => {
            for (name, expected_value) in expected {
                let child = format!("{path}.{name}");
                let Some(actual_value) = actual.get(name) else {
                    return Some((child, expected_value.to_string(), "<missing>".into()));
                };
                if let Some(difference) =
                    first_identity_difference(&child, expected_value, actual_value)
                {
                    return Some(difference);
                }
            }
            actual
                .iter()
                .find(|(name, _)| !expected.contains_key(*name))
                .map(|(name, value)| {
                    (
                        format!("{path}.{name}"),
                        "<missing>".into(),
                        value.to_string(),
                    )
                })
        }
        (serde_json::Value::Array(expected), serde_json::Value::Array(actual)) => {
            for (index, expected_value) in expected.iter().enumerate() {
                let child = format!("{path}[{index}]");
                let Some(actual_value) = actual.get(index) else {
                    return Some((child, expected_value.to_string(), "<missing>".into()));
                };
                if let Some(difference) =
                    first_identity_difference(&child, expected_value, actual_value)
                {
                    return Some(difference);
                }
            }
            actual.get(expected.len()).map(|value| {
                (
                    format!("{path}[{}]", expected.len()),
                    "<missing>".into(),
                    value.to_string(),
                )
            })
        }
        _ if expected == actual => None,
        _ => Some((path.into(), expected.to_string(), actual.to_string())),
    }
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
        if let Some(network) = &config.network {
            network.validate()?;
        }
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
            devices: vec!["isa-serial:diagnostics".into(), "isa-serial:agent".into()],
            network: config
                .network
                .as_ref()
                .map(|network| network.identity.clone()),
        })
    }

    fn arguments(
        &self,
        config: &RecordConfig,
        mode: ExecutionMode,
        fixture_directory: Option<&Path>,
    ) -> io::Result<Vec<OsString>> {
        validate_utf8_paths(config)?;
        let mut arguments = vec![
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
            "-serial".into(),
            "chardev:agent".into(),
            "-qmp".into(),
            option_path("unix:path=", &config.qmp_socket, ",server=on,wait=off")?,
        ];
        if let Some(network) = &config.network {
            network.validate()?;
            let fixture_directory = fixture_directory.ok_or_else(|| {
                invalid_network("adapter-controlled fixture directory was not prepared")
            })?;
            let identity = &network.identity;
            let filter = identity
                .replay_filter
                .as_ref()
                .expect("validated network has a replay filter");
            arguments.extend([
                "-netdev".into(),
                option_path(
                    &format!(
                        "{},id={},restrict=on,tftp=",
                        identity.backend.kind, identity.backend.id
                    ),
                    fixture_directory,
                    "",
                )?,
                "-device".into(),
                format!(
                    "{},netdev={},mac={},bus={},addr={},romfile=",
                    identity.nic.model,
                    identity.backend.id,
                    identity.nic.mac_address,
                    identity.nic.bus,
                    identity.nic.pci_address
                )
                .into(),
                "-object".into(),
                format!(
                    "{},id={},netdev={},queue={}",
                    filter.kind, filter.id, filter.backend_id, filter.queue
                )
                .into(),
            ]);
        } else {
            arguments.extend(["-net".into(), "none".into()]);
        }
        arguments.extend([
            "-icount".into(),
            option_path(
                &format!("shift=auto,rr={},rrfile=", mode.qemu_value()),
                &config.replay_log,
                "",
            )?,
        ]);
        Ok(arguments)
    }

    fn launch(
        &self,
        config: &RecordConfig,
        mode: ExecutionMode,
        expected_identity: Option<&VmIdentity>,
    ) -> io::Result<Box<dyn RunningVm>> {
        validate_utf8_paths(config)?;
        if let Some(expected) = expected_identity {
            validate_replay_network_identity(
                expected,
                config.network.as_ref().map(|network| &network.identity),
            )?;
        }
        if let Some(network) = &config.network {
            network.validate()?;
        }
        let fixture = config
            .network
            .as_ref()
            .map(|network| PreparedFixture::create(network, mode))
            .transpose()?;
        let identity = self.identity(config)?;
        if let Some(expected) = expected_identity {
            validate_identity_compatibility(expected, &identity)?;
        }
        let arguments = self.arguments(
            config,
            mode,
            fixture.as_ref().map(|item| item.path.as_path()),
        )?;
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
        let qemu_log = File::create(&config.qemu_log)?;
        let mut command = ProcessCommand::new(&self.executable);
        command
            .args(arguments)
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
        let (acknowledgements, acknowledged) = mpsc::channel();
        let writer = match CommandWriter::new(input, acknowledged, COMMAND_TIMEOUT) {
            Ok(writer) => writer,
            Err(error) => {
                terminate(&mut child);
                let _ = fs::remove_file(&config.qmp_socket);
                return Err(error);
            }
        };
        let (sender, events) = mpsc::channel();
        let event_reader = match thread::Builder::new()
            .name("qemu-agent-events".into())
            .spawn(move || {
                loop {
                    let event = read_serial_event(&mut output, &acknowledgements);
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
                let _ = fs::remove_file(&config.qmp_socket);
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
            _fixture: fixture,
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

fn write_serial_command(
    output: &mut impl Write,
    acknowledgements: &Receiver<()>,
    frame: &CommandFrame,
    timeout: Duration,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(frame).map_err(io::Error::other)?;
    if bytes.len() > MAX_FRAME_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame exceeds maximum length",
        ));
    }
    bytes.push(b'\n');
    let deadline = Instant::now() + timeout;
    for byte in bytes {
        output.write_all(&[byte])?;
        output.flush()?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        match acknowledgements.recv_timeout(remaining) {
            Ok(()) => {}
            Err(RecvTimeoutError::Timeout) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for guest serial acknowledgement",
                ));
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "guest serial acknowledgement channel disconnected",
                ));
            }
        }
    }
    Ok(())
}

fn read_serial_event(
    input: &mut impl Read,
    acknowledgements: &mpsc::Sender<()>,
) -> io::Result<Option<EventFrame>> {
    let mut body = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) if body.is_empty() => return Ok(None),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated serial event frame",
                ));
            }
            Ok(1) if byte[0] == SERIAL_ACK => {
                let _ = acknowledgements.send(());
            }
            Ok(1) if byte[0] == b'\n' => break,
            Ok(1) => {
                if body.len() >= MAX_FRAME_LENGTH {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "frame exceeds maximum length",
                    ));
                }
                body.push(byte[0]);
            }
            Ok(_) => unreachable!("one-byte buffer accepted more than one byte"),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

struct CommandWriter {
    requests: SyncSender<WriteRequest>,
    thread: Option<JoinHandle<()>>,
    timeout: Duration,
}

impl CommandWriter {
    fn new(
        mut output: impl Write + Send + 'static,
        acknowledgements: Receiver<()>,
        timeout: Duration,
    ) -> io::Result<Self> {
        let (requests, receiver) = mpsc::sync_channel::<WriteRequest>(1);
        let thread = thread::Builder::new()
            .name("qemu-agent-commands".into())
            .spawn(move || {
                while let Ok((frame, completion)) = receiver.recv() {
                    let result =
                        write_serial_command(&mut output, &acknowledgements, &frame, timeout);
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
    _fixture: Option<PreparedFixture>,
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
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
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
            network: None,
        }
    }

    fn network_config(root: &Path) -> NetworkConfig {
        fs::create_dir_all(root.join("fixture")).unwrap();
        fs::write(root.join("fixture/request-000001"), b"fixture").unwrap();
        fs::write(root.join("busybox"), b"busybox").unwrap();
        NetworkConfig::restricted_tftp_record(root.join("fixture"), &root.join("busybox")).unwrap()
    }

    fn network_test_root(name: &str) -> PathBuf {
        fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("simferret-network-{name}-{}", std::process::id()))
    }

    fn adapter(root: &Path) -> QemuAdapter {
        QemuAdapter {
            executable: root.join("bin/qemu-system-x86_64"),
            data_directory: root.join("share/qemu"),
            bios: root.join("share/qemu/bios-256k.bin"),
            linuxboot: root.join("share/qemu/linuxboot_dma.bin"),
        }
    }

    fn identity_with_network(network: NetworkIdentity) -> VmIdentity {
        VmIdentity {
            qemu: FileIdentity {
                path: "qemu".into(),
                sha256: "0".repeat(64),
            },
            qemu_version: "test".into(),
            kernel: FileIdentity {
                path: "kernel".into(),
                sha256: "1".repeat(64),
            },
            initramfs_sha256: "2".repeat(64),
            machine: MACHINE.into(),
            cpu: CPU.into(),
            memory_mib: MEMORY_MIB,
            vcpus: 1,
            accelerator: "tcg".into(),
            firmware: vec![],
            devices: vec![],
            network: Some(network),
        }
    }

    #[test]
    fn record_arguments_fix_identity_and_escape_option_paths() {
        let root = Path::new("/tmp/directory=with,comma");
        let arguments = adapter(root)
            .arguments(&config(root), ExecutionMode::Record, None)
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
            "-serial chardev:agent",
        ] {
            assert!(arguments.contains(required), "missing argument: {required}");
        }
    }

    #[test]
    fn replay_arguments_consume_the_existing_replay_log() {
        let root = Path::new("/tmp/replay");
        let arguments = adapter(root)
            .arguments(&config(root), ExecutionMode::Replay, None)
            .unwrap();
        assert!(
            arguments.iter().any(|argument| {
                argument == "shift=auto,rr=replay,rrfile=/tmp/replay/replay.bin"
            })
        );
    }

    #[test]
    fn network_arguments_match_the_proven_restricted_replay_profile() {
        let root = network_test_root("arguments");
        let mut config = config(&root);
        config.network = Some(network_config(&root));
        let fixture =
            PreparedFixture::create(config.network.as_ref().unwrap(), ExecutionMode::Record)
                .unwrap();
        let arguments = adapter(&root)
            .arguments(&config, ExecutionMode::Record, Some(&fixture.path))
            .unwrap()
            .into_iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(arguments.windows(2).any(|pair| {
            pair == [
                "-netdev",
                &format!(
                    "user,id=simnet,restrict=on,tftp={}",
                    fixture.path.to_string_lossy().replace(',', ",,")
                ),
            ]
        }));
        assert!(arguments.windows(2).any(|pair| {
            pair == [
                "-device",
                "rtl8139,netdev=simnet,mac=52:54:00:12:34:56,bus=pci.0,addr=0x3,romfile=",
            ]
        }));
        assert!(arguments.windows(2).any(|pair| {
            pair == [
                "-object",
                "filter-replay,id=simnet-replay,netdev=simnet,queue=all",
            ]
        }));
        assert!(!arguments.windows(2).any(|pair| pair == ["-net", "none"]));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_and_unrecorded_network_profiles_are_rejected() {
        let root = network_test_root("validation");
        let mut network = network_config(&root);
        network.identity.backend.kind = "tap".into();
        let error = network.validate().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("TAP, bridge"));

        let mut network = network_config(&root);
        network.identity.backend.restricted = false;
        assert!(
            network
                .validate()
                .unwrap_err()
                .to_string()
                .contains("restricted")
        );

        let mut network = network_config(&root);
        network.identity.replay_filter = None;
        assert!(
            network
                .validate()
                .unwrap_err()
                .to_string()
                .contains("mandatory")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn network_identity_excludes_runtime_fixture_path() {
        let first_root = network_test_root("identity-path-first");
        let second_root = network_test_root("identity-path-second");
        let first = network_config(&first_root);
        let second = network_config(&second_root);
        assert_eq!(first.identity, second.identity);
        let replay = NetworkConfig::restricted_tftp_replay(
            first.identity.fixture.content_sha256.clone(),
            first.identity.fault.tool.sha256.clone(),
        );
        assert_eq!(first.identity, replay.identity);
        let encoded = serde_json::to_string(&first.identity).unwrap();
        assert!(!encoded.contains(first_root.to_str().unwrap()));
        assert!(!encoded.contains(second_root.to_str().unwrap()));
        assert!(encoded.contains("immutable-files"));
        assert!(encoded.contains("restrict"));
        fs::remove_dir_all(first_root).unwrap();
        fs::remove_dir_all(second_root).unwrap();
    }

    #[test]
    fn record_fixture_rejects_symlinks_and_special_files() {
        use std::os::unix::fs::symlink;

        let root = network_test_root("special-fixture");
        fs::create_dir_all(root.join("fixture")).unwrap();
        fs::write(root.join("outside"), b"secret").unwrap();
        fs::write(root.join("busybox"), b"busybox").unwrap();
        symlink(root.join("outside"), root.join("fixture/request-000001")).unwrap();
        let error =
            NetworkConfig::restricted_tftp_record(root.join("fixture"), &root.join("busybox"))
                .unwrap_err();
        assert!(error.to_string().contains("regular file"), "{error}");

        fs::remove_file(root.join("fixture/request-000001")).unwrap();
        let fifo =
            std::ffi::CString::new(root.join("fixture/request-000001").as_os_str().as_bytes())
                .unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let error =
            NetworkConfig::restricted_tftp_record(root.join("fixture"), &root.join("busybox"))
                .unwrap_err();
        assert!(error.to_string().contains("regular file"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn record_fixture_rejects_symlinked_directories_and_binds_reads_to_the_open_directory() {
        use std::os::unix::fs::symlink;

        let root = network_test_root("directory-symlink");
        fs::create_dir_all(root.join("real")).unwrap();
        fs::write(root.join("real/request-000001"), b"safe").unwrap();
        fs::write(root.join("real/request-000002"), b"also-safe").unwrap();
        symlink(root.join("real"), root.join("linked")).unwrap();
        for suffix in ["", "/", "/."] {
            let path = PathBuf::from(format!("{}{suffix}", root.join("linked").display()));
            let error = fixture_digest(&path).unwrap_err();
            assert!(
                error.to_string().contains("not a real directory"),
                "{path:?}: {error}"
            );
        }

        let handle = open_directory_without_symlinks(&root.join("real")).unwrap();
        fs::rename(root.join("real"), root.join("moved")).unwrap();
        fs::create_dir(root.join("outside")).unwrap();
        fs::write(root.join("outside/request-000001"), b"secret").unwrap();
        symlink(root.join("outside"), root.join("real")).unwrap();
        let entries = read_fixture_entries_from_handle(&handle).unwrap();
        assert_eq!(
            entries,
            vec![
                ("request-000001".into(), b"safe".to_vec()),
                ("request-000002".into(), b"also-safe".to_vec()),
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fixture_file_count_is_bounded_during_enumeration() {
        let root = network_test_root("fixture-count");
        fs::create_dir_all(root.join("fixture")).unwrap();
        for index in 0..=MAX_FIXTURE_FILES {
            fs::write(root.join(format!("fixture/request-{index:06}")), []).unwrap();
        }
        let error = fixture_digest(&root.join("fixture")).unwrap_err();
        assert!(error.to_string().contains("no more than 256"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fixture_file_size_is_bounded_before_copy() {
        let root = network_test_root("fixture-size");
        fs::create_dir_all(root.join("fixture")).unwrap();
        fs::write(
            root.join("fixture/request-000001"),
            vec![0_u8; MAX_FIXTURE_FILE_BYTES + 1],
        )
        .unwrap();
        let error = fixture_digest(&root.join("fixture")).unwrap_err();
        assert!(
            error.to_string().contains("no larger than 1048576"),
            "{error}"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fixture_identity_is_derived_and_rechecked_before_record() {
        let root = network_test_root("fixture-digest");
        let first = network_config(&root);
        let prepared = PreparedFixture::create(&first, ExecutionMode::Record).unwrap();
        let prepared_path = prepared.path.clone();
        assert_eq!(
            fs::read(prepared.path.join("request-000001")).unwrap(),
            b"fixture"
        );
        fs::write(root.join("fixture/request-000001"), b"changed").unwrap();
        assert_eq!(
            fs::read(prepared.path.join("request-000001")).unwrap(),
            b"fixture"
        );
        drop(prepared);
        assert!(!prepared_path.exists());
        let second =
            NetworkConfig::restricted_tftp_record(root.join("fixture"), &root.join("busybox"))
                .unwrap();
        assert_ne!(
            first.identity.fixture.content_sha256,
            second.identity.fixture.content_sha256
        );
        let error = PreparedFixture::create(&first, ExecutionMode::Record).unwrap_err();
        assert!(error.to_string().contains("expected"), "{error}");
        assert!(error.to_string().contains("actual"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replay_uses_an_empty_adapter_owned_fixture() {
        let network = NetworkConfig::restricted_tftp_replay("a".repeat(64), "b".repeat(64));
        let fixture = PreparedFixture::create(&network, ExecutionMode::Replay).unwrap();
        assert_eq!(fs::read_dir(&fixture.path).unwrap().count(), 0);
        assert_eq!(
            fs::metadata(&fixture.path).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let root = network_test_root("live-replay");
        let record = network_config(&root);
        let error = PreparedFixture::create(&record, ExecutionMode::Replay).unwrap_err();
        assert!(error.to_string().contains("does not accept live fixture"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prepared_fixture_path_is_absolute_for_a_relative_temporary_base() {
        let network = NetworkConfig::restricted_tftp_replay("a".repeat(64), "b".repeat(64));
        let fixture =
            PreparedFixture::create_in(&network, ExecutionMode::Replay, Path::new(".")).unwrap();
        assert!(fixture.path.is_absolute());
    }

    #[test]
    fn fixture_rejection_does_not_delete_an_existing_recording() {
        let root = network_test_root("preserve-recording");
        fs::create_dir_all(&root).unwrap();
        let mut config = config(&root);
        config.network = Some(network_config(&root));
        fs::write(&config.replay_log, b"existing recording").unwrap();
        fs::write(root.join("fixture/request-000001"), b"changed").unwrap();
        let error = match adapter(&root).launch_record(&config) {
            Ok(_) => panic!("changed fixture unexpectedly launched"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("fixture content changed"));
        assert_eq!(fs::read(&config.replay_log).unwrap(), b"existing recording");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn launched_vm_owns_snapshot_after_source_removal_and_cleans_it_on_drop() {
        let root = fs::canonicalize("/tmp")
            .unwrap()
            .join(format!("sf-net-life-{}", std::process::id()));
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("share/qemu")).unwrap();
        fs::write(root.join("kernel"), b"kernel").unwrap();
        fs::write(root.join("initramfs"), b"initramfs").unwrap();
        fs::write(root.join("share/qemu/bios-256k.bin"), b"bios").unwrap();
        fs::write(root.join("share/qemu/linuxboot_dma.bin"), b"linuxboot").unwrap();
        let mut config = config(&root);
        config.network = Some(network_config(&root));
        let source = root.join("fixture");
        let captured = root.join("prepared-path");
        let source_json = serde_json::to_string(source.to_str().unwrap()).unwrap();
        let captured_json = serde_json::to_string(captured.to_str().unwrap()).unwrap();
        let script = format!(
            r#"#!/usr/bin/env python3
import json, os, shutil, socket, sys, time
if "--version" in sys.argv:
    shutil.rmtree({source_json})
    print("QEMU test version")
    raise SystemExit(0)
def option(name):
    index = sys.argv.index(name)
    return sys.argv[index + 1]
netdev = option("-netdev")
fixture = netdev.split("tftp=", 1)[1].replace(",,", ",")
with open({captured_json}, "w", encoding="utf-8") as output:
    output.write(fixture)
qmp = option("-qmp").split("unix:path=", 1)[1].split(",server=", 1)[0]
server = socket.socket(socket.AF_UNIX)
server.bind(qmp)
server.listen(1)
connection, _ = server.accept()
stream = connection.makefile("rwb", buffering=0)
stream.write(b'{{"QMP":{{}}}}\n')
for _ in range(2):
    request = json.loads(stream.readline())
    stream.write(json.dumps({{"return": {{}}, "id": request["id"]}}).encode() + b"\n")
print('{{"protocol_version":2,"event_id":0,"command_id":0,"event":{{"type":"agent_ready"}}}}', flush=True)
time.sleep(30)
"#
        );
        let executable = root.join("bin/qemu-system-x86_64");
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();

        let vm = adapter(&root).launch_record(&config).unwrap();
        assert!(!source.exists(), "version probe did not remove live source");
        let prepared = PathBuf::from(fs::read_to_string(&captured).unwrap());
        assert!(prepared.is_absolute());
        assert_eq!(
            fs::read(prepared.join("request-000001")).unwrap(),
            b"fixture"
        );
        assert!(config.qmp_socket.exists());
        drop(vm);
        assert!(!prepared.exists());
        assert!(!config.qmp_socket.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn actual_replay_network_mismatch_has_field_and_values() {
        let root = network_test_root("actual-mismatch");
        fs::create_dir_all(&root).unwrap();
        let mut actual = network_config(&root);
        let expected = identity_with_network(actual.identity.clone());
        actual.identity.nic.mac_address = "52:54:00:12:34:57".into();
        let mut config = config(&root);
        config.network = Some(actual);
        let error = match adapter(&root).launch_replay(&config, &expected) {
            Ok(_) => panic!("mismatched replay unexpectedly launched"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(message.contains("vm.network.nic.mac_address"), "{message}");
        assert!(message.contains("52:54:00:12:34:56"), "{message}");
        assert!(message.contains("52:54:00:12:34:57"), "{message}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn identity_mismatch_reports_the_first_field_with_both_values() {
        let root = network_test_root("identity");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("share/qemu")).unwrap();
        fs::create_dir_all(root.join("fixture")).unwrap();
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
        for (path, contents) in [
            ("kernel", b"kernel".as_slice()),
            ("initramfs", b"initramfs".as_slice()),
            ("share/qemu/bios-256k.bin", b"bios".as_slice()),
            ("share/qemu/linuxboot_dma.bin", b"linuxboot".as_slice()),
        ] {
            fs::write(root.join(path), contents).unwrap();
        }
        let mut config = config(&root);
        config.network = Some(network_config(&root));
        let actual = adapter(&root).identity(&config).unwrap();
        let mut expected = actual.clone();
        expected.network.as_mut().unwrap().nic.mac_address = "52:54:00:12:34:57".into();
        let error = validate_identity_compatibility(&expected, &actual).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("vm.network.nic.mac_address"), "{message}");
        assert!(message.contains("52:54:00:12:34:57"), "{message}");
        assert!(message.contains("52:54:00:12:34:56"), "{message}");
        fs::remove_dir_all(root).unwrap();
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
        let (_acknowledged, acknowledgements) = mpsc::channel();
        let command_writer =
            CommandWriter::new(writer, acknowledgements, Duration::from_millis(20)).unwrap();
        let frame = CommandFrame {
            protocol_version: PROTOCOL_VERSION,
            command_id: 1,
            command: crate::protocol::Command::Request {
                request_id: "request".into(),
                payload: "x".repeat(crate::protocol::MAX_FRAME_LENGTH - 1024),
                phase: crate::protocol::RequestPhase::PreOutage,
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
    fn serial_event_reader_demultiplexes_command_acknowledgements() {
        let event = EventFrame {
            protocol_version: PROTOCOL_VERSION,
            event_id: 1,
            command_id: 1,
            event: Event::NetworkRestored {
                peer_cidr: "10.0.2.2/32".into(),
            },
            diagnostics: crate::protocol::DiagnosticFields::default(),
        };
        let mut bytes = vec![SERIAL_ACK, SERIAL_ACK];
        bytes.extend(serde_json::to_vec(&event).unwrap());
        bytes.push(b'\n');
        let (acknowledgements, acknowledged) = mpsc::channel();
        assert_eq!(
            read_serial_event(&mut bytes.as_slice(), &acknowledgements).unwrap(),
            Some(event)
        );
        assert_eq!(acknowledged.try_iter().count(), 2);
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
