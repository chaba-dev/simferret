//! RFD 3 Phase 2: the guest process runtime.
//!
//! The agent stays PID 1 outside an immutable workload template. For every
//! invocation it materializes a fresh writable root from that template, applies
//! a versioned runtime overlay, and supervises exactly one workload child in a
//! private filesystem root. The child receives only fresh standard pipes, a
//! cleared supplementary-group set, `no_new_privs`, and the normalized nonzero
//! credentials; it is executed without a shell.
//!
//! Every process in the guest other than the agent is a member of the active
//! invocation. On termination or primary-process exit the runtime kills and
//! reaps until only the agent remains and all workload output pipes reach end
//! of file, then reports `cleanup-complete`. A new invocation is refused until
//! that barrier completes.
//!
//! The runtime reports process and byte facts only. Application protocol
//! interpretation and workload assertions belong to the host scenario checker.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::protocol::{
    Event, LaunchFailure, MAX_INVOCATION_INPUT_BYTES, MAX_INVOCATION_OUTPUT_BYTES,
    MAX_OUTPUT_FRAME_BYTES, MAX_STDIN_FRAME_BYTES, OutputStream, ProcessExit, TERMINATION_SIGNAL,
};
use crate::workload::{
    LaunchIdentity, MAX_FILE_BYTES, MAX_PATH_BYTES, MAX_VIEW_ENTRIES, validate_launch_identity,
};

/// The reserved guest path holding the immutable workload template. The PID-1
/// agent and its tools stay outside it.
pub const GUEST_TEMPLATE_ROOT: &str = "/workload";
/// The default guest path below which fresh writable invocation roots live.
pub const GUEST_RUNTIME_ROOT: &str = "/run/simferret";

/// The overlay directory whose metadata the runtime replaces.
const OVERLAY_TMP: &[u8] = b"tmp";
/// The overlay directory whose metadata and device nodes the runtime replaces.
const OVERLAY_DEV: &[u8] = b"dev";
const DEV_NULL: (u32, u32) = (1, 3);
const DEV_ZERO: (u32, u32) = (1, 5);
const OVERLAY_DIRECTORY_MODE: u32 = 0o755;
const OVERLAY_TMP_MODE: u32 = 0o1777;
const OVERLAY_DEVICE_MODE: u32 = 0o666;

/// Bounds the descriptor scan during the cleanup barrier.
const MAX_DESCRIPTOR_SCAN: u64 = 1 << 16;
/// The bounded wait for the child's setup result before exec.
const SETUP_TIMEOUT: Duration = Duration::from_secs(10);
/// The bounded time the cleanup barrier may take to signal and reap every
/// member and drain both pipes. Exhausting it is a fatal infrastructure error,
/// never a reported completion.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
/// `PF_KTHREAD`. Kernel threads appear in the guest process table but cannot be
/// signalled or reaped, so they are never invocation members.
const KERNEL_THREAD_FLAG: u64 = 0x0020_0000;
/// Bound one output service batch. A continuously ready stream must not
/// monopolize the control loop or allocate an unbounded event vector, and both
/// streams are serviced fairly within the batch.
const MAX_SERVICE_FRAMES: u64 = 64;
const MAX_SERVICE_BYTES: usize = 64 * 1024;

/// Child setup result codes. The child writes one byte to a close-on-exec error
/// pipe before `execve`, so a successful exec is an unreadable pipe and a setup
/// failure is an unambiguous typed byte.
mod child_status {
    pub const DUP: u8 = 1;
    pub const CHROOT: u8 = 2;
    pub const CHDIR: u8 = 3;
    pub const GROUPS: u8 = 4;
    pub const NO_NEW_PRIVS: u8 = 5;
    pub const CREDENTIALS: u8 = 6;
    pub const EXEC: u8 = 7;

    pub fn failure(code: u8) -> (&'static str, &'static str) {
        match code {
            DUP => ("pipe", "could not connect the workload standard pipes"),
            CHROOT => ("setup", "could not change the workload root"),
            CHDIR => (
                "working_directory",
                "could not enter the workload working directory",
            ),
            GROUPS => ("setup", "could not clear supplementary groups"),
            NO_NEW_PRIVS => ("setup", "could not set no_new_privs"),
            CREDENTIALS => ("setup", "could not apply the workload credentials"),
            EXEC => ("executable", "could not execute the workload"),
            _ => ("setup", "unknown workload setup failure"),
        }
    }
}

/// The process-table scope the cleanup barrier is allowed to touch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberScope {
    /// Every process in the guest other than the agent. Valid only when the
    /// agent is PID 1, which is the only process the workload cannot outlive.
    Guest,
    /// Only the invocation's own process group. Used by host tests, where the
    /// agent shares a process table with unrelated processes.
    ProcessGroup,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeLimits {
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub input_frame_bytes: usize,
    pub output_frame_bytes: usize,
    /// Bounds the template walk. Defaults to the canonical view bound the
    /// assembler enforces, so the runtime never rejects a template the
    /// assembler accepted.
    pub template_entries: usize,
    pub template_path_bytes: usize,
    /// Bounds one copied template file, independent of the output byte budget.
    pub file_bytes: usize,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            input_bytes: MAX_INVOCATION_INPUT_BYTES,
            output_bytes: MAX_INVOCATION_OUTPUT_BYTES,
            input_frame_bytes: MAX_STDIN_FRAME_BYTES,
            output_frame_bytes: MAX_OUTPUT_FRAME_BYTES,
            template_entries: MAX_VIEW_ENTRIES,
            template_path_bytes: MAX_PATH_BYTES,
            file_bytes: MAX_FILE_BYTES,
        }
    }
}

pub struct RuntimeConfig {
    pub template_root: PathBuf,
    pub runtime_root: PathBuf,
    pub limits: RuntimeLimits,
    pub scope: MemberScope,
}

impl RuntimeConfig {
    /// The production guest configuration.
    pub fn guest() -> Self {
        Self {
            template_root: PathBuf::from(GUEST_TEMPLATE_ROOT),
            runtime_root: PathBuf::from(GUEST_RUNTIME_ROOT),
            limits: RuntimeLimits::default(),
            scope: MemberScope::Guest,
        }
    }
}

#[derive(Debug)]
struct StreamState {
    offset: u64,
    bytes: u64,
    hasher: Sha256,
    eof: bool,
}

impl StreamState {
    fn new() -> Self {
        Self {
            offset: 0,
            bytes: 0,
            hasher: Sha256::new(),
            eof: false,
        }
    }
}

/// Owns one fresh writable root and removes it when the invocation is dropped,
/// including on every failed-start path.
struct RootGuard {
    path: PathBuf,
}

impl RootGuard {
    fn create(path: PathBuf) -> io::Result<Self> {
        std::fs::create_dir(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RootGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct Invocation {
    id: u64,
    /// Held for its `Drop`: it removes the fresh root when the invocation ends.
    _root: RootGuard,
    pid: libc::pid_t,
    stdin: Option<OwnedFd>,
    stdout: Option<OwnedFd>,
    stderr: Option<OwnedFd>,
    stdout_state: StreamState,
    stderr_state: StreamState,
    input_offset: u64,
    input_bytes: u64,
    /// Input accepted into the bounded queue but not yet written to the child.
    /// It exists so a child that stops reading cannot block the control loop.
    pending_input: Vec<u8>,
    eof_requested: bool,
    sequence: u64,
    frames: u64,
    exit: Option<ProcessExit>,
    reaped: u64,
    cleanup_complete: bool,
}

impl Invocation {
    /// Write as much queued input as the pipe accepts, and close the child's
    /// standard input once the queue is empty and end of input was requested.
    fn flush_input(&mut self) -> io::Result<()> {
        let Some(raw) = self.stdin.as_ref().map(AsRawFd::as_raw_fd) else {
            return Ok(());
        };
        while !self.pending_input.is_empty() {
            // SAFETY: `pending_input` is a live buffer and `raw` is the
            // invocation's non-blocking stdin write end.
            let written = unsafe {
                libc::write(
                    raw,
                    self.pending_input.as_ptr().cast(),
                    self.pending_input.len(),
                )
            };
            if written < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if error.kind() == io::ErrorKind::WouldBlock {
                    return Ok(());
                }
                return Err(error);
            }
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "workload input pipe closed",
                ));
            }
            self.pending_input.drain(..written as usize);
        }
        if self.eof_requested {
            self.stdin = None;
        }
        Ok(())
    }
}

/// One guest process runtime. It owns at most one active invocation.
pub struct Runtime {
    config: RuntimeConfig,
    active: Option<Invocation>,
    /// The greatest invocation identifier ever accepted. Identifiers must be
    /// strictly increasing, so a completed invocation can never be reused.
    last_invocation: Option<u64>,
}

impl Runtime {
    /// Build a runtime, validate its limits, and validate the immutable
    /// template's overlay profile.
    pub fn new(config: RuntimeConfig) -> io::Result<Self> {
        validate_limits(&config.limits)?;
        // The guest-wide scope signals every process in the process table, so it
        // is permitted only where the agent owns that table. Enforcing this at
        // construction keeps the destructive boundary safe for a mistaken host
        // caller.
        if config.scope == MemberScope::Guest && std::process::id() != 1 {
            return Err(invalid(
                "the guest-wide cleanup scope requires the agent to be PID 1",
            ));
        }
        validate_template(&config.template_root, &config.limits)?;
        Ok(Self {
            config,
            active: None,
            last_invocation: None,
        })
    }

    pub fn is_active(&self) -> bool {
        self.active.is_some()
    }

    /// The live output pipe descriptors, so the agent can poll them together
    /// with its control channel instead of busy-waiting.
    pub fn output_fds(&self) -> Vec<RawFd> {
        self.active
            .as_ref()
            .map(|active| {
                poll_descriptors(active)
                    .into_iter()
                    .map(|descriptor| descriptor.fd)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The stdin write descriptor while queued input still needs the pipe to
    /// drain, so the agent can poll it for writability.
    pub fn input_fd(&self) -> Option<RawFd> {
        let active = self.active.as_ref()?;
        if active.pending_input.is_empty() {
            return None;
        }
        active.stdin.as_ref().map(AsRawFd::as_raw_fd)
    }

    pub fn limits(&self) -> &RuntimeLimits {
        &self.config.limits
    }

    /// Start one invocation. Returns typed protocol events; every failure is a
    /// `launch-failed` event rather than a host error, so the host checker sees
    /// a bounded diagnostic.
    pub fn start(&mut self, invocation: u64, launch: &LaunchIdentity) -> Vec<Event> {
        match self.start_inner(invocation, launch) {
            Ok(event) => vec![event],
            Err((failure, detail)) => vec![Event::LaunchFailed {
                invocation,
                failure,
                detail,
            }],
        }
    }

    fn start_inner(
        &mut self,
        invocation: u64,
        launch: &LaunchIdentity,
    ) -> Result<Event, (LaunchFailure, String)> {
        if self.active.is_some() {
            return Err((
                LaunchFailure::InvocationActive,
                "an invocation is already active".into(),
            ));
        }
        // Identifiers must strictly increase, so a completed invocation can
        // never be mistaken for a new one. The mark is consumed by every
        // accepted start, including one that later fails.
        if let Some(last) = self.last_invocation
            && invocation <= last
        {
            return Err((
                LaunchFailure::InvocationRepeated,
                format!(
                    "invocation {invocation} is not greater than the last accepted invocation {last}"
                ),
            ));
        }
        self.last_invocation = Some(invocation);
        validate_launch(launch).map_err(|error| (LaunchFailure::Executable, error.to_string()))?;
        create_private_directory(&self.config.runtime_root).map_err(|error| {
            (
                LaunchFailure::Materialization,
                format!("cannot create the runtime root: {error}"),
            )
        })?;
        let path = self
            .config
            .runtime_root
            .join(format!("invocation-{invocation}"));
        if path.exists() {
            return Err((
                LaunchFailure::InvocationRepeated,
                format!("invocation root {} already exists", path.display()),
            ));
        }
        // The guard owns the root from the moment it exists, so every failure
        // below leaves no partially materialized root behind.
        let root = RootGuard::create(path)
            .map_err(|error| (LaunchFailure::Materialization, error.to_string()))?;
        materialize_into(&self.config.template_root, root.path(), &self.config.limits)
            .map_err(|error| (LaunchFailure::Materialization, error.to_string()))?;
        verify_launch_target(root.path(), launch)?;
        let spawned = spawn(root.path(), launch, self.config.scope)?;
        self.active = Some(Invocation {
            id: invocation,
            _root: root,
            pid: spawned.pid,
            stdin: Some(spawned.stdin),
            stdout: Some(spawned.stdout),
            stderr: Some(spawned.stderr),
            stdout_state: StreamState::new(),
            stderr_state: StreamState::new(),
            input_offset: 0,
            input_bytes: 0,
            pending_input: Vec::new(),
            eof_requested: false,
            sequence: 0,
            frames: 0,
            exit: None,
            reaped: 0,
            cleanup_complete: false,
        });
        Ok(Event::WorkloadStarted {
            invocation,
            launch: launch.clone(),
        })
    }

    /// Accept one bounded, strictly contiguous stdin frame into the invocation's
    /// queue, then write whatever the child's pipe accepts.
    ///
    /// A child that stops reading can fill its pipe. The frame is queued rather
    /// than written synchronously, so the control loop keeps draining output and
    /// can still process `terminate`; the queue is bounded by the invocation's
    /// input limit and overflow is fatal.
    pub fn stdin_write(
        &mut self,
        invocation: u64,
        offset: u64,
        bytes: &str,
    ) -> io::Result<Vec<Event>> {
        let data = crate::protocol::decode_bytes(bytes, self.config.limits.input_frame_bytes)
            .map_err(|error| self.fatal(invocation, error))?;
        if data.is_empty() {
            return Err(self.fatal(
                invocation,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "a stdin frame must not be empty",
                ),
            ));
        }
        let limits = self.config.limits;
        let (current_offset, current_bytes, closed) = {
            let active = self.invocation_mut(invocation)?;
            (
                active.input_offset,
                active.input_bytes,
                active.eof_requested || active.stdin.is_none(),
            )
        };
        if closed {
            return Err(self.fatal(
                invocation,
                io::Error::new(io::ErrorKind::InvalidInput, "workload stdin is closed"),
            ));
        }
        if current_offset != offset {
            return Err(self.fatal(
                invocation,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("stdin offset {offset} is not contiguous with {current_offset}"),
                ),
            ));
        }
        if current_bytes.saturating_add(data.len() as u64) > limits.input_bytes as u64 {
            return Err(self.fatal(
                invocation,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invocation input exceeds the configured bound",
                ),
            ));
        }
        let active = self.invocation_mut(invocation)?;
        active.input_offset += data.len() as u64;
        active.input_bytes += data.len() as u64;
        active.pending_input.extend_from_slice(&data);
        let flushed = active.flush_input();
        let accepted_offset = active.input_offset;
        if let Err(error) = flushed {
            return Err(self.fatal(
                invocation,
                io::Error::new(
                    error.kind(),
                    format!("cannot write workload input: {error}"),
                ),
            ));
        }
        Ok(vec![Event::InputAccepted {
            invocation,
            offset: accepted_offset,
            bytes: data.len() as u64,
            eof: false,
        }])
    }

    /// Request end of input. The queue is flushed first, and the child's
    /// standard input closes only once the queue is empty.
    pub fn stdin_eof(&mut self, invocation: u64) -> io::Result<Vec<Event>> {
        let (offset, flushed) = {
            let active = self.invocation_mut(invocation)?;
            if active.eof_requested {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "end of input was already requested",
                ));
            }
            active.eof_requested = true;
            let flushed = active.flush_input();
            (active.input_offset, flushed)
        };
        if let Err(error) = flushed {
            return Err(self.fatal(
                invocation,
                io::Error::new(
                    error.kind(),
                    format!("cannot flush workload input: {error}"),
                ),
            ));
        }
        Ok(vec![Event::InputAccepted {
            invocation,
            offset,
            bytes: 0,
            eof: true,
        }])
    }

    /// Request unconditional termination of the invocation.
    pub fn terminate(&mut self, invocation: u64) -> io::Result<Vec<Event>> {
        let active = self.invocation_mut(invocation)?;
        if active.exit.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the invocation has already exited",
            ));
        }
        signal_members(active.pid, self.config.scope, TERMINATION_SIGNAL)?;
        Ok(vec![Event::TerminationRequested {
            invocation,
            signal: TERMINATION_SIGNAL,
        }])
    }

    /// Drain live output and advance the invocation. The timeout applies only
    /// while the primary process is live; the cleanup barrier after exit always
    /// runs to completion before this returns.
    pub fn poll(&mut self, timeout: Duration) -> io::Result<Vec<Event>> {
        let Some(active) = self.active.as_mut() else {
            return Ok(Vec::new());
        };
        let mut events = Vec::new();
        if active.exit.is_none() {
            active.flush_input()?;
            drain_ready(active, &self.config.limits, timeout, &mut events)?;
            active.reaped += reap_children(active);
        }
        if active.exit.is_some() && !active.cleanup_complete {
            cleanup(active, self.config.scope, &self.config.limits, &mut events)?;
        }
        // A completed barrier releases the single-workload slot so the next
        // start is accepted only after cleanup.
        let finished = active.cleanup_complete;
        if finished {
            self.active = None;
        }
        Ok(events)
    }

    /// Terminate and reap any active invocation, then report the barrier.
    pub fn shutdown(&mut self) -> io::Result<Vec<Event>> {
        let Some(active) = self.active.as_mut() else {
            return Ok(Vec::new());
        };
        if active.exit.is_none() {
            signal_members(active.pid, self.config.scope, TERMINATION_SIGNAL)?;
        }
        let mut events = Vec::new();
        cleanup(active, self.config.scope, &self.config.limits, &mut events)?;
        self.active = None;
        Ok(events)
    }

    fn invocation_mut(&mut self, invocation: u64) -> io::Result<&mut Invocation> {
        match self.active.as_mut() {
            Some(active) if active.id == invocation => Ok(active),
            Some(active) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invocation {invocation} does not match the active invocation {}",
                    active.id
                ),
            )),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invocation {invocation} is not active"),
            )),
        }
    }

    /// A fatal protocol or transport failure kills the invocation and is
    /// reported as an infrastructure error, never as a workload property.
    fn fatal(&mut self, invocation: u64, error: io::Error) -> io::Error {
        if let Ok(active) = self.invocation_mut(invocation)
            && active.exit.is_none()
        {
            let _ = signal_members(active.pid, self.config.scope, TERMINATION_SIGNAL);
        }
        error
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if let Some(active) = self.active.as_mut() {
            if active.exit.is_none() {
                let _ = signal_members(active.pid, self.config.scope, TERMINATION_SIGNAL);
            }
            let mut ignored = Vec::new();
            let _ = cleanup(active, self.config.scope, &self.config.limits, &mut ignored);
            // The invocation's root guard removes the fresh root on drop.
        }
    }
}

// ---------------------------------------------------------------------------
// Template validation and materialization
// ---------------------------------------------------------------------------

/// Reject a runtime configuration whose bounds would silently change behavior.
///
/// A zero frame size is the important case: `read` with a zero-length buffer
/// returns zero, which the drain loop would mistake for end of file and report
/// as an empty stream for a workload that produced output.
fn validate_limits(limits: &RuntimeLimits) -> io::Result<()> {
    if limits.input_frame_bytes == 0
        || limits.input_frame_bytes > MAX_STDIN_FRAME_BYTES
        || limits.output_frame_bytes == 0
        || limits.output_frame_bytes > MAX_OUTPUT_FRAME_BYTES
    {
        return Err(invalid(
            "runtime frame limits must be positive and within the protocol bounds",
        ));
    }
    if limits.input_bytes < limits.input_frame_bytes
        || limits.output_bytes < limits.output_frame_bytes
    {
        return Err(invalid(
            "runtime byte limits must cover at least one whole frame",
        ));
    }
    if limits.template_entries == 0
        || limits.template_entries > MAX_VIEW_ENTRIES
        || limits.template_path_bytes == 0
        || limits.template_path_bytes > MAX_PATH_BYTES
        || limits.file_bytes == 0
        || limits.file_bytes > MAX_FILE_BYTES
    {
        return Err(invalid(
            "runtime template limits must be positive and within the canonical filesystem bounds",
        ));
    }
    Ok(())
}

/// Walk the immutable template and enforce the versioned overlay profile.
///
/// `/tmp` and `/dev` must be directories when the package provides them, and
/// every package entry below those paths must be a directory: the overlay
/// replaces their metadata and content, so anything else collides.
pub fn validate_template(template: &Path, limits: &RuntimeLimits) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(template)
        .map_err(|error| invalid(format!("cannot inspect the workload template: {error}")))?;
    if !metadata.is_dir() {
        return Err(invalid("the workload template root is not a directory"));
    }
    let mut stack = vec![(template.to_path_buf(), Vec::<u8>::new())];
    // The template root itself is a view entry, exactly as the assembler counts
    // it, so the runtime accepts every template the assembler accepted.
    let mut entries = 1usize;
    while let Some((directory, prefix)) = stack.pop() {
        for entry in std::fs::read_dir(&directory)
            .map_err(|error| invalid(format!("cannot read the workload template: {error}")))?
        {
            let entry =
                entry.map_err(|error| invalid(format!("cannot read a template entry: {error}")))?;
            let name = entry.file_name();
            let name = name.as_bytes();
            if name.contains(&b'/') || name.contains(&0) {
                return Err(invalid("a template entry name is not a path component"));
            }
            let mut path = prefix.clone();
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(name);
            entries += 1;
            if entries > limits.template_entries {
                return Err(invalid(format!(
                    "the workload template exceeds {} entries",
                    limits.template_entries
                )));
            }
            if path.len() > limits.template_path_bytes {
                return Err(invalid(format!(
                    "a workload template path exceeds {} bytes",
                    limits.template_path_bytes
                )));
            }
            let file_type = entry
                .file_type()
                .map_err(|error| invalid(format!("cannot inspect a template entry: {error}")))?;
            let overlay = path.as_slice() == OVERLAY_TMP
                || path.as_slice() == OVERLAY_DEV
                || path.starts_with(b"tmp/")
                || path.starts_with(b"dev/");
            if overlay && !file_type.is_dir() {
                return Err(invalid(format!(
                    "overlay path {:?} collides with the runtime overlay",
                    String::from_utf8_lossy(&path)
                )));
            }
            if file_type.is_dir() {
                stack.push((entry.path(), path));
            } else if !file_type.is_file() && !file_type.is_symlink() {
                return Err(invalid(format!(
                    "workload template entry {:?} is not a regular file, directory, or symbolic link",
                    String::from_utf8_lossy(&path)
                )));
            }
        }
    }
    Ok(())
}

/// Reproduce the template bytes and canonical metadata below an existing fresh
/// root, then apply the versioned runtime overlay.
///
/// The canonical root metadata is applied after the overlay, so creating the
/// overlay entries cannot change the recorded directory timestamps.
fn materialize_into(template: &Path, destination: &Path, limits: &RuntimeLimits) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(template)
        .map_err(|error| invalid(format!("cannot inspect the workload template: {error}")))?;
    copy_entries(template, destination, true, limits)?;
    apply_overlay(destination)?;
    set_metadata(
        destination,
        unix_mode(&metadata),
        unix_owner(&metadata),
        unix_mtime(&metadata),
        false,
    )
}

fn copy_directory(
    source: &Path,
    destination: &Path,
    metadata: &std::fs::Metadata,
    limits: &RuntimeLimits,
) -> io::Result<()> {
    copy_entries(source, destination, false, limits)?;
    set_metadata(
        destination,
        unix_mode(metadata),
        unix_owner(metadata),
        unix_mtime(metadata),
        false,
    )
}

/// Copy one directory level.
///
/// At the template root the `tmp` and `dev` subtrees are skipped: the overlay
/// synthesizes them fresh, so a package-provided entry below them can never
/// collide with the overlay or force a failing removal.
fn copy_entries(
    source: &Path,
    destination: &Path,
    skip_overlay: bool,
    limits: &RuntimeLimits,
) -> io::Result<()> {
    for entry in std::fs::read_dir(source)
        .map_err(|error| invalid(format!("cannot read the workload template: {error}")))?
    {
        let entry =
            entry.map_err(|error| invalid(format!("cannot read a template entry: {error}")))?;
        let name = entry.file_name();
        if skip_overlay && (name.as_bytes() == OVERLAY_TMP || name.as_bytes() == OVERLAY_DEV) {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|error| invalid(format!("cannot inspect a template entry: {error}")))?;
        let target = destination.join(&name);
        let source_path = entry.path();
        let child = std::fs::symlink_metadata(&source_path)
            .map_err(|error| invalid(format!("cannot inspect a template entry: {error}")))?;
        if file_type.is_dir() {
            std::fs::create_dir(&target)
                .map_err(|error| invalid(format!("cannot create a workload directory: {error}")))?;
            copy_directory(&source_path, &target, &child, limits)?;
        } else if file_type.is_symlink() {
            let link = std::fs::read_link(&source_path).map_err(|error| {
                invalid(format!("cannot read a workload symbolic link: {error}"))
            })?;
            std::os::unix::fs::symlink(&link, &target).map_err(|error| {
                invalid(format!("cannot create a workload symbolic link: {error}"))
            })?;
        } else if file_type.is_file() {
            if child.len() > limits.file_bytes as u64 {
                return Err(invalid(format!(
                    "a workload file exceeds the {} byte canonical file bound",
                    limits.file_bytes
                )));
            }
            std::fs::copy(&source_path, &target)
                .map_err(|error| invalid(format!("cannot copy a workload file: {error}")))?;
        } else {
            return Err(invalid(
                "the workload template contains an unsupported file type",
            ));
        }
        set_metadata(
            &target,
            unix_mode(&child),
            unix_owner(&child),
            unix_mtime(&child),
            file_type.is_symlink(),
        )?;
    }
    Ok(())
}

/// Apply the versioned runtime overlay to a freshly materialized root.
///
/// Both overlay directories are synthesized from the canonical profile, so any
/// package-provided content below them is replaced rather than merged. The
/// `/dev` metadata is applied after its device nodes exist, so creating them
/// cannot change the recorded directory timestamp.
fn apply_overlay(root: &Path) -> io::Result<()> {
    let tmp = root.join("tmp");
    ensure_directory(&tmp)?;
    set_metadata(&tmp, OVERLAY_TMP_MODE, (0, 0), 0, false)?;
    let dev = root.join("dev");
    ensure_directory(&dev)?;
    for (name, (major, minor)) in [("null", DEV_NULL), ("zero", DEV_ZERO)] {
        let path = dev.join(name);
        mknod_device(&path, major, minor)?;
        set_metadata(&path, OVERLAY_DEVICE_MODE, (0, 0), 0, false)?;
    }
    set_metadata(&dev, OVERLAY_DIRECTORY_MODE, (0, 0), 0, false)
}

fn ensure_directory(path: &Path) -> io::Result<()> {
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if std::fs::symlink_metadata(path)?.is_dir() {
                Ok(())
            } else {
                Err(invalid(format!(
                    "overlay path {} is not a directory",
                    path.display()
                )))
            }
        }
        Err(error) => Err(invalid(format!(
            "cannot create overlay path {}: {error}",
            path.display()
        ))),
    }
}

/// Require the launch executable and working directory to resolve inside the
/// fresh root without traversing a symbolic link.
fn verify_launch_target(
    root: &Path,
    launch: &LaunchIdentity,
) -> Result<(), (LaunchFailure, String)> {
    let executable = resolve_in_root(root, "the workload executable", &launch.executable)
        .map_err(|error| (LaunchFailure::Executable, error.to_string()))?;
    let metadata = std::fs::symlink_metadata(&executable).map_err(|error| {
        (
            LaunchFailure::Executable,
            format!("cannot inspect the workload executable: {error}"),
        )
    })?;
    if !metadata.is_file() {
        return Err((
            LaunchFailure::Executable,
            "the workload executable is not a regular file".into(),
        ));
    }
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err((
            LaunchFailure::Executable,
            "the workload executable has no execute permission".into(),
        ));
    }
    let working = resolve_in_root(
        root,
        "the workload working directory",
        &launch.working_directory,
    )
    .map_err(|error| (LaunchFailure::WorkingDirectory, error.to_string()))?;
    if !std::fs::symlink_metadata(&working)
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
    {
        return Err((
            LaunchFailure::WorkingDirectory,
            "the workload working directory is not a directory".into(),
        ));
    }
    Ok(())
}

/// Resolve an absolute in-root path component by component, refusing any
/// symbolic link in the path so a link cannot redirect the launch.
///
/// Diagnostics name `field` and never echo the caller-provided path value.
fn resolve_in_root(root: &Path, field: &str, value: &str) -> io::Result<PathBuf> {
    if value.is_empty() || !value.starts_with('/') || value.contains('\0') {
        return Err(invalid(format!("{field} is not an absolute in-root path")));
    }
    if value.split('/').any(|component| component == "..") {
        return Err(invalid(format!("{field} escapes the workload root")));
    }
    let mut current = root.to_path_buf();
    for component in value.split('/').filter(|part| !part.is_empty()) {
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current)
            .map_err(|error| invalid(format!("cannot access {field}: {error}")))?;
        if metadata.is_symlink() {
            return Err(invalid(format!("{field} traverses a symbolic link")));
        }
    }
    Ok(current)
}

/// Validate the launch identity against the shared, versioned launch contract.
///
/// The runtime deliberately does not re-implement the bounds or require
/// `arguments[0]` to equal `executable`: OCI normalization canonicalizes the
/// executable path while preserving the caller's argument vector, so the two
/// may legitimately differ. Symlink-free resolution of the executed paths is a
/// separate runtime concern handled by [`resolve_in_root`].
fn validate_launch(launch: &LaunchIdentity) -> io::Result<()> {
    validate_launch_identity(launch)
}

// ---------------------------------------------------------------------------
// Child process setup and supervision
// ---------------------------------------------------------------------------

struct Spawned {
    pid: libc::pid_t,
    stdin: OwnedFd,
    stdout: OwnedFd,
    stderr: OwnedFd,
}

/// Owns the forked child until the invocation takes it over, so every failure
/// after `fork` kills and reaps the child instead of leaking it.
struct ChildGuard {
    pid: libc::pid_t,
    scope: MemberScope,
    armed: bool,
}

impl ChildGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = signal_members(self.pid, self.scope, TERMINATION_SIGNAL);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut status = 0;
            // SAFETY: `status` is writable and `pid` is the child created by
            // this call.
            let reaped = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if reaped == self.pid || reaped < 0 {
                return;
            }
            if Instant::now() >= deadline {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// The result of waiting for the child's setup pipe.
enum SetupOutcome {
    /// The child closed the setup pipe by successfully exec'ing.
    Ready,
    /// The child reported a typed setup failure.
    Failed(u8),
    /// The child did not report within the setup bound.
    Timeout,
    /// The setup pipe could not be read.
    Transport(io::Error),
}

fn spawn(
    root: &Path,
    launch: &LaunchIdentity,
    scope: MemberScope,
) -> Result<Spawned, (LaunchFailure, String)> {
    let stdin = create_pipe().map_err(|error| (LaunchFailure::Pipe, error.to_string()))?;
    let stdout = create_pipe().map_err(|error| (LaunchFailure::Pipe, error.to_string()))?;
    let stderr = create_pipe().map_err(|error| (LaunchFailure::Pipe, error.to_string()))?;
    let error_pipe = create_pipe().map_err(|error| (LaunchFailure::Pipe, error.to_string()))?;

    let root_c = path_cstring(root).map_err(|error| (LaunchFailure::Setup, error.to_string()))?;
    let working_c = CString::new(launch.working_directory.as_bytes())
        .map_err(|error| (LaunchFailure::WorkingDirectory, error.to_string()))?;
    let executable_c = CString::new(launch.executable.as_bytes())
        .map_err(|error| (LaunchFailure::Executable, error.to_string()))?;
    let arguments = launch
        .arguments
        .iter()
        .map(|value| CString::new(value.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| (LaunchFailure::Executable, error.to_string()))?;
    let environment = launch
        .environment
        .iter()
        .map(|value| CString::new(value.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| (LaunchFailure::Executable, error.to_string()))?;
    let mut argv: Vec<*const libc::c_char> = arguments.iter().map(|value| value.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<*const libc::c_char> =
        environment.iter().map(|value| value.as_ptr()).collect();
    envp.push(std::ptr::null());

    let child_stdin = stdin.read.as_raw_fd();
    let child_stdout = stdout.write.as_raw_fd();
    let child_stderr = stderr.write.as_raw_fd();
    let error_write = error_pipe.write.as_raw_fd();
    let uid = launch.uid;
    let gid = launch.gid;

    // Configure the parent's pipe ends before forking, so no fallible
    // parent-side operation remains once the child exists. The stdin write end
    // is non-blocking so a child that stops reading cannot block the control
    // loop.
    set_nonblocking(stdin.write.as_raw_fd()).map_err(|error| {
        (
            LaunchFailure::Pipe,
            format!("cannot configure the workload input pipe: {error}"),
        )
    })?;
    set_nonblocking(stdout.read.as_raw_fd()).map_err(|error| {
        (
            LaunchFailure::Pipe,
            format!("cannot configure the workload output pipe: {error}"),
        )
    })?;
    set_nonblocking(stderr.read.as_raw_fd()).map_err(|error| {
        (
            LaunchFailure::Pipe,
            format!("cannot configure the workload output pipe: {error}"),
        )
    })?;

    // SAFETY: the child runs only async-signal-safe calls on pre-built
    // arguments and then either `_exit`s or replaces its image with `execve`.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err((
            LaunchFailure::Fork,
            format!(
                "cannot fork the workload child: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    if pid == 0 {
        // SAFETY: the child is a single-threaded forked process that only calls
        // async-signal-safe functions before `execve`.
        unsafe {
            if scope == MemberScope::ProcessGroup {
                libc::setpgid(0, 0);
            }
            child_exec(
                child_stdin,
                child_stdout,
                child_stderr,
                error_write,
                &root_c,
                &working_c,
                &executable_c,
                &argv,
                &envp,
                uid,
                gid,
            );
        }
    }

    drop(stdin.read);
    drop(stdout.write);
    drop(stderr.write);
    drop(error_pipe.write);

    // The guard owns the child from here, so every failure below kills and
    // reaps it instead of leaving a running process behind.
    let mut guard = ChildGuard {
        pid,
        scope,
        armed: true,
    };
    match await_setup(error_pipe.read) {
        SetupOutcome::Ready => {
            guard.disarm();
            Ok(Spawned {
                pid,
                stdin: stdin.write,
                stdout: stdout.read,
                stderr: stderr.read,
            })
        }
        SetupOutcome::Failed(code) => {
            let (kind, detail) = child_status::failure(code);
            let failure = match kind {
                "working_directory" => LaunchFailure::WorkingDirectory,
                "executable" => LaunchFailure::Executable,
                "pipe" => LaunchFailure::Pipe,
                _ => LaunchFailure::Setup,
            };
            Err((failure, detail.to_string()))
        }
        SetupOutcome::Timeout => Err((
            LaunchFailure::Setup,
            "the workload child did not complete setup within the bound".into(),
        )),
        SetupOutcome::Transport(error) => Err((
            LaunchFailure::Pipe,
            format!("cannot read the workload setup result: {error}"),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn child_exec(
    child_stdin: RawFd,
    child_stdout: RawFd,
    child_stderr: RawFd,
    error_write: RawFd,
    root: &CString,
    working: &CString,
    executable: &CString,
    argv: &[*const libc::c_char],
    envp: &[*const libc::c_char],
    uid: u32,
    gid: u32,
) -> ! {
    // SAFETY: every call below uses a live descriptor or a pre-built
    // NUL-terminated string and runs in a forked child before `execve`.
    unsafe {
        if libc::dup2(child_stdin, libc::STDIN_FILENO) < 0
            || libc::dup2(child_stdout, libc::STDOUT_FILENO) < 0
            || libc::dup2(child_stderr, libc::STDERR_FILENO) < 0
        {
            fail_child(error_write, child_status::DUP);
        }
        close_inherited_descriptors(error_write);
        if libc::chroot(root.as_ptr()) != 0 {
            fail_child(error_write, child_status::CHROOT);
        }
        if libc::chdir(working.as_ptr()) != 0 {
            fail_child(error_write, child_status::CHDIR);
        }
        if libc::setgroups(0, std::ptr::null()) != 0 {
            fail_child(error_write, child_status::GROUPS);
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            fail_child(error_write, child_status::NO_NEW_PRIVS);
        }
        if libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
            fail_child(error_write, child_status::CREDENTIALS);
        }
        libc::execve(executable.as_ptr(), argv.as_ptr(), envp.as_ptr());
        fail_child(error_write, child_status::EXEC);
    }
}

unsafe fn fail_child(error_write: RawFd, code: u8) -> ! {
    // SAFETY: `error_write` is the live setup pipe write end and the one-byte
    // value is a stack local.
    unsafe {
        let byte = [code];
        libc::write(error_write, byte.as_ptr().cast(), 1);
        libc::_exit(127);
    }
}

unsafe fn close_inherited_descriptors(preserve: RawFd) {
    let mut limit = 4096_u64;
    let mut rlimit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `rlimit` is writable and the call has no other effects.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlimit) } == 0
        && rlimit.rlim_cur != libc::RLIM_INFINITY
    {
        limit = rlimit.rlim_cur.min(MAX_DESCRIPTOR_SCAN);
    }
    for fd in 3..limit as RawFd {
        if fd != preserve {
            // SAFETY: closing an unused descriptor is harmless; EBADF is
            // ignored because most descriptors in the range are unused.
            unsafe { libc::close(fd) };
        }
    }
}

fn await_setup(error_read: OwnedFd) -> SetupOutcome {
    let fd = error_read.as_raw_fd();
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: `descriptor` is a single initialized pollfd.
        let ready = unsafe { libc::poll(&mut descriptor, 1, SETUP_TIMEOUT.as_millis() as i32) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return SetupOutcome::Transport(error);
        }
        if ready == 0 {
            return SetupOutcome::Timeout;
        }
        let mut byte = [0_u8; 1];
        // SAFETY: `byte` is a writable one-byte buffer on the setup pipe.
        let read = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) };
        return match read {
            1 => SetupOutcome::Failed(byte[0]),
            0 => SetupOutcome::Ready,
            _ => {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                SetupOutcome::Transport(error)
            }
        };
    }
}

/// Poll the live output pipes once and drain a bounded, fair batch.
fn drain_ready(
    active: &mut Invocation,
    limits: &RuntimeLimits,
    timeout: Duration,
    events: &mut Vec<Event>,
) -> io::Result<()> {
    let descriptors = poll_descriptors(active);
    if !descriptors.is_empty() && !poll_once(&descriptors, timeout)? {
        return Ok(());
    }
    drain_batch(active, limits, events)
}

/// Drain both streams fairly within one bounded batch.
///
/// The bounds keep a continuously ready stream from monopolizing the control
/// loop or allocating an unbounded event vector, and alternating the streams
/// keeps one from starving the other.
fn drain_batch(
    active: &mut Invocation,
    limits: &RuntimeLimits,
    events: &mut Vec<Event>,
) -> io::Result<()> {
    let mut frames = 0_u64;
    let mut bytes = 0_usize;
    loop {
        let mut progress = false;
        for stream in [OutputStream::Stdout, OutputStream::Stderr] {
            if frames >= MAX_SERVICE_FRAMES || bytes >= MAX_SERVICE_BYTES {
                return Ok(());
            }
            let (drained, size) = drain_stream(
                active,
                stream,
                limits,
                MAX_SERVICE_FRAMES - frames,
                MAX_SERVICE_BYTES - bytes,
                events,
            )?;
            frames += drained;
            bytes += size;
            progress |= drained > 0;
        }
        if !progress {
            return Ok(());
        }
    }
}

fn poll_descriptors(active: &Invocation) -> Vec<libc::pollfd> {
    let mut descriptors = Vec::new();
    if !active.stdout_state.eof
        && let Some(fd) = active.stdout.as_ref()
    {
        descriptors.push(libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
    }
    if !active.stderr_state.eof
        && let Some(fd) = active.stderr.as_ref()
    {
        descriptors.push(libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
    }
    descriptors
}

fn poll_once(descriptors: &[libc::pollfd], timeout: Duration) -> io::Result<bool> {
    let mut descriptors = descriptors.to_vec();
    // SAFETY: `descriptors` is a live, initialized array of pollfd values.
    let ready = unsafe {
        libc::poll(
            descriptors.as_mut_ptr(),
            descriptors.len() as libc::nfds_t,
            timeout.as_millis() as i32,
        )
    };
    if ready < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(error);
    }
    Ok(ready > 0)
}

/// Drain one stream up to `max_frames` frames and `max_bytes` bytes, returning
/// what was drained so the caller can keep the batch fair and bounded.
fn drain_stream(
    active: &mut Invocation,
    stream: OutputStream,
    limits: &RuntimeLimits,
    max_frames: u64,
    max_bytes: usize,
    events: &mut Vec<Event>,
) -> io::Result<(u64, usize)> {
    let Invocation {
        stdout_state,
        stdout,
        stderr_state,
        stderr,
        sequence,
        frames,
        id,
        ..
    } = active;
    let (state, fd) = match stream {
        OutputStream::Stdout => (stdout_state, stdout),
        OutputStream::Stderr => (stderr_state, stderr),
    };
    if state.eof {
        return Ok((0, 0));
    }
    let Some(fd) = fd.as_ref() else {
        state.eof = true;
        return Ok((0, 0));
    };
    let raw = fd.as_raw_fd();
    let mut drained = 0_u64;
    let mut size = 0_usize;
    while drained < max_frames && size < max_bytes {
        let chunk = limits.output_frame_bytes.min(max_bytes - size);
        if chunk == 0 {
            break;
        }
        let mut buffer = vec![0_u8; chunk];
        // SAFETY: `buffer` is a writable buffer of its own length and `raw` is
        // a live non-blocking pipe read end.
        let read = unsafe { libc::read(raw, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok((drained, size));
            }
            return Err(error);
        }
        if read == 0 {
            state.eof = true;
            return Ok((drained, size));
        }
        buffer.truncate(read as usize);
        if state.bytes.saturating_add(buffer.len() as u64) > limits.output_bytes as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invocation output exceeds the configured bound",
            ));
        }
        state.hasher.update(&buffer);
        *sequence += 1;
        *frames += 1;
        let offset = state.offset;
        state.offset += buffer.len() as u64;
        state.bytes += buffer.len() as u64;
        events.push(Event::WorkloadOutput {
            invocation: *id,
            stream,
            offset,
            sequence: *sequence,
            bytes: crate::protocol::encode_bytes(&buffer),
        });
        drained += 1;
        size += buffer.len();
    }
    Ok((drained, size))
}

/// Record one reaped child. The primary's real status is preserved, so a
/// fabricated exit is never reported.
fn record_reaped(active: &mut Invocation, pid: libc::pid_t, status: i32) {
    if pid != active.pid || active.exit.is_some() {
        return;
    }
    active.exit = if libc::WIFEXITED(status) {
        Some(ProcessExit::Exited {
            code: libc::WEXITSTATUS(status),
        })
    } else if libc::WIFSIGNALED(status) {
        Some(ProcessExit::Signaled {
            signal: libc::WTERMSIG(status),
        })
    } else {
        None
    };
}

/// Reap every child that has exited, recording the primary's status.
fn reap_children(active: &mut Invocation) -> u64 {
    let mut reaped = 0;
    loop {
        let mut status = 0;
        // SAFETY: `status` is writable; only the agent's own children are
        // reaped, which is exactly the invocation's direct members.
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid <= 0 {
            break;
        }
        reaped += 1;
        record_reaped(active, pid, status);
    }
    reaped
}

/// Kill every remaining member, reap until only the agent remains, and drain
/// both pipes to end of file before reporting the barrier.
///
/// The barrier is verified rather than assumed: the loop continues until the
/// process table and both pipes are empty, and exhausting its deadline is a
/// fatal infrastructure error instead of a reported completion.
fn cleanup(
    active: &mut Invocation,
    scope: MemberScope,
    limits: &RuntimeLimits,
    events: &mut Vec<Event>,
) -> io::Result<()> {
    // The cleanup barrier is idempotent: a second call after completion emits
    // nothing, so `poll` can be called freely once an invocation is idle.
    if active.cleanup_complete {
        return Ok(());
    }
    active.stdin = None;
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    loop {
        signal_members(active.pid, scope, TERMINATION_SIGNAL)?;
        active.reaped += reap_children(active);
        drain_batch(active, limits, events)?;
        let members = members_remain(scope, active.pid)?;
        let drained = active.stdout_state.eof && active.stderr_state.eof;
        if !members && drained {
            break;
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the workload cleanup barrier did not complete within its bound",
            ));
        }
        // Wait briefly so a killed member can be reaped and a pipe can reach
        // end of file without spinning.
        wait_for_output(active, Duration::from_millis(10));
    }
    // One final reap after end of file, so a member that exited while the pipes
    // were draining is never left as an unreaped zombie.
    active.reaped += reap_children(active);
    let exit = active
        .exit
        .ok_or_else(|| io::Error::other("the workload primary process was not reaped"))?;
    let stdout_sha256 = finish_stream(&mut active.stdout_state);
    let stderr_sha256 = finish_stream(&mut active.stderr_state);
    let reaped = active.reaped;
    active.cleanup_complete = true;
    active.stdout = None;
    active.stderr = None;
    events.push(Event::WorkloadExited {
        invocation: active.id,
        exit,
        stdout_bytes: active.stdout_state.bytes,
        stdout_sha256,
        stderr_bytes: active.stderr_state.bytes,
        stderr_sha256,
        frames: active.frames,
    });
    events.push(Event::CleanupComplete {
        invocation: active.id,
        reaped,
    });
    Ok(())
}

/// Wait for output readiness or a short timeout, so the cleanup barrier yields
/// the CPU between kill attempts.
fn wait_for_output(active: &Invocation, timeout: Duration) {
    let descriptors = poll_descriptors(active);
    if descriptors.is_empty() {
        std::thread::sleep(timeout);
        return;
    }
    let _ = poll_once(&descriptors, timeout);
}

fn finish_stream(state: &mut StreamState) -> String {
    let digest = std::mem::take(&mut state.hasher).finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn signal_members(pid: libc::pid_t, scope: MemberScope, signal: i32) -> io::Result<()> {
    match scope {
        MemberScope::ProcessGroup => {
            // SAFETY: signalling a process group is harmless when it is empty.
            if unsafe { libc::kill(-pid, signal) } != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(io::Error::new(
                        error.kind(),
                        format!("cannot signal the invocation process group: {error}"),
                    ));
                }
            }
            Ok(())
        }
        MemberScope::Guest => {
            for member in guest_process_table()? {
                // SAFETY: signalling a userspace guest pid is safe in the
                // dedicated guest; ESRCH is expected for exited members.
                if unsafe { libc::kill(member as libc::pid_t, signal) } != 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ESRCH) {
                        return Err(io::Error::new(
                            error.kind(),
                            format!("cannot signal guest member {member}: {error}"),
                        ));
                    }
                }
            }
            Ok(())
        }
    }
}

fn members_remain(scope: MemberScope, pid: libc::pid_t) -> io::Result<bool> {
    match scope {
        MemberScope::ProcessGroup => {
            // SAFETY: signal 0 only probes for existence.
            Ok(unsafe { libc::kill(-pid, 0) } == 0)
        }
        MemberScope::Guest => Ok(!guest_process_table()?.is_empty()),
    }
}

/// Every userspace process in the guest other than the agent. Kernel threads
/// appear in `/proc` but cannot be signalled or reaped, so they are never
/// invocation members.
fn guest_process_table() -> io::Result<Vec<u32>> {
    let mut members = Vec::new();
    let entries = std::fs::read_dir("/proc").map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot enumerate the guest process table: {error}"),
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot read a guest process entry: {error}"),
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pid == std::process::id() {
            continue;
        }
        // A pid that vanished between enumeration and inspection is simply not
        // a member any more.
        if is_kernel_thread(pid)? != Some(false) {
            continue;
        }
        members.push(pid);
    }
    members.sort_unstable();
    Ok(members)
}

/// Report whether a guest pid is a kernel thread. `None` means the process
/// vanished while it was inspected.
fn is_kernel_thread(pid: u32) -> io::Result<Option<bool>> {
    match std::fs::read(format!("/proc/{pid}/stat")) {
        Ok(stat) => Ok(Some(stat_flags(&stat)? & KERNEL_THREAD_FLAG != 0)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("cannot read the state of guest pid {pid}: {error}"),
        )),
    }
}

/// Extract the process flags field from `/proc/<pid>/stat`. The command name is
/// parenthesized and may contain spaces and parentheses, so only the fields
/// after the last `)` are counted positionally: state is 0 and flags is 6.
fn stat_flags(stat: &[u8]) -> io::Result<u64> {
    let text = std::str::from_utf8(stat)
        .map_err(|_| invalid("a guest process state record is not UTF-8"))?;
    let rest = text
        .rsplit_once(')')
        .map(|(_, rest)| rest)
        .ok_or_else(|| invalid("a guest process state record has no command terminator"))?;
    let flags = rest
        .split_whitespace()
        .nth(6)
        .ok_or_else(|| invalid("a guest process state record has no flags field"))?;
    flags
        .parse()
        .map_err(|_| invalid("a guest process state record has an invalid flags field"))
}

// ---------------------------------------------------------------------------
// Filesystem and process primitives
// ---------------------------------------------------------------------------

fn create_private_directory(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    let mut permissions = std::fs::metadata(path)?.permissions();
    use std::os::unix::fs::PermissionsExt;
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)
}

struct Pipe {
    read: OwnedFd,
    write: OwnedFd,
}

/// One close-on-exec pipe pair. The child clears the close-on-exec flag only on
/// the three standard descriptors it `dup2`s, so an unconnected setup pipe is
/// closed by a successful `execve`.
fn create_pipe() -> io::Result<Pipe> {
    let mut descriptors = [0_i32; 2];
    // SAFETY: `descriptors` is a writable two-element array and O_CLOEXEC is a
    // valid flag.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just created and are owned by this process.
    let read = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: see above.
    let write = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    Ok(Pipe { read, write })
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a live descriptor and F_GETFL/F_SETFL have no side
    // effects beyond the descriptor flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: see above.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn unix_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

fn unix_owner(metadata: &std::fs::Metadata) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    (metadata.uid(), metadata.gid())
}

fn unix_mtime(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.mtime().max(0) as u32
}

fn set_metadata(
    path: &Path,
    mode: u32,
    (uid, gid): (u32, u32),
    mtime: u32,
    is_symlink: bool,
) -> io::Result<()> {
    let path_c = path_cstring(path)?;
    if !is_symlink {
        // SAFETY: `path_c` is a live NUL-terminated path.
        if unsafe { libc::chmod(path_c.as_ptr(), mode as libc::mode_t) } != 0 {
            return Err(invalid(format!(
                "cannot set workload mode on {}: {}",
                path.display(),
                io::Error::last_os_error()
            )));
        }
    }
    // SAFETY: `path_c` is a live NUL-terminated path.
    if unsafe { libc::lchown(path_c.as_ptr(), uid, gid) } != 0 {
        return Err(invalid(format!(
            "cannot set workload owner on {}: {}",
            path.display(),
            io::Error::last_os_error()
        )));
    }
    // The field type is the platform `time_t`, which both the pinned glibc and
    // musl targets define as a signed 64-bit integer. Naming it directly is
    // deprecated on musl, so the value is converted rather than cast.
    let seconds = i64::from(mtime);
    let times = [
        libc::timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        },
    ];
    // SAFETY: `path_c` and `times` are live for the duration of the call.
    if unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path_c.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(invalid(format!(
            "cannot set workload timestamp on {}: {}",
            path.display(),
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn mknod_device(path: &Path, major: u32, minor: u32) -> io::Result<()> {
    let path_c = path_cstring(path)?;
    let device = libc::makedev(major, minor);
    // SAFETY: `path_c` is a live NUL-terminated path; the mode requests a
    // character device with the canonical overlay permissions.
    if unsafe {
        libc::mknod(
            path_c.as_ptr(),
            libc::S_IFCHR | OVERLAY_DEVICE_MODE as libc::mode_t,
            device,
        )
    } != 0
    {
        return Err(invalid(format!(
            "cannot create overlay device {}: {}",
            path.display(),
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn path_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| invalid(format!("path {} contains a NUL byte", path.display())))
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "simferret-runtime-test-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            // A previous run in the same PID namespace can leave this path.
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn template() -> TempDir {
        let root = TempDir::new();
        std::fs::create_dir_all(root.0.join("bin")).unwrap();
        std::fs::write(root.0.join("bin/app"), b"payload").unwrap();
        std::fs::create_dir_all(root.0.join("dev/empty")).unwrap();
        std::fs::create_dir_all(root.0.join("tmp")).unwrap();
        symlink("bin/app", root.0.join("link")).unwrap();
        root
    }

    #[test]
    fn the_overlay_profile_accepts_directories_and_content_outside_the_overlay() {
        let root = template();
        validate_template(&root.0, &RuntimeLimits::default()).unwrap();
    }

    #[test]
    fn overlay_entries_must_be_directories() {
        let root = template();
        std::fs::remove_dir_all(root.0.join("tmp")).unwrap();
        std::fs::write(root.0.join("tmp"), b"collision").unwrap();
        let error = validate_template(&root.0, &RuntimeLimits::default()).unwrap_err();
        assert!(error.to_string().contains("collides"), "{error}");

        let root = template();
        std::fs::write(root.0.join("dev/null"), b"collision").unwrap();
        let error = validate_template(&root.0, &RuntimeLimits::default()).unwrap_err();
        assert!(error.to_string().contains("collides"), "{error}");
    }

    #[test]
    fn an_empty_directory_tree_below_the_overlay_is_legal() {
        let root = template();
        std::fs::create_dir_all(root.0.join("tmp/nested")).unwrap();
        validate_template(&root.0, &RuntimeLimits::default()).unwrap();
    }

    /// The runtime bound must be the canonical view bound the assembler
    /// enforces, and it must count the template root like the assembler does,
    /// so the runtime never rejects a template the assembler accepted.
    #[test]
    fn template_entry_bounds_match_the_canonical_view_bounds() {
        assert_eq!(
            RuntimeLimits::default().template_entries,
            crate::workload::MAX_VIEW_ENTRIES
        );
        assert_eq!(
            RuntimeLimits::default().template_path_bytes,
            crate::workload::MAX_PATH_BYTES
        );
        assert_eq!(
            RuntimeLimits::default().file_bytes,
            crate::workload::MAX_FILE_BYTES
        );

        let root = template();
        // `template()` has six entries below the root, so the root-inclusive
        // count is seven.
        let exact = RuntimeLimits {
            template_entries: 7,
            ..RuntimeLimits::default()
        };
        validate_template(&root.0, &exact).unwrap();
        let one_short = RuntimeLimits {
            template_entries: 6,
            ..RuntimeLimits::default()
        };
        assert!(validate_template(&root.0, &one_short).is_err());
    }

    /// A template file is bounded by the canonical file bound, not by the
    /// invocation's output budget: the two describe different things.
    #[test]
    fn the_copied_file_bound_is_independent_of_the_output_budget() {
        let root = template();
        let large = vec![0u8; 2 << 20];
        std::fs::write(root.0.join("bin/large"), &large).unwrap();

        let destination = TempDir::new();
        let limits = RuntimeLimits {
            output_bytes: 1 << 20,
            ..RuntimeLimits::default()
        };
        copy_entries(&root.0, &destination.0, true, &limits)
            .expect("a file within the canonical file bound must be copied");
        assert_eq!(
            std::fs::metadata(destination.0.join("bin/large"))
                .unwrap()
                .len(),
            large.len() as u64
        );

        let destination = TempDir::new();
        let limits = RuntimeLimits {
            file_bytes: 1024,
            ..RuntimeLimits::default()
        };
        let error = copy_entries(&root.0, &destination.0, true, &limits).unwrap_err();
        assert!(error.to_string().contains("file bound"), "{error}");
    }

    /// Materialization must replace the overlay subtrees instead of copying
    /// them, and it must leave the canonical directory timestamps intact.
    #[test]
    fn materialization_replaces_the_overlay_and_preserves_directory_timestamps() {
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: materializing the overlay needs root to create device nodes");
            return;
        }
        let root = template();
        // A directory below an overlay path is legal, but it must not survive
        // into the invocation root, and it must not make the overlay fail.
        std::fs::create_dir_all(root.0.join("tmp/nested")).unwrap();
        std::fs::create_dir_all(root.0.join("dev/null")).unwrap();
        set_metadata(&root.0, 0o755, (0, 0), 1_700_000_000, false).unwrap();
        set_metadata(&root.0.join("dev"), 0o755, (0, 0), 1_600_000_000, false).unwrap();

        let destination = TempDir::new();
        materialize_into(&root.0, &destination.0, &RuntimeLimits::default()).unwrap();

        use std::os::unix::fs::FileTypeExt;
        let dev = destination.0.join("dev");
        assert!(
            std::fs::symlink_metadata(dev.join("null"))
                .unwrap()
                .file_type()
                .is_char_device()
        );
        assert!(!destination.0.join("tmp/nested").exists());
        // The overlay replaces `/dev` metadata, and creating its device nodes
        // must not change it again.
        assert_eq!(
            unix_mtime(&std::fs::symlink_metadata(&dev).unwrap()),
            0,
            "the overlay must own the /dev timestamp"
        );
        // The canonical root timestamp is applied after the overlay.
        assert_eq!(
            unix_mtime(&std::fs::symlink_metadata(&destination.0).unwrap()),
            1_700_000_000,
            "creating the overlay must not change the canonical root timestamp"
        );
    }

    #[test]
    fn stat_flags_reads_the_field_after_the_last_command_terminator() {
        // The command name may contain spaces and parentheses, so only the
        // fields after the last `)` are positional. Index 6 is `flags`.
        let kernel_thread = b"2 (kthreadd) S 0 2 0 0 -1 2097152 0 0 0 0 0 0 0";
        assert_eq!(
            stat_flags(kernel_thread).unwrap() & KERNEL_THREAD_FLAG,
            KERNEL_THREAD_FLAG
        );
        let userspace = b"1 (weird ) name) S 0 1 1 0 -1 4194304 0 0 0";
        assert_eq!(stat_flags(userspace).unwrap() & KERNEL_THREAD_FLAG, 0);
        assert!(stat_flags(b"1 no-command-terminator").is_err());
        assert!(stat_flags(b"1 (short) S 0").is_err());
        assert!(stat_flags(b"1 (short) S 0 1 1 0 -1 not-a-number 0").is_err());
    }

    #[test]
    fn invalid_limits_are_rejected_before_any_invocation() {
        let root = template();
        let cases = [
            RuntimeLimits {
                output_frame_bytes: 0,
                ..RuntimeLimits::default()
            },
            RuntimeLimits {
                input_frame_bytes: 0,
                ..RuntimeLimits::default()
            },
            RuntimeLimits {
                output_frame_bytes: MAX_OUTPUT_FRAME_BYTES + 1,
                ..RuntimeLimits::default()
            },
            RuntimeLimits {
                output_bytes: 1,
                ..RuntimeLimits::default()
            },
            RuntimeLimits {
                template_entries: 0,
                ..RuntimeLimits::default()
            },
            RuntimeLimits {
                template_path_bytes: 0,
                ..RuntimeLimits::default()
            },
            RuntimeLimits {
                file_bytes: 0,
                ..RuntimeLimits::default()
            },
            RuntimeLimits {
                file_bytes: MAX_FILE_BYTES + 1,
                ..RuntimeLimits::default()
            },
        ];
        for limits in cases {
            let error = Runtime::new(RuntimeConfig {
                template_root: root.0.clone(),
                runtime_root: root.0.join("runtime"),
                limits,
                scope: MemberScope::ProcessGroup,
            })
            .err()
            .expect("an invalid limit must be rejected");
            assert!(error.to_string().contains("runtime"), "{error}");
        }
        assert!(!root.0.join("runtime").exists());
    }

    #[test]
    fn guest_scope_requires_pid_one() {
        let root = template();
        let result = Runtime::new(RuntimeConfig {
            template_root: root.0.clone(),
            runtime_root: root.0.join("runtime"),
            limits: RuntimeLimits::default(),
            scope: MemberScope::Guest,
        });
        if std::process::id() == 1 {
            result.unwrap();
        } else {
            let error = result.err().expect("guest scope must be refused off PID 1");
            assert!(error.to_string().contains("PID 1"), "{error}");
        }
    }

    #[test]
    fn template_bounds_are_enforced() {
        let root = template();
        let limits = RuntimeLimits {
            template_entries: 1,
            ..RuntimeLimits::default()
        };
        assert!(validate_template(&root.0, &limits).is_err());

        let limits = RuntimeLimits {
            template_path_bytes: 2,
            ..RuntimeLimits::default()
        };
        assert!(validate_template(&root.0, &limits).is_err());
    }

    #[test]
    fn template_special_files_are_rejected() {
        let root = template();
        let fifo = std::ffi::CString::new(root.0.join("pipe").as_os_str().as_bytes()).unwrap();
        // SAFETY: `fifo` is a live NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let error = validate_template(&root.0, &RuntimeLimits::default()).unwrap_err();
        assert!(error.to_string().contains("not a regular file"), "{error}");
    }

    #[test]
    fn launch_validation_rejects_unsafe_and_privileged_values() {
        let base = LaunchIdentity {
            executable: "/bin/app".into(),
            arguments: vec!["/bin/app".into()],
            environment: vec!["MODE=test".into()],
            working_directory: "/".into(),
            uid: 65534,
            gid: 65534,
        };
        validate_launch(&base).unwrap();

        let mut escaping = base.clone();
        escaping.executable = "/../bin/app".into();
        assert!(validate_launch(&escaping).is_err());

        let mut relative = base.clone();
        relative.executable = "bin/app".into();
        assert!(validate_launch(&relative).is_err());

        let mut root = base.clone();
        root.uid = 0;
        assert!(validate_launch(&root).is_err());

        let mut reserved = base.clone();
        reserved.gid = u32::MAX;
        assert!(validate_launch(&reserved).is_err());

        let mut empty = base.clone();
        empty.arguments.clear();
        assert!(validate_launch(&empty).is_err());

        let mut environment = base.clone();
        environment.environment = vec!["MODE".into()];
        assert!(validate_launch(&environment).is_err());

        let mut duplicate = base.clone();
        duplicate.environment = vec!["MODE=a".into(), "MODE=b".into()];
        assert!(validate_launch(&duplicate).is_err());

        let mut relative_working = base.clone();
        relative_working.working_directory = "tmp".into();
        assert!(validate_launch(&relative_working).is_err());

        let mut too_many_arguments = base.clone();
        too_many_arguments.arguments = vec!["/bin/app".into(); crate::workload::MAX_ARGUMENTS + 1];
        assert!(validate_launch(&too_many_arguments).is_err());

        let mut oversized_argument = base.clone();
        oversized_argument.arguments = vec![
            "/bin/app".into(),
            "x".repeat(crate::workload::MAX_ARGUMENT_BYTES + 1),
        ];
        assert!(validate_launch(&oversized_argument).is_err());

        let mut too_many_environment = base.clone();
        too_many_environment.environment =
            vec!["A=1".into(); crate::workload::MAX_ENVIRONMENT_ENTRIES + 1];
        assert!(validate_launch(&too_many_environment).is_err());

        let mut oversized_environment = base.clone();
        oversized_environment.environment = vec![format!(
            "A={}",
            "x".repeat(crate::workload::MAX_ENVIRONMENT_ENTRY_BYTES)
        )];
        assert!(validate_launch(&oversized_environment).is_err());

        let mut non_absolute_first_argument = base.clone();
        non_absolute_first_argument.arguments = vec!["app".into()];
        assert!(validate_launch(&non_absolute_first_argument).is_err());
    }

    /// OCI normalization canonicalizes the executable while preserving the
    /// caller's argument vector, so a first argument that differs from the
    /// executable is a valid identity and must launch.
    #[test]
    fn launch_validation_accepts_a_normalized_executable_with_an_original_first_argument() {
        let launch = LaunchIdentity {
            executable: "/bin/app".into(),
            arguments: vec!["/bin/./app".into(), "--serve".into()],
            environment: vec!["MODE=test".into()],
            working_directory: "/".into(),
            uid: 65534,
            gid: 65534,
        };
        validate_launch(&launch).unwrap();
    }

    /// The diagnostics travel to the host, so they must name the field instead
    /// of echoing a caller-provided argument or environment value.
    #[test]
    fn launch_diagnostics_do_not_echo_caller_values() {
        let secret = "hunter2-should-not-appear";
        let launch = LaunchIdentity {
            executable: "/bin/app".into(),
            arguments: vec!["/bin/app".into()],
            environment: vec![format!("MODE={secret}")],
            working_directory: "/".into(),
            uid: 65534,
            gid: 65534,
        };
        validate_launch(&launch).unwrap();

        let mut duplicate = launch.clone();
        duplicate.environment = vec![format!("MODE={secret}"), format!("MODE={secret}")];
        let error = validate_launch(&duplicate).unwrap_err().to_string();
        assert!(!error.contains(secret), "{error}");

        let mut bad = launch;
        bad.environment = vec![format!("MODE{secret}")];
        let error = validate_launch(&bad).unwrap_err().to_string();
        assert!(!error.contains(secret), "{error}");
    }
}
