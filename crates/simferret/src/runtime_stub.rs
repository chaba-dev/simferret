//! Non-Linux placeholder for the guest process runtime.
//!
//! The real runtime changes root, drops credentials, creates device nodes, and
//! signals the guest process table, all of which are Linux-only. Other platforms
//! keep the same public surface so the agent, the guest image assembler, and the
//! CLI still compile, but every entry point reports `Unsupported`. The protocol
//! types and the workload assembler are portable and remain available.
//!
//! This module must mirror every public item of the Linux runtime: the CI
//! macOS job is the only thing that compiles it, so a missing item shows up as
//! a `macos-latest` failure rather than a local one.

use std::io;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::time::Duration;

use crate::protocol::{Event, LaunchFailure};
use crate::workload::LaunchIdentity;

/// The reserved guest path holding the immutable workload template.
pub const GUEST_TEMPLATE_ROOT: &str = "/workload";
/// The default guest path below which fresh writable invocation roots live.
pub const GUEST_RUNTIME_ROOT: &str = "/run/simferret";

/// The process-table scope the cleanup barrier is allowed to touch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberScope {
    Guest,
    ProcessGroup,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeLimits {
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub input_frame_bytes: usize,
    pub output_frame_bytes: usize,
    pub template_entries: usize,
    pub template_path_bytes: usize,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            input_bytes: crate::protocol::MAX_INVOCATION_INPUT_BYTES,
            output_bytes: crate::protocol::MAX_INVOCATION_OUTPUT_BYTES,
            input_frame_bytes: crate::protocol::MAX_STDIN_FRAME_BYTES,
            output_frame_bytes: crate::protocol::MAX_OUTPUT_FRAME_BYTES,
            template_entries: 1 << 14,
            template_path_bytes: 1024,
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

/// One guest process runtime. It cannot be constructed off Linux.
pub struct Runtime {
    limits: RuntimeLimits,
}

impl Runtime {
    pub fn new(_config: RuntimeConfig) -> io::Result<Self> {
        Err(unsupported())
    }

    pub fn is_active(&self) -> bool {
        false
    }

    /// The write end of the active invocation's bounded input queue, or `None`
    /// when no invocation is active. Off Linux no invocation can be active, so
    /// the control loop never has an input descriptor to poll.
    pub fn input_fd(&self) -> Option<RawFd> {
        None
    }

    pub fn output_fds(&self) -> Vec<RawFd> {
        Vec::new()
    }

    pub fn limits(&self) -> &RuntimeLimits {
        &self.limits
    }

    /// Start one invocation. Off Linux this is always a typed `no-runtime`
    /// launch failure, so the agent protocol stays identical.
    pub fn start(&mut self, invocation: u64, _launch: &LaunchIdentity) -> Vec<Event> {
        vec![Event::LaunchFailed {
            invocation,
            failure: LaunchFailure::NoRuntime,
            detail: "the guest process runtime supports Linux only".into(),
        }]
    }

    pub fn stdin_write(
        &mut self,
        _invocation: u64,
        _offset: u64,
        _bytes: &str,
    ) -> io::Result<Vec<Event>> {
        Err(unsupported())
    }

    pub fn stdin_eof(&mut self, _invocation: u64) -> io::Result<Vec<Event>> {
        Err(unsupported())
    }

    pub fn terminate(&mut self, _invocation: u64) -> io::Result<Vec<Event>> {
        Err(unsupported())
    }

    pub fn poll(&mut self, _timeout: Duration) -> io::Result<Vec<Event>> {
        Err(unsupported())
    }

    pub fn shutdown(&mut self) -> io::Result<Vec<Event>> {
        Err(unsupported())
    }
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "the guest process runtime supports Linux only",
    )
}
