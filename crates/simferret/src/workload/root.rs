//! Bounded regular-file access beneath one opened directory.
//!
//! Every path component below the opened root is traversed with `openat` and
//! `O_NOFOLLOW`, so a symbolic link, device, or FIFO anywhere beneath the root
//! is rejected instead of followed. File opens also pass `O_NONBLOCK`: without
//! it, opening a FIFO blocks until a writer appears, so a special file would
//! hang verification instead of being rejected. Reads are bounded before and
//! during the read so an oversized or sparse file cannot force unbounded work.

use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct Root {
    fd: OwnedFd,
}

impl Root {
    /// Open one directory without following a symbolic link at the final
    /// component. Intermediate components are host-provided operational paths.
    pub fn open(path: &Path) -> io::Result<Self> {
        let fd = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self { fd })
    }

    /// Open one directory that must already satisfy the private-store contract.
    ///
    /// A store that already exists with group or other access, or that belongs
    /// to another user, is rejected instead of being reused. Reusing it would
    /// let the published artifacts be replaced or read outside the owner, which
    /// is exactly what the owner-only requirement forbids.
    pub fn open_private(path: &Path) -> io::Result<Self> {
        let root = Self::open(path)?;
        root.require_private(&rustix::fs::fstat(&root.fd)?, &path.display().to_string())?;
        Ok(root)
    }

    /// Require one existing directory beneath the root to be owner-only.
    pub fn require_private_directory(&self, relative: &str) -> io::Result<()> {
        let directory = self.open_directory(relative)?;
        self.require_private(&rustix::fs::fstat(&directory.fd)?, relative)
    }

    /// Require one existing regular file beneath the root to be owner-only.
    pub fn require_private_file(&self, relative: &str) -> io::Result<()> {
        let (fd, _) = self.open_regular(relative)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("cannot open file {relative:?}"),
            )
        })?;
        self.require_private(&rustix::fs::fstat(&fd)?, relative)
    }

    fn require_private(&self, stat: &rustix::fs::Stat, relative: &str) -> io::Result<()> {
        let mode = stat.st_mode as rustix::fs::RawMode;
        if stat.st_uid != current_uid() {
            return Err(invalid(format!(
                "{relative:?} is not owned by the current user"
            )));
        }
        if mode & 0o077 != 0 {
            return Err(invalid(format!("{relative:?} is not owner-only")));
        }
        Ok(())
    }

    pub fn read_file(&self, relative: &str, limit: usize) -> io::Result<Vec<u8>> {
        match self.read_file_if_exists(relative, limit)? {
            Some(data) => Ok(data),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("cannot open file {relative:?}"),
            )),
        }
    }

    pub fn read_file_if_exists(&self, relative: &str, limit: usize) -> io::Result<Option<Vec<u8>>> {
        match self.open_regular(relative)? {
            Some((fd, size)) => Ok(Some(read_bounded(fd, size, relative, limit)?)),
            None => Ok(None),
        }
    }

    /// Hash one bounded regular file beneath the root without retaining it.
    ///
    /// Type and size validation happen on the same opened descriptor that is
    /// hashed, so a FIFO, device, or oversized file is rejected here exactly as
    /// it would be by [`Root::read_file`].
    pub fn sha256_file(&self, relative: &str, limit: usize) -> io::Result<String> {
        let (fd, size) = self.open_regular(relative)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("cannot open file {relative:?}"),
            )
        })?;
        if size > limit as u64 {
            return Err(invalid(format!("{relative:?} exceeds {limit} bytes")));
        }
        let mut file = std::fs::File::from(fd);
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024];
        let mut total = 0_u64;
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            total += read as u64;
            if total > limit as u64 {
                return Err(invalid(format!("{relative:?} exceeds {limit} bytes")));
            }
            hasher.update(&buffer[..read]);
        }
        Ok(super::tree::hex(&hasher.finalize()))
    }

    /// Open one directory beneath the root, traversing every component without
    /// following a symbolic link.
    pub fn open_directory(&self, relative: &str) -> io::Result<Self> {
        Ok(Self {
            fd: self.open_beneath(&components(relative)?)?,
        })
    }

    /// Report whether any entry exists at the relative path, without following
    /// a symbolic link at that path.
    pub fn exists(&self, relative: &str) -> io::Result<bool> {
        let (parent, name) = split_relative(relative)?;
        let directory = self.open_beneath(&parent)?;
        match rustix::fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(error) => Err(describe(error, relative)),
        }
    }

    /// Open (creating if needed) one directory beneath the root.
    ///
    /// Directories created here are owner-only, because the store may hold
    /// workload configuration and application data.
    pub fn open_or_create_directory(&self, relative: &str) -> io::Result<OwnedFd> {
        self.open_or_create_beneath(relative, &components(relative)?)
    }

    fn open_or_create_beneath(&self, relative: &str, components: &[&str]) -> io::Result<OwnedFd> {
        let mut current = self.fd.try_clone()?;
        for component in components {
            match rustix::fs::mkdirat(&current, *component, Mode::from_bits_truncate(0o700)) {
                Ok(()) => {}
                Err(Errno::EXIST) => {}
                Err(error) => return Err(describe(error, relative)),
            }
            current = rustix::fs::openat(
                &current,
                *component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| describe(error, relative))?;
            // A directory that already existed is reused only when it already
            // satisfies the private-store contract, so assembly never adopts a
            // directory that other users can write to.
            self.require_private(&rustix::fs::fstat(&current)?, relative)?;
        }
        Ok(current)
    }

    /// Create one directory beneath the root, failing when it already exists.
    pub fn create_directory(&self, relative: &str) -> io::Result<()> {
        let (parent, name) = split_relative(relative)?;
        let directory = self.open_beneath(&parent)?;
        rustix::fs::mkdirat(&directory, name, Mode::from_bits_truncate(0o700))
            .map_err(|error| describe(error, relative))
    }

    /// Publish one file beneath the root through an exclusive private staging
    /// name and an atomic rename. Returns `false` when the destination already
    /// existed, without replacing it.
    pub fn publish_exclusive(&self, relative: &str, data: &[u8]) -> io::Result<bool> {
        let (parent, name) = split_relative(relative)?;
        let directory = self.open_or_create_beneath(relative, &parent)?;
        let temporary = write_staging_file(&directory, name, data)?;
        match rustix::fs::renameat_with(
            &directory,
            temporary.as_str(),
            &directory,
            name,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => Ok(true),
            Err(Errno::EXIST) => {
                let _ = rustix::fs::unlinkat(&directory, temporary.as_str(), AtFlags::empty());
                Ok(false)
            }
            Err(error) => {
                let _ = rustix::fs::unlinkat(&directory, temporary.as_str(), AtFlags::empty());
                Err(describe(error, relative))
            }
        }
    }

    /// Publish one file beneath the root, replacing any existing entry.
    pub fn write_file_atomic(&self, relative: &str, data: &[u8]) -> io::Result<()> {
        let (parent, name) = split_relative(relative)?;
        let directory = self.open_or_create_beneath(relative, &parent)?;
        let temporary = write_staging_file(&directory, name, data)?;
        match rustix::fs::renameat(&directory, temporary.as_str(), &directory, name) {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = rustix::fs::unlinkat(&directory, temporary.as_str(), AtFlags::empty());
                Err(describe(error, relative))
            }
        }
    }

    pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let (from_parent, from_name) = split_relative(from)?;
        let (to_parent, to_name) = split_relative(to)?;
        let from_directory = self.open_beneath(&from_parent)?;
        let to_directory = self.open_beneath(&to_parent)?;
        rustix::fs::renameat(&from_directory, from_name, &to_directory, to_name)
            .map_err(|error| describe(error, to))
    }

    pub fn remove_file_if_exists(&self, relative: &str) -> io::Result<()> {
        let (parent, name) = split_relative(relative)?;
        let directory = self.open_beneath(&parent)?;
        match rustix::fs::unlinkat(&directory, name, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(error) => Err(describe(error, relative)),
        }
    }

    pub fn remove_directory_if_exists(&self, relative: &str) -> io::Result<()> {
        let (parent, name) = split_relative(relative)?;
        let directory = self.open_beneath(&parent)?;
        match rustix::fs::unlinkat(&directory, name, AtFlags::REMOVEDIR) {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(error) => Err(describe(error, relative)),
        }
    }

    fn open_regular(&self, relative: &str) -> io::Result<Option<(OwnedFd, u64)>> {
        let (parent, name) = split_relative(relative)?;
        let directory = match self.open_beneath(&parent) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let fd = match rustix::fs::openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => return Err(describe(error, relative)),
        };
        let stat = rustix::fs::fstat(&fd)?;
        if !FileType::from_raw_mode(stat.st_mode as rustix::fs::RawMode).is_file() {
            return Err(invalid(format!("{relative:?} is not a regular file")));
        }
        if stat.st_size < 0 {
            return Err(invalid(format!("{relative:?} has a negative size")));
        }
        Ok(Some((fd, stat.st_size as u64)))
    }

    fn open_beneath(&self, components: &[&str]) -> io::Result<OwnedFd> {
        let mut current = self.fd.try_clone()?;
        for component in components {
            current = rustix::fs::openat(
                &current,
                *component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| describe(error, component))?;
        }
        Ok(current)
    }
}

fn read_bounded(fd: OwnedFd, size: u64, relative: &str, limit: usize) -> io::Result<Vec<u8>> {
    if size > limit as u64 {
        return Err(invalid(format!("{relative:?} exceeds {limit} bytes")));
    }
    let mut file = std::fs::File::from(fd);
    let mut data = Vec::new();
    (&mut file).take(limit as u64 + 1).read_to_end(&mut data)?;
    if data.len() > limit {
        return Err(invalid(format!("{relative:?} exceeds {limit} bytes")));
    }
    Ok(data)
}

fn write_staging_file(directory: &OwnedFd, name: &str, data: &[u8]) -> io::Result<String> {
    let temporary = staging_name(name);
    let fd = rustix::fs::openat(
        directory,
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| describe(error, &temporary))?;
    let written = (|| -> io::Result<()> {
        let mut file = std::fs::File::from(fd);
        file.write_all(data)?;
        file.sync_all()
    })();
    if let Err(error) = written {
        let _ = rustix::fs::unlinkat(directory, temporary.as_str(), AtFlags::empty());
        return Err(error);
    }
    Ok(temporary)
}

pub fn staging_name(name: &str) -> String {
    format!(
        ".{name}.staging.{}.{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn describe(error: Errno, path: &str) -> io::Error {
    let kind = match error {
        Errno::NOENT => io::ErrorKind::NotFound,
        Errno::LOOP | Errno::NOTDIR | Errno::INVAL => io::ErrorKind::InvalidInput,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("cannot access {path:?}: {error}"))
}

fn split_relative(relative: &str) -> io::Result<(Vec<&str>, &str)> {
    let components = components(relative)?;
    match components.split_last() {
        Some((name, parent)) => Ok((parent.to_vec(), name)),
        None => Err(invalid(format!("invalid empty path {relative:?}"))),
    }
}

fn components(relative: &str) -> io::Result<Vec<&str>> {
    if relative.is_empty() {
        return Err(invalid("invalid empty path"));
    }
    let mut result = Vec::new();
    for component in relative.split('/') {
        match component {
            "" | "." => continue,
            ".." => {
                return Err(invalid(format!(
                    "path {relative:?} must not escape its opened root"
                )));
            }
            value if value.as_bytes().contains(&0) => {
                return Err(invalid(format!("path {relative:?} contains a NUL byte")));
            }
            value => result.push(value),
        }
    }
    Ok(result)
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// The effective user that owns every file this process creates.
fn current_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}
