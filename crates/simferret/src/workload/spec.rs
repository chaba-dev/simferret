//! The versioned workload specification and its normalized launch identity.

use std::io::{self, Read};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::root::invalid;
use super::tree::{ROOT_PATH, Tree};
use super::{
    MAX_ARGUMENT_BYTES, MAX_ARGUMENTS, MAX_ENVIRONMENT_BYTES, MAX_ENVIRONMENT_ENTRIES,
    MAX_ENVIRONMENT_ENTRY_BYTES, MAX_SPECIFICATION_BYTES, WORKLOAD_SPEC_VERSION,
};

/// The SimFerret default when an OCI config declares no user.
pub const DEFAULT_USER: &str = "65534:65534";
/// The one fixed canonical install path for a standalone binary workload.
pub const BINARY_INSTALL_PATH: &str = "bin/simferret-workload";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Binary,
    Oci,
}

impl SourceKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Oci => "oci",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadSpec {
    pub version: u16,
    pub source: WorkloadSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkloadSource {
    Binary(BinarySource),
    Oci(OciSource),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinarySource {
    /// Operational locator relative to the workload specification directory.
    pub path: String,
    pub arguments: Vec<String>,
    pub environment: Vec<String>,
    pub working_directory: String,
    pub user: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OciSource {
    /// Operational locator relative to the workload specification directory.
    pub layout: String,
    pub manifest_digest: String,
}

impl WorkloadSpec {
    /// Read and parse a specification from one bounded regular file.
    ///
    /// The open is non-blocking, so a specification that is a FIFO with no
    /// writer is rejected instead of blocking the assembler, and the descriptor
    /// is checked to be a regular file before it is read.
    pub fn read(path: &Path) -> io::Result<Self> {
        let fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| {
            invalid(format!(
                "cannot open workload specification {path:?}: {error}"
            ))
        })?;
        let stat = rustix::fs::fstat(&fd)?;
        if !rustix::fs::FileType::from_raw_mode(stat.st_mode as rustix::fs::RawMode).is_file() {
            return Err(invalid(format!(
                "workload specification {path:?} is not a regular file"
            )));
        }
        if stat.st_size < 0 || stat.st_size as u64 > MAX_SPECIFICATION_BYTES as u64 {
            return Err(invalid(format!(
                "workload specification must not exceed {MAX_SPECIFICATION_BYTES} bytes"
            )));
        }
        let mut source = Vec::new();
        std::fs::File::from(fd)
            .take(MAX_SPECIFICATION_BYTES as u64 + 1)
            .read_to_end(&mut source)?;
        Self::parse(&source)
    }

    pub fn parse(source: &[u8]) -> io::Result<Self> {
        if source.len() > MAX_SPECIFICATION_BYTES {
            return Err(invalid(format!(
                "workload specification must not exceed {MAX_SPECIFICATION_BYTES} bytes"
            )));
        }
        let text = std::str::from_utf8(source)
            .map_err(|error| invalid(format!("workload specification is not UTF-8: {error}")))?;
        let probe: KindProbe = toml::from_str(text)
            .map_err(|error| invalid(format!("malformed workload specification: {error}")))?;
        if probe.version != WORKLOAD_SPEC_VERSION {
            return Err(invalid(format!(
                "unsupported workload specification version {}",
                probe.version
            )));
        }
        match probe.kind {
            SourceKind::Binary => {
                let document: BinaryDocument = toml::from_str(text)
                    .map_err(|error| invalid(format!("malformed binary workload: {error}")))?;
                if document.kind != SourceKind::Binary {
                    return Err(invalid("binary workload must declare kind = \"binary\""));
                }
                validate_locator("path", &document.path)?;
                if document.user.is_empty() {
                    return Err(invalid(
                        "binary workload must declare an explicit nonzero uid:gid user",
                    ));
                }
                normalize_arguments(&document.args, "args")?;
                normalize_environment(&document.env)?;
                Ok(Self {
                    version: document.version,
                    source: WorkloadSource::Binary(BinarySource {
                        path: document.path,
                        arguments: document.args,
                        environment: document.env,
                        working_directory: document.working_directory,
                        user: document.user,
                    }),
                })
            }
            SourceKind::Oci => {
                let document: OciDocument = toml::from_str(text)
                    .map_err(|error| invalid(format!("malformed OCI workload: {error}")))?;
                if document.kind != SourceKind::Oci {
                    return Err(invalid("OCI workload must declare kind = \"oci\""));
                }
                validate_locator("layout", &document.layout)?;
                parse_digest(&document.manifest_digest)?;
                Ok(Self {
                    version: document.version,
                    source: WorkloadSource::Oci(OciSource {
                        layout: document.layout,
                        manifest_digest: document.manifest_digest,
                    }),
                })
            }
        }
    }
}

#[derive(Deserialize)]
struct KindProbe {
    version: u16,
    kind: SourceKind,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BinaryDocument {
    version: u16,
    kind: SourceKind,
    path: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: Vec<String>,
    #[serde(default = "default_working_directory")]
    working_directory: String,
    user: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OciDocument {
    version: u16,
    kind: SourceKind,
    layout: String,
    manifest_digest: String,
}

fn default_working_directory() -> String {
    "/".into()
}

/// The canonical binary workload specification retained as raw closure
/// evidence. It excludes the operational source locator and records the
/// normalized numeric credentials so defaulting decisions are explicit.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalBinarySpec {
    pub version: u16,
    pub kind: SourceKind,
    pub install_path: String,
    pub arguments: Vec<String>,
    pub environment: Vec<String>,
    pub working_directory: String,
    pub uid: u32,
    pub gid: u32,
}

/// The normalized launch identity shared by both source forms.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchIdentity {
    pub executable: String,
    pub arguments: Vec<String>,
    pub environment: Vec<String>,
    pub working_directory: String,
    pub uid: u32,
    pub gid: u32,
}

fn validate_locator(field: &str, value: &str) -> io::Result<()> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must not be empty")));
    }
    if value.starts_with('/') {
        return Err(invalid(format!(
            "{field} must be relative to the workload specification"
        )));
    }
    if value.contains('\0') {
        return Err(invalid(format!("{field} contains a NUL byte")));
    }
    for component in value.split('/') {
        if component == ".." {
            return Err(invalid(format!(
                "{field} must not escape the workload specification directory"
            )));
        }
        if component.is_empty() {
            return Err(invalid(format!(
                "{field} must not contain an empty path component"
            )));
        }
    }
    Ok(())
}

pub fn parse_digest(value: &str) -> io::Result<String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(invalid(format!("unsupported digest {value:?}")));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(format!("malformed digest {value:?}")));
    }
    Ok(hex.to_ascii_lowercase())
}

pub fn normalize_arguments(values: &[String], field: &str) -> io::Result<Vec<String>> {
    if values.len() > MAX_ARGUMENTS {
        return Err(invalid(format!(
            "{field} must not contain more than {MAX_ARGUMENTS} entries"
        )));
    }
    for value in values {
        if value.len() > MAX_ARGUMENT_BYTES {
            return Err(invalid(format!(
                "an entry of {field} exceeds {MAX_ARGUMENT_BYTES} bytes"
            )));
        }
        if value.contains('\0') {
            return Err(invalid(format!("an entry of {field} contains a NUL byte")));
        }
    }
    Ok(values.to_vec())
}

/// Treat null or absence as empty, require bounded `NAME=VALUE` UTF-8 entries,
/// reject NUL and duplicate names, preserve order, and inherit nothing.
pub fn normalize_environment(values: &[String]) -> io::Result<Vec<String>> {
    if values.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(invalid(format!(
            "environment must not contain more than {MAX_ENVIRONMENT_ENTRIES} entries"
        )));
    }
    let mut total = 0;
    let mut seen: Vec<&str> = Vec::new();
    for entry in values {
        if entry.len() > MAX_ENVIRONMENT_ENTRY_BYTES {
            return Err(invalid(format!(
                "environment entry exceeds {MAX_ENVIRONMENT_ENTRY_BYTES} bytes"
            )));
        }
        total += entry.len();
        if total > MAX_ENVIRONMENT_BYTES {
            return Err(invalid(format!(
                "environment must not exceed {MAX_ENVIRONMENT_BYTES} bytes"
            )));
        }
        if entry.contains('\0') {
            return Err(invalid("environment entry contains a NUL byte"));
        }
        let Some((name, _)) = entry.split_once('=') else {
            return Err(invalid(format!(
                "environment entry {entry:?} is not NAME=VALUE"
            )));
        };
        if name.is_empty() {
            return Err(invalid(format!(
                "environment entry {entry:?} is not NAME=VALUE"
            )));
        }
        if seen.contains(&name) {
            return Err(invalid(format!("duplicate environment name {name:?}")));
        }
        seen.push(name);
    }
    Ok(values.to_vec())
}

/// Treat null, absence, or an empty string as the SimFerret default. Otherwise
/// require an explicit nonzero decimal `uid:gid` pair.
pub fn normalize_user(value: Option<&str>) -> io::Result<(u32, u32)> {
    match value {
        None | Some("") => parse_user(DEFAULT_USER),
        Some(value) => parse_user(value),
    }
}

/// Binary specifications require an explicit nonzero `uid:gid` pair.
pub fn normalize_required_user(value: &str) -> io::Result<(u32, u32)> {
    if value.is_empty() {
        return Err(invalid("user must be an explicit nonzero uid:gid pair"));
    }
    parse_user(value)
}

fn parse_user(value: &str) -> io::Result<(u32, u32)> {
    let mut parts = value.split(':');
    let (Some(uid), Some(gid), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(invalid(format!("unsupported user {value:?}")));
    };
    if uid.is_empty()
        || gid.is_empty()
        || !uid.bytes().all(|byte| byte.is_ascii_digit())
        || !gid.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid(format!(
            "user {value:?} is not a numeric uid:gid pair"
        )));
    }
    let uid: u32 = uid
        .parse()
        .map_err(|_| invalid(format!("user {value:?} is out of range")))?;
    let gid: u32 = gid
        .parse()
        .map_err(|_| invalid(format!("user {value:?} is out of range")))?;
    if uid == 0 || gid == 0 {
        return Err(invalid("root credentials are not supported"));
    }
    if uid == super::RESERVED_OWNER || gid == super::RESERVED_OWNER {
        return Err(invalid(format!(
            "user {value:?} uses the reserved owner identifier"
        )));
    }
    Ok((uid, gid))
}

/// Treat null, absence, or an empty string as `/`. Otherwise require an
/// absolute path that resolves to a directory inside the final workload root
/// without traversing a symbolic link.
pub fn normalize_working_directory(value: Option<&str>, tree: &Tree) -> io::Result<String> {
    let value = match value {
        None | Some("") => "/",
        Some(value) => value,
    };
    if !value.starts_with('/') {
        return Err(invalid(format!(
            "working directory {value:?} is not absolute"
        )));
    }
    let stripped = value.trim_matches('/');
    let relative = if stripped.is_empty() {
        ROOT_PATH.to_vec()
    } else {
        super::tree::normalize_layer_path(stripped.as_bytes())?
    };
    for ancestor in super::tree::ancestors(&relative)
        .into_iter()
        .chain([relative.clone()])
    {
        if let Some(entry) = tree.get(&ancestor)
            && entry.kind == super::tree::EntryKind::Symlink
        {
            return Err(invalid(format!(
                "working directory {value:?} traverses a symbolic link"
            )));
        }
    }
    if relative != ROOT_PATH
        && tree.get(&relative).map(|entry| entry.kind) != Some(super::tree::EntryKind::Directory)
    {
        return Err(invalid(format!(
            "working directory {value:?} is not a directory in the workload"
        )));
    }
    if relative == ROOT_PATH {
        Ok("/".into())
    } else {
        let text = std::str::from_utf8(&relative)
            .map_err(|_| invalid(format!("working directory {value:?} is not UTF-8")))?;
        Ok(format!("/{text}"))
    }
}
