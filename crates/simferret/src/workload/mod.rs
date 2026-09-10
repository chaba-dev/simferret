//! RFD 3 Phase 1: typed workload specification and canonical assembler.
//!
//! One standalone static binary or one local `linux/amd64` OCI image layout is
//! normalized into one content-addressed guest workload: a canonical filesystem
//! tree, an exact launch identity, a raw replay closure, and an encoded
//! immutable guest template. Everything is fixed before QEMU starts, and replay
//! re-derives the workload from verified raw objects without consulting a live
//! source, a registry, a container daemon, or a host mount.

mod oci;
mod root;
mod spec;
mod store;
mod tree;

use std::io;

pub use spec::{
    BINARY_INSTALL_PATH, BinarySource, LaunchIdentity, OciSource, SourceKind, WorkloadSource,
};
pub use store::{AssembledWorkload, LoadedWorkload};
pub use tree::{Entry, EntryKind, Tree};

pub(crate) use spec::WorkloadSpec;

/// Version of the TOML workload specification and of the retained canonical
/// binary specification.
pub const WORKLOAD_SPEC_VERSION: u16 = 1;
/// Version of the canonical filesystem serialization and identity.
pub const CANONICAL_FORMAT_VERSION: u16 = 1;
/// Version of the OCI descriptor, manifest, config, and layer extraction policy.
pub const EXTRACTION_POLICY_VERSION: u16 = 1;
/// Version of the whiteout, opaque, replacement, and link-application policy.
pub const LAYER_APPLICATION_POLICY_VERSION: u16 = 1;
/// Version of the encoded immutable guest template.
pub const TEMPLATE_FORMAT_VERSION: u16 = 1;
/// Version of the raw closure and derived lock records.
pub const CLOSURE_VERSION: u16 = 1;
/// Version of the derived cache lock record.
pub const DERIVED_LOCK_VERSION: u16 = 1;

/// The reserved guest path below which the workload root is assembled. The
/// PID-1 agent and its tools stay outside it.
pub const GUEST_WORKLOAD_ROOT: &str = "/workload";
/// The template root name, which is [`GUEST_WORKLOAD_ROOT`] without its leading
/// separator.
pub const GUEST_TEMPLATE_ROOT: &str = "workload";

pub const MAX_SPECIFICATION_BYTES: usize = 1 << 20;
pub const MAX_LAYOUT_BYTES: usize = 1 << 20;
pub const MAX_INDEX_BYTES: usize = 4 << 20;
pub const MAX_MANIFEST_BYTES: usize = 1 << 20;
pub const MAX_CONFIG_BYTES: usize = 1 << 20;
pub const MAX_LAYER_BYTES: usize = 64 << 20;
pub const MAX_EXPANDED_LAYER_BYTES: usize = 256 << 20;
pub const MAX_FILE_BYTES: usize = 16 << 20;
pub const MAX_ENTRIES: usize = 4096;
pub const MAX_LAYERS: usize = 16;
pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_SYMLINK_TARGET_BYTES: usize = 4096;
pub const MAX_SYMLINK_HOPS: usize = 40;
pub const MAX_RAW_OBJECTS: usize = 64;
pub const MAX_VIEW_ENTRIES: usize = 1 << 15;
pub const MAX_CACHE_METADATA_BYTES: usize = 4 << 20;
pub const MAX_ARGUMENTS: usize = 256;
pub const MAX_ARGUMENT_BYTES: usize = 4096;
pub const MAX_ENVIRONMENT_ENTRIES: usize = 256;
pub const MAX_ENVIRONMENT_ENTRY_BYTES: usize = 4096;
pub const MAX_ENVIRONMENT_BYTES: usize = 64 * 1024;
/// The encoded template may exceed its expanded file bytes by one bounded
/// `newc` header and path per canonical entry.
pub const MAX_TEMPLATE_BYTES: usize =
    MAX_EXPANDED_LAYER_BYTES + MAX_VIEW_ENTRIES * (MAX_PATH_BYTES + 128);

pub use store::{assemble, load};

/// Validate that an opened binary source is a little-endian x86-64 Linux ELF
/// executable with no interpreter program header, so no undeclared host or
/// guest library closure can affect execution.
pub(crate) fn validate_static_elf(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() < 64
        || &bytes[..4] != b"\x7fELF"
        || bytes[4] != 2
        || bytes[5] != 1
        || read_u16(bytes, 18)? != 62
    {
        return Err(invalid(
            "binary workload must be a little-endian x86-64 Linux ELF executable",
        ));
    }
    let table_offset =
        usize::try_from(read_u64(bytes, 32)?).map_err(|_| invalid("invalid ELF program table"))?;
    let entry_size = usize::from(read_u16(bytes, 54)?);
    let entry_count = usize::from(read_u16(bytes, 56)?);
    if entry_size < 4 {
        return Err(invalid("invalid ELF program header size"));
    }
    for index in 0..entry_count {
        let offset = table_offset
            .checked_add(
                index
                    .checked_mul(entry_size)
                    .ok_or_else(|| invalid("invalid ELF program table"))?,
            )
            .ok_or_else(|| invalid("invalid ELF program table"))?;
        if read_u32(bytes, offset)? == 3 {
            return Err(invalid(
                "binary workload must be statically linked; use an OCI source for a dynamic closure",
            ));
        }
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> io::Result<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| invalid("truncated ELF binary"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| invalid("truncated ELF binary"))?;
    Ok(u32::from_le_bytes(
        value.try_into().expect("four-byte slice"),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> io::Result<u64> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| invalid("truncated ELF binary"))?;
    Ok(u64::from_le_bytes(
        value.try_into().expect("eight-byte slice"),
    ))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
