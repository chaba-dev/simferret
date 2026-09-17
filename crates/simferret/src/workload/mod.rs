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
    validate_launch_identity,
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

/// `(uid_t)-1` and `(gid_t)-1` mean "leave unchanged" to the guest's ownership
/// syscalls, so they can never be a reproducible owner or launch credential.
pub const RESERVED_OWNER: u32 = u32::MAX;

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

/// The runtime overlay directories the guest runtime replaces with fresh
/// metadata and content.
const OVERLAY_TMP: &[u8] = b"tmp";
const OVERLAY_DEV: &[u8] = b"dev";

/// Reject a canonical tree whose package entries collide with the runtime
/// overlay, or whose launch paths the overlay replacement would invalidate.
///
/// The guest runtime copies a template into a fresh root while skipping the
/// `/tmp` and `/dev` subtrees, then synthesizes both directories itself. An entry
/// at either path must therefore be a directory, nothing below them survives, and
/// no launch path may depend on it. Enforcing this during assembly means a
/// template the runtime would refuse is never published, and replay re-derives
/// the same decision from the raw closure instead of reaching the runtime
/// boundary with a template it will reject.
pub fn validate_overlay_compatibility(tree: &Tree, launch: &LaunchIdentity) -> io::Result<()> {
    let below_or_at = |path: &[u8]| {
        path == OVERLAY_TMP
            || path == OVERLAY_DEV
            || path.starts_with(b"tmp/")
            || path.starts_with(b"dev/")
    };
    for (path, entry) in tree.iter() {
        if below_or_at(path) && entry.kind != EntryKind::Directory {
            return Err(invalid(format!(
                "workload entry {:?} collides with the runtime overlay",
                String::from_utf8_lossy(path)
            )));
        }
    }
    let executable = launch.executable.trim_start_matches('/');
    if below_or_at(executable.as_bytes()) {
        return Err(invalid(
            "the workload executable is replaced by the runtime overlay",
        ));
    }
    let working_directory = launch.working_directory.trim_start_matches('/');
    if working_directory.starts_with("tmp/") || working_directory.starts_with("dev/") {
        return Err(invalid(
            "the workload working directory does not survive the runtime overlay",
        ));
    }
    Ok(())
}

/// The native little-endian x86-64 program-header size the guest loader requires.
const NATIVE_PROGRAM_HEADER_BYTES: usize = 56;
/// The largest program table the guest loader accepts.
const MAX_PROGRAM_TABLE_BYTES: usize = 65_536;
/// The guest's mapping granularity, which fixes the required relation between a
/// loadable segment's file offset and its virtual address.
const GUEST_PAGE_BYTES: u64 = 4096;
/// The guest's user address-space limit. The pinned guest CPU model does not
/// expose five-level paging, so the four-level limit of `(1 << 47) - 4096`
/// applies at runtime.
const MAX_GUEST_USER_ADDRESS: u64 = 0x0000_7fff_ffff_f000;
/// The lowest address the guest maps for a fixed-address executable. The pinned
/// guest kernel keeps its default minimum mapping address, and the workload runs
/// without `CAP_SYS_RAWIO`, so a lower fixed mapping is refused.
const MIN_GUEST_MAPPING_ADDRESS: u64 = 65_536;

/// Validate that an opened binary source is a little-endian x86-64 Linux ELF
/// executable with no interpreter program header, so no undeclared host or
/// guest library closure can affect execution.
///
/// The binary profile accepts only a fixed-address (`ET_EXEC`) image. A relocated
/// image's load base, entry address, and mapping alignment are chosen by the
/// guest loader at exec time, so assembly cannot establish that it would load;
/// a static PIE is refused with that diagnostic and can be packaged as an OCI
/// source instead.
///
/// Every field read is bounds-checked, and the program table and each loadable
/// segment are required to lie inside the file, so a crafted header cannot
/// panic or describe a segment the guest could not map.
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
    let elf_type = read_u16(bytes, 16)?;
    if elf_type != 2 {
        return Err(invalid(
            "binary workload must be a fixed-address executable ELF file, not a relocatable, core, or static-PIE image",
        ));
    }
    let table_offset =
        usize::try_from(read_u64(bytes, 32)?).map_err(|_| invalid("invalid ELF program table"))?;
    let entry_size = usize::from(read_u16(bytes, 54)?);
    let entry_count = usize::from(read_u16(bytes, 56)?);
    // The guest loader accepts only the native program-header size and only a
    // program table no larger than 64 KiB, so a file it would refuse to execute
    // is refused here instead of being published as a runnable workload.
    if entry_size != NATIVE_PROGRAM_HEADER_BYTES {
        return Err(invalid("invalid ELF program header size"));
    }
    if entry_count > MAX_PROGRAM_TABLE_BYTES / NATIVE_PROGRAM_HEADER_BYTES {
        return Err(invalid("ELF program table exceeds the loader limit"));
    }
    let table_end = table_offset
        .checked_add(
            entry_size
                .checked_mul(entry_count)
                .ok_or_else(|| invalid("invalid ELF program table"))?,
        )
        .ok_or_else(|| invalid("invalid ELF program table"))?;
    if table_end > bytes.len() {
        return Err(invalid("ELF program table extends past the file"));
    }
    // The guest rejects an entry address at or above its user address-space
    // limit, and a fixed-address image enters exactly where it declares.
    if read_u64(bytes, 24)? >= MAX_GUEST_USER_ADDRESS {
        return Err(invalid(
            "ELF entry point is outside the guest user address space",
        ));
    }
    let mut loadable = 0;
    for index in 0..entry_count {
        let offset = table_offset
            .checked_add(
                index
                    .checked_mul(entry_size)
                    .ok_or_else(|| invalid("invalid ELF program table"))?,
            )
            .ok_or_else(|| invalid("invalid ELF program table"))?;
        match read_u32(bytes, offset)? {
            1 => {
                loadable += 1;
                let file_offset = read_u64(bytes, offset + 8)?;
                let address = read_u64(bytes, offset + 16)?;
                let file_size = read_u64(bytes, offset + 32)?;
                let memory_size = read_u64(bytes, offset + 40)?;
                if file_size > memory_size {
                    return Err(invalid(
                        "ELF loadable segment is larger in the file than in memory",
                    ));
                }
                let segment_end = file_offset
                    .checked_add(file_size)
                    .ok_or_else(|| invalid("invalid ELF loadable segment"))?;
                if segment_end > bytes.len() as u64 {
                    return Err(invalid("ELF loadable segment extends past the file"));
                }
                // The guest maps a file-backed segment at
                // `address - (address % page)` from `file_offset - (address %
                // page)`, so the two must share a page offset or the mapping
                // fails after the process image has already been replaced.
                if file_size != 0 && file_offset % GUEST_PAGE_BYTES != address % GUEST_PAGE_BYTES {
                    return Err(invalid(
                        "ELF loadable segment file offset and address are not page-congruent",
                    ));
                }
                let address_end = address
                    .checked_add(memory_size)
                    .ok_or_else(|| invalid("invalid ELF loadable segment"))?;
                // A segment's exclusive end may equal the limit; only a larger
                // one is refused.
                if address >= MAX_GUEST_USER_ADDRESS || address_end > MAX_GUEST_USER_ADDRESS {
                    return Err(invalid(
                        "ELF loadable segment is outside the guest user address space",
                    ));
                }
                // A fixed-address mapping below the guest's minimum mapping
                // address is refused. A segment with no memory content requests
                // no mapping at all, so it is exempt.
                if memory_size != 0 {
                    let page_start = address & !(GUEST_PAGE_BYTES - 1);
                    if page_start < MIN_GUEST_MAPPING_ADDRESS {
                        return Err(invalid(
                            "ELF fixed-address segment is below the guest minimum mapping address",
                        ));
                    }
                }
            }
            3 => {
                return Err(invalid(
                    "binary workload must be statically linked; use an OCI source for a dynamic closure",
                ));
            }
            _ => {}
        }
    }
    if loadable == 0 {
        return Err(invalid("binary workload has no loadable segment"));
    }
    Ok(())
}

fn read_exact(bytes: &[u8], offset: usize, length: usize) -> io::Result<&[u8]> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| invalid("truncated ELF binary"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| invalid("truncated ELF binary"))
}

fn read_u16(bytes: &[u8], offset: usize) -> io::Result<u16> {
    let value = read_exact(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    let value = read_exact(bytes, offset, 4)?;
    Ok(u32::from_le_bytes(
        value.try_into().expect("four-byte slice"),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> io::Result<u64> {
    let value = read_exact(bytes, offset, 8)?;
    Ok(u64::from_le_bytes(
        value.try_into().expect("eight-byte slice"),
    ))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch(executable: &str, working_directory: &str) -> LaunchIdentity {
        LaunchIdentity {
            executable: executable.into(),
            arguments: vec![executable.into()],
            environment: Vec::new(),
            working_directory: working_directory.into(),
            uid: 65534,
            gid: 65534,
        }
    }

    #[test]
    fn a_malformed_specification_never_quotes_the_environment() {
        // A TOML type error can quote the offending value, and an environment
        // value is a secret, so the diagnostic must not carry it.
        let source = b"version = 1\nkind = \"binary\"\npath = \"app\"\nargs = []\nenv = [\"SECRET=classification-marker\", 17]\nworking_directory = \"/\"\nuser = \"65534:65534\"\n";
        let error = WorkloadSpec::parse(source).unwrap_err();
        assert!(
            !error.to_string().contains("classification-marker"),
            "{error}"
        );

        // A syntax error must still name its location without the document text.
        let syntax = b"version = 1\nkind = \"binary\n";
        let error = WorkloadSpec::parse(syntax).unwrap_err();
        assert!(error.to_string().contains("byte offset"), "{error}");
    }

    #[test]
    fn overlay_collisions_are_refused_during_assembly() {
        let mut tree = Tree::new();
        tree.insert_default_directory(b".");
        tree.insert_default_directory(b"tmp");
        tree.insert_default_directory(b"dev");
        assert!(validate_overlay_compatibility(&tree, &launch("/bin/app", "/")).is_ok());

        let mut file_at_tmp = tree.clone();
        file_at_tmp.insert(b"tmp".to_vec(), Entry::file(b"x".to_vec(), 0o644, 0, 0, 0));
        assert!(validate_overlay_compatibility(&file_at_tmp, &launch("/bin/app", "/")).is_err());

        let mut file_below_dev = tree.clone();
        file_below_dev.insert(
            b"dev/null".to_vec(),
            Entry::file(b"x".to_vec(), 0o644, 0, 0, 0),
        );
        assert!(validate_overlay_compatibility(&file_below_dev, &launch("/bin/app", "/")).is_err());

        let mut link_below_tmp = tree;
        link_below_tmp.insert(
            b"tmp/link".to_vec(),
            Entry::symlink(b"/etc/passwd".to_vec(), 0, 0, 0),
        );
        assert!(validate_overlay_compatibility(&link_below_tmp, &launch("/bin/app", "/")).is_err());
    }

    #[test]
    fn launch_paths_the_overlay_invalidates_are_refused_during_assembly() {
        let mut tree = Tree::new();
        tree.insert_default_directory(b".");
        tree.insert_default_directory(b"tmp");
        // A working directory of `/tmp` is recreated by the overlay.
        assert!(validate_overlay_compatibility(&tree, &launch("/bin/app", "/tmp")).is_ok());
        // Nothing below it survives.
        assert!(validate_overlay_compatibility(&tree, &launch("/bin/app", "/tmp/work")).is_err());
        assert!(validate_overlay_compatibility(&tree, &launch("/tmp/app", "/")).is_err());
        assert!(validate_overlay_compatibility(&tree, &launch("/dev/app", "/")).is_err());
    }
}
