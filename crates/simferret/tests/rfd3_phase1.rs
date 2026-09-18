//! RFD 3 Phase 1 acceptance: the typed workload specification and canonical
//! assembler.
//!
//! The suite builds standalone binary and local OCI image-layout sources,
//! assembles them into content-addressed stores, and verifies the canonical
//! tree, launch identity, raw closure, and derived cache entry. It also covers
//! the Phase 1 rejection requirements: unsupported OCI constructs, unsafe
//! links, expansion and entry bounds, tampered or missing raw and derived
//! content, and concurrent publication.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use simferret::workload::{Entry, EntryKind, Tree, assemble, load};

const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const PLAIN_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";
const GZIP_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const INSTALL_PATH: &str = "/bin/simferret-workload";

static COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(data) {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[derive(Clone, Copy)]
struct ProgramHeader {
    p_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;

fn payload_offset(header_count: usize) -> u64 {
    (64 + 56 * header_count) as u64
}

/// A loadable segment whose virtual address shares a page offset with its file
/// offset, as the guest loader requires.
fn load_segment(header_count: usize, payload_len: usize) -> ProgramHeader {
    ProgramHeader {
        p_type: PT_LOAD,
        flags: 5,
        offset: payload_offset(header_count),
        vaddr: 0x40_0000 + payload_offset(header_count),
        filesz: payload_len as u64,
        memsz: payload_len as u64,
        align: 0x1000,
    }
}

fn interp_segment() -> ProgramHeader {
    ProgramHeader {
        p_type: PT_INTERP,
        flags: 4,
        offset: 0,
        vaddr: 0,
        filesz: 0,
        memsz: 0,
        align: 1,
    }
}

fn null_segment() -> ProgramHeader {
    ProgramHeader {
        p_type: 0,
        flags: 0,
        offset: 0,
        vaddr: 0,
        filesz: 0,
        memsz: 0,
        align: 0,
    }
}

/// A loadable segment that requests no mapping at all.
fn noop_segment(vaddr: u64) -> ProgramHeader {
    ProgramHeader {
        p_type: PT_LOAD,
        flags: 0,
        offset: 0,
        vaddr,
        filesz: 0,
        memsz: 0,
        align: 0x1000,
    }
}

/// Build a structurally valid little-endian x86-64 ELF image.
fn elf_with(elf_type: u16, headers: &[ProgramHeader], payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0_u8; 64];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&elf_type.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&(headers.len() as u16).to_le_bytes());
    // A fixed-address executable enters at its first loadable segment.
    let entry = headers
        .iter()
        .find(|header| header.p_type == PT_LOAD)
        .map_or(0, |header| header.vaddr);
    bytes[24..32].copy_from_slice(&entry.to_le_bytes());
    for header in headers {
        let mut encoded = [0_u8; 56];
        encoded[0..4].copy_from_slice(&header.p_type.to_le_bytes());
        encoded[4..8].copy_from_slice(&header.flags.to_le_bytes());
        encoded[8..16].copy_from_slice(&header.offset.to_le_bytes());
        encoded[16..24].copy_from_slice(&header.vaddr.to_le_bytes());
        encoded[32..40].copy_from_slice(&header.filesz.to_le_bytes());
        encoded[40..48].copy_from_slice(&header.memsz.to_le_bytes());
        encoded[48..56].copy_from_slice(&header.align.to_le_bytes());
        bytes.extend_from_slice(&encoded);
    }
    bytes.extend_from_slice(payload);
    bytes
}

fn static_elf() -> Vec<u8> {
    let payload = vec![0x90_u8; 64];
    elf_with(2, &[load_segment(1, payload.len())], &payload)
}

fn dynamic_elf() -> Vec<u8> {
    let payload = vec![0x90_u8; 64];
    elf_with(
        2,
        &[interp_segment(), load_segment(2, payload.len())],
        &payload,
    )
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "simferret-rfd3-{label}-{}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn join(&self, name: impl AsRef<Path>) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MemberKind {
    Directory,
    File,
    Symlink,
    HardLink,
    CharacterDevice,
    PaxHeader,
    GnuLongName,
}

#[derive(Clone)]
struct Member {
    name: String,
    kind: MemberKind,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u32,
    data: Vec<u8>,
    target: String,
}

fn directory(name: &str) -> Member {
    Member {
        name: name.into(),
        kind: MemberKind::Directory,
        mode: 0o755,
        uid: 0,
        gid: 0,
        mtime: 0,
        data: Vec::new(),
        target: String::new(),
    }
}

fn file(name: &str, data: &[u8]) -> Member {
    file_with(name, data, 0o644, 0, 0, 0)
}

fn file_with(name: &str, data: &[u8], mode: u32, uid: u32, gid: u32, mtime: u32) -> Member {
    Member {
        name: name.into(),
        kind: MemberKind::File,
        mode,
        uid,
        gid,
        mtime,
        data: data.to_vec(),
        target: String::new(),
    }
}

fn symlink(name: &str, target: &str) -> Member {
    Member {
        name: name.into(),
        kind: MemberKind::Symlink,
        mode: 0o777,
        uid: 0,
        gid: 0,
        mtime: 0,
        data: Vec::new(),
        target: target.into(),
    }
}

fn hard_link(name: &str, target: &str) -> Member {
    Member {
        name: name.into(),
        kind: MemberKind::HardLink,
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
        data: Vec::new(),
        target: target.into(),
    }
}

fn character_device(name: &str) -> Member {
    Member {
        name: name.into(),
        kind: MemberKind::CharacterDevice,
        mode: 0o666,
        uid: 0,
        gid: 0,
        mtime: 0,
        data: Vec::new(),
        target: String::new(),
    }
}

fn pax_header(name: &str) -> Member {
    Member {
        name: name.into(),
        kind: MemberKind::PaxHeader,
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
        data: b"30 mtime=1700000000.5\n".to_vec(),
        target: String::new(),
    }
}

fn gnu_long_name(name: &str) -> Member {
    Member {
        name: name.into(),
        kind: MemberKind::GnuLongName,
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
        data: {
            let mut data = name.as_bytes().to_vec();
            data.push(0);
            data
        },
        target: String::new(),
    }
}

fn tar_bytes(members: &[Member]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for member in members {
        let mut header = tar::Header::new_ustar();
        header.set_mode(member.mode);
        header.set_uid(u64::from(member.uid));
        header.set_gid(u64::from(member.gid));
        header.set_mtime(u64::from(member.mtime));
        let escapes = member.name.starts_with('/')
            || member.name.split('/').any(|component| component == "..");
        let set_path = |header: &mut tar::Header| {
            if escapes {
                header.set_path_absolute(&member.name).unwrap();
            } else {
                header.set_path(&member.name).unwrap();
            }
        };
        match member.kind {
            MemberKind::Directory => {
                header.set_entry_type(tar::EntryType::Directory);
                set_path(&mut header);
                header.set_size(0);
                header.set_cksum();
                builder.append(&header, std::io::empty()).unwrap();
            }
            MemberKind::File => {
                header.set_entry_type(tar::EntryType::Regular);
                set_path(&mut header);
                header.set_size(member.data.len() as u64);
                header.set_cksum();
                builder.append(&header, member.data.as_slice()).unwrap();
            }
            MemberKind::Symlink => {
                header.set_entry_type(tar::EntryType::Symlink);
                set_path(&mut header);
                header.set_link_name(&member.target).unwrap();
                header.set_size(0);
                header.set_cksum();
                builder.append(&header, std::io::empty()).unwrap();
            }
            MemberKind::HardLink => {
                header.set_entry_type(tar::EntryType::Link);
                set_path(&mut header);
                header.set_link_name(&member.target).unwrap();
                header.set_size(0);
                header.set_cksum();
                builder.append(&header, std::io::empty()).unwrap();
            }
            MemberKind::CharacterDevice => {
                header.set_entry_type(tar::EntryType::Char);
                set_path(&mut header);
                header.set_size(0);
                header.set_cksum();
                builder.append(&header, std::io::empty()).unwrap();
            }
            MemberKind::PaxHeader => {
                header.set_entry_type(tar::EntryType::XHeader);
                set_path(&mut header);
                header.set_size(member.data.len() as u64);
                header.set_cksum();
                builder.append(&header, member.data.as_slice()).unwrap();
            }
            MemberKind::GnuLongName => {
                header.set_entry_type(tar::EntryType::GNULongName);
                header.set_path("././@LongLink").unwrap();
                header.set_size(member.data.len() as u64);
                header.set_cksum();
                builder.append(&header, member.data.as_slice()).unwrap();
            }
        }
    }
    builder.finish().unwrap();
    builder.into_inner().unwrap()
}

struct Layer {
    members: Vec<Member>,
    compressed: bool,
    media_type: Option<String>,
    raw: Option<Vec<u8>>,
    stored: Option<Vec<u8>>,
}

impl Layer {
    fn bytes(&self) -> Vec<u8> {
        match &self.raw {
            Some(raw) => raw.clone(),
            None => tar_bytes(&self.members),
        }
    }
}

fn plain_layer(members: Vec<Member>) -> Layer {
    Layer {
        members,
        compressed: false,
        media_type: None,
        raw: None,
        stored: None,
    }
}

fn gzip_layer(members: Vec<Member>) -> Layer {
    Layer {
        members,
        compressed: true,
        media_type: None,
        raw: None,
        stored: None,
    }
}

fn raw_layer(raw: Vec<u8>) -> Layer {
    Layer {
        members: Vec::new(),
        compressed: false,
        media_type: None,
        raw: Some(raw),
        stored: None,
    }
}

/// A layer whose stored blob is supplied already gzip-compressed, used to prove
/// the expansion bound is enforced before the stream is parsed.
fn stored_gzip_layer(stored: Vec<u8>) -> Layer {
    Layer {
        members: Vec::new(),
        compressed: true,
        media_type: None,
        raw: None,
        stored: Some(stored),
    }
}

fn layer_with_media_type(members: Vec<Member>, media_type: &str) -> Layer {
    Layer {
        members,
        compressed: false,
        media_type: Some(media_type.into()),
        raw: None,
        stored: None,
    }
}

/// A physical USTAR entry the `tar` crate's builder refuses to write, used to
/// prove that the parser rejects unsafe paths itself.
fn raw_tar_entry(name: &[u8], data: &[u8]) -> Vec<u8> {
    raw_tar_member(name, b'0', b"", data)
}

/// A physical USTAR entry with an explicit type byte and link name.
fn raw_tar_member(name: &[u8], typeflag: u8, link_name: &[u8], data: &[u8]) -> Vec<u8> {
    assert!(name.len() <= 100);
    assert!(link_name.len() <= 100);
    let mut block = [0_u8; 512];
    block[..name.len()].copy_from_slice(name);
    block[100..108].copy_from_slice(b"0000755\0");
    block[108..116].copy_from_slice(b"0000000\0");
    block[116..124].copy_from_slice(b"0000000\0");
    block[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
    block[136..148].copy_from_slice(b"00000000000\0");
    block[148..156].copy_from_slice(b"        ");
    block[156] = typeflag;
    block[157..157 + link_name.len()].copy_from_slice(link_name);
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    let sum: u32 = block.iter().map(|byte| u32::from(*byte)).sum();
    block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut output = block.to_vec();
    output.extend_from_slice(data);
    while !output.len().is_multiple_of(512) {
        output.push(0);
    }
    output.extend_from_slice(&[0_u8; 1024]);
    output
}

fn default_config() -> Value {
    json!({
        "config": {
            "Entrypoint": [INSTALL_PATH],
            "User": "1000:1000",
            "WorkingDir": "/",
        }
    })
}

fn canonical_json(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn store_blob(blobs: &Path, data: &[u8]) -> (String, usize) {
    let hex = sha256_hex(data);
    fs::write(blobs.join(&hex), data).unwrap();
    (format!("sha256:{hex}"), data.len())
}

type Mutator = Box<dyn FnOnce(&mut Value, &mut Value, &mut Value)>;
type IndexEdit = (&'static str, fn(&Path));
type StoreMutation = (&'static str, fn(&Path, &str));

fn write_layout(
    directory: &Path,
    layers: &[Layer],
    config: Value,
    platform: Option<Value>,
    mutate: Option<Mutator>,
) -> String {
    let blobs = directory.join("blobs/sha256");
    fs::create_dir_all(&blobs).unwrap();
    let mut stored_layers = Vec::new();
    let mut diff_ids = Vec::new();
    for layer in layers {
        let raw = layer.bytes();
        let stored = match &layer.stored {
            Some(stored) => stored.clone(),
            None if layer.compressed => {
                let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(&raw).unwrap();
                encoder.finish().unwrap()
            }
            None => raw.clone(),
        };
        let media_type = layer.media_type.clone().unwrap_or_else(|| {
            if layer.compressed {
                GZIP_LAYER_MEDIA_TYPE.into()
            } else {
                PLAIN_LAYER_MEDIA_TYPE.into()
            }
        });
        let (digest, size) = store_blob(&blobs, &stored);
        stored_layers.push(json!({
            "mediaType": media_type,
            "digest": digest,
            "size": size,
        }));
        diff_ids.push(format!("sha256:{}", sha256_hex(&raw)));
    }

    let mut config = config;
    config["architecture"] = json!("amd64");
    config["os"] = json!("linux");
    config["rootfs"] = json!({"type": "layers", "diff_ids": diff_ids});
    let mut manifest = json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "config": {},
        "layers": stored_layers,
    });
    let mut index = json!({
        "schemaVersion": 2,
        "manifests": [{
            "mediaType": MANIFEST_MEDIA_TYPE,
            "digest": "",
            "size": 0,
            "platform": platform.unwrap_or_else(|| json!({"architecture": "amd64", "os": "linux"})),
        }],
    });
    if let Some(mutate) = mutate {
        mutate(&mut config, &mut manifest, &mut index);
    }

    let config_bytes = canonical_json(&config);
    let (config_digest, config_size) = store_blob(&blobs, &config_bytes);
    manifest["config"] = json!({
        "mediaType": CONFIG_MEDIA_TYPE,
        "digest": config_digest,
        "size": config_size,
    });
    let manifest_bytes = canonical_json(&manifest);
    let (manifest_digest, manifest_size) = store_blob(&blobs, &manifest_bytes);
    index["manifests"][0]["digest"] = json!(manifest_digest);
    index["manifests"][0]["size"] = json!(manifest_size);
    fs::write(directory.join("index.json"), canonical_json(&index)).unwrap();
    fs::write(
        directory.join("oci-layout"),
        canonical_json(&json!({"imageLayoutVersion": "1.0.0"})),
    )
    .unwrap();
    manifest_digest
}

fn edit_index(directory: &Path, edit: impl FnOnce(&mut Value)) {
    let path = directory.join("index.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    edit(&mut value);
    fs::write(&path, canonical_json(&value)).unwrap();
}

fn write_spec(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
}

fn binary_spec(path: &str, user: &str) -> String {
    format!(
        "version = 1\nkind = \"binary\"\npath = \"{path}\"\nargs = []\nenv = []\nworking_directory = \"/\"\nuser = \"{user}\"\n"
    )
}

fn oci_spec(layout: &str, digest: &str) -> String {
    format!("version = 1\nkind = \"oci\"\nlayout = \"{layout}\"\nmanifest_digest = \"{digest}\"\n")
}

fn fixture_layer(binary: &[u8]) -> Vec<Member> {
    vec![
        directory("bin"),
        file_with("bin/simferret-workload", binary, 0o755, 1000, 1000, 0),
    ]
}

fn entry<'a>(tree: &'a Tree, path: &str) -> &'a Entry {
    tree.get(path.as_bytes())
        .unwrap_or_else(|| panic!("missing canonical path {path:?}"))
}

// ---------------------------------------------------------------------------
// Binary sources
// ---------------------------------------------------------------------------

#[test]
fn binary_workload_round_trips() {
    let temp = TempDir::new("binary-round-trip");
    let binary = static_elf();
    fs::write(temp.join("fixture"), &binary).unwrap();
    write_spec(
        &temp.join("workload.toml"),
        &binary_spec("fixture", "1000:1000"),
    );

    let store = temp.join("store");
    let assembled = assemble(&temp.join("workload.toml"), &store).unwrap();
    assert_eq!(assembled.entries, 3);
    assert_eq!(assembled.expanded_bytes, binary.len());
    assert_eq!(assembled.raw_objects, 2);
    assert_eq!(assembled.launch.executable, INSTALL_PATH);
    assert_eq!(assembled.launch.arguments, vec![INSTALL_PATH.to_string()]);
    assert_eq!(assembled.launch.working_directory, "/");
    assert_eq!((assembled.launch.uid, assembled.launch.gid), (1000, 1000));

    let loaded = load(&store).unwrap();
    assert_eq!(loaded.closure_sha256, assembled.closure_sha256);
    assert_eq!(loaded.canonical_digest, assembled.canonical_digest);
    assert_eq!(loaded.launch, assembled.launch);
    assert_eq!(entry(&loaded.tree, ".").kind, EntryKind::Directory);
    assert_eq!(entry(&loaded.tree, "bin").kind, EntryKind::Directory);
    let installed = entry(&loaded.tree, "bin/simferret-workload");
    assert_eq!(installed.kind, EntryKind::File);
    assert_eq!(installed.mode, 0o755);
    assert_eq!(
        (installed.uid, installed.gid, installed.mtime),
        (1000, 1000, 0)
    );
    assert_eq!(installed.data.as_deref(), Some(binary.as_slice()));

    // The template is a pure function of the canonical tree, so re-assembling
    // into a second store reproduces both identities byte for byte.
    let second = temp.join("second-store");
    let reassembled = assemble(&temp.join("workload.toml"), &second).unwrap();
    assert_eq!(reassembled.canonical_digest, assembled.canonical_digest);
    assert_eq!(reassembled.closure_sha256, assembled.closure_sha256);
    assert_eq!(reassembled.template_sha256, assembled.template_sha256);
    assert_eq!(
        fs::read(second.join("raw/closure.json")).unwrap(),
        fs::read(store.join("raw/closure.json")).unwrap()
    );
}

#[test]
fn binary_and_oci_sources_converge_before_the_runtime_boundary() {
    let temp = TempDir::new("converge");
    let binary = static_elf();
    fs::write(temp.join("fixture"), &binary).unwrap();
    write_spec(
        &temp.join("workload.toml"),
        &binary_spec("fixture", "1000:1000"),
    );

    let layout = temp.join("layout");
    let digest = write_layout(
        &layout,
        &[plain_layer(fixture_layer(&binary))],
        default_config(),
        None,
        None,
    );
    write_spec(&temp.join("oci.toml"), &oci_spec("layout", &digest));

    let binary_store = temp.join("binary-store");
    let oci_store = temp.join("oci-store");
    let binary_result = assemble(&temp.join("workload.toml"), &binary_store).unwrap();
    let oci_result = assemble(&temp.join("oci.toml"), &oci_store).unwrap();

    assert_eq!(binary_result.canonical_digest, oci_result.canonical_digest);
    assert_eq!(binary_result.template_sha256, oci_result.template_sha256);
    assert_eq!(binary_result.launch, oci_result.launch);
    // The source identities stay distinct: an OCI source carries layer evidence
    // and a manifest digest that a binary source does not.
    assert_ne!(binary_result.closure_sha256, oci_result.closure_sha256);
}

// ---------------------------------------------------------------------------
// OCI sources and layer semantics
// ---------------------------------------------------------------------------

fn semantics_base_layer(binary: &[u8]) -> Vec<Member> {
    vec![
        directory("bin"),
        file_with("bin/simferret-workload", binary, 0o755, 1000, 1000, 0),
        file_with("etc/config", b"base\n", 0o644, 0, 0, 1700000001),
        file_with("etc/remove-me", b"base-remove\n", 0o644, 0, 0, 1700000001),
        file_with("etc/pure-delete", b"base-pure\n", 0o644, 0, 0, 1700000001),
        file_with("etc/swap", b"base-swap\n", 0o644, 0, 0, 1700000001),
        symlink("links/current", "../bin/simferret-workload"),
        file_with("opt/keep", b"keep\n", 0o644, 0, 0, 1700000001),
        file_with("opt/drop", b"drop\n", 0o644, 0, 0, 1700000001),
        file_with("opt/nested/child", b"child\n", 0o644, 0, 0, 1700000001),
        file_with("srv/opaque/lower", b"lower\n", 0o644, 0, 0, 1700000001),
    ]
}

fn semantics_upper_layer() -> Vec<Member> {
    vec![
        Member {
            mode: 0o750,
            uid: 2000,
            gid: 2000,
            mtime: 1700000003,
            ..directory("etc")
        },
        file_with("etc/config", b"upper\n", 0o640, 1000, 1000, 1700000002),
        file_with(
            "etc/remove-me",
            b"upper-remove\n",
            0o600,
            1000,
            1000,
            1700000002,
        ),
        // Every marker below appears after the additions it coexists with, so an
        // implementation that applied markers in archive order would delete
        // same-layer additions and change the asserted tree.
        file("etc/.wh.remove-me", b""),
        file("etc/.wh.pure-delete", b""),
        file("etc/.wh.absent", b""),
        Member {
            mode: 0o755,
            uid: 1000,
            gid: 1000,
            mtime: 1700000005,
            ..directory("etc/swap")
        },
        file("etc/swap/.wh..wh..opq", b""),
        file_with("etc/swap/new", b"swap-new\n", 0o644, 1000, 1000, 1700000005),
        file("opt/new", b"new\n"),
        file("opt/.wh..wh..opq", b""),
        Member {
            mode: 0o750,
            uid: 1000,
            gid: 1000,
            mtime: 1700000000,
            ..directory("var/log")
        },
        file_with(
            "var/log/upper",
            b"upper-log\n",
            0o640,
            1000,
            1000,
            1700000004,
        ),
        symlink("links/latest", "current"),
    ]
}

#[test]
fn layer_semantics_are_order_independent_and_legally_replace_lower_entries() {
    let temp = TempDir::new("semantics");
    let binary = static_elf();
    let layout = temp.join("layout");
    let digest = write_layout(
        &layout,
        &[
            plain_layer(semantics_base_layer(&binary)),
            plain_layer(semantics_upper_layer()),
        ],
        default_config(),
        None,
        None,
    );
    write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));

    let store = temp.join("store");
    let assembled = assemble(&temp.join("workload.toml"), &store).unwrap();
    assert_eq!(assembled.entries, 19);
    let loaded = load(&store).unwrap();
    let tree = &loaded.tree;

    let etc = entry(tree, "etc");
    assert_eq!(
        (etc.mode, etc.uid, etc.gid, etc.mtime),
        (0o750, 2000, 2000, 1700000003)
    );
    let config = entry(tree, "etc/config");
    assert_eq!(config.data.as_deref(), Some(b"upper\n".as_slice()));
    assert_eq!(
        (config.mode, config.uid, config.mtime),
        (0o640, 1000, 1700000002)
    );
    // A whiteout removes only the lower-layer entry, so the same-layer addition
    // survives regardless of archive order.
    assert_eq!(
        entry(tree, "etc/remove-me").data.as_deref(),
        Some(b"upper-remove\n".as_slice())
    );
    // A whiteout with no same-layer addition removes its lower entry.
    assert!(tree.get(b"etc/pure-delete").is_none());
    // A lower file can be replaced by an opaque directory; the marker precedes
    // its own addition in the archive.
    assert_eq!(entry(tree, "etc/swap").kind, EntryKind::Directory);
    assert_eq!(
        entry(tree, "etc/swap/new").data.as_deref(),
        Some(b"swap-new\n".as_slice())
    );
    // The opaque marker appears after `opt/new`, so an in-order implementation
    // would have deleted it.
    assert!(tree.get(b"opt/keep").is_none());
    assert!(tree.get(b"opt/drop").is_none());
    assert!(tree.get(b"opt/nested").is_none());
    assert_eq!(
        entry(tree, "opt/new").data.as_deref(),
        Some(b"new\n".as_slice())
    );
    // An unrelated opaque marker leaves `srv/opaque/lower` alone.
    assert!(tree.get(b"srv/opaque/lower").is_some());
    assert_eq!(
        entry(tree, "links/current").target.as_deref(),
        Some(b"../bin/simferret-workload".as_slice())
    );
    assert_eq!(
        entry(tree, "links/latest").target.as_deref(),
        Some(b"current".as_slice())
    );
    assert_eq!(entry(tree, "var/log/upper").mode, 0o640);
    assert!(tree.get(b"etc/.wh.remove-me").is_none());
    assert!(tree.get(b"opt/.wh..wh..opq").is_none());
}

#[test]
fn root_level_opacity_keeps_only_upper_layer_additions() {
    let temp = TempDir::new("root-opacity");
    let binary = static_elf();
    let base = vec![
        directory("bin"),
        file_with(
            "bin/simferret-workload",
            binary.as_slice(),
            0o755,
            1000,
            1000,
            0,
        ),
        file("keep/lower", b"lower\n"),
        file("drop", b"drop\n"),
        file("dir/child", b"child\n"),
    ];
    let upper = vec![
        directory("bin"),
        file_with(
            "bin/simferret-workload",
            binary.as_slice(),
            0o755,
            1000,
            1000,
            0,
        ),
        file("keep/upper", b"upper\n"),
        file(".wh..wh..opq", b""),
    ];
    let layout = temp.join("layout");
    let digest = write_layout(
        &layout,
        &[plain_layer(base), plain_layer(upper)],
        default_config(),
        None,
        None,
    );
    write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));

    let store = temp.join("store");
    assemble(&temp.join("workload.toml"), &store).unwrap();
    let loaded = load(&store).unwrap();
    let paths: Vec<String> = loaded
        .tree
        .iter()
        .map(|(path, _)| String::from_utf8_lossy(path).into_owned())
        .collect();
    assert_eq!(
        paths,
        vec![".", "bin", "bin/simferret-workload", "keep", "keep/upper"]
    );
}

#[test]
fn dynamically_linked_oci_closure_assembles_from_in_image_files() {
    let temp = TempDir::new("dynamic");
    let binary = static_elf();
    let loader = b"\x7fELFloader".to_vec();
    let library = b"\x7fELFlibrary".to_vec();
    let layer = vec![
        directory("bin"),
        file_with(
            "bin/simferret-workload",
            binary.as_slice(),
            0o755,
            1000,
            1000,
            0,
        ),
        directory("lib"),
        file_with("lib/libc.so.6", &library, 0o755, 0, 0, 0),
        directory("lib64"),
        file_with("lib64/ld-linux-x86-64.so.2", &loader, 0o755, 0, 0, 0),
    ];
    let layout = temp.join("layout");
    let digest = write_layout(&layout, &[gzip_layer(layer)], default_config(), None, None);
    write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
    let store = temp.join("store");
    assemble(&temp.join("workload.toml"), &store).unwrap();
    let loaded = load(&store).unwrap();
    assert_eq!(
        entry(&loaded.tree, "lib64/ld-linux-x86-64.so.2")
            .data
            .as_deref(),
        Some(loader.as_slice())
    );
    assert_eq!(
        entry(&loaded.tree, "lib/libc.so.6").data.as_deref(),
        Some(library.as_slice())
    );
}

// ---------------------------------------------------------------------------
// Rejections
// ---------------------------------------------------------------------------

fn unsupported_layout(name: &str, root: &Path, binary: &[u8]) -> String {
    let fixture = fixture_layer(binary);
    match name {
        "absolute-path" => write_layout(
            root,
            &[plain_layer(vec![file("/etc/passwd", b"x")])],
            default_config(),
            None,
            None,
        ),
        "escaping-path" => write_layout(
            root,
            &[raw_layer(raw_tar_entry(b"../escape", b"x"))],
            default_config(),
            None,
            None,
        ),
        "hard-link" => write_layout(
            root,
            &[plain_layer(
                fixture
                    .iter()
                    .cloned()
                    .chain([hard_link("bin/second", "bin/simferret-workload")])
                    .collect(),
            )],
            default_config(),
            None,
            None,
        ),
        "setuid-mode" => write_layout(
            root,
            &[plain_layer(vec![
                directory("bin"),
                file_with("bin/simferret-workload", binary, 0o4755, 1000, 1000, 0),
            ])],
            default_config(),
            None,
            None,
        ),
        "device-node" => write_layout(
            root,
            &[plain_layer(
                fixture
                    .iter()
                    .cloned()
                    .chain([character_device("dev/null")])
                    .collect(),
            )],
            default_config(),
            None,
            None,
        ),
        "duplicate-path" => write_layout(
            root,
            &[plain_layer(
                fixture
                    .iter()
                    .cloned()
                    .chain([file("bin/simferret-workload", b"duplicate")])
                    .collect(),
            )],
            default_config(),
            None,
            None,
        ),
        "pax-extended-metadata" => write_layout(
            root,
            &[plain_layer(
                fixture
                    .iter()
                    .cloned()
                    .chain([pax_header("PaxHeaders.0/x")])
                    .collect(),
            )],
            default_config(),
            None,
            None,
        ),
        "gnu-long-name" => write_layout(
            root,
            &[plain_layer(
                fixture
                    .iter()
                    .cloned()
                    .chain([gnu_long_name("a/very/long/name")])
                    .collect(),
            )],
            default_config(),
            None,
            None,
        ),
        "symlink-traversal" => write_layout(
            root,
            &[
                plain_layer(
                    fixture
                        .iter()
                        .cloned()
                        .chain([symlink("redirect", "elsewhere")])
                        .collect(),
                ),
                plain_layer(vec![file("redirect/file", b"x")]),
            ],
            default_config(),
            None,
            None,
        ),
        "unsupported-media-type" => write_layout(
            root,
            &[layer_with_media_type(
                fixture.clone(),
                "application/vnd.oci.image.layer.v1.tar+zstd",
            )],
            default_config(),
            None,
            None,
        ),
        "wrong-platform" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            default_config(),
            Some(json!({"architecture": "amd64", "os": "darwin"})),
            None,
        ),
        "diffid-mismatch" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            default_config(),
            None,
            Some(Box::new(|config, _, _| {
                config["rootfs"]["diff_ids"][0] = json!("sha256:".to_owned() + &"0".repeat(64));
            })),
        ),
        "rootfs-type" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            default_config(),
            None,
            Some(Box::new(|config, _, _| {
                config["rootfs"]["type"] = json!("squashfs");
            })),
        ),
        "nonempty-whiteout" => write_layout(
            root,
            &[
                plain_layer(
                    fixture
                        .iter()
                        .cloned()
                        .chain([file("victim", b"v")])
                        .collect(),
                ),
                plain_layer(vec![file(".wh.victim", b"not empty\n")]),
            ],
            default_config(),
            None,
            None,
        ),
        "marker-through-symlink" => write_layout(
            root,
            &[
                plain_layer(
                    fixture
                        .iter()
                        .cloned()
                        .chain([symlink("redirect", "elsewhere")])
                        .collect(),
                ),
                plain_layer(vec![file("redirect/.wh.victim", b"")]),
            ],
            default_config(),
            None,
            None,
        ),
        "chained-symlink-escape" => write_layout(
            root,
            &[plain_layer(
                fixture
                    .iter()
                    .cloned()
                    .chain([symlink("a", "."), symlink("b", "a/../outside")])
                    .collect(),
            )],
            default_config(),
            None,
            None,
        ),
        "whiteout-not-basename" => write_layout(
            root,
            &[plain_layer(
                fixture
                    .iter()
                    .cloned()
                    .chain([file(".wh.a/b", b"")])
                    .collect(),
            )],
            default_config(),
            None,
            None,
        ),
        "volumes" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            json!({"config": {"Entrypoint": [INSTALL_PATH], "User": "1000:1000", "Volumes": {"/data": {}}}}),
            None,
            None,
        ),
        "stop-signal" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            json!({"config": {"Entrypoint": [INSTALL_PATH], "User": "1000:1000", "StopSignal": "SIGTERM"}}),
            None,
            None,
        ),
        "args-escaped" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            json!({"config": {"Entrypoint": [INSTALL_PATH], "User": "1000:1000", "ArgsEscaped": true}}),
            None,
            None,
        ),
        "entrypoint-wrong-type" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            json!({"config": {"Entrypoint": false, "Cmd": [INSTALL_PATH], "User": "1000:1000"}}),
            None,
            None,
        ),
        "cmd-wrong-type" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            json!({"config": {"Entrypoint": [INSTALL_PATH], "Cmd": {}, "User": "1000:1000"}}),
            None,
            None,
        ),
        "volumes-wrong-type" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            json!({"config": {"Entrypoint": [INSTALL_PATH], "User": "1000:1000", "Volumes": false}}),
            None,
            None,
        ),
        "stop-signal-wrong-type" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            json!({"config": {"Entrypoint": [INSTALL_PATH], "User": "1000:1000", "StopSignal": {}}}),
            None,
            None,
        ),
        "args-escaped-wrong-type" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            json!({"config": {"Entrypoint": [INSTALL_PATH], "User": "1000:1000", "ArgsEscaped": []}}),
            None,
            None,
        ),
        "root-user" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            json!({"config": {"Entrypoint": [INSTALL_PATH], "User": "0:0"}}),
            None,
            None,
        ),
        "named-user" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            json!({"config": {"Entrypoint": [INSTALL_PATH], "User": "nobody"}}),
            None,
            None,
        ),
        "duplicate-environment" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            json!({"config": {"Entrypoint": [INSTALL_PATH], "User": "1000:1000", "Env": ["A=1", "A=2"]}}),
            None,
            None,
        ),
        "relative-entrypoint" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            json!({"config": {"Entrypoint": ["bin/simferret-workload"], "User": "1000:1000"}}),
            None,
            None,
        ),
        "missing-executable" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            json!({"config": {"Entrypoint": ["/bin/absent"], "User": "1000:1000"}}),
            None,
            None,
        ),
        "non-executable-mode" => write_layout(
            root,
            &[plain_layer(vec![
                directory("bin"),
                file_with("bin/simferret-workload", binary, 0o644, 1000, 1000, 0),
            ])],
            default_config(),
            None,
            None,
        ),
        "relative-working-directory" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            json!({"config": {"Entrypoint": [INSTALL_PATH], "User": "1000:1000", "WorkingDir": "etc"}}),
            None,
            None,
        ),
        "missing-working-directory" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            json!({"config": {"Entrypoint": [INSTALL_PATH], "User": "1000:1000", "WorkingDir": "/absent"}}),
            None,
            None,
        ),
        "wrong-config-platform" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            default_config(),
            None,
            Some(Box::new(|config, _, _| {
                config["architecture"] = json!("arm64");
            })),
        ),
        "config-variant" => write_layout(
            root,
            &[plain_layer(fixture.clone())],
            default_config(),
            None,
            Some(Box::new(|config, _, _| {
                config["variant"] = json!("v8");
            })),
        ),
        "no-layers" => write_layout(root, &[], default_config(), None, None),
        other => panic!("unknown unsupported layout {other}"),
    }
}

const UNSUPPORTED: &[&str] = &[
    "absolute-path",
    "escaping-path",
    "hard-link",
    "setuid-mode",
    "device-node",
    "duplicate-path",
    "pax-extended-metadata",
    "gnu-long-name",
    "symlink-traversal",
    "unsupported-media-type",
    "wrong-platform",
    "diffid-mismatch",
    "rootfs-type",
    "nonempty-whiteout",
    "marker-through-symlink",
    "chained-symlink-escape",
    "whiteout-not-basename",
    "volumes",
    "stop-signal",
    "args-escaped",
    "entrypoint-wrong-type",
    "cmd-wrong-type",
    "volumes-wrong-type",
    "stop-signal-wrong-type",
    "args-escaped-wrong-type",
    "root-user",
    "named-user",
    "duplicate-environment",
    "relative-entrypoint",
    "missing-executable",
    "non-executable-mode",
    "relative-working-directory",
    "missing-working-directory",
    "wrong-config-platform",
    "config-variant",
    "no-layers",
];

#[test]
fn unsupported_oci_constructs_are_rejected_before_publication() {
    let binary = static_elf();
    for name in UNSUPPORTED {
        let temp = TempDir::new(name);
        let layout = temp.join("layout");
        let digest = unsupported_layout(name, &layout, &binary);
        write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
        let store = temp.join("store");
        let error = assemble(&temp.join("workload.toml"), &store)
            .err()
            .unwrap_or_else(|| panic!("{name} was accepted"));
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidInput,
            "{name}: {error}"
        );
        assert!(
            !store.join("derived").exists(),
            "{name} published a derived entry"
        );
        assert!(
            !store.join("raw/closure.json").exists(),
            "{name} published a raw closure"
        );
    }
}

#[test]
fn a_metadata_only_member_with_a_data_record_is_rejected() {
    // USTAR records no data for a directory or a symbolic link, and the raw
    // iterator advances by the declared size, so a nonzero size would silently
    // skip physical bytes instead of failing.
    let binary = static_elf();
    let cases: &[(&str, u8, &[u8])] = &[
        ("symlink", b'2', b"bin/simferret-workload"),
        ("directory", b'5', b""),
    ];
    for (name, typeflag, link_name) in cases {
        let temp = TempDir::new(name);
        let mut layer = tar_bytes(&fixture_layer(&binary));
        // Replace the builder's end-of-archive marker with the malformed member.
        layer.truncate(layer.len() - 1024);
        layer.extend_from_slice(&raw_tar_member(name.as_bytes(), *typeflag, link_name, b"x"));
        let layout = temp.join("layout");
        let digest = write_layout(&layout, &[raw_layer(layer)], default_config(), None, None);
        write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
        let error = assemble(&temp.join("workload.toml"), &temp.join("store"))
            .expect_err("a metadata-only member with a data record was accepted");
        assert!(
            error.to_string().contains("nonzero size"),
            "{name}: {error}"
        );
    }
}

#[test]
fn a_layer_without_a_valid_end_of_archive_marker_is_rejected() {
    // The raw iterator stops at the first zero block or at end of input, so a
    // truncated archive, or one with a member hidden behind a single zero block,
    // must be refused by the terminator check instead of being parsed as a
    // shorter valid archive.
    let binary = static_elf();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("missing-terminator", {
            let mut layer = tar_bytes(&fixture_layer(&binary));
            layer.truncate(layer.len() - 1024);
            layer
        }),
        ("single-zero-block", {
            let mut layer = tar_bytes(&fixture_layer(&binary));
            layer.truncate(layer.len() - 1024);
            layer.extend_from_slice(&[0_u8; 512]);
            layer.extend_from_slice(&raw_tar_member(b"hidden", b'5', b"", b"x"));
            layer
        }),
    ];
    for (name, layer) in cases {
        let temp = TempDir::new(name);
        let layout = temp.join("layout");
        let digest = write_layout(&layout, &[raw_layer(layer)], default_config(), None, None);
        write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
        let store = temp.join("store");
        let error = assemble(&temp.join("workload.toml"), &store)
            .expect_err("a layer without a valid end-of-archive marker was accepted");
        assert!(
            error.to_string().contains("end-of-archive marker"),
            "{name}: {error}"
        );
        assert!(
            !store.join("raw/closure.json").exists(),
            "{name} published a raw closure"
        );
    }
}

#[test]
fn descriptor_selection_rejects_ambiguous_platform_less_and_remote_content() {
    let binary = static_elf();
    let cases: &[IndexEdit] = &[
        ("ambiguous", |directory| {
            edit_index(directory, |index| {
                let duplicate = index["manifests"][0].clone();
                index["manifests"].as_array_mut().unwrap().push(duplicate);
            });
        }),
        ("platform-less", |directory| {
            edit_index(directory, |index| {
                index["manifests"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("platform");
            });
        }),
        ("nested-index", |directory| {
            edit_index(directory, |index| {
                index["manifests"][0]["mediaType"] =
                    json!("application/vnd.oci.image.index.v1+json");
            });
        }),
        ("descriptor-urls", |directory| {
            edit_index(directory, |index| {
                index["manifests"][0]["urls"] = json!(["https://example.invalid/blob"]);
            });
        }),
        ("descriptor-data", |directory| {
            edit_index(directory, |index| {
                index["manifests"][0]["data"] = json!("aGVsbG8=");
            });
        }),
        ("platform-variant", |directory| {
            edit_index(directory, |index| {
                index["manifests"][0]["platform"]["variant"] = json!("v8");
            });
        }),
    ];
    for (name, edit) in cases {
        let temp = TempDir::new(name);
        let layout = temp.join("layout");
        let digest = write_layout(
            &layout,
            &[plain_layer(fixture_layer(&binary))],
            default_config(),
            None,
            None,
        );
        edit(&layout);
        write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
        let error = assemble(&temp.join("workload.toml"), &temp.join("store"))
            .err()
            .unwrap_or_else(|| panic!("{name} was accepted"));
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidInput,
            "{name}: {error}"
        );
    }
}

#[test]
fn unrelated_index_entries_and_blobs_are_ignored() {
    let temp = TempDir::new("unrelated");
    let binary = static_elf();
    let layout = temp.join("layout");
    let digest = write_layout(
        &layout,
        &[plain_layer(fixture_layer(&binary))],
        default_config(),
        None,
        None,
    );
    edit_index(&layout, |index| {
        index["manifests"].as_array_mut().unwrap().push(json!({
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "digest": "sha256:".to_owned() + &"a".repeat(64),
            "size": 12,
            "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"},
            "urls": ["https://example.invalid/absent"],
            "annotations": {"note": "ignored"},
        }));
    });
    fs::write(layout.join("unrelated.txt"), b"ignored").unwrap();
    write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
    let store = temp.join("store");
    assemble(&temp.join("workload.toml"), &store).unwrap();
    let loaded = load(&store).unwrap();
    assert_eq!(entry(&loaded.tree, "bin/simferret-workload").mode, 0o755);
}

#[test]
fn corrupt_or_missing_selected_blobs_are_rejected() {
    for (name, missing) in [("corrupt-blob", false), ("missing-blob", true)] {
        let temp = TempDir::new(name);
        let binary = static_elf();
        let layout = temp.join("layout");
        let digest = write_layout(
            &layout,
            &[plain_layer(fixture_layer(&binary))],
            default_config(),
            None,
            None,
        );
        let manifest: Value = serde_json::from_slice(
            &fs::read(layout.join(format!("blobs/sha256/{}", &digest[7..]))).unwrap(),
        )
        .unwrap();
        let layer_hex = manifest["layers"][0]["digest"].as_str().unwrap()[7..].to_owned();
        let layer = layout.join("blobs/sha256").join(&layer_hex);
        if missing {
            fs::remove_file(&layer).unwrap();
        } else {
            let mut data = fs::read(&layer).unwrap();
            let index = data.len() / 2;
            data[index] ^= 0xff;
            fs::write(&layer, data).unwrap();
        }
        write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
        let error = assemble(&temp.join("workload.toml"), &temp.join("store"))
            .err()
            .unwrap_or_else(|| panic!("{name} was accepted"));
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidInput,
            "{name}: {error}"
        );
    }
}

#[test]
fn unsupported_binary_inputs_are_rejected() {
    let payload = vec![0x90_u8; 64];
    let mut relocatable = elf_with(1, &[load_segment(1, payload.len())], &payload);
    relocatable[16..18].copy_from_slice(&1_u16.to_le_bytes());
    let no_loadable = elf_with(2, &[], &payload);
    let mut huge_table = elf_with(2, &[load_segment(1, payload.len())], &payload);
    huge_table[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    huge_table[56..58].copy_from_slice(&1_u16.to_le_bytes());
    let mut segment_past_file = elf_with(2, &[load_segment(1, payload.len())], &payload);
    let file_len = segment_past_file.len() as u64;
    segment_past_file[64 + 8..64 + 16].copy_from_slice(&file_len.to_le_bytes());
    segment_past_file[64 + 16..64 + 24].copy_from_slice(&(0x40_0000 + file_len).to_le_bytes());
    segment_past_file[64 + 32..64 + 40].copy_from_slice(&1_u64.to_le_bytes());
    segment_past_file[64 + 40..64 + 48].copy_from_slice(&1_u64.to_le_bytes());
    let mut segment_offset_overflow = elf_with(2, &[load_segment(1, payload.len())], &payload);
    let overflow_offset = u64::MAX - 8;
    segment_offset_overflow[64 + 8..64 + 16].copy_from_slice(&overflow_offset.to_le_bytes());
    segment_offset_overflow[64 + 16..64 + 24]
        .copy_from_slice(&(0x40_0000 + overflow_offset % 4096).to_le_bytes());
    segment_offset_overflow[64 + 32..64 + 40].copy_from_slice(&16_u64.to_le_bytes());
    segment_offset_overflow[64 + 40..64 + 48].copy_from_slice(&16_u64.to_le_bytes());
    let mut misaligned_segment = elf_with(2, &[load_segment(1, payload.len())], &payload);
    misaligned_segment[64 + 16..64 + 24].copy_from_slice(&0x40_0000_u64.to_le_bytes());
    let mut segment_outside_address_space =
        elf_with(2, &[load_segment(1, payload.len())], &payload);
    segment_outside_address_space[64 + 40..64 + 48]
        .copy_from_slice(&0x8000_0000_0000_0000_u64.to_le_bytes());
    let mut entry_outside_address_space = elf_with(2, &[load_segment(1, payload.len())], &payload);
    entry_outside_address_space[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
    let mut below_minimum_mapping = elf_with(2, &[load_segment(1, payload.len())], &payload);
    below_minimum_mapping[64 + 16..64 + 24].copy_from_slice(&0x78_u64.to_le_bytes());
    below_minimum_mapping[24..32].copy_from_slice(&0x78_u64.to_le_bytes());
    let mut tiny_header = elf_with(2, &[load_segment(1, payload.len())], &payload);
    tiny_header[54..56].copy_from_slice(&8_u16.to_le_bytes());
    let mut wrong_header_size = elf_with(2, &[load_segment(1, payload.len())], &payload);
    wrong_header_size[54..56].copy_from_slice(&57_u16.to_le_bytes());
    // 1,171 entries of 56 bytes is a 65,576-byte table, past the loader limit.
    let mut oversized_table = vec![load_segment(1171, payload.len())];
    oversized_table.extend((0..1170).map(|_| null_segment()));
    let oversized_table = elf_with(2, &oversized_table, &payload);
    let mut wrong_architecture = static_elf();
    wrong_architecture[18..20].copy_from_slice(&40_u16.to_le_bytes());
    let mut wrong_endianness = static_elf();
    wrong_endianness[5] = 2;
    let mut oversized = static_elf();
    oversized.resize((16 << 20) + 1, 0);

    let cases: &[(&str, Vec<u8>)] = &[
        ("dynamic", dynamic_elf()),
        ("malformed", b"not an elf".to_vec()),
        ("wrong-architecture", wrong_architecture),
        ("wrong-endianness", wrong_endianness),
        ("relocatable", relocatable),
        ("no-loadable-segment", no_loadable),
        ("program-table-past-file", huge_table),
        ("loadable-segment-past-file", segment_past_file),
        ("loadable-segment-offset-overflow", segment_offset_overflow),
        ("misaligned-loadable-segment", misaligned_segment),
        (
            "loadable-segment-outside-address-space",
            segment_outside_address_space,
        ),
        ("entry-outside-address-space", entry_outside_address_space),
        ("fixed-segment-below-minimum-mapping", below_minimum_mapping),
        ("tiny-program-header", tiny_header),
        ("wrong-program-header-size", wrong_header_size),
        ("oversized-program-table", oversized_table),
        ("oversized", oversized),
    ];
    for (name, bytes) in cases {
        let temp = TempDir::new(name);
        fs::write(temp.join("fixture"), bytes).unwrap();
        write_spec(
            &temp.join("workload.toml"),
            &binary_spec("fixture", "1000:1000"),
        );
        let error = assemble(&temp.join("workload.toml"), &temp.join("store"))
            .err()
            .unwrap_or_else(|| panic!("{name} was accepted"));
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidInput,
            "{name}: {error}"
        );
    }

    // A symbolic link source is rejected rather than followed, and a source
    // outside the specification directory is never opened.
    let temp = TempDir::new("binary-links");
    fs::write(temp.join("fixture"), static_elf()).unwrap();
    std::os::unix::fs::symlink(temp.join("fixture"), temp.join("link")).unwrap();
    write_spec(
        &temp.join("workload.toml"),
        &binary_spec("link", "1000:1000"),
    );
    assert!(
        assemble(&temp.join("workload.toml"), &temp.join("store")).is_err(),
        "a symbolic link source was accepted"
    );
    write_spec(
        &temp.join("workload.toml"),
        "version = 1\nkind = \"binary\"\npath = \"../escape\"\nargs = []\nenv = []\nworking_directory = \"/\"\nuser = \"1000:1000\"\n",
    );
    assert!(
        assemble(&temp.join("workload.toml"), &temp.join("store")).is_err(),
        "an escaping source was accepted"
    );
}

#[test]
fn elf_address_space_boundaries_are_enforced_exactly() {
    // The guest accepts a segment whose exclusive end equals its user
    // address-space limit and refuses one page more; it accepts a fixed-address
    // mapping exactly at its minimum mapping address; and it exempts a
    // fixed-address load that requests no mapping at all.
    const LIMIT: u64 = 0x0000_7fff_ffff_f000;
    const MINIMUM: u64 = 65_536;
    let payload = vec![0x90_u8; 4096];

    let segment = |vaddr: u64, filesz: u64, memsz: u64| {
        let mut segment = load_segment(1, payload.len());
        segment.offset = 0;
        segment.vaddr = vaddr;
        segment.filesz = filesz;
        segment.memsz = memsz;
        segment
    };
    let length = payload.len() as u64;
    let accepted = [
        (
            "segment-end-at-limit",
            elf_with(2, &[segment(LIMIT - length, length, length)], &payload),
        ),
        (
            "segment-at-minimum-mapping-address",
            elf_with(2, &[segment(MINIMUM, length, length)], &payload),
        ),
        (
            // A segment with no memory content requests no mapping, so it is
            // not subject to the fixed-address minimum.
            "fixed-address-no-op-load-below-minimum",
            elf_with(
                2,
                &[load_segment(2, payload.len()), noop_segment(0x1000)],
                &payload,
            ),
        ),
    ];
    for (name, binary) in accepted {
        let temp = TempDir::new(name);
        fs::write(temp.join("fixture"), &binary).unwrap();
        write_spec(
            &temp.join("workload.toml"),
            &binary_spec("fixture", "1000:1000"),
        );
        assemble(&temp.join("workload.toml"), &temp.join("store"))
            .unwrap_or_else(|error| panic!("{name} was rejected: {error}"));
    }

    let temp = TempDir::new("segment-end-past-limit");
    let binary = elf_with(2, &[segment(LIMIT - length, length, length * 2)], &payload);
    fs::write(temp.join("fixture"), &binary).unwrap();
    write_spec(
        &temp.join("workload.toml"),
        &binary_spec("fixture", "1000:1000"),
    );
    let error = assemble(&temp.join("workload.toml"), &temp.join("store"))
        .expect_err("a segment past the user address-space limit was accepted");
    assert!(error.to_string().contains("address space"), "{error}");
}

#[test]
fn a_relocated_binary_is_refused_with_a_profile_diagnostic() {
    // The standalone binary profile is fixed-address only, because a relocated
    // image's load base, entry, and mapping alignment are chosen by the guest
    // loader at exec time.
    let temp = TempDir::new("static-pie-binary");
    let payload = vec![0x90_u8; 64];
    let binary = elf_with(3, &[load_segment(1, payload.len())], &payload);
    fs::write(temp.join("fixture"), &binary).unwrap();
    write_spec(
        &temp.join("workload.toml"),
        &binary_spec("fixture", "1000:1000"),
    );
    let store = temp.join("store");
    let error = assemble(&temp.join("workload.toml"), &store)
        .expect_err("a relocated binary source was accepted");
    assert!(error.to_string().contains("static-PIE"), "{error}");
    assert!(
        !store.join("raw/closure.json").exists(),
        "a refused binary source published a raw closure"
    );
}

#[test]
fn the_same_relocated_executable_is_accepted_from_an_oci_source() {
    // The fixed-address restriction belongs to the binary source alone. An OCI
    // layer may carry a relocated executable, and assembly and replay leave
    // loading to the guest.
    let temp = TempDir::new("static-pie-oci");
    let payload = vec![0x90_u8; 64];
    let binary = elf_with(3, &[load_segment(1, payload.len())], &payload);
    let layout = temp.join("layout");
    let digest = write_layout(
        &layout,
        &[plain_layer(vec![
            directory("bin"),
            file_with("bin/simferret-workload", &binary, 0o755, 1000, 1000, 0),
        ])],
        default_config(),
        None,
        None,
    );
    write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
    let store = temp.join("store");
    let assembled = assemble(&temp.join("workload.toml"), &store).unwrap();
    let loaded = load(&store).unwrap();
    assert_eq!(loaded.closure_sha256, assembled.closure_sha256);
    assert_eq!(entry(&loaded.tree, "bin/simferret-workload").mode, 0o755);
}

#[test]
fn a_program_table_at_the_loader_limit_is_accepted() {
    // 1,170 entries of 56 bytes is exactly the 65,520-byte table the guest
    // loader accepts, so the limit must not reject the boundary itself.
    let temp = TempDir::new("program-table-limit");
    let payload = vec![0x90_u8; 64];
    let mut headers = vec![load_segment(1170, payload.len())];
    headers.extend((0..1169).map(|_| null_segment()));
    let binary = elf_with(2, &headers, &payload);
    fs::write(temp.join("fixture"), &binary).unwrap();
    write_spec(
        &temp.join("workload.toml"),
        &binary_spec("fixture", "1000:1000"),
    );
    let assembled = assemble(&temp.join("workload.toml"), &temp.join("store")).unwrap();
    assert_eq!(assembled.entries, 3);
}

#[test]
fn oversized_inputs_are_rejected_by_their_bounds() {
    let temp = TempDir::new("oversized");
    // A file entry larger than the per-file bound is refused before any output
    // exists, even though the layer is gzip-compressed.
    let layout = temp.join("layout");
    let digest = write_layout(
        &layout,
        &[gzip_layer(vec![
            directory("bin"),
            file_with(
                "bin/simferret-workload",
                &static_elf(),
                0o755,
                1000,
                1000,
                0,
            ),
            file_with(
                "data/oversized",
                &vec![0_u8; (16 << 20) + 1],
                0o644,
                0,
                0,
                0,
            ),
        ])],
        default_config(),
        None,
        None,
    );
    write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
    let store = temp.join("store");
    let error =
        assemble(&temp.join("workload.toml"), &store).expect_err("an oversized file was accepted");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{error}");
    assert!(!store.join("derived").exists());
}

// ---------------------------------------------------------------------------
// Identity, tampering, and the content cache
// ---------------------------------------------------------------------------

fn assemble_fixture(temp: &TempDir) -> (PathBuf, String) {
    let binary = static_elf();
    fs::write(temp.join("fixture"), &binary).unwrap();
    write_spec(
        &temp.join("workload.toml"),
        &binary_spec("fixture", "1000:1000"),
    );
    let store = temp.join("store");
    let assembled = assemble(&temp.join("workload.toml"), &store).unwrap();
    (store, assembled.closure_sha256)
}

#[test]
fn every_launch_identity_class_changes_the_closure() {
    let temp = TempDir::new("launch-identity");
    let binary = static_elf();
    fs::write(temp.join("fixture"), &binary).unwrap();
    let baseline = binary_spec("fixture", "1000:1000");
    let variants: &[(&str, &str)] = &[
        (
            "arguments",
            "version = 1\nkind = \"binary\"\npath = \"fixture\"\nargs = [\"--listen\"]\nenv = []\nworking_directory = \"/\"\nuser = \"1000:1000\"\n",
        ),
        (
            "environment",
            "version = 1\nkind = \"binary\"\npath = \"fixture\"\nargs = []\nenv = [\"MODE=acceptance\"]\nworking_directory = \"/\"\nuser = \"1000:1000\"\n",
        ),
        (
            "working-directory",
            "version = 1\nkind = \"binary\"\npath = \"fixture\"\nargs = []\nenv = []\nworking_directory = \"/bin\"\nuser = \"1000:1000\"\n",
        ),
        (
            "credentials",
            "version = 1\nkind = \"binary\"\npath = \"fixture\"\nargs = []\nenv = []\nworking_directory = \"/\"\nuser = \"2000:2000\"\n",
        ),
    ];
    let baseline_spec = temp.join("baseline.toml");
    write_spec(&baseline_spec, &baseline);
    let baseline_store = temp.join("baseline-store");
    let baseline_result = assemble(&baseline_spec, &baseline_store).unwrap();
    for (name, spec) in variants {
        let spec_path = temp.join(format!("{name}.toml"));
        write_spec(&spec_path, spec);
        let result = assemble(&spec_path, &temp.join(format!("{name}-store"))).unwrap();
        assert_ne!(
            result.closure_sha256, baseline_result.closure_sha256,
            "{name} did not change the workload identity"
        );
        // Arguments and environment do not change the canonical filesystem
        // tree, while numeric credentials do because a binary workload installs
        // its executable with the declared owner.
        if *name == "credentials" {
            assert_ne!(result.canonical_digest, baseline_result.canonical_digest);
        } else {
            assert_eq!(result.canonical_digest, baseline_result.canonical_digest);
        }
    }
}

#[test]
fn tampered_raw_or_derived_content_is_rejected() {
    let temp = TempDir::new("tampering");
    let (store, closure_sha256) = assemble_fixture(&temp);
    let loaded = load(&store).unwrap();
    let canonical = loaded.canonical_digest.clone();
    drop(loaded);
    assert_eq!(closure_sha256.len(), 64);

    let mutations: &[StoreMutation] = &[
        ("raw-executable", |store, _| {
            let mut objects: Vec<PathBuf> = fs::read_dir(store.join("raw/sha256"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            objects.sort();
            let mut data = fs::read(&objects[0]).unwrap();
            data[0] ^= 0xff;
            fs::write(&objects[0], data).unwrap();
        }),
        ("raw-missing", |store, _| {
            let mut objects: Vec<PathBuf> = fs::read_dir(store.join("raw/sha256"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            objects.sort();
            fs::remove_file(&objects[0]).unwrap();
        }),
        ("closure-launch", |store, _| {
            let path = store.join("raw/closure.json");
            let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            value["launch"]["uid"] = json!(4321);
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        }),
        ("closure-unknown-field", |store, _| {
            let path = store.join("raw/closure.json");
            let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            value["extra"] = json!(1);
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        }),
        ("derived-tree", |store, canonical| {
            let path = store.join(format!("derived/{canonical}/tree.bin"));
            let mut data = fs::read(&path).unwrap();
            data[0] ^= 0xff;
            fs::write(&path, data).unwrap();
        }),
        ("derived-template", |store, canonical| {
            let path = store.join(format!("derived/{canonical}/template.cpio"));
            let mut data = fs::read(&path).unwrap();
            data[0] ^= 0xff;
            fs::write(&path, data).unwrap();
        }),
        ("derived-lock", |store, canonical| {
            let path = store.join(format!("derived/{canonical}/lock.json"));
            let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            value["closure_sha256"] = json!("0".repeat(64));
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        }),
        ("derived-missing-template", |store, canonical| {
            fs::remove_file(store.join(format!("derived/{canonical}/template.cpio"))).unwrap();
        }),
        ("derived-missing-tree", |store, canonical| {
            fs::remove_file(store.join(format!("derived/{canonical}/tree.bin"))).unwrap();
        }),
    ];
    for (name, mutate) in mutations {
        let copy = TempDir::new(name);
        copy_store(&store, &copy.join("store"));
        mutate(&copy.join("store"), &canonical);
        let error = load(&copy.join("store"))
            .err()
            .unwrap_or_else(|| panic!("{name} was accepted"));
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidInput,
            "{name}: {error}"
        );
    }
}

#[test]
fn a_changed_manifest_and_layer_under_the_old_digest_is_rejected() {
    let temp = TempDir::new("self-consistent");
    let binary = static_elf();
    let layout = temp.join("layout");
    let digest = write_layout(
        &layout,
        &[plain_layer(fixture_layer(&binary))],
        default_config(),
        None,
        None,
    );
    write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
    let store = temp.join("store");
    assemble(&temp.join("workload.toml"), &store).unwrap();

    // Replace the stored layer with different content under its new digest and
    // point the manifest at it, leaving the config DiffID and closure record
    // unchanged. The closure names the old manifest, so verification must fail.
    let blobs = store.join("raw/sha256");
    let manifest_path = blobs.join(&digest[7..]);
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let replacement = tar_bytes(&[directory("bin")]);
    let replacement_hex = sha256_hex(&replacement);
    fs::write(blobs.join(&replacement_hex), &replacement).unwrap();
    manifest["layers"][0]["digest"] = json!(format!("sha256:{replacement_hex}"));
    manifest["layers"][0]["size"] = json!(replacement.len());
    fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert!(load(&store).is_err());
}

#[test]
fn missing_raw_content_fails_even_with_a_valid_derived_entry() {
    let temp = TempDir::new("raw-required");
    let (store, _) = assemble_fixture(&temp);
    let canonical = load(&store).unwrap().canonical_digest.clone();
    assert!(store.join(format!("derived/{canonical}/tree.bin")).exists());
    fs::remove_dir_all(store.join("raw/sha256")).unwrap();
    let error = load(&store).expect_err("a derived entry alone was accepted");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{error}");
}

#[test]
fn a_store_reuses_identical_content_and_rejects_a_different_closure() {
    let temp = TempDir::new("store-reuse");
    let binary = static_elf();
    fs::write(temp.join("fixture"), &binary).unwrap();
    write_spec(
        &temp.join("workload.toml"),
        &binary_spec("fixture", "1000:1000"),
    );
    let store = temp.join("store");
    let first = assemble(&temp.join("workload.toml"), &store).unwrap();
    let second = assemble(&temp.join("workload.toml"), &store).unwrap();
    assert_eq!(first.closure_sha256, second.closure_sha256);
    assert_eq!(first.canonical_digest, second.canonical_digest);

    write_spec(
        &temp.join("other.toml"),
        "version = 1\nkind = \"binary\"\npath = \"fixture\"\nargs = [\"--x\"]\nenv = []\nworking_directory = \"/\"\nuser = \"1000:1000\"\n",
    );
    let error = assemble(&temp.join("other.toml"), &store)
        .expect_err("a second closure replaced a verified store entry");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{error}");
    // The original closure still verifies after the rejected publication.
    assert_eq!(load(&store).unwrap().closure_sha256, first.closure_sha256);
}

#[test]
fn concurrent_assembly_publishes_one_verified_entry() {
    let temp = TempDir::new("concurrent");
    let binary = static_elf();
    fs::write(temp.join("fixture"), &binary).unwrap();
    write_spec(
        &temp.join("workload.toml"),
        &binary_spec("fixture", "1000:1000"),
    );
    let spec = temp.join("workload.toml");
    let store = temp.join("store");
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let spec = spec.clone();
            let store = store.clone();
            std::thread::spawn(move || assemble(&spec, &store).unwrap().closure_sha256)
        })
        .collect();
    let digests: Vec<String> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert!(digests.iter().all(|digest| digest == &digests[0]));
    assert_eq!(load(&store).unwrap().closure_sha256, digests[0]);
}

#[test]
fn a_special_file_in_the_store_is_rejected() {
    let temp = TempDir::new("special-store");
    let (store, _) = assemble_fixture(&temp);
    let closure = store.join("raw/closure.json");
    let moved = store.join("raw/closure.real");
    fs::rename(&closure, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &closure).unwrap();
    let error = load(&store).expect_err("a symlinked closure was read");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{error}");
}

// ---------------------------------------------------------------------------
// Specification parsing
// ---------------------------------------------------------------------------

#[test]
fn specification_parsing_is_strict() {
    let temp = TempDir::new("spec");
    let binary = static_elf();
    fs::write(temp.join("fixture"), &binary).unwrap();
    let cases: &[(&str, &str)] = &[
        (
            "unknown-field",
            "version = 1\nkind = \"binary\"\npath = \"fixture\"\nargs = []\nenv = []\nworking_directory = \"/\"\nuser = \"1000:1000\"\nextra = 1\n",
        ),
        (
            "wrong-version",
            "version = 2\nkind = \"binary\"\npath = \"fixture\"\nargs = []\nenv = []\nworking_directory = \"/\"\nuser = \"1000:1000\"\n",
        ),
        (
            "missing-user",
            "version = 1\nkind = \"binary\"\npath = \"fixture\"\nargs = []\nenv = []\nworking_directory = \"/\"\n",
        ),
        (
            "root-user",
            "version = 1\nkind = \"binary\"\npath = \"fixture\"\nargs = []\nenv = []\nworking_directory = \"/\"\nuser = \"0:1000\"\n",
        ),
        (
            "named-user",
            "version = 1\nkind = \"binary\"\npath = \"fixture\"\nargs = []\nenv = []\nworking_directory = \"/\"\nuser = \"root\"\n",
        ),
        (
            "uid-only",
            "version = 1\nkind = \"binary\"\npath = \"fixture\"\nargs = []\nenv = []\nworking_directory = \"/\"\nuser = \"1000\"\n",
        ),
        (
            "absolute-locator",
            "version = 1\nkind = \"binary\"\npath = \"/fixture\"\nargs = []\nenv = []\nworking_directory = \"/\"\nuser = \"1000:1000\"\n",
        ),
        (
            "escaping-locator",
            "version = 1\nkind = \"binary\"\npath = \"../fixture\"\nargs = []\nenv = []\nworking_directory = \"/\"\nuser = \"1000:1000\"\n",
        ),
        (
            "unknown-kind",
            "version = 1\nkind = \"archive\"\npath = \"fixture\"\nuser = \"1000:1000\"\n",
        ),
        (
            "oci-extra-field",
            "version = 1\nkind = \"oci\"\nlayout = \"layout\"\nmanifest_digest = \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\npath = \"fixture\"\n",
        ),
        (
            "malformed-digest",
            "version = 1\nkind = \"oci\"\nlayout = \"layout\"\nmanifest_digest = \"sha256:xyz\"\n",
        ),
        (
            "unsupported-digest",
            "version = 1\nkind = \"oci\"\nlayout = \"layout\"\nmanifest_digest = \"sha512:0000000000000000000000000000000000000000000000000000000000000000\"\n",
        ),
        (
            "binary-missing-kind",
            "version = 1\npath = \"fixture\"\nargs = []\nenv = []\nworking_directory = \"/\"\nuser = \"1000:1000\"\n",
        ),
    ];
    for (name, spec) in cases {
        let path = temp.join(format!("{name}.toml"));
        write_spec(&path, spec);
        let error = assemble(&path, &temp.join(format!("{name}-store")))
            .err()
            .unwrap_or_else(|| panic!("{name} was accepted"));
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidInput,
            "{name}: {error}"
        );
    }
}

fn copy_store(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let destination = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_store(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// Hardening regression tests
// ---------------------------------------------------------------------------

struct CpioEntry {
    name: String,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u32,
    contents: Vec<u8>,
}

/// Decode a `newc` CPIO archive so template metadata is asserted on the encoded
/// bytes rather than on substrings.
fn decode_cpio(bytes: &[u8]) -> Vec<CpioEntry> {
    let mut entries = Vec::new();
    let mut offset = 0;
    loop {
        assert_eq!(&bytes[offset..offset + 6], b"070701", "bad cpio magic");
        let field = |index: usize| -> u32 {
            let start = offset + 6 + index * 8;
            let text = std::str::from_utf8(&bytes[start..start + 8]).unwrap();
            u32::from_str_radix(text, 16).unwrap()
        };
        let mode = field(1);
        let uid = field(2);
        let gid = field(3);
        let mtime = field(5);
        let filesize = field(6) as usize;
        let namesize = field(11) as usize;
        let name_start = offset + 110;
        let name =
            String::from_utf8(bytes[name_start..name_start + namesize - 1].to_vec()).unwrap();
        let data_start = (name_start + namesize + 3) & !3;
        let contents = bytes[data_start..data_start + filesize].to_vec();
        offset = (data_start + filesize + 3) & !3;
        if name == "TRAILER!!!" {
            break;
        }
        entries.push(CpioEntry {
            name,
            mode,
            uid,
            gid,
            mtime,
            contents,
        });
    }
    entries
}

fn make_fifo(path: &Path) {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
    assert_eq!(result, 0, "mkfifo failed");
}

fn permission_bits(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn template_emits_the_root_before_paths_that_sort_before_it() {
    // `!early` sorts before the `.` root sentinel, and initramfs extraction does
    // not create missing parents, so the root must be emitted first.
    let temp = TempDir::new("template-order");
    let binary = static_elf();
    let layer = vec![
        directory("!early"),
        file_with("!early/data", b"x", 0o644, 0, 0, 0),
        file_with("bin/simferret-workload", &binary, 0o755, 1000, 1000, 0),
    ];
    let layout = temp.join("layout");
    let digest = write_layout(&layout, &[plain_layer(layer)], default_config(), None, None);
    write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
    let store = temp.join("store");
    assemble(&temp.join("workload.toml"), &store).unwrap();
    let loaded = load(&store).unwrap();

    let entries = decode_cpio(&loaded.template);
    let names: Vec<String> = entries.iter().map(|entry| entry.name.clone()).collect();
    assert_eq!(
        names,
        vec![
            "workload",
            "workload/!early",
            "workload/!early/data",
            "workload/bin",
            "workload/bin/simferret-workload",
        ]
    );
    for (index, name) in names.iter().enumerate() {
        if let Some((parent, _)) = name.rsplit_once('/') {
            let parent_index = names
                .iter()
                .position(|candidate| candidate == parent)
                .unwrap();
            assert!(parent_index < index, "{name} precedes its parent {parent}");
        }
    }
}

#[test]
fn template_reproduces_canonical_metadata() {
    let temp = TempDir::new("template-metadata");
    let binary = static_elf();
    let layer = vec![
        Member {
            mode: 0o750,
            uid: 2000,
            gid: 2000,
            mtime: 1700000003,
            ..directory("bin")
        },
        file_with("bin/simferret-workload", &binary, 0o755, 1000, 1000, 7),
        Member {
            mtime: 1700000004,
            ..symlink("bin/current", "simferret-workload")
        },
    ];
    let layout = temp.join("layout");
    let digest = write_layout(&layout, &[plain_layer(layer)], default_config(), None, None);
    write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
    let store = temp.join("store");
    assemble(&temp.join("workload.toml"), &store).unwrap();
    let loaded = load(&store).unwrap();

    let entries = decode_cpio(&loaded.template);
    let root = &entries[0];
    assert_eq!(root.name, "workload");
    assert_eq!(root.mode, 0o040755);
    assert_eq!((root.uid, root.gid, root.mtime), (0, 0, 0));

    let bin = entries
        .iter()
        .find(|entry| entry.name == "workload/bin")
        .unwrap();
    assert_eq!(bin.mode, 0o040750);
    assert_eq!((bin.uid, bin.gid, bin.mtime), (2000, 2000, 1700000003));

    let executable = entries
        .iter()
        .find(|entry| entry.name == "workload/bin/simferret-workload")
        .unwrap();
    assert_eq!(executable.mode, 0o100755);
    assert_eq!(
        (executable.uid, executable.gid, executable.mtime),
        (1000, 1000, 7)
    );
    assert_eq!(executable.contents, binary);

    let link = entries
        .iter()
        .find(|entry| entry.name == "workload/bin/current")
        .unwrap();
    assert_eq!(link.mode, 0o120777);
    assert_eq!(link.mtime, 1700000004);
    assert_eq!(link.contents, b"simferret-workload");
}

#[test]
fn a_non_directory_root_is_rejected() {
    let temp = TempDir::new("root-file");
    let binary = static_elf();
    let layout = temp.join("layout");
    let digest = write_layout(
        &layout,
        &[raw_layer(raw_tar_entry(b".", &binary))],
        json!({"config": {"Entrypoint": ["/."], "User": "1000:1000"}}),
        None,
        None,
    );
    write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
    let error = assemble(&temp.join("workload.toml"), &temp.join("store"))
        .expect_err("a non-directory root was accepted");
    assert!(
        error.to_string().contains("root must be a directory"),
        "{error}"
    );
}

#[test]
fn a_fifo_in_the_store_is_rejected() {
    let temp = TempDir::new("store-fifo-template");
    let (store, _) = assemble_fixture(&temp);
    let canonical = load(&store).unwrap().canonical_digest.clone();
    let template = store.join(format!("derived/{canonical}/template.cpio"));
    fs::remove_file(&template).unwrap();
    make_fifo(&template);
    let error = load(&store).expect_err("a FIFO template was hashed");
    assert!(
        error.to_string().contains("is not a regular file"),
        "{error}"
    );

    let other = TempDir::new("store-fifo-closure");
    let (other_store, _) = assemble_fixture(&other);
    let closure = other_store.join("raw/closure.json");
    fs::remove_file(&closure).unwrap();
    make_fifo(&closure);
    let error = load(&other_store).expect_err("a FIFO closure was read");
    assert!(
        error.to_string().contains("is not a regular file"),
        "{error}"
    );
}

#[test]
fn a_symlinked_layout_locator_is_rejected() {
    let temp = TempDir::new("layout-link");
    let binary = static_elf();
    let real = temp.join("real-layout");
    let digest = write_layout(
        &real,
        &[plain_layer(fixture_layer(&binary))],
        default_config(),
        None,
        None,
    );
    std::os::unix::fs::symlink(&real, temp.join("link")).unwrap();
    write_spec(&temp.join("workload.toml"), &oci_spec("link/.", &digest));
    let error = assemble(&temp.join("workload.toml"), &temp.join("store"))
        .expect_err("a symlinked layout locator was followed");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{error}");
}

#[test]
fn a_fifo_specification_does_not_block() {
    let temp = TempDir::new("spec-fifo");
    let specification = temp.join("workload.toml");
    make_fifo(&specification);
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_simferret"))
        .args(["workload", "assemble", "--specification"])
        .arg(&specification)
        .args(["--store"])
        .arg(temp.join("store"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success(), "a FIFO specification was accepted");
            return;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("assembly blocked on a FIFO specification");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[test]
fn store_artifacts_are_owner_only() {
    let temp = TempDir::new("permissions");
    let (store, _) = assemble_fixture(&temp);
    let canonical = load(&store).unwrap().canonical_digest.clone();
    for directory in [
        store.clone(),
        store.join("raw"),
        store.join("raw/sha256"),
        store.join("derived"),
        store.join(format!("derived/{canonical}")),
    ] {
        assert_eq!(
            permission_bits(&directory),
            0o700,
            "{}",
            directory.display()
        );
    }
    for file in [
        store.join("raw/closure.json"),
        store.join(format!("derived/{canonical}/tree.bin")),
        store.join(format!("derived/{canonical}/template.cpio")),
        store.join(format!("derived/{canonical}/lock.json")),
    ] {
        assert_eq!(permission_bits(&file), 0o600, "{}", file.display());
    }
    for object in fs::read_dir(store.join("raw/sha256")).unwrap() {
        let object = object.unwrap().path();
        assert_eq!(permission_bits(&object), 0o600, "{}", object.display());
    }
}

#[test]
fn a_reused_store_path_must_already_be_owner_only() {
    let binary = static_elf();

    // A pre-existing store root with group or other access is not adopted.
    let temp = TempDir::new("reused-store-root");
    fs::write(temp.join("fixture"), &binary).unwrap();
    write_spec(
        &temp.join("workload.toml"),
        &binary_spec("fixture", "1000:1000"),
    );
    let store = temp.join("store");
    fs::create_dir(&store).unwrap();
    set_mode(&store, 0o777);
    let error = assemble(&temp.join("workload.toml"), &store)
        .expect_err("a world-writable store root was adopted");
    assert!(error.to_string().contains("not owner-only"), "{error}");

    // A pre-existing internal directory with group or other access is not adopted.
    let temp = TempDir::new("reused-store-directory");
    fs::write(temp.join("fixture"), &binary).unwrap();
    write_spec(
        &temp.join("workload.toml"),
        &binary_spec("fixture", "1000:1000"),
    );
    let store = temp.join("store");
    fs::create_dir(&store).unwrap();
    set_mode(&store, 0o700);
    fs::create_dir(store.join("raw")).unwrap();
    set_mode(&store.join("raw"), 0o755);
    let error = assemble(&temp.join("workload.toml"), &store)
        .expect_err("a group-readable store directory was adopted");
    assert!(error.to_string().contains("not owner-only"), "{error}");

    // Re-assembling into an existing store must not reuse weakened artifacts.
    let temp = TempDir::new("reused-store-artifacts");
    let (store, _) = assemble_fixture(&temp);
    let canonical = load(&store).unwrap().canonical_digest.clone();

    // A reused object is read without reopening its parent, so the populated
    // raw object directory is validated on its own.
    set_mode(&store.join("raw/sha256"), 0o755);
    let error = assemble(&temp.join("workload.toml"), &store)
        .expect_err("a reused raw object directory was accepted with group or other access");
    assert!(error.to_string().contains("not owner-only"), "{error}");
    set_mode(&store.join("raw/sha256"), 0o700);

    let object = fs::read_dir(store.join("raw/sha256"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    set_mode(&object, 0o644);
    let error = assemble(&temp.join("workload.toml"), &store)
        .expect_err("a reused raw object was accepted with group or other access");
    assert!(error.to_string().contains("not owner-only"), "{error}");
    set_mode(&object, 0o600);

    set_mode(&store.join(format!("derived/{canonical}")), 0o755);
    let error = assemble(&temp.join("workload.toml"), &store)
        .expect_err("a reused derived entry was accepted with group or other access");
    assert!(error.to_string().contains("not owner-only"), "{error}");
}

#[test]
fn a_failed_derived_publication_leaves_no_closure() {
    let temp = TempDir::new("partial-store");
    let binary = static_elf();
    fs::write(temp.join("fixture"), &binary).unwrap();
    write_spec(
        &temp.join("workload.toml"),
        &binary_spec("fixture", "1000:1000"),
    );
    let store = temp.join("store");
    fs::create_dir(&store).unwrap();
    set_mode(&store, 0o700);
    fs::write(store.join("derived"), b"not a directory").unwrap();
    assemble(&temp.join("workload.toml"), &store)
        .expect_err("publication into a store with a file named derived succeeded");
    assert!(
        !store.join("raw/closure.json").exists(),
        "a raw closure was published without its derived entry"
    );
    assert!(load(&store).is_err(), "an incomplete store loaded");
}

#[test]
fn a_conflicting_builder_cannot_commit_an_unusable_store() {
    // Two specifications share one canonical tree but have different closures.
    // A derived entry left by an interrupted builder must not let a different
    // closure be committed against it.
    let temp = TempDir::new("conflicting-builders");
    let binary = static_elf();
    fs::write(temp.join("fixture"), &binary).unwrap();
    write_spec(
        &temp.join("a.toml"),
        "version = 1\nkind = \"binary\"\npath = \"fixture\"\nargs = []\nenv = []\nworking_directory = \"/\"\nuser = \"1000:1000\"\n",
    );
    write_spec(
        &temp.join("b.toml"),
        "version = 1\nkind = \"binary\"\npath = \"fixture\"\nargs = [\"--x\"]\nenv = []\nworking_directory = \"/\"\nuser = \"1000:1000\"\n",
    );
    let store = temp.join("store");
    let first = assemble(&temp.join("a.toml"), &store).unwrap();

    // Simulate an interrupted publication: the derived entry exists, the
    // closure does not.
    fs::remove_file(store.join("raw/closure.json")).unwrap();

    let error = assemble(&temp.join("b.toml"), &store)
        .expect_err("a closure was committed against another builder's derived entry");
    assert!(
        error.to_string().contains("does not name this raw closure"),
        "{error}"
    );
    assert!(
        !store.join("raw/closure.json").exists(),
        "a closure was committed without a matching derived entry"
    );

    // The original builder can still complete, and the store then loads.
    let recovered = assemble(&temp.join("a.toml"), &store).unwrap();
    assert_eq!(recovered.closure_sha256, first.closure_sha256);
    assert_eq!(load(&store).unwrap().closure_sha256, first.closure_sha256);
}

#[test]
fn a_valid_closure_with_the_wrong_lock_is_rejected() {
    // Two valid assemblies with the same canonical tree but different closures.
    // Replacing one store's raw closure with the other's, while keeping the
    // original derived lock, must fail on the lock rather than on raw content.
    let temp = TempDir::new("wrong-lock");
    let binary = static_elf();
    fs::write(temp.join("fixture"), &binary).unwrap();
    write_spec(
        &temp.join("a.toml"),
        "version = 1\nkind = \"binary\"\npath = \"fixture\"\nargs = []\nenv = []\nworking_directory = \"/\"\nuser = \"1000:1000\"\n",
    );
    write_spec(
        &temp.join("b.toml"),
        "version = 1\nkind = \"binary\"\npath = \"fixture\"\nargs = [\"--x\"]\nenv = []\nworking_directory = \"/\"\nuser = \"1000:1000\"\n",
    );
    let a_store = temp.join("a-store");
    let b_store = temp.join("b-store");
    let first = assemble(&temp.join("a.toml"), &a_store).unwrap();
    let second = assemble(&temp.join("b.toml"), &b_store).unwrap();
    assert_eq!(first.canonical_digest, second.canonical_digest);
    assert_ne!(first.closure_sha256, second.closure_sha256);

    for entry in fs::read_dir(b_store.join("raw/sha256")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(
            entry.path(),
            a_store.join("raw/sha256").join(entry.file_name()),
        )
        .unwrap();
    }
    fs::copy(
        b_store.join("raw/closure.json"),
        a_store.join("raw/closure.json"),
    )
    .unwrap();

    let error = load(&a_store).expect_err("a closure with the wrong lock was accepted");
    assert!(
        error.to_string().contains("does not name this raw closure"),
        "{error}"
    );
}

#[test]
fn a_self_consistent_config_change_is_rejected_by_relationship_checks() {
    let temp = TempDir::new("self-consistent");
    let binary = static_elf();
    let layout = temp.join("layout");
    let digest = write_layout(
        &layout,
        &[plain_layer(fixture_layer(&binary))],
        default_config(),
        None,
        None,
    );
    write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
    let store = temp.join("store");
    assemble(&temp.join("workload.toml"), &store).unwrap();

    // Rewrite the config with a different DiffID under its own digest, then
    // update the closure so the raw content is internally consistent. The
    // unchanged manifest/config relationship and derived lock must still reject
    // the recording.
    let closure_path = store.join("raw/closure.json");
    let mut closure: Value = serde_json::from_slice(&fs::read(&closure_path).unwrap()).unwrap();
    let record = closure["objects"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|record| record["role"] == "config")
        .unwrap();
    let old_hex = record["digest"].as_str().unwrap()[7..].to_owned();
    let mut config: Value =
        serde_json::from_slice(&fs::read(store.join("raw/sha256").join(&old_hex)).unwrap())
            .unwrap();
    config["rootfs"]["diff_ids"][0] = json!("sha256:".to_owned() + &"1".repeat(64));
    let new_config = serde_json::to_vec(&config).unwrap();
    let new_hex = sha256_hex(&new_config);
    fs::write(store.join("raw/sha256").join(&new_hex), &new_config).unwrap();
    record["digest"] = json!(format!("sha256:{new_hex}"));
    record["bytes"] = json!(new_config.len());
    fs::write(&closure_path, serde_json::to_vec(&closure).unwrap()).unwrap();

    let error = load(&store).expect_err("a self-consistent raw change was accepted");
    assert!(
        error.to_string().contains("config descriptor")
            && error.to_string().contains("does not match stored bytes"),
        "{error}"
    );
}

#[test]
fn oci_launch_arguments_are_bounded() {
    let binary = static_elf();
    let cases: Vec<(&str, Value)> = vec![
        (
            "nul-argument",
            json!({"config": {"Entrypoint": [INSTALL_PATH], "Cmd": ["a\u{0}b"], "User": "1000:1000"}}),
        ),
        (
            "oversized-argument",
            json!({"config": {"Entrypoint": [INSTALL_PATH], "Cmd": ["x".repeat(4097)], "User": "1000:1000"}}),
        ),
        (
            "too-many-arguments",
            json!({"config": {"Entrypoint": [INSTALL_PATH], "Cmd": vec!["a"; 257], "User": "1000:1000"}}),
        ),
    ];
    for (name, config) in cases {
        let temp = TempDir::new(name);
        let layout = temp.join("layout");
        let digest = write_layout(
            &layout,
            &[plain_layer(fixture_layer(&binary))],
            config,
            None,
            None,
        );
        write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
        let error = assemble(&temp.join("workload.toml"), &temp.join("store"))
            .expect_err("an unbounded OCI argument vector was accepted");
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidInput,
            "{name}: {error}"
        );
    }
}

#[test]
fn the_reserved_owner_identifier_is_rejected() {
    let binary = static_elf();

    // A binary source may name its owner through the specification.
    let temp = TempDir::new("reserved-owner-spec");
    fs::write(temp.join("fixture"), &binary).unwrap();
    for user in ["4294967295:1000", "1000:4294967295"] {
        write_spec(&temp.join("workload.toml"), &binary_spec("fixture", user));
        let error = assemble(&temp.join("workload.toml"), &temp.join("store"))
            .expect_err("the reserved owner identifier was accepted in the specification");
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidInput,
            "{user}: {error}"
        );
    }

    // The OCI launch credentials reject it as well.
    let temp = TempDir::new("reserved-owner-config");
    let layout = temp.join("layout");
    let digest = write_layout(
        &layout,
        &[plain_layer(fixture_layer(&binary))],
        json!({"config": {"Entrypoint": [INSTALL_PATH], "User": format!("{0}:1000", u32::MAX)}}),
        None,
        None,
    );
    write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
    let error = assemble(&temp.join("workload.toml"), &temp.join("store"))
        .expect_err("the reserved owner identifier was accepted in the image configuration");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{error}");

    // A layer entry may not claim it either, in either ownership field.
    for (uid, gid) in [(u32::MAX, 1000), (1000, u32::MAX)] {
        let temp = TempDir::new("reserved-owner-layer");
        let layout = temp.join("layout");
        let digest = write_layout(
            &layout,
            &[plain_layer(vec![
                directory("bin"),
                file_with("bin/simferret-workload", &binary, 0o755, uid, gid, 0),
            ])],
            default_config(),
            None,
            None,
        );
        write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
        let error = assemble(&temp.join("workload.toml"), &temp.join("store"))
            .expect_err("a layer entry claimed the reserved owner identifier");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{error}");
    }
}

/// Rewrite the retained binary canonical specification and update the closure
/// record that names it, so the raw subgraph stays internally consistent and
/// the replay-time validation is what rejects the recording.
fn rewrite_retained_specification(store: &Path, edit: impl FnOnce(&mut Value)) {
    let closure_path = store.join("raw/closure.json");
    let mut closure: Value = serde_json::from_slice(&fs::read(&closure_path).unwrap()).unwrap();
    let record = closure["objects"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|record| record["role"] == "workload-specification")
        .unwrap();
    let old_hex = record["digest"].as_str().unwrap()[7..].to_owned();
    let mut specification: Value =
        serde_json::from_slice(&fs::read(store.join("raw/sha256").join(&old_hex)).unwrap())
            .unwrap();
    edit(&mut specification);
    let specification = serde_json::to_vec(&specification).unwrap();
    let new_hex = sha256_hex(&specification);
    fs::write(store.join("raw/sha256").join(&new_hex), &specification).unwrap();
    record["digest"] = json!(format!("sha256:{new_hex}"));
    record["bytes"] = json!(specification.len());
    fs::write(&closure_path, serde_json::to_vec(&closure).unwrap()).unwrap();
}

#[test]
fn a_retained_specification_with_a_reserved_owner_is_rejected_on_replay() {
    // The numeric owner in a retained canonical specification never passes
    // through the specification parser, so replay must enforce the reserved
    // identifier itself.
    let temp = TempDir::new("reserved-owner-replay");
    let (store, _) = assemble_fixture(&temp);
    rewrite_retained_specification(&store, |specification| {
        specification["uid"] = json!(u32::MAX);
    });

    let error = load(&store)
        .expect_err("a retained specification with the reserved owner identifier was accepted");
    assert!(error.to_string().contains("reserved owner"), "{error}");
}

#[test]
fn a_retained_specification_with_a_moved_install_path_is_rejected_on_replay() {
    // A self-consistent recording whose install path violates the binary
    // profile must fail on the profile invariant rather than on a later hash.
    let temp = TempDir::new("moved-install-path");
    let (store, _) = assemble_fixture(&temp);
    rewrite_retained_specification(&store, |specification| {
        specification["install_path"] = json!("opt/app");
        specification["arguments"][0] = json!("/opt/app");
    });

    let error = load(&store).expect_err("a moved binary install path was accepted on replay");
    assert!(error.to_string().contains("install path"), "{error}");
}

#[test]
fn empty_launch_extension_fields_are_treated_as_unconfigured() {
    // Each unsupported field has its own unconfigured representation: an empty
    // object, an empty string, and `false` respectively.
    let temp = TempDir::new("empty-launch-extensions");
    let binary = static_elf();
    let layout = temp.join("layout");
    let digest = write_layout(
        &layout,
        &[plain_layer(fixture_layer(&binary))],
        json!({"config": {
            "Entrypoint": [INSTALL_PATH],
            "User": "1000:1000",
            "WorkingDir": "/",
            "Volumes": {},
            "StopSignal": "",
            "ArgsEscaped": false,
        }}),
        None,
        None,
    );
    write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
    let assembled = assemble(&temp.join("workload.toml"), &temp.join("store")).unwrap();
    assert_eq!(assembled.entries, 3);
}

#[test]
fn a_null_environment_is_treated_as_empty() {
    let temp = TempDir::new("null-env");
    let binary = static_elf();
    let layout = temp.join("layout");
    let digest = write_layout(
        &layout,
        &[plain_layer(fixture_layer(&binary))],
        json!({"config": {"Entrypoint": [INSTALL_PATH], "User": "1000:1000", "Env": null, "WorkingDir": null}}),
        None,
        None,
    );
    write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
    let store = temp.join("store");
    assemble(&temp.join("workload.toml"), &store).unwrap();
    let loaded = load(&store).unwrap();
    assert!(loaded.launch.environment.is_empty());
    assert_eq!(loaded.launch.working_directory, "/");
}

#[test]
fn an_opaque_marker_may_not_traverse_a_lower_symlink() {
    let temp = TempDir::new("opaque-symlink");
    let binary = static_elf();
    let lower = vec![
        directory("bin"),
        file_with("bin/simferret-workload", &binary, 0o755, 1000, 1000, 0),
        symlink("a", "bin"),
    ];
    let upper = vec![file(".wh.a", b""), file("a/.wh..wh..opq", b"")];
    let layout = temp.join("layout");
    let digest = write_layout(
        &layout,
        &[plain_layer(lower), plain_layer(upper)],
        default_config(),
        None,
        None,
    );
    write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
    let error = assemble(&temp.join("workload.toml"), &temp.join("store"))
        .expect_err("an opaque marker traversed a lower symlink");
    assert!(
        error.to_string().contains("traverses a symbolic link"),
        "{error}"
    );
}

#[test]
fn a_self_contained_store_survives_source_mutation() {
    let temp = TempDir::new("source-mutation");
    let (store, closure) = assemble_fixture(&temp);
    fs::write(temp.join("fixture"), b"mutated").unwrap();
    fs::remove_file(temp.join("workload.toml")).unwrap();
    let loaded = load(&store).unwrap();
    assert_eq!(loaded.closure_sha256, closure);
    assert_eq!(entry(&loaded.tree, "bin/simferret-workload").mode, 0o755);
}

#[test]
fn an_expanded_layer_beyond_the_limit_is_rejected() {
    let temp = TempDir::new("expansion-limit");
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    let chunk = vec![0_u8; 1 << 20];
    for _ in 0..257 {
        encoder.write_all(&chunk).unwrap();
    }
    let bomb = encoder.finish().unwrap();
    let layout = temp.join("layout");
    let digest = write_layout(
        &layout,
        &[stored_gzip_layer(bomb)],
        default_config(),
        None,
        None,
    );
    write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
    let error = assemble(&temp.join("workload.toml"), &temp.join("store"))
        .expect_err("an oversized expanded layer was accepted");
    assert!(error.to_string().contains("expansion limit"), "{error}");
}

#[test]
fn an_over_entry_limit_tree_is_rejected_during_construction() {
    // Nine layers of 4,096 distinct entries push the intermediate tree past the
    // 32,768-entry bound, and a tenth layer removes enough entries that the
    // final tree would be legal. A publication-only check would accept the
    // recording, so this proves the per-layer check runs during construction.
    let temp = TempDir::new("entry-limit");
    let binary = static_elf();
    let mut layers = Vec::new();
    for layer in 0..9 {
        let mut members = vec![
            directory("bin"),
            file_with("bin/simferret-workload", &binary, 0o755, 1000, 1000, 0),
        ];
        for entry in 0..4094 {
            members.push(file(&format!("layer{layer}/entry{entry}"), b""));
        }
        layers.push(plain_layer(members));
    }
    let mut whiteouts = Vec::new();
    for entry in 0..4094 {
        whiteouts.push(file(&format!("layer8/.wh.entry{entry}"), b""));
    }
    whiteouts.push(file("layer7/.wh.entry4093", b""));
    layers.push(plain_layer(whiteouts));

    // 3 root/bin/executable entries plus 9 * 4,094 additions minus 4,095
    // whiteouts: legal, and small enough that only the intermediate tree fails.
    let final_entries = 3 + 9 * 4094 - 4095;
    assert!(final_entries <= simferret::workload::MAX_VIEW_ENTRIES);

    let layout = temp.join("layout");
    let digest = write_layout(&layout, &layers, default_config(), None, None);
    write_spec(&temp.join("workload.toml"), &oci_spec("layout", &digest));
    let store = temp.join("store");
    let error = assemble(&temp.join("workload.toml"), &store)
        .expect_err("an over-limit canonical tree was accepted");
    assert!(error.to_string().contains("entries"), "{error}");
    assert!(!store.join("raw/closure.json").exists());
}

#[test]
fn oci_launch_identity_is_normalized_and_selected() {
    let temp = TempDir::new("oci-launch");
    let binary = static_elf();
    let layer = vec![
        directory("bin"),
        file_with("bin/one", &binary, 0o755, 1000, 1000, 0),
        file_with("bin/two", &binary, 0o755, 1000, 1000, 0),
    ];
    let first = temp.join("first");
    let first_digest = write_layout(
        &first,
        &[plain_layer(layer.clone())],
        json!({"config": {"Entrypoint": ["/bin/one"], "Cmd": ["--flag"], "Env": ["A=1"], "User": "1000:1000", "WorkingDir": "/bin"}}),
        None,
        None,
    );
    write_spec(&temp.join("first.toml"), &oci_spec("first", &first_digest));
    let first_store = temp.join("first-store");
    assemble(&temp.join("first.toml"), &first_store).unwrap();
    let loaded = load(&first_store).unwrap();
    assert_eq!(loaded.launch.executable, "/bin/one");
    assert_eq!(
        loaded.launch.arguments,
        vec!["/bin/one".to_owned(), "--flag".to_owned()]
    );
    assert_eq!(loaded.launch.environment, vec!["A=1".to_owned()]);
    assert_eq!(loaded.launch.working_directory, "/bin");
    assert_eq!((loaded.launch.uid, loaded.launch.gid), (1000, 1000));

    let second = temp.join("second");
    let second_digest = write_layout(
        &second,
        &[plain_layer(layer)],
        json!({"config": {"Entrypoint": ["/bin/two"], "User": "1000:1000"}}),
        None,
        None,
    );
    write_spec(
        &temp.join("second.toml"),
        &oci_spec("second", &second_digest),
    );
    let second_result = assemble(&temp.join("second.toml"), &temp.join("second-store")).unwrap();
    assert_eq!(second_result.canonical_digest, loaded.canonical_digest);
    assert_ne!(second_result.closure_sha256, loaded.closure_sha256);
}
