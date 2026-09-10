//! RFD 3 Phase 1 acceptance: the typed workload specification and canonical
//! assembler.
//!
//! The suite builds standalone binary and local OCI image-layout sources,
//! assembles them into content-addressed stores, and verifies the canonical
//! tree, launch identity, raw closure, and derived cache entry. It also covers
//! the Phase 1 rejection requirements: unsupported OCI constructs, unsafe
//! links, expansion and entry bounds, tampered or missing raw and derived
//! content, and concurrent publication.

use std::collections::BTreeMap;
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

fn elf_header() -> Vec<u8> {
    let mut bytes = vec![0_u8; 64];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes
}

fn static_elf() -> Vec<u8> {
    let mut bytes = elf_header();
    bytes.extend_from_slice(&[0x90; 64]);
    bytes
}

fn dynamic_elf() -> Vec<u8> {
    let mut bytes = elf_header();
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
    bytes.resize(64 + 56, 0);
    bytes[64..68].copy_from_slice(&3_u32.to_le_bytes());
    bytes
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
    }
}

fn gzip_layer(members: Vec<Member>) -> Layer {
    Layer {
        members,
        compressed: true,
        media_type: None,
        raw: None,
    }
}

fn raw_layer(raw: Vec<u8>) -> Layer {
    Layer {
        members: Vec::new(),
        compressed: false,
        media_type: None,
        raw: Some(raw),
    }
}

fn layer_with_media_type(members: Vec<Member>, media_type: &str) -> Layer {
    Layer {
        members,
        compressed: false,
        media_type: Some(media_type.into()),
        raw: None,
    }
}

/// A physical USTAR entry the `tar` crate's builder refuses to write, used to
/// prove that the parser rejects unsafe paths itself.
fn raw_tar_entry(name: &[u8], data: &[u8]) -> Vec<u8> {
    assert!(name.len() <= 100);
    let mut block = [0_u8; 512];
    block[..name.len()].copy_from_slice(name);
    block[100..108].copy_from_slice(b"0000755\0");
    block[108..116].copy_from_slice(b"0000000\0");
    block[116..124].copy_from_slice(b"0000000\0");
    block[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
    block[136..148].copy_from_slice(b"00000000000\0");
    block[148..156].copy_from_slice(b"        ");
    block[156] = b'0';
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
        let stored = if layer.compressed {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&raw).unwrap();
            encoder.finish().unwrap()
        } else {
            raw.clone()
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
    let cases: &[(&str, Vec<u8>)] = &[
        ("dynamic", dynamic_elf()),
        ("malformed", b"not an elf".to_vec()),
        ("wrong-architecture", {
            let mut bytes = static_elf();
            bytes[18..20].copy_from_slice(&40_u16.to_le_bytes());
            bytes
        }),
        ("wrong-endianness", {
            let mut bytes = static_elf();
            bytes[5] = 2;
            bytes
        }),
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
fn a_self_consistent_manifest_and_layer_change_still_fails() {
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

// Keep the `BTreeMap` import meaningful for future fixtures that compare
// ordered role maps without changing the public API.
#[allow(dead_code)]
fn ordered_roles(roles: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
    roles
        .iter()
        .map(|(role, data)| ((*role).to_owned(), data.to_vec()))
        .collect()
}
