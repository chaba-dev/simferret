// The guest-visible conformance check changes root, drops credentials, and
// creates device nodes, so this target is Linux-only. The checked-in script
// `scripts/rfd3-phase4-runtime.sh` runs it as PID 1 in a fresh PID namespace,
// exactly as the guest owns its process table.
#![cfg(target_os = "linux")]

//! RFD 3 Phase 4 acceptance: guest-visible conformance and input exclusion.
//!
//! Phase 1 proves the canonical view on the host and Phase 3 proves the packaged
//! workload records and replays in the real guest. This suite closes the
//! remaining RFD acceptance criterion: canonical modes, owners, modification
//! times, symbolic links, legal cross-layer replacements, whiteouts, and opaque
//! directories survive CPIO encoding and are observed correctly inside the
//! workload root. It assembles a real OCI layout, encodes the canonical tree as
//! the guest template, extracts that template exactly as the guest initramfs
//! does, and runs an ordinary workload that reports the metadata it sees.
//!
//! The remaining tests assert the other Phase 4 acceptance requirements that do
//! not need a guest: no ambient host environment, unrelated host file, or host
//! source path enters the assembled workload.

use std::ffi::{CString, OsStr};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use simferret::protocol::{Event, OutputStream};
use simferret::runtime::{MemberScope, Runtime, RuntimeConfig, RuntimeLimits};
use simferret::workload::{assemble, load};

const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const PLAIN_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";
const INSTALL_PATH: &str = "/bin/busybox";

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

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "simferret-rfd3-phase4-{label}-{}-{counter}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn join(&self, name: impl AsRef<Path>) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn require_root() -> bool {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    eprintln!(
        "skipping: the guest-visible conformance check requires root to change root and credentials"
    );
    false
}

fn busybox() -> Vec<u8> {
    let path = std::env::var_os("SIMFERRET_BUSYBOX")
        .expect("SIMFERRET_BUSYBOX must name the pinned static busybox");
    fs::read(path).expect("the pinned static busybox must be readable")
}

/// A structurally valid fixed-address little-endian x86-64 ELF image.
fn static_elf() -> Vec<u8> {
    let payload = vec![0x90_u8; 64];
    let header_count = 1_usize;
    let offset = (64 + 56 * header_count) as u64;
    let mut bytes = vec![0_u8; 64];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&(0x40_0000 + offset).to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&(header_count as u16).to_le_bytes());
    let mut encoded = [0_u8; 56];
    encoded[0..4].copy_from_slice(&1_u32.to_le_bytes());
    encoded[4..8].copy_from_slice(&5_u32.to_le_bytes());
    encoded[8..16].copy_from_slice(&offset.to_le_bytes());
    encoded[16..24].copy_from_slice(&(0x40_0000 + offset).to_le_bytes());
    encoded[32..40].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    encoded[40..48].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    encoded[48..56].copy_from_slice(&0x1000_u64.to_le_bytes());
    bytes.extend_from_slice(&encoded);
    bytes.extend_from_slice(&payload);
    bytes
}

#[derive(Clone)]
struct Member {
    name: String,
    kind: char,
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
        kind: 'd',
        mode: 0o755,
        uid: 0,
        gid: 0,
        mtime: 0,
        data: Vec::new(),
        target: String::new(),
    }
}

fn file_with(name: &str, data: &[u8], mode: u32, uid: u32, gid: u32, mtime: u32) -> Member {
    Member {
        name: name.into(),
        kind: 'f',
        mode,
        uid,
        gid,
        mtime,
        data: data.to_vec(),
        target: String::new(),
    }
}

fn symlink(name: &str, target: &str, mtime: u32) -> Member {
    Member {
        name: name.into(),
        kind: 'l',
        mode: 0o777,
        uid: 0,
        gid: 0,
        mtime,
        data: Vec::new(),
        target: target.into(),
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
        match member.kind {
            'd' => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_path(&member.name).unwrap();
                header.set_size(0);
                header.set_cksum();
                builder.append(&header, std::io::empty()).unwrap();
            }
            'l' => {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_path(&member.name).unwrap();
                header.set_link_name(&member.target).unwrap();
                header.set_size(0);
                header.set_cksum();
                builder.append(&header, std::io::empty()).unwrap();
            }
            _ => {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_path(&member.name).unwrap();
                header.set_size(member.data.len() as u64);
                header.set_cksum();
                builder.append(&header, member.data.as_slice()).unwrap();
            }
        }
    }
    builder.finish().unwrap();
    builder.into_inner().unwrap()
}

fn store_blob(blobs: &Path, data: &[u8]) -> (String, usize) {
    let hex = sha256_hex(data);
    fs::write(blobs.join(&hex), data).unwrap();
    (format!("sha256:{hex}"), data.len())
}

/// Write one local OCI image layout with the given plain layers and config, and
/// return the selected manifest digest.
fn write_layout(directory: &Path, layers: &[Vec<Member>], config: Value) -> String {
    let blobs = directory.join("blobs/sha256");
    fs::create_dir_all(&blobs).unwrap();
    let mut stored_layers = Vec::new();
    let mut diff_ids = Vec::new();
    for members in layers {
        let raw = tar_bytes(members);
        let (digest, size) = store_blob(&blobs, &raw);
        stored_layers.push(json!({
            "mediaType": PLAIN_LAYER_MEDIA_TYPE,
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
            "platform": {"architecture": "amd64", "os": "linux"},
        }],
    });
    let config_bytes = serde_json::to_vec(&config).unwrap();
    let (config_digest, config_size) = store_blob(&blobs, &config_bytes);
    manifest["config"] = json!({
        "mediaType": CONFIG_MEDIA_TYPE,
        "digest": config_digest,
        "size": config_size,
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let (manifest_digest, manifest_size) = store_blob(&blobs, &manifest_bytes);
    index["manifests"][0]["digest"] = json!(manifest_digest);
    index["manifests"][0]["size"] = json!(manifest_size);
    fs::write(
        directory.join("index.json"),
        serde_json::to_vec(&index).unwrap(),
    )
    .unwrap();
    fs::write(
        directory.join("oci-layout"),
        serde_json::to_vec(&json!({"imageLayoutVersion": "1.0.0"})).unwrap(),
    )
    .unwrap();
    manifest_digest
}

fn binary_spec(path: &str, user: &str) -> String {
    format!(
        "version = 1\nkind = \"binary\"\npath = \"{path}\"\nargs = []\nenv = []\nworking_directory = \"/\"\nuser = \"{user}\"\n"
    )
}

fn oci_spec(layout: &str, digest: &str) -> String {
    format!("version = 1\nkind = \"oci\"\nlayout = \"{layout}\"\nmanifest_digest = \"{digest}\"\n")
}

// ---------------------------------------------------------------------------
// The guest-visible conformance fixture
// ---------------------------------------------------------------------------

/// The base layer carries ordinary entries with non-default metadata plus the
/// lower-layer entries the upper layer replaces, removes, or hides. Each
/// mechanism lives in its own subtree, because opacity hides every lower child of
/// its directory: sharing one directory would let opacity mask both the
/// replacement and the whiteout.
fn base_layer() -> Vec<Member> {
    let busybox = busybox();
    vec![
        directory("bin"),
        file_with("bin/busybox", &busybox, 0o755, 0, 0, 0),
        // BusyBox resolves an applet from the name it is invoked with, so the
        // workload needs the applets it calls as links to the one binary.
        symlink("bin/sh", "busybox", 0),
        symlink("bin/stat", "busybox", 0),
        symlink("bin/readlink", "busybox", 0),
        symlink("bin/cat", "busybox", 0),
        // Legal replacement: the upper layer writes new bytes and metadata over
        // an existing lower-layer file in a directory nothing else touches.
        // 0751 keeps the directory traversable for the workload's "other" class
        // while proving a non-default mode, owner, and timestamp survive.
        Member {
            mode: 0o751,
            uid: 2000,
            gid: 2000,
            mtime: 1_700_000_003,
            ..directory("replace")
        },
        file_with("replace/keep", b"base", 0o600, 1000, 1000, 1_700_000_007),
        // Whiteout: `hide/removed` is marked, and `hide/kept` must survive with
        // its own lower-layer bytes and metadata.
        directory("hide"),
        file_with("hide/removed", b"gone", 0o640, 1200, 1200, 1_700_000_001),
        file_with("hide/kept", b"safe", 0o644, 1200, 1200, 1_700_000_005),
        // Opacity: every lower child of `opaque` must disappear, including a
        // nested directory, while a same-layer addition survives.
        directory("opaque"),
        file_with("opaque/lower-child", b"hidden", 0o644, 0, 0, 1_700_000_001),
        Member {
            mtime: 1_700_000_001,
            ..directory("opaque/nested")
        },
        file_with("opaque/nested/deep", b"deep", 0o644, 0, 0, 1_700_000_001),
    ]
}

/// The upper layer legally replaces one file, whiteouts one lower path, marks
/// `opaque` opaque, and adds a symlink and a file. The whiteout marker and the
/// opaque marker both appear after the same-layer entries they coexist with, so
/// an implementation that applied markers in archive order would delete a
/// same-layer addition and change the asserted tree.
fn upper_layer() -> Vec<Member> {
    vec![
        // The replacement shares its directory with no marker.
        file_with("replace/keep", b"upper", 0o640, 1001, 1001, 1_700_000_008),
        // The whiteout shares its directory only with `kept`.
        file_with(WHITEOUT_MARKER, b"", 0o644, 0, 0, 0),
        // The same-layer addition under `opaque` must survive the marker that
        // follows it. It stays world-readable so the workload's nonzero user can
        // read it while its non-default owner is still asserted.
        file_with("opaque/added", b"added", 0o644, 1300, 1300, 1_700_000_006),
        file_with(OPACITY_MARKER, b"", 0o644, 0, 0, 0),
        symlink("link", "replace/keep", 1_700_000_004),
    ]
}

/// The lower-layer entry the upper layer legally replaces.
const REPLACEMENT_PATH: &str = "replace/keep";
const REPLACEMENT_LOWER: &[u8] = b"base";
const REPLACEMENT_LOWER_MODE: u32 = 0o600;
const REPLACEMENT_LOWER_OWNER: (u32, u32) = (1000, 1000);
const REPLACEMENT_LOWER_MTIME: u32 = 1_700_000_007;
/// The lower-layer entry the upper layer whiteouts, and its sibling that must
/// survive the same marker.
const WHITEOUT_MARKER: &str = "hide/.wh.removed";
const WHITEOUT_PATH: &str = "hide/removed";
const WHITEOUT_LOWER: &[u8] = b"gone";
const WHITEOUT_LOWER_MODE: u32 = 0o640;
const WHITEOUT_LOWER_OWNER: (u32, u32) = (1200, 1200);
const WHITEOUT_LOWER_MTIME: u32 = 1_700_000_001;
const WHITEOUT_SURVIVOR: &str = "hide/kept";
/// The directory the upper layer marks opaque, its lower-layer children, and the
/// same-layer addition that must survive the marker.
const OPACITY_MARKER: &str = "opaque/.wh..wh..opq";
const OPACITY_DIRECTORY: &str = "opaque";
const OPACITY_LOWER_CHILDREN: &[&str] =
    &["opaque/lower-child", "opaque/nested", "opaque/nested/deep"];
const OPACITY_LOWER_CHILD: &str = "opaque/lower-child";
const OPACITY_LOWER_CHILD_BYTES: &[u8] = b"hidden";
const OPACITY_LOWER_CHILD_MODE: u32 = 0o644;
const OPACITY_LOWER_CHILD_OWNER: (u32, u32) = (0, 0);
const OPACITY_NESTED: &str = "opaque/nested";
const OPACITY_NESTED_MODE: u32 = 0o755;
const OPACITY_NESTED_DEEP: &str = "opaque/nested/deep";
const OPACITY_NESTED_DEEP_BYTES: &[u8] = b"deep";
const OPACITY_NESTED_DEEP_MODE: u32 = 0o644;
const OPACITY_LOWER_MTIME: u32 = 1_700_000_001;
const OPACITY_ADDITION: &str = "opaque/added";
const OPACITY_ADDITION_MODE: u32 = 0o644;

/// One upper-layer mechanism a variant layout omits, so the conformance suite can
/// prove each mechanism is load-bearing on its own rather than being masked by
/// another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mechanism {
    None,
    Replacement,
    Whiteout,
    Opacity,
}

/// The upper layer with exactly one mechanism removed.
fn upper_layer_without(mechanism: Mechanism) -> Vec<Member> {
    upper_layer()
        .into_iter()
        .filter(|member| match mechanism {
            Mechanism::None => true,
            Mechanism::Replacement => member.name != REPLACEMENT_PATH,
            Mechanism::Whiteout => member.name != WHITEOUT_MARKER,
            Mechanism::Opacity => member.name != OPACITY_MARKER,
        })
        .collect()
}

/// Write a conformance layout that omits `mechanism` from its upper layer and
/// return the selected manifest digest.
fn write_conformance_layout(directory: &Path, mechanism: Mechanism) -> String {
    let config = json!({
        "config": {
            "Entrypoint": [INSTALL_PATH, "sh", "-c", CONFORMANCE_SCRIPT],
            "Env": ["PATH=/bin"],
            "User": "1001:1001",
            "WorkingDir": "/",
        }
    });
    write_layout(
        directory,
        &[base_layer(), upper_layer_without(mechanism)],
        config,
    )
}

/// Assemble one conformance variant into its own store under `temp`. The layout
/// locator must be relative to the specification, so each variant gets its own
/// directory holding the layout, the specification, and the store.
fn assemble_variant(temp: &TempDir, name: &str, mechanism: Mechanism) -> PathBuf {
    let form = temp.join(name);
    let layout = form.join("layout");
    let digest = write_conformance_layout(&layout, mechanism);
    let specification = form.join("workload.toml");
    fs::write(&specification, oci_spec("layout", &digest)).unwrap();
    let store = form.join("store");
    assemble(&specification, &store).unwrap();
    store
}

#[test]
fn each_layer_mechanism_is_independently_load_bearing() {
    // A conformance fixture that put the replacement, the whiteout, and the
    // opacity marker in one directory would prove nothing about the whiteout and
    // nothing about the replacement: opacity hides every lower child of its
    // directory, so both cases would pass even if the marker or the replacement
    // were dropped. Each variant here omits exactly one mechanism and requires
    // the lower-layer entry the mechanism should have affected to survive with
    // its original bytes and metadata.
    let temp = TempDir::new("mechanism-controls");

    let baseline = load(&assemble_variant(&temp, "baseline", Mechanism::None)).unwrap();
    assert!(
        baseline.tree.get(WHITEOUT_PATH.as_bytes()).is_none(),
        "the whiteout target survives the baseline"
    );
    assert_eq!(
        baseline
            .tree
            .get(WHITEOUT_SURVIVOR.as_bytes())
            .expect("the whiteout leaves its sibling alone")
            .data
            .as_deref(),
        Some(b"safe".as_slice())
    );
    assert_eq!(
        baseline
            .tree
            .get(REPLACEMENT_PATH.as_bytes())
            .expect("the replacement survives")
            .data
            .as_deref(),
        Some(b"upper".as_slice())
    );
    for path in OPACITY_LOWER_CHILDREN {
        assert!(
            baseline.tree.get(path.as_bytes()).is_none(),
            "{path} survives the baseline"
        );
    }
    let addition = baseline
        .tree
        .get(OPACITY_ADDITION.as_bytes())
        .expect("the opacity addition survives");
    assert_eq!(addition.data.as_deref(), Some(b"added".as_slice()));
    assert_eq!(
        addition.mode, OPACITY_ADDITION_MODE,
        "the opacity addition keeps its own metadata"
    );

    let without_whiteout =
        load(&assemble_variant(&temp, "no-whiteout", Mechanism::Whiteout)).unwrap();
    let survivor = without_whiteout
        .tree
        .get(WHITEOUT_PATH.as_bytes())
        .unwrap_or_else(|| {
            panic!(
                "omitting the whiteout marker did not restore {WHITEOUT_PATH}, so the \
                 marker is not what removed it"
            )
        });
    assert_eq!(survivor.data.as_deref(), Some(WHITEOUT_LOWER));
    assert_eq!(survivor.mode, WHITEOUT_LOWER_MODE);
    assert_eq!((survivor.uid, survivor.gid), WHITEOUT_LOWER_OWNER);
    assert_eq!(survivor.mtime, WHITEOUT_LOWER_MTIME);
    assert_eq!(
        without_whiteout
            .tree
            .get(WHITEOUT_SURVIVOR.as_bytes())
            .and_then(|entry| entry.data.as_deref()),
        Some(b"safe".as_slice()),
        "the whiteout never touched its sibling"
    );

    let without_replacement = load(&assemble_variant(
        &temp,
        "no-replacement",
        Mechanism::Replacement,
    ))
    .unwrap();
    let survivor = without_replacement
        .tree
        .get(REPLACEMENT_PATH.as_bytes())
        .unwrap_or_else(|| {
            panic!(
                "omitting the replacement did not restore {REPLACEMENT_PATH}, so the \
                 replacement is not what replaced it"
            )
        });
    assert_eq!(survivor.data.as_deref(), Some(REPLACEMENT_LOWER));
    assert_eq!(survivor.mode, REPLACEMENT_LOWER_MODE);
    assert_eq!((survivor.uid, survivor.gid), REPLACEMENT_LOWER_OWNER);
    assert_eq!(survivor.mtime, REPLACEMENT_LOWER_MTIME);

    let without_opacity = load(&assemble_variant(&temp, "no-opacity", Mechanism::Opacity)).unwrap();
    assert!(
        without_opacity
            .tree
            .get(OPACITY_DIRECTORY.as_bytes())
            .is_some(),
        "the marked directory itself survives the marker"
    );
    for path in OPACITY_LOWER_CHILDREN {
        assert!(
            without_opacity.tree.get(path.as_bytes()).is_some(),
            "omitting the opaque marker did not restore {path}, so the marker is not \
             what hid it"
        );
    }
    let restored = without_opacity
        .tree
        .get(OPACITY_LOWER_CHILD.as_bytes())
        .expect("the hidden lower child is restored");
    assert_eq!(restored.data.as_deref(), Some(OPACITY_LOWER_CHILD_BYTES));
    assert_eq!(restored.mode, OPACITY_LOWER_CHILD_MODE);
    assert_eq!((restored.uid, restored.gid), OPACITY_LOWER_CHILD_OWNER);
    assert_eq!(restored.mtime, OPACITY_LOWER_MTIME);
    let nested = without_opacity
        .tree
        .get(OPACITY_NESTED.as_bytes())
        .expect("the hidden nested directory is restored");
    assert_eq!(
        nested.kind,
        simferret::workload::EntryKind::Directory,
        "the restored nested directory keeps its kind"
    );
    assert_eq!(nested.mode, OPACITY_NESTED_MODE);
    assert_eq!(nested.mtime, OPACITY_LOWER_MTIME);
    let deep = without_opacity
        .tree
        .get(OPACITY_NESTED_DEEP.as_bytes())
        .expect("the hidden nested file is restored");
    assert_eq!(deep.data.as_deref(), Some(OPACITY_NESTED_DEEP_BYTES));
    assert_eq!(deep.mode, OPACITY_NESTED_DEEP_MODE);
    assert_eq!(deep.mtime, OPACITY_LOWER_MTIME);
}

/// The workload reports exactly the metadata it can observe inside its root.
const CONFORMANCE_SCRIPT: &str = r#"printf 'root %s\n' "$(stat -c '%a %u %g %Y' /)"
printf 'bin %s\n' "$(stat -c '%a %u %g %Y' /bin)"
printf 'busybox %s\n' "$(stat -c '%a %u %g %Y' /bin/busybox)"
printf 'replace %s\n' "$(stat -c '%a %u %g %Y' /replace)"
printf 'keep %s %s\n' "$(stat -c '%a %u %g %Y' /replace/keep)" "$(cat /replace/keep)"
printf 'kept %s %s\n' "$(stat -c '%a %u %g %Y' /hide/kept)" "$(cat /hide/kept)"
printf 'added %s %s\n' "$(stat -c '%a %u %g %Y' /opaque/added)" "$(cat /opaque/added)"
printf 'link %s\n' "$(readlink /link)"
printf 'linkmode %s\n' "$(stat -c '%a %Y' /link)"
if [ -e /hide/removed ]; then printf 'removed=present\n'; else printf 'removed=absent\n'; fi
if [ -e /opaque/lower-child ]; then printf 'lower=present\n'; else printf 'lower=absent\n'; fi
if [ -e /opaque/nested ]; then printf 'nested=present\n'; else printf 'nested=absent\n'; fi
"#;

const CONFORMANCE_EXPECTED: &str = "\
root 755 0 0 0
bin 755 0 0 0
busybox 755 0 0 0
replace 751 2000 2000 1700000003
keep 640 1001 1001 1700000008 upper
kept 644 1200 1200 1700000005 safe
added 644 1300 1300 1700000006 added
link replace/keep
linkmode 777 1700000004
removed=absent
lower=absent
nested=absent
";

// ---------------------------------------------------------------------------
// CPIO decoding, exactly as the guest initramfs extracts the template
// ---------------------------------------------------------------------------

struct CpioEntry {
    name: Vec<u8>,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u32,
    data: Vec<u8>,
}

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
        let name = bytes[name_start..name_start + namesize - 1].to_vec();
        let data_start = (name_start + namesize + 3) & !3;
        let data = bytes[data_start..data_start + filesize].to_vec();
        offset = (data_start + filesize + 3) & !3;
        if name == b"TRAILER!!!" {
            break;
        }
        entries.push(CpioEntry {
            name,
            mode,
            uid,
            gid,
            mtime,
            data,
        });
    }
    entries
}

fn set_owner(path: &Path, entry: &CpioEntry) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `path` is a valid NUL-terminated path and the ids are plain values.
    let result = unsafe { libc::lchown(path.as_ptr(), entry.uid, entry.gid) };
    assert_eq!(
        result,
        0,
        "lchown failed: {}",
        std::io::Error::last_os_error()
    );
}

fn set_mtime(path: &Path, mtime: u32, nofollow: bool) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: i64::from(mtime),
            tv_nsec: 0,
        },
    ];
    let flags = if nofollow {
        libc::AT_SYMLINK_NOFOLLOW
    } else {
        0
    };
    // SAFETY: `path` and `times` are valid for the duration of the call.
    let result = unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), flags) };
    assert_eq!(
        result,
        0,
        "utimensat failed: {}",
        std::io::Error::last_os_error()
    );
}

/// Extract the encoded template into a directory the runtime can materialize,
/// stripping the reserved `workload` root and preserving exactly the metadata
/// the CPIO header carries. Directory timestamps are applied after their
/// children exist, because creating a child updates its parent.
fn extract_template(bytes: &[u8], destination: &Path) {
    let entries = decode_cpio(bytes);
    fs::create_dir_all(destination).unwrap();
    let mut directories: Vec<(PathBuf, &CpioEntry)> = Vec::new();
    for entry in &entries {
        let relative = entry
            .name
            .strip_prefix(b"workload/")
            .or_else(|| entry.name.strip_prefix(b"workload"))
            .unwrap_or(&entry.name);
        let kind = entry.mode & 0o170_000;
        if relative.is_empty() {
            directories.push((destination.to_path_buf(), entry));
            continue;
        }
        let path = destination.join(OsStr::from_bytes(relative));
        match kind {
            0o040_000 => {
                fs::create_dir_all(&path).unwrap();
                directories.push((path, entry));
            }
            0o120_000 => {
                std::os::unix::fs::symlink(OsStr::from_bytes(&entry.data), &path).unwrap();
                set_owner(&path, entry);
                set_mtime(&path, entry.mtime, true);
            }
            _ => {
                fs::write(&path, &entry.data).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(entry.mode & 0o7777))
                    .unwrap();
                set_owner(&path, entry);
                set_mtime(&path, entry.mtime, false);
            }
        }
    }
    let mut by_depth: Vec<&(PathBuf, &CpioEntry)> = directories.iter().collect();
    by_depth.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (path, entry) in &by_depth {
        fs::set_permissions(path, fs::Permissions::from_mode(entry.mode & 0o7777)).unwrap();
        set_owner(path, entry);
    }
    for (path, entry) in &by_depth {
        set_mtime(path, entry.mtime, false);
    }
}

fn stdout_bytes(events: &[Event]) -> Vec<u8> {
    let mut output = Vec::new();
    for event in events {
        if let Event::WorkloadOutput {
            stream: OutputStream::Stdout,
            bytes,
            ..
        } = event
        {
            output.extend_from_slice(&simferret::protocol::decode_bytes(bytes, 4096).unwrap());
        }
    }
    output
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Assemble the checked-in conformance layout and return its store.
fn assemble_conformance(temp: &TempDir) -> PathBuf {
    let layout = temp.join("layout");
    let config = json!({
        "config": {
            "Entrypoint": [INSTALL_PATH, "sh", "-c", CONFORMANCE_SCRIPT],
            "Env": ["PATH=/bin"],
            "User": "1001:1001",
            "WorkingDir": "/",
        }
    });
    let digest = write_layout(&layout, &[base_layer(), upper_layer()], config);
    fs::write(temp.join("workload.toml"), oci_spec("layout", &digest)).unwrap();
    let store = temp.join("store");
    assemble(&temp.join("workload.toml"), &store).unwrap();
    store
}

/// Whether `haystack` contains `needle` anywhere, for byte-level leak checks.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Every regular file below one directory with its bytes, so a test can prove a
/// canary never reaches a retained artifact. The paths are relative to `root`.
fn stored_files(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(&directory).unwrap() {
            let entry = entry.unwrap();
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file() {
                files.push((
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(entry.path()).unwrap(),
                ));
            }
        }
    }
    files.sort();
    files
}

/// Every retained raw object digest, sorted, so two stores can be compared by
/// content rather than by path.
fn raw_object_digests(store: &Path) -> Vec<String> {
    let mut digests = fs::read_dir(store.join("raw/sha256"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    digests.sort();
    digests
}

/// The retained raw closure as parsed JSON, so a test can assert on the values
/// the closure records instead of searching its text for names it never holds.
fn closure_value(store: &Path) -> Value {
    serde_json::from_slice(&fs::read(store.join("raw/closure.json")).unwrap()).unwrap()
}

/// Every entry path in a canonical tree, sorted.
fn tree_paths(tree: &simferret::workload::Tree) -> Vec<String> {
    let mut paths: Vec<String> = tree
        .iter()
        .map(|(path, _)| String::from_utf8_lossy(path).into_owned())
        .collect();
    paths.sort();
    paths
}

/// The credentials the conformance fixture declares. The permission test
/// asserts the loaded launch identity matches them and then decides permissions
/// for that identity, so changing the fixture's `User` cannot leave the check
/// evaluating credentials the runtime does not use.
const CONFORMANCE_UID: u32 = 1001;
const CONFORMANCE_GID: u32 = 1001;

/// Every path the conformance script reads, so a fixture change cannot make the
/// guest run fail on permissions the host suite never checks.
const CONFORMANCE_READ_PATHS: &[&str] = &[
    "/bin/busybox",
    "/replace/keep",
    "/hide/kept",
    "/opaque/added",
];

/// Whether `entry` grants `bit` to the launch credentials. A mode bit is
/// granted by the owner class, the group class, or the other class, and no
/// other class applies because the workload has no supplementary groups.
fn granted(entry: &simferret::workload::Entry, uid: u32, gid: u32, bit: u32) -> bool {
    if entry.uid == uid {
        return entry.mode & (bit << 6) != 0;
    }
    if entry.gid == gid {
        return entry.mode & (bit << 3) != 0;
    }
    entry.mode & bit != 0
}

#[test]
fn the_conformance_workload_can_read_every_path_it_reports() {
    // The guest-visible test returns early without root, so an unreadable
    // fixture would only fail in the root CI job. This test decides the same
    // permissions the runtime grants the workload: every ancestor of a reported
    // path must be searchable and the path itself readable by the launch
    // credentials, and the executable must be executable.
    let temp = TempDir::new("conformance-access");
    let loaded = load(&assemble_conformance(&temp)).unwrap();
    let (uid, gid) = (loaded.launch.uid, loaded.launch.gid);
    assert_eq!(
        (uid, gid),
        (CONFORMANCE_UID, CONFORMANCE_GID),
        "the conformance workload's credentials changed"
    );
    let root = loaded.tree.get(b".").expect("the canonical root exists");
    assert!(
        granted(root, uid, gid, 0o1),
        "the workload cannot traverse the root"
    );
    for path in CONFORMANCE_READ_PATHS {
        let relative = path.strip_prefix('/').expect("paths are absolute");
        let mut prefix = String::new();
        for component in relative.split('/') {
            prefix = if prefix.is_empty() {
                component.to_owned()
            } else {
                format!("{prefix}/{component}")
            };
            let entry = loaded
                .tree
                .get(prefix.as_bytes())
                .unwrap_or_else(|| panic!("{path} has no {prefix}"));
            let needed = if prefix == relative { 0o4 } else { 0o1 };
            assert!(
                granted(entry, uid, gid, needed),
                "{prefix} is not {} for the launch credentials",
                if needed == 0o4 {
                    "readable"
                } else {
                    "searchable"
                }
            );
        }
    }
    let executable = loaded
        .tree
        .get(b"bin/busybox")
        .expect("the executable exists");
    assert!(
        granted(executable, uid, gid, 0o1),
        "the workload cannot execute /bin/busybox"
    );
}

#[test]
fn template_encoding_preserves_oci_conformance_metadata() {
    // The encoded guest template is a pure function of the canonical view, so
    // the CPIO headers must carry the modes, owners, timestamps, link targets,
    // and replacement bytes the layer semantics produced, and must never carry a
    // whiteout or opaque marker.
    let temp = TempDir::new("conformance-encoding");
    let store = assemble_conformance(&temp);
    let loaded = load(&store).unwrap();
    let entries = decode_cpio(&loaded.template);
    let names: Vec<String> = entries
        .iter()
        .map(|entry| String::from_utf8_lossy(&entry.name).into_owned())
        .collect();
    assert_eq!(
        names,
        vec![
            "workload",
            "workload/bin",
            "workload/bin/busybox",
            "workload/bin/cat",
            "workload/bin/readlink",
            "workload/bin/sh",
            "workload/bin/stat",
            "workload/hide",
            "workload/hide/kept",
            "workload/link",
            "workload/opaque",
            "workload/opaque/added",
            "workload/replace",
            "workload/replace/keep",
        ]
    );
    let find = |name: &str| {
        entries
            .iter()
            .find(|entry| entry.name == name.as_bytes())
            .unwrap()
    };

    let root = find("workload");
    assert_eq!(root.mode, 0o040755);
    assert_eq!((root.uid, root.gid, root.mtime), (0, 0, 0));

    let replacement_directory = find("workload/replace");
    assert_eq!(replacement_directory.mode, 0o040751);
    assert_eq!(
        (
            replacement_directory.uid,
            replacement_directory.gid,
            replacement_directory.mtime
        ),
        (2000, 2000, 1_700_000_003)
    );

    let keep = find("workload/replace/keep");
    assert_eq!(keep.mode, 0o100640);
    assert_eq!(
        (keep.uid, keep.gid, keep.mtime),
        (1001, 1001, 1_700_000_008)
    );
    assert_eq!(keep.data, b"upper");

    // The whiteout removes only `removed`; its sibling keeps the lower-layer
    // bytes and metadata the same layer never touched.
    let kept = find("workload/hide/kept");
    assert_eq!(kept.mode, 0o100644);
    assert_eq!(
        (kept.uid, kept.gid, kept.mtime),
        (1200, 1200, 1_700_000_005)
    );
    assert_eq!(kept.data, b"safe");

    // The same-layer addition under an opaque directory survives the marker and
    // keeps its own metadata.
    let added = find("workload/opaque/added");
    assert_eq!(added.mode, 0o100644);
    assert_eq!(
        (added.uid, added.gid, added.mtime),
        (1300, 1300, 1_700_000_006)
    );
    assert_eq!(added.data, b"added");

    let link = find("workload/link");
    assert_eq!(link.mode, 0o120777);
    assert_eq!(link.mtime, 1_700_000_004);
    assert_eq!(link.data, b"replace/keep");

    let busybox = find("workload/bin/busybox");
    assert_eq!(busybox.mode, 0o100755);
}

#[test]
fn canonical_metadata_survives_cpio_encoding_and_is_visible_in_the_guest() {
    if !require_root() {
        return;
    }
    let temp = TempDir::new("conformance");
    let store = assemble_conformance(&temp);
    let loaded = load(&store).unwrap();

    // The host-side canonical view already carries the layer semantics.
    for path in OPACITY_LOWER_CHILDREN {
        assert!(
            loaded.tree.get(path.as_bytes()).is_none(),
            "{path} survives the baseline"
        );
    }
    assert!(loaded.tree.get(WHITEOUT_PATH.as_bytes()).is_none());
    assert!(loaded.tree.get(WHITEOUT_MARKER.as_bytes()).is_none());
    assert!(loaded.tree.get(OPACITY_MARKER.as_bytes()).is_none());
    assert_eq!(
        loaded
            .tree
            .get(WHITEOUT_SURVIVOR.as_bytes())
            .expect("the whiteout leaves its sibling alone")
            .data
            .as_deref(),
        Some(b"safe".as_slice())
    );
    let keep = loaded
        .tree
        .get(REPLACEMENT_PATH.as_bytes())
        .expect("the replacement survives");
    assert_eq!(keep.data.as_deref(), Some(b"upper".as_slice()));
    assert_eq!(
        (keep.mode, keep.uid, keep.gid, keep.mtime),
        (0o640, 1001, 1001, 1_700_000_008)
    );
    assert_eq!(loaded.launch.executable, INSTALL_PATH);

    // The guest template is the encoded canonical view, so extract it exactly as
    // the guest initramfs would and run the packaged workload against it.
    let template_root = temp.join("template");
    extract_template(&loaded.template, &template_root);
    let mut runtime = Runtime::new(RuntimeConfig {
        template_root,
        runtime_root: temp.join("runtime"),
        limits: RuntimeLimits::default(),
        scope: MemberScope::ProcessGroup,
    })
    .unwrap();
    let mut events = runtime.start(1, &loaded.launch);
    for _ in 0..400 {
        events.extend(runtime.poll(Duration::from_millis(50)).unwrap());
        if events
            .iter()
            .any(|event| matches!(event, Event::CleanupComplete { .. }))
        {
            break;
        }
    }
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::CleanupComplete { .. })),
        "the invocation did not reach the cleanup barrier: {events:#?}"
    );
    let observed = String::from_utf8(stdout_bytes(&events)).unwrap();
    assert_eq!(observed, CONFORMANCE_EXPECTED);
}

#[test]
fn ambient_host_environment_never_enters_the_assembled_workload() {
    let temp = TempDir::new("ambient");
    fs::write(temp.join("app"), static_elf()).unwrap();
    fs::write(
        temp.join("workload.toml"),
        binary_spec("app", "1000:1000").replace("env = []", "env = [\"MODE=acceptance\"]"),
    )
    .unwrap();

    let first = assemble(&temp.join("workload.toml"), &temp.join("store-a")).unwrap();
    let loaded = load(&temp.join("store-a")).unwrap();
    // The launch environment is exactly the specification's, so no ambient
    // variable can be inherited whatever this process's environment holds.
    assert_eq!(
        loaded.launch.environment,
        vec!["MODE=acceptance".to_string()]
    );
    assert_eq!(
        closure_value(&temp.join("store-a"))["launch"]["environment"],
        json!(["MODE=acceptance"])
    );

    // A distinctive canary in the assembling process's environment must not
    // reach any retained artifact. The canary is set on a child process, so the
    // assertion neither depends on nor mutates this test process's environment,
    // and the canary value cannot occur in the store by coincidence.
    let canary_name = "SIMFERRET_PHASE4_AMBIENT_CANARY";
    let canary_value = "simferret-phase4-ambient-canary-6f2a1c";
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_simferret"))
        .args(["workload", "assemble", "--specification"])
        .arg(temp.join("workload.toml"))
        .arg("--store")
        .arg(temp.join("store-canary"))
        .env(canary_name, canary_value)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "the canary assembly failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let canary_store = temp.join("store-canary");
    let canary_loaded = load(&canary_store).unwrap();
    assert_eq!(
        canary_loaded.canonical_digest, loaded.canonical_digest,
        "an ambient variable changed the canonical identity"
    );
    assert_eq!(canary_loaded.closure_sha256, first.closure_sha256);
    assert_eq!(canary_loaded.launch.environment, loaded.launch.environment);
    for (path, bytes) in stored_files(&canary_store) {
        for needle in [canary_name.as_bytes(), canary_value.as_bytes()] {
            assert!(
                !contains(&bytes, needle),
                "{} carries {:?}",
                path.display(),
                String::from_utf8_lossy(needle)
            );
        }
    }

    // Assembly is deterministic: a second assembly of the same source
    // reproduces every identity byte for byte.
    let second = assemble(&temp.join("workload.toml"), &temp.join("store-b")).unwrap();
    assert_eq!(first.closure_sha256, second.closure_sha256);
    assert_eq!(first.canonical_digest, second.canonical_digest);
    assert_eq!(first.template_sha256, second.template_sha256);
}

#[test]
fn an_unrelated_host_file_never_enters_the_assembled_workload() {
    // The raw closure records roles, digests, and byte counts and never file
    // names, so searching its text for a name proves nothing. Each source form
    // is therefore assembled twice: once alone, and once with an unrelated
    // regular file beside the binary source and inside the OCI layout
    // directory. Every identity, every retained raw object, the canonical tree,
    // and the encoded guest template must be identical.
    let temp = TempDir::new("unrelated");
    fs::write(temp.join("app"), static_elf()).unwrap();
    fs::write(temp.join("workload.toml"), binary_spec("app", "1000:1000")).unwrap();
    let layout = temp.join("layout");
    let digest = write_layout(
        &layout,
        &[base_layer()],
        json!({"config": {"Entrypoint": [INSTALL_PATH], "User": "1000:1000"}}),
    );
    fs::write(temp.join("oci.toml"), oci_spec("layout", &digest)).unwrap();

    let baseline_binary =
        assemble(&temp.join("workload.toml"), &temp.join("baseline-binary")).unwrap();
    let baseline_oci = assemble(&temp.join("oci.toml"), &temp.join("baseline-oci")).unwrap();
    let baseline_binary_objects = raw_object_digests(&temp.join("baseline-binary"));
    let baseline_oci_objects = raw_object_digests(&temp.join("baseline-oci"));

    fs::write(temp.join("unrelated-host-file"), b"host-marker").unwrap();
    fs::write(layout.join("unrelated-host-file"), b"layout-marker").unwrap();

    let binary = assemble(&temp.join("workload.toml"), &temp.join("store-binary")).unwrap();
    assert_eq!(
        binary.entries, 3,
        "only the root, bin, and the executable are present"
    );
    assert_eq!(binary.entries, baseline_binary.entries);
    assert_eq!(binary.canonical_digest, baseline_binary.canonical_digest);
    assert_eq!(binary.closure_sha256, baseline_binary.closure_sha256);
    assert_eq!(binary.tree_sha256, baseline_binary.tree_sha256);
    assert_eq!(binary.template_sha256, baseline_binary.template_sha256);
    assert_eq!(binary.expanded_bytes, baseline_binary.expanded_bytes);
    assert_eq!(binary.raw_objects, baseline_binary.raw_objects);
    assert_eq!(
        raw_object_digests(&temp.join("store-binary")),
        baseline_binary_objects,
        "an unrelated file beside the source changed the retained objects"
    );

    let oci = assemble(&temp.join("oci.toml"), &temp.join("store-oci")).unwrap();
    assert_eq!(oci.entries, baseline_oci.entries);
    assert_eq!(oci.canonical_digest, baseline_oci.canonical_digest);
    assert_eq!(oci.closure_sha256, baseline_oci.closure_sha256);
    assert_eq!(oci.tree_sha256, baseline_oci.tree_sha256);
    assert_eq!(oci.template_sha256, baseline_oci.template_sha256);
    assert_eq!(oci.expanded_bytes, baseline_oci.expanded_bytes);
    assert_eq!(oci.raw_objects, baseline_oci.raw_objects);
    assert_eq!(
        raw_object_digests(&temp.join("store-oci")),
        baseline_oci_objects,
        "an unrelated file inside the layout changed the retained objects"
    );

    // The canonical tree and the encoded template both name every entry they
    // carry, so neither may name an unrelated file, and no retained byte may
    // carry its content.
    for store in [temp.join("store-binary"), temp.join("store-oci")] {
        let loaded = load(&store).unwrap();
        let paths = tree_paths(&loaded.tree);
        assert!(
            paths.iter().all(|path| !path.contains("unrelated")),
            "{paths:?}"
        );
        let names: Vec<String> = decode_cpio(&loaded.template)
            .iter()
            .map(|entry| String::from_utf8_lossy(&entry.name).into_owned())
            .collect();
        assert!(
            names.iter().all(|name| !name.contains("unrelated")),
            "{names:?}"
        );
        for (path, bytes) in stored_files(&store) {
            for marker in [b"host-marker".as_slice(), b"layout-marker".as_slice()] {
                assert!(
                    !contains(&bytes, marker),
                    "{} carries {:?}",
                    path.display(),
                    String::from_utf8_lossy(marker)
                );
            }
        }
    }
}

#[test]
fn a_host_source_path_never_enters_the_retained_closure() {
    let temp = TempDir::new("host-path");
    fs::write(temp.join("app"), static_elf()).unwrap();
    fs::write(temp.join("workload.toml"), binary_spec("app", "1000:1000")).unwrap();
    let assembled = assemble(&temp.join("workload.toml"), &temp.join("store")).unwrap();
    let store = temp.join("store");

    let root = temp.0.to_str().unwrap();
    // The derived cache entry is a directory, so it has to be walked rather
    // than read as one file: the lock and the encoded template are host-written
    // artifacts that must not name the host path either.
    let derived = store.join("derived").join(&assembled.canonical_digest);
    assert!(
        derived.is_dir(),
        "the derived cache entry must be a directory"
    );
    for name in ["lock.json", "template.cpio", "tree.bin"] {
        let bytes = fs::read(derived.join(name)).unwrap();
        assert!(
            !contains(&bytes, root.as_bytes()),
            "derived/{name} carries the host path"
        );
    }
    let closure = fs::read(store.join("raw/closure.json")).unwrap();
    assert!(
        !contains(&closure, root.as_bytes()),
        "the raw closure carries the host path"
    );
    // No other retained byte may carry it either.
    for (path, bytes) in stored_files(&store) {
        assert!(
            !contains(&bytes, root.as_bytes()),
            "{} carries the host path",
            path.display()
        );
    }
}
