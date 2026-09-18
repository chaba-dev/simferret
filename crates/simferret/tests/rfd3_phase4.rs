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
/// lower-layer entries the upper layer replaces, removes, or hides.
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
        // 0751 keeps the directory traversable for the workload's "other" class
        // while proving a non-default mode, owner, and timestamp survive.
        Member {
            mode: 0o751,
            uid: 2000,
            gid: 2000,
            mtime: 1_700_000_003,
            ..directory("data")
        },
        file_with("data/keep", b"base", 0o600, 1000, 1000, 1_700_000_007),
        file_with("data/removed", b"gone", 0o600, 0, 0, 1_700_000_001),
        directory("data/sub"),
        file_with("data/sub/child", b"child", 0o644, 0, 0, 1_700_000_001),
        file_with("data/lower-only", b"lower", 0o644, 0, 0, 1_700_000_001),
    ]
}

/// The upper layer legally replaces one file, whiteouts one lower path, marks
/// `data` opaque so every remaining lower child is hidden, and adds a symlink.
/// The markers appear after the additions they coexist with, so an
/// implementation that applied markers in archive order would delete the
/// same-layer addition and change the asserted tree.
fn upper_layer() -> Vec<Member> {
    vec![
        Member {
            mode: 0o751,
            uid: 2000,
            gid: 2000,
            mtime: 1_700_000_003,
            ..directory("data")
        },
        file_with("data/keep", b"upper", 0o640, 1001, 1001, 1_700_000_008),
        file_with("data/.wh.removed", b"", 0o644, 0, 0, 0),
        file_with("data/.wh..wh..opq", b"", 0o644, 0, 0, 0),
        symlink("link", "data/keep", 1_700_000_004),
    ]
}

/// The workload reports exactly the metadata it can observe inside its root.
const CONFORMANCE_SCRIPT: &str = r#"printf 'root %s\n' "$(stat -c '%a %u %g %Y' /)"
printf 'bin %s\n' "$(stat -c '%a %u %g %Y' /bin)"
printf 'busybox %s\n' "$(stat -c '%a %u %g %Y' /bin/busybox)"
printf 'data %s\n' "$(stat -c '%a %u %g %Y' /data)"
printf 'keep %s %s\n' "$(stat -c '%a %u %g %Y' /data/keep)" "$(cat /data/keep)"
printf 'link %s\n' "$(readlink /link)"
printf 'linkmode %s\n' "$(stat -c '%a %Y' /link)"
if [ -e /data/removed ]; then printf 'removed=present\n'; else printf 'removed=absent\n'; fi
if [ -e /data/sub ]; then printf 'sub=present\n'; else printf 'sub=absent\n'; fi
if [ -e /data/lower-only ]; then printf 'lower=present\n'; else printf 'lower=absent\n'; fi
"#;

const CONFORMANCE_EXPECTED: &str = "\
root 755 0 0 0
bin 755 0 0 0
busybox 755 0 0 0
data 751 2000 2000 1700000003
keep 640 1001 1001 1700000008 upper
link data/keep
linkmode 777 1700000004
removed=absent
sub=absent
lower=absent
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
            "workload/data",
            "workload/data/keep",
            "workload/link",
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

    let data = find("workload/data");
    assert_eq!(data.mode, 0o040751);
    assert_eq!(
        (data.uid, data.gid, data.mtime),
        (2000, 2000, 1_700_000_003)
    );

    let keep = find("workload/data/keep");
    assert_eq!(keep.mode, 0o100640);
    assert_eq!(
        (keep.uid, keep.gid, keep.mtime),
        (1001, 1001, 1_700_000_008)
    );
    assert_eq!(keep.data, b"upper");

    let link = find("workload/link");
    assert_eq!(link.mode, 0o120777);
    assert_eq!(link.mtime, 1_700_000_004);
    assert_eq!(link.data, b"data/keep");

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
    assert!(loaded.tree.get(b"data/removed").is_none());
    assert!(loaded.tree.get(b"data/sub").is_none());
    assert!(loaded.tree.get(b"data/lower-only").is_none());
    assert!(loaded.tree.get(b"data/.wh.removed").is_none());
    assert!(loaded.tree.get(b"data/.wh..wh..opq").is_none());
    let keep = loaded
        .tree
        .get(b"data/keep")
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
    // variable is inherited.
    assert_eq!(
        loaded.launch.environment,
        vec!["MODE=acceptance".to_string()]
    );

    // No ambient variable name or value reaches the retained closure. The
    // canaries are the test process's own environment values, so this holds
    // without mutating the environment of a parallel test process.
    let closure = fs::read_to_string(temp.join("store-a/raw/closure.json")).unwrap();
    for name in ["PATH", "HOME"] {
        if let Ok(value) = std::env::var(name)
            && !value.is_empty()
        {
            assert!(
                !closure.contains(&value),
                "the {name} value entered the closure: {closure}"
            );
        }
        assert!(!closure.contains(&format!("{name}=")), "{closure}");
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
    let temp = TempDir::new("unrelated");
    fs::write(temp.join("app"), static_elf()).unwrap();
    fs::write(temp.join("workload.toml"), binary_spec("app", "1000:1000")).unwrap();
    // An unrelated regular file beside the source and an unrelated blob in an
    // OCI layout must not enter the closure.
    fs::write(temp.join("unrelated-host-file"), b"host-marker").unwrap();

    let layout = temp.join("layout");
    let digest = write_layout(
        &layout,
        &[base_layer()],
        json!({"config": {"Entrypoint": [INSTALL_PATH], "User": "1000:1000"}}),
    );
    fs::write(temp.join("layout/unrelated-host-file"), b"layout-marker").unwrap();
    fs::write(temp.join("oci.toml"), oci_spec("layout", &digest)).unwrap();

    let binary = assemble(&temp.join("workload.toml"), &temp.join("store-binary")).unwrap();
    assert_eq!(
        binary.entries, 3,
        "only the root, bin, and the executable are present"
    );
    let binary_closure = fs::read_to_string(temp.join("store-binary/raw/closure.json")).unwrap();
    assert!(
        !binary_closure.contains("unrelated-host-file"),
        "{binary_closure}"
    );

    let oci = assemble(&temp.join("oci.toml"), &temp.join("store-oci")).unwrap();
    assert!(
        !oci.tree_sha256.is_empty(),
        "the OCI source assembles without the unrelated layout file"
    );
    let oci_closure = fs::read_to_string(temp.join("store-oci/raw/closure.json")).unwrap();
    assert!(
        !oci_closure.contains("unrelated-host-file"),
        "{oci_closure}"
    );
}

#[test]
fn a_host_source_path_never_enters_the_retained_closure() {
    let temp = TempDir::new("host-path");
    fs::write(temp.join("app"), static_elf()).unwrap();
    fs::write(temp.join("workload.toml"), binary_spec("app", "1000:1000")).unwrap();
    assemble(&temp.join("workload.toml"), &temp.join("store")).unwrap();

    let root = temp.0.to_str().unwrap();
    for name in ["raw/closure.json", "derived"] {
        let path = temp.join("store").join(name);
        if path.is_file() {
            let contents = fs::read_to_string(&path).unwrap();
            assert!(
                !contents.contains(root),
                "{name} carries the host path: {contents}"
            );
        }
    }
    let closure = fs::read_to_string(temp.join("store/raw/closure.json")).unwrap();
    assert!(!closure.contains(root), "{closure}");
}
