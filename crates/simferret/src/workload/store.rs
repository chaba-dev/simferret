//! Raw content-addressed replay closure and derived cache publication.
//!
//! Assembly writes raw and derived entries through private staging, verifies
//! complete bytes and relationships, and publishes atomically. Replay
//! re-derives the canonical tree from verified raw objects and refuses to fall
//! back to a live source, a derived entry alone, or a store that names a
//! different closure.

use std::collections::BTreeMap;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::oci::{self, LayerEvidence, OciObjects};
use super::root::{Root, invalid, staging_name};
use super::spec::{
    BinarySource, CanonicalBinarySpec, LaunchIdentity, OciSource, SourceKind, normalize_arguments,
    normalize_environment, normalize_required_user, normalize_working_directory, parse_digest,
    validate_launch_identity,
};
use super::tree::{
    Entry, ROOT_PATH, Tree, ancestors, normalize_layer_path, sha256_bytes, validate_canonical_tree,
};
use super::{
    BINARY_INSTALL_PATH, CANONICAL_FORMAT_VERSION, CLOSURE_VERSION, DERIVED_LOCK_VERSION,
    EXTRACTION_POLICY_VERSION, GUEST_TEMPLATE_ROOT, LAYER_APPLICATION_POLICY_VERSION,
    MAX_ARGUMENT_BYTES, MAX_ARGUMENTS, MAX_CACHE_METADATA_BYTES, MAX_CONFIG_BYTES, MAX_ENTRIES,
    MAX_ENVIRONMENT_BYTES, MAX_ENVIRONMENT_ENTRIES, MAX_ENVIRONMENT_ENTRY_BYTES,
    MAX_EXPANDED_LAYER_BYTES, MAX_FILE_BYTES, MAX_INDEX_BYTES, MAX_LAYER_BYTES, MAX_LAYERS,
    MAX_LAYOUT_BYTES, MAX_MANIFEST_BYTES, MAX_PATH_BYTES, MAX_RAW_OBJECTS, MAX_SPECIFICATION_BYTES,
    MAX_SYMLINK_HOPS, MAX_SYMLINK_TARGET_BYTES, MAX_TEMPLATE_BYTES, MAX_VIEW_ENTRIES,
    TEMPLATE_FORMAT_VERSION, WORKLOAD_SPEC_VERSION,
};

pub const RAW_CLOSURE_PATH: &str = "raw/closure.json";

#[derive(Debug)]
pub struct AssembledWorkload {
    pub source_kind: SourceKind,
    pub closure_sha256: String,
    pub canonical_digest: String,
    pub tree_sha256: String,
    pub template_sha256: String,
    pub entries: usize,
    pub expanded_bytes: usize,
    pub raw_objects: usize,
    pub launch: LaunchIdentity,
}

#[derive(Debug)]
pub struct LoadedWorkload {
    pub source_kind: SourceKind,
    pub closure_sha256: String,
    pub canonical_digest: String,
    pub tree: Tree,
    pub template: Vec<u8>,
    pub launch: LaunchIdentity,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub canonical_format: u16,
    pub extraction: u16,
    pub layer_application: u16,
    pub template_format: u16,
}

impl Policy {
    fn current() -> Self {
        Self {
            canonical_format: CANONICAL_FORMAT_VERSION,
            extraction: EXTRACTION_POLICY_VERSION,
            layer_application: LAYER_APPLICATION_POLICY_VERSION,
            template_format: TEMPLATE_FORMAT_VERSION,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub specification_bytes: usize,
    pub layout_bytes: usize,
    pub index_bytes: usize,
    pub manifest_bytes: usize,
    pub config_bytes: usize,
    pub layer_bytes: usize,
    pub expanded_layer_bytes: usize,
    pub file_bytes: usize,
    pub entries: usize,
    pub layers: usize,
    pub path_bytes: usize,
    pub symlink_target_bytes: usize,
    pub symlink_hops: usize,
    pub raw_objects: usize,
    pub view_entries: usize,
    pub cache_metadata_bytes: usize,
    pub template_bytes: usize,
    pub arguments: usize,
    pub argument_bytes: usize,
    pub environment_entries: usize,
    pub environment_entry_bytes: usize,
    pub environment_bytes: usize,
}

impl Limits {
    fn current() -> Self {
        Self {
            specification_bytes: MAX_SPECIFICATION_BYTES,
            layout_bytes: MAX_LAYOUT_BYTES,
            index_bytes: MAX_INDEX_BYTES,
            manifest_bytes: MAX_MANIFEST_BYTES,
            config_bytes: MAX_CONFIG_BYTES,
            layer_bytes: MAX_LAYER_BYTES,
            expanded_layer_bytes: MAX_EXPANDED_LAYER_BYTES,
            file_bytes: MAX_FILE_BYTES,
            entries: MAX_ENTRIES,
            layers: MAX_LAYERS,
            path_bytes: MAX_PATH_BYTES,
            symlink_target_bytes: MAX_SYMLINK_TARGET_BYTES,
            symlink_hops: MAX_SYMLINK_HOPS,
            raw_objects: MAX_RAW_OBJECTS,
            view_entries: MAX_VIEW_ENTRIES,
            cache_metadata_bytes: MAX_CACHE_METADATA_BYTES,
            template_bytes: MAX_TEMPLATE_BYTES,
            arguments: MAX_ARGUMENTS,
            argument_bytes: MAX_ARGUMENT_BYTES,
            environment_entries: MAX_ENVIRONMENT_ENTRIES,
            environment_entry_bytes: MAX_ENVIRONMENT_ENTRY_BYTES,
            environment_bytes: MAX_ENVIRONMENT_BYTES,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ObjectRecord {
    role: String,
    digest: String,
    bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Closure {
    version: u16,
    kind: SourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    manifest_digest: Option<String>,
    policy: Policy,
    limits: Limits,
    objects: Vec<ObjectRecord>,
    layers: Vec<LayerEvidence>,
    launch: LaunchIdentity,
    canonical_digest: String,
    tree_sha256: String,
    template_sha256: String,
    entries: usize,
    expanded_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DerivedLock {
    version: u16,
    canonical_digest: String,
    tree_sha256: String,
    template_sha256: String,
    closure_sha256: String,
    raw_closure: String,
}

struct WorkloadGraph {
    kind: SourceKind,
    manifest_digest: Option<String>,
    objects: Vec<(String, Vec<u8>)>,
    tree: Tree,
    launch: LaunchIdentity,
    layers: Vec<LayerEvidence>,
}

struct BinaryInput {
    install_path: String,
    arguments: Vec<String>,
    environment: Vec<String>,
    working_directory: String,
    uid: u32,
    gid: u32,
}

/// Read one workload specification, normalize its source into a canonical
/// workload, and publish the raw closure and derived cache entry atomically.
///
/// Source objects are read through one directory descriptor opened at the
/// specification's directory, so every component of a source locator is
/// traversed without following a symbolic link.
pub fn assemble(specification: &Path, store: &Path) -> io::Result<AssembledWorkload> {
    let spec = super::WorkloadSpec::read(specification)?;
    let directory = specification
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    let root = Root::open(&directory)?;
    let graph = match &spec.source {
        super::WorkloadSource::Binary(source) => binary_graph(&root, source)?,
        super::WorkloadSource::Oci(source) => oci_graph(&root, source)?,
    };
    publish(store, graph)
}

/// Verify the complete raw closure and the derived cache entry, then return the
/// canonical tree and encoded guest template. No live source is consulted.
pub fn load(store: &Path) -> io::Result<LoadedWorkload> {
    let root = Root::open(store)?;
    let closure_bytes = read_required(
        &root,
        RAW_CLOSURE_PATH,
        MAX_CACHE_METADATA_BYTES,
        &format!("raw closure {RAW_CLOSURE_PATH}"),
    )?;
    let closure_sha256 = sha256_bytes(&closure_bytes);
    let closure: Closure = serde_json::from_slice(&closure_bytes)
        .map_err(|error| crate::diagnostics::json_error("malformed raw closure", &error))?;
    if closure.version != CLOSURE_VERSION {
        return Err(invalid(format!(
            "unsupported raw closure version {}",
            closure.version
        )));
    }
    if closure.policy != Policy::current() {
        return Err(invalid(
            "raw closure was recorded under a different policy version",
        ));
    }
    if closure.limits != Limits::current() {
        return Err(invalid("raw closure was recorded under different limits"));
    }
    let objects = read_objects(&root, &closure)?;
    let graph = replay_graph(&closure, &objects)?;
    super::validate_overlay_compatibility(&graph.tree, &graph.launch)?;
    if graph.launch != closure.launch {
        return Err(invalid(
            "re-derived launch identity does not match the raw closure",
        ));
    }
    if graph.layers != closure.layers {
        return Err(invalid(
            "re-derived layer evidence does not match the raw closure",
        ));
    }
    let canonical_digest = graph.tree.canonical_digest();
    if canonical_digest != closure.canonical_digest {
        return Err(invalid(
            "re-derived canonical digest does not match the raw closure",
        ));
    }
    let tree_bytes = graph.tree.encode();
    if sha256_bytes(&tree_bytes) != closure.tree_sha256 {
        return Err(invalid(
            "re-derived tree manifest does not match the raw closure",
        ));
    }
    let template = graph.tree.template(GUEST_TEMPLATE_ROOT)?;
    if sha256_bytes(&template) != closure.template_sha256 {
        return Err(invalid(
            "re-derived guest template does not match the raw closure",
        ));
    }
    if graph.tree.len() != closure.entries || graph.tree.expanded_bytes() != closure.expanded_bytes
    {
        return Err(invalid(
            "re-derived canonical tree does not match the raw closure",
        ));
    }
    verify_derived(
        &root,
        &canonical_digest,
        &tree_bytes,
        &closure.template_sha256,
        &closure_sha256,
        &closure.tree_sha256,
    )?;
    Ok(LoadedWorkload {
        source_kind: closure.kind,
        closure_sha256,
        canonical_digest,
        tree: graph.tree,
        template,
        launch: closure.launch,
    })
}

fn binary_graph(root: &Root, source: &BinarySource) -> io::Result<WorkloadGraph> {
    let executable = root.read_file(&source.path, MAX_FILE_BYTES)?;
    super::validate_static_elf(&executable)?;
    let (uid, gid) = normalize_required_user(&source.user)?;
    let install = normalize_layer_path(BINARY_INSTALL_PATH.as_bytes())?;
    let executable_text = format!(
        "/{}",
        std::str::from_utf8(&install).expect("fixed install path is ASCII")
    );
    let mut arguments = vec![executable_text];
    arguments.extend(normalize_arguments(&source.arguments, "args")?);
    let input = BinaryInput {
        install_path: BINARY_INSTALL_PATH.to_owned(),
        arguments,
        environment: normalize_environment(&source.environment)?,
        working_directory: source.working_directory.clone(),
        uid,
        gid,
    };
    let (tree, launch) = binary_tree_and_launch(&executable, &input)?;
    let canonical = CanonicalBinarySpec {
        version: WORKLOAD_SPEC_VERSION,
        kind: SourceKind::Binary,
        install_path: input.install_path,
        arguments: launch.arguments.clone(),
        environment: launch.environment.clone(),
        working_directory: launch.working_directory.clone(),
        uid,
        gid,
    };
    let specification = canonical_json(&canonical)?;
    let mut objects = vec![
        ("executable".to_owned(), executable),
        ("workload-specification".to_owned(), specification),
    ];
    objects.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(WorkloadGraph {
        kind: SourceKind::Binary,
        manifest_digest: None,
        objects,
        tree,
        launch,
        layers: Vec::new(),
    })
}

fn binary_tree_and_launch(
    executable: &[u8],
    input: &BinaryInput,
) -> io::Result<(Tree, LaunchIdentity)> {
    if input.uid == 0 || input.gid == 0 {
        return Err(invalid("root credentials are not supported"));
    }
    if input.uid == super::RESERVED_OWNER || input.gid == super::RESERVED_OWNER {
        return Err(invalid(
            "the reserved owner identifier is not a launch credential",
        ));
    }
    // The binary profile installs at one fixed path. Assembly always uses it,
    // and replay re-derives from the retained canonical specification, so the
    // same invariant is enforced here for both directions.
    if input.install_path != BINARY_INSTALL_PATH {
        return Err(invalid(format!(
            "binary install path must be {BINARY_INSTALL_PATH:?}"
        )));
    }
    let install = normalize_layer_path(input.install_path.as_bytes())?;
    if install == ROOT_PATH {
        return Err(invalid("binary install path must name a file"));
    }
    let executable_text = format!(
        "/{}",
        std::str::from_utf8(&install).map_err(|_| invalid("binary install path is not UTF-8"))?
    );
    let arguments = normalize_arguments(&input.arguments, "arguments")?;
    if arguments.first().map(String::as_str) != Some(executable_text.as_str()) {
        return Err(invalid(
            "binary argument vector must begin with the installed executable",
        ));
    }
    let environment = normalize_environment(&input.environment)?;
    let mut tree = Tree::new();
    tree.insert_default_directory(ROOT_PATH);
    for ancestor in ancestors(&install) {
        tree.insert_default_directory(&ancestor);
    }
    tree.insert(
        install,
        Entry::file(executable.to_vec(), 0o755, input.uid, input.gid, 0),
    );
    let working_directory = normalize_working_directory(Some(&input.working_directory), &tree)?;
    validate_canonical_tree(&tree, MAX_VIEW_ENTRIES, MAX_EXPANDED_LAYER_BYTES)?;
    let launch = LaunchIdentity {
        executable: executable_text,
        arguments,
        environment,
        working_directory,
        uid: input.uid,
        gid: input.gid,
    };
    validate_launch_identity(&launch)?;
    Ok((tree, launch))
}

fn oci_graph(root: &Root, source: &OciSource) -> io::Result<WorkloadGraph> {
    let layout = root.open_directory(&source.layout)?;
    let objects = oci::read_objects(&layout, &source.manifest_digest)?;
    let graph = oci::parse_graph(&objects)?;
    Ok(WorkloadGraph {
        kind: SourceKind::Oci,
        manifest_digest: Some(objects.manifest_digest.clone()),
        objects: oci_roles(&objects),
        tree: graph.tree,
        launch: graph.launch,
        layers: graph.layers,
    })
}

fn oci_roles(objects: &OciObjects) -> Vec<(String, Vec<u8>)> {
    let mut roles = vec![
        ("oci-layout".to_owned(), objects.layout.clone()),
        ("index.json".to_owned(), objects.index.clone()),
        ("manifest".to_owned(), objects.manifest.clone()),
        ("config".to_owned(), objects.config.clone()),
    ];
    for (position, layer) in objects.layers.iter().enumerate() {
        roles.push((format!("layer-{position}"), layer.clone()));
    }
    roles.sort_by(|left, right| left.0.cmp(&right.0));
    roles
}

fn publish(store: &Path, graph: WorkloadGraph) -> io::Result<AssembledWorkload> {
    validate_canonical_tree(&graph.tree, MAX_VIEW_ENTRIES, MAX_EXPANDED_LAYER_BYTES)?;
    super::validate_overlay_compatibility(&graph.tree, &graph.launch)?;
    let expanded_bytes = graph.tree.expanded_bytes();
    let canonical_digest = graph.tree.canonical_digest();
    let tree_bytes = graph.tree.encode();
    if tree_bytes.len() > MAX_CACHE_METADATA_BYTES {
        return Err(invalid(format!(
            "canonical tree manifest exceeds {MAX_CACHE_METADATA_BYTES} bytes"
        )));
    }
    let template = graph.tree.template(GUEST_TEMPLATE_ROOT)?;
    if template.len() > MAX_TEMPLATE_BYTES {
        return Err(invalid(format!(
            "guest template exceeds {MAX_TEMPLATE_BYTES} bytes"
        )));
    }
    let tree_sha256 = sha256_bytes(&tree_bytes);
    let template_sha256 = sha256_bytes(&template);

    if graph.objects.len() > MAX_RAW_OBJECTS {
        return Err(invalid(format!(
            "raw closure has more than {MAX_RAW_OBJECTS} objects"
        )));
    }
    let mut records = Vec::with_capacity(graph.objects.len());
    for (index, (role, data)) in graph.objects.iter().enumerate() {
        let Some(limit) = role_limit(role) else {
            return Err(invalid(format!(
                "assembled raw closure object {index} names an unknown role"
            )));
        };
        if data.len() > limit {
            return Err(invalid(format!(
                "raw object {index} exceeds its {limit}-byte policy limit"
            )));
        }
        records.push(ObjectRecord {
            role: role.clone(),
            digest: format!("sha256:{}", sha256_bytes(data)),
            bytes: data.len(),
        });
    }

    let closure = Closure {
        version: CLOSURE_VERSION,
        kind: graph.kind,
        manifest_digest: graph.manifest_digest.clone(),
        policy: Policy::current(),
        limits: Limits::current(),
        objects: records,
        layers: graph.layers.clone(),
        launch: graph.launch.clone(),
        canonical_digest: canonical_digest.clone(),
        tree_sha256: tree_sha256.clone(),
        template_sha256: template_sha256.clone(),
        entries: graph.tree.len(),
        expanded_bytes,
    };
    let closure_bytes = canonical_json(&closure)?;
    if closure_bytes.len() > MAX_CACHE_METADATA_BYTES {
        return Err(invalid(format!(
            "raw closure record exceeds {MAX_CACHE_METADATA_BYTES} bytes"
        )));
    }
    let closure_sha256 = sha256_bytes(&closure_bytes);

    // The store is created owner-only, and the raw closure is published last so
    // a failure part-way through never leaves a committed closure without the
    // derived entry it names. An incomplete candidate is retried idempotently.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(store)?;
    // Every pre-existing store path is revalidated against the private-store
    // contract instead of being reused with weaker permissions: the root here,
    // each directory in `Root::open_or_create_beneath`, and every artifact
    // reused below.
    let root = Root::open_private(store)?;
    if let Some(existing) = root.read_file_if_exists(RAW_CLOSURE_PATH, MAX_CACHE_METADATA_BYTES)?
        && existing != closure_bytes
    {
        return Err(invalid(
            "store already contains a different raw closure; use a separate store per workload",
        ));
    }
    // Revalidate the raw object directory before any object is written or
    // reused: a reused object is read without reopening its parent, so a
    // pre-existing `raw/sha256` must already be owner-only.
    root.open_or_create_directory("raw/sha256")?;
    for (_, data) in &graph.objects {
        write_object(&root, data)?;
    }
    publish_derived(
        &root,
        &canonical_digest,
        &tree_bytes,
        &template,
        &closure_sha256,
        &tree_sha256,
        &template_sha256,
    )?;
    require_private_derived(&root, &canonical_digest)?;
    // The derived entry must name this closure before the closure is committed.
    // Otherwise a concurrent builder whose closure differs but whose canonical
    // tree matches could leave the store naming a derived entry it does not own.
    verify_derived(
        &root,
        &canonical_digest,
        &tree_bytes,
        &template_sha256,
        &closure_sha256,
        &tree_sha256,
    )?;
    publish_closure(&root, &closure_bytes)?;
    Ok(AssembledWorkload {
        source_kind: graph.kind,
        closure_sha256,
        canonical_digest,
        tree_sha256,
        template_sha256,
        entries: graph.tree.len(),
        expanded_bytes,
        raw_objects: graph.objects.len(),
        launch: graph.launch,
    })
}

fn replay_graph(
    closure: &Closure,
    objects: &BTreeMap<String, Vec<u8>>,
) -> io::Result<WorkloadGraph> {
    match closure.kind {
        SourceKind::Binary => {
            let specification = objects
                .get("workload-specification")
                .ok_or_else(|| invalid("binary closure has no workload-specification object"))?;
            let executable = objects
                .get("executable")
                .ok_or_else(|| invalid("binary closure has no executable object"))?;
            if objects.len() != 2 {
                return Err(invalid("binary closure names unexpected objects"));
            }
            let canonical: CanonicalBinarySpec =
                serde_json::from_slice(specification).map_err(|error| {
                    crate::diagnostics::json_error("malformed canonical specification", &error)
                })?;
            if canonical.version != WORKLOAD_SPEC_VERSION || canonical.kind != SourceKind::Binary {
                return Err(invalid("canonical specification is not a version-1 binary"));
            }
            super::validate_static_elf(executable)?;
            let input = BinaryInput {
                install_path: canonical.install_path,
                arguments: canonical.arguments,
                environment: canonical.environment,
                working_directory: canonical.working_directory,
                uid: canonical.uid,
                gid: canonical.gid,
            };
            let (tree, launch) = binary_tree_and_launch(executable, &input)?;
            let mut role_objects = objects
                .iter()
                .map(|(role, data)| (role.clone(), data.clone()))
                .collect::<Vec<_>>();
            role_objects.sort_by(|left, right| left.0.cmp(&right.0));
            Ok(WorkloadGraph {
                kind: SourceKind::Binary,
                manifest_digest: None,
                objects: role_objects,
                tree,
                launch,
                layers: Vec::new(),
            })
        }
        SourceKind::Oci => {
            // The recorded digest is a raw closure value, so it is validated
            // before it can reach a diagnostic that names it.
            let raw_digest = closure
                .manifest_digest
                .clone()
                .ok_or_else(|| invalid("OCI closure has no manifest digest"))?;
            let hex = super::spec::parse_digest(&raw_digest)
                .map_err(|_| invalid("the OCI closure manifest digest is not a sha256 digest"))?;
            let manifest_digest = format!("sha256:{hex}");
            let layer_count = closure.layers.len();
            let expected = expected_oci_roles(layer_count);
            if objects.len() != expected.len()
                || !expected.iter().all(|role| objects.contains_key(role))
            {
                return Err(invalid("OCI closure names unexpected objects"));
            }
            let mut layers = Vec::with_capacity(layer_count);
            for position in 0..layer_count {
                layers.push(
                    objects
                        .get(&format!("layer-{position}"))
                        .ok_or_else(|| invalid("OCI closure is missing a layer object"))?
                        .clone(),
                );
            }
            let oci_objects = OciObjects {
                layout: objects["oci-layout"].clone(),
                index: objects["index.json"].clone(),
                manifest: objects["manifest"].clone(),
                config: objects["config"].clone(),
                layers,
                manifest_digest: manifest_digest.clone(),
            };
            let graph = oci::parse_graph(&oci_objects)?;
            let mut role_objects = objects
                .iter()
                .map(|(role, data)| (role.clone(), data.clone()))
                .collect::<Vec<_>>();
            role_objects.sort_by(|left, right| left.0.cmp(&right.0));
            Ok(WorkloadGraph {
                kind: SourceKind::Oci,
                manifest_digest: Some(manifest_digest),
                objects: role_objects,
                tree: graph.tree,
                launch: graph.launch,
                layers: graph.layers,
            })
        }
    }
}

fn expected_oci_roles(layer_count: usize) -> Vec<String> {
    let mut roles = vec![
        "config".to_owned(),
        "index.json".to_owned(),
        "manifest".to_owned(),
        "oci-layout".to_owned(),
    ];
    for position in 0..layer_count {
        roles.push(format!("layer-{position}"));
    }
    roles
}

fn read_objects(root: &Root, closure: &Closure) -> io::Result<BTreeMap<String, Vec<u8>>> {
    if closure.objects.len() > MAX_RAW_OBJECTS {
        return Err(invalid(format!(
            "raw closure has more than {MAX_RAW_OBJECTS} objects"
        )));
    }
    let mut objects = BTreeMap::new();
    for (index, record) in closure.objects.iter().enumerate() {
        let Some(limit) = role_limit(&record.role) else {
            // The role is an arbitrary string from a private artifact, so the
            // diagnostic names the object's position instead of its value.
            return Err(invalid(format!(
                "raw closure object {index} names an unknown role"
            )));
        };
        if record.bytes > limit {
            return Err(invalid(format!(
                "raw object {index} exceeds the {limit}-byte policy limit"
            )));
        }
        let hex = parse_digest(&record.digest)?;
        if objects.contains_key(&record.role) {
            return Err(invalid(format!(
                "raw closure object {index} repeats the role of an earlier object"
            )));
        }
        let data = read_required(
            root,
            &format!("raw/sha256/{hex}"),
            record.bytes,
            &format!("raw object {}", record.digest),
        )?;
        if data.len() != record.bytes || sha256_bytes(&data) != hex {
            return Err(invalid(format!(
                "raw object {} does not match its recorded identity",
                record.digest
            )));
        }
        objects.insert(record.role.clone(), data);
    }
    Ok(objects)
}

fn role_limit(role: &str) -> Option<usize> {
    match role {
        "oci-layout" => Some(MAX_LAYOUT_BYTES),
        "index.json" => Some(MAX_INDEX_BYTES),
        "manifest" => Some(MAX_MANIFEST_BYTES),
        "config" => Some(MAX_CONFIG_BYTES),
        "executable" => Some(MAX_FILE_BYTES),
        "workload-specification" => Some(MAX_SPECIFICATION_BYTES),
        _ => match role.strip_prefix("layer-") {
            Some(index) if !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit()) => {
                Some(MAX_LAYER_BYTES)
            }
            _ => None,
        },
    }
}

fn write_object(root: &Root, data: &[u8]) -> io::Result<()> {
    let digest = sha256_bytes(data);
    let path = format!("raw/sha256/{digest}");
    match root.read_file_if_exists(&path, data.len())? {
        Some(existing) => {
            if existing != data {
                return Err(invalid(format!("existing raw object {digest} is corrupt")));
            }
            // A reused object must already be owner-only, like a published one.
            root.require_private_file(&path)?;
            Ok(())
        }
        None => root.write_file_atomic(&path, data),
    }
}

fn publish_closure(root: &Root, bytes: &[u8]) -> io::Result<()> {
    if root.publish_exclusive(RAW_CLOSURE_PATH, bytes)? {
        return Ok(());
    }
    let existing = root.read_file(RAW_CLOSURE_PATH, MAX_CACHE_METADATA_BYTES)?;
    if existing == bytes {
        root.require_private_file(RAW_CLOSURE_PATH)?;
        Ok(())
    } else {
        Err(invalid(
            "store already contains a different raw closure; use a separate store per workload",
        ))
    }
}

/// Require a reused derived cache entry to be owner-only.
///
/// `publish_derived` accepts a derived entry that another builder already
/// published, so the entry is revalidated here rather than assumed to have been
/// written by this process.
fn require_private_derived(root: &Root, canonical_digest: &str) -> io::Result<()> {
    let base = format!("derived/{canonical_digest}");
    root.require_private_directory(&base)?;
    for name in ["tree.bin", "template.cpio", "lock.json"] {
        root.require_private_file(&format!("{base}/{name}"))?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn publish_derived(
    root: &Root,
    canonical_digest: &str,
    tree_bytes: &[u8],
    template: &[u8],
    closure_sha256: &str,
    tree_sha256: &str,
    template_sha256: &str,
) -> io::Result<()> {
    let lock = DerivedLock {
        version: DERIVED_LOCK_VERSION,
        canonical_digest: canonical_digest.to_owned(),
        tree_sha256: tree_sha256.to_owned(),
        template_sha256: template_sha256.to_owned(),
        closure_sha256: closure_sha256.to_owned(),
        raw_closure: RAW_CLOSURE_PATH.to_owned(),
    };
    let lock_bytes = canonical_json(&lock)?;
    if lock_bytes.len() > MAX_CACHE_METADATA_BYTES {
        return Err(invalid(format!(
            "derived lock exceeds {MAX_CACHE_METADATA_BYTES} bytes"
        )));
    }
    root.open_or_create_directory("derived")?;
    let staging = format!("derived/{}", staging_name(canonical_digest));
    root.create_directory(&staging)?;
    let written = (|| -> io::Result<()> {
        root.write_file_atomic(&format!("{staging}/tree.bin"), tree_bytes)?;
        root.write_file_atomic(&format!("{staging}/template.cpio"), template)?;
        root.write_file_atomic(&format!("{staging}/lock.json"), &lock_bytes)?;
        Ok(())
    })();
    if let Err(error) = written {
        cleanup_staging(root, &staging);
        return Err(error);
    }
    let destination = format!("derived/{canonical_digest}");
    match root.rename(&staging, &destination) {
        Ok(()) => Ok(()),
        Err(error) => {
            cleanup_staging(root, &staging);
            if root.exists(&destination)? {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

fn cleanup_staging(root: &Root, staging: &str) {
    let _ = root.remove_file_if_exists(&format!("{staging}/tree.bin"));
    let _ = root.remove_file_if_exists(&format!("{staging}/template.cpio"));
    let _ = root.remove_file_if_exists(&format!("{staging}/lock.json"));
    let _ = root.remove_directory_if_exists(staging);
}

fn verify_derived(
    root: &Root,
    canonical_digest: &str,
    tree_bytes: &[u8],
    template_sha256: &str,
    closure_sha256: &str,
    tree_sha256: &str,
) -> io::Result<()> {
    let base = format!("derived/{canonical_digest}");
    let stored_tree = read_required(
        root,
        &format!("{base}/tree.bin"),
        MAX_CACHE_METADATA_BYTES,
        "derived tree manifest",
    )?;
    if stored_tree != tree_bytes {
        return Err(invalid(
            "derived cache entry does not match the raw closure",
        ));
    }
    let stored_template = root
        .sha256_file(&format!("{base}/template.cpio"), MAX_TEMPLATE_BYTES)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                invalid("derived guest template is missing")
            } else {
                error
            }
        })?;
    if stored_template != template_sha256 {
        return Err(invalid(
            "derived guest template does not match the raw closure",
        ));
    }
    let lock_bytes = read_required(
        root,
        &format!("{base}/lock.json"),
        MAX_CACHE_METADATA_BYTES,
        "derived lock",
    )?;
    let lock: DerivedLock = serde_json::from_slice(&lock_bytes)
        .map_err(|error| crate::diagnostics::json_error("malformed derived lock", &error))?;
    if lock.version != DERIVED_LOCK_VERSION
        || lock.canonical_digest != canonical_digest
        || lock.tree_sha256 != tree_sha256
        || lock.template_sha256 != template_sha256
        || lock.closure_sha256 != closure_sha256
        || lock.raw_closure != RAW_CLOSURE_PATH
    {
        return Err(invalid(
            "derived cache entry does not name this raw closure",
        ));
    }
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| invalid(format!("cannot serialize canonical metadata: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn read_required(root: &Root, path: &str, limit: usize, what: &str) -> io::Result<Vec<u8>> {
    root.read_file(path, limit).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            invalid(format!("{what} is missing"))
        } else {
            error
        }
    })
}
