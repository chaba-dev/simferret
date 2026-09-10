//! Local OCI image-layout parsing and bounded layer application.
//!
//! Only a direct `linux/amd64` image manifest is selected. Unrelated index
//! entries and blobs are ignored even when they use unsupported media types or
//! refer to unavailable content, but every selected descriptor's media type,
//! size, and SHA-256 digest is checked against the opened bytes before the
//! content is parsed or decompressed.

use std::collections::BTreeSet;
use std::io::{self, Read};

use flate2::read::MultiGzDecoder;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::root::{Root, invalid};
use super::spec::{
    LaunchIdentity, normalize_environment, normalize_user, normalize_working_directory,
};
use super::tree::{
    Entry, EntryKind, Tree, ancestors, join_path, normalize_layer_path, parent_of, sha256_bytes,
    validate_symlink_syntax, validate_symlinks,
};
use super::{
    MAX_CONFIG_BYTES, MAX_ENTRIES, MAX_EXPANDED_LAYER_BYTES, MAX_FILE_BYTES, MAX_INDEX_BYTES,
    MAX_LAYER_BYTES, MAX_LAYERS, MAX_LAYOUT_BYTES, MAX_MANIFEST_BYTES, MAX_RAW_OBJECTS,
};

pub const LAYOUT_VERSION: &str = "1.0.0";
pub const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub const CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
pub const PLAIN_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";
pub const GZIP_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerEvidence {
    pub media_type: String,
    pub digest: String,
    pub diff_id: String,
    pub bytes: usize,
    pub expanded_bytes: usize,
}

pub struct OciObjects {
    pub layout: Vec<u8>,
    pub index: Vec<u8>,
    pub manifest: Vec<u8>,
    pub config: Vec<u8>,
    pub layers: Vec<Vec<u8>>,
    pub manifest_digest: String,
}

pub struct OciGraph {
    pub tree: Tree,
    pub launch: LaunchIdentity,
    pub layers: Vec<LayerEvidence>,
}

/// Read the exact raw closure of one selected image through bounded,
/// link-free reads beneath the opened layout directory.
pub fn read_objects(root: &Root, manifest_digest: &str) -> io::Result<OciObjects> {
    let layout = read_source_file(root, "oci-layout", MAX_LAYOUT_BYTES)?;
    let index = read_source_file(root, "index.json", MAX_INDEX_BYTES)?;
    let index_value = parse_json(&index, "index")?;
    let descriptor = select_manifest_descriptor(&index_value, manifest_digest)?;
    let manifest = read_source_file(root, &blob_path(&descriptor.digest)?, MAX_MANIFEST_BYTES)?;
    verify_descriptor(&descriptor, &manifest, "manifest")?;
    let manifest_value = parse_json(&manifest, "manifest")?;
    let manifest_object = as_object(&manifest_value, "manifest")?;
    let config_descriptor = parse_descriptor(
        manifest_object
            .get("config")
            .ok_or_else(|| invalid("manifest has no config descriptor"))?,
        "config",
    )?;
    let config = read_source_file(
        root,
        &blob_path(&config_descriptor.digest)?,
        MAX_CONFIG_BYTES,
    )?;
    verify_descriptor(&config_descriptor, &config, "config")?;
    let layers_value = manifest_object
        .get("layers")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("manifest has no layer list"))?;
    if layers_value.len() > MAX_LAYERS {
        return Err(invalid(format!(
            "manifest has more than {MAX_LAYERS} layers"
        )));
    }
    if 4 + layers_value.len() > MAX_RAW_OBJECTS {
        return Err(invalid(format!(
            "raw closure has more than {MAX_RAW_OBJECTS} objects"
        )));
    }
    let mut layers = Vec::with_capacity(layers_value.len());
    for (position, value) in layers_value.iter().enumerate() {
        let descriptor = parse_descriptor(value, &format!("layer {position}"))?;
        layers.push(read_source_file(
            root,
            &blob_path(&descriptor.digest)?,
            MAX_LAYER_BYTES,
        )?);
    }
    Ok(OciObjects {
        layout,
        index,
        manifest,
        config,
        layers,
        manifest_digest: manifest_digest.to_owned(),
    })
}

fn read_source_file(root: &Root, path: &str, limit: usize) -> io::Result<Vec<u8>> {
    root.read_file(path, limit).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            invalid(format!("missing source object {path:?}"))
        } else {
            error
        }
    })
}

/// Re-derive the canonical tree and normalized launch from verified raw
/// objects. Nothing here reads a live source or a host filesystem.
pub fn parse_graph(objects: &OciObjects) -> io::Result<OciGraph> {
    let layout_value = parse_json(&objects.layout, "oci-layout")?;
    let layout = as_object(&layout_value, "oci-layout")?;
    if required_string(layout, "imageLayoutVersion", "oci-layout")? != LAYOUT_VERSION {
        return Err(invalid(format!(
            "unsupported image layout version {:?}",
            layout.get("imageLayoutVersion")
        )));
    }
    let index_value = parse_json(&objects.index, "index")?;
    let descriptor = select_manifest_descriptor(&index_value, &objects.manifest_digest)?;
    verify_descriptor(&descriptor, &objects.manifest, "manifest")?;
    let manifest_value = parse_json(&objects.manifest, "manifest")?;
    let manifest = as_object(&manifest_value, "manifest")?;
    if required_integer(manifest, "schemaVersion", "manifest")? != 2 {
        return Err(invalid("unsupported manifest schema version"));
    }
    if required_string(manifest, "mediaType", "manifest")? != MANIFEST_MEDIA_TYPE {
        return Err(invalid("manifest media type is unsupported"));
    }
    let config_descriptor = parse_descriptor(
        manifest
            .get("config")
            .ok_or_else(|| invalid("manifest has no config descriptor"))?,
        "config",
    )?;
    verify_descriptor(&config_descriptor, &objects.config, "config")?;
    if config_descriptor.media_type.as_deref() != Some(CONFIG_MEDIA_TYPE) {
        return Err(invalid("config media type is unsupported"));
    }
    let config_value = parse_json(&objects.config, "config")?;
    let config = as_object(&config_value, "config")?;

    let layer_values = manifest
        .get("layers")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("manifest has no layer list"))?;
    if layer_values.is_empty() {
        return Err(invalid("manifest has no layers"));
    }
    if layer_values.len() > MAX_LAYERS {
        return Err(invalid(format!(
            "manifest has more than {MAX_LAYERS} layers"
        )));
    }
    if layer_values.len() != objects.layers.len() {
        return Err(invalid(
            "raw layer count does not match the manifest layer count",
        ));
    }
    let rootfs = config
        .get("rootfs")
        .filter(|value| !value.is_null())
        .ok_or_else(|| invalid("config has no rootfs"))?;
    let rootfs = as_object(rootfs, "config rootfs")?;
    if required_string(rootfs, "type", "config rootfs")? != "layers" {
        return Err(invalid("config rootfs type is not layers"));
    }
    let diff_ids = rootfs
        .get("diff_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("config rootfs has no diff_ids"))?;
    if diff_ids.len() != layer_values.len() {
        return Err(invalid("config diff_id count does not match layer count"));
    }

    let mut tree = Tree::new();
    let mut evidence = Vec::with_capacity(layer_values.len());
    for (position, (value, data)) in layer_values.iter().zip(&objects.layers).enumerate() {
        let descriptor = parse_descriptor(value, &format!("layer {position}"))?;
        let media_type = descriptor
            .media_type
            .clone()
            .ok_or_else(|| invalid(format!("layer {position} has no media type")))?;
        if media_type != PLAIN_LAYER_MEDIA_TYPE && media_type != GZIP_LAYER_MEDIA_TYPE {
            return Err(invalid(format!(
                "unsupported layer media type {media_type:?}"
            )));
        }
        verify_descriptor(&descriptor, data, &format!("layer {position}"))?;
        let expanded = expand_layer(data, &media_type)?;
        let diff_id = diff_ids[position]
            .as_str()
            .ok_or_else(|| invalid("config diff_id is not a string"))?;
        let diff_id = super::spec::parse_digest(diff_id)?;
        if sha256_bytes(&expanded) != diff_id {
            return Err(invalid(format!(
                "layer {position} DiffID does not match uncompressed bytes"
            )));
        }
        apply_layer(&mut tree, parse_layer(&expanded)?)?;
        evidence.push(LayerEvidence {
            media_type,
            digest: descriptor.digest,
            diff_id: format!("sha256:{diff_id}"),
            bytes: data.len(),
            expanded_bytes: expanded.len(),
        });
    }
    tree.insert_default_directory(b".");
    validate_symlinks(&tree)?;
    let launch = normalize_launch(config, &tree)?;
    Ok(OciGraph {
        tree,
        launch,
        layers: evidence,
    })
}

struct Descriptor {
    media_type: Option<String>,
    digest: String,
    size: i64,
}

fn parse_descriptor(value: &Value, what: &str) -> io::Result<Descriptor> {
    let object = as_object(value, &format!("{what} descriptor"))?;
    let digest = required_string(object, "digest", &format!("{what} descriptor"))?;
    let hex = super::spec::parse_digest(digest)?;
    let size = required_integer(object, "size", &format!("{what} descriptor"))?;
    if size < 0 {
        return Err(invalid(format!(
            "{what} descriptor declares a negative size"
        )));
    }
    let media_type = optional_string(object, "mediaType")?.map(str::to_owned);
    if object.get("urls").is_some_and(|value| !value.is_null()) {
        return Err(invalid(format!("{what} descriptor declares URLs")));
    }
    if object.get("data").is_some_and(|value| !value.is_null()) {
        return Err(invalid(format!("{what} descriptor carries embedded data")));
    }
    Ok(Descriptor {
        media_type,
        digest: format!("sha256:{hex}"),
        size,
    })
}

fn verify_descriptor(descriptor: &Descriptor, data: &[u8], what: &str) -> io::Result<()> {
    if descriptor.size != data.len() as i64 {
        return Err(invalid(format!(
            "{what} descriptor size does not match stored bytes"
        )));
    }
    if descriptor.digest != format!("sha256:{}", sha256_bytes(data)) {
        return Err(invalid(format!(
            "{what} descriptor digest does not match stored bytes"
        )));
    }
    Ok(())
}

fn select_manifest_descriptor(index: &Value, manifest_digest: &str) -> io::Result<Descriptor> {
    let index = as_object(index, "index")?;
    if required_integer(index, "schemaVersion", "index")? != 2 {
        return Err(invalid("unsupported index schema version"));
    }
    let manifests = index
        .get("manifests")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("index has no manifest list"))?;
    let selected: Vec<&Value> = manifests
        .iter()
        .filter(|value| {
            value
                .get("digest")
                .and_then(Value::as_str)
                .is_some_and(|digest| digest == manifest_digest)
        })
        .collect();
    if selected.is_empty() {
        return Err(invalid(format!(
            "index has no descriptor for {manifest_digest}"
        )));
    }
    if selected.len() > 1 {
        return Err(invalid(format!(
            "index has {} descriptors for {manifest_digest}",
            selected.len()
        )));
    }
    let descriptor = parse_descriptor(selected[0], "selected")?;
    if descriptor.media_type.as_deref() != Some(MANIFEST_MEDIA_TYPE) {
        return Err(invalid(format!(
            "selected descriptor media type {:?}",
            descriptor.media_type
        )));
    }
    let platform = selected[0]
        .get("platform")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("selected descriptor has no platform"))?;
    if platform.get("architecture").and_then(Value::as_str) != Some("amd64")
        || platform.get("os").and_then(Value::as_str) != Some("linux")
    {
        return Err(invalid("selected descriptor is not linux/amd64"));
    }
    for extension in ["variant", "os.version", "os.features"] {
        if platform.contains_key(extension) {
            return Err(invalid(format!("selected descriptor declares {extension}")));
        }
    }
    Ok(descriptor)
}

fn normalize_launch(config: &Map<String, Value>, tree: &Tree) -> io::Result<LaunchIdentity> {
    if required_string(config, "architecture", "config")? != "amd64"
        || required_string(config, "os", "config")? != "linux"
    {
        return Err(invalid("selected config is not linux/amd64"));
    }
    for extension in ["variant", "os.version", "os.features"] {
        if config.contains_key(extension) {
            return Err(invalid(format!("selected config declares {extension}")));
        }
    }
    let oci = match config.get("config").filter(|value| !value.is_null()) {
        Some(value) => Some(as_object(value, "config launch section")?),
        None => None,
    };
    if let Some(oci) = oci {
        for field in ["Volumes", "StopSignal", "ArgsEscaped"] {
            if oci.get(field).is_some_and(truthy) {
                return Err(invalid(format!(
                    "the {field} launch field is not supported"
                )));
            }
        }
    }
    let mut arguments = string_list(oci.and_then(|oci| oci.get("Entrypoint")), "Entrypoint")?;
    arguments.extend(string_list(oci.and_then(|oci| oci.get("Cmd")), "Cmd")?);
    if arguments.is_empty() {
        return Err(invalid("workload has no executable"));
    }
    let executable = &arguments[0];
    if !executable.starts_with('/') {
        return Err(invalid(format!(
            "executable {executable:?} is not an absolute path"
        )));
    }
    let relative = normalize_layer_path(executable.trim_start_matches('/').as_bytes())?;
    let entry = tree.get(&relative).ok_or_else(|| {
        invalid(format!(
            "executable {executable:?} is not a file in the workload"
        ))
    })?;
    if entry.kind != EntryKind::File {
        return Err(invalid(format!(
            "executable {executable:?} is not a file in the workload"
        )));
    }
    if entry.mode & 0o111 == 0 {
        return Err(invalid(format!(
            "executable {executable:?} is not executable"
        )));
    }
    let (uid, gid) = normalize_user(optional_string_value(
        oci.and_then(|oci| oci.get("User")),
        "User",
    )?)?;
    let environment = match oci.and_then(|oci| oci.get("Env")) {
        None => Vec::new(),
        Some(value) => {
            let array = value
                .as_array()
                .ok_or_else(|| invalid("config environment is not a list"))?;
            let mut entries = Vec::with_capacity(array.len());
            for item in array {
                entries.push(
                    item.as_str()
                        .ok_or_else(|| invalid("config environment is not a list of strings"))?
                        .to_owned(),
                );
            }
            normalize_environment(&entries)?
        }
    };
    let working_directory = normalize_working_directory(
        optional_string_value(oci.and_then(|oci| oci.get("WorkingDir")), "WorkingDir")?,
        tree,
    )?;
    Ok(LaunchIdentity {
        executable: format!("/{}", String::from_utf8_lossy(&relative)),
        arguments,
        environment,
        working_directory,
        uid,
        gid,
    })
}

fn string_list(value: Option<&Value>, what: &str) -> io::Result<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if !truthy(value) {
        return Ok(Vec::new());
    }
    let array = value
        .as_array()
        .ok_or_else(|| invalid(format!("{what} must be a list of strings")))?;
    array
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid(format!("{what} must be a list of strings")))
        })
        .collect()
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(number) => number.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn blob_path(digest: &str) -> io::Result<String> {
    Ok(format!(
        "blobs/sha256/{}",
        super::spec::parse_digest(digest)?
    ))
}

fn parse_json(bytes: &[u8], what: &str) -> io::Result<Value> {
    serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("malformed {what} JSON: {error}")))
}

fn as_object<'a>(value: &'a Value, what: &str) -> io::Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} is not a JSON object")))
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    what: &str,
) -> io::Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{what} has no {key} string")))
}

fn optional_string<'a>(object: &'a Map<String, Value>, key: &str) -> io::Result<Option<&'a str>> {
    match object.get(key).filter(|value| !value.is_null()) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| invalid(format!("{key} is not a string"))),
    }
}

fn optional_string_value<'a>(value: Option<&'a Value>, what: &str) -> io::Result<Option<&'a str>> {
    match value {
        None => Ok(None),
        Some(value) if value.is_null() => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| invalid(format!("{what} is not a string"))),
    }
}

fn required_integer(object: &Map<String, Value>, key: &str, what: &str) -> io::Result<i64> {
    object
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| invalid(format!("{what} has no {key} integer")))
}

fn expand_layer(data: &[u8], media_type: &str) -> io::Result<Vec<u8>> {
    if media_type == PLAIN_LAYER_MEDIA_TYPE {
        if data.len() > MAX_EXPANDED_LAYER_BYTES {
            return Err(invalid("layer expansion limit"));
        }
        return Ok(data.to_vec());
    }
    if media_type != GZIP_LAYER_MEDIA_TYPE {
        return Err(invalid(format!(
            "unsupported layer media type {media_type:?}"
        )));
    }
    let mut expanded = Vec::new();
    MultiGzDecoder::new(data)
        .take(MAX_EXPANDED_LAYER_BYTES as u64 + 1)
        .read_to_end(&mut expanded)
        .map_err(|error| invalid(format!("malformed gzip layer: {error}")))?;
    if expanded.len() > MAX_EXPANDED_LAYER_BYTES {
        return Err(invalid("layer expansion limit"));
    }
    Ok(expanded)
}

struct Member {
    name: Vec<u8>,
    entry: Entry,
}

enum Marker {
    Whiteout(Vec<u8>),
    Opaque(Vec<u8>),
}

impl Marker {
    fn target(&self) -> &[u8] {
        match self {
            Self::Whiteout(target) | Self::Opaque(target) => target,
        }
    }
}

fn parse_layer(expanded: &[u8]) -> io::Result<Vec<Member>> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(expanded));
    let entries = archive
        .entries()
        .map_err(|error| invalid(format!("malformed layer archive: {error}")))?;
    let mut members = Vec::new();
    for entry in entries.raw(true) {
        let mut entry =
            entry.map_err(|error| invalid(format!("malformed layer archive: {error}")))?;
        let entry_type = entry.header().entry_type();
        let name = normalize_layer_path(&entry.path_bytes())?;
        let mode = entry
            .header()
            .mode()
            .map_err(|error| invalid(format!("malformed layer archive: {error}")))?;
        if mode > 0o7777 {
            return Err(invalid(format!(
                "unsupported mode at {:?}",
                String::from_utf8_lossy(&name)
            )));
        }
        if mode & 0o6000 != 0 {
            return Err(invalid(format!(
                "setuid or setgid mode at {:?}",
                String::from_utf8_lossy(&name)
            )));
        }
        let uid = entry
            .header()
            .uid()
            .map_err(|error| invalid(format!("malformed layer archive: {error}")))?;
        let gid = entry
            .header()
            .gid()
            .map_err(|error| invalid(format!("malformed layer archive: {error}")))?;
        let mtime = entry
            .header()
            .mtime()
            .map_err(|error| invalid(format!("malformed layer archive: {error}")))?;
        if uid > u32::MAX as u64 || gid > u32::MAX as u64 {
            return Err(invalid(format!(
                "ownership out of range at {:?}",
                String::from_utf8_lossy(&name)
            )));
        }
        if mtime > u32::MAX as u64 {
            return Err(invalid(format!(
                "timestamp out of range at {:?}",
                String::from_utf8_lossy(&name)
            )));
        }
        let entry = match entry_type {
            tar::EntryType::Directory => {
                Entry::directory(mode, uid as u32, gid as u32, mtime as u32)
            }
            tar::EntryType::Symlink => {
                let target = entry
                    .header()
                    .link_name_bytes()
                    .ok_or_else(|| {
                        invalid(format!(
                            "symbolic link at {:?} has no target",
                            String::from_utf8_lossy(&name)
                        ))
                    })?
                    .into_owned();
                validate_symlink_syntax(&name, &target)?;
                Entry::symlink(target, uid as u32, gid as u32, mtime as u32)
            }
            tar::EntryType::Regular => {
                let size = entry
                    .header()
                    .size()
                    .map_err(|error| invalid(format!("malformed layer archive: {error}")))?;
                if size > MAX_FILE_BYTES as u64 {
                    return Err(invalid(format!(
                        "file {:?} exceeds {MAX_FILE_BYTES} bytes",
                        String::from_utf8_lossy(&name)
                    )));
                }
                let mut data = Vec::new();
                entry
                    .read_to_end(&mut data)
                    .map_err(|error| invalid(format!("malformed layer archive: {error}")))?;
                if data.len() as u64 != size {
                    return Err(invalid(format!(
                        "truncated file at {:?}",
                        String::from_utf8_lossy(&name)
                    )));
                }
                Entry::file(data, mode, uid as u32, gid as u32, mtime as u32)
            }
            tar::EntryType::Link => {
                return Err(invalid(format!(
                    "hard link at {:?}",
                    String::from_utf8_lossy(&name)
                )));
            }
            tar::EntryType::Char | tar::EntryType::Block | tar::EntryType::Fifo => {
                return Err(invalid(format!(
                    "unsupported file type at {:?}",
                    String::from_utf8_lossy(&name)
                )));
            }
            tar::EntryType::GNUSparse => {
                return Err(invalid(format!(
                    "sparse file at {:?}",
                    String::from_utf8_lossy(&name)
                )));
            }
            tar::EntryType::GNULongName
            | tar::EntryType::GNULongLink
            | tar::EntryType::XHeader
            | tar::EntryType::XGlobalHeader => {
                return Err(invalid(format!(
                    "unsupported extended metadata at {:?}",
                    String::from_utf8_lossy(&name)
                )));
            }
            _ => {
                return Err(invalid(format!(
                    "unsupported file type at {:?}",
                    String::from_utf8_lossy(&name)
                )));
            }
        };
        members.push(Member { name, entry });
        if members.len() > MAX_ENTRIES {
            return Err(invalid(format!("layer exceeds {MAX_ENTRIES} entries")));
        }
    }
    Ok(members)
}

fn split_marker(member: &Member) -> io::Result<Option<Marker>> {
    let components: Vec<&[u8]> = member
        .name
        .split(|byte| *byte == b'/')
        .filter(|part| !part.is_empty() && *part != b".")
        .collect();
    let Some((base, parents)) = components.split_last() else {
        return Ok(None);
    };
    for component in parents {
        if component.starts_with(b".wh.") {
            return Err(invalid(format!(
                "whiteout marker {:?} is not a basename",
                String::from_utf8_lossy(component)
            )));
        }
    }
    let parent = parent_of(&member.name).unwrap_or_else(|| b".".to_vec());
    if *base == b".wh..wh..opq" {
        if member.entry.kind != EntryKind::File || !is_empty_file(&member.entry) {
            return Err(invalid(format!(
                "opaque marker at {:?} is not an empty regular file",
                String::from_utf8_lossy(&member.name)
            )));
        }
        return Ok(Some(Marker::Opaque(parent)));
    }
    if base.starts_with(b".wh.") {
        if member.entry.kind != EntryKind::File || !is_empty_file(&member.entry) {
            return Err(invalid(format!(
                "whiteout marker at {:?} is not an empty regular file",
                String::from_utf8_lossy(&member.name)
            )));
        }
        let target = &base[4..];
        if target.is_empty()
            || target == b"."
            || target == b".."
            || target.contains(&b'/')
            || target.contains(&0)
        {
            return Err(invalid(format!(
                "invalid whiteout marker at {:?}",
                String::from_utf8_lossy(&member.name)
            )));
        }
        return Ok(Some(Marker::Whiteout(join_path(&parent, target))));
    }
    Ok(None)
}

fn is_empty_file(entry: &Entry) -> bool {
    entry.data.as_ref().is_none_or(Vec::is_empty)
}

fn apply_layer(tree: &mut Tree, members: Vec<Member>) -> io::Result<()> {
    let mut seen: BTreeSet<&[u8]> = BTreeSet::new();
    let mut markers = Vec::new();
    let mut additions = Vec::new();
    for member in &members {
        if !seen.insert(&member.name) {
            return Err(invalid(format!(
                "duplicate layer path {:?}",
                String::from_utf8_lossy(&member.name)
            )));
        }
        match split_marker(member)? {
            None => additions.push(member),
            Some(marker) => markers.push(marker),
        }
    }

    // A marker path is still a path. It may not traverse a lower-layer symlink
    // unless this layer replaces that ancestor with a directory. The check runs
    // against the view the marker affects, so an upper layer that replaces the
    // marker's parent with a symlink does not retroactively invalidate deletion
    // of a lower child.
    let mut provided_directories: BTreeSet<Vec<u8>> = BTreeSet::new();
    for member in &additions {
        if member.entry.kind == EntryKind::Directory {
            provided_directories.insert(member.name.clone());
        }
        for ancestor in ancestors(&member.name) {
            provided_directories.insert(ancestor);
        }
    }
    for marker in &markers {
        for ancestor in ancestors(marker.target()) {
            if let Some(entry) = tree.get(&ancestor)
                && entry.kind == EntryKind::Symlink
                && !provided_directories.contains(&ancestor)
            {
                return Err(invalid(format!(
                    "marker {:?} traverses symlink {:?}",
                    String::from_utf8_lossy(marker.target()),
                    String::from_utf8_lossy(&ancestor)
                )));
            }
        }
    }

    // Markers affect the lower-layer view only, whatever order the archive uses,
    // so same-layer additions survive a whiteout and opacity cannot erase them.
    for marker in &markers {
        match marker {
            Marker::Whiteout(target) => tree.remove_subtree(target),
            Marker::Opaque(target) => tree.remove_children(target),
        }
    }

    for member in &additions {
        for ancestor in ancestors(&member.name) {
            if let Some(entry) = tree.get(&ancestor)
                && entry.kind != EntryKind::Directory
            {
                return Err(invalid(format!(
                    "path {:?} traverses {} {:?}",
                    String::from_utf8_lossy(&member.name),
                    entry.kind.name(),
                    String::from_utf8_lossy(&ancestor)
                )));
            }
        }
        for ancestor in ancestors(&member.name) {
            tree.insert_default_directory(&ancestor);
        }
        let existing = tree.get(&member.name).map(|entry| entry.kind);
        match member.entry.kind {
            EntryKind::Directory => {
                if existing.is_some() && existing != Some(EntryKind::Directory) {
                    tree.remove_subtree(&member.name);
                }
            }
            _ => {
                if existing == Some(EntryKind::Directory) {
                    tree.remove_subtree(&member.name);
                }
            }
        }
        tree.insert(member.name.clone(), member.entry.clone());
    }

    // Opacity is checked after additions, so replacing a lower file with an
    // opaque directory is legal while an opaque marker on a surviving
    // non-directory is not.
    for marker in &markers {
        if let Marker::Opaque(target) = marker
            && let Some(entry) = tree.get(target)
            && entry.kind != EntryKind::Directory
        {
            return Err(invalid(format!(
                "opaque marker on non-directory {:?}",
                String::from_utf8_lossy(target)
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> Member {
        member(name, Entry::directory(0o755, 0, 0, 0))
    }

    fn dir_with_mode(name: &str, mode: u32) -> Member {
        member(name, Entry::directory(mode, 0, 0, 0))
    }

    fn file(name: &str, data: &[u8]) -> Member {
        member(name, Entry::file(data.to_vec(), 0o644, 0, 0, 0))
    }

    fn symlink(name: &str, target: &str) -> Member {
        member(name, Entry::symlink(target.as_bytes().to_vec(), 0, 0, 0))
    }

    fn member(name: &str, entry: Entry) -> Member {
        Member {
            name: name.as_bytes().to_vec(),
            entry,
        }
    }

    fn seeded() -> Tree {
        let mut tree = Tree::new();
        tree.insert(b".".to_vec(), Entry::default_directory());
        tree.insert(b"bin".to_vec(), Entry::default_directory());
        tree.insert(
            b"bin/app".to_vec(),
            Entry::file(b"app".to_vec(), 0o755, 0, 0, 0),
        );
        tree
    }

    #[test]
    fn duplicate_paths_in_one_layer_are_rejected() {
        let mut tree = seeded();
        let error = apply_layer(
            &mut tree,
            vec![file("etc/a", b"one"), file("etc/a", b"two")],
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("duplicate layer path"),
            "{error}"
        );
    }

    #[test]
    fn directory_over_directory_updates_attributes_and_keeps_children() {
        let mut tree = seeded();
        apply_layer(&mut tree, vec![dir("etc"), file("etc/keep", b"keep")]).unwrap();
        apply_layer(&mut tree, vec![dir_with_mode("etc", 0o750)]).unwrap();
        let etc = tree.get(b"etc").unwrap();
        assert_eq!(etc.mode, 0o750);
        assert!(tree.get(b"etc/keep").is_some());
    }

    #[test]
    fn a_non_directory_replacement_removes_the_previous_subtree() {
        let mut tree = seeded();
        apply_layer(&mut tree, vec![dir("etc"), file("etc/child", b"x")]).unwrap();
        apply_layer(&mut tree, vec![file("etc", b"now a file")]).unwrap();
        assert_eq!(tree.get(b"etc").unwrap().kind, EntryKind::File);
        assert!(tree.get(b"etc/child").is_none());
    }

    #[test]
    fn whiteout_of_a_missing_path_is_legal() {
        let mut tree = seeded();
        apply_layer(&mut tree, vec![file(".wh.absent", b"")]).unwrap();
        assert!(tree.get(b"bin/app").is_some());
    }

    #[test]
    fn opaque_marker_on_a_surviving_non_directory_is_rejected() {
        let mut tree = seeded();
        let error = apply_layer(&mut tree, vec![file("bin/app/.wh..wh..opq", b"")]).unwrap_err();
        assert!(error.to_string().contains("non-directory"), "{error}");
    }

    #[test]
    fn a_marker_may_traverse_a_lower_symlink_replaced_by_a_directory() {
        let mut tree = seeded();
        tree.insert(
            b"redirect".to_vec(),
            Entry::symlink(b"elsewhere".to_vec(), 0, 0, 0),
        );
        // The same layer replaces `redirect` with a directory, so the marker
        // inside it is legal.
        apply_layer(
            &mut tree,
            vec![dir("redirect"), file("redirect/.wh.victim", b"")],
        )
        .unwrap();
        assert_eq!(tree.get(b"redirect").unwrap().kind, EntryKind::Directory);

        // Without that replacement the marker traverses a lower symlink.
        let mut tree = seeded();
        tree.insert(
            b"redirect".to_vec(),
            Entry::symlink(b"elsewhere".to_vec(), 0, 0, 0),
        );
        let error = apply_layer(&mut tree, vec![file("redirect/.wh.victim", b"")]).unwrap_err();
        assert!(error.to_string().contains("traverses symlink"), "{error}");
    }

    #[test]
    fn markers_are_classified_only_by_their_basename() {
        let mut tree = seeded();
        let error = apply_layer(&mut tree, vec![file(".wh.a/b", b"")]).unwrap_err();
        assert!(error.to_string().contains("not a basename"), "{error}");

        let error = apply_layer(&mut tree, vec![file(".wh.victim", b"content")]).unwrap_err();
        assert!(error.to_string().contains("empty regular file"), "{error}");
    }

    #[test]
    fn additions_may_not_traverse_a_lower_non_directory() {
        let mut tree = seeded();
        tree.insert(
            b"etc".to_vec(),
            Entry::file(b"file".to_vec(), 0o644, 0, 0, 0),
        );
        let error = apply_layer(&mut tree, vec![file("etc/config", b"x")]).unwrap_err();
        assert!(error.to_string().contains("traverses file"), "{error}");
    }

    #[test]
    fn symlink_targets_are_validated_when_read() {
        assert!(validate_symlink_syntax(b"link", b"").is_err());
        assert!(validate_symlink_syntax(b"link", b"/abs").is_err());
        assert!(validate_symlink_syntax(b"link", b"rel").is_ok());
    }

    #[test]
    fn a_symbolic_link_addition_records_its_target() {
        let mut tree = seeded();
        apply_layer(&mut tree, vec![symlink("bin/current", "app")]).unwrap();
        let link = tree.get(b"bin/current").unwrap();
        assert_eq!(link.kind, EntryKind::Symlink);
        assert_eq!(link.target.as_deref(), Some(b"app".as_slice()));
        assert_eq!(link.mode, 0o777);
    }
}
