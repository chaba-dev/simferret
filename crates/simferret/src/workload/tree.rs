//! Canonical workload filesystem model, identity, and guest-template encoding.
//!
//! The canonical tree is a map from normalized in-root path to one entry. Paths
//! are raw bytes because a Linux path need not be UTF-8, and they are ordered by
//! byte value so the identity never depends on host directory enumeration, tar
//! member order where OCI semantics do not make order significant, locale, or
//! host umask.

use std::collections::BTreeMap;
use std::io::{self, Write};

use sha2::{Digest, Sha256};

use super::root::invalid;

pub const CANONICAL_PREFIX: &[u8] = b"simferret-canonical-filesystem-v1\0";
pub const DEFAULT_DIRECTORY_MODE: u32 = 0o755;
/// A Linux symbolic link has no settable mode, so the canonical model records
/// the conventional link mode rather than claiming a mode the guest cannot have.
pub const SYMLINK_MODE: u32 = 0o777;
pub const ROOT_PATH: &[u8] = b".";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Directory,
    File,
    Symlink,
}

impl EntryKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::File => "file",
            Self::Symlink => "symbolic link",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub kind: EntryKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u32,
    pub data: Option<Vec<u8>>,
    pub target: Option<Vec<u8>>,
}

impl Entry {
    pub fn directory(mode: u32, uid: u32, gid: u32, mtime: u32) -> Self {
        Self {
            kind: EntryKind::Directory,
            mode,
            uid,
            gid,
            mtime,
            data: None,
            target: None,
        }
    }

    pub fn default_directory() -> Self {
        Self::directory(DEFAULT_DIRECTORY_MODE, 0, 0, 0)
    }

    pub fn file(data: Vec<u8>, mode: u32, uid: u32, gid: u32, mtime: u32) -> Self {
        Self {
            kind: EntryKind::File,
            mode,
            uid,
            gid,
            mtime,
            data: Some(data),
            target: None,
        }
    }

    pub fn symlink(target: Vec<u8>, uid: u32, gid: u32, mtime: u32) -> Self {
        Self {
            kind: EntryKind::Symlink,
            mode: SYMLINK_MODE,
            uid,
            gid,
            mtime,
            data: None,
            target: Some(target),
        }
    }

    /// File bytes for a regular-file entry. A file entry always carries data
    /// when it is built through this module; a caller-built entry without data
    /// is treated as empty rather than panicking.
    fn file_bytes(&self) -> &[u8] {
        self.data.as_deref().unwrap_or(&[])
    }

    /// Link target for a symbolic-link entry. A link without a target is
    /// rejected by symbolic-link validation rather than panicking.
    fn link_target(&self) -> &[u8] {
        self.target.as_deref().unwrap_or(&[])
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tree {
    entries: BTreeMap<Vec<u8>, Entry>,
}

impl Tree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, path: &[u8]) -> Option<&Entry> {
        self.entries.get(path)
    }

    pub fn contains(&self, path: &[u8]) -> bool {
        self.entries.contains_key(path)
    }

    pub fn insert(&mut self, path: Vec<u8>, entry: Entry) -> Option<Entry> {
        self.entries.insert(path, entry)
    }

    pub fn insert_default_directory(&mut self, path: &[u8]) {
        self.entries
            .entry(path.to_vec())
            .or_insert_with(Entry::default_directory);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &Entry)> {
        self.entries.iter()
    }

    /// Remove `path` and every descendant. A root request removes everything,
    /// including the root entry itself; the caller restores a default root.
    pub fn remove_subtree(&mut self, path: &[u8]) {
        let prefix = subtree_prefix(path);
        self.entries.retain(|candidate, _| {
            !(candidate.as_slice() == path
                || (!prefix.is_empty() && candidate.starts_with(&prefix))
                || path == ROOT_PATH)
        });
    }

    /// Remove every descendant of `path` while keeping `path` itself.
    pub fn remove_children(&mut self, path: &[u8]) {
        let prefix = subtree_prefix(path);
        self.entries.retain(|candidate, _| {
            candidate.as_slice() == ROOT_PATH
                || (!prefix.is_empty() && !candidate.starts_with(&prefix))
        });
    }

    pub fn expanded_bytes(&self) -> usize {
        self.entries
            .values()
            .filter_map(|entry| entry.data.as_ref().map(Vec::len))
            .sum()
    }

    /// The canonical, domain-separated identity of the whole tree.
    pub fn canonical_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(CANONICAL_PREFIX);
        hasher.update(self.encode());
        hex(&hasher.finalize())
    }

    /// A bounded, unambiguous serialization of every guest-visible path, type,
    /// byte, link target, mode, owner, group, and timestamp decision.
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        for (path, entry) in &self.entries {
            output.push(match entry.kind {
                EntryKind::Directory => b'D',
                EntryKind::File => b'F',
                EntryKind::Symlink => b'L',
            });
            put_bytes32(&mut output, path);
            output.extend_from_slice(&entry.mode.to_be_bytes());
            output.extend_from_slice(&entry.uid.to_be_bytes());
            output.extend_from_slice(&entry.gid.to_be_bytes());
            output.extend_from_slice(&entry.mtime.to_be_bytes());
            match entry.kind {
                EntryKind::Directory => {}
                EntryKind::File => {
                    let data = entry.file_bytes();
                    output.extend_from_slice(&(data.len() as u64).to_be_bytes());
                    output.extend_from_slice(&Sha256::digest(data));
                }
                EntryKind::Symlink => {
                    put_bytes32(&mut output, entry.link_target());
                }
            }
        }
        output
    }

    /// Encode the immutable guest template as a `newc` CPIO archive rooted at
    /// `root_name`. The encoding is a pure function of the canonical tree, so a
    /// verifier can reproduce it byte for byte instead of trusting the stored
    /// copy.
    ///
    /// The root entry is emitted first and must be a directory. Initramfs
    /// extraction does not create missing parent directories, and byte order
    /// alone would place a path such as `!data` before the root sentinel `.`,
    /// so emitting the root first is what keeps every child extractable.
    pub fn template(&self, root_name: &str) -> io::Result<Vec<u8>> {
        let mut output = self.template_entries(root_name)?;
        append_cpio(&mut output, b"TRAILER!!!", 0, 0, 0, 0, &[])?;
        Ok(output)
    }

    /// The same `newc` entries without the trailing archive marker, so an
    /// initramfs assembler can concatenate the workload template with the
    /// agent's own entries into one archive.
    pub fn template_entries(&self, root_name: &str) -> io::Result<Vec<u8>> {
        let root = self
            .entries
            .get(ROOT_PATH)
            .ok_or_else(|| invalid("canonical tree has no root entry"))?;
        if root.kind != EntryKind::Directory {
            return Err(invalid("canonical root must be a directory"));
        }
        let mut output = Vec::new();
        append_template_entry(&mut output, root_name.as_bytes(), root)?;
        for (path, entry) in &self.entries {
            if path.as_slice() == ROOT_PATH {
                continue;
            }
            let mut name = Vec::new();
            name.extend_from_slice(root_name.as_bytes());
            name.push(b'/');
            name.extend_from_slice(path);
            append_template_entry(&mut output, &name, entry)?;
        }
        Ok(output)
    }
}

/// Enforce the canonical tree bounds shared by assembly and replay.
pub fn validate_canonical_tree(
    tree: &Tree,
    max_entries: usize,
    max_expanded_bytes: usize,
) -> io::Result<()> {
    if tree.len() > max_entries {
        return Err(invalid(format!(
            "canonical tree exceeds {max_entries} entries"
        )));
    }
    if tree.expanded_bytes() > max_expanded_bytes {
        return Err(invalid(format!(
            "canonical tree exceeds {max_expanded_bytes} expanded bytes"
        )));
    }
    Ok(())
}

fn append_template_entry(output: &mut Vec<u8>, name: &[u8], entry: &Entry) -> io::Result<()> {
    let (mode, contents) = match entry.kind {
        EntryKind::Directory => (0o040000 | entry.mode, Vec::new()),
        EntryKind::File => (0o100000 | entry.mode, entry.file_bytes().to_vec()),
        EntryKind::Symlink => (0o120000 | entry.mode, entry.link_target().to_vec()),
    };
    append_cpio(
        output,
        name,
        mode,
        entry.uid,
        entry.gid,
        entry.mtime,
        &contents,
    )
}

pub fn subtree_prefix(path: &[u8]) -> Vec<u8> {
    if path == ROOT_PATH {
        Vec::new()
    } else {
        let mut prefix = path.to_vec();
        prefix.push(b'/');
        prefix
    }
}

/// The parent of a canonical path, or `None` for the root.
pub fn parent_of(path: &[u8]) -> Option<Vec<u8>> {
    if path == ROOT_PATH {
        return None;
    }
    match path.iter().rposition(|byte| *byte == b'/') {
        Some(index) => Some(path[..index].to_vec()),
        None => Some(ROOT_PATH.to_vec()),
    }
}

/// The chain of ancestors from the immediate parent up to the root.
pub fn ancestors(path: &[u8]) -> Vec<Vec<u8>> {
    let mut chain = Vec::new();
    let mut current = parent_of(path);
    while let Some(value) = current {
        chain.push(value.clone());
        current = parent_of(&value);
    }
    chain
}

pub fn join_path(parent: &[u8], name: &[u8]) -> Vec<u8> {
    if parent == ROOT_PATH {
        return name.to_vec();
    }
    let mut joined = parent.to_vec();
    joined.push(b'/');
    joined.extend_from_slice(name);
    joined
}

/// Normalize one archive path exactly once: reject an absolute path, NUL, or an
/// escaping `..` component, drop empty and `.` components, and bound the length.
pub fn normalize_layer_path(raw: &[u8]) -> io::Result<Vec<u8>> {
    if raw.is_empty() || raw.contains(&0) {
        return Err(invalid(format!(
            "invalid layer path {:?}",
            String::from_utf8_lossy(raw)
        )));
    }
    if raw[0] == b'/' {
        return Err(invalid(format!(
            "absolute layer path {:?}",
            String::from_utf8_lossy(raw)
        )));
    }
    let mut parts: Vec<&[u8]> = Vec::new();
    for part in raw.split(|byte| *byte == b'/') {
        if part.is_empty() || part == b"." {
            continue;
        }
        if part == b".." {
            return Err(invalid(format!(
                "escaping layer path {:?}",
                String::from_utf8_lossy(raw)
            )));
        }
        parts.push(part);
    }
    let path = if parts.is_empty() {
        ROOT_PATH.to_vec()
    } else {
        parts.join(&b'/')
    };
    if path.len() > super::MAX_PATH_BYTES {
        return Err(invalid(format!(
            "layer path is longer than {} bytes",
            super::MAX_PATH_BYTES
        )));
    }
    Ok(path)
}

/// Reject a symbolic link target that is invalid regardless of the rest of the
/// tree.
pub fn validate_symlink_syntax(link_path: &[u8], target: &[u8]) -> io::Result<()> {
    if target.is_empty() || target.contains(&0) {
        return Err(invalid(format!(
            "invalid symbolic link target at {:?}",
            String::from_utf8_lossy(link_path)
        )));
    }
    if target.len() > super::MAX_SYMLINK_TARGET_BYTES {
        return Err(invalid(format!(
            "symbolic link target at {:?} is too long",
            String::from_utf8_lossy(link_path)
        )));
    }
    if target[0] == b'/' {
        return Err(invalid(format!(
            "absolute symbolic link target at {:?}",
            String::from_utf8_lossy(link_path)
        )));
    }
    Ok(())
}

/// Resolve every symbolic link against the final view with bounded expansion.
///
/// Counting `..` components lexically is not enough: `a -> .` followed by
/// `b -> a/../outside` passes a lexical check but resolves outside the root.
/// This walks the tree, follows existing links, and rejects any step that would
/// leave the workload root.
pub fn validate_symlinks(tree: &Tree) -> io::Result<()> {
    for (path, entry) in tree.iter() {
        if entry.kind != EntryKind::Symlink {
            continue;
        }
        let target = entry.link_target();
        resolve_symlink(tree, path, target)?;
    }
    Ok(())
}

fn resolve_symlink(tree: &Tree, link_path: &[u8], target: &[u8]) -> io::Result<()> {
    validate_symlink_syntax(link_path, target)?;
    let mut components: Vec<Vec<u8>> = Vec::new();
    for part in parent_of(link_path)
        .unwrap_or_default()
        .split(|b| *b == b'/')
    {
        if !part.is_empty() && part != b"." {
            components.push(part.to_vec());
        }
    }
    for part in target.split(|b| *b == b'/') {
        if !part.is_empty() && part != b"." {
            components.push(part.to_vec());
        }
    }
    let mut resolved: Vec<Vec<u8>> = Vec::new();
    let mut hops = 0;
    let mut index = 0;
    while index < components.len() {
        let part = &components[index];
        index += 1;
        if part == b".." {
            if resolved.pop().is_none() {
                return Err(invalid(format!(
                    "escaping symbolic link target at {:?}",
                    String::from_utf8_lossy(link_path)
                )));
            }
            continue;
        }
        let mut candidate = resolved.join(&b'/');
        if !candidate.is_empty() {
            candidate.push(b'/');
        }
        candidate.extend_from_slice(part);
        if let Some(entry) = tree.get(&candidate)
            && entry.kind == EntryKind::Symlink
        {
            hops += 1;
            if hops > super::MAX_SYMLINK_HOPS {
                return Err(invalid(format!(
                    "symbolic link chain too deep at {:?}",
                    String::from_utf8_lossy(link_path)
                )));
            }
            let nested = entry.link_target();
            validate_symlink_syntax(link_path, nested)?;
            let expansion: Vec<Vec<u8>> = nested
                .split(|b| *b == b'/')
                .filter(|piece| !piece.is_empty() && *piece != b".")
                .map(<[u8]>::to_vec)
                .collect();
            for piece in expansion.into_iter().rev() {
                components.insert(index, piece);
            }
            continue;
        }
        resolved.push(part.clone());
    }
    Ok(())
}

fn put_bytes32(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn append_cpio(
    output: &mut Vec<u8>,
    name: &[u8],
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u32,
    contents: &[u8],
) -> io::Result<()> {
    let name_size = name.len() + 1;
    let fields = [
        1_u32,
        mode,
        uid,
        gid,
        1,
        mtime,
        u32::try_from(contents.len()).map_err(|_| invalid("guest template file is too large"))?,
        0,
        0,
        0,
        0,
        u32::try_from(name_size).map_err(|_| invalid("guest template name is too large"))?,
        0,
    ];
    output.extend_from_slice(b"070701");
    for field in fields {
        write!(output, "{field:08x}")?;
    }
    output.extend_from_slice(name);
    output.push(0);
    while !output.len().is_multiple_of(4) {
        output.push(0);
    }
    output.extend_from_slice(contents);
    while !output.len().is_multiple_of(4) {
        output.push(0);
    }
    Ok(())
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    output
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Tree {
        let mut tree = Tree::new();
        tree.insert(ROOT_PATH.to_vec(), Entry::default_directory());
        tree.insert(b"bin".to_vec(), Entry::default_directory());
        tree.insert(
            b"bin/app".to_vec(),
            Entry::file(b"payload".to_vec(), 0o755, 1, 2, 3),
        );
        tree.insert(
            b"link".to_vec(),
            Entry::symlink(b"bin/app".to_vec(), 0, 0, 4),
        );
        tree
    }

    fn mutate_entry(tree: &mut Tree, path: &[u8], change: impl FnOnce(&mut Entry)) {
        let mut entry = tree.get(path).unwrap().clone();
        change(&mut entry);
        tree.insert(path.to_vec(), entry);
    }

    type TreeMutation = (&'static str, Box<dyn Fn(&mut Tree)>);

    #[test]
    fn canonical_identity_is_insertion_order_independent() {
        let mut reordered = Tree::new();
        for path in [b"link".as_slice(), b"bin/app", b"bin", b"."] {
            let entry = sample().get(path).unwrap().clone();
            reordered.insert(path.to_vec(), entry);
        }
        assert_eq!(sample().canonical_digest(), reordered.canonical_digest());
        assert_eq!(sample().encode(), reordered.encode());
        assert_eq!(
            sample().template("workload").unwrap(),
            reordered.template("workload").unwrap()
        );
    }

    #[test]
    fn canonical_identity_covers_every_guest_visible_field() {
        let baseline = sample().canonical_digest();
        let mutations: Vec<TreeMutation> = vec![
            (
                "mode",
                Box::new(|tree| mutate_entry(tree, b"bin", |entry| entry.mode = 0o700)),
            ),
            (
                "uid",
                Box::new(|tree| mutate_entry(tree, b"bin", |entry| entry.uid = 7)),
            ),
            (
                "gid",
                Box::new(|tree| mutate_entry(tree, b"bin", |entry| entry.gid = 7)),
            ),
            (
                "mtime",
                Box::new(|tree| mutate_entry(tree, b"bin", |entry| entry.mtime = 9)),
            ),
            (
                "content",
                Box::new(|tree| {
                    mutate_entry(tree, b"bin/app", |entry| {
                        entry.data = Some(b"other".to_vec())
                    })
                }),
            ),
            (
                "target",
                Box::new(|tree| {
                    mutate_entry(tree, b"link", |entry| entry.target = Some(b"bin".to_vec()))
                }),
            ),
            (
                "path",
                Box::new(|tree| {
                    let entry = tree.get(b"link").unwrap().clone();
                    tree.insert(b"renamed".to_vec(), entry);
                    tree.remove_subtree(b"link");
                }),
            ),
        ];
        for (name, mutate) in mutations {
            let mut tree = sample();
            mutate(&mut tree);
            assert_ne!(
                tree.canonical_digest(),
                baseline,
                "{name} is not covered by canonical identity"
            );
        }
    }

    #[test]
    fn template_emits_the_root_first_with_canonical_metadata() {
        let template = sample().template("workload").unwrap();
        assert!(template.len().is_multiple_of(4));
        assert_eq!(&template[..6], b"070701");
        let field = |index: usize| -> u32 {
            let start = 6 + index * 8;
            u32::from_str_radix(
                std::str::from_utf8(&template[start..start + 8]).unwrap(),
                16,
            )
            .unwrap()
        };
        // The first entry is the root directory, not a child that sorts first.
        assert_eq!(field(1), 0o040755);
        assert_eq!(field(2), 0);
        assert_eq!(field(3), 0);
        assert_eq!(field(5), 0);
        let name_size = field(11) as usize;
        assert_eq!(&template[110..110 + name_size - 1], b"workload");
        assert!(
            template
                .windows(10)
                .any(|window| window == b"TRAILER!!!".as_slice())
        );
        // A symbolic link target is encoded as the entry contents.
        assert!(
            template
                .windows(7)
                .any(|window| window == b"bin/app".as_slice())
        );
    }

    #[test]
    fn canonical_tree_bounds_are_enforced() {
        let tree = sample();
        assert!(validate_canonical_tree(&tree, tree.len(), tree.expanded_bytes()).is_ok());
        assert!(validate_canonical_tree(&tree, tree.len() - 1, usize::MAX).is_err());
        assert!(validate_canonical_tree(&tree, usize::MAX, tree.expanded_bytes() - 1).is_err());
    }

    #[test]
    fn a_non_directory_root_has_no_template() {
        let mut tree = sample();
        tree.insert(
            ROOT_PATH.to_vec(),
            Entry::file(b"root".to_vec(), 0o755, 0, 0, 0),
        );
        let error = tree.template("workload").unwrap_err();
        assert!(
            error.to_string().contains("root must be a directory"),
            "{error}"
        );
    }

    #[test]
    fn symlink_resolution_is_bounded_and_rooted() {
        let mut escaping = Tree::new();
        escaping.insert(ROOT_PATH.to_vec(), Entry::default_directory());
        escaping.insert(b"a".to_vec(), Entry::symlink(b".".to_vec(), 0, 0, 0));
        escaping.insert(
            b"b".to_vec(),
            Entry::symlink(b"a/../outside".to_vec(), 0, 0, 0),
        );
        assert!(validate_symlinks(&escaping).is_err());

        let mut absolute = Tree::new();
        absolute.insert(ROOT_PATH.to_vec(), Entry::default_directory());
        absolute.insert(
            b"a".to_vec(),
            Entry::symlink(b"/etc/passwd".to_vec(), 0, 0, 0),
        );
        assert!(validate_symlinks(&absolute).is_err());

        let mut in_root = Tree::new();
        in_root.insert(ROOT_PATH.to_vec(), Entry::default_directory());
        in_root.insert(b"bin".to_vec(), Entry::default_directory());
        in_root.insert(
            b"bin/app".to_vec(),
            Entry::file(b"x".to_vec(), 0o755, 1, 1, 0),
        );
        in_root.insert(
            b"link".to_vec(),
            Entry::symlink(b"bin/app".to_vec(), 0, 0, 0),
        );
        in_root.insert(b"dir".to_vec(), Entry::default_directory());
        in_root.insert(
            b"dir/up".to_vec(),
            Entry::symlink(b"../bin/app".to_vec(), 0, 0, 0),
        );
        validate_symlinks(&in_root).unwrap();
    }

    #[test]
    fn normalize_layer_path_is_strict() {
        assert_eq!(normalize_layer_path(b"a/b").unwrap(), b"a/b");
        assert_eq!(normalize_layer_path(b"a/./b").unwrap(), b"a/b");
        assert_eq!(normalize_layer_path(b"a//b").unwrap(), b"a/b");
        assert_eq!(normalize_layer_path(b".").unwrap(), b".");
        for invalid in [b"/etc".as_slice(), b"../x", b"a/../x", b"a\0b", b""] {
            assert!(
                normalize_layer_path(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        assert!(normalize_layer_path(&vec![b'a'; super::super::MAX_PATH_BYTES + 1]).is_err());
    }
}
