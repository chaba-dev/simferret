#!/usr/bin/env python3
"""RFD 3 Phase 0 spike prototype for OCI normalization and canonical identity.

This is throwaway spike code. The Phase 1 Rust assembler replaces it. The
prototype exists to answer the Phase 0 questions about layer semantics, digest
stability, and raw-versus-derived closure sufficiency before that assembler is
written, so it deliberately reuses standard-library primitives (``json``,
``tarfile``, ``gzip``, ``hashlib``) instead of hand-rolling container parsing.
It never delegates extraction to the host ``tar`` program.

Policy versions and limits are prototype-local constants. They are recorded in
the content-addressed closure so a Phase 1 implementation can show that a
changed default or bound changes workload identity.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import sys
import tarfile

CANONICAL_FORMAT_VERSION = 1
EXTRACTION_POLICY_VERSION = 1
LAYER_APPLICATION_POLICY_VERSION = 1

LAYOUT_VERSION = "1.0.0"
MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
PLAIN_LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar"
GZIP_LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"
SUPPORTED_LAYER_MEDIA_TYPES = (PLAIN_LAYER_MEDIA_TYPE, GZIP_LAYER_MEDIA_TYPE)

LIMITS = {
    "layout_bytes": 1 << 20,
    "index_bytes": 4 << 20,
    "descriptor_bytes": 1 << 20,
    "manifest_bytes": 1 << 20,
    "config_bytes": 1 << 20,
    "layer_bytes": 64 << 20,
    "expanded_layer_bytes": 256 << 20,
    "file_bytes": 16 << 20,
    "entries": 4096,
    "layers": 16,
    "path_bytes": 1024,
    "symlink_target_bytes": 4096,
    "symlink_hops": 40,
    "raw_objects": 64,
    "cache_bytes": 4 << 20,
    "lock_bytes": 128,
    "specification_bytes": 1 << 20,
    # The aggregate entry bound for the canonical tree. It is deliberately below
    # the number of minimum-size records a cache-sized manifest can hold, so a
    # pathological tree is rejected by the entry bound rather than by a
    # downstream size check.
    "view_entries": 1 << 15,
}

DEFAULT_DIRECTORY_MODE = 0o755
DEFAULT_USER = "65534:65534"
CANONICAL_PREFIX = b"simferret-canonical-filesystem-v1\0"


class Rejection(Exception):
    """A bounded, user-actionable refusal to accept a source object."""


def fail(message):
    raise Rejection(message)


class Entry:
    """One canonical workload filesystem entry."""

    __slots__ = ("kind", "mode", "uid", "gid", "mtime", "data", "target")

    def __init__(self, kind, mode, uid, gid, mtime, data=None, target=None):
        self.kind = kind
        self.mode = mode
        self.uid = uid
        self.gid = gid
        self.mtime = mtime
        self.data = data
        self.target = target


def default_directory():
    return Entry("dir", DEFAULT_DIRECTORY_MODE, 0, 0, 0)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_regular_file(path, limit):
    """Hash one regular file without following links, blocking, or overreading.

    ``O_NONBLOCK`` matters: without it, opening a FIFO blocks until a writer
    appears, so a special file would hang verification instead of being
    rejected. The size is checked before hashing, so an oversized or sparse file
    cannot force unbounded work.
    """

    try:
        handle_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        fail(f"cannot open {path!r}: {error.strerror}")
    digest = hashlib.sha256()
    total = 0
    with os.fdopen(handle_fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            fail(f"{path!r} is not a regular file")
        if info.st_size > limit:
            fail(f"{path!r} exceeds {limit} bytes")
        for block in iter(lambda: handle.read(1 << 20), b""):
            total += len(block)
            if total > limit:
                fail(f"{path!r} exceeds {limit} bytes")
            digest.update(block)
    return digest.hexdigest()


def parse_digest(value):
    algorithm, separator, hexdigest = value.partition(":")
    if separator != ":" or algorithm != "sha256" or len(hexdigest) != 64:
        fail(f"unsupported digest {value!r}")
    try:
        int(hexdigest, 16)
    except ValueError:
        fail(f"malformed digest {value!r}")
    return hexdigest


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def parse_json(data, what):
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"malformed {what} JSON")


class SourceRoot:
    """Bounded regular-file reads beneath one opened real directory.

    Every path component is opened with ``O_NOFOLLOW`` so a symbolic link,
    device, or FIFO anywhere below the opened root is rejected instead of
    followed.
    """

    def __init__(self, path):
        try:
            self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as error:
            fail(f"cannot open source root {path!r}: {error.strerror}")

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def _open_directory(self, relative):
        fd = os.dup(self.fd)
        for component in relative.split("/"):
            if component in ("", "."):
                continue
            try:
                child = os.open(
                    component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                )
            except OSError as error:
                os.close(fd)
                fail(f"cannot open directory {relative!r}: {error.strerror}")
            os.close(fd)
            fd = child
        return fd

    def read(self, relative, limit):
        """Read one bounded regular file.

        ``O_NONBLOCK`` matters: without it, opening a FIFO blocks until a writer
        appears, so a special file would hang the parser instead of being
        rejected.
        """

        parent, _, name = relative.rpartition("/")
        if not name:
            fail(f"empty path {relative!r}")
        fd = self._open_directory(parent)
        try:
            try:
                handle_fd = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd
                )
            except OSError as error:
                fail(f"cannot open file {relative!r}: {error.strerror}")
        finally:
            os.close(fd)
        with os.fdopen(handle_fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                fail(f"{relative!r} is not a regular file")
            if info.st_size > limit:
                fail(f"{relative!r} exceeds {limit} bytes")
            data = handle.read(limit + 1)
        if len(data) > limit:
            fail(f"{relative!r} exceeds {limit} bytes")
        return data


def normalize_path(raw):
    if not raw or "\0" in raw:
        fail(f"invalid layer path {raw!r}")
    if raw.startswith("/"):
        fail(f"absolute layer path {raw!r}")
    parts = []
    for part in raw.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            fail(f"escaping layer path {raw!r}")
        parts.append(part)
    path = "/".join(parts) if parts else "."
    if len(path.encode()) > LIMITS["path_bytes"]:
        fail(f"layer path longer than {LIMITS['path_bytes']} bytes")
    return path


def parent_of(path):
    if path == ".":
        return None
    head, separator, _ = path.rpartition("/")
    return head if separator else "."


def join_path(parent, name):
    return name if parent == "." else f"{parent}/{name}"


def ancestors(path):
    chain = []
    current = parent_of(path)
    while current is not None and current != ".":
        chain.append(current)
        current = parent_of(current)
    chain.append(".")
    return chain


def subtree_prefix(path):
    """The prefix shared by every descendant of ``path``.

    The canonical root is ``"."`` and every other canonical path has no leading
    component, so the root is the only path whose descendant prefix is empty.
    """

    return "" if path == "." else path + "/"


def remove_subtree(view, path):
    prefix = subtree_prefix(path)
    for candidate in list(view):
        if candidate == path or (prefix and candidate.startswith(prefix)) or path == ".":
            del view[candidate]


def remove_children(view, path):
    prefix = subtree_prefix(path)
    for candidate in list(view):
        if candidate == ".":
            continue
        if prefix and not candidate.startswith(prefix):
            continue
        del view[candidate]


def validate_symlink_syntax(link_path, target):
    """Reject a target that is invalid regardless of the rest of the tree."""

    if not target or "\0" in target:
        fail(f"invalid symbolic link target at {link_path!r}")
    if len(target.encode()) > LIMITS["symlink_target_bytes"]:
        fail(f"symbolic link target at {link_path!r} is too long")
    if target.startswith("/"):
        fail(f"absolute symbolic link target at {link_path!r}")
    return target


def resolve_symlink(view, link_path, target):
    """Resolve a target against the final view with bounded link expansion.

    Counting ``..`` components lexically is not enough: ``a -> .`` followed by
    ``b -> a/../outside`` passes a lexical check but resolves outside the root.
    This walks the tree instead, following existing links, and rejects any step
    that would leave the workload root. It runs against the final view so a
    later layer cannot change an earlier link's resolution after the fact.
    """

    validate_symlink_syntax(link_path, target)
    components = [
        part for part in parent_of(link_path).split("/") if part not in ("", ".")
    ] + [part for part in target.split("/") if part not in ("", ".")]
    resolved = []
    hops = 0
    while components:
        part = components.pop(0)
        if part == "..":
            if not resolved:
                fail(f"escaping symbolic link target at {link_path!r}")
            resolved.pop()
            continue
        candidate = "/".join(resolved + [part])
        entry = view.get(candidate)
        if entry is not None and entry.kind == "symlink":
            hops += 1
            if hops > LIMITS["symlink_hops"]:
                fail(f"symbolic link chain too deep at {link_path!r}")
            validate_symlink_syntax(link_path, entry.target)
            expansion = [piece for piece in entry.target.split("/") if piece not in ("", ".")]
            components = expansion + components
            continue
        resolved.append(part)
    return "/".join(resolved)


def validate_symlinks(view):
    for path in sorted(view, key=lambda value: value.encode()):
        entry = view[path]
        if entry.kind == "symlink":
            resolve_symlink(view, path, entry.target)


def validate_numeric(path, mode, uid, gid, mtime):
    """Reject archive metadata that cannot be serialized unambiguously."""

    if not 0 <= mode <= 0o7777:
        fail(f"unsupported mode at {path!r}")
    for name, value in (("uid", uid), ("gid", gid)):
        if not 0 <= value <= 0xFFFFFFFF:
            fail(f"{name} out of range at {path!r}")
    if not -(2**63) <= mtime < 2**63:
        fail(f"timestamp out of range at {path!r}")


class LayerMember:
    __slots__ = ("name", "kind", "mode", "uid", "gid", "mtime", "data", "target")

    def __init__(self, name, kind, mode, uid, gid, mtime, data=None, target=None):
        self.name = name
        self.kind = kind
        self.mode = mode
        self.uid = uid
        self.gid = gid
        self.mtime = mtime
        self.data = data
        self.target = target


def expand_layer(data, media_type):
    if media_type == PLAIN_LAYER_MEDIA_TYPE:
        if len(data) > LIMITS["expanded_layer_bytes"]:
            fail("layer expansion limit")
        return data
    if media_type != GZIP_LAYER_MEDIA_TYPE:
        fail(f"unsupported layer media type {media_type!r}")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            expanded = stream.read(LIMITS["expanded_layer_bytes"] + 1)
    except (OSError, EOFError):
        fail("malformed gzip layer")
    if len(expanded) > LIMITS["expanded_layer_bytes"]:
        fail("layer expansion limit")
    return expanded


def parse_layer(expanded):
    members = []
    try:
        with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
            for member in archive:
                members.append(read_member(archive, member))
                if len(members) > LIMITS["entries"]:
                    fail(f"layer exceeds {LIMITS['entries']} entries")
    except tarfile.TarError:
        fail("malformed layer archive")
    return members


def read_member(archive, member):
    name = normalize_path(member.name)
    # Validate the archive's own values, not a value already masked into range,
    # so an out-of-range mode is rejected instead of silently narrowed.
    validate_numeric(name, member.mode, member.uid, member.gid, member.mtime)
    mode = member.mode & 0o7777
    if member.mode & 0o6000:
        fail(f"setuid or setgid mode at {name!r}")
    if member.pax_headers:
        fail(f"unsupported extended metadata at {name!r}")
    if member.islnk():
        fail(f"hard link at {name!r}")
    if member.isdev() or member.isfifo():
        fail(f"unsupported file type at {name!r}")
    if member.issparse():
        fail(f"sparse file at {name!r}")
    if member.isdir():
        return LayerMember(name, "dir", mode, member.uid, member.gid, member.mtime)
    if member.issym():
        # A Linux symbolic link has no settable mode, so the canonical model
        # normalizes it rather than recording a mode the guest cannot have.
        return LayerMember(
            name,
            "symlink",
            0o777,
            member.uid,
            member.gid,
            member.mtime,
            target=validate_symlink_syntax(name, member.linkname),
        )
    if not member.isreg():
        fail(f"unsupported file type at {name!r}")
    if member.size > LIMITS["file_bytes"]:
        fail(f"file {name!r} exceeds {LIMITS['file_bytes']} bytes")
    contents = archive.extractfile(member)
    if contents is None:
        fail(f"unreadable file at {name!r}")
    data = contents.read(LIMITS["file_bytes"] + 1)
    if len(data) != member.size:
        fail(f"truncated file at {name!r}")
    return LayerMember(name, "file", mode, member.uid, member.gid, member.mtime, data=data)


def split_marker(member):
    """Classify a member as a whiteout, an opaque marker, or an addition.

    A ``.wh.`` component is only meaningful as a basename, so a marker anywhere
    else in a path is rejected rather than treated as an ordinary name. Markers
    are empty files, so a marker with contents is rejected too.
    """

    parent = parent_of(member.name)
    for component in [part for part in member.name.split("/") if part not in ("", ".")][:-1]:
        if component.startswith(".wh."):
            fail(f"whiteout marker {component!r} is not a basename")
    base = member.name if parent in (None, ".") else member.name[len(parent) + 1 :]
    if base == ".wh..wh..opq":
        if member.kind != "file" or member.data:
            fail(f"opaque marker at {member.name!r} is not an empty regular file")
        return ("opaque", parent)
    if base.startswith(".wh."):
        if member.kind != "file" or member.data:
            fail(f"whiteout marker at {member.name!r} is not an empty regular file")
        target = base[4:]
        if target in ("", ".", "..") or "/" in target or "\0" in target:
            fail(f"invalid whiteout marker at {member.name!r}")
        return ("whiteout", join_path(parent, target))
    return None


def apply_layer(view, members):
    seen = set()
    markers = []
    additions = []
    for member in members:
        if member.name in seen:
            fail(f"duplicate layer path {member.name!r}")
        seen.add(member.name)
        marker = split_marker(member)
        if marker is None:
            additions.append(member)
        else:
            markers.append(marker)

    # A marker path is still a path. It may not traverse a lower-layer symlink
    # unless this layer replaces that ancestor with a directory. The check runs
    # against the view the marker affects, so an upper layer that replaces the
    # marker's parent with a symlink does not retroactively invalidate deletion
    # of a lower child.
    provided_directories = set()
    for member in additions:
        if member.kind == "dir":
            provided_directories.add(member.name)
        provided_directories.update(ancestors(member.name))
    for kind, target in markers:
        for ancestor in ancestors(target):
            if (
                ancestor in view
                and view[ancestor].kind == "symlink"
                and ancestor not in provided_directories
            ):
                fail(f"marker {target!r} traverses symlink {ancestor!r}")

    # Markers affect the lower-layer view only, whatever order the archive uses,
    # so same-layer additions survive a whiteout and opacity cannot erase them.
    for kind, target in markers:
        if kind == "whiteout":
            remove_subtree(view, target)
        else:
            remove_children(view, target)

    for member in additions:
        for ancestor in ancestors(member.name):
            if ancestor in view and view[ancestor].kind != "dir":
                fail(f"path {member.name!r} traverses {view[ancestor].kind} {ancestor!r}")
        for ancestor in ancestors(member.name):
            view.setdefault(ancestor, default_directory())
        existing = view.get(member.name)
        if member.kind == "dir":
            if existing is not None and existing.kind != "dir":
                remove_subtree(view, member.name)
            view[member.name] = Entry(
                "dir", member.mode, member.uid, member.gid, member.mtime
            )
        else:
            if existing is not None and existing.kind == "dir":
                remove_subtree(view, member.name)
            view[member.name] = Entry(
                member.kind,
                member.mode,
                member.uid,
                member.gid,
                member.mtime,
                data=member.data,
                target=member.target,
            )

    # Opacity is checked after additions, so replacing a lower file with an
    # opaque directory is legal while an opaque marker on a surviving
    # non-directory is not.
    for kind, target in markers:
        if kind == "opaque" and target in view and view[target].kind != "dir":
            fail(f"opaque marker on non-directory {target!r}")
    return view


def canonical_digest(view):
    digest = hashlib.sha256()
    digest.update(CANONICAL_PREFIX)
    for path in sorted(view, key=lambda value: value.encode()):
        entry = view[path]
        encoded = path.encode()
        digest.update({"dir": b"D", "file": b"F", "symlink": b"L"}[entry.kind])
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(entry.mode.to_bytes(4, "big"))
        digest.update(entry.uid.to_bytes(4, "big"))
        digest.update(entry.gid.to_bytes(4, "big"))
        digest.update(entry.mtime.to_bytes(8, "big", signed=True))
        if entry.kind == "file":
            digest.update(len(entry.data).to_bytes(8, "big"))
            digest.update(hashlib.sha256(entry.data).digest())
        elif entry.kind == "symlink":
            target = entry.target.encode()
            digest.update(len(target).to_bytes(4, "big"))
            digest.update(target)
    return digest.hexdigest()


def serialize_tree(view):
    lines = []
    for path in sorted(view, key=lambda value: value.encode()):
        entry = view[path]
        record = {
            "path": path,
            "type": entry.kind,
            "mode": entry.mode,
            "uid": entry.uid,
            "gid": entry.gid,
            "mtime": entry.mtime,
        }
        if entry.kind == "file":
            record["bytes"] = len(entry.data)
            record["sha256"] = sha256_bytes(entry.data)
        elif entry.kind == "symlink":
            record["target"] = entry.target
        lines.append(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return ("\n".join(lines) + "\n").encode()


def expanded_bytes(view):
    return sum(len(entry.data) for entry in view.values() if entry.kind == "file")


def materialize(view, destination):
    """Write a canonical tree to disk.

    Mode, size, link target, and whole-second modification time are reproduced.
    Numeric ownership is not: the prototype runs unprivileged, so guest-visible
    owner fidelity is deferred to the Phase 2 assembler.
    """
    if os.path.lexists(destination):
        shutil.rmtree(destination)
    directories = [path for path in view if view[path].kind == "dir"]
    for path in sorted(directories, key=lambda value: value.count("/")):
        target = destination if path == "." else os.path.join(destination, path)
        os.makedirs(target, exist_ok=True)
    for path in sorted(view):
        entry = view[path]
        target = os.path.join(destination, path)
        if entry.kind == "dir":
            continue
        if entry.kind == "file":
            with open(target, "wb") as handle:
                handle.write(entry.data)
            os.chmod(target, entry.mode)
            os.utime(target, (entry.mtime, entry.mtime))
        else:
            os.symlink(entry.target, target)
            os.utime(target, (entry.mtime, entry.mtime), follow_symlinks=False)
    for path in sorted(directories, key=lambda value: value.count("/"), reverse=True):
        target = destination if path == "." else os.path.join(destination, path)
        os.chmod(target, view[path].mode)
        os.utime(target, (view[path].mtime, view[path].mtime))


def describe_tree(root, entry_limit):
    """Describe a materialized tree, including the root's own metadata.

    The root is included because tampering with its mode or timestamp is
    otherwise invisible to a comparison. Traversal is incremental and bounded:
    entries are counted as they are visited, a symbolic link is never descended
    into, and a root that is not itself a real directory is rejected, so a
    tampered tree cannot make verification walk or read outside the store.
    Regular files are bounded before they are read.
    """

    root_info = os.lstat(root)
    if not stat.S_ISDIR(root_info.st_mode):
        fail(f"{root!r} is not a directory")
    records = [("dir", ".", root_info.st_mode & 0o7777, root_info.st_mtime_ns, None)]
    total_bytes = 0
    pending = [("", root)]
    while pending:
        relative_directory, absolute_directory = pending.pop()
        try:
            entries = os.scandir(absolute_directory)
        except OSError as error:
            fail(f"cannot read directory {relative_directory or '.'!r}: {error.strerror}")
        with entries:
            for entry in entries:
                relative = entry.name if not relative_directory else f"{relative_directory}/{entry.name}"
                if len(records) >= entry_limit:
                    fail(f"materialized tree exceeds {entry_limit} entries")
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    records.append(("dir", relative, info.st_mode & 0o7777, info.st_mtime_ns, None))
                    pending.append((relative, entry.path))
                elif stat.S_ISLNK(info.st_mode):
                    records.append(
                        (
                            "symlink",
                            relative,
                            info.st_mode & 0o7777,
                            info.st_mtime_ns,
                            os.readlink(entry.path),
                        )
                    )
                elif stat.S_ISREG(info.st_mode):
                    if info.st_size > LIMITS["file_bytes"]:
                        fail(
                            f"materialized tree file {relative!r} exceeds "
                            f"{LIMITS['file_bytes']} bytes"
                        )
                    total_bytes += info.st_size
                    if total_bytes > LIMITS["expanded_layer_bytes"]:
                        fail(
                            f"materialized tree exceeds "
                            f"{LIMITS['expanded_layer_bytes']} bytes"
                        )
                    records.append(
                        (
                            "file",
                            relative,
                            info.st_mode & 0o7777,
                            info.st_mtime_ns,
                            sha256_regular_file(entry.path, LIMITS["file_bytes"]),
                        )
                    )
                else:
                    fail(f"materialized tree contains a special file at {relative!r}")
    return sorted(records, key=lambda record: record[1])


def compare_trees(left, right):
    if describe_tree(left, LIMITS["view_entries"]) != describe_tree(
        right, LIMITS["view_entries"]
    ):
        fail("materialized trees differ")
    return True


# ---------------------------------------------------------------------------
# OCI source parsing
# ---------------------------------------------------------------------------


def select_manifest_descriptor(index, manifest_digest):
    if index.get("schemaVersion") != 2:
        fail("unsupported index schema version")
    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        fail("index has no manifest list")
    selected = [
        descriptor
        for descriptor in manifests
        if isinstance(descriptor, dict) and descriptor.get("digest") == manifest_digest
    ]
    if not selected:
        fail(f"index has no descriptor for {manifest_digest}")
    if len(selected) > 1:
        fail(f"index has {len(selected)} descriptors for {manifest_digest}")
    descriptor = selected[0]
    if descriptor.get("mediaType") != MANIFEST_MEDIA_TYPE:
        fail(f"selected descriptor media type {descriptor.get('mediaType')!r}")
    platform = descriptor.get("platform")
    if not isinstance(platform, dict):
        fail("selected descriptor has no platform")
    if platform.get("architecture") != "amd64" or platform.get("os") != "linux":
        fail("selected descriptor is not linux/amd64")
    for extension in ("variant", "os.version", "os.features"):
        if extension in platform:
            fail(f"selected descriptor declares {extension}")
    return descriptor


def verify_descriptor(descriptor, data, what):
    if not isinstance(descriptor, dict):
        fail(f"{what} descriptor is malformed")
    size = descriptor.get("size")
    if not isinstance(size, int) or size != len(data):
        fail(f"{what} descriptor size does not match stored bytes")
    if parse_digest(descriptor.get("digest", "")) != sha256_bytes(data):
        fail(f"{what} descriptor digest does not match stored bytes")


def normalize_environment(entries):
    if entries is None:
        return []
    if not isinstance(entries, list):
        fail("config environment is not a list")
    environment = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, str) or "\0" in entry:
            fail("invalid environment entry")
        try:
            entry.encode("utf-8")
        except UnicodeEncodeError:
            fail("environment entry is not UTF-8")
        name, separator, _ = entry.partition("=")
        if not separator or not name:
            fail(f"environment entry {entry!r} is not NAME=VALUE")
        if name in seen:
            fail(f"duplicate environment name {name!r}")
        seen.add(name)
        environment.append(entry)
    return environment


def normalize_user(value):
    if value is None or value == "":
        value = DEFAULT_USER
    if not isinstance(value, str) or value.count(":") != 1:
        fail(f"unsupported user {value!r}")
    uid_text, gid_text = value.split(":")
    if not uid_text.isdigit() or not gid_text.isdigit():
        fail(f"user {value!r} is not a numeric uid:gid pair")
    uid, gid = int(uid_text), int(gid_text)
    if uid == 0 or gid == 0:
        fail("root credentials are not supported")
    for value in (uid, gid):
        if value > 0xFFFFFFFF:
            fail(f"user {value!r} is out of range")
    return uid, gid


def normalize_working_directory(value, view):
    if value is None or value == "":
        value = "/"
    if not isinstance(value, str) or not value.startswith("/"):
        fail(f"working directory {value!r} is not absolute")
    stripped = value.strip("/")
    relative = normalize_path(stripped) if stripped else "."
    for ancestor in ancestors(relative) + [relative]:
        if ancestor in view and view[ancestor].kind == "symlink":
            fail(f"working directory {value!r} traverses a symbolic link")
    if relative != "." and (relative not in view or view[relative].kind != "dir"):
        fail(f"working directory {value!r} is not a directory in the workload")
    return "/" + (relative if relative != "." else "")


def normalize_launch(config, view):
    if config.get("architecture") != "amd64" or config.get("os") != "linux":
        fail("selected config is not linux/amd64")
    for extension in ("variant", "os.version", "os.features"):
        if extension in config:
            fail(f"selected config declares {extension}")
    oci = config.get("config") or {}
    if not isinstance(oci, dict):
        fail("config launch section is malformed")
    if oci.get("Volumes"):
        fail("volumes are not supported")
    if oci.get("StopSignal"):
        fail("a configured stop signal is not supported")
    if oci.get("ArgsEscaped"):
        fail("ArgsEscaped is not supported")

    entrypoint = oci.get("Entrypoint") or []
    command = oci.get("Cmd") or []
    for value in (entrypoint, command):
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            fail("Entrypoint and Cmd must be string lists")
    arguments = list(entrypoint) + list(command)
    if not arguments:
        fail("workload has no executable")
    executable = arguments[0]
    if not executable.startswith("/"):
        fail(f"executable {executable!r} is not an absolute path")
    relative = normalize_path(executable.lstrip("/"))
    if relative not in view or view[relative].kind != "file":
        fail(f"executable {executable!r} is not a file in the workload")
    if not view[relative].mode & 0o111:
        fail(f"executable {executable!r} is not executable")
    uid, gid = normalize_user(oci.get("User"))
    return {
        "executable": "/" + relative,
        "arguments": arguments,
        "environment": normalize_environment(oci.get("Env")),
        "working_directory": normalize_working_directory(oci.get("WorkingDir"), view),
        "uid": uid,
        "gid": gid,
    }


def parse_oci_graph(objects, manifest_digest):
    layout = parse_json(objects["oci-layout"], "oci-layout")
    if layout.get("imageLayoutVersion") != LAYOUT_VERSION:
        fail(f"unsupported image layout version {layout.get('imageLayoutVersion')!r}")
    index = parse_json(objects["index.json"], "index")
    descriptor = select_manifest_descriptor(index, manifest_digest)
    manifest_bytes = objects["manifest"]
    verify_descriptor(descriptor, manifest_bytes, "manifest")
    manifest = parse_json(manifest_bytes, "manifest")
    if manifest.get("schemaVersion") != 2:
        fail("unsupported manifest schema version")
    if manifest.get("mediaType") != MANIFEST_MEDIA_TYPE:
        fail("manifest media type is unsupported")
    config_bytes = objects["config"]
    verify_descriptor(manifest.get("config"), config_bytes, "config")
    if manifest["config"].get("mediaType") != CONFIG_MEDIA_TYPE:
        fail("config media type is unsupported")
    config = parse_json(config_bytes, "config")

    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers:
        fail("manifest has no layers")
    if len(layers) > LIMITS["layers"]:
        fail(f"manifest has more than {LIMITS['layers']} layers")
    rootfs = config.get("rootfs")
    if not isinstance(rootfs, dict) or rootfs.get("type") != "layers":
        fail("config rootfs type is not layers")
    diff_ids = rootfs.get("diff_ids")
    if not isinstance(diff_ids, list) or len(diff_ids) != len(layers):
        fail("config diff_id count does not match layer count")

    view = {}
    layer_evidence = []
    for position, layer_descriptor in enumerate(layers):
        media_type = layer_descriptor.get("mediaType")
        if media_type not in SUPPORTED_LAYER_MEDIA_TYPES:
            fail(f"unsupported layer media type {media_type!r}")
        data = objects[f"layer-{position}"]
        verify_descriptor(layer_descriptor, data, f"layer {position}")
        expanded = expand_layer(data, media_type)
        if parse_digest(diff_ids[position]) != sha256_bytes(expanded):
            fail(f"layer {position} DiffID does not match uncompressed bytes")
        apply_layer(view, parse_layer(expanded))
        layer_evidence.append(
            {
                "media_type": media_type,
                "digest": layer_descriptor["digest"],
                "diff_id": diff_ids[position],
                "bytes": len(data),
                "expanded_bytes": len(expanded),
            }
        )
    view.setdefault(".", default_directory())
    validate_symlinks(view)
    return {
        "view": view,
        "launch": normalize_launch(config, view),
        "layers": layer_evidence,
        "manifest_digest": manifest_digest,
    }


def read_oci_objects(root, manifest_digest):
    objects = {}
    objects["oci-layout"] = root.read("oci-layout", LIMITS["layout_bytes"])
    objects["index.json"] = root.read("index.json", LIMITS["index_bytes"])
    index = parse_json(objects["index.json"], "index")
    descriptor = select_manifest_descriptor(index, manifest_digest)
    manifest_bytes = root.read(
        blob_path(manifest_digest), LIMITS["manifest_bytes"]
    )
    verify_descriptor(descriptor, manifest_bytes, "manifest")
    manifest = parse_json(manifest_bytes, "manifest")
    if not isinstance(manifest.get("config"), dict):
        fail("manifest has no config descriptor")
    config_digest = manifest["config"].get("digest")
    objects["manifest"] = manifest_bytes
    objects["config"] = root.read(blob_path(config_digest), LIMITS["config_bytes"])
    layers = manifest.get("layers")
    if not isinstance(layers, list):
        fail("manifest has no layers")
    if len(layers) > LIMITS["layers"]:
        fail(f"manifest has more than {LIMITS['layers']} layers")
    for position, layer_descriptor in enumerate(layers):
        if not isinstance(layer_descriptor, dict):
            fail(f"layer {position} descriptor is malformed")
        objects[f"layer-{position}"] = root.read(
            blob_path(layer_descriptor.get("digest")), LIMITS["layer_bytes"]
        )
    return objects


def blob_path(digest):
    if not isinstance(digest, str):
        fail("missing digest")
    return f"blobs/sha256/{parse_digest(digest)}"


def read_binary_objects(path):
    parent, _, name = path.rpartition("/")
    if not name:
        fail(f"binary source {path!r} is not a regular file")
    root = SourceRoot(parent or ".")
    try:
        return root.read(name, LIMITS["file_bytes"])
    finally:
        root.close()


def parse_binary_graph(objects, specification):
    executable = objects["executable"]
    view = {".": default_directory()}
    install_path = normalize_path(specification["install_path"].lstrip("/"))
    if install_path == ".":
        fail("binary install path must name a file")
    for ancestor in ancestors(install_path):
        view.setdefault(ancestor, default_directory())
    uid, gid = normalize_user(specification.get("user"))
    view[install_path] = Entry("file", 0o755, uid, gid, 0, data=executable)
    environment = normalize_environment(specification.get("environment"))
    return {
        "view": view,
        "launch": {
            "executable": "/" + install_path,
            "arguments": [specification["install_path"]] + list(specification.get("arguments", [])),
            "environment": environment,
            "working_directory": normalize_working_directory(
                specification.get("working_directory"), view
            ),
            "uid": uid,
            "gid": gid,
        },
        "layers": [],
    }


def parse_closure(closure, objects):
    if closure["kind"] == "oci":
        return parse_oci_graph(objects, closure["manifest_digest"])
    if closure["kind"] == "binary":
        # The specification is re-parsed from its verified raw object, not read
        # back from the closure record, so editing the record cannot change the
        # launch the store reproduces.
        specification_bytes = objects.get("workload-specification")
        if specification_bytes is None:
            fail("binary closure has no workload-specification object")
        return parse_binary_graph(
            objects, parse_json(specification_bytes, "workload specification")
        )
    fail(f"unsupported source kind {closure['kind']!r}")


# ---------------------------------------------------------------------------
# Content-addressed store
# ---------------------------------------------------------------------------


def raw_object_limit(role):
    """The ingestion limit that applies to one raw-object role.

    Replay must apply the bound the role was read under, so an object that could
    not have been ingested cannot be read back, and an unknown role is a
    tampered closure rather than an unconstrained object.
    """

    if role == "oci-layout":
        return LIMITS["layout_bytes"]
    if role == "index.json":
        return LIMITS["index_bytes"]
    if role == "manifest":
        return LIMITS["manifest_bytes"]
    if role == "config":
        return LIMITS["config_bytes"]
    if role == "executable":
        return LIMITS["file_bytes"]
    if role == "workload-specification":
        return LIMITS["specification_bytes"]
    if role.startswith("layer-") and role[len("layer-") :].isdigit():
        return LIMITS["layer_bytes"]
    fail(f"raw closure names unknown object role {role!r}")


def check_publishable(name, data, limit):
    """Refuse to publish metadata or an object that replay could not read back."""

    if len(data) > limit:
        fail(f"generated {name} exceeds the {limit}-byte policy limit")


def open_store_directory(store, relative, create=False):
    """Open one directory beneath the store root without following any link.

    Every component is opened relative to its parent descriptor, and created
    there when asked, so a symbolic link anywhere in the store path is rejected
    instead of followed or written through.
    """

    try:
        fd = os.open(store, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        fail(f"cannot open store {store!r}: {error.strerror}")
    for component in [part for part in relative.split("/") if part not in ("", ".")]:
        if create:
            try:
                os.mkdir(component, 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            except OSError as error:
                os.close(fd)
                fail(f"cannot create store directory {relative!r}: {error.strerror}")
        try:
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
        except OSError as error:
            os.close(fd)
            fail(f"cannot open store directory {relative!r}: {error.strerror}")
        os.close(fd)
        fd = child
    return fd


def write_store_file(directory, name, data):
    """Write one file inside an already opened store directory.

    The staging name is created exclusively and relative to the directory
    descriptor, so a pre-existing file, symbolic link, or FIFO at either name
    cannot be followed, truncated, or blocked on.
    """

    temporary = f"{name}.staging.{os.getpid()}"
    try:
        handle_fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o644,
            dir_fd=directory,
        )
    except OSError as error:
        fail(f"cannot create {name!r}: {error.strerror}")
    try:
        with os.fdopen(handle_fd, "wb") as handle:
            handle.write(data)
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=directory)
        except OSError:
            pass
        raise


def write_object(store, data):
    digest = sha256_bytes(data)
    directory = open_store_directory(store, "raw/sha256", create=True)
    try:
        # An existing object must be a regular file of exactly the expected
        # length: a FIFO or an oversized file is rejected rather than read.
        try:
            existing = os.open(
                digest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
            )
        except FileNotFoundError:
            existing = None
        except OSError as error:
            fail(f"cannot open existing raw object {digest}: {error.strerror}")
        if existing is not None:
            with os.fdopen(existing, "rb") as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode):
                    fail(f"raw object {digest} is not a regular file")
                if info.st_size != len(data) or handle.read(len(data) + 1) != data:
                    fail(f"existing raw object {digest} is corrupt")
            return digest
        write_store_file(directory, digest, data)
        return digest
    finally:
        os.close(directory)


def read_store_file(store, relative, limit):
    """Read one bounded regular file beneath the store root."""

    root = SourceRoot(store)
    try:
        return root.read(relative, limit)
    finally:
        root.close()


def read_object(store, digest, expected_bytes, limit):
    """Read one raw object beneath the store with a bounded, link-free read."""

    if expected_bytes < 0:
        fail(f"raw object {digest} has a negative recorded size")
    if expected_bytes > limit:
        fail(f"raw object {digest} exceeds the {limit}-byte policy limit")
    data = read_store_file(store, f"raw/sha256/{parse_digest(digest)}", expected_bytes + 1)
    if len(data) != expected_bytes or sha256_bytes(data) != parse_digest(digest):
        fail(f"raw object {digest} does not match its recorded identity")
    return data


def current_policy():
    return {
        "canonical_format": CANONICAL_FORMAT_VERSION,
        "extraction": EXTRACTION_POLICY_VERSION,
        "layer_application": LAYER_APPLICATION_POLICY_VERSION,
    }


def derived_directory(store, canonical):
    return os.path.join(store, "derived", canonical)


def write_closure(store, closure):
    """Write the closure record and the lock that pins it.

    The lock is what makes the record verifiable: without it, editing
    ``closure.json`` would silently change the launch or the recorded limits,
    because nothing else names the record's digest. The authoritative lock
    belongs in the run manifest in the Phase 1 assembler; this sidecar is the
    prototype equivalent.
    """

    data = canonical_json(closure)
    raw = open_store_directory(store, "raw", create=True)
    try:
        write_store_file(raw, "closure.json", data)
        write_store_file(raw, "closure.sha256", (sha256_bytes(data) + "\n").encode())
    finally:
        os.close(raw)
    return sha256_bytes(data)


def assemble_store(store, closure, objects, graph):
    view = graph["view"]
    # Everything generated here is validated against the limit replay reads it
    # under, before anything is written, so a source that assembly accepts is a
    # store that materialization can read back, and a rejected source leaves no
    # partial store behind.
    if len(view) > LIMITS["view_entries"]:
        fail(f"canonical tree exceeds {LIMITS['view_entries']} entries")
    if expanded_bytes(view) > LIMITS["expanded_layer_bytes"]:
        fail(f"canonical tree exceeds {LIMITS['expanded_layer_bytes']} expanded bytes")
    canonical = canonical_digest(view)
    manifest = serialize_tree(view)
    check_publishable("tree manifest", manifest, LIMITS["cache_bytes"])
    for role in sorted(objects):
        check_publishable(f"{role} object", objects[role], raw_object_limit(role))
    object_records = [
        {"role": role, "digest": f"sha256:{sha256_bytes(objects[role])}", "bytes": len(objects[role])}
        for role in sorted(objects)
    ]
    closure = dict(closure)
    closure.update(
        {
            "policy": current_policy(),
            "limits": LIMITS,
            "objects": object_records,
            "layers": graph["layers"],
            "launch": graph["launch"],
            "canonical_digest": canonical,
            "tree_manifest_sha256": sha256_bytes(manifest),
            "entries": len(view),
            "expanded_bytes": expanded_bytes(view),
        }
    )
    closure_data = canonical_json(closure)
    check_publishable("closure record", closure_data, LIMITS["cache_bytes"])
    closure_digest = sha256_bytes(closure_data)
    lock_data = canonical_json(
        {
            "closure_sha256": closure_digest,
            "raw_closure": "raw/closure.json",
            "canonical_digest": canonical,
            "tree_manifest_sha256": sha256_bytes(manifest),
        }
    )
    check_publishable("derived lock", lock_data, LIMITS["cache_bytes"])

    os.makedirs(store, exist_ok=True)
    # The derived entry is published through an opened `derived` descriptor, so a
    # symbolic link in the store path cannot redirect the staging tree or the
    # published entry outside the store.
    derived = open_store_directory(store, "derived", create=True)
    try:
        try:
            os.stat(canonical, dir_fd=derived, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            fail(f"derived entry {canonical} already exists")
        for role in sorted(objects):
            write_object(store, objects[role])
        staging_name = f"{canonical}.staging.{os.getpid()}"
        try:
            os.mkdir(staging_name, 0o755, dir_fd=derived)
        except OSError as error:
            fail(f"cannot create derived staging directory: {error.strerror}")
        try:
            staging_fd = os.open(
                staging_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=derived,
            )
        except OSError as error:
            fail(f"cannot open derived staging directory: {error.strerror}")
        try:
            write_store_file(staging_fd, "tree.json", manifest)
            write_store_file(staging_fd, "lock.json", lock_data)
        finally:
            os.close(staging_fd)
        materialize(view, os.path.join(store, "derived", staging_name, "tree"))
        os.replace(staging_name, canonical, src_dir_fd=derived, dst_dir_fd=derived)
    finally:
        os.close(derived)
    write_closure(store, closure)
    return {
        "canonical_digest": canonical,
        "tree_manifest_sha256": sha256_bytes(manifest),
        "closure_sha256": closure_digest,
        "entries": len(view),
        "expanded_bytes": expanded_bytes(view),
        "raw_bytes": sum(len(objects[role]) for role in objects),
        "raw_objects": len(objects),
        "launch": graph["launch"],
        "layers": len(graph["layers"]),
    }


def load_store(store, out):
    closure_bytes = read_store_file(store, "raw/closure.json", LIMITS["cache_bytes"])
    expected = (
        read_store_file(store, "raw/closure.sha256", LIMITS["lock_bytes"])
        .decode("utf-8")
        .strip()
    )
    if sha256_bytes(closure_bytes) != expected:
        fail("raw closure does not match its recorded lock")
    closure = json.loads(closure_bytes.decode("utf-8"))

    if closure.get("policy") != current_policy():
        fail("raw closure was recorded under a different policy version")
    if closure.get("limits") != LIMITS:
        fail("raw closure was recorded under different limits")

    # Bound the object list before reading any object, so an over-long closure
    # cannot force reads or allocations first.
    records = closure.get("objects")
    if not isinstance(records, list):
        fail("raw closure has no object list")
    if len(records) > LIMITS["raw_objects"]:
        fail(f"raw closure has more than {LIMITS['raw_objects']} objects")

    objects = {}
    for record in records:
        objects[record["role"]] = read_object(
            store, record["digest"], record["bytes"], raw_object_limit(record["role"])
        )
    graph = parse_closure(closure, objects)
    view = graph["view"]

    if graph["launch"] != closure["launch"]:
        fail("re-derived launch identity does not match the raw closure")
    if graph["layers"] != closure["layers"]:
        fail("re-derived layer evidence does not match the raw closure")

    canonical = canonical_digest(view)
    if canonical != closure["canonical_digest"]:
        fail("re-derived canonical digest does not match the raw closure")
    manifest = serialize_tree(view)
    if sha256_bytes(manifest) != closure["tree_manifest_sha256"]:
        fail("re-derived tree manifest does not match the raw closure")

    directory = derived_directory(store, canonical)
    stored_tree = os.path.join(directory, "tree")
    # The cached tree must be a real directory beneath the store: a symbolic
    # link there would make verification read a tree outside the store.
    try:
        tree_info = os.lstat(stored_tree)
    except FileNotFoundError:
        fail("derived cache entry is missing")
    if not stat.S_ISDIR(tree_info.st_mode):
        fail("derived cache entry is not a directory")
    stored = read_store_file(
        store, f"derived/{canonical}/tree.json", LIMITS["cache_bytes"]
    )
    if stored != manifest:
        fail("derived cache entry does not match the raw closure")
    lock = json.loads(
        read_store_file(
            store, f"derived/{canonical}/lock.json", LIMITS["cache_bytes"]
        ).decode("utf-8")
    )
    if lock.get("closure_sha256") != expected or lock.get("canonical_digest") != canonical:
        fail("derived cache entry does not name this raw closure")

    materialize(view, out)
    compare_trees(stored_tree, out)
    return {
        "canonical_digest": canonical,
        "tree_manifest_sha256": sha256_bytes(manifest),
        "closure_sha256": expected,
        "entries": len(view),
        "expanded_bytes": expanded_bytes(view),
        "launch": graph["launch"],
        "verified": True,
    }


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def command_apply(arguments):
    root = SourceRoot(arguments.layout)
    try:
        objects = read_oci_objects(root, arguments.manifest_digest)
    finally:
        root.close()
    graph = parse_oci_graph(objects, arguments.manifest_digest)
    view = graph["view"]
    # Identity is computed before any output exists, so a rejection cannot leave
    # a partially materialized tree behind.
    canonical = canonical_digest(view)
    manifest = serialize_tree(view)
    materialize(view, arguments.out)
    return {
        "canonical_digest": canonical,
        "tree_manifest_sha256": sha256_bytes(manifest),
        "entries": len(view),
        "expanded_bytes": expanded_bytes(view),
        "launch": graph["launch"],
        "layers": graph["layers"],
    }


def command_assemble(arguments):
    root = SourceRoot(arguments.layout)
    try:
        objects = read_oci_objects(root, arguments.manifest_digest)
    finally:
        root.close()
    graph = parse_oci_graph(objects, arguments.manifest_digest)
    return assemble_store(
        arguments.store,
        {"kind": "oci", "manifest_digest": arguments.manifest_digest},
        objects,
        graph,
    )


def command_assemble_binary(arguments):
    data = read_binary_objects(arguments.binary)
    specification = {
        "version": 1,
        "kind": "binary",
        "install_path": arguments.install_path,
        "arguments": arguments.argument,
        "environment": arguments.environment,
        "working_directory": arguments.working_directory,
        "user": arguments.user,
    }
    objects = {
        "executable": data,
        "workload-specification": canonical_json(specification),
    }
    graph = parse_binary_graph(objects, specification)
    return assemble_store(
        arguments.store,
        {"kind": "binary", "specification": specification},
        objects,
        graph,
    )


def command_materialize(arguments):
    return load_store(arguments.store, arguments.out)


def command_compare_trees(arguments):
    compare_trees(arguments.left, arguments.right)
    return {"equal": True}


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    apply_parser = subcommands.add_parser("apply")
    apply_parser.add_argument("--layout", required=True)
    apply_parser.add_argument("--manifest-digest", required=True)
    apply_parser.add_argument("--out", required=True)
    apply_parser.set_defaults(handler=command_apply)

    assemble_parser = subcommands.add_parser("assemble")
    assemble_parser.add_argument("--layout", required=True)
    assemble_parser.add_argument("--manifest-digest", required=True)
    assemble_parser.add_argument("--store", required=True)
    assemble_parser.set_defaults(handler=command_assemble)

    binary_parser = subcommands.add_parser("assemble-binary")
    binary_parser.add_argument("--binary", required=True)
    binary_parser.add_argument("--store", required=True)
    binary_parser.add_argument("--install-path", default="bin/simferret-workload-fixture")
    binary_parser.add_argument("--argument", action="append", default=[])
    binary_parser.add_argument("--environment", action="append", default=[])
    binary_parser.add_argument("--working-directory", default="/")
    binary_parser.add_argument("--user", default=DEFAULT_USER)
    binary_parser.set_defaults(handler=command_assemble_binary)

    materialize_parser = subcommands.add_parser("materialize")
    materialize_parser.add_argument("--store", required=True)
    materialize_parser.add_argument("--out", required=True)
    materialize_parser.set_defaults(handler=command_materialize)

    compare_parser = subcommands.add_parser("compare-trees")
    compare_parser.add_argument("--left", required=True)
    compare_parser.add_argument("--right", required=True)
    compare_parser.set_defaults(handler=command_compare_trees)

    arguments = parser.parse_args(argv)
    try:
        result = arguments.handler(arguments)
    except Rejection as rejection:
        print(f"rejected: {rejection}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
