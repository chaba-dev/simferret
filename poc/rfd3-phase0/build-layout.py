#!/usr/bin/env python3
"""Build the representative local OCI image layouts used by the RFD 3 Phase 0
spike.

This is throwaway spike code and is deliberately independent of the prototype
parser it feeds: the spike must not prove a layout is well formed by using the
same code that produced it. Layouts are written with canonical JSON, USTAR
metadata, and a fixed entry order, and nothing here contacts a registry or a
container daemon.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import shutil
import sys
import tarfile
from pathlib import Path

MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
PLAIN_LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar"
GZIP_LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"

ENTRYPOINT = ["/bin/simferret-workload-fixture"]
DEFAULT_CONFIG = {
    "config": {
        "Entrypoint": ENTRYPOINT,
        "Env": ["MODE=acceptance"],
        "User": "65534:65534",
        "WorkingDir": "/",
    }
}

OVERSIZED_FILE_BYTES = 17 << 20


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def tar_bytes(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for entry in entries:
            info = tarfile.TarInfo(entry["name"])
            info.mode = entry.get("mode", 0o755)
            info.uid = entry.get("uid", 0)
            info.gid = entry.get("gid", 0)
            info.mtime = entry.get("mtime", 0)
            info.uname = ""
            info.gname = ""
            kind = entry["kind"]
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == "file":
                info.type = tarfile.REGTYPE
                data = entry["data"]
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = entry["target"]
                archive.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = entry["linkname"]
                archive.addfile(info)
            elif kind == "char":
                info.type = tarfile.CHRTYPE
                info.devmajor = entry.get("devmajor", 1)
                info.devminor = entry.get("devminor", 3)
                archive.addfile(info)
            else:
                raise SystemExit(f"unknown tar entry kind {kind}")
    return buffer.getvalue()


def file_entry(name, data, mode, uid, gid, mtime):
    return {
        "name": name,
        "kind": "file",
        "mode": mode,
        "uid": uid,
        "gid": gid,
        "mtime": mtime,
        "data": data,
    }


def directory_entry(name, mode=0o755, uid=0, gid=0, mtime=0):
    return {"name": name, "kind": "dir", "mode": mode, "uid": uid, "gid": gid, "mtime": mtime}


def workload_layer(binary):
    return [
        directory_entry("bin"),
        file_entry("bin/simferret-workload-fixture", binary, 0o755, 65534, 65534, 0),
    ]


def dynamic_base_layer(loader, library):
    return [
        directory_entry("lib"),
        file_entry("lib/libc.so.6", library, 0o755, 0, 0, 0),
        directory_entry("lib64"),
        file_entry("lib64/ld-linux-x86-64.so.2", loader, 0o755, 0, 0, 0),
    ]


def semantics_base_layer(binary):
    return [
        directory_entry("bin"),
        file_entry("bin/simferret-workload-fixture", binary, 0o755, 65534, 65534, 0),
        directory_entry("etc", 0o755, 0, 0, 1700000000),
        file_entry("etc/config", b"base\n", 0o644, 0, 0, 1700000001),
        file_entry("etc/remove-me", b"base-remove\n", 0o644, 0, 0, 1700000001),
        file_entry("etc/pure-delete", b"base-pure\n", 0o644, 0, 0, 1700000001),
        file_entry("etc/swap", b"base-swap\n", 0o644, 0, 0, 1700000001),
        directory_entry("links", 0o755, 0, 0, 1700000000),
        {
            "name": "links/current",
            "kind": "symlink",
            "mode": 0o777,
            "uid": 0,
            "gid": 0,
            "mtime": 1700000000,
            "target": "../bin/simferret-workload-fixture",
        },
        directory_entry("opt", 0o755, 0, 0, 1700000000),
        file_entry("opt/keep", b"keep\n", 0o644, 0, 0, 1700000001),
        file_entry("opt/drop", b"drop\n", 0o644, 0, 0, 1700000001),
        directory_entry("opt/nested", 0o755, 0, 0, 1700000000),
        file_entry("opt/nested/child", b"child\n", 0o644, 0, 0, 1700000001),
        directory_entry("srv", 0o755, 0, 0, 1700000000),
        directory_entry("srv/opaque", 0o755, 0, 0, 1700000000),
        file_entry("srv/opaque/lower", b"lower\n", 0o644, 0, 0, 1700000001),
    ]


def semantics_upper_layer():
    return [
        directory_entry("etc", 0o750, 2000, 2000, 1700000003),
        file_entry("etc/config", b"upper\n", 0o640, 1000, 1000, 1700000002),
        file_entry("etc/remove-me", b"upper-remove\n", 0o600, 1000, 1000, 1700000002),
        # Every marker below appears after the additions it coexists with, so an
        # implementation that applied markers in archive order would delete
        # same-layer additions and change the asserted tree.
        file_entry("etc/.wh.remove-me", b"", 0o644, 0, 0, 0),
        file_entry("etc/.wh.pure-delete", b"", 0o644, 0, 0, 0),
        file_entry("etc/.wh.absent", b"", 0o644, 0, 0, 0),
        directory_entry("etc/swap", 0o755, 1000, 1000, 1700000005),
        file_entry("etc/swap/.wh..wh..opq", b"", 0o644, 0, 0, 0),
        file_entry("etc/swap/new", b"swap-new\n", 0o644, 1000, 1000, 1700000005),
        file_entry("opt/new", b"new\n", 0o644, 0, 0, 0),
        file_entry("opt/.wh..wh..opq", b"", 0o644, 0, 0, 0),
        directory_entry("var", 0o755, 0, 0, 1700000000),
        directory_entry("var/log", 0o750, 1000, 1000, 1700000000),
        file_entry("var/log/upper", b"upper-log\n", 0o640, 1000, 1000, 1700000004),
        {
            "name": "links/latest",
            "kind": "symlink",
            "mode": 0o777,
            "uid": 0,
            "gid": 0,
            "mtime": 1700000000,
            "target": "current",
        },
    ]


def write_layout(out, layers, config=None, platform=None, mutate=None):
    """Write one local image layout and return its selected manifest digest."""
    out = Path(out)
    blobs = out / "blobs" / "sha256"
    if out.exists():
        shutil.rmtree(out)
    blobs.mkdir(parents=True)

    def store(data):
        identity = digest(data)
        (blobs / identity).write_bytes(data)
        return identity

    stored_layers = []
    diff_ids = []
    for layer in layers:
        raw = tar_bytes(layer["entries"])
        compressed = layer.get("compressed", False)
        stored = gzip.compress(raw, mtime=0) if compressed else raw
        media_type = layer.get(
            "media_type",
            GZIP_LAYER_MEDIA_TYPE if compressed else PLAIN_LAYER_MEDIA_TYPE,
        )
        stored_layers.append(
            {
                "mediaType": media_type,
                "digest": f"sha256:{store(stored)}",
                "size": len(stored),
            }
        )
        diff_ids.append(f"sha256:{digest(raw)}")

    config_document = json.loads(json.dumps(config or DEFAULT_CONFIG))
    config_document["architecture"] = "amd64"
    config_document["os"] = "linux"
    config_document["rootfs"] = {"type": "layers", "diff_ids": diff_ids}
    manifest_document = {
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "config": {},
        "layers": stored_layers,
    }
    index_document = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": MANIFEST_MEDIA_TYPE,
                "digest": "",
                "size": 0,
                "platform": platform or {"architecture": "amd64", "os": "linux"},
            }
        ],
    }
    if mutate is not None:
        mutate(config_document, manifest_document, index_document)

    config_bytes = canonical_json(config_document)
    manifest_document["config"] = {
        "mediaType": CONFIG_MEDIA_TYPE,
        "digest": f"sha256:{store(config_bytes)}",
        "size": len(config_bytes),
    }
    manifest_bytes = canonical_json(manifest_document)
    manifest_digest = store(manifest_bytes)
    index_document["manifests"][0]["digest"] = f"sha256:{manifest_digest}"
    index_document["manifests"][0]["size"] = len(manifest_bytes)
    index_bytes = canonical_json(index_document)
    (out / "index.json").write_bytes(index_bytes)
    (out / "oci-layout").write_bytes(canonical_json({"imageLayoutVersion": "1.0.0"}))

    files = sorted(path for path in out.rglob("*") if path.is_file())
    capture = {
        "format_version": 1,
        "manifest_digest": f"sha256:{manifest_digest}",
        "config_digest": manifest_document["config"]["digest"],
        "layers": stored_layers,
        "files": len(files),
        "layout_bytes": sum(path.stat().st_size for path in files),
    }
    (out.parent / f"{out.name}.capture.json").write_bytes(canonical_json(capture))
    return capture


def build_static(out, binary):
    return write_layout(out, [{"entries": workload_layer(binary)}])


def build_dynamic(out, binary, loader, library):
    return write_layout(
        out,
        [
            {"entries": dynamic_base_layer(loader, library), "compressed": True},
            {"entries": workload_layer(binary)},
        ],
    )


def root_opacity_layers(binary):
    return [
        {
            "entries": [
                directory_entry("bin"),
                file_entry("bin/simferret-workload-fixture", binary, 0o755, 65534, 65534, 0),
                directory_entry("keep"),
                file_entry("keep/lower", b"lower\n", 0o644, 0, 0, 1700000001),
                file_entry("drop", b"drop\n", 0o644, 0, 0, 1700000001),
                directory_entry("dir"),
                file_entry("dir/child", b"child\n", 0o644, 0, 0, 1700000001),
            ]
        },
        {
            "entries": [
                # Root opacity applies to the lower view only, so entries added
                # in the same layer survive even though the marker is last.
                directory_entry("bin"),
                file_entry("bin/simferret-workload-fixture", binary, 0o755, 65534, 65534, 0),
                directory_entry("keep"),
                file_entry("keep/upper", b"upper\n", 0o644, 0, 0, 1700000002),
                file_entry(".wh..wh..opq", b"", 0o644, 0, 0, 0),
            ]
        },
    ]


def build_root_opacity(out, binary):
    return write_layout(out, root_opacity_layers(binary))


def build_semantics(out, binary):
    return write_layout(
        out,
        [
            {"entries": semantics_base_layer(binary)},
            {"entries": semantics_upper_layer()},
        ],
    )


# USTAR stores at most 155 bytes of path prefix and 100 bytes of name, and the
# per-layer entry limit is 4096, so these are the largest layers that stay inside
# every layer limit while producing a large canonical tree manifest.
BIG_MANIFEST_LAYERS = 4
BIG_MANIFEST_ENTRIES_PER_LAYER = 4000
BIG_MANIFEST_PREFIX = "d" * 100 + "/" + "e" * 54
BIG_MANIFEST_NAME_PADDING = 95


def big_manifest_layers(binary):
    """Layers whose union exceeds the bound materialize reads the tree under.

    Every layer stays inside the per-layer entry, path, and size limits, but the
    canonical tree manifest for the union is larger than the derived cache's
    metadata bound. Assembly must refuse the source rather than publish a store
    that cannot be read back.
    """

    layers = [{"entries": workload_layer(binary)}]
    for layer_index in range(BIG_MANIFEST_LAYERS):
        entries = []
        for offset in range(BIG_MANIFEST_ENTRIES_PER_LAYER):
            serial = layer_index * BIG_MANIFEST_ENTRIES_PER_LAYER + offset
            entries.append(
                file_entry(
                    f"{BIG_MANIFEST_PREFIX}/{'f' * BIG_MANIFEST_NAME_PADDING}{serial:05d}",
                    b"x",
                    0o644,
                    0,
                    0,
                    0,
                )
            )
        layers.append({"entries": entries})
    return layers


def build_big_manifest(out, binary):
    return write_layout(out, big_manifest_layers(binary))


def build_adversarial(out, defect, binary):
    simple = lambda: {"entries": workload_layer(binary)}
    if defect == "absolute-path":
        entries = workload_layer(binary) + [file_entry("/etc/passwd", b"x\n", 0o644, 0, 0, 0)]
        return write_layout(out, [{"entries": entries}])
    if defect == "escape-path":
        entries = workload_layer(binary) + [file_entry("../escape", b"x\n", 0o644, 0, 0, 0)]
        return write_layout(out, [{"entries": entries}])
    if defect == "hard-link":
        entries = workload_layer(binary) + [
            {
                "name": "bin/second",
                "kind": "hardlink",
                "mode": 0o755,
                "uid": 65534,
                "gid": 65534,
                "mtime": 0,
                "linkname": "bin/simferret-workload-fixture",
            }
        ]
        return write_layout(out, [{"entries": entries}])
    if defect == "setuid-mode":
        return write_layout(
            out,
            [
                {
                    "entries": [
                        directory_entry("bin"),
                        file_entry("bin/simferret-workload-fixture", binary, 0o4755, 65534, 65534, 0),
                    ]
                }
            ],
        )
    if defect == "device-node":
        entries = workload_layer(binary) + [
            {
                "name": "dev/null",
                "kind": "char",
                "mode": 0o666,
                "uid": 0,
                "gid": 0,
                "mtime": 0,
            }
        ]
        return write_layout(out, [{"entries": entries}])
    if defect == "duplicate-path":
        entries = workload_layer(binary) + [
            file_entry("bin/simferret-workload-fixture", b"duplicate\n", 0o755, 65534, 65534, 0)
        ]
        return write_layout(out, [{"entries": entries}])
    if defect == "symlink-traversal":
        return write_layout(
            out,
            [
                {
                    "entries": [
                        directory_entry("bin"),
                        file_entry("bin/simferret-workload-fixture", binary, 0o755, 65534, 65534, 0),
                        {
                            "name": "redirect",
                            "kind": "symlink",
                            "mode": 0o777,
                            "uid": 0,
                            "gid": 0,
                            "mtime": 0,
                            "target": "elsewhere",
                        },
                    ]
                },
                {"entries": [file_entry("redirect/file", b"x\n", 0o644, 0, 0, 0)]},
            ],
        )
    if defect == "oversized-file":
        entries = workload_layer(binary) + [
            file_entry("data/oversized", b"\0" * OVERSIZED_FILE_BYTES, 0o644, 0, 0, 0)
        ]
        return write_layout(out, [{"entries": entries, "compressed": True}])
    if defect == "unsupported-media-type":
        return write_layout(
            out,
            [
                {
                    "entries": workload_layer(binary),
                    "media_type": "application/vnd.oci.image.layer.v1.tar+zstd",
                }
            ],
        )
    if defect == "wrong-platform":
        return write_layout(
            out,
            [simple()],
            platform={"architecture": "amd64", "os": "darwin"},
        )
    if defect == "diffid-mismatch":
        def mutate(config, manifest, index):
            config["rootfs"]["diff_ids"][0] = "sha256:" + "0" * 64

        return write_layout(out, [simple()], mutate=mutate)
    if defect == "rootfs-type":
        def mutate(config, manifest, index):
            config["rootfs"]["type"] = "squashfs"

        return write_layout(out, [simple()], mutate=mutate)
    if defect == "nonempty-whiteout":
        return write_layout(
            out,
            [
                {
                    "entries": [
                        directory_entry("bin"),
                        file_entry("bin/simferret-workload-fixture", binary, 0o755, 65534, 65534, 0),
                        file_entry("victim", b"victim\n", 0o644, 0, 0, 0),
                    ]
                },
                {"entries": [file_entry(".wh.victim", b"not empty\n", 0o644, 0, 0, 0)]},
            ],
        )
    if defect == "marker-through-symlink":
        return write_layout(
            out,
            [
                {
                    "entries": [
                        directory_entry("bin"),
                        file_entry("bin/simferret-workload-fixture", binary, 0o755, 65534, 65534, 0),
                        {
                            "name": "redirect",
                            "kind": "symlink",
                            "mode": 0o777,
                            "uid": 0,
                            "gid": 0,
                            "mtime": 0,
                            "target": "elsewhere",
                        },
                    ]
                },
                {"entries": [file_entry("redirect/.wh.victim", b"", 0o644, 0, 0, 0)]},
            ],
        )
    if defect == "chained-symlink-escape":
        return write_layout(
            out,
            [
                {
                    "entries": [
                        directory_entry("bin"),
                        file_entry("bin/simferret-workload-fixture", binary, 0o755, 65534, 65534, 0),
                        {
                            "name": "a",
                            "kind": "symlink",
                            "mode": 0o777,
                            "uid": 0,
                            "gid": 0,
                            "mtime": 0,
                            "target": ".",
                        },
                        {
                            "name": "b",
                            "kind": "symlink",
                            "mode": 0o777,
                            "uid": 0,
                            "gid": 0,
                            "mtime": 0,
                            "target": "a/../outside",
                        },
                    ]
                }
            ],
        )
    if defect == "whiteout-not-basename":
        entries = workload_layer(binary) + [file_entry(".wh.a/b", b"", 0o644, 0, 0, 0)]
        return write_layout(out, [{"entries": entries}])
    if defect in ("corrupt-blob", "missing-blob"):
        capture = write_layout(out, [simple()])
        layer = Path(out) / "blobs" / "sha256" / capture["layers"][0]["digest"].split(":")[1]
        if defect == "corrupt-blob":
            data = bytearray(layer.read_bytes())
            data[len(data) // 2] ^= 0xFF
            layer.write_bytes(bytes(data))
        else:
            layer.unlink()
        return capture
    raise SystemExit(f"unknown adversarial defect {defect}")


DEFECTS = (
    "absolute-path",
    "escape-path",
    "hard-link",
    "setuid-mode",
    "device-node",
    "duplicate-path",
    "symlink-traversal",
    "oversized-file",
    "unsupported-media-type",
    "wrong-platform",
    "diffid-mismatch",
    "rootfs-type",
    "corrupt-blob",
    "missing-blob",
    "nonempty-whiteout",
    "marker-through-symlink",
    "chained-symlink-escape",
    "whiteout-not-basename",
)


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    static_parser = subcommands.add_parser("static")
    static_parser.add_argument("--binary", required=True)
    static_parser.add_argument("--out", required=True)

    dynamic_parser = subcommands.add_parser("dynamic")
    dynamic_parser.add_argument("--binary", required=True)
    dynamic_parser.add_argument("--loader", required=True)
    dynamic_parser.add_argument("--library", required=True)
    dynamic_parser.add_argument("--out", required=True)

    root_opacity_parser = subcommands.add_parser("root-opacity")
    root_opacity_parser.add_argument("--binary", required=True)
    root_opacity_parser.add_argument("--out", required=True)

    semantics_parser = subcommands.add_parser("semantics")
    semantics_parser.add_argument("--binary", required=True)
    semantics_parser.add_argument("--out", required=True)

    big_manifest_parser = subcommands.add_parser("big-manifest")
    big_manifest_parser.add_argument("--binary", required=True)
    big_manifest_parser.add_argument("--out", required=True)

    adversarial_parser = subcommands.add_parser("adversarial")
    adversarial_parser.add_argument("--defect", required=True, choices=DEFECTS)
    adversarial_parser.add_argument("--binary", required=True)
    adversarial_parser.add_argument("--out", required=True)

    subcommands.add_parser("defects")

    arguments = parser.parse_args(argv)
    if arguments.command == "defects":
        print("\n".join(DEFECTS))
        return 0
    if arguments.command == "static":
        capture = build_static(arguments.out, Path(arguments.binary).read_bytes())
    elif arguments.command == "dynamic":
        capture = build_dynamic(
            arguments.out,
            Path(arguments.binary).read_bytes(),
            Path(arguments.loader).read_bytes(),
            Path(arguments.library).read_bytes(),
        )
    elif arguments.command == "root-opacity":
        capture = build_root_opacity(arguments.out, Path(arguments.binary).read_bytes())
    elif arguments.command == "semantics":
        capture = build_semantics(arguments.out, Path(arguments.binary).read_bytes())
    elif arguments.command == "big-manifest":
        capture = build_big_manifest(arguments.out, Path(arguments.binary).read_bytes())
    else:
        capture = build_adversarial(arguments.out, arguments.defect, Path(arguments.binary).read_bytes())
    print(json.dumps(capture, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
