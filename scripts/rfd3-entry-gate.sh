#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_root="${SIMFERRET_RFD3_ENTRY_OUTPUT:-$repo_root/.poc/rfd3-entry-gate}"
cc="${CC:-cc}"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "The RFD 3 entry gate supports x86-64 Linux only." >&2
  exit 1
fi
for command in "$cc" python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done

umask 077
mkdir -p "$output_root"
capture="$(mktemp -d "$output_root/capture.XXXXXXXX")"
trap 'rm -rf "$capture"' EXIT

binary="$capture/simferret-workload-fixture"
layout="$capture/oci-layout"
"$cc" -static -Os -Wall -Wextra -Werror \
  "$repo_root/poc/rfd3-workload/main.c" -o "$binary"
mkdir -p "$layout/blobs/sha256"

python3 - "$repo_root" "$binary" "$layout" <<'PY'
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

repo = Path(sys.argv[1])
binary = Path(sys.argv[2])
layout = Path(sys.argv[3])


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def store(data):
    identity = digest(data)
    (layout / "blobs" / "sha256" / identity).write_bytes(data)
    return identity


binary_bytes = binary.read_bytes()
layer_buffer = io.BytesIO()
with tarfile.open(fileobj=layer_buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
    directory = tarfile.TarInfo("bin/")
    directory.type = tarfile.DIRTYPE
    directory.mode = 0o755
    directory.uid = 0
    directory.gid = 0
    directory.mtime = 0
    directory.uname = ""
    directory.gname = ""
    archive.addfile(directory)

    executable = tarfile.TarInfo("bin/simferret-workload-fixture")
    executable.mode = 0o755
    executable.uid = 65534
    executable.gid = 65534
    executable.mtime = 0
    executable.uname = ""
    executable.gname = ""
    executable.size = len(binary_bytes)
    archive.addfile(executable, io.BytesIO(binary_bytes))

layer = layer_buffer.getvalue()
layer_digest = store(layer)
config = encoded({
    "architecture": "amd64",
    "config": {
        "Entrypoint": ["/bin/simferret-workload-fixture"],
        "Env": ["MODE=acceptance"],
        "User": "65534:65534",
        "WorkingDir": "/",
    },
    "os": "linux",
    "rootfs": {"diff_ids": [f"sha256:{layer_digest}"], "type": "layers"},
})
config_digest = store(config)
manifest = encoded({
    "config": {
        "digest": f"sha256:{config_digest}",
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "size": len(config),
    },
    "layers": [{
        "digest": f"sha256:{layer_digest}",
        "mediaType": "application/vnd.oci.image.layer.v1.tar",
        "size": len(layer),
    }],
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "schemaVersion": 2,
})
manifest_digest = store(manifest)
index = encoded({
    "manifests": [{
        "annotations": {"org.opencontainers.image.ref.name": "rfd3-entry-gate"},
        "digest": f"sha256:{manifest_digest}",
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "platform": {"architecture": "amd64", "os": "linux"},
        "size": len(manifest),
    }],
    "schemaVersion": 2,
})
(layout / "index.json").write_bytes(index)
(layout / "oci-layout").write_bytes(encoded({"imageLayoutVersion": "1.0.0"}))

source = (repo / "poc" / "rfd3-workload" / "main.c").read_bytes()
layout_files = sorted(path for path in layout.rglob("*") if path.is_file())
capture = {
    "binary": {"bytes": len(binary_bytes), "sha256": digest(binary_bytes)},
    "fixture_source_sha256": digest(source),
    "format_version": 1,
    "oci": {
        "config": {"bytes": len(config), "sha256": config_digest},
        "files": len(layout_files),
        "layer": {
            "bytes": len(layer),
            "diff_id": f"sha256:{layer_digest}",
            "sha256": layer_digest,
        },
        "layout_bytes": sum(path.stat().st_size for path in layout_files),
        "manifest": {"bytes": len(manifest), "sha256": manifest_digest},
    },
}
(layout.parent / "capture.json").write_bytes(encoded(capture))
PY

trap - EXIT
cat "$capture/capture.json"
