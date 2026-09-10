#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_root="${SIMFERRET_RFD3_PHASE1_OUTPUT:-$repo_root/.poc/rfd3-phase1-evidence}"
cc="${CC:-cc}"
binary="$repo_root/target/x86_64-unknown-linux-musl/release/simferret"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "The RFD 3 Phase 1 evidence run supports x86-64 Linux only." >&2
  exit 1
fi
for command in "$cc" python3 cargo du find jq sha256sum stat; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done

umask 077
mkdir -p "$output_root"
capture="$(mktemp -d "$output_root/run.XXXXXXXX")"
trap 'rm -rf "$capture"' EXIT

cargo build --manifest-path "$repo_root/Cargo.toml" \
  --locked --release --target x86_64-unknown-linux-musl \
  --target-dir "$repo_root/target"

workload="$capture/simferret-workload"
"$cc" -static -Os -Wall -Wextra -Werror \
  "$repo_root/poc/rfd3-workload/main.c" -o "$workload"

layout="$capture/layout"
manifest_digest="$(python3 - "$workload" "$layout" <<'PY'
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

workload = Path(sys.argv[1])
layout = Path(sys.argv[2])
blobs = layout / "blobs" / "sha256"
blobs.mkdir(parents=True)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def store(data):
    identity = hashlib.sha256(data).hexdigest()
    (blobs / identity).write_bytes(data)
    return identity


def entry(archive, name, mode, uid, gid, mtime, data=None, kind=tarfile.REGTYPE):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.mode = mode
    info.uid = uid
    info.gid = gid
    info.mtime = mtime
    info.uname = ""
    info.gname = ""
    if data is not None:
        info.size = len(data)
    archive.addfile(info, io.BytesIO(data) if data is not None else None)


executable = workload.read_bytes()
layer_buffer = io.BytesIO()
with tarfile.open(fileobj=layer_buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
    entry(archive, "bin/", 0o755, 0, 0, 0, kind=tarfile.DIRTYPE)
    entry(archive, "bin/simferret-workload", 0o755, 65534, 65534, 0, data=executable)
layer = layer_buffer.getvalue()
layer_digest = store(layer)

config = encoded({
    "architecture": "amd64",
    "config": {
        "Entrypoint": ["/bin/simferret-workload"],
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
        "digest": f"sha256:{manifest_digest}",
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "platform": {"architecture": "amd64", "os": "linux"},
        "size": len(manifest),
    }],
    "schemaVersion": 2,
})
(layout / "index.json").write_bytes(index)
(layout / "oci-layout").write_bytes(encoded({"imageLayoutVersion": "1.0.0"}))
print(manifest_digest)
PY
)"

cat >"$capture/binary.toml" <<'EOF'
version = 1
kind = "binary"
path = "simferret-workload"
args = []
env = ["MODE=acceptance"]
working_directory = "/"
user = "65534:65534"
EOF

cat >"$capture/oci.toml" <<EOF
version = 1
kind = "oci"
layout = "layout"
manifest_digest = "sha256:$manifest_digest"
EOF

started="$(date +%s%N)"
"$binary" workload assemble \
  --specification "$capture/binary.toml" --store "$capture/binary-store" \
  >"$capture/binary.stdout"
"$binary" workload assemble \
  --specification "$capture/oci.toml" --store "$capture/oci-store" \
  >"$capture/oci.stdout"
finished="$(date +%s%N)"
assembly_duration_ns=$((finished - started))

"$binary" workload verify "$capture/binary-store" >"$capture/binary.verify"
"$binary" workload verify "$capture/oci-store" >"$capture/oci.verify"

"$binary" workload assemble \
  --specification "$capture/binary.toml" --store "$capture/second-store" \
  >"$capture/second.stdout"

value() {
  awk -F ': ' -v key="$2" '$1 == key { print $2 }' "$1"
}

binary_canonical="$(value "$capture/binary.stdout" canonical)"
oci_canonical="$(value "$capture/oci.stdout" canonical)"
binary_closure="$(value "$capture/binary.stdout" closure)"
second_closure="$(value "$capture/second.stdout" closure)"

if [[ "$binary_canonical" != "$oci_canonical" ]]; then
  echo "binary and OCI sources did not converge: $binary_canonical vs $oci_canonical" >&2
  exit 1
fi
if [[ "$binary_closure" != "$second_closure" ]]; then
  echo "re-assembly did not reproduce the closure identity" >&2
  exit 1
fi
if ! diff -q "$capture/binary.stdout" "$capture/second.stdout" >/dev/null; then
  echo "re-assembly did not reproduce the assembly summary" >&2
  exit 1
fi

{
  echo "format_version=1"
  echo "fixture_source_sha256=$(sha256sum "$repo_root/poc/rfd3-workload/main.c" | cut -d' ' -f1)"
  echo "static_executable_bytes=$(stat -c %s "$workload")"
  echo "static_executable_sha256=$(sha256sum "$workload" | cut -d' ' -f1)"
  echo "oci_manifest_digest=sha256:$manifest_digest"
  echo "oci_layout_bytes=$(find "$layout" -type f -printf '%s\n' | awk '{ total += $1 } END { print total }')"
  echo "assembly_duration_ns=$assembly_duration_ns"
  echo "binary_canonical=$binary_canonical"
  echo "binary_closure=$binary_closure"
  echo "binary_tree=$(value "$capture/binary.stdout" tree)"
  echo "binary_template=$(value "$capture/binary.stdout" template)"
  echo "binary_executable=$(value "$capture/binary.stdout" executable)"
  echo "binary_entries=$(value "$capture/binary.stdout" entries)"
  echo "binary_expanded_bytes=$(value "$capture/binary.stdout" 'expanded bytes')"
  echo "binary_raw_objects=$(value "$capture/binary.stdout" 'raw objects')"
  echo "oci_canonical=$oci_canonical"
  echo "oci_closure=$(value "$capture/oci.stdout" closure)"
  echo "oci_tree=$(value "$capture/oci.stdout" tree)"
  echo "oci_template=$(value "$capture/oci.stdout" template)"
  echo "oci_entries=$(value "$capture/oci.stdout" entries)"
  echo "oci_expanded_bytes=$(value "$capture/oci.stdout" 'expanded bytes')"
  echo "oci_raw_objects=$(value "$capture/oci.stdout" 'raw objects')"
  echo "binary_store_bytes=$(du -sb "$capture/binary-store" | cut -f1)"
  echo "oci_store_bytes=$(du -sb "$capture/oci-store" | cut -f1)"
  echo "verify_canonical=$(value "$capture/binary.verify" canonical)"
  echo "reassembly_equal=true"
} >"$capture/evidence.txt"

trap - EXIT
cat "$capture/evidence.txt"
echo "evidence: $capture"
