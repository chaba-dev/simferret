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
for command in "$cc" python3 cargo du find jq sha256sum stat cmp; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done

umask 022
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
  local found
  # The failing status is propagated explicitly: inside a command substitution
  # `errexit` is disabled, so a reader that emits a usable field and then fails
  # would otherwise be accepted as success.
  if ! found="$(awk -F ': ' -v key="$2" '$1 == key { print $2 }' "$1")"; then
    echo "cannot read field '$2' from $1" >&2
    return 1
  fi
  if [[ -z "$found" ]]; then
    echo "missing field '$2' in $1" >&2
    return 1
  fi
  printf '%s\n' "$found"
}

require_digest() {
  if [[ ! "$2" =~ ^[0-9a-f]{64}$ ]]; then
    echo "$1 is not a sha256 digest: '$2'" >&2
    exit 1
  fi
}

require_count() {
  if [[ ! "$2" =~ ^[0-9]+$ ]]; then
    echo "$1 is not a count: '$2'" >&2
    exit 1
  fi
}

# Fault injection: a reader that emits a usable field and then fails must still
# abort the script, because partial output is not a valid field.
fault_bin="$capture/fault-injection"
mkdir -p "$fault_bin"
cat >"$fault_bin/awk" <<'FAULT'
#!/bin/sh
printf 'canonical: %064d\n' 0
exit 7
FAULT
chmod 700 "$fault_bin/awk"
export -f value
if PATH="$fault_bin:$PATH" bash -c 'value "$1" canonical' _ "$capture/binary.stdout" \
  >/dev/null 2>&1; then
  echo "the field reader accepted a failed command with partial output" >&2
  exit 1
fi

require_digest "oci manifest digest" "$manifest_digest"

# Every reported field is read into a variable here, where a missing field
# aborts the script, rather than inside the report block where `echo` would mask
# the substitution's failing status.
binary_canonical="$(value "$capture/binary.stdout" canonical)"
oci_canonical="$(value "$capture/oci.stdout" canonical)"
binary_closure="$(value "$capture/binary.stdout" closure)"
second_closure="$(value "$capture/second.stdout" closure)"
oci_closure="$(value "$capture/oci.stdout" closure)"
binary_tree="$(value "$capture/binary.stdout" tree)"
oci_tree="$(value "$capture/oci.stdout" tree)"
binary_template="$(value "$capture/binary.stdout" template)"
oci_template="$(value "$capture/oci.stdout" template)"
binary_executable="$(value "$capture/binary.stdout" executable)"
oci_executable="$(value "$capture/oci.stdout" executable)"
binary_entries="$(value "$capture/binary.stdout" entries)"
oci_entries="$(value "$capture/oci.stdout" entries)"
binary_expanded_bytes="$(value "$capture/binary.stdout" 'expanded bytes')"
oci_expanded_bytes="$(value "$capture/oci.stdout" 'expanded bytes')"
binary_raw_objects="$(value "$capture/binary.stdout" 'raw objects')"
oci_raw_objects="$(value "$capture/oci.stdout" 'raw objects')"
binary_verify_canonical="$(value "$capture/binary.verify" canonical)"
oci_verify_canonical="$(value "$capture/oci.verify" canonical)"

for pair in \
  "binary canonical digest:$binary_canonical" \
  "oci canonical digest:$oci_canonical" \
  "binary closure digest:$binary_closure" \
  "re-assembled closure digest:$second_closure" \
  "oci closure digest:$oci_closure" \
  "binary tree digest:$binary_tree" \
  "oci tree digest:$oci_tree" \
  "binary template digest:$binary_template" \
  "oci template digest:$oci_template" \
  "binary verification digest:$binary_verify_canonical" \
  "oci verification digest:$oci_verify_canonical"; do
  require_digest "${pair%%:*}" "${pair#*:}"
done

if [[ "$binary_canonical" != "$oci_canonical" ]]; then
  echo "binary and OCI sources did not converge: $binary_canonical vs $oci_canonical" >&2
  exit 1
fi
if [[ "$binary_tree" != "$oci_tree" ]]; then
  echo "binary and OCI trees did not converge: $binary_tree vs $oci_tree" >&2
  exit 1
fi
if [[ "$binary_template" != "$oci_template" ]]; then
  echo "binary and OCI templates did not converge: $binary_template vs $oci_template" >&2
  exit 1
fi
if [[ "$binary_closure" != "$second_closure" ]]; then
  echo "re-assembly did not reproduce the closure identity" >&2
  exit 1
fi
if [[ "$binary_verify_canonical" != "$binary_canonical" ]]; then
  echo "binary verification reported a different canonical digest: $binary_verify_canonical" >&2
  exit 1
fi
if [[ "$oci_verify_canonical" != "$oci_canonical" ]]; then
  echo "OCI verification reported a different canonical digest: $oci_verify_canonical" >&2
  exit 1
fi
if ! diff -q "$capture/binary.stdout" "$capture/second.stdout" >/dev/null; then
  echo "re-assembly did not reproduce the assembly summary" >&2
  exit 1
fi

# The convergence above is only meaningful if the two independently derived
# guest templates are byte-identical, so compare the stored artifacts directly.
binary_stored_template="$capture/binary-store/derived/$binary_canonical/template.cpio"
oci_stored_template="$capture/oci-store/derived/$oci_canonical/template.cpio"
for stored_template in "$binary_stored_template" "$oci_stored_template"; do
  if [[ ! -f "$stored_template" ]]; then
    echo "missing stored guest template: $stored_template" >&2
    exit 1
  fi
done
if ! cmp -s "$binary_stored_template" "$oci_stored_template"; then
  echo "the stored guest templates are not byte-identical" >&2
  exit 1
fi

# Every directory and file in both stores must be owner-only, not just the two
# paths sampled above. The inventory is written to a private file and `find`'s
# own status is checked, so a partial or failed enumeration cannot pass.
check_store_permissions() {
  local store="$1" inventory="$2" path mode
  if ! find "$store" -mindepth 1 -print0 >"$inventory"; then
    echo "cannot enumerate store contents: $store" >&2
    exit 1
  fi
  while IFS= read -r -d '' path; do
    mode="$(stat -c %a "$path")"
    if [[ -d "$path" && "$mode" != "700" ]]; then
      echo "store directory is not owner-only: $path ($mode)" >&2
      exit 1
    fi
    if [[ -f "$path" && "$mode" != "600" ]]; then
      echo "store file is not owner-only: $path ($mode)" >&2
      exit 1
    fi
  done <"$inventory"
}
for store in "$capture/binary-store" "$capture/oci-store"; do
  if [[ "$(stat -c %a "$store")" != "700" ]]; then
    echo "the store root is not owner-only: $store" >&2
    exit 1
  fi
  check_store_permissions "$store" "$capture/inventory.$(basename "$store")"
done

# The remaining report fields are computed here for the same reason: a failing
# substitution inside the report block would be masked by `echo`.
fixture_source_sha256="$(sha256sum "$repo_root/poc/rfd3-workload/main.c" | cut -d' ' -f1)"
static_executable_bytes="$(stat -c %s "$workload")"
static_executable_sha256="$(sha256sum "$workload" | cut -d' ' -f1)"
oci_layout_bytes="$(find "$layout" -type f -printf '%s\n' | awk '{ total += $1 } END { print total }')"
binary_store_bytes="$(du -sb "$capture/binary-store" | cut -f1)"
oci_store_bytes="$(du -sb "$capture/oci-store" | cut -f1)"

for pair in \
  "fixture source digest:$fixture_source_sha256" \
  "static executable digest:$static_executable_sha256"; do
  require_digest "${pair%%:*}" "${pair#*:}"
done
for pair in \
  "static executable bytes:$static_executable_bytes" \
  "oci layout bytes:$oci_layout_bytes" \
  "binary store bytes:$binary_store_bytes" \
  "oci store bytes:$oci_store_bytes" \
  "assembly duration:$assembly_duration_ns" \
  "binary entries:$binary_entries" \
  "oci entries:$oci_entries" \
  "binary expanded bytes:$binary_expanded_bytes" \
  "oci expanded bytes:$oci_expanded_bytes" \
  "binary raw objects:$binary_raw_objects" \
  "oci raw objects:$oci_raw_objects"; do
  require_count "${pair%%:*}" "${pair#*:}"
done

{
  echo "format_version=1"
  echo "fixture_source_sha256=$fixture_source_sha256"
  echo "static_executable_bytes=$static_executable_bytes"
  echo "static_executable_sha256=$static_executable_sha256"
  echo "oci_manifest_digest=sha256:$manifest_digest"
  echo "oci_layout_bytes=$oci_layout_bytes"
  echo "assembly_duration_ns=$assembly_duration_ns"
  echo "binary_canonical=$binary_canonical"
  echo "binary_closure=$binary_closure"
  echo "binary_tree=$binary_tree"
  echo "binary_template=$binary_template"
  echo "binary_executable=$binary_executable"
  echo "binary_entries=$binary_entries"
  echo "binary_expanded_bytes=$binary_expanded_bytes"
  echo "binary_raw_objects=$binary_raw_objects"
  echo "oci_canonical=$oci_canonical"
  echo "oci_closure=$oci_closure"
  echo "oci_tree=$oci_tree"
  echo "oci_template=$oci_template"
  echo "oci_executable=$oci_executable"
  echo "oci_entries=$oci_entries"
  echo "oci_expanded_bytes=$oci_expanded_bytes"
  echo "oci_raw_objects=$oci_raw_objects"
  echo "binary_store_bytes=$binary_store_bytes"
  echo "oci_store_bytes=$oci_store_bytes"
  echo "verify_canonical=$binary_verify_canonical"
  echo "oci_verify_canonical=$oci_verify_canonical"
  echo "reassembly_equal=true"
} >"$capture/evidence.txt"

trap - EXIT
cat "$capture/evidence.txt"
echo "evidence: $capture"
