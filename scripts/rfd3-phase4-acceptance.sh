#!/usr/bin/env bash
# RFD 3 Phase 4 acceptance: unprivileged acceptance and evidence.
#
# Runs the checked-in Phase 3 record-and-two-replay demonstration for the
# standalone binary and both local OCI source forms, then adds the Phase 4
# evidence the RFD requires: assembly cost, the ambient-input exclusion check,
# the private-artifact and shareable-diagnostic classification check, and the
# workload output and traffic volumes. Every command runs without elevated
# privileges, a container daemon, a registry, or a host mount.
#
# The guest-visible OCI conformance check changes root, drops credentials, and
# creates device nodes, so it runs separately as PID 1 under
# `scripts/rfd3-phase4-runtime.sh`; this script records its result when it is
# already root and otherwise names the checked-in command.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_root="${SIMFERRET_RFD3_PHASE4_OUTPUT:-$repo_root/.poc/rfd3-phase4-acceptance}"
kernel="${SIMFERRET_KERNEL:-}"
qemu="${QEMU_SYSTEM_X86_64:-qemu-system-x86_64}"
binary="$repo_root/target/x86_64-unknown-linux-musl/release/simferret"
python="${PYTHON:-python3}"
phase3_script="$repo_root/scripts/rfd3-phase3-acceptance.sh"
runtime_script="$repo_root/scripts/rfd3-phase4-runtime.sh"
ambient_canary="SIMFERRET_PHASE4_AMBIENT_CANARY"
ambient_value="ambient-canary-value"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "RFD 3 phase 4 acceptance supports x86-64 Linux only." >&2
  exit 1
fi
if [[ -z "$kernel" || ! -f "$kernel" ]]; then
  echo "SIMFERRET_KERNEL must name the pinned x86-64 Linux bzImage." >&2
  echo "Run this script through .agents/dev." >&2
  exit 1
fi
for command in cargo "$qemu" "$python" jq mktemp sha256sum stat du; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done
if [[ ! -x "$phase3_script" ]]; then
  echo "The Phase 3 acceptance script must be executable: $phase3_script" >&2
  exit 1
fi

umask 022
mkdir -p "$output_root"
output_dir="$(mktemp -d "$output_root/run.XXXXXXXX")"

run_timed() {
  local name="$1"
  local stdout="$output_dir/$name.stdout"
  local stderr="$output_dir/$name.stderr"
  local started finished
  shift

  started="$(date +%s%N)"
  set +e
  "$@" >"$stdout" 2>"$stderr"
  RUN_STATUS=$?
  set -e
  finished="$(date +%s%N)"
  RUN_DURATION_NS=$((finished - started))
  printf '%s\n' "$RUN_STATUS" >"$output_dir/$name.status"
  printf '%s\n' "$RUN_DURATION_NS" >"$output_dir/$name.duration-ns"
}

expect_status() {
  local name="$1"
  local expected="$2"
  if [[ "$RUN_STATUS" -ne "$expected" ]]; then
    echo "$name returned $RUN_STATUS; expected $expected" >&2
    cat "$output_dir/$name.stderr" >&2
    exit 1
  fi
}

require_absent() {
  local name="$1" needle="$2" path="$3"
  if grep -R -F -- "$needle" "$path" >/dev/null 2>&1; then
    echo "$name: '$needle' must not appear under $path" >&2
    exit 1
  fi
}

require_mode() {
  local path="$1" expected="$2"
  local mode
  mode="$(stat -c %a "$path")"
  if [[ "$mode" != "$expected" ]]; then
    echo "$path is mode $mode; expected $expected" >&2
    exit 1
  fi
}

json_field() {
  "$python" -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

# The phase 3 demonstration builds the static and dynamic fixtures, packages the
# static one as both source forms, records and passively replays each twice, and
# rejects a self-consistently changed lock, a changed derived cache entry, a
# missing raw closure, and a removed closure-referenced raw object.
phase3_out="$output_dir/phase3"
mkdir -p "$phase3_out"
run_timed phase3 env SIMFERRET_RFD3_PHASE3_OUTPUT="$phase3_out" "$phase3_script"
expect_status phase3 0

mapfile -t phase3_runs < <(find "$phase3_out" -maxdepth 1 -type d -name 'run.*' | sort)
if [[ "${#phase3_runs[@]}" -ne 1 ]]; then
  echo "expected exactly one Phase 3 evidence directory, found ${#phase3_runs[@]}" >&2
  exit 1
fi
phase3_run="${phase3_runs[0]}"

# ---------------------------------------------------------------------------
# Assembly cost, measured independently of the recorded runs
# ---------------------------------------------------------------------------
assembly="$output_dir/assembly"
mkdir -p "$assembly"
cp "$phase3_run/sources/app" "$assembly/app"
cat >"$assembly/workload.toml" <<'EOF'
version = 1
kind = "binary"
path = "app"
args = []
env = ["MODE=acceptance"]
working_directory = "/"
user = "65534:65534"
EOF

run_timed assemble env SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
  "$binary" workload assemble --specification "$assembly/workload.toml" \
  --store "$assembly/store"
expect_status assemble 0
assembly_duration_ns="$(cat "$output_dir/assemble.duration-ns")"
assembly_canonical="$(awk -F ': ' '$1 == "canonical" { print $2 }' "$output_dir/assemble.stdout")"
assembly_closure="$(awk -F ': ' '$1 == "closure" { print $2 }' "$output_dir/assemble.stdout")"
assembly_entries="$(awk -F ': ' '$1 == "entries" { print $2 }' "$output_dir/assemble.stdout")"
assembly_expanded="$(awk -F ': ' '$1 == "expanded bytes" { print $2 }' "$output_dir/assemble.stdout")"
assembly_objects="$(awk -F ': ' '$1 == "raw objects" { print $2 }' "$output_dir/assemble.stdout")"
assembly_store_bytes="$(du -sb "$assembly/store" | cut -f1)"
assembly_template_bytes="$(stat -c %s "$assembly/store/derived/$assembly_canonical/template.cpio")"

# ---------------------------------------------------------------------------
# Ambient host input never enters the workload
# ---------------------------------------------------------------------------
ambient="$output_dir/ambient"
mkdir -p "$ambient"
cp "$assembly/app" "$ambient/app"
cp "$assembly/workload.toml" "$ambient/workload.toml"
run_timed ambient env "$ambient_canary=$ambient_value" \
  SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
  "$binary" workload assemble --specification "$ambient/workload.toml" \
  --store "$ambient/store"
expect_status ambient 0
ambient_canonical="$(awk -F ': ' '$1 == "canonical" { print $2 }' "$output_dir/ambient.stdout")"
if [[ "$ambient_canonical" != "$assembly_canonical" ]]; then
  echo "the ambient environment changed the canonical identity" >&2
  exit 1
fi
# The canary value, the host output path, and every host environment value the
# process was given must stay out of the retained closure and derived lock.
require_absent "ambient canary" "$ambient_value" "$ambient/store"
require_absent "host path" "$output_dir" "$ambient/store/raw/closure.json"
require_absent "host path" "$output_dir" "$ambient/store/derived/$ambient_canonical/lock.json"
launch_environment="$(jq -c '.launch.environment' "$ambient/store/raw/closure.json")"
if [[ "$launch_environment" != '["MODE=acceptance"]' ]]; then
  echo "the workload inherited an unexpected environment: $launch_environment" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Private artifacts are owner-only and the shareable bundle excludes workload data
# ---------------------------------------------------------------------------
private_runs="$phase3_run/runs-binary"
record_run="$(awk -F ': ' '$1 == "artifacts" { print substr($0, length($1) + 3) }' \
  "$phase3_run/record-binary.stdout")"
# The run directory, the guest image cache, and the workload store carry the
# recorded environment, the exact streams, and the replay closure, so each is
# owner-only. The runs directory that contains them holds only owner-only
# children.
require_mode "$record_run" 700
require_mode "$private_runs/.images" 700
require_mode "$private_runs/.workload-store" 700
for artifact in events.jsonl assertions.json workload.lock manifest.json; do
  require_mode "$record_run/$artifact" 600
done

mapfile -t bundles < <(find "$private_runs/failures" -mindepth 1 -maxdepth 1 -type d | sort)
if [[ "${#bundles[@]}" -lt 1 ]]; then
  echo "the rejected tamper cases published no shareable failure bundle" >&2
  exit 1
fi
for bundle in "${bundles[@]}"; do
  # A shareable bundle carries typed errors and counts, never the recorded launch
  # environment or the exact workload stream bytes.
  require_absent "shareable environment" "MODE=acceptance" "$bundle"
  require_absent "shareable stream bytes" "ready version=1" "$bundle"
  if ! grep -R -F '"error_kind"' "$bundle" >/dev/null 2>&1; then
    echo "the shareable bundle $bundle names no typed error" >&2
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# Workload output and traffic volume, and the recorded identities
# ---------------------------------------------------------------------------
measurements="$output_dir/measurements.txt"
: >"$measurements"
for name in binary oci-static oci-dynamic; do
  run_dir="$(awk -F ': ' '$1 == "artifacts" { print substr($0, length($1) + 3) }' \
    "$phase3_run/record-$name.stdout")"
  if [[ -z "$run_dir" || ! -d "$run_dir" ]]; then
    echo "the Phase 3 $name recording published no run directory" >&2
    exit 1
  fi
  jq -e '.passed' "$run_dir/assertions.json" >/dev/null
  read -r stdout_bytes stderr_bytes attempted succeeded unavailable <<<"$("$python" - "$run_dir/events.jsonl" <<'PY'
import json
import sys

stdout_bytes = 0
stderr_bytes = 0
streams = {}
with open(sys.argv[1], encoding="utf-8") as handle:
    for line in handle:
        event = json.loads(line)["event"]
        if event["type"] == "workload_exited":
            stdout_bytes += event["stdout_bytes"]
            stderr_bytes += event["stderr_bytes"]
        elif event["type"] == "workload_output" and event["stream"] == "stdout":
            streams.setdefault(event["invocation"], bytearray()).extend(
                bytes.fromhex(event["bytes"])
            )
# The packaged workload, not the agent, originates the network traffic, so its
# volume is read from the reconstructed stdout lines it printed.
succeeded = 0
unavailable = 0
for data in streams.values():
    for line in bytes(data).split(b"\n"):
        if line.startswith(b"network state=ok "):
            succeeded += 1
        elif line.startswith(b"network state=unavailable "):
            unavailable += 1
print(stdout_bytes, stderr_bytes, succeeded + unavailable, succeeded, unavailable)
PY
)"
  canonical="$(jq -r '.workload.canonical_digest' "$run_dir/workload.lock")"
  {
    printf '%s_canonical=%s\n' "$name" "$canonical"
    printf '%s_workload_stdout_bytes=%s\n' "$name" "$stdout_bytes"
    printf '%s_workload_stderr_bytes=%s\n' "$name" "$stderr_bytes"
    printf '%s_traffic_attempted=%s\n' "$name" "$attempted"
    printf '%s_traffic_succeeded=%s\n' "$name" "$succeeded"
    printf '%s_traffic_unavailable=%s\n' "$name" "$unavailable"
  } >>"$measurements"
done

# The guest-visible conformance check needs root and a private PID namespace. It
# is the checked-in Phase 4 runtime command; record whether it ran here.
conformance="not run here; run scripts/rfd3-phase4-runtime.sh as root"
if [[ "$(id -u)" -eq 0 && -x "$runtime_script" && -n "${SIMFERRET_BUSYBOX:-}" ]]; then
  run_timed conformance env SIMFERRET_BUSYBOX="$SIMFERRET_BUSYBOX" "$runtime_script"
  expect_status conformance 0
  conformance="passed; see conformance.stdout"
fi

{
  printf 'qemu_version=%s\n' "$("$qemu" --version | head -n 1)"
  printf 'kernel=%s\n' "$kernel"
  printf 'phase3_duration_ns=%s\n' "$(cat "$output_dir/phase3.duration-ns")"
  printf 'assembly_duration_ns=%s\n' "$assembly_duration_ns"
  printf 'assembly_canonical=%s\n' "$assembly_canonical"
  printf 'assembly_closure=%s\n' "$assembly_closure"
  printf 'assembly_entries=%s\n' "$assembly_entries"
  printf 'assembly_expanded_bytes=%s\n' "$assembly_expanded"
  printf 'assembly_raw_objects=%s\n' "$assembly_objects"
  printf 'assembly_store_bytes=%s\n' "$assembly_store_bytes"
  printf 'assembly_template_bytes=%s\n' "$assembly_template_bytes"
  printf 'ambient_identity_unchanged=%s\n' "$ambient_canonical"
  printf 'shareable_bundles=%s\n' "${#bundles[@]}"
  printf 'shareable_excludes_environment_and_streams=yes\n'
  printf 'private_artifacts=run directory, guest image cache, workload store, and run artifacts are owner-only\n'
  printf 'guest_visible_conformance=%s\n' "$conformance"
  cat "$measurements"
} >"$output_dir/evidence.txt"

cat "$output_dir/evidence.txt"
printf '\nRFD 3 phase 4 acceptance passed; artifacts: %s\n' "$output_dir"
