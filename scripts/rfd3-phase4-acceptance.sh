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
# The evidence checks are fail-closed: an unreadable artifact, a failed
# measurement producer, a leaked canary in either its plain or its hex
# encoding, or an unexpected file in a shareable bundle stops the run. The
# classification check also records its own canary workload, so it never relies
# on a value that could appear by coincidence.
#
# The guest-visible OCI conformance check changes root, drops credentials, and
# creates device nodes, so it runs separately as PID 1 under
# `scripts/rfd3-phase4-runtime.sh`; this script records its result when it is
# already root and otherwise names the checked-in command.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/rfd3-phase4-checks.sh
source "$repo_root/scripts/rfd3-phase4-checks.sh"
output_root="${SIMFERRET_RFD3_PHASE4_OUTPUT:-$repo_root/.poc/rfd3-phase4-acceptance}"
kernel="${SIMFERRET_KERNEL:-}"
qemu="${QEMU_SYSTEM_X86_64:-qemu-system-x86_64}"
binary="$repo_root/target/x86_64-unknown-linux-musl/release/simferret"
python="${PYTHON:-python3}"
phase3_script="$repo_root/scripts/rfd3-phase3-acceptance.sh"
runtime_script="$repo_root/scripts/rfd3-phase4-runtime.sh"
scenario="$repo_root/scenarios/rfd3-workload-acceptance.toml"
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

# The run directory one `simferret run` or `simferret replay` invocation
# published, as the command reported it.
artifact_directory() {
  awk -F ': ' '$1 == "artifacts" { print substr($0, length($1) + 3) }' "$1"
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
# The ambient canary value, the host output path, and the recorded launch
# environment must stay out of the retained closure and derived lock. The
# launch environment is exactly the specification's, so no ambient variable is
# inherited.
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
record_run="$(artifact_directory "$phase3_run/record-binary.stdout")"
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

# Phase 3's fixture records the fixed launch value `acceptance`, which cannot
# distinguish a real leak from a coincidental match. A dedicated canary
# recording therefore carries a distinctive launch environment and per-run
# stream tokens, so the classification check has values that cannot appear in a
# shareable artifact by accident.
canary_dir="$output_dir/classification"
canary_value="simferret-phase4-canary-$(od -An -v -tx1 -N8 /dev/urandom | tr -d ' \n')"
mkdir -p "$canary_dir"
cp "$assembly/app" "$canary_dir/app"
cat >"$canary_dir/workload.toml" <<EOF
version = 1
kind = "binary"
path = "app"
args = []
env = ["MODE=$canary_value"]
working_directory = "/"
user = "65534:65534"
EOF
run_timed canary-record env SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
  "$binary" run --workload "$canary_dir/workload.toml" --scenario "$scenario" \
  --seed 42 --runs-dir "$canary_dir/runs"
expect_status canary-record 0
canary_run="$(artifact_directory "$output_dir/canary-record.stdout")"
if [[ -z "$canary_run" || ! -d "$canary_run" ]]; then
  echo "the canary recording published no run directory" >&2
  exit 1
fi
jq -e '.passed' "$canary_run/assertions.json" >/dev/null
# The recording must carry the launch environment the script generated, or the
# classification check would test a different value than the one it published.
canary_environment="$(jq -c '.workload.launch.environment' "$canary_run/workload.lock")"
if [[ "$canary_environment" != "[\"MODE=$canary_value\"]" ]]; then
  echo "the canary recording did not keep its launch environment: $canary_environment" >&2
  exit 1
fi
# Removing one retained raw object makes the next replay of the canary
# recording fail before QEMU starts, so it publishes a shareable failure bundle
# for a store that carries the canary launch environment.
canary_object="$(jq -r '.objects[0].digest' "$canary_dir/runs/.workload-store/raw/closure.json")"
canary_object_path="$canary_dir/runs/.workload-store/raw/sha256/${canary_object#sha256:}"
if [[ ! -f "$canary_object_path" ]]; then
  echo "the canary store retains no object $canary_object" >&2
  exit 1
fi
mv "$canary_object_path" "$canary_object_path.saved"
run_timed canary-replay env SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
  "$binary" replay "$canary_run"
expect_status canary-replay 1
# The rejected replay has to be the intended one, and it has to publish its own
# bundle: otherwise the check below could silently fall back to the Phase 3
# bundles and never exercise the canary.
if ! grep -F "raw object $canary_object is missing" "$output_dir/canary-replay.stderr" >/dev/null; then
  echo "the canary replay did not report the removed raw object" >&2
  cat "$output_dir/canary-replay.stderr" >&2
  exit 1
fi

# Every shareable bundle the Phase 3 demonstration and the canary recording
# published, including the ones a tampered copy of a run directory published.
if ! bundle_list="$(find "$phase3_run" "$canary_dir/runs" -type d -name failures \
  -exec find {} -mindepth 1 -maxdepth 1 -type d \; | sort)"; then
  echo "the published shareable bundles could not be listed" >&2
  exit 1
fi
mapfile -t bundles <<<"$bundle_list"
if [[ "${#bundles[@]}" -lt 1 ]]; then
  echo "the rejected cases published no shareable failure bundle" >&2
  exit 1
fi
canary_bundle_dir="$canary_dir/runs/failures"
require_canary_bundle "$canary_bundle_dir" "${bundles[@]}"
# Each recording is read on its own, so one recording without stdout cannot
# hide behind the other's canaries.
if ! record_stream_canaries="$(stream_canaries "$record_run/events.jsonl")"; then
  echo "the Phase 3 recording produced no stream canary" >&2
  exit 1
fi
if ! canary_stream_canaries="$(stream_canaries "$canary_run/events.jsonl")"; then
  echo "the canary recording produced no stream canary" >&2
  exit 1
fi
# The two recordings share their generic lines, so the merged canary set is
# deduplicated before it is counted and searched.
if ! stream_canary_list="$(
  printf '%s\n%s\n' "$record_stream_canaries" "$canary_stream_canaries" | sort -u
)"; then
  echo "the recorded workload streams produced no canary" >&2
  exit 1
fi
mapfile -t stream_canary_values <<<"$stream_canary_list"
if [[ "${#stream_canary_values[@]}" -eq 0 || -z "${stream_canary_values[0]}" ]]; then
  echo "the recorded workload streams produced no canary" >&2
  exit 1
fi
if ! environment_canary_list="$(environment_canaries "$record_run")" ||
  ! canary_environment_list="$(environment_canaries "$canary_run")"; then
  echo "the recorded runs named no launch environment" >&2
  exit 1
fi
mapfile -t environment_canary_values <<<"$environment_canary_list"
mapfile -t canary_environment_values <<<"$canary_environment_list"
for bundle in "${bundles[@]}"; do
  # A shareable bundle carries a typed error and counts, never the recorded
  # launch environment or the exact workload stream bytes. The canaries are
  # searched in plain text and in the hex encoding the event stream uses, so a
  # leaked `workload_output.bytes` value cannot hide.
  require_shareable_bundle "$bundle" \
    "${environment_canary_values[@]}" "${canary_environment_values[@]}" \
    "${stream_canary_values[@]}"
done

# ---------------------------------------------------------------------------
# Workload output and traffic volume, and the recorded identities
# ---------------------------------------------------------------------------
measurements="$output_dir/measurements.txt"
: >"$measurements"
for name in binary oci-static oci-dynamic; do
  run_dir="$(artifact_directory "$phase3_run/record-$name.stdout")"
  if [[ -z "$run_dir" || ! -d "$run_dir" ]]; then
    echo "the Phase 3 $name recording published no run directory" >&2
    exit 1
  fi
  jq -e '.passed' "$run_dir/assertions.json" >/dev/null
  # The measurement producer is checked before its output is read: a producer
  # that fails or prints nothing must never be recorded as an empty result.
  if ! measurement="$(workload_measurement "$run_dir/events.jsonl")"; then
    echo "the $name workload measurement failed" >&2
    exit 1
  fi
  read -r stdout_bytes stderr_bytes attempted succeeded unavailable <<<"$measurement"
  require_nonnegative_integers "$name workload measurement" \
    "$stdout_bytes" "$stderr_bytes" "$attempted" "$succeeded" "$unavailable"
  if [[ "$attempted" -ne $((succeeded + unavailable)) ]]; then
    echo "the $name traffic measurement is inconsistent: $attempted attempted, $succeeded succeeded, $unavailable unavailable" >&2
    exit 1
  fi
  if [[ "$attempted" -eq 0 || "$succeeded" -eq 0 ]]; then
    echo "the $name recording measured no workload traffic" >&2
    exit 1
  fi
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
  printf 'shareable_canaries=%s\n' \
    "$((${#environment_canary_values[@]} + ${#canary_environment_values[@]} + ${#stream_canary_values[@]}))"
  printf 'shareable_excludes_environment_and_streams=yes\n'
  printf 'classification_canary_recorded=yes\n'
  printf 'private_artifacts=run directory, guest image cache, workload store, and run artifacts are owner-only\n'
  printf 'guest_visible_conformance=%s\n' "$conformance"
  cat "$measurements"
} >"$output_dir/evidence.txt"

cat "$output_dir/evidence.txt"
printf '\nRFD 3 phase 4 acceptance passed; artifacts: %s\n' "$output_dir"
