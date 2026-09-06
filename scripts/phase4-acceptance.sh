#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_root="${SIMFERRET_ACCEPTANCE_OUTPUT:-$repo_root/.poc/phase4-acceptance}"
kernel="${SIMFERRET_KERNEL:-}"
qemu="${QEMU_SYSTEM_X86_64:-qemu-system-x86_64}"
binary="$repo_root/target/x86_64-unknown-linux-musl/release/simferret"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "Phase 4 acceptance supports x86-64 Linux only." >&2
  exit 1
fi
if [[ -z "$kernel" || ! -f "$kernel" ]]; then
  echo "SIMFERRET_KERNEL must name the pinned x86-64 Linux bzImage." >&2
  echo "Run this script through .agents/dev." >&2
  exit 1
fi
for command in cargo "$qemu" date jq mktemp sha256sum stat; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done

umask 022
mkdir -p "$output_root"
output_dir="$(mktemp -d "$output_root/run.XXXXXXXX")"
runs_dir="$output_dir/runs"
mkdir -p "$runs_dir"

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

artifact_directory() {
  awk -F ': ' '$1 == "artifacts" { print substr($0, length($1) + 3) }' "$1"
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

cargo build --manifest-path "$repo_root/Cargo.toml" \
  --locked --release --target x86_64-unknown-linux-musl

run_timed record-seed-42 env \
  SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
  "$binary" run \
  --scenario "$repo_root/scenarios/echo-process-restart.toml" \
  --seed 42 --runs-dir "$runs_dir"
expect_status record-seed-42 0
record_duration="$RUN_DURATION_NS"
recorded_run="$(artifact_directory "$output_dir/record-seed-42.stdout")"
test -d "$recorded_run"

jq -s -e '
  ([.[] | select(.event.type == "request_attempted" and .event.phase == "stopped")][0]) as $attempt |
  $attempt != null and
  any(.[];
    .event.type == "request_unavailable" and
    .event.phase == "stopped" and
    .event.request_id == $attempt.event.request_id and
    .event_id > $attempt.event_id and
    .event_id - $attempt.event_id <= 1)
' "$recorded_run/events.jsonl" >/dev/null
jq -e '
  .passed and
  any(.assertions[]; .name == "controlled_outage" and .passed)
' "$recorded_run/assertions.json" >/dev/null

run_timed replay-1 env \
  SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
  "$binary" replay "$recorded_run"
expect_status replay-1 0
replay_1_duration="$RUN_DURATION_NS"
run_timed replay-2 env \
  SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
  "$binary" replay "$recorded_run"
expect_status replay-2 0
replay_2_duration="$RUN_DURATION_NS"
cmp "$output_dir/replay-1.stdout" "$output_dir/replay-2.stdout"

tampered_artifact_parent="$output_dir/tampered-artifact"
mkdir "$tampered_artifact_parent"
cp -a "$recorded_run" "$tampered_artifact_parent/"
tampered_artifact_run="$tampered_artifact_parent/$(basename "$recorded_run")"
printf 'tampered\n' >>"$tampered_artifact_run/events.jsonl"
run_timed tampered-artifact env \
  SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
  "$binary" replay "$tampered_artifact_run"
if [[ "$RUN_STATUS" -eq 0 ]] ||
  ! grep -F "artifact digest mismatch for events.jsonl" \
    "$output_dir/tampered-artifact.stderr" >/dev/null; then
  echo "tampered artifact was not rejected as expected" >&2
  exit 1
fi

tampered_identity_parent="$output_dir/tampered-identity"
mkdir "$tampered_identity_parent"
cp -a "$recorded_run" "$tampered_identity_parent/"
tampered_identity_run="$tampered_identity_parent/$(basename "$recorded_run")"
jq '.vm.memory_mib += 1' "$tampered_identity_run/manifest.json" \
  >"$tampered_identity_run/manifest.json.tmp"
mv "$tampered_identity_run/manifest.json.tmp" "$tampered_identity_run/manifest.json"
run_timed tampered-identity env \
  SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
  "$binary" replay "$tampered_identity_run"
if [[ "$RUN_STATUS" -eq 0 ]] ||
  ! grep -F "replay environment identity differs" \
    "$output_dir/tampered-identity.stderr" >/dev/null; then
  echo "tampered replay identity was not rejected as expected" >&2
  exit 1
fi

run_timed record-corrupt-seed-43 env \
  SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
  "$binary" run \
  --scenario "$repo_root/scenarios/echo-process-restart-corrupt.toml" \
  --seed 43 --runs-dir "$runs_dir"
expect_status record-corrupt-seed-43 1
corrupt_duration="$RUN_DURATION_NS"
corrupt_run="$(artifact_directory "$output_dir/record-corrupt-seed-43.stdout")"
test -d "$corrupt_run"
if ! jq -s -e '
  .[0].fault_request_index != .[1].fault_request_index or
  .[0].requests != .[1].requests
' "$recorded_run/choices.json" "$corrupt_run/choices.json" >/dev/null; then
  echo "different seeds did not change requests or the fault choice" >&2
  exit 1
fi
jq -e '
  (.passed | not) and
  any(.assertions[]; .name == "safety" and (.passed | not))
' "$corrupt_run/assertions.json" >/dev/null

{
  printf 'qemu_version=%s\n' "$("$qemu" --version | head -n 1)"
  printf 'kernel=%s\n' "$kernel"
  printf 'record_seed_42_duration_ns=%s\n' "$record_duration"
  printf 'replay_1_duration_ns=%s\n' "$replay_1_duration"
  printf 'replay_2_duration_ns=%s\n' "$replay_2_duration"
  printf 'record_corrupt_seed_43_duration_ns=%s\n' "$corrupt_duration"
  printf 'recorded_run=%s\n' "$recorded_run"
  printf 'corrupt_run=%s\n' "$corrupt_run"
  stat -c '%n=%s' \
    "$recorded_run/replay.bin" \
    "$recorded_run/events.jsonl" \
    "$recorded_run/assertions.json" \
    "$recorded_run/choices.json" \
    "$recorded_run/scenario.toml" \
    "$recorded_run/manifest.json"
  sha256sum \
    "$recorded_run/replay.bin" \
    "$recorded_run/events.jsonl" \
    "$recorded_run/assertions.json"
  printf 'semantic_outcome_sha256=%s\n' \
    "$(jq -r .semantic_outcome_sha256 "$recorded_run/manifest.json")"
  printf 'artifact_tamper_error=%s\n' \
    "$(tr '\n' ' ' <"$output_dir/tampered-artifact.stderr")"
  printf 'identity_tamper_error=%s\n' \
    "$(tr '\n' ' ' <"$output_dir/tampered-identity.stderr")"
  printf 'intentional_divergence=safety assertion failed with CLI status 1\n'
} >"$output_dir/evidence.txt"

cat "$output_dir/evidence.txt"
printf '\nPhase 4 acceptance passed; artifacts: %s\n' "$output_dir"
