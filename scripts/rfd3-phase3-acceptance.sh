#!/usr/bin/env bash
# RFD 3 Phase 3 acceptance: workload-driven scenario and passive replay.
#
# Builds one external static fixture and one dynamically linked fixture, packages
# the static fixture as both a standalone binary workload and a local OCI image
# layout, records each source form through the shared guest runtime, passively
# replays each twice after removing every live source, and checks that a changed
# workload, launch, cache, or scenario identity is rejected before QEMU starts.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_root="${SIMFERRET_RFD3_PHASE3_OUTPUT:-$repo_root/.poc/rfd3-phase3-acceptance}"
kernel="${SIMFERRET_KERNEL:-}"
qemu="${QEMU_SYSTEM_X86_64:-qemu-system-x86_64}"
binary="$repo_root/target/x86_64-unknown-linux-musl/release/simferret"
# The pinned development environment exports CC as the static musl compiler.
# The dynamically linked fixture and its in-image loader closure need the glibc
# compiler, exactly as the Phase 0 spike established.
static_cc="${SIMFERRET_STATIC_CC:-${CC:-cc}}"
dynamic_cc="${SIMFERRET_DYNAMIC_CC:-cc}"
python="${PYTHON:-python3}"
readelf="${READELF:-readelf}"
layout_builder="$repo_root/poc/rfd3-phase0/build-layout.py"
fixture_source="$repo_root/poc/rfd3-workload/main.c"
scenario="$repo_root/scenarios/rfd3-workload-acceptance.toml"
corrupt_scenario="$repo_root/scenarios/rfd3-workload-acceptance-corrupt.toml"
store_name=".workload-store"
interpreter_path="/lib64/ld-linux-x86-64.so.2"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "RFD 3 phase 3 acceptance supports x86-64 Linux only." >&2
  exit 1
fi
if [[ -z "$kernel" || ! -f "$kernel" ]]; then
  echo "SIMFERRET_KERNEL must name the pinned x86-64 Linux bzImage." >&2
  echo "Run this script through .agents/dev." >&2
  exit 1
fi
for command in cargo "$qemu" "$static_cc" "$dynamic_cc" "$python" "$readelf" \
  jq mktemp sha256sum stat cmp readlink; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done

umask 022
mkdir -p "$output_root"
output_dir="$(mktemp -d "$output_root/run.XXXXXXXX")"
sources="$output_dir/sources"
mkdir -p "$sources"

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

expect_error() {
  local name="$1"
  local needle="$2"
  if [[ "$RUN_STATUS" -eq 0 ]] || ! grep -F "$needle" "$output_dir/$name.stderr" >/dev/null; then
    echo "$name did not fail with the expected diagnostic: $needle" >&2
    cat "$output_dir/$name.stderr" >&2
    exit 1
  fi
}

json_stdin_field() {
  "$python" -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

require_file() {
  local name="$1" path="$2"
  if [[ -z "$path" || ! -f "$path" ]]; then
    echo "$name must name a pinned regular file; run this script through .agents/dev." >&2
    exit 1
  fi
}

require_digest() {
  if [[ ! "$2" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "$1 is not a sha256 digest: '$2'" >&2
    exit 1
  fi
}

cargo build --manifest-path "$repo_root/Cargo.toml" \
  --locked --release --target x86_64-unknown-linux-musl \
  --target-dir "$repo_root/target"

"$static_cc" -static -Os -Wall -Wextra -Werror \
  "$fixture_source" -o "$sources/app"
"$dynamic_cc" -Os -Wall -Wextra -Werror \
  -Wl,--dynamic-linker="$interpreter_path" -Wl,-rpath,/lib \
  "$fixture_source" -o "$sources/app-dynamic"
loader="$(readlink -f "$("$dynamic_cc" -print-file-name=ld-linux-x86-64.so.2)")"
library="$(readlink -f "$("$dynamic_cc" -print-file-name=libc.so.6)")"
require_file "loader closure" "$loader"
require_file "libc closure" "$library"
declared_interpreter="$("$readelf" -l "$sources/app-dynamic" |
  grep -o 'interpreter: [^]]*' | sed 's/interpreter: //')"
if [[ "$declared_interpreter" != "$interpreter_path" ]]; then
  echo "The dynamic fixture declares unexpected interpreter $declared_interpreter." >&2
  exit 1
fi

static_manifest="$("$python" "$layout_builder" static \
  --binary "$sources/app" --entrypoint /bin/simferret-workload \
  --out "$sources/layout-static" | json_stdin_field manifest_digest)"
dynamic_manifest="$("$python" "$layout_builder" dynamic \
  --binary "$sources/app-dynamic" --loader "$loader" --library "$library" \
  --out "$sources/layout-dynamic" | json_stdin_field manifest_digest)"
require_digest "static OCI manifest digest" "$static_manifest"
require_digest "dynamic OCI manifest digest" "$dynamic_manifest"

# One source form lives in its own directory, so the recorded specification is
# resolved relative to it and the whole directory can be removed before replay.
prepare_binary() {
  local directory="$1"
  mkdir -p "$directory"
  cp "$sources/app" "$directory/app"
  cat >"$directory/workload.toml" <<'EOF'
version = 1
kind = "binary"
path = "app"
args = []
env = ["MODE=acceptance"]
working_directory = "/"
user = "65534:65534"
EOF
}

prepare_oci() {
  local directory="$1" layout="$2" digest="$3"
  mkdir -p "$directory"
  cp -a "$layout" "$directory/layout"
  cat >"$directory/workload.toml" <<EOF
version = 1
kind = "oci"
layout = "layout"
manifest_digest = "$digest"
EOF
}

# Record, replay twice without any live source, and prove that every identity
# class is rejected before QEMU starts.
exercise() {
  local name="$1"
  local form="$output_dir/form-$name"
  local spec="$form/workload.toml"
  local runs="$output_dir/runs-$name"
  local store="$runs/$store_name"
  mkdir -p "$runs"

  run_timed "record-$name" env \
    SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
    "$binary" run --workload "$spec" --scenario "$scenario" \
    --seed 42 --runs-dir "$runs"
  expect_status "record-$name" 0
  local run_dir
  run_dir="$(artifact_directory "$output_dir/record-$name.stdout")"
  test -d "$run_dir"

  jq -e '
    .passed and
    ([.assertions[].name] == ["process_safety", "response_integrity",
      "controlled_outage", "restoration", "bounded_recovery"])
  ' "$run_dir/assertions.json" >/dev/null
  jq -e --arg store "$store_name" '
    .version == 1 and .store == $store and .workload.source_kind != null
  ' "$run_dir/workload.lock" >/dev/null
  jq -e '.workload != null and .artifacts["workload.lock"] != null' \
    "$run_dir/manifest.json" >/dev/null
  jq -s -e '
    ([.[] | select(.event.type == "workload_started" and .event.invocation == 1)] | length) == 1 and
    ([.[] | select(.event.type == "workload_started" and .event.invocation == 2)] | length) == 1 and
    any(.[]; .event.type == "termination_requested" and .event.signal == 9) and
    any(.[]; .event.type == "workload_exited" and .event.invocation == 1 and
      .event.exit.kind == "signaled" and .event.exit.signal == 9) and
    any(.[]; .event.type == "workload_exited" and .event.invocation == 2 and
      .event.exit.kind == "exited" and .event.exit.code == 0 and .event.stdout_bytes > 0) and
    any(.[]; .event.type == "cleanup_complete" and .event.reaped >= 2) and
    any(.[]; .event.type == "outage_activated") and
    any(.[]; .event.type == "network_restored")
  ' "$run_dir/events.jsonl" >/dev/null

  # Each invocation must witness a fresh root twice over: the /tmp marker proves
  # the writable overlay was recreated, and the executable mode proves the
  # immutable workload root was re-materialized as well. The frames are
  # concatenated per invocation before they are split into lines, exactly as the
  # host checker reconstructs the streams, so a line split across frames counts.
  local fresh_witnesses
  fresh_witnesses="$("$python" - "$run_dir/events.jsonl" <<'PY'
import json, sys
streams = {}
with open(sys.argv[1], encoding="utf-8") as handle:
    for line in handle:
        event = json.loads(line)["event"]
        if event["type"] == "workload_output" and event["stream"] == "stdout":
            streams.setdefault(event["invocation"], bytearray()).extend(
                bytes.fromhex(event["bytes"])
            )
fresh = 0
for data in streams.values():
    for line in bytes(data).split(b"\n"):
        if line == b"state value=fresh root=fresh":
            fresh += 1
print(f"{len(streams)}:{fresh}")
PY
)"
  if [[ "$fresh_witnesses" != "2:2" ]]; then
    echo "expected two invocations with two fresh-root witnesses, observed $fresh_witnesses" >&2
    exit 1
  fi

  # The run directory, the guest image cache, and the workload store carry the
  # packaged workload, its launch identity, and the exact streams, so every one
  # of them is owner-only.
  local mode path
  for path in "$run_dir" "$runs/.images" "$store"; do
    mode="$(stat -c %a "$path")"
    if [[ "$mode" != "700" ]]; then
      echo "$path is not owner-only: $mode" >&2
      exit 1
    fi
  done
  for path in "$run_dir/events.jsonl" "$run_dir/assertions.json" \
    "$run_dir/workload.lock" "$run_dir/manifest.json" "$runs/.images/"*.cpio.gz; do
    mode="$(stat -c %a "$path")"
    if [[ "$mode" != "600" ]]; then
      echo "$path is not owner-only: $mode" >&2
      exit 1
    fi
  done

  # The intentional corruption must fail safety with a nonzero result.
  local corrupt_runs="$output_dir/runs-corrupt-$name"
  mkdir -p "$corrupt_runs"
  run_timed "corrupt-$name" env \
    SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
    "$binary" run --workload "$spec" --scenario "$corrupt_scenario" \
    --seed 42 --runs-dir "$corrupt_runs"
  expect_status "corrupt-$name" 1
  local corrupt_run
  corrupt_run="$(artifact_directory "$output_dir/corrupt-$name.stdout")"
  jq -e '
    (.passed | not) and
    any(.assertions[]; .name == "process_safety" and (.passed | not)) and
    any(.assertions[]; .name == "response_integrity" and (.passed | not))
  ' "$corrupt_run/assertions.json" >/dev/null

  # Replay consults no live source: the whole form directory is removed first.
  rm -rf "$form"
  run_timed "replay-1-$name" env \
    SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
    "$binary" replay "$run_dir"
  expect_status "replay-1-$name" 0
  run_timed "replay-2-$name" env \
    SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
    "$binary" replay "$run_dir"
  expect_status "replay-2-$name" 0
  cmp "$output_dir/replay-1-$name.stdout" "$output_dir/replay-2-$name.stdout"

  # A self-consistently changed workload lock still disagrees with the manifest.
  local tampered="$output_dir/tampered-$name"
  mkdir -p "$tampered"
  cp -a "$run_dir" "$tampered/"
  local tampered_run="$tampered/$(basename "$run_dir")"
  jq '.workload.canonical_digest = ("0" * 64)' \
    "$tampered_run/workload.lock" >"$tampered_run/workload.lock.tmp"
  mv "$tampered_run/workload.lock.tmp" "$tampered_run/workload.lock"
  local tampered_lock_digest
  tampered_lock_digest="$(sha256sum "$tampered_run/workload.lock" | cut -d' ' -f1)"
  jq --arg digest "$tampered_lock_digest" \
    '.artifacts["workload.lock"] = $digest' \
    "$tampered_run/manifest.json" >"$tampered_run/manifest.json.tmp"
  mv "$tampered_run/manifest.json.tmp" "$tampered_run/manifest.json"
  run_timed "tampered-lock-$name" env \
    SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
    "$binary" replay "$tampered_run"
  expect_error "tampered-lock-$name" "the workload lock identity differs from the manifest"

  # A changed derived cache entry fails independent verification.
  local canonical
  canonical="$(jq -r '.workload.canonical_digest' "$run_dir/workload.lock")"
  local template="$store/derived/$canonical/template.cpio"
  test -f "$template"
  cp "$template" "$template.saved"
  printf 'tampered template\n' >"$template"
  run_timed "tampered-template-$name" env \
    SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
    "$binary" replay "$run_dir"
  expect_error "tampered-template-$name" \
    "derived guest template does not match the raw closure"
  mv "$template.saved" "$template"

  # Missing raw evidence fails even though the derived entry still exists, and
  # the diagnostic names the missing raw closure. The store is verified before
  # QEMU starts, so this exact message is the intended rejection.
  mv "$store/raw/closure.json" "$store/raw/closure.json.saved"
  run_timed "missing-raw-$name" env \
    SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
    "$binary" replay "$run_dir"
  expect_error "missing-raw-$name" "raw closure raw/closure.json is missing"
  mv "$store/raw/closure.json.saved" "$store/raw/closure.json"

  # A raw object the closure still references must be present too, even though
  # the closure itself is intact.
  local object_digest object_path
  object_digest="$(jq -r '.objects[0].digest' "$store/raw/closure.json")"
  object_path="$store/raw/sha256/${object_digest#sha256:}"
  test -f "$object_path"
  mv "$object_path" "$object_path.saved"
  run_timed "missing-object-$name" env \
    SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
    "$binary" replay "$run_dir"
  expect_error "missing-object-$name" "raw object $object_digest is missing"
  mv "$object_path.saved" "$object_path"

  # The untouched recording still replays after every tamper is restored.
  run_timed "restored-$name" env \
    SIMFERRET_KERNEL="$kernel" QEMU_SYSTEM_X86_64="$qemu" \
    "$binary" replay "$run_dir"
  expect_status "restored-$name" 0
}

prepare_binary "$output_dir/form-binary"
prepare_oci "$output_dir/form-oci-static" "$sources/layout-static" "$static_manifest"
prepare_oci "$output_dir/form-oci-dynamic" "$sources/layout-dynamic" "$dynamic_manifest"

exercise binary
exercise oci-static
exercise oci-dynamic

binary_canonical="$(jq -r '.workload.canonical_digest' \
  "$(artifact_directory "$output_dir/record-binary.stdout")/workload.lock")"
oci_static_canonical="$(jq -r '.workload.canonical_digest' \
  "$(artifact_directory "$output_dir/record-oci-static.stdout")/workload.lock")"
oci_dynamic_canonical="$(jq -r '.workload.canonical_digest' \
  "$(artifact_directory "$output_dir/record-oci-dynamic.stdout")/workload.lock")"
if [[ "$binary_canonical" != "$oci_static_canonical" ]]; then
  echo "binary and static OCI sources did not converge: $binary_canonical vs $oci_static_canonical" >&2
  exit 1
fi
if [[ "$binary_canonical" == "$oci_dynamic_canonical" ]]; then
  echo "the dynamically linked OCI fixture produced the static canonical tree" >&2
  exit 1
fi

{
  printf 'qemu_version=%s\n' "$("$qemu" --version | head -n 1)"
  printf 'kernel=%s\n' "$kernel"
  printf 'static_fixture_sha256=%s\n' "$(sha256sum "$sources/app" | cut -d' ' -f1)"
  printf 'dynamic_fixture_sha256=%s\n' "$(sha256sum "$sources/app-dynamic" | cut -d' ' -f1)"
  printf 'dynamic_interpreter=%s\n' "$declared_interpreter"
  printf 'static_manifest_digest=%s\n' "$static_manifest"
  printf 'dynamic_manifest_digest=%s\n' "$dynamic_manifest"
  for name in binary oci-static oci-dynamic; do
    recorded_run="$(artifact_directory "$output_dir/record-$name.stdout")"
    printf '%s_canonical=%s\n' "$name" "$(jq -r '.workload.canonical_digest' "$recorded_run/workload.lock")"
    printf '%s_closure=%s\n' "$name" "$(jq -r '.workload.closure_sha256' "$recorded_run/workload.lock")"
    printf '%s_record_duration_ns=%s\n' "$name" "$(cat "$output_dir/record-$name.duration-ns")"
    printf '%s_replay_1_duration_ns=%s\n' "$name" "$(cat "$output_dir/replay-1-$name.duration-ns")"
    printf '%s_replay_2_duration_ns=%s\n' "$name" "$(cat "$output_dir/replay-2-$name.duration-ns")"
    printf '%s_store_bytes=%s\n' "$name" "$(du -sb "$output_dir/runs-$name/$store_name" | cut -f1)"
    printf '%s_initramfs_bytes=%s\n' "$name" "$(stat -c %s "$output_dir/runs-$name/.images/"*.cpio.gz | awk '{ total += $1 } END { print total }')"
    printf '%s_semantic_outcome=%s\n' "$name" "$(jq -r '.semantic_outcome_sha256' "$recorded_run/manifest.json")"
    printf '%s_events=%s\n' "$name" "$(wc -l <"$recorded_run/events.jsonl")"
    printf '%s_replay_log_bytes=%s\n' "$name" "$(stat -c %s "$recorded_run/replay.bin")"
  done
  printf 'intentional_divergence=process_safety and response_integrity failed with CLI status 1\n'
  printf 'workload_lock_tamper_error=%s\n' \
    "$(tr '\n' ' ' <"$output_dir/tampered-lock-binary.stderr")"
  printf 'derived_template_tamper_error=%s\n' \
    "$(tr '\n' ' ' <"$output_dir/tampered-template-binary.stderr")"
  printf 'missing_raw_closure_error=%s\n' \
    "$(tr '\n' ' ' <"$output_dir/missing-raw-binary.stderr")"
  printf 'missing_raw_object_error=%s\n' \
    "$(tr '\n' ' ' <"$output_dir/missing-object-binary.stderr")"
  printf 'private_artifacts=run directory, guest image cache, and workload store are owner-only\n'
  printf 'fresh_root_witnesses=state value=fresh root=fresh observed once per invocation\n'
} >"$output_dir/evidence.txt"

cat "$output_dir/evidence.txt"
printf '\nRFD 3 phase 3 acceptance passed; artifacts: %s\n' "$output_dir"
