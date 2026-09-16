#!/usr/bin/env bash
set -euo pipefail

# RFD 3 Phase 0 workload and OCI spike.
#
# Builds one external static executable and two local OCI image layouts, applies
# representative base and upper layers twice into stable canonical trees,
# normalizes both source forms into one content-addressed store, removes every
# live workload source before QEMU starts, and records and passively replays
# each workload through the same guest supervisor.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
prototype="$repo_root/poc/rfd3-phase0/oci_prototype.py"
layout_builder="$repo_root/poc/rfd3-phase0/build-layout.py"
supervisor_source="$repo_root/poc/rfd3-phase0/supervisor.c"
fixture_source="$repo_root/poc/rfd3-workload/main.c"
output_root="${SIMFERRET_RFD3_PHASE0_OUTPUT:-$repo_root/.poc/rfd3-phase0-spike}"
kernel="${SIMFERRET_KERNEL:-}"
qemu="${QEMU_SYSTEM_X86_64:-qemu-system-x86_64}"
# The pinned development environment exports CC as the static musl compiler,
# which is what the repository-built guest executables use. The dynamically
# linked fixture and its in-image loader closure need the glibc compiler.
static_cc="${SIMFERRET_STATIC_CC:-${CC:-cc}}"
dynamic_cc="${SIMFERRET_DYNAMIC_CC:-cc}"
python="${PYTHON:-python3}"
readelf="${READELF:-readelf}"
qemu_timeout="${SIMFERRET_QEMU_TIMEOUT:-120s}"
qemu_kill_after="${SIMFERRET_QEMU_KILL_AFTER:-5s}"
output_dir=""
complete=false

report_incomplete() {
  if [[ "$complete" != true && -n "$output_dir" ]]; then
    echo "RFD 3 Phase 0 spike failed; diagnostics: $output_dir" >&2
  fi
}

trap report_incomplete EXIT

validate_positive_duration() {
  local name="$1"
  local value="$2"
  local pattern='^(([0-9]*[1-9][0-9]*)(\.[0-9]+)?|0*\.[0-9]*[1-9][0-9]*)[smhd]?$'

  if [[ ! "$value" =~ $pattern ]]; then
    echo "$name must be a finite, positive duration (for example, 5s or 0.1s)." >&2
    exit 1
  fi
}

require_file() {
  local name="$1"
  local path="$2"

  if [[ -z "$path" || ! -f "$path" ]]; then
    echo "$name must name a pinned regular file; run this script through .agents/dev." >&2
    exit 1
  fi
}

json_field() {
  "$python" -c 'import json, sys; print(json.loads(sys.argv[1])[sys.argv[2]])' "$1" "$2"
}

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "The RFD 3 Phase 0 spike supports x86-64 Linux only." >&2
  exit 1
fi
validate_positive_duration SIMFERRET_QEMU_TIMEOUT "$qemu_timeout"
validate_positive_duration SIMFERRET_QEMU_KILL_AFTER "$qemu_kill_after"
require_file SIMFERRET_KERNEL "$kernel"
require_file "RFD 3 workload fixture" "$fixture_source"
require_file "RFD 3 supervisor" "$supervisor_source"

for command in "$qemu" "$static_cc" "$dynamic_cc" "$python" "$readelf" cpio gzip mktemp sha256sum timeout; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done

umask 022
mkdir -p "$output_root"
output_dir="$(mktemp -d "$output_root/run.XXXXXXXX")"
sources="$output_dir/sources"
images="$output_dir/images"
mkdir -p "$sources/static" "$sources/dynamic" "$sources/adversarial" "$images"

# ---------------------------------------------------------------------------
# Representative sources: one external static executable, one dynamically
# linked executable, and the local image layouts that carry them.
# ---------------------------------------------------------------------------

"$static_cc" -static -Os -Wall -Wextra -Werror \
  "$fixture_source" -o "$sources/static/simferret-workload-fixture"
"$dynamic_cc" -Os -Wall -Wextra -Werror \
  -Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2 -Wl,-rpath,/lib \
  "$fixture_source" -o "$sources/dynamic/simferret-workload-fixture"
static_binary_bytes="$(wc -c <"$sources/static/simferret-workload-fixture")"
dynamic_binary_bytes="$(wc -c <"$sources/dynamic/simferret-workload-fixture")"

loader="$(readlink -f "$("$dynamic_cc" -print-file-name=ld-linux-x86-64.so.2)")"
library="$(readlink -f "$("$dynamic_cc" -print-file-name=libc.so.6)")"
require_file "loader closure" "$loader"
require_file "libc closure" "$library"

static_interpreter="$("$readelf" -l "$sources/static/simferret-workload-fixture" |
  grep -o 'interpreter: [^]]*' | sed 's/interpreter: //' || true)"
if [[ -n "$static_interpreter" ]]; then
  echo "The static fixture unexpectedly declares interpreter $static_interpreter." >&2
  exit 1
fi
dynamic_interpreter="$("$readelf" -l "$sources/dynamic/simferret-workload-fixture" |
  grep -o 'interpreter: [^]]*' | sed 's/interpreter: //')"
if [[ "$dynamic_interpreter" != "/lib64/ld-linux-x86-64.so.2" ]]; then
  echo "The dynamic fixture declares unexpected interpreter $dynamic_interpreter." >&2
  exit 1
fi

static_capture="$("$python" "$layout_builder" static \
  --binary "$sources/static/simferret-workload-fixture" --out "$sources/layout-static")"
dynamic_capture="$("$python" "$layout_builder" dynamic \
  --binary "$sources/dynamic/simferret-workload-fixture" \
  --loader "$loader" --library "$library" --out "$sources/layout-dynamic")"
semantics_capture="$("$python" "$layout_builder" semantics \
  --binary "$sources/static/simferret-workload-fixture" --out "$sources/layout-semantics")"
opacity_capture="$("$python" "$layout_builder" root-opacity \
  --binary "$sources/static/simferret-workload-fixture" --out "$sources/layout-opacity")"

static_manifest="$(json_field "$static_capture" manifest_digest)"
dynamic_manifest="$(json_field "$dynamic_capture" manifest_digest)"
semantics_manifest="$(json_field "$semantics_capture" manifest_digest)"
opacity_manifest="$(json_field "$opacity_capture" manifest_digest)"

# ---------------------------------------------------------------------------
# Layer semantics: apply the same base and upper layers twice, in separate
# processes with different hash seeds, and compare the normalized result.
# ---------------------------------------------------------------------------

semantics_started="$(date +%s%N)"
first_apply="$(PYTHONHASHSEED=0 "$python" "$prototype" apply \
  --layout "$sources/layout-semantics" --manifest-digest "$semantics_manifest" \
  --out "$output_dir/semantics-1")"
second_apply="$(PYTHONHASHSEED=1 "$python" "$prototype" apply \
  --layout "$sources/layout-semantics" --manifest-digest "$semantics_manifest" \
  --out "$output_dir/semantics-2")"
semantics_finished="$(date +%s%N)"
semantics_duration_ns="$((semantics_finished - semantics_started))"

"$python" "$prototype" compare-trees \
  --left "$output_dir/semantics-1" --right "$output_dir/semantics-2" >/dev/null

semantics_digest="$(json_field "$first_apply" canonical_digest)"
if [[ "$semantics_digest" != "$(json_field "$second_apply" canonical_digest)" ]]; then
  echo "Applying the same layers twice produced different canonical digests." >&2
  exit 1
fi

"$python" "$prototype" apply --layout "$sources/layout-opacity" \
  --manifest-digest "$opacity_manifest" --out "$output_dir/opacity-1" >/dev/null
"$python" "$prototype" apply --layout "$sources/layout-opacity" \
  --manifest-digest "$opacity_manifest" --out "$output_dir/opacity-2" >/dev/null
"$python" "$prototype" compare-trees \
  --left "$output_dir/opacity-1" --right "$output_dir/opacity-2" >/dev/null
opacity_tree="$(cd "$output_dir/opacity-1" && find . -mindepth 1 | LC_ALL=C sort | tr '\n' ' ')"
if [[ "$opacity_tree" != "./bin ./bin/simferret-workload-fixture ./keep ./keep/upper " ]]; then
  echo "Root-level opacity produced an unexpected tree: $opacity_tree" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Unsupported OCI constructs: every defect must be refused before any output.
# ---------------------------------------------------------------------------

rejections="$output_dir/rejections.txt"
: >"$rejections"
mapfile -t defects < <("$python" "$layout_builder" defects)
for defect in "${defects[@]}"; do
  adversarial_out="$sources/adversarial/$defect"
  adversarial_capture="$("$python" "$layout_builder" adversarial --defect "$defect" \
    --binary "$sources/static/simferret-workload-fixture" --out "$adversarial_out")"
  adversarial_manifest="$(json_field "$adversarial_capture" manifest_digest)"
  materialized="$output_dir/adversarial/$defect"
  if "$python" "$prototype" apply --layout "$adversarial_out" \
    --manifest-digest "$adversarial_manifest" --out "$materialized" \
    >/dev/null 2>"$output_dir/adversarial-$defect.err"; then
    echo "Adversarial layout $defect was unexpectedly accepted." >&2
    exit 1
  fi
  if [[ -e "$materialized" ]]; then
    echo "Adversarial layout $defect left partial output." >&2
    exit 1
  fi
  printf '%s\t%s\n' "$defect" "$(cat "$output_dir/adversarial-$defect.err")" >>"$rejections"
done

# ---------------------------------------------------------------------------
# Content-addressed assembly and guest images
# ---------------------------------------------------------------------------

workload_commands=$'echo asymmetric_42\nstate\nspawn-descendant\nexit\n'

build_image() {
  local name="$1"
  local store="$2"
  local root="$images/$name-root"
  local initramfs="$images/$name.cpio.gz"

  rm -rf "$root"
  mkdir -p "$root/etc"
  "$python" "$prototype" materialize --store "$store" --out "$root/workload" \
    >"$images/$name.materialize.json"
  "$static_cc" -static -Os -Wall -Wextra -Werror "$supervisor_source" -o "$root/init"
  printf '%s\n' "$name" >"$root/etc/simferret-source-kind"
  printf '%s' "$workload_commands" >"$root/etc/simferret-commands"
  chmod 0755 "$root/init"
  find "$root" -exec touch -h -d @0 {} +
  (
    cd "$root"
    find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc \
      --owner=0:0 --reproducible --quiet
  ) | gzip -n >"$initramfs"
}

run_qemu() {
  local initramfs="$1"
  local mode="$2"
  local serial_log="$3"
  local diagnostic_log="$4"
  local replay_log="$5"
  local started finished

  started="$(date +%s%N)"
  timeout --kill-after="$qemu_kill_after" "$qemu_timeout" \
    "$qemu" \
    -machine "pc-i440fx-9.2,accel=tcg" \
    -cpu qemu64 \
    -smp 1 \
    -m 256M \
    -nodefaults \
    -no-user-config \
    -display none \
    -monitor none \
    -serial stdio \
    -no-reboot \
    -net none \
    -rtc "base=2000-01-01T00:00:00,clock=vm" \
    -kernel "$kernel" \
    -initrd "$initramfs" \
    -append "console=ttyS0 quiet loglevel=0 panic=-1 nokaslr random.trust_cpu=off init=/init" \
    -icount "shift=auto,rr=$mode,rrfile=$replay_log" \
    >"$serial_log" 2>"$diagnostic_log"
  finished="$(date +%s%N)"
  printf '%s\n' "$((finished - started))" >"$serial_log.duration-ns"
}

verify_serial() {
  local name="$1"
  local serial_log="$2"

  for line in \
    'ready version=1' \
    'echo value=asymmetric_42' \
    'state value=fresh' \
    'descendant state=escaped' \
    'stopped status=0' \
    'supervisor workload_status=0' \
    'supervisor cleanup_reaped=1' \
    'SIMFERRET_PHASE0_SUPERVISOR_OK version=1'; do
    if ! grep -Fxq "$line"$'\r' "$serial_log"; then
      echo "Workload $name did not report: $line" >&2
      exit 1
    fi
  done
  if grep -F 'SIMFERRET_PHASE0_INFRA_FAILURE' "$serial_log" >/dev/null; then
    echo "Workload $name reported an infrastructure failure." >&2
    exit 1
  fi
}

exercise_workload() {
  local name="$1"
  local store="$2"

  build_image "$name" "$store"
  cp "$images/$name.cpio.gz" "$images/$name.record.cpio.gz"
  run_qemu "$images/$name.cpio.gz" record "$images/$name-record.serial" \
    "$images/$name-record.qemu.log" "$images/$name-record.replay.bin"
  verify_serial "$name" "$images/$name-record.serial"

  local replay
  for replay in 1 2; do
    build_image "$name" "$store"
    if ! cmp -s "$images/$name.record.cpio.gz" "$images/$name.cpio.gz"; then
      echo "Workload $name image changed between record and replay $replay." >&2
      exit 1
    fi
    run_qemu "$images/$name.cpio.gz" replay "$images/$name-replay-$replay.serial" \
      "$images/$name-replay-$replay.qemu.log" "$images/$name-record.replay.bin"
    cmp "$images/$name-record.serial" "$images/$name-replay-$replay.serial"
  done
}

# Every source is assembled into its content-addressed store first. No QEMU
# invocation happens until the entire generated source tree is gone, so the
# record and replay runs cannot read a live workload source even by accident.
binary_store="$output_dir/store-binary"
binary_started="$(date +%s%N)"
binary_assemble="$("$python" "$prototype" assemble-binary \
  --binary "$sources/static/simferret-workload-fixture" --store "$binary_store" \
  --install-path bin/simferret-workload-fixture --user 65534:65534 \
  --environment MODE=acceptance --working-directory /)"
binary_finished="$(date +%s%N)"
binary_digest="$(json_field "$binary_assemble" canonical_digest)"

repeat_store="$output_dir/store-binary-repeat"
repeat_assemble="$("$python" "$prototype" assemble-binary \
  --binary "$sources/static/simferret-workload-fixture" --store "$repeat_store" \
  --install-path bin/simferret-workload-fixture --user 65534:65534 \
  --environment MODE=acceptance --working-directory /)"
cmp "$binary_store/raw/closure.json" "$repeat_store/raw/closure.json"

oci_static_store="$output_dir/store-oci-static"
oci_static_started="$(date +%s%N)"
oci_static_assemble="$("$python" "$prototype" assemble \
  --layout "$sources/layout-static" --manifest-digest "$static_manifest" \
  --store "$oci_static_store")"
oci_static_finished="$(date +%s%N)"
oci_static_digest="$(json_field "$oci_static_assemble" canonical_digest)"

oci_dynamic_store="$output_dir/store-oci-dynamic"
oci_dynamic_started="$(date +%s%N)"
oci_dynamic_assemble="$("$python" "$prototype" assemble \
  --layout "$sources/layout-dynamic" --manifest-digest "$dynamic_manifest" \
  --store "$oci_dynamic_store")"
oci_dynamic_finished="$(date +%s%N)"
oci_dynamic_digest="$(json_field "$oci_dynamic_assemble" canonical_digest)"

if [[ "$binary_digest" != "$oci_static_digest" ]]; then
  echo "The binary and static OCI sources did not converge on one canonical tree." >&2
  exit 1
fi
if [[ "$oci_static_digest" == "$oci_dynamic_digest" ]]; then
  echo "The static and dynamic OCI sources produced the same canonical tree." >&2
  exit 1
fi

# Remove the complete generated source tree, including the dynamic fixture and
# every adversarial layout, and prove it is gone before the first QEMU run.
rm -rf "$sources"
if [[ -e "$sources" ]]; then
  echo "The generated source tree survived removal." >&2
  exit 1
fi

exercise_workload binary "$binary_store"
exercise_workload oci-static "$oci_static_store"
exercise_workload oci-dynamic "$oci_dynamic_store"

# A workload-free image isolates how much of the initramfs is the workload.
baseline_root="$images/baseline-root"
rm -rf "$baseline_root"
mkdir -p "$baseline_root"
"$static_cc" -static -Os -Wall -Wextra -Werror "$supervisor_source" -o "$baseline_root/init"
chmod 0755 "$baseline_root/init"
find "$baseline_root" -exec touch -h -d @0 {} +
(
  cd "$baseline_root"
  find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc \
    --owner=0:0 --reproducible --quiet
) | gzip -n >"$images/baseline.cpio.gz"

# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

tree_bytes() {
  local path="$1"
  local total=0
  while IFS= read -r file; do
    total=$((total + $(wc -c <"$file")))
  done < <(find "$path" -type f)
  printf '%s' "$total"
}

{
  printf 'qemu_version=%s\n' "$("$qemu" --version | head -n 1)"
  printf 'machine=pc-i440fx-9.2\n'
  printf 'kernel=%s\n' "$kernel"
  printf 'fixture_source=%s\n' "$fixture_source"
  printf 'fixture_source_sha256=%s\n' "$(sha256sum "$fixture_source" | cut -d' ' -f1)"
  printf 'static_binary_bytes=%s\n' "$static_binary_bytes"
  printf 'dynamic_binary_bytes=%s\n' "$dynamic_binary_bytes"
  printf 'static_interpreter=none\n'
  printf 'dynamic_interpreter=%s\n' "$dynamic_interpreter"
  printf 'dynamic_loader_sha256=%s\n' "$(sha256sum "$loader" | cut -d' ' -f1)"
  printf 'dynamic_library_sha256=%s\n' "$(sha256sum "$library" | cut -d' ' -f1)"
  printf 'static_layout_bytes=%s\n' "$(json_field "$static_capture" layout_bytes)"
  printf 'static_layout_manifest=%s\n' "$static_manifest"
  printf 'dynamic_layout_bytes=%s\n' "$(json_field "$dynamic_capture" layout_bytes)"
  printf 'dynamic_layout_manifest=%s\n' "$dynamic_manifest"
  printf 'semantics_layout_bytes=%s\n' "$(json_field "$semantics_capture" layout_bytes)"
  printf 'semantics_layout_manifest=%s\n' "$semantics_manifest"
  printf 'semantics_canonical_digest=%s\n' "$semantics_digest"
  printf 'semantics_entries=%s\n' "$(json_field "$first_apply" entries)"
  printf 'semantics_expanded_bytes=%s\n' "$(json_field "$first_apply" expanded_bytes)"
  printf 'semantics_duration_ns=%s\n' "$semantics_duration_ns"
  printf 'semantics_reapply_equal=true\n'
  printf 'binary_canonical_digest=%s\n' "$binary_digest"
  printf 'binary_entries=%s\n' "$(json_field "$binary_assemble" entries)"
  printf 'binary_expanded_bytes=%s\n' "$(json_field "$binary_assemble" expanded_bytes)"
  printf 'binary_raw_bytes=%s\n' "$(json_field "$binary_assemble" raw_bytes)"
  printf 'binary_assembly_duration_ns=%s\n' "$((binary_finished - binary_started))"
  printf 'binary_reassemble_equal=%s\n' "$([[ "$binary_digest" == "$(json_field "$repeat_assemble" canonical_digest)" ]] && echo true || echo false)"
  printf 'oci_static_canonical_digest=%s\n' "$oci_static_digest"
  printf 'oci_static_entries=%s\n' "$(json_field "$oci_static_assemble" entries)"
  printf 'oci_static_expanded_bytes=%s\n' "$(json_field "$oci_static_assemble" expanded_bytes)"
  printf 'oci_static_raw_bytes=%s\n' "$(json_field "$oci_static_assemble" raw_bytes)"
  printf 'oci_static_raw_objects=%s\n' "$(json_field "$oci_static_assemble" raw_objects)"
  printf 'oci_static_assembly_duration_ns=%s\n' "$((oci_static_finished - oci_static_started))"
  printf 'oci_dynamic_canonical_digest=%s\n' "$oci_dynamic_digest"
  printf 'oci_dynamic_entries=%s\n' "$(json_field "$oci_dynamic_assemble" entries)"
  printf 'oci_dynamic_expanded_bytes=%s\n' "$(json_field "$oci_dynamic_assemble" expanded_bytes)"
  printf 'oci_dynamic_raw_bytes=%s\n' "$(json_field "$oci_dynamic_assemble" raw_bytes)"
  printf 'oci_dynamic_raw_objects=%s\n' "$(json_field "$oci_dynamic_assemble" raw_objects)"
  printf 'oci_dynamic_layers=%s\n' "$(json_field "$oci_dynamic_assemble" layers)"
  printf 'oci_dynamic_assembly_duration_ns=%s\n' "$((oci_dynamic_finished - oci_dynamic_started))"
  printf 'binary_equals_oci_static=true\n'
  printf 'baseline_initramfs_bytes=%s\n' "$(wc -c <"$images/baseline.cpio.gz")"
  printf 'opacity_layout_manifest=%s\n' "$opacity_manifest"
  printf 'opacity_tree=%s\n' "$opacity_tree"
  for name in binary oci-static oci-dynamic; do
    printf '%s_initramfs_bytes=%s\n' "$name" "$(wc -c <"$images/$name.record.cpio.gz")"
    printf '%s_initramfs_growth_bytes=%s\n' "$name" \
      "$(( $(wc -c <"$images/$name.record.cpio.gz") - $(wc -c <"$images/baseline.cpio.gz") ))"
    printf '%s_workload_tree_bytes=%s\n' "$name" "$(tree_bytes "$images/$name-root/workload")"
    printf '%s_record_duration_ns=%s\n' "$name" "$(cat "$images/$name-record.serial.duration-ns")"
    printf '%s_replay_1_duration_ns=%s\n' "$name" "$(cat "$images/$name-replay-1.serial.duration-ns")"
    printf '%s_replay_2_duration_ns=%s\n' "$name" "$(cat "$images/$name-replay-2.serial.duration-ns")"
    printf '%s_replay_log_bytes=%s\n' "$name" "$(wc -c <"$images/$name-record.replay.bin")"
    printf '%s_serial_sha256=%s\n' "$name" "$(sha256sum "$images/$name-record.serial" | cut -d' ' -f1)"
    printf '%s_record_replay_identical=true\n' "$name"
  done
  printf 'live_sources_removed_before_qemu=true\n'
  printf 'qemu_runs_after_source_removal=true\n'
  printf 'unsupported_constructs=%s\n' "$(wc -l <"$rejections")"
} >"$output_dir/evidence.txt"

cat "$output_dir/evidence.txt"
printf '\nunsupported OCI constructs:\n'
cat "$rejections"
printf '\nRFD 3 Phase 0 spike passed; artifacts: %s\n' "$output_dir"
complete=true
