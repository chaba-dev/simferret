#!/usr/bin/env bash
set -euo pipefail

# Focused regression tests for the RFD 3 Phase 0 workload and OCI spike.
#
# The QEMU invocation is faked so the orchestration, source-removal, and
# replay-comparison behavior is exercised quickly. The prototype's layer
# semantics, raw-closure sufficiency, and rejection behavior are exercised
# against real layouts.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
spike="$repo_root/scripts/rfd3-phase0-spike.sh"
prototype="$repo_root/poc/rfd3-phase0/oci_prototype.py"
layout_builder="$repo_root/poc/rfd3-phase0/build-layout.py"
static_cc="${SIMFERRET_STATIC_CC:-${CC:-cc}}"
python="${PYTHON:-python3}"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/simferret-rfd3-phase0.XXXXXXXX")"
fake_qemu="$test_root/qemu-system-x86_64"
kernel="$test_root/bzImage"
fixture="$test_root/simferret-workload-fixture"
trap 'rm -rf "$test_root"' EXIT

printf 'fake kernel\n' >"$kernel"
"$static_cc" -static -Os -Wall -Wextra -Werror \
  "$repo_root/poc/rfd3-workload/main.c" -o "$fixture"

cat >"$fake_qemu" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--version" ]]; then
  echo "QEMU emulator version test"
  exit 0
fi
if [[ -n "${FAKE_QEMU_STARTED_FILE:-}" ]]; then
  touch "$FAKE_QEMU_STARTED_FILE"
fi
# Any QEMU run that starts while a generated source tree still exists is a
# failure, so moving source removal after QEMU cannot pass unnoticed.
if [[ -n "${FAKE_QEMU_FORBID_ROOT:-}" ]] &&
  find "$FAKE_QEMU_FORBID_ROOT" -mindepth 2 -maxdepth 2 -type d -name sources |
  grep -q .; then
  printf 'SIMFERRET_PHASE0_INFRA_FAILURE kind=live_source_present\r\n'
  exit 2
fi
{
  echo '--- invocation'
  printf '%s\n' "$@"
} >>"$FAKE_QEMU_ARGUMENTS"

mode=""
replay_log=""
for argument in "$@"; do
  if [[ "$argument" == shift=auto,rr=*,rrfile=* ]]; then
    mode="${argument#*rr=}"
    mode="${mode%%,*}"
    replay_log="${argument#*rrfile=}"
  fi
done
if [[ "$mode" == record ]]; then
  printf 'fake replay log\n' >"$replay_log"
fi

emit_success() {
  printf 'ready version=1\r\n'
  printf 'echo value=asymmetric_42\r\n'
  printf 'state value=fresh root=fresh\r\n'
  printf 'descendant state=escaped\r\n'
  printf 'stopped status=0\r\n'
  printf 'supervisor workload_status=0\r\n'
  printf 'supervisor cleanup_reaped=1\r\n'
  printf 'SIMFERRET_PHASE0_SUPERVISOR_OK version=1\r\n'
}

case "${FAKE_QEMU_BEHAVIOR:-success}" in
  success) emit_success ;;
  mismatch)
    if [[ "$mode" == record ]]; then
      emit_success
    else
      printf 'ready version=1\r\n'
      printf 'supervisor workload_status=0\r\n'
      printf 'supervisor cleanup_reaped=1\r\n'
      printf 'SIMFERRET_PHASE0_SUPERVISOR_OK version=1\r\n'
    fi
    ;;
  missing-marker)
    printf 'ready version=1\r\n'
    printf 'echo value=asymmetric_42\r\n'
    printf 'state value=fresh root=fresh\r\n'
    printf 'descendant state=escaped\r\n'
    printf 'stopped status=0\r\n'
    printf 'supervisor workload_status=0\r\n'
    printf 'supervisor cleanup_reaped=1\r\n'
    ;;
  infrastructure-failure)
    printf 'SIMFERRET_PHASE0_INFRA_FAILURE kind=workload_status\r\n'
    ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$fake_qemu"

run_spike() {
  local output_root="$1"
  shift
  env \
    SIMFERRET_KERNEL="$kernel" \
    SIMFERRET_RFD3_PHASE0_OUTPUT="$output_root" \
    QEMU_SYSTEM_X86_64="$fake_qemu" \
    FAKE_QEMU_ARGUMENTS="$test_root/qemu.arguments" \
    FAKE_QEMU_FORBID_ROOT="$output_root" \
    "$@" \
    "$spike" >/dev/null 2>&1
}

# The successful run preserves unrelated output and records exactly three QEMU
# invocations per workload source.
preserved="$test_root/preserved"
mkdir -p "$preserved"
printf 'keep me\n' >"$preserved/sentinel"
: >"$test_root/qemu.arguments"
run_spike "$preserved"
test "$(cat "$preserved/sentinel")" = "keep me"
run_dir="$(find "$preserved" -mindepth 1 -maxdepth 1 -type d -name 'run.*')"
test -n "$run_dir"
test "$(grep -c '^--- invocation$' "$test_root/qemu.arguments")" -eq 9
test "$(grep -c '^shift=auto,rr=record,rrfile=' "$test_root/qemu.arguments")" -eq 3
test "$(grep -c '^shift=auto,rr=replay,rrfile=' "$test_root/qemu.arguments")" -eq 6
test "$(grep -c '^user,id=' "$test_root/qemu.arguments" || true)" -eq 0
awk '$0 == "-net" { getline; if ($0 != "none") found = 1 } END { exit found }' \
  "$test_root/qemu.arguments"
for line in 'ready version=1' 'echo value=asymmetric_42' 'state value=fresh root=fresh' \
  'descendant state=escaped' 'stopped status=0' 'supervisor workload_status=0' \
  'supervisor cleanup_reaped=1' 'SIMFERRET_PHASE0_SUPERVISOR_OK version=1'; do
  grep -Fxq "$line"$'\r' "$run_dir/images/binary-record.serial"
done
test ! -e "$run_dir/sources"
test -d "$run_dir/store-binary/raw/sha256"
test -d "$run_dir/store-oci-dynamic/derived"
grep -Fq 'live_sources_removed_before_qemu=true' "$run_dir/evidence.txt"
grep -Fq 'qemu_runs_after_source_removal=true' "$run_dir/evidence.txt"
grep -Fq 'binary_equals_oci_static=true' "$run_dir/evidence.txt"
grep -Fq 'unsupported_constructs=18' "$run_dir/evidence.txt"

# Divergent, incomplete, and failed guest output must all fail the spike.
for behavior in mismatch missing-marker infrastructure-failure; do
  if run_spike "$test_root/$behavior" "FAKE_QEMU_BEHAVIOR=$behavior"; then
    echo "$behavior unexpectedly passed" >&2
    exit 1
  fi
done

# Invalid bounds must fail before QEMU starts.
for duration in 0 -1s invalid; do
  started_file="$test_root/duration-$duration.started"
  if run_spike "$test_root/duration" \
    "SIMFERRET_QEMU_TIMEOUT=$duration" \
    "FAKE_QEMU_STARTED_FILE=$started_file"; then
    echo "invalid duration $duration unexpectedly passed" >&2
    exit 1
  fi
  test ! -e "$started_file"
done

# ---------------------------------------------------------------------------
# Prototype layer semantics, canonical identity, and rejection behavior
# ---------------------------------------------------------------------------

layout="$test_root/layout"
semantics_capture="$("$python" "$layout_builder" semantics \
  --binary "$fixture" --out "$layout")"
semantics_manifest="$("$python" -c \
  'import json, sys; print(json.loads(sys.argv[1])["manifest_digest"])' "$semantics_capture")"
first="$("$python" "$prototype" apply --layout "$layout" \
  --manifest-digest "$semantics_manifest" --out "$test_root/semantics-1")"
second="$(PYTHONHASHSEED=1 "$python" "$prototype" apply --layout "$layout" \
  --manifest-digest "$semantics_manifest" --out "$test_root/semantics-2")"
test "$("$python" -c 'import json, sys; print(json.loads(sys.argv[1])["canonical_digest"])' "$first")" = \
  "$("$python" -c 'import json, sys; print(json.loads(sys.argv[1])["canonical_digest"])' "$second")"
"$python" "$prototype" compare-trees \
  --left "$test_root/semantics-1" --right "$test_root/semantics-2" >/dev/null

tree="$test_root/semantics-1"
# Metadata, replacement, whiteout, and opaque-directory semantics. Ownership is
# excluded because the unprivileged prototype cannot reproduce numeric owners.
test "$(stat -c '%a %Y' "$tree/etc")" = "750 1700000003"
test "$(stat -c '%a %Y' "$tree/etc/config")" = "640 1700000002"
test "$(cat "$tree/etc/config")" = "upper"
test "$(stat -c '%a' "$tree/etc/remove-me")" = "600"
test "$(cat "$tree/etc/remove-me")" = "upper-remove"
test ! -e "$tree/opt/keep"
test ! -e "$tree/opt/drop"
test ! -e "$tree/opt/nested"
test ! -e "$tree/etc/pure-delete"
test -d "$tree/etc/swap"
test "$(cat "$tree/etc/swap/new")" = "swap-new"
test "$(cat "$tree/opt/new")" = "new"
test "$(cat "$tree/srv/opaque/lower")" = "lower"
test "$(stat -c '%a %Y' "$tree/var/log")" = "750 1700000000"
test "$(stat -c '%a %Y' "$tree/var/log/upper")" = "640 1700000004"
test "$(readlink "$tree/links/current")" = "../bin/simferret-workload-fixture"
test "$(readlink "$tree/links/latest")" = "current"

# Root-level opacity applies to the lower view only.
opacity_layout="$test_root/layout-opacity"
opacity_capture="$("$python" "$layout_builder" root-opacity --binary "$fixture" \
  --out "$opacity_layout")"
opacity_manifest="$("$python" -c \
  'import json, sys; print(json.loads(sys.argv[1])["manifest_digest"])' "$opacity_capture")"
"$python" "$prototype" apply --layout "$opacity_layout" \
  --manifest-digest "$opacity_manifest" --out "$test_root/opacity" >/dev/null
test "$(cd "$test_root/opacity" && find . -mindepth 1 | LC_ALL=C sort | tr '\n' ' ')" = \
  "./bin ./bin/simferret-workload-fixture ./keep ./keep/upper "

# Repeated layout generation is byte-stable.
repeat_layout="$test_root/layout-repeat"
repeat_capture="$("$python" "$layout_builder" semantics \
  --binary "$fixture" --out "$repeat_layout")"
test "$semantics_manifest" = \
  "$("$python" -c 'import json, sys; print(json.loads(sys.argv[1])["manifest_digest"])' "$repeat_capture")"

# The binary and static OCI sources converge on one canonical tree.
static_layout="$test_root/layout-static"
static_capture="$("$python" "$layout_builder" static --binary "$fixture" --out "$static_layout")"
static_manifest="$("$python" -c \
  'import json, sys; print(json.loads(sys.argv[1])["manifest_digest"])' "$static_capture")"
static_apply="$("$python" "$prototype" apply --layout "$static_layout" \
  --manifest-digest "$static_manifest" --out "$test_root/static-apply")"
binary_store="$test_root/store-binary"
binary_assemble="$("$python" "$prototype" assemble-binary --binary "$fixture" \
  --store "$binary_store" --install-path bin/simferret-workload-fixture \
  --user 65534:65534 --environment MODE=acceptance --working-directory /)"
test "$("$python" -c 'import json, sys; print(json.loads(sys.argv[1])["canonical_digest"])' "$static_apply")" = \
  "$("$python" -c 'import json, sys; print(json.loads(sys.argv[1])["canonical_digest"])' "$binary_assemble")"

# The binary source must be a regular file beneath its opened directory.
ln -s "$fixture" "$test_root/symlinked-fixture"
if "$python" "$prototype" assemble-binary --binary "$test_root/symlinked-fixture" \
  --store "$test_root/store-symlink" >/dev/null 2>&1; then
  echo "assemble-binary accepted a symbolic link source" >&2
  exit 1
fi

# Replay needs the raw closure: a missing, corrupt, or tampered object fails.
"$python" "$prototype" materialize --store "$binary_store" \
  --out "$test_root/materialized" >/dev/null
raw_objects=("$binary_store"/raw/sha256/*)
test "${#raw_objects[@]}" -eq 2
cp -a "$binary_store" "$test_root/store-missing"
rm -f "$test_root/store-missing"/raw/sha256/"$(basename "${raw_objects[0]}")"
if "$python" "$prototype" materialize --store "$test_root/store-missing" \
  --out "$test_root/missing-out" >/dev/null 2>&1; then
  echo "materialize accepted a missing raw object" >&2
  exit 1
fi
cp -a "$binary_store" "$test_root/store-corrupt"
corrupt="$test_root/store-corrupt/raw/sha256/$(basename "${raw_objects[0]}")"
printf 'corrupt' >>"$corrupt"
if "$python" "$prototype" materialize --store "$test_root/store-corrupt" \
  --out "$test_root/corrupt-out" >/dev/null 2>&1; then
  echo "materialize accepted a corrupt raw object" >&2
  exit 1
fi
cp -a "$binary_store" "$test_root/store-tampered"
derived="$test_root/store-tampered/derived"
canonical="$("$python" -c \
  'import json, sys; print(json.loads(sys.argv[1])["canonical_digest"])' "$binary_assemble")"
printf '{"path":".","type":"dir"}\n' >"$derived/$canonical/tree.json"
if "$python" "$prototype" materialize --store "$test_root/store-tampered" \
  --out "$test_root/tampered-out" >/dev/null 2>&1; then
  echo "materialize accepted a tampered derived entry" >&2
  exit 1
fi

# The raw closure record is pinned by its lock, the launch is re-derived from
# the retained specification object, and the specification is required.
cp -a "$binary_store" "$test_root/store-edited"
"$python" - "$test_root/store-edited" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1]) / "raw" / "closure.json"
closure = json.loads(path.read_text())
closure["launch"]["environment"] = ["MODE=tampered"]
path.write_text(json.dumps(closure, sort_keys=True, separators=(",", ":")) + "\n")
PY
if "$python" "$prototype" materialize --store "$test_root/store-edited" \
  --out "$test_root/edited-out" >/dev/null 2>&1; then
  echo "materialize accepted an edited closure record" >&2
  exit 1
fi

cp -a "$binary_store" "$test_root/store-relocked"
"$python" - "$test_root/store-relocked" <<'PY'
import hashlib, json, pathlib, sys
directory = pathlib.Path(sys.argv[1])
path = directory / "raw" / "closure.json"
closure = json.loads(path.read_text())
closure["launch"]["environment"] = ["MODE=tampered"]
data = (json.dumps(closure, sort_keys=True, separators=(",", ":")) + "\n").encode()
path.write_bytes(data)
digest = hashlib.sha256(data).hexdigest()
(directory / "raw" / "closure.sha256").write_text(digest + "\n")
# Update the derived lock too, so only the launch comparison can catch this.
lock = directory / "derived" / closure["canonical_digest"] / "lock.json"
entry = json.loads(lock.read_text())
entry["closure_sha256"] = digest
lock.write_text(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
PY
if "$python" "$prototype" materialize --store "$test_root/store-relocked" \
  --out "$test_root/relocked-out" 2>"$test_root/relocked.err"; then
  echo "materialize accepted a closure whose launch no longer matches" >&2
  exit 1
fi
grep -Fq 'launch identity does not match' "$test_root/relocked.err"

cp -a "$binary_store" "$test_root/store-nospec"
"$python" - "$test_root/store-nospec" <<'PY'
import hashlib, json, pathlib, sys
directory = pathlib.Path(sys.argv[1])
path = directory / "raw" / "closure.json"
closure = json.loads(path.read_text())
record = [item for item in closure["objects"] if item["role"] == "workload-specification"][0]
(directory / "raw" / "sha256" / record["digest"].split(":")[1]).unlink()
closure["objects"] = [
    item for item in closure["objects"] if item["role"] != "workload-specification"
]
data = (json.dumps(closure, sort_keys=True, separators=(",", ":")) + "\n").encode()
path.write_bytes(data)
digest = hashlib.sha256(data).hexdigest()
(directory / "raw" / "closure.sha256").write_text(digest + "\n")
lock = directory / "derived" / closure["canonical_digest"] / "lock.json"
entry = json.loads(lock.read_text())
entry["closure_sha256"] = digest
lock.write_text(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
PY
if "$python" "$prototype" materialize --store "$test_root/store-nospec" \
  --out "$test_root/nospec-out" 2>"$test_root/nospec.err"; then
  echo "materialize accepted a closure without its specification object" >&2
  exit 1
fi
grep -Fq 'no workload-specification object' "$test_root/nospec.err"

# Cache metadata is bounded, and a special file in a materialized tree is
# rejected rather than read.
cp -a "$binary_store" "$test_root/store-huge"
"$python" -c 'import pathlib, sys; pathlib.Path(sys.argv[1]).write_bytes(b"{}" + b" " * (5 << 20))' \
  "$test_root/store-huge/raw/closure.json"
if "$python" "$prototype" materialize --store "$test_root/store-huge" \
  --out "$test_root/huge-out" 2>"$test_root/huge.err"; then
  echo "materialize accepted an oversized closure record" >&2
  exit 1
fi
grep -Fq 'exceeds' "$test_root/huge.err"

cp -a "$binary_store" "$test_root/store-fifo"
canonical="$("$python" -c \
  'import json, sys; print(json.loads(sys.argv[1])["canonical_digest"])' "$binary_assemble")"
rm -f "$test_root/store-fifo/derived/$canonical/tree/bin/simferret-workload-fixture"
mkfifo "$test_root/store-fifo/derived/$canonical/tree/bin/simferret-workload-fixture"
if timeout 20s "$python" "$prototype" materialize --store "$test_root/store-fifo" \
  --out "$test_root/fifo-out" 2>"$test_root/fifo.err"; then
  echo "materialize accepted a special file in the cached tree" >&2
  exit 1
fi
grep -Fq 'special file' "$test_root/fifo.err"

# A cached tree file larger than the policy allows is rejected before it is read,
# rather than hashed in full.
cp -a "$binary_store" "$test_root/store-huge-file"
truncate -s 17M "$test_root/store-huge-file/derived/$canonical/tree/bin/simferret-workload-fixture"
if timeout 20s "$python" "$prototype" materialize --store "$test_root/store-huge-file" \
  --out "$test_root/huge-file-out" 2>"$test_root/huge-file.err"; then
  echo "materialize accepted an oversized file in the cached tree" >&2
  exit 1
fi
grep -Fq 'exceeds' "$test_root/huge-file.err"

# The raw closure, raw objects, and an existing object at assembly are all read
# through bounded, link-free, non-blocking readers: a FIFO is rejected instead of
# blocking the run.
fixture_digest="$(sha256sum "$fixture" | cut -d' ' -f1)"
cp -a "$binary_store" "$test_root/store-fifo-closure"
rm -f "$test_root/store-fifo-closure/raw/closure.json"
mkfifo "$test_root/store-fifo-closure/raw/closure.json"
if timeout 20s "$python" "$prototype" materialize --store "$test_root/store-fifo-closure" \
  --out "$test_root/fifo-closure-out" 2>"$test_root/fifo-closure.err"; then
  echo "materialize accepted a FIFO in place of the raw closure" >&2
  exit 1
fi
grep -Fq 'is not a regular file' "$test_root/fifo-closure.err"

cp -a "$binary_store" "$test_root/store-fifo-object"
rm -f "$test_root/store-fifo-object/raw/sha256/$fixture_digest"
mkfifo "$test_root/store-fifo-object/raw/sha256/$fixture_digest"
if timeout 20s "$python" "$prototype" materialize --store "$test_root/store-fifo-object" \
  --out "$test_root/fifo-object-out" 2>"$test_root/fifo-object.err"; then
  echo "materialize accepted a FIFO in place of a raw object" >&2
  exit 1
fi
grep -Fq 'is not a regular file' "$test_root/fifo-object.err"

mkdir -p "$test_root/store-fifo-existing/raw/sha256"
mkfifo "$test_root/store-fifo-existing/raw/sha256/$fixture_digest"
if timeout 20s "$python" "$prototype" assemble-binary --binary "$fixture" \
  --store "$test_root/store-fifo-existing" 2>"$test_root/fifo-existing.err"; then
  echo "assemble-binary read a FIFO standing in for an existing raw object" >&2
  exit 1
fi
grep -Fq 'is not a regular file' "$test_root/fifo-existing.err"

# A closure naming an object role the prototype does not define is rejected,
# rather than read under another role's limit.
cp -a "$binary_store" "$test_root/store-role"
"$python" - "$test_root/store-role" <<'PY'
import hashlib, json, pathlib, sys

directory = pathlib.Path(sys.argv[1])
data = b"unexpected object\n"
digest = hashlib.sha256(data).hexdigest()
(directory / "raw" / "sha256" / digest).write_bytes(data)
path = directory / "raw" / "closure.json"
closure = json.loads(path.read_text())
closure["objects"].append({"role": "unexpected", "digest": f"sha256:{digest}", "bytes": len(data)})
raw = (json.dumps(closure, sort_keys=True, separators=(",", ":")) + "\n").encode()
path.write_bytes(raw)
lock_digest = hashlib.sha256(raw).hexdigest()
(directory / "raw" / "closure.sha256").write_text(lock_digest + "\n")
lock = directory / "derived" / closure["canonical_digest"] / "lock.json"
entry = json.loads(lock.read_text())
entry["closure_sha256"] = lock_digest
lock.write_text(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
PY
if "$python" "$prototype" materialize --store "$test_root/store-role" \
  --out "$test_root/role-out" 2>"$test_root/role.err"; then
  echo "materialize accepted an unknown raw object role" >&2
  exit 1
fi
grep -Fq 'unknown object role' "$test_root/role.err"

# A cached tree that is a symbolic link, and a store whose raw directory is a
# symbolic link, are rejected instead of read through.
cp -a "$binary_store" "$test_root/store-tree-link"
rm -rf "$test_root/store-tree-link/derived/$canonical/tree"
mkdir -p "$test_root/outside-tree/bin"
ln -s "$test_root/outside-tree" "$test_root/store-tree-link/derived/$canonical/tree"
if "$python" "$prototype" materialize --store "$test_root/store-tree-link" \
  --out "$test_root/tree-link-out" 2>"$test_root/tree-link.err"; then
  echo "materialize accepted a symbolic link as the cached tree" >&2
  exit 1
fi
grep -Fq 'not a directory' "$test_root/tree-link.err"

cp -a "$binary_store" "$test_root/store-raw-link"
mv "$test_root/store-raw-link/raw" "$test_root/store-raw-link/raw-real"
ln -s raw-real "$test_root/store-raw-link/raw"
if "$python" "$prototype" materialize --store "$test_root/store-raw-link" \
  --out "$test_root/raw-link-out" 2>"$test_root/raw-link.err"; then
  echo "materialize followed a symbolic link in the store path" >&2
  exit 1
fi
grep -Fq 'cannot open directory' "$test_root/raw-link.err"

# Assembly must not write through a symbolic link in the store path either.
mkdir -p "$test_root/store-raw-link-assemble" "$test_root/store-raw-link-outside"
ln -s "$test_root/store-raw-link-outside" "$test_root/store-raw-link-assemble/raw"
if "$python" "$prototype" assemble-binary --binary "$fixture" \
  --store "$test_root/store-raw-link-assemble" 2>"$test_root/raw-link-assemble.err"; then
  echo "assemble-binary wrote through a symbolic link in the store path" >&2
  exit 1
fi
grep -Fq 'cannot open store directory' "$test_root/raw-link-assemble.err"
test ! -e "$test_root/store-raw-link-outside/sha256"

# Assembly must not publish the derived entry through a symbolic link in the
# store path, and materialization must not read through one either.
mkdir -p "$test_root/store-derived-link" "$test_root/store-derived-outside"
ln -s "$test_root/store-derived-outside" "$test_root/store-derived-link/derived"
if "$python" "$prototype" assemble-binary --binary "$fixture" \
  --store "$test_root/store-derived-link" 2>"$test_root/derived-link.err"; then
  echo "assemble-binary published a derived entry through a symbolic link" >&2
  exit 1
fi
grep -Fq 'cannot open store directory' "$test_root/derived-link.err"
test -z "$(find "$test_root/store-derived-outside" -mindepth 1)"

cp -a "$binary_store" "$test_root/store-derived-link-materialize"
mv "$test_root/store-derived-link-materialize/derived" "$test_root/store-derived-moved"
ln -s "$test_root/store-derived-moved" "$test_root/store-derived-link-materialize/derived"
if "$python" "$prototype" materialize --store "$test_root/store-derived-link-materialize" \
  --out "$test_root/derived-link-out" 2>"$test_root/derived-link-materialize.err"; then
  echo "materialize followed a symbolic link in the store path" >&2
  exit 1
fi
grep -Fq 'cannot open directory' "$test_root/derived-link-materialize.err"

# Verification is bounded and link-free, and the aggregate entry and expanded
# bounds are enforced at assembly before anything is written.
PYTHONDONTWRITEBYTECODE=1 "$python" - "$prototype" "$test_root/verify-bounds" <<'PY'
import importlib.util, pathlib, sys

spec = importlib.util.spec_from_file_location("proto", sys.argv[1])
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

scratch = pathlib.Path(sys.argv[2])
scratch.mkdir(parents=True)
tree = scratch / "tree"
tree.mkdir()
for index in range(5):
    (tree / f"file{index}").write_bytes(b"x")

link = scratch / "link"
link.symlink_to(tree)
try:
    p.describe_tree(str(link), p.LIMITS["view_entries"])
except p.Rejection as rejection:
    assert "not a directory" in str(rejection), rejection
else:
    raise SystemExit("describe_tree followed a symbolic link root")

try:
    p.describe_tree(str(tree), 4)
except p.Rejection as rejection:
    assert "entries" in str(rejection), rejection
else:
    raise SystemExit("describe_tree accepted a tree over the entry limit")

# The files in the size case share one buffer: the smallest source that exceeds
# the aggregate expanded bound needs more than 256 MiB of file data, which is
# not worth generating in a fast regression test. The entry case uses
# directories so that it is the entry bound, and not the manifest size bound,
# that rejects it.
shared = bytes(16 << 20)
cases = (
    (
        "entries",
        {
            ".": p.default_directory(),
            **{
                f"d{index:05d}": p.Entry("dir", 0o755, 0, 0, 0)
                for index in range(p.LIMITS["view_entries"])
            },
        },
        "entries",
    ),
    (
        "expanded",
        {
            ".": p.default_directory(),
            **{
                f"f{index:03d}": p.Entry("file", 0o644, 0, 0, 0, data=shared)
                for index in range(17)
            },
        },
        "expanded bytes",
    ),
)
for label, view, message in cases:
    store = scratch / f"store-{label}"
    graph = {
        "view": view,
        "layers": [],
        "launch": {
            "executable": "/bin/x",
            "arguments": [],
            "environment": [],
            "working_directory": "/",
            "uid": 0,
            "gid": 0,
        },
    }
    try:
        p.assemble_store(str(store), {"kind": "binary"}, {}, graph)
    except p.Rejection as rejection:
        assert message in str(rejection), rejection
    else:
        raise SystemExit(f"assemble_store accepted a tree over the aggregate {label} bound")
    assert not store.exists(), f"a rejected {label} assembly left a store behind"
PY

# A source whose canonical tree manifest exceeds the bound replay reads it under
# is refused at assembly, so assembly cannot publish a store that materialization
# cannot read back, and the refusal leaves no store behind.
big_layout="$test_root/layout-big-manifest"
big_capture="$("$python" "$layout_builder" big-manifest --binary "$fixture" --out "$big_layout")"
big_manifest="$("$python" -c \
  'import json, sys; print(json.loads(sys.argv[1])["manifest_digest"])' "$big_capture")"
big_store="$test_root/store-big-manifest"
if "$python" "$prototype" assemble --layout "$big_layout" \
  --manifest-digest "$big_manifest" --store "$big_store" 2>"$test_root/big-manifest.err"; then
  echo "assemble published a store whose tree manifest replay cannot read" >&2
  exit 1
fi
grep -Fq 'tree manifest' "$test_root/big-manifest.err"
test ! -e "$big_store"

# Marker semantics that a layout cannot conveniently express: a whiteout whose
# parent the same layer replaces with a symbolic link is valid, while a marker
# inside a lower-layer symbolic link is not.
PYTHONDONTWRITEBYTECODE=1 "$python" - "$prototype" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("proto", sys.argv[1])
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def file(name, data=b"x"):
    return p.LayerMember(name, "file", 0o644, 0, 0, 0, data=data)


def symlink(name, target):
    return p.LayerMember(name, "symlink", 0o777, 0, 0, 0, target=target)


def directory(name):
    return p.LayerMember(name, "dir", 0o755, 0, 0, 0)


lower = {".": p.default_directory(), "d": p.default_directory(), "d/child": file("d/child")}
p.apply_layer(lower, [file("d/.wh.child", b""), symlink("d", "target")])
assert "d/child" not in lower, "whiteout with a replaced parent did not delete the lower child"

try:
    p.apply_layer(
        {".": p.default_directory(), "redirect": symlink("redirect", "elsewhere")},
        [file("redirect/.wh.victim", b"")],
    )
except p.Rejection:
    pass
else:
    raise SystemExit("a marker inside a lower-layer symlink was accepted")

# A layer that provides the directory itself may whiteout through it, because
# the provided directory replaces the lower symlink during additions.
provided = {".": p.default_directory(), "redirect": symlink("redirect", "elsewhere")}
p.apply_layer(provided, [directory("redirect"), file("redirect/.wh.victim", b"")])
assert provided["redirect"].kind == "dir", "a provided directory did not replace the lower symlink"

# Providing only a nested file does not replace the lower symlink, so the path
# still traverses a symbolic link and must be rejected.
try:
    p.apply_layer(
        {".": p.default_directory(), "redirect": symlink("redirect", "elsewhere")},
        [file("redirect/new"), file("redirect/.wh.victim", b"")],
    )
except p.Rejection as rejection:
    assert "traverses" in str(rejection), f"unexpected rejection {rejection}"
else:
    raise SystemExit("a marker through a surviving lower symlink was accepted")
PY

# Every unsupported construct is refused without partial output.
while IFS= read -r defect; do
  adversarial="$test_root/adversarial-$defect"
  adversarial_capture="$("$python" "$layout_builder" adversarial --defect "$defect" \
    --binary "$fixture" --out "$adversarial")"
  adversarial_manifest="$("$python" -c \
    'import json, sys; print(json.loads(sys.argv[1])["manifest_digest"])' "$adversarial_capture")"
  if "$python" "$prototype" apply --layout "$adversarial" \
    --manifest-digest "$adversarial_manifest" --out "$test_root/out-$defect" \
    >/dev/null 2>&1; then
    echo "adversarial layout $defect was unexpectedly accepted" >&2
    exit 1
  fi
  test ! -e "$test_root/out-$defect"
done < <("$python" "$layout_builder" defects)

# ---------------------------------------------------------------------------
# Supervisor cleanup barrier, executed as a real PID 1 in a PID namespace
# ---------------------------------------------------------------------------
# The supervisor is only meaningful as a guest init, so its cleanup behavior is
# exercised by running the same control flow as PID 1 of a private PID namespace
# on the host. The guest paths and the power-off call are the only differences;
# the loop, kill, and reap logic is the code the guest runs.
supervisor_namespace_kind() {
  if unshare --user --map-root-user --pid --fork --kill-child true 2>/dev/null; then
    printf '%s\n' unprivileged
    return 0
  fi
  # Ubuntu 24.04 and later restrict unprivileged user namespaces, so a
  # privileged namespace is the fallback where sudo is available. The test build
  # never powers off, which is what makes that safe.
  if command -v sudo >/dev/null 2>&1 &&
    sudo -n unshare --pid --fork --kill-child true 2>/dev/null; then
    printf '%s\n' privileged
    return 0
  fi
  return 1
}

if ! namespace_kind="$(supervisor_namespace_kind)"; then
  echo "the supervisor cleanup cases need a PID namespace, unprivileged or through sudo" >&2
  exit 1
fi
if [[ "$namespace_kind" == "unprivileged" ]]; then
  namespace=(unshare --user --map-root-user --pid --fork --kill-child)
else
  namespace=(sudo -n unshare --pid --fork --kill-child)
fi
printf 'Supervisor cleanup cases use a %s PID namespace.\n' "$namespace_kind"

supervisor_root="$test_root/supervisor"
mkdir -p "$supervisor_root/workload/bin" "$supervisor_root/etc"
printf 'binary\n' >"$supervisor_root/etc/simferret-source-kind"
printf 'echo value=supervisor-test\n' >"$supervisor_root/etc/simferret-commands"
"$static_cc" -static -Os -Wall -Wextra -Werror \
  "$repo_root/poc/rfd3-phase0/supervisor-test-workload.c" \
  -o "$supervisor_root/workload/bin/simferret-workload-fixture"
"$static_cc" -static -Os -Wall -Wextra -Werror \
  -DSIMFERRET_SUPERVISOR_TEST_NO_REBOOT \
  -DWORKLOAD_ROOT="\"$supervisor_root/workload\"" \
  -DCOMMAND_PATH="\"$supervisor_root/etc/simferret-commands\"" \
  -DSOURCE_PATH="\"$supervisor_root/etc/simferret-source-kind\"" \
  "$repo_root/poc/rfd3-phase0/supervisor.c" -o "$supervisor_root/supervisor"

# `writer`: the primary exits while a descendant keeps the output pipe busy, so
# the primary's exit must be noticed inside the read loop. `silent`: end of file
# arrives before the primary exits, while a descendant that holds no output
# descriptor is still alive, so the cleanup barrier must run on that path too.
for supervisor_case in writer silent; do
  printf '%s\n' "$supervisor_case" >"$supervisor_root/workload/mode"
  supervisor_status=0
  timeout --kill-after=5s 15s "${namespace[@]}" "$supervisor_root/supervisor" \
    >"$supervisor_root/$supervisor_case.stdout" 2>"$supervisor_root/$supervisor_case.stderr" ||
    supervisor_status=$?
  if [[ "$supervisor_status" -ne 0 ]]; then
    echo "supervisor $supervisor_case case did not complete (status $supervisor_status)" >&2
    exit 1
  fi
  grep -Fxq 'supervisor workload_status=0' "$supervisor_root/$supervisor_case.stdout"
  grep -Fxq 'supervisor cleanup_reaped=1' "$supervisor_root/$supervisor_case.stdout"
  grep -Fxq 'SIMFERRET_PHASE0_SUPERVISOR_OK version=1' \
    "$supervisor_root/$supervisor_case.stdout"
done

printf 'RFD 3 Phase 0 spike regression tests passed.\n'
