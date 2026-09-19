#!/usr/bin/env bash
# Regression harness for the RFD 3 Phase 4 evidence checks.
#
# The acceptance script must fail closed: an unreadable tree, a failed
# measurement producer, a leaked canary in either encoding, an unexpected file
# in a shareable bundle, or a bundle that is not a typed failure report all have
# to be rejected. Every case below is a negative control for one of those
# checks, plus the accepted shapes they must not reject.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/rfd3-phase4-checks.sh
source "$repo_root/scripts/rfd3-phase4-checks.sh"

test_root="$(mktemp -d "${TMPDIR:-/tmp}/simferret-rfd3-phase4-checks.XXXXXXXX")"
trap 'rm -rf "$test_root"' EXIT
output="$test_root/output.txt"

expect_pass() { # expect_pass DESCRIPTION COMMAND...
  local description="$1"
  shift
  if ! "$@" >"$output" 2>&1; then
    echo "expected $description to pass:" >&2
    cat "$output" >&2
    exit 1
  fi
}

expect_fail() { # expect_fail DESCRIPTION EXPECTED-TEXT COMMAND...
  local description="$1" expected="$2"
  shift 2
  if "$@" >"$output" 2>&1; then
    echo "expected $description to fail" >&2
    exit 1
  fi
  if ! grep -F -- "$expected" "$output" >/dev/null; then
    echo "expected $description to report '$expected':" >&2
    cat "$output" >&2
    exit 1
  fi
}

canary_value="simferret-phase4-canary-9c41"
canary_hex="$(printf '%s' "$canary_value" | od -An -v -tx1 | tr -d ' \n')"

write_report() { # write_report PATH ERROR-TEXT
  "$python" - "$1" "$2" <<'PY'
import json
import sys

report = {
    "version": 1,
    "error_kind": "infrastructure",
    "error": sys.argv[2],
    "diagnostics": {
        "operation": "replay",
        "stage": "preflight",
        "backend_mode": "replay",
        "fixture_mode": "empty-passive",
        "network_status": "not-yet-validated",
        "network": None,
        "fault_transitions": [],
        "traffic": {
            "requests_attempted": 0,
            "requests_succeeded": 0,
            "requests_unavailable": 0,
        },
        "packet_counters": {
            "available": False,
            "incoming": None,
            "outgoing": None,
            "reason": "the selected QEMU user backend and replay filter expose no packet-counter API",
        },
    },
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(report, handle)
PY
}

clean_bundle="$test_root/clean"
mkdir -p "$clean_bundle"
write_report "$clean_bundle/failure.json" "raw closure raw/closure.json is missing"

logged_bundle="$test_root/logged"
mkdir -p "$logged_bundle/logs"
cp "$clean_bundle/failure.json" "$logged_bundle/failure.json"
printf 'qemu: guest started\n' >"$logged_bundle/logs/qemu.log"
printf 'guest: console\n' >"$logged_bundle/logs/serial.log"

leaky_plain="$test_root/leaky-plain"
mkdir -p "$leaky_plain"
write_report "$leaky_plain/failure.json" "the workload printed $canary_value"

leaky_log="$test_root/leaky-log"
mkdir -p "$leaky_log/logs"
cp "$clean_bundle/failure.json" "$leaky_log/failure.json"
printf 'guest: %s\n' "$canary_value" >"$leaky_log/logs/serial.log"

leaky_hex="$test_root/leaky-hex"
mkdir -p "$leaky_hex"
write_report "$leaky_hex/failure.json" "{\"bytes\":\"$canary_hex\"}"

leaky_upper_hex="$test_root/leaky-upper-hex"
mkdir -p "$leaky_upper_hex"
write_report "$leaky_upper_hex/failure.json" "{\"bytes\":\"${canary_hex^^}\"}"

leaky_file="$test_root/leaky-file"
mkdir -p "$leaky_file"
cp "$clean_bundle/failure.json" "$leaky_file/failure.json"
printf 'ready version=1\n' >"$leaky_file/events.jsonl"

leaky_store="$test_root/leaky-store"
mkdir -p "$leaky_store/store/raw"
cp "$clean_bundle/failure.json" "$leaky_store/failure.json"
printf '{}\n' >"$leaky_store/store/raw/closure.json"

leaky_field="$test_root/leaky-field"
mkdir -p "$leaky_field"
"$python" - "$clean_bundle/failure.json" "$leaky_field/failure.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
report["environment"] = ["MODE=acceptance"]
json.dump(report, open(sys.argv[2], "w"))
PY

nested_field="$test_root/nested-field"
mkdir -p "$nested_field"
"$python" - "$clean_bundle/failure.json" "$nested_field/failure.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
report["diagnostics"]["environment"] = ["MODE=acceptance"]
json.dump(report, open(sys.argv[2], "w"))
PY

empty_diagnostics="$test_root/empty-diagnostics"
mkdir -p "$empty_diagnostics"
"$python" - "$clean_bundle/failure.json" "$empty_diagnostics/failure.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
report["diagnostics"] = {}
json.dump(report, open(sys.argv[2], "w"))
PY

unknown_kind="$test_root/unknown-kind"
mkdir -p "$unknown_kind"
"$python" - "$clean_bundle/failure.json" "$unknown_kind/failure.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
report["error_kind"] = "other"
json.dump(report, open(sys.argv[2], "w"))
PY

unreadable_bundle="$test_root/unreadable"
mkdir -p "$unreadable_bundle/logs"
cp "$clean_bundle/failure.json" "$unreadable_bundle/failure.json"
printf 'guest: console\n' >"$unreadable_bundle/logs/serial.log"
chmod 000 "$unreadable_bundle/logs"

linked_bundle="$test_root/linked"
mkdir -p "$linked_bundle" "$test_root/linked-target"
cp "$clean_bundle/failure.json" "$linked_bundle/failure.json"
ln -s "$test_root/linked-target" "$linked_bundle/logs"

fifo_bundle="$test_root/fifo"
mkdir -p "$fifo_bundle/logs"
cp "$clean_bundle/failure.json" "$fifo_bundle/failure.json"
mkfifo "$fifo_bundle/logs/qemu.log"

untyped_bundle="$test_root/untyped"
mkdir -p "$untyped_bundle"
"$python" - "$clean_bundle/failure.json" "$untyped_bundle/failure.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
report["error_kind"] = ""
json.dump(report, open(sys.argv[2], "w"))
PY

missing_field_bundle="$test_root/missing-field"
mkdir -p "$missing_field_bundle"
"$python" - "$clean_bundle/failure.json" "$missing_field_bundle/failure.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1]))
del report["diagnostics"]
json.dump(report, open(sys.argv[2], "w"))
PY

malformed_bundle="$test_root/malformed"
mkdir -p "$malformed_bundle"
printf 'not json\n' >"$malformed_bundle/failure.json"

empty_bundle="$test_root/empty"
mkdir -p "$empty_bundle"

absent_root="$test_root/absent-root"
mkdir -p "$absent_root"
printf 'clean\n' >"$absent_root/file.txt"
printf 'canary %s\n' "$canary_value" >"$absent_root/leak.txt"

# require_absent: absence, presence, and an unreadable tree.
expect_pass "a clean tree" require_absent "clean tree" "$canary_value" "$absent_root/file.txt"
expect_fail "a tree that carries the needle" \
  "must not appear" require_absent "leak" "$canary_value" "$absent_root"
expect_fail "a tree that does not exist" \
  "cannot inspect" require_absent "missing tree" "$canary_value" "$test_root/no-such-tree"

# require_shareable_bundle: the two accepted shapes.
expect_pass "a report-only bundle" \
  require_shareable_bundle "$clean_bundle" "$canary_value"
expect_pass "a bundle with sanitized log tails" \
  require_shareable_bundle "$logged_bundle" "$canary_value"

# require_shareable_bundle: every leak and every malformed shape.
expect_fail "a plain canary" \
  "carries the canary" require_shareable_bundle "$leaky_plain" "$canary_value"
expect_fail "a plain canary in a log tail" \
  "carries the canary" require_shareable_bundle "$leaky_log" "$canary_value"
expect_fail "a lower-case hex canary" \
  "carries the canary" require_shareable_bundle "$leaky_hex" "$canary_value"
expect_fail "an upper-case hex canary" \
  "carries the canary" require_shareable_bundle "$leaky_upper_hex" "$canary_value"
expect_fail "an unexpected event stream" \
  "unexpected shareable" require_shareable_bundle "$leaky_file" "$canary_value"
expect_fail "an unexpected store copy" \
  "unexpected shareable" require_shareable_bundle "$leaky_store" "$canary_value"
expect_fail "an unexpected report field" \
  "expected" require_shareable_bundle "$leaky_field" "$canary_value"
expect_fail "an unexpected diagnostics field" \
  "expected" require_shareable_bundle "$nested_field" "$canary_value"
expect_fail "empty diagnostics" \
  "expected" require_shareable_bundle "$empty_diagnostics" "$canary_value"
expect_fail "an unknown error kind" \
  "names error kind" require_shareable_bundle "$unknown_kind" "$canary_value"
expect_fail "a report without a typed error" \
  "names error kind" require_shareable_bundle "$untyped_bundle" "$canary_value"
expect_fail "a report without its diagnostics" \
  "expected" require_shareable_bundle "$missing_field_bundle" "$canary_value"
expect_fail "a malformed report" \
  "Expecting value" require_shareable_bundle "$malformed_bundle" "$canary_value"
expect_fail "a bundle with no report" \
  "carries no failure.json" require_shareable_bundle "$empty_bundle" "$canary_value"
expect_fail "a linked bundle entry" \
  "is a symbolic link" require_shareable_bundle "$linked_bundle" "$canary_value"
expect_fail "a special bundle entry" \
  "is not a regular file" require_shareable_bundle "$fifo_bundle" "$canary_value"
if [[ "$(id -u)" -ne 0 ]]; then
  # Root bypasses directory permissions, so this negative control is only
  # meaningful for the unprivileged run the acceptance script also performs.
  expect_fail "an unreadable bundle directory" \
    "cannot read" require_shareable_bundle "$unreadable_bundle" "$canary_value"
fi
chmod 700 "$unreadable_bundle/logs"

# stream_canaries and environment_canaries: the canary set has to carry both the
# whole stream line and the per-run token, and both spellings of the recorded
# launch environment, or the bundle check silently loses reach.
events="$test_root/events.jsonl"
{
  printf '{"event": {"type": "workload_exited", "stdout_bytes": 15, "stderr_bytes": 0}}\n'
  printf '{"event": {"type": "workload_output", "stream": "stdout", "invocation": 1, "bytes": "%s"}}\n' \
    "$(printf 'ready version=1\nnetwork state=ok request=request-0001\n' | od -An -v -tx1 | tr -d ' \n')"
  printf '{"event": {"type": "workload_output", "stream": "stderr", "invocation": 1, "bytes": "%s"}}\n' \
    "$(printf 'ignored\n' | od -An -v -tx1 | tr -d ' \n')"
} >"$events"
mapfile -t extracted < <(stream_canaries "$events")
for expected in "ready version=1" "network state=ok request=request-0001" "request-0001"; do
  if ! printf '%s\n' "${extracted[@]}" | grep -F -x -- "$expected" >/dev/null; then
    echo "stream_canaries did not extract '$expected'" >&2
    exit 1
  fi
done
if printf '%s\n' "${extracted[@]}" | grep -F -x -- "ignored" >/dev/null; then
  echo "stream_canaries extracted a stderr line" >&2
  exit 1
fi
expect_fail "a stream without a recording" \
  "No such file" stream_canaries "$test_root/no-events.jsonl"
# A recording that carries no stdout must not read as an empty canary set: the
# acceptance script would otherwise check a bundle against nothing at all.
printf '{"event": {"type": "workload_exited", "stdout_bytes": 0, "stderr_bytes": 0}}\n' \
  >"$test_root/silent-events.jsonl"
expect_fail "a recording without stdout" \
  "recorded no workload stdout" stream_canaries "$test_root/silent-events.jsonl"

lock_run="$test_root/lock-run"
mkdir -p "$lock_run"
printf '{"workload": {"launch": {"environment": ["MODE=acceptance"]}}}\n' >"$lock_run/workload.lock"
empty_lock="$test_root/empty-lock"
mkdir -p "$empty_lock"
printf '{"workload": {"launch": {}}}\n' >"$empty_lock/workload.lock"
mapfile -t extracted < <(environment_canaries "$lock_run")
if [[ "${extracted[0]}" != "MODE=acceptance" || "${extracted[1]}" != "acceptance" ]]; then
  echo "environment_canaries did not extract the assignment and its value" >&2
  exit 1
fi
expect_fail "a lock without a launch environment" \
  "names no launch environment entry" environment_canaries "$test_root/empty-lock"
# jq can print a value and still fail on trailing input, so the assignment
# itself has to be checked rather than only its result.
truncated_lock="$test_root/truncated-lock"
mkdir -p "$truncated_lock"
{
  printf '{"workload": {"launch": {"environment": ["MODE=acceptance"]}}}\n'
  printf 'not json\n'
} >"$truncated_lock/workload.lock"
expect_fail "a lock jq cannot finish reading" \
  "cannot read the launch environment" environment_canaries "$truncated_lock"

# published_bundles: discovery has to report every published bundle and fail
# rather than return a partial list. A nested `find -exec` reports a failing
# child as an expression result, so the two steps are listed separately.
discovery_root="$test_root/discovery"
mkdir -p "$discovery_root/first/failures/bundle-a" \
  "$discovery_root/second/failures/bundle-b" \
  "$discovery_root/second/failures/bundle-c" \
  "$discovery_root/second/not-a-failure"
if ! discovered_list="$(published_bundles "$discovery_root")"; then
  echo "published_bundles failed on a readable tree" >&2
  exit 1
fi
mapfile -t discovered <<<"$discovered_list"
if [[ "${#discovered[@]}" -ne 3 ]]; then
  echo "published_bundles found ${#discovered[@]} bundles; expected 3" >&2
  printf '%s\n' "${discovered[@]}" >&2
  exit 1
fi
for expected in \
  "$discovery_root/first/failures/bundle-a" \
  "$discovery_root/second/failures/bundle-b" \
  "$discovery_root/second/failures/bundle-c"; do
  if ! printf '%s\n' "${discovered[@]}" | grep -F -x -- "$expected" >/dev/null; then
    echo "published_bundles did not list $expected" >&2
    exit 1
  fi
done
expect_fail "a bundle root that cannot be listed" \
  "could not be listed" published_bundles "$discovery_root" "$test_root/no-such-root"
# The second listing needs its own regression: both cases above fail during the
# recursive discovery, so a scoped `find` stub lets that step succeed, then
# emits partial bundle output and fails.
real_find="$(command -v find)"
stub_dir="$test_root/stub-bin"
mkdir -p "$stub_dir"
cat >"$stub_dir/find" <<EOF
#!/usr/bin/env bash
for argument in "\$@"; do
  if [[ "\$argument" == "-mindepth" ]]; then
    printf '%s\\n' "\$STUB_PARTIAL_BUNDLE"
    exit 1
  fi
done
exec "$real_find" "\$@"
EOF
chmod +x "$stub_dir/find"
partial_output="$test_root/partial-listing.txt"
if (PATH="$stub_dir:$PATH" STUB_PARTIAL_BUNDLE="$discovery_root/first/failures/bundle-a" \
  published_bundles "$discovery_root") >"$partial_output" 2>&1; then
  echo "expected a partial second listing to fail" >&2
  exit 1
fi
if ! grep -F "could not be listed" "$partial_output" >/dev/null; then
  echo "a partial second listing did not report its failure:" >&2
  cat "$partial_output" >&2
  exit 1
fi
if [[ "$(id -u)" -ne 0 ]]; then
  mkdir -p "$discovery_root/third/failures/hidden"
  chmod 000 "$discovery_root/third/failures"
  expect_fail "an unreadable failures directory" \
    "could not be listed" published_bundles "$discovery_root/third"
  chmod 700 "$discovery_root/third/failures"
fi

# require_canary_bundle: the canary recording's own bundle has to be one of the
# inspected bundles, or the classification check would silently test other
# bundles' results.
expect_pass "a canary bundle among the inspected bundles" \
  require_canary_bundle "$test_root/canary/failures" \
  "$clean_bundle" "$test_root/canary/failures/replay-attempt-1"
expect_fail "a canary bundle that was never published" \
  "no shareable bundle was published" require_canary_bundle "$test_root/canary/failures" \
  "$clean_bundle" "$logged_bundle"

# workload_measurement: a recorded stream is measured exactly, and a missing or
# malformed recording fails instead of printing an empty result.
measurement="$(workload_measurement "$events")"
if [[ "$measurement" != "15 0 1 1 0" ]]; then
  echo "expected the recorded stream to measure '15 0 1 1 0', found '$measurement'" >&2
  exit 1
fi
expect_fail "a missing event stream" \
  "No such file" workload_measurement "$test_root/no-events.jsonl"
printf 'not json\n' >"$test_root/malformed-events.jsonl"
expect_fail "a malformed event stream" \
  "Expecting value" workload_measurement "$test_root/malformed-events.jsonl"

# require_nonnegative_integers: accepted values, and the empty result a failed
# producer leaves behind.
expect_pass "five measurements" \
  require_nonnegative_integers "measurement" 551 0 6 4 2
expect_fail "a failed producer" \
  "no values were produced" require_nonnegative_integers "measurement" $(
    bash -c 'exit 1'
  )
expect_fail "an empty value" \
  "is not a nonnegative integer" require_nonnegative_integers "measurement" ""
expect_fail "a negative value" \
  "is not a nonnegative integer" require_nonnegative_integers "measurement" 1 -1
expect_fail "a non-numeric value" \
  "is not a nonnegative integer" require_nonnegative_integers "measurement" 1 unknown

printf 'RFD 3 phase 4 evidence check regression tests passed.\n'
