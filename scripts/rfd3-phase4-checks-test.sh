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
    "diagnostics": {"operation": "replay", "stage": "preflight"},
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
cat >"$leaky_field/failure.json" <<EOF
{
  "version": 1,
  "error_kind": "infrastructure",
  "error": "raw closure raw/closure.json is missing",
  "environment": ["MODE=acceptance"],
  "diagnostics": {}
}
EOF

untyped_bundle="$test_root/untyped"
mkdir -p "$untyped_bundle"
cat >"$untyped_bundle/failure.json" <<'EOF'
{
  "version": 1,
  "error_kind": "",
  "error": "raw closure raw/closure.json is missing",
  "diagnostics": {}
}
EOF

missing_field_bundle="$test_root/missing-field"
mkdir -p "$missing_field_bundle"
cat >"$missing_field_bundle/failure.json" <<'EOF'
{
  "version": 1,
  "error_kind": "infrastructure",
  "error": "raw closure raw/closure.json is missing"
}
EOF

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
  "shareable bundles carry only" require_shareable_bundle "$leaky_file" "$canary_value"
expect_fail "an unexpected store copy" \
  "shareable bundles carry only" require_shareable_bundle "$leaky_store" "$canary_value"
expect_fail "an unexpected report field" \
  "expected" require_shareable_bundle "$leaky_field" "$canary_value"
expect_fail "a report without a typed error" \
  "names no typed error" require_shareable_bundle "$untyped_bundle" "$canary_value"
expect_fail "a report without its diagnostics" \
  "expected" require_shareable_bundle "$missing_field_bundle" "$canary_value"
expect_fail "a malformed report" \
  "Expecting value" require_shareable_bundle "$malformed_bundle" "$canary_value"
expect_fail "a bundle with no report" \
  "carries no failure.json" require_shareable_bundle "$empty_bundle" "$canary_value"

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

lock_run="$test_root/lock-run"
mkdir -p "$lock_run"
printf '{"workload": {"launch": {"environment": ["MODE=acceptance"]}}}\n' >"$lock_run/workload.lock"
mapfile -t extracted < <(environment_canaries "$lock_run")
if [[ "${extracted[0]}" != "MODE=acceptance" || "${extracted[1]}" != "acceptance" ]]; then
  echo "environment_canaries did not extract the assignment and its value" >&2
  exit 1
fi
expect_fail "a lock without a launch environment" \
  "names no launch environment entry" environment_canaries "$clean_bundle"

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
