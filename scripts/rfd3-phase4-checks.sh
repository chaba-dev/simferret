#!/usr/bin/env bash
# RFD 3 Phase 4 evidence checks.
#
# The acceptance script and its regression harness share these checks, so the
# harness proves the same code the acceptance run relies on. Every check treats
# an unreadable artifact as a failure rather than as evidence of absence, and
# every canary is searched in both its plain and its serialized (hex) encoding,
# because the recorded workload stream is stored hex-encoded.
#
# This file is sourced; it must not run anything at load time.

python="${python:-${PYTHON:-python3}}"

# require_absent NAME NEEDLE PATH
#
# Fail unless every regular file below PATH is provably free of NEEDLE. A grep
# exit status of 1 is the only evidence of absence: a missing or unreadable
# tree (status 2) is an error, because a check that cannot read the artifact
# must never report a clean result.
require_absent() {
  local name="$1" needle="$2" path="$3" status=0
  grep -R -F -- "$needle" "$path" >/dev/null 2>&1 || status=$?
  case "$status" in
    0)
      printf "%s: '%s' must not appear under %s\n" "$name" "$needle" "$path" >&2
      return 1
      ;;
    1) return 0 ;;
    *)
      printf '%s: cannot inspect %s (grep exit %s)\n' "$name" "$path" "$status" >&2
      return 1
      ;;
  esac
}

# require_shareable_bundle BUNDLE CANARY...
#
# Fail unless BUNDLE is a shareable failure bundle: a `failure.json` with
# exactly the published report and diagnostics fields, optionally the sanitized
# diagnostic log tails, nothing else, and no canary in any file in either its
# plain or its hex encoding. A private run directory, store, event stream, or
# launch environment that reached the bundle fails the check. Traversal is
# strict: an unreadable, linked, or special entry is a failure rather than an
# artifact that was skipped, so the check can never certify a tree it did not
# read.
require_shareable_bundle() {
  local bundle="$1"
  shift
  "$python" - "$bundle" "$@" <<'PY'
import json
import os
import stat
import sys

bundle = sys.argv[1]
canaries = sys.argv[2:]
allowed = {"failure.json", "logs/qemu.log", "logs/serial.log"}
report_fields = {"version", "error_kind", "error", "diagnostics"}
# The published FailureReport and FailureDiagnostics structures. Every field is
# required and no other field is published, so a report that carries an
# unexpected nested value fails here even when its value is not a known canary.
diagnostic_fields = {
    "operation",
    "stage",
    "backend_mode",
    "fixture_mode",
    "network_status",
    "network",
    "fault_transitions",
    "traffic",
    "packet_counters",
}
traffic_fields = {"requests_attempted", "requests_succeeded", "requests_unavailable"}
counter_fields = {"available", "incoming", "outgoing", "reason"}
# run.rs maps io::ErrorKind onto this vocabulary.
error_kinds = {
    "watchdog",
    "invalid-data",
    "early-termination",
    "channel-failure",
    "not-found",
    "permission-denied",
    "infrastructure",
}


def fail(message):
    print(f"{bundle}: {message}", file=sys.stderr)
    raise SystemExit(1)


def is_nonnegative(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def require_fields(node, fields, what):
    if not isinstance(node, dict):
        fail(f"{what} is not an object")
    if set(node) != fields:
        fail(f"{what} names {sorted(node)}; expected {sorted(fields)}")
    return node


def validate_diagnostics(diagnostics):
    node = require_fields(diagnostics, diagnostic_fields, "diagnostics")
    for name in ["operation", "stage", "backend_mode", "fixture_mode", "network_status"]:
        if not isinstance(node[name], str) or not node[name]:
            fail(f"diagnostics.{name} is not a nonempty string")
    if node["network"] is not None and not isinstance(node["network"], dict):
        fail("diagnostics.network is neither null nor an object")
    if not isinstance(node["fault_transitions"], list):
        fail("diagnostics.fault_transitions is not a list")
    traffic = require_fields(node["traffic"], traffic_fields, "diagnostics.traffic")
    for name in sorted(traffic_fields):
        if not is_nonnegative(traffic[name]):
            fail(f"diagnostics.traffic.{name} is not a nonnegative integer")
    counters = require_fields(node["packet_counters"], counter_fields, "diagnostics.packet_counters")
    if not isinstance(counters["available"], bool):
        fail("diagnostics.packet_counters.available is not a boolean")
    for name in ["incoming", "outgoing"]:
        if counters[name] is not None and not is_nonnegative(counters[name]):
            fail(f"diagnostics.packet_counters.{name} is not null or a nonnegative integer")
    if not isinstance(counters["reason"], str) or not counters["reason"]:
        fail("diagnostics.packet_counters.reason is not a nonempty string")


present = set()
contents = []


def collect(directory, relative):
    try:
        entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
    except OSError as error:
        fail(f"cannot read {relative or '.'}: {error}")
    for entry in entries:
        path = f"{relative}/{entry.name}" if relative else entry.name
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError as error:
            fail(f"cannot stat {path}: {error}")
        mode = info.st_mode
        if stat.S_ISLNK(mode):
            fail(f"{path} is a symbolic link")
        if stat.S_ISDIR(mode):
            if path != "logs":
                fail(f"unexpected shareable directory {path}")
            collect(entry.path, path)
        elif stat.S_ISREG(mode):
            if path not in allowed:
                fail(f"unexpected shareable artifact {path}")
            try:
                with open(entry.path, "rb") as handle:
                    data = handle.read()
            except OSError as error:
                fail(f"cannot read {path}: {error}")
            present.add(path)
            contents.append((path, data))
        else:
            fail(f"{path} is not a regular file")


collect(bundle, "")
if "failure.json" not in present:
    fail("the bundle carries no failure.json")
report = json.loads(dict(contents)["failure.json"])
require_fields(report, report_fields, "failure.json")
if report["version"] != 1:
    fail(f"failure.json has version {report['version']!r}")
if report["error_kind"] not in error_kinds:
    fail(f"failure.json names error kind {report['error_kind']!r}")
if not isinstance(report["error"], str) or not report["error"]:
    fail("failure.json carries no error message")
validate_diagnostics(report["diagnostics"])

for canary in canaries:
    plain = canary.encode()
    for spelling in {plain, plain.hex().encode(), plain.hex().upper().encode()}:
        for relative, data in contents:
            if spelling in data:
                fail(f"{relative} carries the canary {canary!r} ({spelling[:96]!r})")
print(f"{bundle}: {len(present)} shareable artifact(s), {len(canaries)} canaries absent")
PY
}

# stream_canaries EVENTS.JSONL
#
# Print every distinct stdout line the recorded run produced, plus the tokens
# inside them. The streams are the private artifacts a shareable bundle must
# not carry, and a leak could quote a whole line or a single per-run token, in
# plain text or in the hex encoding the event stream uses. A recording that
# contains no stdout is an error rather than an empty canary set.
stream_canaries() {
  "$python" - "$1" <<'PY'
import json
import sys

lines = set()
streams = {}
with open(sys.argv[1], encoding="utf-8") as handle:
    for line in handle:
        event = json.loads(line)["event"]
        if event["type"] == "workload_output" and event["stream"] == "stdout":
            streams.setdefault(event["invocation"], bytearray()).extend(
                bytes.fromhex(event["bytes"])
            )
for data in streams.values():
    for line in bytes(data).split(b"\n"):
        if line:
            lines.add(line.decode())
if not lines:
    print(f"{sys.argv[1]} recorded no workload stdout", file=sys.stderr)
    raise SystemExit(1)
for line in sorted(lines):
    print(line)
    for token in line.replace("=", " ").split():
        # Only per-run identifiers are canaries on their own: a short or
        # word-only token (`unavailable`, `requests_`) also occurs in the
        # published schema and would reject a clean bundle.
        if len(token) >= 12 and any(c.isdigit() for c in token) and any(c.isalpha() for c in token):
            print(token)
PY
}

# environment_canaries RUN_DIRECTORY
#
# Print the recorded launch environment as the whole assignment and as the bare
# value, so a bundle that drops the `MODE=` prefix is still rejected.
environment_canaries() {
  local entry
  if ! entry="$(jq -r '.workload.launch.environment[0]' "$1/workload.lock")"; then
    printf 'cannot read the launch environment from %s\n' "$1/workload.lock" >&2
    return 1
  fi
  if [[ -z "$entry" || "$entry" != *=* ]]; then
    printf "the recorded run names no launch environment entry: '%s'\n" "$entry" >&2
    return 1
  fi
  printf '%s\n%s\n' "$entry" "${entry#*=}"
}

# require_canary_bundle BUNDLE_DIR BUNDLE...
#
# Fail unless at least one inspected bundle lives under BUNDLE_DIR, so a canary
# experiment that published nothing cannot pass on other bundles' results.
require_canary_bundle() {
  local directory="$1"
  shift
  local bundle
  for bundle in "$@"; do
    if [[ "$bundle" == "$directory/"* ]]; then
      return 0
    fi
  done
  printf 'no shareable bundle was published under %s\n' "$directory" >&2
  return 1
}

# workload_measurement EVENTS.JSONL
#
# Print "stdout_bytes stderr_bytes attempted succeeded unavailable" for one
# recorded run. The caller reads the five values and validates them; a producer
# that fails exits nonzero rather than printing an empty or partial line.
workload_measurement() {
  "$python" - "$1" <<'PY'
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
}

# require_nonnegative_integers NAME VALUE...
#
# Fail unless every value is a nonnegative decimal integer, so a measurement
# producer that fails or prints nothing can never be read as an empty result.
require_nonnegative_integers() {
  local name="$1"
  shift
  if [[ "$#" -eq 0 ]]; then
    printf '%s: no values were produced\n' "$name" >&2
    return 1
  fi
  local value
  for value in "$@"; do
    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
      printf "%s: '%s' is not a nonnegative integer\n" "$name" "$value" >&2
      return 1
    fi
  done
  return 0
}
