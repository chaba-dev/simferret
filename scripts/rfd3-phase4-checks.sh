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
# exactly the published fields, optionally the sanitized diagnostic log tails,
# nothing else, and no canary in any file in either its plain or its hex
# encoding. A private run directory, store, event stream, or launch
# environment that reached the bundle fails the check.
require_shareable_bundle() {
  local bundle="$1"
  shift
  "$python" - "$bundle" "$@" <<'PY'
import json
import os
import sys

bundle = sys.argv[1]
canaries = sys.argv[2:]
allowed = {"failure.json", "logs/qemu.log", "logs/serial.log"}
fields = {"version", "error_kind", "error", "diagnostics"}


def fail(message):
    print(f"{bundle}: {message}", file=sys.stderr)
    raise SystemExit(1)


present = set()
contents = []
for root, directories, files in os.walk(bundle):
    directories.sort()
    for name in sorted(files):
        path = os.path.join(root, name)
        present.add(os.path.relpath(path, bundle))
        with open(path, "rb") as handle:
            contents.append((os.path.relpath(path, bundle), handle.read()))
unexpected = sorted(present - allowed)
if unexpected:
    fail(f"shareable bundles carry only {sorted(allowed)}, found {unexpected}")
if "failure.json" not in present:
    fail("the bundle carries no failure.json")
report = json.loads(dict(contents)["failure.json"])
if set(report) != fields:
    fail(f"failure.json names {sorted(report)}; expected {sorted(fields)}")
if report["version"] != 1:
    fail(f"failure.json has version {report['version']!r}")
if not isinstance(report["error_kind"], str) or not report["error_kind"]:
    fail("failure.json names no typed error")
if not isinstance(report["error"], str) or not report["error"]:
    fail("failure.json carries no error message")
if not isinstance(report["diagnostics"], dict):
    fail("failure.json carries no diagnostics object")

for canary in canaries:
    plain = canary.encode()
    for spelling in {plain, plain.hex().encode(), plain.hex().upper().encode()}:
        for relative, data in contents:
            if spelling in data:
                fail(f"{relative} carries the canary {canary!r} ({spelling[:96]!r})")
print(f"{bundle}: {len(present)} shareable artifact(s), {len(canaries)} canaries absent")
PY
}

# stream_canaries EVENTS.JSONL...
#
# Print every distinct stdout line the recorded runs produced, plus the tokens
# inside them. The streams are the private artifacts a shareable bundle must
# not carry, and a leak could quote a whole line or a single per-run token, in
# plain text or in the hex encoding the event stream uses.
stream_canaries() {
  "$python" - "$@" <<'PY'
import json
import sys

lines = set()
for path in sys.argv[1:]:
    streams = {}
    with open(path, encoding="utf-8") as handle:
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
  entry="$(jq -r '.workload.launch.environment[0]' "$1/workload.lock")"
  if [[ -z "$entry" || "$entry" != *=* ]]; then
    printf "the recorded run names no launch environment entry: '%s'\n" "$entry" >&2
    return 1
  fi
  printf '%s\n%s\n' "$entry" "${entry#*=}"
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
