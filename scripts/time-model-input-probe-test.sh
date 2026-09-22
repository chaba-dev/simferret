#!/usr/bin/env bash
set -euo pipefail

# Regression tests for the host-input probe guest.
#
# The shell probe's measurement rests on properties of the guest loop that a
# harness double cannot check, so this test drives the real loop
# (`poc/time-model/input-probe.c`) through the stubs in
# `poc/time-model/input-probe-test.c`: the loop has no iteration limit, it
# reports progress while it waits, and it reports a line that arrives late as
# received rather than as a give-up. Restoring an iteration limit or a give-up
# report fails here, which is the defect the probe's `not-delivered` measurement
# would otherwise depend on.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
harness="$repo_root/poc/time-model/input-probe-test.c"
guest="$repo_root/poc/time-model/input-probe.c"
cc="${SIMFERRET_DYNAMIC_CC:-cc}"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/simferret-input-probe.XXXXXXXX")"
trap 'rm -rf "$test_root"' EXIT

test -f "$guest"
"$cc" -O2 -Wall -Wextra -Werror "$harness" -o "$test_root/input-probe-test"

run_scenario() { # $1 scenario, $2 output file
  "$test_root/input-probe-test" "$1" >"$2" 2>"$2.stderr"
}

no_give_up() { # $1 output file
  if grep -Fq 'GAVE-UP' "$1"; then
    echo "the guest reported giving up instead of polling until it was stopped:" >&2
    cat "$1" >&2
    exit 1
  fi
}

# A line that arrives after more than the 2000 polls the guest used to stop after
# is reported as received, and the guest powers off with it.
run_scenario late-delivery "$test_root/late-delivery.out"
grep -Fq 'WAITING iterations=2500' "$test_root/late-delivery.out"
grep -Fq 'GOT:hello-from-host iterations=2501' "$test_root/late-delivery.out"
grep -Fq 'rebooted=1' "$test_root/late-delivery.out"
no_give_up "$test_root/late-delivery.out"

# Polling has no bound below the host's wait: the guest is still polling when the
# stub ends the process.
run_scenario no-limit "$test_root/no-limit.out"
last_polls="$(grep -o 'WAITING iterations=[0-9]*' "$test_root/no-limit.out" |
  tail -1 | cut -d= -f2)"
test -n "$last_polls"
test "$last_polls" -gt 20000
no_give_up "$test_root/no-limit.out"

# A line that is already available is reported on the first poll, so the loop
# does not wait for a report interval before reading it.
run_scenario immediate "$test_root/immediate.out"
grep -Fq 'GOT:hello-from-host iterations=1' "$test_root/immediate.out"
grep -Fq 'rebooted=1' "$test_root/immediate.out"

printf 'Host-input probe guest regression tests passed.\n'
