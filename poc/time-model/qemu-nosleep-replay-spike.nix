# Spike expression: build the pinned QEMU with the no-sleep replay flush patch.
#
# This file is a feasibility spike for the RFD 4 Phase 0 record-mode blocker, not
# a project dependency. It is deliberately not wired into flake.nix and nothing
# in the repository builds it: carrying a patched QEMU is a decision the project
# has to make. Build it explicitly, for example:
#
#   rev=$(jq -r '.nodes.nixpkgs.locked.rev' flake.lock)
#   nix build --impure --no-link --print-out-paths --expr "
#     let pkgs = import (builtins.fetchTarball
#           \"https://github.com/NixOS/nixpkgs/archive/$rev.tar.gz\") {};
#     in import ./poc/time-model/qemu-nosleep-replay-spike.nix { inherit pkgs; }"
#
# and point the probes and suites at the result with
# QEMU_SYSTEM_X86_64=<store path>/bin/qemu-system-x86_64.
#
# The patch and its measured results are recorded in rfd/0004/EVIDENCE.adoc.
{ pkgs }:

pkgs.qemu.overrideAttrs (old: {
  patches = (old.patches or [ ]) ++ [ ./qemu-nosleep-replay-flush.patch ];
})
