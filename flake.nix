{
  description = "SimFerret deterministic simulation testing platform";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        rustToolchain = pkgs.rust-bin.stable."1.98.1".default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
            "clippy"
            "rustfmt"
          ];
          targets = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
            "x86_64-unknown-linux-musl"
          ];
        };
        # The pinned emulator, built from the repository's patch rather than from
        # a second expression: `sleep=off` needs the replay flush the patch
        # restores, and only the system target the project runs is built.
        # `rfd/0004/README.adoc` records why it is carried and what dropping it
        # means.
        qemuPinned = (pkgs.qemu.override {
          hostCpuTargets = [ "x86_64-softmmu" ];
          enableDocs = false;
        }).overrideAttrs (previous: {
          patches = (previous.patches or [ ]) ++ [
            ./poc/time-model/qemu-nosleep-replay-flush.patch
          ];
        });
      in {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [
            rustToolchain
            pkgs.jujutsu
            pkgs.jq
            pkgs.python3
          ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
            pkgs.cpio
            pkgs.gzip
            pkgs.pkgsStatic.stdenv.cc
            qemuPinned
            pkgs.xz
          ];
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
          shellHook = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
            export SIMFERRET_BUSYBOX="${pkgs.pkgsStatic.busybox}/bin/busybox"
            export SIMFERRET_KERNEL="${pkgs.linuxPackages.kernel}/bzImage"
            export SIMFERRET_KERNEL_MODULES="${pkgs.linuxPackages.kernel.modules}"
          '';
        };

        # Jobs that do not run QEMU use this shell, so they do not build the
        # pinned emulator. The QEMU job uses the default shell.
        devShells.light = pkgs.mkShell {
          nativeBuildInputs = [
            rustToolchain
            pkgs.jujutsu
            pkgs.jq
            pkgs.python3
          ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
            pkgs.cpio
            pkgs.gzip
            pkgs.pkgsStatic.stdenv.cc
            pkgs.xz
          ];
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
          shellHook = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
            export SIMFERRET_BUSYBOX="${pkgs.pkgsStatic.busybox}/bin/busybox"
            export SIMFERRET_KERNEL="${pkgs.linuxPackages.kernel}/bzImage"
            export SIMFERRET_KERNEL_MODULES="${pkgs.linuxPackages.kernel.modules}"
          '';
        };
      });
}
