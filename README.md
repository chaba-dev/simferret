# SimFerret

SimFerret is an experimental deterministic simulation platform for finding and
reproducing failures in unmodified software.

The project is currently in design and proof-of-concept development. See the
[Requests for Discussion](rfd/README.adoc) for architecture decisions and
implementation plans.

## Development

The Nix flake provides the pinned Rust toolchain and Jujutsu. On an x86-64 Linux
Amp orb, run `.agents/setup` once to install Nix when needed and initialize a
colocated Jujutsu repository. On other Linux architectures and macOS, install
Nix separately, then enter the environment with `nix develop`.

Run repository commands through the development environment:

```shell
nix flake check
.agents/dev cargo fmt --all -- --check
.agents/dev cargo clippy --locked --workspace --all-targets --all-features -- --deny warnings
.agents/dev cargo test --locked --workspace --all-targets --all-features
bash -n .agents/dev .agents/setup
.agents/dev jj status
```
