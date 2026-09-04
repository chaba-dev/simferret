# Version control

- Use `.agents/dev jj` for repository version-control operations, including status, diffs, logs, and commits. It guarantees that the Nix-provided Jujutsu binary is available in non-login shells.
- Use Git only when an external integration specifically requires a Git command.
- This checkout is colocated with Git. Before a Git-only integration, point the intended JJ bookmark at the integration revision, run `.agents/dev jj git export`, and, when the integration requires an attached `HEAD`, run `git switch <branch>` immediately before it. Do not use Git staging, reset, or rebase commands.

# Commit messages

- Use Conventional Commit titles: `<type>(optional-scope): <description>`.
- Allowed types are `feat`, `fix`, `doc`, `docs`, `test`, `ci`, `refactor`, `perf`, `chore`, `revert`, `style`, and `security`.
- Use `docs(plan): ...` for planning-only changes.
- Use `!` or a `BREAKING CHANGE:` footer for breaking changes.
- Pull request titles are validated because squash merges use the title as the commit message. Keep the allowed types aligned with `.github/workflows/commits.yml`.

# Development

- Run repository tools through `.agents/dev` so they use the pinned Nix environment.
- Keep the Rust toolchain version and extensions centralized in `flake.nix`; do not add a separate `rust-toolchain.toml`.
- Run `nix flake check`, `cargo fetch --locked`, and shell syntax checks before committing toolchain changes.
- Add Cargo format, Clippy, and test checks to CI when the workspace gains its first crate.

# RFDs

- Follow the lifecycle and source conventions in `rfd/README.md`.
- Keep design documents in `rfd/NNNN/README.adoc` and implementation progress in the adjacent `IMPLEMENTATION.org` or `IMPLEMENTATION.md` file.
