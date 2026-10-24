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
- Before committing, run `nix --extra-experimental-features 'nix-command flakes' flake check`, Cargo format, Clippy with warnings denied, tests, and shell syntax checks.

# RFDs

- RFDs are published at https://chaba-rfds.pages.dev. Their source lives in the shared chaba-dev/rfds repository (https://github.com/chaba-dev/rfds), which is private to the organization; follow its lifecycle and source conventions there, not in this repository.
