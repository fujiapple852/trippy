# Trippy Agent Guidelines

This repository follows the guidance below when making changes.

## Development commands

- Format Rust code with `cargo fmt --all`.
- Lint with `cargo clippy --workspace --all-features --tests -- -Dwarnings`.
- Format non-Rust code with `dprint fmt`.
- When dependencies change, run `cargo deny check --hide-inclusion-graph` and check the MSRV with `cargo msrv verify --manifest-path crates/trippy/Cargo.toml`.
- If CLI arguments, man pages or shell completions change, update snapshots:
  `cargo test && cargo insta review`.
- When documentation is modified, run `cargo spellcheck check`.
- If the `Dockerfile` changes, build it locally using `docker build . -t trippy:dev`.

## Commit messages

- Use the Conventional Commits format:
  `<type>[optional scope]: <description>` where `<type>` is one of
  `feat`, `fix`, `chore`, `docs`, `style`, `refactor`, `test`, `build`, `ci`, or `revert`.
- For code changes set the scope to one of `core`, `dns`, `packet`, `privilege` or `tui`.
- Use backquotes for file names and code items in the description.
- Prefer small, focused commits. For larger changes, use multiple commits with clear messages.

## Recommendations

- Run tests, format (both Rust and non-Rust code) and lints before submitting a pull request and ensure all CI checks pass.
- Keep documentation and examples in sync with code changes.
- Use feature branches for separate tasks.
- Open issues and pull requests through GitHub for discussion and review.
- Always rebase your branch before when editing an open pull request to keep the history clean.
