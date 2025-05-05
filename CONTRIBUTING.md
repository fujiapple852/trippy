# Contributing to Trippy

Contributions to Trippy are most welcome, whether you wish to report a bug, request a feature, or contribute code.

Raise issues and feature requests in the GitHub [issue tracker](https://github.com/fujiapple852/trippy/issues) and raise
all changes as GitHub [pull requests](https://github.com/fujiapple852/trippy/pulls).

## Development

This section describes how to set up a development environment and the development process for Trippy.

### Development tools

The following tools are needed for local development. Note that most of the following are checked during CI, so it is
recommended to run these checks locally before submitting a pull request.

#### Rust

Trippy is written in [`Rust`](https://www.rust-lang.org/tools/install) and requires the Rust toolchain to build and run.
As well as default components such as `cargo`, you will need `rustfmt` and `clippy` for code formatting and linting.

> [!NOTE]
> Trippy uses the `stable` toolchain.

To install `rustfmt` and `clippy`:

```shell
rustup component add rustfmt clippy
```

To format the Rust code:

```shell
cargo fmt --all
```

> [!NOTE]
> Trippy uses default settings for code formatting.

To lint the Rust code:

```shell
cargo clippy --workspace --all-features --tests -- -Dwarnings
```

> [!NOTE]
> Clippy configuration is defined at the workspace level in the root `Cargo.toml` file.

#### Cargo `deny`

If you add or update dependencies, you must run Cargo [`deny`](https://github.com/EmbarkStudios/cargo-deny) to ensure
that the licenses of the dependencies are acceptable.

```shell
cargo deny check --hide-inclusion-graph
```

The allowed licenses are defined in the `deny.toml` file.

#### Cargo `insta`

If you make changes that impact the command line interface arguments, manual pages or shell completions, you must update
the testing snapshots using Cargo [`insta`](https://insta.rs).

After making your changes, run `cargo test` to generate the new snapshots followed by `cargo insta` to review and update
the snapshots.

```shell
cargo test && cargo insta review
```

#### Cargo `spelling`

If you make changes to code documentation, you must run Cargo [`spellcheck`](https://github.com/drahnr/cargo-spellcheck)
to ensure they are free from misspellings and typos.

To check the spelling:

```shell
cargo spellcheck check
```

The configuration for `spellcheck` is defined in the `.config/spellcheck.toml` file and the custom dictionary is defined
in the `.config/trippy.dic` file.

#### Cargo `msrv`

If you add or update dependencies, you should use the Cargo [msrv](https://github.com/foresterre/cargo-msrv) tool to
check the Minimum Supported Rust Version (MSRV) to ensure that the new dependencies are compatible with the current
MSRV.

To check the MSRV of the `trippy` crate:

```shell
cargo msrv verify --manifest-path crates/trippy/Cargo.toml-- cargo check
```

#### `dprint`

The [`dprint`](https://dprint.dev/) tool is needed to ensure consistent formatting of the non-Rust portions of the
codebase and docs.

To format the non-Rust code:

```shell
dprint fmt
```

The configuration for `dprint` is defined in the `dprint.json` file.

#### Docker

If you make changes to the `Dockerfile`, you should build the Docker image locally to ensure it builds correctly.

```shell
docker build . -t trippy:dev
```

> [!NOTE]
> If you add new files that are required at build time then you must update the `Dockerfile` to include them explicitly.

### Development process

This section describes the development process for Trippy.

#### Conventional commits

All commit messages should follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) format.

The commit message should be structured as follows:

```text
<type>[optional scope]: <description>
```

Where `type` is one of the following:

- `feat`: A new feature
- `fix`: A bug fix
- `chore`: Build process, dependency and version updates
- `docs`: Documentation only changes
- `style`: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)
- `refactor`: A code change that neither fixes a bug nor adds a feature
- `test`: Adding missing tests or correcting existing tests
- `build`: Changes that affect the build system or external dependencies
- `ci`: Changes to our CI configuration files and scripts
- `revert`: Reverts a previous commit

The `scope` is optional and, if given, should be the name of the crate being modified, currently one of `core`,
`packet`, `dns`, `privilege`, `tui` or `trippy`.

> [!NOTE]
> Small do-one-things commits are preferred over large do-many-things commits. This makes changes easier to review and
> revert if necessary. For example, if you are adding a new feature and fixing a bug, it is better to create two
> separate commits.

## Releases

Instructions for releasing a new `0.xx.0` version of Trippy.

Many distribution packages are managed by external maintainers, however the following are managed by the Trippy
maintainers:

- GitHub Releases
- Crates.io
- Docker
- Snapcraft
- WinGet
- Ubuntu PPA

### Prerequisites

- Check the MSRV (Minimum Supported Rust Version) in the `trippy` crate `Cargo.toml` is still correct.

> [!NOTE]
> The MSRV should typically be the version from around 1 year before the current date to maximise compatibility.

- Update all dependencies to the latest SemVer compatible versions

> [!NOTE]
> Some distributions may not support the latest versions of all dependencies, so be conservative with updates.

- Record and add an `assets/0.xx.0/demo.gif` for the new version
- Update the `README.md` with details of the features in the new version
- Update the `CHANGELOG.md` for the new version
- Update the `RELEASES.md` for the new version
- Update the version to `0.xx.0` in `Cargo.toml`, `snap/snapcraft.yaml` & `ubuntu-ppa/release.sh`

### Testing

Trippy is tested extensively in CI on Linux, Windows and macOS for every pull request. However, it is recommended to
test the release binaries on all platforms before release.

### GitHub Releases

- Tag the release with the version number `0.xx.0` and push the tag to GitHub:

```shell
git tag 0.xx.0
git push origin tag 0.xx.0
```

This will trigger the GitHub Actions workflow to build the release binaries and publish them to the GitHub release page.

- Edit GitHub release page and copy the relevant sections from `RELEASES.md` and `CHANGELOG.md`. Refer to previous
  releases for the format.

### Crates.io

- Publish all crates to crates.io (in order):

```shell
cargo publish -p trippy-dns
cargo publish -p trippy-packet
cargo publish -p trippy-privilege
cargo publish -p trippy-core
cargo publish -p trippy-tui
cargo publish -p trippy
```

### Docker

From the repository root directory:

```shell
docker build . -t fujiapple/trippy:0.xx.0 -t fujiapple/trippy:latest
docker push fujiapple/trippy:0.xx.0
docker push fujiapple/trippy:latest
```

### Snapcraft

- Promote the first `0.xx.0` build to the `latest/stable` channel from the
  Snapcraft [releases](https://snapcraft.io/trippy/releases) page

### WinGet

- Download the latest release Windows `zip` from
  the [GitHub releases page](https://github.com/fujiapple852/trippy/releases/latest)
- Determine the SHA256 checksum of the release:

```shell
shasum -a 256 trippy-0.xx.0-x86_64-pc-windows-msvc.zip
```

- Update the `winget` [fork](https://github.com/fujiapple852/winget-pkgs) to the latest upstream
- Checkout the fork and create a branch called `fujiapple852-trippy-0.xx.0`
- Go to the Trippy directory

```shell
cd winget-pkgs/manifests/f/FujiApple/Trippy
```

- Copy the previous `0.yy.0` directory to a new directory for the new `0.xx.0` version
- Update the `PackageVersion`, `ReleaseDate` and update all paths to the new version
- Update the `InstallerSha256` with the checksum from the previous step
- Update the release notes from [CHANGELOG.md](https://github.com/fujiapple852/trippy/blob/master/CHANGELOG.md)
- Commit the changes with message:

```text
update fujiapple852/trippy to 0.xx.0
```

- Push the branch to the fork and create a pull request against the upstream `winget-pkgs` repository

### Ubuntu PPA

See the Ubuntu PPA [README.md](https://github.com/fujiapple852/trippy/blob/master/ubuntu-ppa/README.md)

## Help wanted

There are several the issues tagged
as [help wanted](https://github.com/fujiapple852/trippy/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22) in the
GitHub issue tracker for which I would be especially grateful for assistance.

## License

This project is distributed under the terms of the Apache License (Version 2.0).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in time by you, as defined
in the Apache-2.0 license, shall be licensed as above, without any additional terms or conditions.
