# Contributing to Trippy

Contributions to Trippy are most welcome, whether you wish to report a bug, submit a fix or feature or request a
feature.

Raise issues and feature requests in the GitHub [issue tracker](https://github.com/fujiapple852/trippy/issues) and raise
all changes as GitHub [pull requests](https://github.com/fujiapple852/trippy/pulls).

## Release instructions

Instructions for releasing a new `0.xx.0` version of Trippy.

Many distribution packages are managed by external maintainers, however the following are managed by the Trippy
maintainers:

- GitHub Releases
- Crates.io
- Docker
- Snapcraft
- Winget
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

### Github Releases

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
cargo publish trippy-dns
cargo publish trippy-packet
cargo publish trippy-privilege
cargo publish trippy-tui
cargo publish trippy
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

### Winget

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