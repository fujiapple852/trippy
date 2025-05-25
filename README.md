<p align="center">
  <img src="https://raw.githubusercontent.com/fujiapple852/trippy/master/docs/src/assets/Trippy-Vertical-DarkMode.svg#gh-dark-mode-only" width="300">
  <img src="https://raw.githubusercontent.com/fujiapple852/trippy/master/docs/src/assets/Trippy-Vertical.svg#gh-light-mode-only" width="300"><br>
  <br>
  <a href="https://github.com/fujiapple852/trippy/actions/workflows/ci.yml">
    <img src="https://github.com/fujiapple852/trippy/actions/workflows/ci.yml/badge.svg?branch=master"></a>
  <a href="https://crates.io/crates/trippy/0.13.0">
    <img src="https://img.shields.io/crates/v/trippy.svg"></a>
  <a href="https://repology.org/project/trippy/versions">
    <img src="https://repology.org/badge/tiny-repos/trippy.svg"></a>
  <a href="https://trippy.zulipchat.com">
    <img src="https://img.shields.io/badge/zulip-join_chat-brightgreen.svg"></a>
  <a href="https://matrix.to/#/#trippy-dev:matrix.org">
    <img src="https://img.shields.io/badge/matrix/trippy-dev:matrix.org-blue"></a>
  <br>
  <br>
  Trippy combines the functionality of traceroute and ping and is designed to assist with the analysis of networking
issues.
</p>

<img src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.12.0/demo.gif" alt="trippy"/>

## Quick Start

See the [getting started](https://trippy.rs/start/getting-started) guide.

### Install

Trippy runs on Linux, BSD, macOS, and Windows. It can be installed from most package managers, precompiled binaries, or
source.

For example, to install Trippy from `cargo`:

```shell
cargo install trippy --locked
```

<details>

<summary>All package managers</summary>

### Cargo

[![Crates.io](https://img.shields.io/crates/v/trippy)](https://crates.io/crates/trippy/0.13.0)

```shell
cargo install trippy --locked
```

### APT (Debian)

[![Debian 13 package](https://repology.org/badge/version-for-repo/debian_13/trippy.svg)](https://tracker.debian.org/pkg/trippy)

```shell
apt install trippy
```

> ⓘ Note:
>
> Only available for Debian 13 (`trixie`) and later.

### PPA (Ubuntu)

[![Ubuntu PPA](https://img.shields.io/badge/Ubuntu%20PPA-0.13.0-brightgreen)](https://launchpad.net/~fujiapple/+archive/ubuntu/trippy/+packages)

```shell
add-apt-repository ppa:fujiapple/trippy
apt update && apt install trippy
```

> ⓘ Note:
>
> Only available for Ubuntu 24.04 (`Noble`) and 22.04 (`Jammy`).

### Snap (Linux)

[![trippy](https://snapcraft.io/trippy/badge.svg)](https://snapcraft.io/trippy)

```shell
snap install trippy
```

### Homebrew (macOS)

[![Homebrew package](https://repology.org/badge/version-for-repo/homebrew/trippy.svg)](https://formulae.brew.sh/formula/trippy)

```shell
brew install trippy
```

### WinGet (Windows)

[![winget package](https://img.shields.io/badge/WinGet-0.13.0-brightgreen)](https://github.com/microsoft/winget-pkgs/tree/master/manifests/f/FujiApple/Trippy/0.13.0)

```shell
winget install trippy
```

### Scoop (Windows)

[![Scoop package](https://img.shields.io/scoop/v/trippy?style=flat&labelColor=5c5c5c&color=%234dc71f)](https://github.com/ScoopInstaller/Main/blob/master/bucket/trippy.json)

```shell
scoop install trippy
```

### Chocolatey (Windows)

[![Chocolatey package](https://repology.org/badge/version-for-repo/chocolatey/trippy.svg)](https://community.chocolatey.org/packages/trippy)

```shell
choco install trippy
```

### NetBSD

[![pkgsrc current package](https://repology.org/badge/version-for-repo/pkgsrc_current/trippy.svg)](https://pkgsrc.se/net/trippy)

```shell
pkgin install trippy
```

### FreeBSD

[![FreeBSD port](https://repology.org/badge/version-for-repo/freebsd/trippy.svg)](https://www.freshports.org/net/trippy/)

```shell
pkg install trippy
```

### OpenBSD

[![OpenBSD port](https://repology.org/badge/version-for-repo/openbsd/trippy.svg)](https://openports.pl/path/net/trippy)

```shell
pkg_add trippy
```

### Arch Linux

[![Arch package](https://repology.org/badge/version-for-repo/arch/trippy.svg)](https://archlinux.org/packages/extra/x86_64/trippy)

```shell
pacman -S trippy
```

### Gentoo Linux

[![Gentoo package](https://repology.org/badge/version-for-repo/gentoo/trippy.svg)](https://packages.gentoo.org/packages/net-analyzer/trippy)

```shell
emerge -av net-analyzer/trippy
```

### Void Linux

[![Void Linux x86_64 package](https://repology.org/badge/version-for-repo/void_x86_64/trippy.svg)](https://github.com/void-linux/void-packages/tree/master/srcpkgs/trippy)

```shell
xbps-install -S trippy
```

### ALT Sisyphus

[![ALT Sisyphus package](https://repology.org/badge/version-for-repo/altsisyphus/trippy.svg)](https://packages.altlinux.org/en/sisyphus/srpms/trippy/)

```shell
apt-get install trippy
```

### Chimera Linux

[![Chimera Linux package](https://repology.org/badge/version-for-repo/chimera/trippy.svg)](https://github.com/chimera-linux/cports/tree/master/user/trippy)

```shell
apk add trippy
```

### Nix

[![nixpkgs unstable package](https://repology.org/badge/version-for-repo/nix_unstable/trippy.svg)](https://github.com/NixOS/nixpkgs/blob/master/pkgs/by-name/tr/trippy/package.nix)

```shell
nix-env -iA trippy
```

### Docker

[![Docker Image Version (latest by date)](https://img.shields.io/docker/v/fujiapple/trippy)](https://hub.docker.com/r/fujiapple/trippy/)

```shell
docker run -it fujiapple/trippy
```

### All Repositories

[![Packaging status](https://repology.org/badge/vertical-allrepos/trippy.svg)](https://repology.org/project/trippy/versions)

</details>

See the [installation](https://trippy.rs/start/installation) guide for details of how to install Trippy on your system.

### Run

To run a basic trace to `example.com` with default settings, use the following command:

```shell
sudo trip example.com
```

See the [usage examples](https://trippy.rs/guides/usage) and [CLI reference](https://trippy.rs/reference/cli) for
details of how to use Trippy. To use Trippy without elevated privileges, see
the [privileges](https://trippy.rs/guides/privileges) guide.

## Documentation

Full documentation is available at [trippy.rs](https://trippy.rs).

<details>

<summary>documentation links</summary>

## Getting Started

See the [Getting Started](https://trippy.rs/start/getting-started/) guide.

## Features

See the [Features](https://trippy.rs/start/features/) list.

## Distributions

See the [Distributions](https://trippy.rs/start/installation/) list.

## Privileges

See the [Privileges](https://trippy.rs/guides/privileges/) guide.

## Usage Examples

See the [Usage Examples](https://trippy.rs/guides/usage/).

## Command Reference

See the [Command Reference](https://trippy.rs/reference/cli/).

## Theme Reference

See the [Theme Reference](https://trippy.rs/reference/theme/).

## Column Reference

See the [Column Reference](https://trippy.rs/reference/column/).

## Configuration Reference

See the [Configuration Reference](https://trippy.rs/reference/configuration/).

## Locale Reference

See the [Locale Reference](https://trippy.rs/reference/locale/).

## Versions

See the [Version Reference](https://trippy.rs/reference/version/).

## Frequently Asked Questions

### Why does Trippy show "Awaiting data..."?

See the [Awaiting Data](https://trippy.rs/guides/faq/) guide.

<a name="windows-defender"></a>

### How do I allow incoming ICMP traffic in the Windows Defender firewall?

See the [Windows Defender Firewall](https://trippy.rs/guides/windows_firewall/) guide.

### What are the recommended settings for Trippy?

See the [Recommended Tracing Settings](https://trippy.rs/guides/recommendation/) guide.

</details>

## Acknowledgements

Trippy is made possible by [ratatui](https://github.com/ratatui-org/ratatui) (
formerly [tui-rs](https://github.com/fdehau/tui-rs)),
[crossterm](https://github.com/crossterm-rs/crossterm) as well
as [several](https://github.com/fujiapple852/trippy/blob/master/Cargo.toml) foundational Rust libraries.

Trippy draws heavily from [mtr](https://github.com/traviscross/mtr) and also incorporates ideas
from both [libparistraceroute](https://github.com/libparistraceroute/libparistraceroute)
& [Dublin Traceroute](https://github.com/insomniacslk/dublin-traceroute).

The Trippy networking code is inspired by [pnet](https://github.com/libpnet/libpnet) and some elements of that codebase
are incorporated in Trippy.

The [AS][autonomous_system] data is retrieved from
the [IP to ASN Mapping Service](https://team-cymru.com/community-services/ip-asn-mapping/#dns) provided
by [Team Cymru](https://team-cymru.com).

The [trippy.cli.rs](https://trippy.cli.rs) CNAME hosting is provided by [cli.rs](https://cli.rs).

The Trippy chat room is sponsored by [Zulip](https://zulip.com).

Trippy logo designed by [Harun Ocaksiz Design](https://www.instagram.com/harunocaksiz).

## License

This project is distributed under the terms of the Apache License (Version 2.0).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in time by you, as defined
in the Apache-2.0 license, shall be licensed as above, without any additional terms or conditions.

See [LICENSE](LICENSE) for details.

Copyright 2022 [Trippy Contributors](https://github.com/fujiapple852/trippy/graphs/contributors)

[autonomous_system]: https://en.wikipedia.org/wiki/Autonomous_system_(Internet)
