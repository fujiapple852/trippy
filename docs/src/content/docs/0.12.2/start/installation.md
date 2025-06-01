---
title: Installation
description: Install Trippy on your platform.
sidebar:
  order: 2
slug: 0.12.2/start/installation
---

The following sections provide instructions for installing Trippy on your platform.

Trippy runs on Linux, BSD, macOS, and Windows. It can be installed from most common package managers, precompiled
binaries, or source.

## Distributions

Trippy is available for a variety of platforms and package managers.

### Cargo

[![Crates.io](https://img.shields.io/crates/v/trippy)](https://crates.io/crates/trippy/0.12.2)

```shell
cargo install trippy --locked
```

### APT (Debian)

[![Debian 13 package](https://repology.org/badge/version-for-repo/debian_13/trippy.svg)](https://tracker.debian.org/pkg/trippy)

```shell
apt install trippy
```

:::note
Only available for Debian 13 (`trixie`) and later.
:::

### PPA (Ubuntu)

[![Ubuntu PPA](https://img.shields.io/badge/Ubuntu%20PPA-0.12.2-brightgreen)](https://launchpad.net/~fujiapple/+archive/ubuntu/trippy/+packages)

```shell
add-apt-repository ppa:fujiapple/trippy
apt update && apt install trippy
```

:::note
Only available for Ubuntu 24.04 (`Noble`) and 22.04 (`Jammy`).
:::

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

[![winget package](https://img.shields.io/badge/WinGet-0.12.2-brightgreen)](https://github.com/microsoft/winget-pkgs/tree/master/manifests/f/FujiApple/Trippy/0.12.2)

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

## Downloads

Download the latest release for your platform.

| OS      | Arch      | Env          | Current (0.12.2)                                                                                                              | Previous (0.11.0)                                                                                                             | Previous (0.10.0)                                                                                                             |
| ------- | --------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Linux   | `x86_64`  | `gnu`        | [0.12.2](https://github.com/fujiapple852/trippy/releases/download/0.12.2/trippy-0.12.2-x86_64-unknown-linux-gnu.tar.gz)       | [0.11.0](https://github.com/fujiapple852/trippy/releases/download/0.11.0/trippy-0.11.0-x86_64-unknown-linux-gnu.tar.gz)       | [0.10.0](https://github.com/fujiapple852/trippy/releases/download/0.10.0/trippy-0.10.0-x86_64-unknown-linux-gnu.tar.gz)       |
| Linux   | `x86_64`  | `musl`       | [0.12.2](https://github.com/fujiapple852/trippy/releases/download/0.12.2/trippy-0.12.2-x86_64-unknown-linux-musl.tar.gz)      | [0.11.0](https://github.com/fujiapple852/trippy/releases/download/0.11.0/trippy-0.11.0-x86_64-unknown-linux-musl.tar.gz)      | [0.10.0](https://github.com/fujiapple852/trippy/releases/download/0.10.0/trippy-0.10.0-x86_64-unknown-linux-musl.tar.gz)      |
| Linux   | `aarch64` | `gnu`        | [0.12.2](https://github.com/fujiapple852/trippy/releases/download/0.12.2/trippy-0.12.2-aarch64-unknown-linux-gnu.tar.gz)      | [0.11.0](https://github.com/fujiapple852/trippy/releases/download/0.11.0/trippy-0.11.0-aarch64-unknown-linux-gnu.tar.gz)      | [0.10.0](https://github.com/fujiapple852/trippy/releases/download/0.10.0/trippy-0.10.0-aarch64-unknown-linux-gnu.tar.gz)      |
| Linux   | `aarch64` | `musl`       | [0.12.2](https://github.com/fujiapple852/trippy/releases/download/0.12.2/trippy-0.12.2-aarch64-unknown-linux-musl.tar.gz)     | [0.11.0](https://github.com/fujiapple852/trippy/releases/download/0.11.0/trippy-0.11.0-aarch64-unknown-linux-musl.tar.gz)     | [0.10.0](https://github.com/fujiapple852/trippy/releases/download/0.10.0/trippy-0.10.0-aarch64-unknown-linux-musl.tar.gz)     |
| Linux   | `arm7`    | `gnueabihf`  | [0.12.2](https://github.com/fujiapple852/trippy/releases/download/0.12.2/trippy-0.12.2-armv7-unknown-linux-gnueabihf.tar.gz)  | [0.11.0](https://github.com/fujiapple852/trippy/releases/download/0.11.0/trippy-0.11.0-armv7-unknown-linux-gnueabihf.tar.gz)  | [0.10.0](https://github.com/fujiapple852/trippy/releases/download/0.10.0/trippy-0.10.0-armv7-unknown-linux-gnueabihf.tar.gz)  |
| Linux   | `arm7`    | `musleabi`   | [0.12.2](https://github.com/fujiapple852/trippy/releases/download/0.12.2/trippy-0.12.2-armv7-unknown-linux-musleabi.tar.gz)   | [0.11.0](https://github.com/fujiapple852/trippy/releases/download/0.11.0/trippy-0.11.0-armv7-unknown-linux-musleabi.tar.gz)   | [0.10.0](https://github.com/fujiapple852/trippy/releases/download/0.10.0/trippy-0.10.0-armv7-unknown-linux-musleabi.tar.gz)   |
| Linux   | `arm7`    | `musleabihf` | [0.12.2](https://github.com/fujiapple852/trippy/releases/download/0.12.2/trippy-0.12.2-armv7-unknown-linux-musleabihf.tar.gz) | [0.11.0](https://github.com/fujiapple852/trippy/releases/download/0.11.0/trippy-0.11.0-armv7-unknown-linux-musleabihf.tar.gz) | [0.10.0](https://github.com/fujiapple852/trippy/releases/download/0.10.0/trippy-0.10.0-armv7-unknown-linux-musleabihf.tar.gz) |
| macOS   | `x86_64`  | `darwin`     | [0.12.2](https://github.com/fujiapple852/trippy/releases/download/0.12.2/trippy-0.12.2-x86_64-apple-darwin.tar.gz)            | [0.11.0](https://github.com/fujiapple852/trippy/releases/download/0.11.0/trippy-0.11.0-x86_64-apple-darwin.tar.gz)            | [0.10.0](https://github.com/fujiapple852/trippy/releases/download/0.10.0/trippy-0.10.0-x86_64-apple-darwin.tar.gz)            |
| macOS   | `aarch64` | `darwin`     | [0.12.2](https://github.com/fujiapple852/trippy/releases/download/0.12.2/trippy-0.12.2-aarch64-apple-darwin.tar.gz)           | [0.11.0](https://github.com/fujiapple852/trippy/releases/download/0.11.0/trippy-0.11.0-aarch64-apple-darwin.tar.gz)           | [0.10.0](https://github.com/fujiapple852/trippy/releases/download/0.10.0/trippy-0.10.0-aarch64-apple-darwin.tar.gz)           |
| Windows | `x86_64`  | `msvc`       | [0.12.2](https://github.com/fujiapple852/trippy/releases/download/0.12.2/trippy-0.12.2-x86_64-pc-windows-msvc.zip)            | [0.11.0](https://github.com/fujiapple852/trippy/releases/download/0.11.0/trippy-0.11.0-x86_64-pc-windows-msvc.zip)            | [0.10.0](https://github.com/fujiapple852/trippy/releases/download/0.10.0/trippy-0.10.0-x86_64-pc-windows-msvc.zip)            |
| Windows | `x86_64`  | `gnu`        | [0.12.2](https://github.com/fujiapple852/trippy/releases/download/0.12.2/trippy-0.12.2-x86_64-pc-windows-gnu.zip)             | [0.11.0](https://github.com/fujiapple852/trippy/releases/download/0.11.0/trippy-0.11.0-x86_64-pc-windows-gnu.zip)             | [0.10.0](https://github.com/fujiapple852/trippy/releases/download/0.10.0/trippy-0.10.0-x86_64-pc-windows-gnu.zip)             |
| Windows | `aarch64` | `msvc`       | [0.12.2](https://github.com/fujiapple852/trippy/releases/download/0.12.2/trippy-0.12.2-aarch64-pc-windows-msvc.zip)           | [0.11.0](https://github.com/fujiapple852/trippy/releases/download/0.11.0/trippy-0.11.0-aarch64-pc-windows-msvc.zip)           | [0.10.0](https://github.com/fujiapple852/trippy/releases/download/0.10.0/trippy-0.10.0-aarch64-pc-windows-msvc.zip)           |
| FreeBSD | `x86_64`  | n/a          | [0.12.2](https://github.com/fujiapple852/trippy/releases/download/0.12.2/trippy-0.12.2-x86_64-unknown-freebsd.tar.gz)         | [0.11.0](https://github.com/fujiapple852/trippy/releases/download/0.11.0/trippy-0.11.0-x86_64-unknown-freebsd.tar.gz)         | [0.10.0](https://github.com/fujiapple852/trippy/releases/download/0.10.0/trippy-0.10.0-x86_64-unknown-freebsd.tar.gz)         |
| NetBSD  | `x86_64`  | n/a          | [0.12.2](https://github.com/fujiapple852/trippy/releases/download/0.12.2/trippy-0.12.2-x86_64-unknown-netbsd.tar.gz)          | [0.11.0](https://github.com/fujiapple852/trippy/releases/download/0.11.0/trippy-0.11.0-x86_64-unknown-netbsd.tar.gz)          | [0.10.0](https://github.com/fujiapple852/trippy/releases/download/0.10.0/trippy-0.10.0-x86_64-unknown-netbsd.tar.gz)          |
| RPM     | `x86_64`  | `gnu`        | [0.12.2](https://github.com/fujiapple852/trippy/releases/download/0.12.2/trippy-0.12.2-x86_64.rpm)                            | [0.11.0](https://github.com/fujiapple852/trippy/releases/download/0.11.0/trippy-0.11.0-x86_64.rpm)                            | [0.10.0](https://github.com/fujiapple852/trippy/releases/download/0.10.0/trippy-0.10.0-x86_64.rpm)                            |
| Debian  | `x86_64`  | `gnu`        | [0.12.2](https://github.com/fujiapple852/trippy/releases/download/0.12.2/trippy_x86_64-unknown-linux-gnu_0.12.2_amd64.deb)    | [0.11.0](https://github.com/fujiapple852/trippy/releases/download/0.11.0/trippy_x86_64-unknown-linux-gnu_0.11.0_amd64.deb)    | [0.10.0](https://github.com/fujiapple852/trippy/releases/download/0.10.0/trippy_x86_64-unknown-linux-gnu_0.10.0_amd64.deb)    |
| Debian  | `x86_64`  | `musl`       | [0.12.2](https://github.com/fujiapple852/trippy/releases/download/0.12.2/trippy_x86_64-unknown-linux-musl_0.12.2_amd64.deb)   | [0.11.0](https://github.com/fujiapple852/trippy/releases/download/0.11.0/trippy_x86_64-unknown-linux-musl_0.11.0_amd64.deb)   | [0.10.0](https://github.com/fujiapple852/trippy/releases/download/0.10.0/trippy_x86_64-unknown-linux-musl_0.10.0_amd64.deb)   |
