# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2022-04-29

### Added

- Added the `-r` (`--dns-resolve-method`) flag to specify using either the OS DNS resolver (default), a 3rd party
  resolver (Google `1.1.1.1` and Cloudflare `8.8.8.8`) or DNS resolver configuration from the `/etc/resolv.conf` file
- Added the `-z` (`--dns-lookup-as-info`) flag to display the ASN for each discovered host. This is not yet supported
  for the default `system` resolver, see [#66](https://github.com/fujiapple852/trippy/issues/66).
- Added the `--dns-timeout` flag to allow setting a timeout on all DNS queries
- Added additional parameter validation for `first-ttl`, `max-ttl` & `initial-sequence`

### Changed

- All DNS queries are now non-blocking to prevent the Tui from freezing during slow DNS query
- Renamed `min-sequence` flag as `initial-sequence`

### Fixed

- Fixed the behaviour when the sequence number wraps around at `2^16 - 1`

## [0.1.0] - 2022-04-27

### Added

- Initial WIP release of `trippy`

[0.2.0]: https://github.com/fujiapple852/trippy/compare/0.1.0...0.2.0

[0.1.0]: https://github.com/fujiapple852/trippy/compare/0.0.0...0.1.0