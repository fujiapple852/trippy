# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

## [0.3.0] - 2022-05-08

### Added

- Added ability for `icmp`  tracing to multiple targets simultaneously in
  Tui ([#72](https://github.com/fujiapple852/trippy/issues/72))
- Added ability to enable and disable the `AS` lookup from the
  Tui ([#126](https://github.com/fujiapple852/trippy/issues/126))
- Added ability to switch between hop address display modes (ip, hostname or both) in thr
  Tui ([#124](https://github.com/fujiapple852/trippy/issues/124))
- Added ability to expand and collapse the number of hosts displays per hop in the
  Tui ([#124](https://github.com/fujiapple852/trippy/issues/124))
- Added the `-s` (`--tui-max-samples`) flag to specify the number of samples to keep for analysis and
  display ([#110](https://github.com/fujiapple852/trippy/issues/110))
- Added ability to flush the DNS cache from the Tui ([#71](https://github.com/fujiapple852/trippy/issues/371))

### Changed

- Simplified `Tracer` by removing circular buffer ([#106](https://github.com/fujiapple852/trippy/issues/106))
- Added round end reason indicator to `Tracer` ([#88](https://github.com/fujiapple852/trippy/issues/88))
- SHow better error message for failed DNS resolution ([#119](https://github.com/fujiapple852/trippy/issues/119))

### Fixed

- Tracing with `udp` protocol not showing the target hop due to incorrect handling of `DestinationUnreachable`
  responses ([#131](https://github.com/fujiapple852/trippy/issues/131))
- Tui failing on shutdown on Windows due to `DisableMouseCapture` being invoked without a prior `EnableMouseCapture`
  call ([#116](https://github.com/fujiapple852/trippy/issues/116))
- Build failing on Windows due to incorrect conditional compilation
  configuration ([#113](https://github.com/fujiapple852/trippy/issues/113))
- Tracing not publishing all `Probe` in a round when the round ends without finding the
  target ([#103](https://github.com/fujiapple852/trippy/issues/103))
- Tracing with `tcp` protocol not working as the checksum was not
  set ([#79](https://github.com/fujiapple852/trippy/issues/79))
- Do not show FQDN for reverse DNS queries from non-system
  resolvers ([#120](https://github.com/fujiapple852/trippy/issues/120))

## [0.2.0] - 2022-04-29

### Added

- Added the `-r` (`--dns-resolve-method`) flag to specify using either the OS DNS resolver (default), a 3rd party
  resolver (Google `8.8.8.8` and Cloudflare `1.1.1.1`) or DNS resolver configuration from the `/etc/resolv.conf` file
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

[0.3.0]: https://github.com/fujiapple852/trippy/compare/0.2.0...0.3.0

[0.2.0]: https://github.com/fujiapple852/trippy/compare/0.1.0...0.2.0

[0.1.0]: https://github.com/fujiapple852/trippy/compare/0.0.0...0.1.0