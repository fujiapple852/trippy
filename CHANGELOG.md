# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added translations for locale `zh-TW` ([#1630](https://github.com/fujiapple852/trippy/pull/1630))

### Changed

- [BREAKING CHANGE] Change default `address-family` to be
  `system` ([#1475](https://github.com/fujiapple852/trippy/issues/1475))
- Increase MSRV to 1.82 ([#1633](https://github.com/fujiapple852/trippy/issues/1633))

### Fixed

- Default the `system` `address-family` to `ipv4-then-ipv6` for non-`system`
  resolvers ([#1635](https://github.com/fujiapple852/trippy/issues/1635))
- Locale parsing fails for valid BCP 47 language tags ([#1631](https://github.com/fujiapple852/trippy/pull/1631))

## [0.13.0] - 2025-05-05

### Added

- Added DSCP and ECN columns ([#1539](https://github.com/fujiapple852/trippy/issues/1539))
- Added support for setting IPv6 traffic class from `--tos` ([#202](https://github.com/fujiapple852/trippy/issues/202))
- Added ability to read config from `$XDG_CONFIG_HOME/trippy`
  directory ([#1528](https://github.com/fujiapple852/trippy/issues/1528))
- Added `--tui-timezone` flag to set a custom timezone ([#1513](https://github.com/fujiapple852/trippy/issues/1513))
- Added support for `--addr-family system` to defer address family selection to the OS
  resolver ([#1469](https://github.com/fujiapple852/trippy/issues/1469))
- Added tracing start and end timestamps to the `json`
  report ([#1510](https://github.com/fujiapple852/trippy/issues/1510))
- Added the Trippy logo! ([#100](https://github.com/fujiapple852/trippy/issues/100))

### Changed

- Remove address family downgrade for `dublin` strategy ([#1476](https://github.com/fujiapple852/trippy/issues/1476))
- Reduce verbosity of tracing for library users ([#1482](https://github.com/fujiapple852/trippy/issues/1482))
- Increase MSRV to 1.78 ([#1576](https://github.com/fujiapple852/trippy/issues/1576))

### Fixed

- Tracer panic for large icmp packets ([#1561](https://github.com/fujiapple852/trippy/issues/1561))
- Memory corruption on Windows ([#1527](https://github.com/fujiapple852/trippy/issues/1527))
- Socket being closed twice on Windows ([#1443](https://github.com/fujiapple852/trippy/issues/1443))
- Potential crash on Windows for adapters without unicast
  addresses ([#1547](https://github.com/fujiapple852/trippy/issues/1547))
- Potential use-after-free when discovering source address on
  Windows ([#1558](https://github.com/fujiapple852/trippy/issues/1558))
- The `--tos` (`-Q`) flag is ignored for `IPv4/udp`
  tracing ([#1540](https://github.com/fujiapple852/trippy/issues/1540))
- Items missing from settings dialog ([#1541](https://github.com/fujiapple852/trippy/issues/1541))

## [0.12.2] - 2025-01-03

### Fixed

- Tracer panic when `--first-ttl` is greater than 1 ([#1460](https://github.com/fujiapple852/trippy/issues/1460))
- IP `--addr-family` not respected for
  `--dns-resolve-method resolv` ([#1461](https://github.com/fujiapple852/trippy/issues/1461))
- Incorrect cli help text for `--addr-family` ([#1456](https://github.com/fujiapple852/trippy/issues/1456))

## [0.12.1] - 2024-12-21

### Changed

- Replace use of `yaml` with `toml` dependency ([#1416](https://github.com/fujiapple852/trippy/issues/1416))

### Fixed

- Locale data not copied into docker image ([#1431](https://github.com/fujiapple852/trippy/issues/1431))

## [0.12.0] - 2024-12-04

### Added

- Highlight lost probes in sample history ([#1247](https://github.com/fujiapple852/trippy/issues/1247))
- Added `quit-preserve-screen` (default: `shift+q`) key binding to quit Tui without clearing the
  screen ([#1382](https://github.com/fujiapple852/trippy/issues/1382))
- Added forward add backward loss heuristics ([#860](https://github.com/fujiapple852/trippy/issues/860))
- Added `--tui-locale` flag to support i18n ([#1319](https://github.com/fujiapple852/trippy/issues/1319))
- Added translations for locales `en`, `fr`, `tr`, `zh`, `pt`, `sv`, `it`, `ru`, `es` &
  `de` ([#506](https://github.com/fujiapple852/trippy/issues/506))
- Added `--print-locales` flag to print all available
  locales ([#1357](https://github.com/fujiapple852/trippy/issues/1357))
- Added Debian package ([#1312](https://github.com/fujiapple852/trippy/issues/1312))
- Added Ubuntu `noble` PPA package ([#1308](https://github.com/fujiapple852/trippy/issues/1308))

### Changed

- Added information bar to Tui ([#1349](https://github.com/fujiapple852/trippy/issues/1349))
- [BREAKING CHANGE] Remove `Timestamp` from all `DnsEntry`
  variants ([#1296](https://github.com/fujiapple852/trippy/issues/1296))
- [BREAKING CHANGE] Replace `toggle-privacy` key binding with `expand-privacy` and
  `contract-privacy` ([#1347](https://github.com/fujiapple852/trippy/issues/1347))
- [BREAKING CHANGE] Hide source address when `--tui-privacy-max-ttl` is
  set ([#1365](https://github.com/fujiapple852/trippy/issues/1365))
- Only show hostnames if different from IPs ([#1363](https://github.com/fujiapple852/trippy/issues/1363))
- Lookup GeoIp with current locale ([#1336](https://github.com/fujiapple852/trippy/issues/1336))
- Enable Link-Time Optimization (LTO) for release builds ([#1341](https://github.com/fujiapple852/trippy/issues/1341))

### Fixed

- Reverse dns enqueued multiple times when dns-ttl expires ([#1290](https://github.com/fujiapple852/trippy/issues/1290))
- Fixed panic for icmp extensions with malformed length ([#1287](https://github.com/fujiapple852/trippy/issues/1287))
- Cursor not moved to the bottom on exit when using
  `--tui-preserve-screen` ([#1375](https://github.com/fujiapple852/trippy/issues/1375))
- Config item `tui-address-mode` does not accept `ip` ([#1327](https://github.com/fujiapple852/trippy/issues/1327))
- Icmp extension mode not shown in Tui settings ([#1289](https://github.com/fujiapple852/trippy/issues/1289))
- Sample history and frequency charts ignore sub-millisecond
  samples ([#1398](https://github.com/fujiapple852/trippy/issues/1398))

## [0.11.0] - 2024-08-11

### Added

- Added NAT detection for `IPv4/udp/dublin` ([#1104](https://github.com/fujiapple852/trippy/issues/1104))
- Added public API ([#1192](https://github.com/fujiapple852/trippy/issues/1192))
- Added support for NAT detection (`N`) column ([#1219](https://github.com/fujiapple852/trippy/issues/1219))
- Added support for last icmp packet type (`T`) column ([#1105](https://github.com/fujiapple852/trippy/issues/1105))
- Added support for last icmp packet code (`C`) column ([#1109](https://github.com/fujiapple852/trippy/issues/1109))
- Added support for the probe failure count (`f`) column ([#1258](https://github.com/fujiapple852/trippy/issues/1258))
- Added settings dialog tab hotkeys ([#1217](https://github.com/fujiapple852/trippy/issues/1217))
- Added `--dns-ttl` flag to allow refreshing the reverse DNS
  results ([#1233](https://github.com/fujiapple852/trippy/issues/1233))
- Added `--generate-man` flag for generating [ROFF](https://en.wikipedia.org/wiki/Roff_(software)) man
  page ([#85](https://github.com/fujiapple852/trippy/issues/85))
- Added Ubuntu PPA package ([#859](https://github.com/fujiapple852/trippy/issues/859))
- Added Chocolatey package ([#572](https://github.com/fujiapple852/trippy/issues/572))

### Changed

- [BREAKING CHANGE] Changed initial sequence to be `33434` ([#1203](https://github.com/fujiapple852/trippy/issues/1203))
- [BREAKING CHANGE] Renamed `tui-max-[samples|flows]`
  as `max-[samples|flows]` ([#1187](https://github.com/fujiapple852/trippy/issues/1187))
- Separated library and binary crates ([#1141](https://github.com/fujiapple852/trippy/issues/1141))
- Record `icmp` packet code ([#734](https://github.com/fujiapple852/trippy/issues/734))
- Transient error handling for `IPv4` on macOS, Linux &
  Windows ([#1255](https://github.com/fujiapple852/trippy/issues/1255))
- Improved error messages ([#1150](https://github.com/fujiapple852/trippy/issues/1150))
- Revamp the help dialog ([#1260](https://github.com/fujiapple852/trippy/issues/1260))

### Fixed

- Fixed `DestinationUnreachable` incorrectly assumed to come from target
  host ([#1225](https://github.com/fujiapple852/trippy/issues/1225))
- Fixed incorrect target hop calculation ([#1226](https://github.com/fujiapple852/trippy/issues/1226))
- Do not conflate `AddressInUse` and `AddrNotAvailable`
  errors ([#1246](https://github.com/fujiapple852/trippy/issues/1246))

## [0.10.0] - 2024-03-31

### Added

- Added support for calculating and displaying jitter ([#39](https://github.com/fujiapple852/trippy/issues/39))
- Added support for customizing columns ([#757](https://github.com/fujiapple852/trippy/issues/757))
- Added support for reordering and toggling column
  visibility in Tui ([#1026](https://github.com/fujiapple852/trippy/issues/1026))
- Added support for [dublin](https://github.com/insomniacslk/dublin-traceroute) ECMP routing
  for `IPv6/udp` ([#272](https://github.com/fujiapple852/trippy/issues/272))
- Added support for [IPinfo](https://ipinfo.io) flavoured `mmdb`
  files ([#862](https://github.com/fujiapple852/trippy/issues/862))
- Added support for `IPv4->IPv6` and `IPv6->IPv4` DNS fallback
  modes ([#864](https://github.com/fujiapple852/trippy/issues/864))
- Added [TUN](https://en.wikipedia.org/wiki/TUN/TAP) based simulation
  tests ([#908](https://github.com/fujiapple852/trippy/issues/908))
- Added support for last src port (`S`) and last dest port (`P`) custom
  columns ([#974](https://github.com/fujiapple852/trippy/issues/974))
- Added support for last sequence (`Q`) custom column ([#976](https://github.com/fujiapple852/trippy/issues/976))
- Added support for more named theme colors ([#1011](https://github.com/fujiapple852/trippy/issues/1011))

### Changed

- Ensure `paris` and `dublin` ECMP strategy are only used with supported
  protocols ([#848](https://github.com/fujiapple852/trippy/issues/848))
- Restrict flows to `paris` and `dublin` ECMP strategies ([#1007](https://github.com/fujiapple852/trippy/issues/1007))
- Improved Tui table column layout logic ([#925](https://github.com/fujiapple852/trippy/issues/925))
- Use exclusive reference `&mut` for all Socket operations ([#843](https://github.com/fujiapple852/trippy/issues/843))
- Reduced maximum sequence per round from 1024 to 512 ([#1067](https://github.com/fujiapple852/trippy/issues/1067))

### Fixed

- Fixed off-by-one bug in max-rounds calculation ([#906](https://github.com/fujiapple852/trippy/issues/906))
- Fixed panic with `expand-hosts-max` Tui command ([#892](https://github.com/fujiapple852/trippy/issues/892))
- Fixed failure to parse generated config file on Windows ([#958](https://github.com/fujiapple852/trippy/issues/958))
- Fixed tracer panic for `icmp` TimeExceeded "Fragment reassembly time exceeded"
  packets ([#979](https://github.com/fujiapple852/trippy/issues/979))
- Fixed tracer not discarding unrelated `icmp` packets for `udp` and `tcp`
  protocols ([#982](https://github.com/fujiapple852/trippy/issues/982))
- Fixed incorrect minimum packet size for `IPv6` ([#985](https://github.com/fujiapple852/trippy/issues/985))
- Fixed permission denied error reading configuration file from snap
  installation ([#1058](https://github.com/fujiapple852/trippy/issues/1058))

## [0.9.0] - 2023-11-30

### Added

- Added support for tracing flows ([#776](https://github.com/fujiapple852/trippy/issues/776))
- Added support for `icmp` extensions ([#33](https://github.com/fujiapple852/trippy/issues/33))
- Added support for `MPLS` label stack class `icmp` extension
  objects ([#753](https://github.com/fujiapple852/trippy/issues/753))
- Added support for [paris](https://github.com/libparistraceroute/libparistraceroute) ECMP routing
  for `IPv6/udp` ([#749](https://github.com/fujiapple852/trippy/issues/749))
- Added `--unprivileged` (`-u`) flag to allow tracing without elevated privileges (macOS
  only) ([#101](https://github.com/fujiapple852/trippy/issues/101))
- Added `--tui-privacy-max-ttl` flag to hide host and IP details for low ttl
  hops ([#766](https://github.com/fujiapple852/trippy/issues/766))
- Added `toggle-privacy` (default: `p`) key binding to show or hide private
  hops ([#823](https://github.com/fujiapple852/trippy/issues/823))
- Added `toggle-flows` (default: `f`) key binding to show or hide tracing
  flows ([#777](https://github.com/fujiapple852/trippy/issues/777))
- Added `--dns-resolve-all` (`-y`) flag to allow tracing to all IPs resolved from DNS lookup
  entry ([#743](https://github.com/fujiapple852/trippy/issues/743))
- Added `dot` report mode (`-m dot`) to output hop graph in Graphviz `DOT`
  format ([#582](https://github.com/fujiapple852/trippy/issues/582))
- Added `flows` report mode (`-m flows`) to output a list of all unique tracing
  flows ([#770](https://github.com/fujiapple852/trippy/issues/770))
- Added `--icmp-extensions` (`-e`) flag for parsing `IPv4`/`IPv6` `icmp`
  extensions ([#751](https://github.com/fujiapple852/trippy/issues/751))
- Added `--tui-icmp-extension-mode` flag to control how `icmp` extensions are
  rendered ([#752](https://github.com/fujiapple852/trippy/issues/752))
- Added `--print-config-template` flag to output a template config
  file ([#792](https://github.com/fujiapple852/trippy/issues/792))
- Added `--icmp` flag as a shortcut for `--protocol icmp` ([#649](https://github.com/fujiapple852/trippy/issues/649))
- Added `toggle-help-alt` (default: `?`) key binding to show or hide
  help ([#694](https://github.com/fujiapple852/trippy/issues/694))
- Added panic handing to Tui ([#784](https://github.com/fujiapple852/trippy/issues/784))
- Added official Windows `scoop` package ([#462](https://github.com/fujiapple852/trippy/issues/462))
- Added official Windows `winget` package ([#460](https://github.com/fujiapple852/trippy/issues/460))
- Release `musl` Debian `deb` binary asset ([#568](https://github.com/fujiapple852/trippy/issues/568))
- Release `armv7` Linux binary assets ([#712](https://github.com/fujiapple852/trippy/issues/712))
- Release `aarch64-apple-darwin` (aka macOS Apple Silicon) binary
  assets ([#801](https://github.com/fujiapple852/trippy/issues/801))
- Added additional Rust Tier 1 and Tier 2 binary assets ([#811](https://github.com/fujiapple852/trippy/issues/811))

### Changed

- [BREAKING CHANGE] `icmp` extension object data added to `json` and `stream`
  reports ([#806](https://github.com/fujiapple852/trippy/issues/806))
- [BREAKING CHANGE] IPs field added to `csv` and all tabular
  reports ([#597](https://github.com/fujiapple852/trippy/issues/597))
- [BREAKING CHANGE] Command line flags `--dns-lookup-as-info` and `--tui-preserve-screen` no longer require a boolean
  argument ([#708](https://github.com/fujiapple852/trippy/issues/708))
- [BREAKING CHANGE] Default key binding for `ToggleFreeze` changed from `f`
  to `ctrl+f` ([#785](https://github.com/fujiapple852/trippy/issues/785))
- Always render AS lines in hop details mode ([#825](https://github.com/fujiapple852/trippy/issues/825))
- Expose DNS resolver module as part of `trippy` library ([#754](https://github.com/fujiapple852/trippy/issues/754))
- Replaced unmaintained `tui-rs` crate with `ratatui` crate ([#569](https://github.com/fujiapple852/trippy/issues/569))

### Fixed

- Reverse DNS lookup not working in reports ([#509](https://github.com/fujiapple852/trippy/issues/509))
- Crash on NetBSD during window resizing ([#276](https://github.com/fujiapple852/trippy/issues/276))
- Protocol mismatch causes tracer panic ([#745](https://github.com/fujiapple852/trippy/issues/745))
- Incorrect row height in Tui hop detail navigation view for hops with no
  responses ([#765](https://github.com/fujiapple852/trippy/issues/765))
- Unnecessary socket creation in certain tracing modes ([#647](https://github.com/fujiapple852/trippy/issues/647))
- Incorrect byte order in `IPv4` packet length calculation ([#686](https://github.com/fujiapple852/trippy/issues/686))

## [0.8.0] - 2023-05-15

### Added

- Added `--tui-as-mode` flag to control how AS information is
  rendered ([#483](https://github.com/fujiapple852/trippy/issues/483))
- Added support for configuration files and added a `-c` (`--config-file`)
  flag ([#412](https://github.com/fujiapple852/trippy/issues/412))
- Added `--generate` flag for generating shell completions ([#86](https://github.com/fujiapple852/trippy/issues/86))
- Added support for showing and navigating host detail ([#70](https://github.com/fujiapple852/trippy/issues/70))
- Added `--geoip-mmdb-file` and `--tui-geoip-mode` flags for looking up and displaying GeoIp information from `mmdb`
  files ([#503](https://github.com/fujiapple852/trippy/issues/503))
- Added settings dialog and simplified Tui header display ([#521](https://github.com/fujiapple852/trippy/issues/521))
- Added interactive GeoIp map display ([#505](https://github.com/fujiapple852/trippy/issues/505))
- Added support for the [paris](https://github.com/libparistraceroute/libparistraceroute) ECMP traceroute strategy
  for `IPv4/udp` ([#542](https://github.com/fujiapple852/trippy/issues/542))
- Added `silent` reporting mode to run tracing without producing any
  output ([#555](https://github.com/fujiapple852/trippy/issues/555))
- Added `-v` (`--verbose`), `--log-format`, `--log-filter` & `--log-span-events` flags to support generating debug trace
  logging output ([#552](https://github.com/fujiapple852/trippy/issues/552))

### Changed

- Show AS information for IP addresses without PTR record ([#479](https://github.com/fujiapple852/trippy/issues/479))
- Re-enabled musl release builds ([#456](https://github.com/fujiapple852/trippy/issues/456))
- [BREAKING CHANGE] Renamed short config flag for `report-cycles` from `-c`
  to `-C` ([#491](https://github.com/fujiapple852/trippy/issues/491))
- Ensure administrator privileges on Windows ([#451](https://github.com/fujiapple852/trippy/issues/451))
- Add context information to socket errors ([#153](https://github.com/fujiapple852/trippy/issues/153))

### Fixed

- Do not require passing targets for certain command line
  flags ([#500](https://github.com/fujiapple852/trippy/issues/500))
- Key press registering two events on Windows ([#513](https://github.com/fujiapple852/trippy/issues/513))
- Command line parameter names in error messages should be
  in `kebab-case` ([#516](https://github.com/fujiapple852/trippy/issues/516))

## [0.7.0] - 2023-03-25

### Added

- Added support for Windows (`icmp`, `udp` & `tcp`
  for `IPv4` &`IPv6`) ([#98](https://github.com/fujiapple852/trippy/issues/98))
- Added support for custom Tui key bindings ([#448](https://github.com/fujiapple852/trippy/issues/448))
- Added support for custom Tui color themes ([#411](https://github.com/fujiapple852/trippy/issues/411))
- Added RPM packaging ([#95](https://github.com/fujiapple852/trippy/issues/95))
- Added DEB packaging ([#94](https://github.com/fujiapple852/trippy/issues/94))

### Fixed

- Variable Equal Cost Multi-path Routing (ECMP) causing truncated
  trace ([#269](https://github.com/fujiapple852/trippy/issues/269))
- Tracing using the `tcp` may ignore some incoming `icmp`
  responses ([#407](https://github.com/fujiapple852/trippy/issues/407))
- Tracer panics with large `--initial-sequence` and delayed TCP probe
  response ([#435](https://github.com/fujiapple852/trippy/issues/435))
- Trippy Docker fails to start ([#277](https://github.com/fujiapple852/trippy/issues/277))

## [0.6.0] - 2022-08-19

### Added

- Added support for tracing using `IPv6` for `tcp` ([#191](https://github.com/fujiapple852/trippy/issues/191))
- Added `-R` (`--multipath-strategy`) flag to allow setting
  the [Equal Cost Multi-path Routing](https://en.wikipedia.org/wiki/Equal-cost_multi-path_routing) strategy and added
  support for the [dublin](https://github.com/insomniacslk/dublin-traceroute)
  traceroute strategies for `IPv4/udp` ([#158](https://github.com/fujiapple852/trippy/issues/158))
- Added zoom-able chart showing round trip times for all hops in a
  trace ([#209](https://github.com/fujiapple852/trippy/issues/209))
- Added `--udp` and `--tcp` flags as shortcuts to `-p udp` and `-p tcp`
  respectively ([#205](https://github.com/fujiapple852/trippy/issues/205))

### Changed

- Gray out hops which did not update in the current round ([#216](https://github.com/fujiapple852/trippy/issues/216))

## [0.5.0] - 2022-06-02

### Added

- Added support for tracing using `IPv6` for `icmp` and `udp` ([#35](https://github.com/fujiapple852/trippy/issues/35))
- Added BSOD error reporting to Tui ([#179](https://github.com/fujiapple852/trippy/issues/179))
- Added Ctrl-C keyboard command to quit the Tui ([#91](https://github.com/fujiapple852/trippy/issues/91))

### Changed

- Rewrite of network code to use RAW sockets ([#195](https://github.com/fujiapple852/trippy/issues/195),
  [#192](https://github.com/fujiapple852/trippy/issues/192))

### Fixed

- Setting `-c` (`--report-cycles`) to 1 returns no traces ([#189](https://github.com/fujiapple852/trippy/issues/189))
- Tracer failures not being shown for reports ([#183](https://github.com/fujiapple852/trippy/issues/183))

## [0.4.0] - 2022-05-18

### Added

- Added `-P` (`--target-port`) flag to allow specifying the target
  port ([1](https://github.com/fujiapple852/trippy/commit/5773fe5e5323543612be6bd4606db5aa8347d71e),
  [2](https://github.com/fujiapple852/trippy/commit/9f03047dd231b10b13911fcc7af60afbb8b21473))
- Added ability to trace with either a fixed source or a fixed destination port for both `udp` and `tcp`
  tracing ([#43](https://github.com/fujiapple852/trippy/issues/43))
- Display source and destination ports in Tui ([#156](https://github.com/fujiapple852/trippy/issues/156))
- Added the `-A` (`--source-address`) flag to allow specifying the source
  address ([#162](https://github.com/fujiapple852/trippy/issues/162))
- Added the `-I` (`--interface`) flag to allow specifying the source
  interface ([#142](https://github.com/fujiapple852/trippy/issues/42))
- Added the `-Q` (`--tos`) flag to allow specifying the `TOS` (`DSCP`+`ECN`) `IPv4` header
  value ([#38](https://github.com/fujiapple852/trippy/issues/38))

### Changed

- Changed `tcp` tracing to use a standard (non-raw) socket to be able to detect the
  target ([#134](https://github.com/fujiapple852/trippy/issues/134))
- Changed `udp` tracing to use a standard (non-raw) socket ([#155](https://github.com/fujiapple852/trippy/issues/155))
- Renamed the `--tui-max-addresses-per-hop` flag
  as `tui-max-addrs` ([#165](https://github.com/fujiapple852/trippy/issues/165))
- Reorder the cli flags in the help output ([#163](https://github.com/fujiapple852/trippy/issues/163))
- Change short alias for flag `max_round_duration` from `-I`
  to `-T` ([1](https://github.com/fujiapple852/trippy/commit/15978b0909139bb2b38baa4c6f6ca969c818fc75))
- Added short cli flags for `source-port` (`-S`), `first-ttl` (`-f`) and `tui-max-addrs` (
  `-M`) ([1](https://github.com/fujiapple852/trippy/commit/6a6a490174582c8500972b89407ba8d694c4c6fa))

### Fixed

- Checksums for `udp` packets were not being set (obsoleted
  by [#155](https://github.com/fujiapple852/trippy/issues/155)) ([#159](https://github.com/fujiapple852/trippy/issues/159))
- `TimeExceeded` responses _from_ the target address were not being
  handled ([1](https://github.com/fujiapple852/trippy/commit/3afa41326a33287a3ad9c17713dd7426ca86b481))
- The largest time-to-live for a given round was being calculated incorrectly in some
  cases ([1](https://github.com/fujiapple852/trippy/commit/688a8d00d84a816449cfee48b2d6f6dd90946511))

## [0.3.1] - 2022-05-09

### Fixed

- Local IPv4 discovery fails on some platforms ([#133](https://github.com/fujiapple852/trippy/issues/133),
  [#142](https://github.com/fujiapple852/trippy/issues/142))
- DNS resolution not filtering for `IPv4` addresses ([#148](https://github.com/fujiapple852/trippy/issues/148))
  - Note: see [#35](https://github.com/fujiapple852/trippy/issues/35) for the status of `IPv6` support

## [0.3.0] - 2022-05-08

### Added

- Added ability for `icmp` tracing to multiple targets simultaneously in
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
- Show better error message for failed DNS resolution ([#119](https://github.com/fujiapple852/trippy/issues/119))

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

[Unreleased]: https://github.com/fujiapple852/trippy/compare/0.13.0...master
[0.13.0]: https://github.com/fujiapple852/trippy/compare/0.12.2...0.13.0
[0.12.2]: https://github.com/fujiapple852/trippy/compare/0.12.1...0.12.2
[0.12.1]: https://github.com/fujiapple852/trippy/compare/0.12.0...0.12.1
[0.12.0]: https://github.com/fujiapple852/trippy/compare/0.11.0...0.12.0
[0.11.0]: https://github.com/fujiapple852/trippy/compare/0.10.0...0.11.0
[0.10.0]: https://github.com/fujiapple852/trippy/compare/0.9.0...0.10.0
[0.9.0]: https://github.com/fujiapple852/trippy/compare/0.8.0...0.9.0
[0.8.0]: https://github.com/fujiapple852/trippy/compare/0.7.0...0.8.0
[0.7.0]: https://github.com/fujiapple852/trippy/compare/0.6.0...0.7.0
[0.6.0]: https://github.com/fujiapple852/trippy/compare/0.5.0...0.6.0
[0.5.0]: https://github.com/fujiapple852/trippy/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/fujiapple852/trippy/compare/0.3.1...0.4.0
[0.3.1]: https://github.com/fujiapple852/trippy/compare/0.3.0...0.3.1
[0.3.0]: https://github.com/fujiapple852/trippy/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/fujiapple852/trippy/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/fujiapple852/trippy/compare/0.0.0...0.1.0
