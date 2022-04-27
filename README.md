[![Continuous integration](https://github.com/fujiapple852/trippy/workflows/Continuous%20integration/badge.svg)](https://github.com/fujiapple852/trippy/actions/workflows/ci.yml)
[![Crate](https://img.shields.io/crates/v/trippy.svg)](https://crates.io/crates/trippy/0.0.0)

# Trippy

A network diagnostic tool, inspired by [mtr](https://github.com/traviscross/mtr).

<img src="assets/trippy-0.0.0-27-04-2022.gif" alt="trippy"/>

## Status

In development & untested.

## Features

Feature status and high level roadmap:

- Trace: ICMP protocol (✅)
- Trace: Adjustable packet size (✅)
- Trace: Adjustable payload pattern (✅)
- Trace: Adjustable starting and ended time-to-live values (✅)
- Trace: Adjustable minimum and maximum round trip time (✅)
- Trace: Adjustable round end grace period (✅)
- Trace: Adjustable maximum number of unknown hops (✅)
- Trace: Adjustable source port for `UDP` (✅)
- Trace: UDP protocol (✅)
- Trace: TCP protocol (✅)
- Trace: SCTP protocol ([#41](https://github.com/fujiapple852/trippy/issues/41))
- Trace: IPv6 ([#35](https://github.com/fujiapple852/trippy/issues/35))
- Trace: MPLS ([#33](https://github.com/fujiapple852/trippy/issues/33))
- Trace: Adjustable `DSCP` IP header ([#38](https://github.com/fujiapple852/trippy/issues/38))
- Trace: Adjustable network interface binding ([#42](https://github.com/fujiapple852/trippy/issues/42))
- Trace: Adjustable target port for `UDP`/`TCP` ([#43](https://github.com/fujiapple852/trippy/issues/43))
- Trace: Capabilities awareness ([#36](https://github.com/fujiapple852/trippy/issues/36))
- Tui: Display core hop statistics (✅)
- Tui: hop navigation (✅)
- Tui: Pause display (✅)
- Tui: Help dialog (✅)
- Tui: Allow preserving screen on exit (✅)
- Tui: Adjustable refresh rate (✅)
- Tui: RTT history per hop (✅)
- Tui: RTT frequency histogram per hop (✅)
- Tui: Display multiple hosts per hop (✅)
- Tui: Reset statistics (✅)
- Tui: show Jitter ([#39](https://github.com/fujiapple852/trippy/issues/39))
- Tui: show top-N hosts per hop (✅)
- Tui: `AS` lookup ([#34](https://github.com/fujiapple852/trippy/issues/34))
- DNS: Basic reverse `DNS` lookup (✅)
- DNS: Non-blocking `DNS` resolver ([#37](https://github.com/fujiapple852/trippy/issues/37))
- Report: `JSON` report mode (✅)
- Report: `CSV` report mode (✅)
- Report: Tabular report mode (✅)
- Report: Streaming text mode (✅)

## Distributions

### Cargo

```shell
$ cargo install trippy
```

Note: Not yet published to `crates.io`.

### Docker (Linux only)

```shell
$ docker run -it fujiapple/trippy www.bitwizard.nl
```

## Privileges

Trippy uses a raw socket which require elevated privileges.  Enabling the required privilege can be achieved in several 
ways, including:

1: Run as `root` user via `sudo`:

```shell
sudo trip www.bitwizard.nl
```

2: `chown` `trip` as the `root` user and set the `setuid` bit:

```shell
sudo chown root $(which trip) && sudo chmod +s $(which trip)
```

3: [Linux only] Set the `CAP_NET_RAW` capability:

```shell
sudo setcap CAP_NET_RAW+p $(which trip)
```

Trippy is a capability aware application and will add `CAP_NET_RAW` to the effective set if it is present in the allowed
set. Note that trippy will drop all capabilities after creating the raw socket.

Note that `trippy` uses raw sockets and is not currently capabilities-aware and so needs to run as `root`.

Basic usage:

```shell
trip www.bitwizard.nl
```

Trace using the `udp` protocol:

```shell
trip www.bitwizard.nl -p udp
```

Trace with a minimum round time of `250ms` and a grace period of `50ms`:

```shell
trip www.bitwizard.nl -i 250ms -g 50ms
```

Trace with a custom first and maximum `time-to-live`:

```shell
trip www.bitwizard.nl --first-ttl 2 --max-ttl 10
```

Generate a `json` tracing report with 10 rounds of data:

```shell
trip www.bitwizard.nl -m json -c 5
```

## Acknowledgement

Trippy is made possible by [tui-rs](https://github.com/fdehau/tui-rs)
, [crossterm](https://github.com/crossterm-rs/crossterm) & [pnet](https://github.com/libpnet/libpnet) as well as several
common foundational Rust libraries.  It also draws heavily from [mtr](https://github.com/traviscross/mtr).

## Keyboard Controls

Press `h` in the Tui to display te keyboard controls.

## License

This project is distributed under the terms of the Apache License (Version 2.0).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in time by you, as defined
in the Apache-2.0 license, shall be licensed as above, without any additional terms or conditions.

See [LICENSE](LICENSE) for details.

Copyright 2022 [Trippy Contributors](https://github.com/fujiapple852/trippy/graphs/contributors)