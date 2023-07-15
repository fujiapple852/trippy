[![Continuous integration](https://github.com/fujiapple852/trippy/workflows/CI/badge.svg)](https://github.com/fujiapple852/trippy/actions/workflows/ci.yml)
[![Crate](https://img.shields.io/crates/v/trippy.svg)](https://crates.io/crates/trippy/0.8.0)
[![Packaging status](https://repology.org/badge/tiny-repos/trippy.svg)](https://repology.org/project/trippy/versions)

# Trippy

Trippy combines the functionality of traceroute and ping and is designed to assist with the analysis of networking
issues.

<img src="assets/0.8.0/trippy.gif" alt="trippy"/>

## Navigation

<!-- TOC -->

* [Trippy](#trippy)
    * [Features](#features)
    * [Distributions](#distributions)
    * [Platforms](#platforms)
    * [Privileges](#privileges)
    * [Usage Examples](#usage-examples)
    * [Command Reference](#command-reference)
    * [Theme Reference](#theme-reference)
    * [Key Bindings Reference](#key-bindings-reference)
    * [Configuration Reference](#configuration-reference)
    * [Acknowledgements](#acknowledgements)
    * [License](#license)

<!-- TOC -->

## Features

- Trace using multiple protocols:
    - `ICMP`, `UDP` & `TCP`
    - `IPv4` & `IPv6`
- Customizable tracing options:
    - packet size & payload pattern
    - start and maximum time-to-live (TTL)
    - minimum and maximum round duration
    - round end grace period & maximum number of unknown hops
    - source & destination port (`TCP` & `UDP`)
    - source address and source interface
    - `TOS` (aka `DSCP + ECN`)
- Support for `classic`, `paris`
  and `dublin` [Equal Cost Multi-path Routing](https://en.wikipedia.org/wiki/Equal-cost_multi-path_routing)
  strategies ([tracking issue](https://github.com/fujiapple852/trippy/issues/274))
- Tui interface:
    - Trace multiple targets simultaneously from a single instance of Trippy
    - Per hop stats (sent, received, loss%, last, avg, best, worst, stddev & status)
    - Per hop round-trip-time (RTT) history and frequency distributing charts
    - Interactive chart of RTT for all hops in a trace with zooming capability
    - Interactive GeoIp world map
    - Customizable color theme & key bindings
    - Configuration via both command line arguments and a configuration file
    - Show multiple hosts per hop with ability to cap display to N hosts and show frequency %
    - Show hop details and navigate hosts within each hop
    - Freeze/unfreeze the Tui, reset the stats, flush the cache, preserve screen on exit
    - Responsive UI with adjustable refresh rate
- DNS:
    - Use system, external (Google `8.8.8.8` or Cloudflare `1.1.1.1`) or custom resolver
    - Lazy reverse DNS queries
    - Lookup [autonomous system](https://en.wikipedia.org/wiki/Autonomous_system_(Internet)) number (ASN) and name
- GeoIp:
    - Lookup and display GeoIp information from local `mmdb` files
- Generate tracing reports:
    - `json`, `csv` & tabular (pretty-printed and markdown)
    - configurable reporting cycles
- Runs on multiple platform (macOS, Linux, NetBSD, FreeBSD, Windows)
- Capabilities aware application (Linux only)

## Distributions

### Cargo

[![Crates.io](https://img.shields.io/crates/v/trippy)](https://crates.io/crates/trippy/0.8.0)

```shell
cargo install trippy
```

### Snap (Linux)

[![trippy](https://snapcraft.io/trippy/badge.svg)](https://snapcraft.io/trippy)

```shell
snap install trippy
```

### Homebrew (MacOS)

[![Homebrew package](https://repology.org/badge/version-for-repo/homebrew/trippy.svg)](https://formulae.brew.sh/formula/trippy)

```shell
brew install trippy
```

### WinGet (Windows)

[![winget package](https://repology.org/badge/version-for-repo/winget/trippy.svg)](https://github.com/microsoft/winget-pkgs/tree/master/manifests/f/FujiApple/Trippy/0.8.0)

```shell
winget install trippy
```

### Scoop (Windows)

[![Scoop package](https://repology.org/badge/version-for-repo/scoop/trippy.svg)](https://github.com/ScoopInstaller/Main/blob/master/bucket/trippy.json)

```shell
scoop install trippy
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

### Pacman (Arch Linux)

[![Arch package](https://repology.org/badge/version-for-repo/arch/trippy.svg)](https://archlinux.org/packages/community/x86_64/trippy)

```shell
pacman -S trippy
```

### Nix

[![nixpkgs unstable package](https://repology.org/badge/version-for-repo/nix_unstable/trippy.svg)](https://github.com/NixOS/nixpkgs/blob/master/pkgs/tools/networking/trippy/default.nix)

```shell
nix-env -iA trippy
```

### Docker

[![Docker Image Version (latest by date)](https://img.shields.io/docker/v/fujiapple/trippy)](https://hub.docker.com/r/fujiapple/trippy/)

```shell
docker run -it fujiapple/trippy
```

## Platforms

Trippy has been (lightly...) tested on the following platforms:

### IPv4

| Platform | ICMP | UDP | TCP | Notes                                                         |
|----------|------|-----|-----|---------------------------------------------------------------|
| Linux    | ✅    | ✅   | ✅   |                                                               |
| macOS    | ✅    | ✅   | ✅   |                                                               |
| NetBSD   | ✅    | ✅   | ✅   |                                                               |
| OpenBSD  | ⏳    | ⏳   | ⏳   | See [#213](https://github.com/fujiapple852/trippy/issues/213) |
| FreeBSD  | ✅    | ✅   | ✅   | See [#214](https://github.com/fujiapple852/trippy/issues/214) |
| Windows  | ✅    | ✅   | ✅   | See [#98](https://github.com/fujiapple852/trippy/issues/98)   |

### IPv6

| Platform | ICMP | UDP | TCP | Notes                                                         |
|----------|------|-----|-----|---------------------------------------------------------------|
| Linux    | ✅    | ✅   | ✅   |                                                               |
| macOS    | ✅    | ✅   | ✅   |                                                               |
| NetBSD   | ✅    | ✅   | ✅   |                                                               |
| OpenBSD  | ⏳    | ⏳   | ⏳   | See [#213](https://github.com/fujiapple852/trippy/issues/213) |
| FreeBSD  | ✅    | ✅   | ✅   | See [#214](https://github.com/fujiapple852/trippy/issues/214) |
| Windows  | ✅    | ✅   | ✅   | See [#98](https://github.com/fujiapple852/trippy/issues/98)   |

## Privileges

Trippy uses a raw socket which require elevated privileges. Enabling the required privilege can be achieved in several
ways, including:

1: Run as `root` user via `sudo`:

```shell
sudo trip www.example.com
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

## Usage Examples

Basic usage with default parameters:

```shell
trip www.example.com
```

Trace using the `udp` (or `tcp` or `icmp`) protocol (also aliases `--udp` & `--tcp`):

```shell
trip www.example.com -p udp
```

Trace to multiple targets simultaneously (`icmp` protocol only,
see [#72](https://github.com/fujiapple852/trippy/issues/72)):

```shell
trip www.example.com google.com crates.io
```

Trace with a minimum round time of `250ms` and a grace period of `50ms`:

```shell
trip www.example.com -i 250ms -g 50ms
```

Trace with a custom first and maximum `time-to-live`:

```shell
trip www.example.com --first-ttl 2 --max-ttl 10
```

Use custom destination port `443` for `tcp` tracing:

```shell
trip www.example.com -p tcp -P 443
```

Use custom source port `5000` for `udp` tracing:

```shell
trip www.example.com -p udp -S 5000
```

Use the `dublin` (or `paris`) ECMP routing strategy for `udp` with fixed source and destination ports:

```shell
trip www.example.com -p udp -R dublin -S 5000 -P 3500
```

Trace with a custom source address:

```shell
trip www.example.com -p tcp -A 127.0.0.1
```

Trace with a source address determined by the IPv4 address for interface `en0`:

```shell
trip www.example.com -p tcp -I en0
```

Trace using `IPv6`:

```shell
trip www.example.com -6
```

Generate a `json` (or `csv`, `pretty`, `markdown`) tracing report with 5 rounds of data:

```shell
trip www.example.com -m json -C 5
```

Perform DNS queries using the `google` DNS resolver (or `cloudflare`, `system`, `resolv`):

```shell
trip www.example.com -r google
```

Lookup AS information for all discovered IP addresses (not yet available for the `system` resolver,
see [#66](https://github.com/fujiapple852/trippy/issues/66)):

```shell
trip www.example.com -r google -z true
```

Lookup and display `short` (or `long` or `location` or `off`) GeoIp information from a `mmdb` file:

```shell
trip www.example.com --geoip-mmdb-file GeoLite2-City.mmdb --tui-geoip-mode short
```

Customize the color theme:

```shell
trip www.example.com --tui-theme-colors bg-color=blue,text-color=ffff00
```

List all Tui items that can have a custom color theme:

```shell
trip --print-tui-theme-items
```

Customize the key bindings:

```shell
trip www.example.com --tui-key-bindings previous-hop=k,next-hop=j,quit=shift-q
```

List all Tui commands that can have a custom key binding:

```shell
trip --print-tui-binding-commands
```

Specify the location of the trippy config file:

```shell
trip www.example.com --config-file /path/to/trippy.toml
```

Generate `bash` shell completions (or `fish`, `powershell`, `zsh`, `elvish`):

```shell
trip --generate bash
```

Run in `silent` tracing mode and output `compact` trace logging with `full` span events:

```shell
trip www.example.com -m silent -v --log-format compact --log-span-events full
```

## Command Reference

```shell
Usage: trip [OPTIONS] [TARGETS]...

Arguments:
  [TARGETS]...
          A space delimited list of hostnames and IPs to trace

Options:
  -c, --config-file <CONFIG_FILE>
          Config file

  -m, --mode <MODE>
          Output mode [default: tui]

          Possible values:
          - tui:      Display interactive TUI
          - stream:   Display a continuous stream of tracing data
          - pretty:   Generate an pretty text table report for N cycles
          - markdown: Generate a markdown text table report for N cycles
          - csv:      Generate a SCV report for N cycles
          - json:     Generate a JSON report for N cycles
          - silent:   Do not generate any tracing output for N cycles

  -p, --protocol <PROTOCOL>
          Tracing protocol [default: icmp]

          Possible values:
          - icmp: Internet Control Message Protocol
          - udp:  User Datagram Protocol
          - tcp:  Transmission Control Protocol

      --udp
          Trace using the UDP protocol

      --tcp
          Trace using the TCP protocol

  -4, --ipv4
          use IPv4 only

  -6, --ipv6
          Use IPv6 only

  -P, --target-port <TARGET_PORT>
          The target port (TCP & UDP only) [default: 80]

  -S, --source-port <SOURCE_PORT>
          The source port (TCP & UDP only) [default: auto]

  -A, --source-address <SOURCE_ADDRESS>
          The source IP address [default: auto]

  -I, --interface <INTERFACE>
          The network interface [default: auto]

  -i, --min-round-duration <MIN_ROUND_DURATION>
          The minimum duration of every round [default: 1s]

  -T, --max-round-duration <MAX_ROUND_DURATION>
          The maximum duration of every round [default: 1s]

  -g, --grace-duration <GRACE_DURATION>
          The period of time to wait for additional ICMP responses after the
          target has responded [default: 100ms]

      --initial-sequence <INITIAL_SEQUENCE>
          The initial sequence number [default: 33000]

  -R, --multipath-strategy <MULTIPATH_STRATEGY>
          The Equal-cost Multi-Path routing strategy (IPv4/UDP only) [default:
          classic]

          Possible values:
          - classic:
            The src or dest port is used to store the sequence number
          - paris:
            The UDP `checksum` field is used to store the sequence number
          - dublin:
            The IP `identifier` field is used to store the sequence number

  -U, --max-inflight <MAX_INFLIGHT>
          The maximum number of in-flight ICMP echo requests [default: 24]

  -f, --first-ttl <FIRST_TTL>
          The TTL to start from [default: 1]

  -t, --max-ttl <MAX_TTL>
          The maximum number of TTL hops [default: 64]

      --packet-size <PACKET_SIZE>
          The size of IP packet to send (IP header + ICMP header + payload)
          [default: 84]

      --payload-pattern <PAYLOAD_PATTERN>
          The repeating pattern in the payload of the ICMP packet [default: 0]

  -Q, --tos <TOS>
          The TOS (i.e. DSCP+ECN) IP header value (TCP and UDP only) [default:
          0]

      --read-timeout <READ_TIMEOUT>
          The socket read timeout [default: 10ms]

  -r, --dns-resolve-method <DNS_RESOLVE_METHOD>
          How to perform DNS queries [default: system]

          Possible values:
          - system:     Resolve using the OS resolver
          - resolv:     Resolve using the `/etc/resolv.conf` DNS configuration
          - google:     Resolve using the Google `8.8.8.8` DNS service
          - cloudflare: Resolve using the Cloudflare `1.1.1.1` DNS service

      --dns-timeout <DNS_TIMEOUT>
          The maximum time to wait to perform DNS queries [default: 5s]

  -z, --dns-lookup-as-info <DNS_LOOKUP_AS_INFO>
          Lookup autonomous system (AS) information during DNS queries [default:
          false]

          [possible values: true, false]

  -a, --tui-address-mode <TUI_ADDRESS_MODE>
          How to render addresses [default: host]

          Possible values:
          - ip:   Show IP address only
          - host: Show reverse-lookup DNS hostname only
          - both: Show both IP address and reverse-lookup DNS hostname

      --tui-as-mode <TUI_AS_MODE>
          How to render AS information [default: asn]

          Possible values:
          - asn:          Show the ASN
          - prefix:       Display the AS prefix
          - country-code: Display the country code
          - registry:     Display the registry name
          - allocated:    Display the allocated date
          - name:         Display the AS name

      --tui-geoip-mode <TUI_GEOIP_MODE>
          How to render GeoIp information [default: short]

          Possible values:
          - off:      Do not display GeoIp data
          - short:    Show short format
          - long:     Show long format
          - location: Show latitude and Longitude format

  -M, --tui-max-addrs <TUI_MAX_ADDRS>
          The maximum number of addresses to show per hop [default: auto]

  -s, --tui-max-samples <TUI_MAX_SAMPLES>
          The maximum number of samples to record per hop [default: 256]

      --tui-preserve-screen <TUI_PRESERVE_SCREEN>
          Preserve the screen on exit [default: false]

          [possible values: true, false]

      --tui-refresh-rate <TUI_REFRESH_RATE>
          The Tui refresh rate [default: 100ms]

      --tui-theme-colors <TUI_THEME_COLORS>
          The TUI theme colors [item=color,item=color,..]

      --print-tui-theme-items
          Print all TUI theme items and exit

      --tui-key-bindings <TUI_KEY_BINDINGS>
          The TUI key bindings [command=key,command=key,..]

      --print-tui-binding-commands
          Print all TUI commands that can be bound and exit

  -C, --report-cycles <REPORT_CYCLES>
          The number of report cycles to run [default: 10]

  -G, --geoip-mmdb-file <GEOIP_MMDB_FILE>
          The MaxMind City GeoLite2 mmdb file

      --generate <GENERATE>
          Generate shell completion

          [possible values: bash, elvish, fish, powershell, zsh]

      --log-format <LOG_FORMAT>
          The debug log format [default: pretty]

          Possible values:
          - compact: Display log data in a compact format
          - pretty:  Display log data in a pretty format
          - json:    Display log data in a json format
          - chrome:  Display log data in Chrome trace format

      --log-filter <LOG_FILTER>
          The debug log filter [default: trippy=debug]

      --log-span-events <LOG_SPAN_EVENTS>
          The debug log format [default: off]

          Possible values:
          - off:    Do not display event spans
          - active: Display enter and exit event spans
          - full:   Display all event spans

  -v, --verbose
          Enable verbose debug logging

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## Theme Reference

The following table lists the default Tui color theme. These can be overridden with the `--tui-theme-colors` command
line option.

| Item                                 | Description                                          | Default    |
|--------------------------------------|------------------------------------------------------|------------|
| `bg-color`                           | The default background color                         | `Black`    |
| `border-color`                       | The default color of borders                         | `Gray`     |
| `text-color`                         | The default color of text                            | `Gray`     |
| `tab-text-color`                     | The color of the text in traces tabs                 | `Green`    |
| `hops-table-header-bg-color`         | The background color of the hops table header        | `White`    |
| `hops-table-header-text-color`       | The color of text in the hops table header           | `Black`    |
| `hops-table-row-active-text-color`   | The color of text of active rows in the hops table   | `Gray`     |
| `hops-table-row-inactive-text-color` | The color of text of inactive rows in the hops table | `DarkGray` |
| `hops-chart-selected-color`          | The color of the selected series in the hops chart   | `Green`    |
| `hops-chart-unselected-color`        | The color of the unselected series in the hops chart | `Gray`     |
| `hops-chart-axis-color`              | The color of the axis in the hops chart              | `DarkGray` |
| `frequency-chart-bar-color`          | The color of bars in the frequency chart             | `Green`    |
| `frequency-chart-text-color`         | The color of text in the bars of the frequency chart | `Gray`     |
| `samples-chart-color`                | The color of the samples chart                       | `Yellow`   |
| `help-dialog-bg-color`               | The background color of the help dialog              | `Blue`     |
| `help-dialog-text-color`             | The color of the text in the help dialog             | `Gray`     |
| `settings-dialog-bg-color`           | The background color of the settings dialog          | `blue`     |
| `settings-tab-text-color`            | The color of the text in settings dialog tabs        | `green`    |
| `settings-table-header-text-color`   | The color of text in the settings table header       | `black`    |
| `settings-table-header-bg-color`     | The background color of the settings table header    | `white`    |
| `settings-table-row-text-color`      | The color of text of rows in the settings table      | `gray`     |
| `map-world-color`                    | The color of the map world diagram                   | `white`    |
| `map-radius-color`                   | The color of the map accuracy radius circle          | `yellow`   |
| `map-selected-color`                 | The color of the map selected item box               | `green`    |
| `map-info-panel-border-color`        | The color of border of the map info panel            | `gray`     |
| `map-info-panel-bg-color`            | The background color of the map info panel           | `black`    |
| `map-info-panel-text-color`          | The color of text in the map info panel              | `gray`     |

The supported colors are:

- `Black`, `Red`, `Green`, `Yellow`, `Blue`, `Magenta`, `Cyan`, `Gray`, `DarkGray`, `LightRed`, `LightGreen`, `LightYellow`, `LightBlue`, `LightMagenta`, `LightCyan`, `White`

Color names are case-insensitive and may contain dashes. Raw hex values, such as `ffffff` for white, may also be used.

## Key Bindings Reference

The following table lists the default Tui command key bindings. These can be overridden with the `--tui-key-bindings`
command line option.

| Command                | Description                                     | Default  |
|------------------------|-------------------------------------------------|----------|
| `toggle-help`          | Toggle help                                     | `h`      |
| `toggle-settings`      | Toggle settings                                 | `s`      |
| `next-hop`             | Select next hop                                 | `down`   |
| `previous-hop`         | Select previous hop                             | `up`     |
| `next-trace`           | Select next trace                               | `right`  |
| `previous-trace`       | Select previous trace                           | `left`   | 
| `next-hop-address`     | Select next hop address                         | `.`      |
| `previous-hop-address` | Select previous hop address                     | `,`      |
| `address-mode-ip`      | Show IP address only                            | `i`      |
| `address-mode-host`    | Show hostname only                              | `n`      |
| `address-mode-both`    | Show both IP address and hostname               | `b`      |
| `toggle-freeze`        | Toggle freezing the display                     | `f`      |
| `toggle-chart`         | Toggle the chart                                | `c`      |
| `toggle-map`           | Toggle the GeoIp map                            | `m`      |
| `expand-hosts`         | Expand the hosts shown per hop                  | `]`      |
| `expand-hosts-max`     | Expand the hosts shown per hop to the maximum   | `}`      |
| `contract-hosts`       | Contract the hosts shown per hop                | `[`      |
| `contract-hosts-min`   | Contract the hosts shown per hop to the minimum | `{`      |
| `chart-zoom-in`        | Zoom in the chart                               | `=`      |
| `chart-zoom-out`       | Zoom out the chart                              | `-`      |
| `clear-trace-data`     | Clear all trace data                            | `ctrl+r` |
| `clear-dns-cache`      | Flush the DNS cache                             | `ctrl+k` |
| `clear-selection`      | Clear the current selection                     | `esc`    |
| `toggle-as-info`       | Toggle AS info display                          | `z`      |
| `toggle-hop-details`   | Toggle hop details                              | `d`      |
| `quit`                 | Quit the application                            | `q`      |

The supported modifiers are: `shift`, `ctrl`, `alt`, `super`, `hyper` & `meta`. Multiple modifiers may be specified, for
example `ctrl+shift+b`.

## Configuration Reference

Trippy can be configured with via command line arguments or an optional configuration file. If a given configuration
item is specified in both the configuration file and via a command line argument then the latter will take precedence.

The configuration file location may be provided to trippy via the `-c` (`--config-file`) argument. If not provided,
Trippy will attempt to locate a `trippy.toml` or `.trippy.toml` configuration file in one of the following locations:

- The current directory
- The user home directory
- the XDG config directory (Unix only): `$XDG_CONFIG_HOME` or `~/.config`
- the Windows data directory (Windows only): `%APPDATA%`

An annotated [template configuration file](trippy-config-sample.toml) is available.

## Acknowledgements

Trippy is made possible by [tui-rs](https://github.com/fdehau/tui-rs),
[crossterm](https://github.com/crossterm-rs/crossterm) as well
as [several](https://github.com/fujiapple852/trippy/blob/master/Cargo.toml) foundational Rust libraries.

Trippy draws heavily from [mtr](https://github.com/traviscross/mtr) and also incorporates ideas
from both [libparistraceroute](https://github.com/libparistraceroute/libparistraceroute)
& [Dublin Traceroute](https://github.com/insomniacslk/dublin-traceroute).

The Trippy networking code is inspired by [pnet](https://github.com/libpnet/libpnet) and some elements of that codebase
are incorporated in Trippy.

The [AS](https://en.wikipedia.org/wiki/Autonomous_system_(Internet)) data is retrieved from
the [IP to ASN Mapping Service](https://team-cymru.com/community-services/ip-asn-mapping/#dns) provided
by [Team Cymru](https://team-cymru.com).

The [trippy.cli.rs](https://trippy.cli.rs) CNAME hosting is provided by [cli.rs](https://cli.rs).

## License

This project is distributed under the terms of the Apache License (Version 2.0).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in time by you, as defined
in the Apache-2.0 license, shall be licensed as above, without any additional terms or conditions.

See [LICENSE](LICENSE) for details.

Copyright 2022 [Trippy Contributors](https://github.com/fujiapple852/trippy/graphs/contributors)
