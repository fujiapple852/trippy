---
title: Usage Examples
description: Examples of how to use the Trippy command line interface.
sidebar:
  order: 1
---

Basic usage with default parameters:

```shell
trip example.com
```

Trace without requiring elevated privileges (supported platforms only, see [privileges](/guides/privileges)):

```shell
trip example.com --unprivileged
```

Trace using the `udp` (or `tcp` or `icmp`) protocol (also aliases `--icmp`, `--udp` & `--tcp`):

```shell
trip example.com -p udp
```

Trace to multiple targets simultaneously (`icmp` protocol only,
see [#72](https://github.com/fujiapple852/trippy/issues/72)):

```shell
trip example.com google.com crates.io
```

Trace with a minimum round time of `250ms` and a grace period of `50ms`:

```shell
trip example.com -i 250ms -g 50ms
```

Trace with a custom first and maximum `time-to-live`:

```shell
trip example.com --first-ttl 2 --max-ttl 10
```

Use custom destination port `443` for `tcp` tracing:

```shell
trip example.com -p tcp -P 443
```

Use custom source port `5000` for `udp` tracing:

```shell
trip example.com -p udp -S 5000
```

Use the `dublin` (or `paris`) ECMP routing strategy for `udp` with fixed source and destination ports:

```shell
trip example.com -p udp -R dublin -S 5000 -P 3500
```

Trace with a custom source address:

```shell
trip example.com -p tcp -A 127.0.0.1
```

Trace with a source address determined by the IPv4 address for interface `en0`:

```shell
trip example.com -p tcp -I en0
```

Trace using `IPv6`:

```shell
trip example.com -6
```

Trace using `ipv4-then-ipv6` fallback (or `ipv6-then-ipv4` or `ipv4` or `ipv6`):

```shell
trip example.com --addr-family ipv4-then-ipv6
```

Generate a `json` (or `csv`, `pretty`, `markdown`) tracing report with 5 rounds of data:

```shell
trip example.com -m json -C 5
```

Generate a [Graphviz](https://graphviz.org) `DOT` file report of all tracing flows for a TCP trace after 5 rounds:

```shell
trip example.com --tcp -m dot -C 5
```

Generate a textual report of all tracing flows for a UDP trace after 5 rounds:

```shell
trip example.com --udp -m flows -C 5
```

Perform DNS queries using the `google` DNS resolver (or `cloudflare`, `system`, `resolv`):

```shell
trip example.com -r google
```

Lookup [AS][autonomous_system] information for all discovered IP addresses (not yet available for the `system` resolver,
see [#66](https://github.com/fujiapple852/trippy/issues/66)):

```shell
trip example.com -r google -z
```

Set the reverse DNS lookup cache time-to-live to be 60 seconds:

```shell
trip example.com --dns-ttl 60sec
```

Lookup and display `short` (or `long` or `location` or `off`) GeoIp information from a `mmdb` file:

```shell
trip example.com --geoip-mmdb-file GeoLite2-City.mmdb --tui-geoip-mode short
```

Parse `icmp` extensions:

```shell
trip example.com -e
```

Hide the IP address, hostname and GeoIp for the first two hops:

```shell
trip example.com --tui-privacy-max-ttl 2
```

Customize Tui columns (see [Column Reference](/reference/column)):

```shell
trip example.com --tui-custom-columns holsravbwdt
```

Customize the color theme:

```shell
trip example.com --tui-theme-colors bg-color=blue,text-color=ffff00
```

List all Tui items that can have a custom color theme:

```shell
trip --print-tui-theme-items
```

Customize the key bindings:

```shell
trip example.com --tui-key-bindings previous-hop=k,next-hop=j,quit=shift-q
```

List all Tui commands that can have a custom key binding:

```shell
trip --print-tui-binding-commands
```

Specify the location of the Trippy config file:

```shell
trip example.com --config-file /path/to/trippy.toml
```

Generate a template configuration file:

```shell
trip --print-config-template > trippy.toml
```

Generate `bash` shell completions (or `fish`, `powershell`, `zsh`, `elvish`):

```shell
trip --generate bash
```

Generate `ROFF` man page:

```shell
trip --generate-man
```

Use the `de` Tui locale:

```shell
trip example.com --tui-locale de
```

List supported Tui locales:

```shell
trip --print-locales
```

Set the Tui timezone to `UTC`:

```shell
trip example.com --tui-timezone UTC
```

Run in `silent` tracing mode and output `compact` trace logging with `full` span events:

```shell
trip example.com -m silent -v --log-format compact --log-span-events full
```
