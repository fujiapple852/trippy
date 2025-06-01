---
title: Features
description: Learn about the features of Trippy.
sidebar:
  order: 3
slug: 0.12.2/start/features
---

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
- RFC4884 [ICMP Multi-Part Messages](https://datatracker.ietf.org/doc/html/rfc4884)
  - Generic Extension Objects
  - MPLS Label Stacks
- Unprivileged mode
- NAT detection
- Tui interface:
  - Trace multiple targets simultaneously from a single instance of Trippy
  - Per hop stats (sent, received, loss%, last, avg, best, worst, stddev, jitter & status)
  - Per hop round-trip-time (RTT) history and frequency distributing charts
  - Interactive chart of RTT for all hops in a trace with zooming capability
  - Interactive GeoIp world map
  - Isolate and filter by individual tracing flows
  - Customizable color theme & key bindings
  - Customizable column order and visibility
  - Configuration via both command line arguments and a configuration file
  - Show multiple hosts per hop with ability to cap display to N hosts and show frequency %
  - Show hop details and navigate hosts within each hop
  - Freeze/unfreeze the Tui, reset the stats, flush the cache, preserve screen on exit
  - Responsive UI with adjustable refresh rate
  - Hop privacy
  - Multiple language support
- DNS:
  - Use system, external (Google `8.8.8.8` or Cloudflare `1.1.1.1`) or custom resolver
  - Lazy reverse DNS queries
  - Lookup [autonomous system][autonomous_system] number (ASN) and name
- GeoIp:
  - Lookup and display GeoIp information from local [MaxMind](https://www.maxmind.com)
    and [IPinfo](https://ipinfo.io) `mmdb` files
- Generate tracing reports:
  - `json`, `csv` & tabular (pretty-printed and markdown)
  - Tracing `flows` report
  - Graphviz `dot` charts
  - configurable reporting cycles
- Runs on multiple platform (macOS, Linux, Windows, NetBSD, FreeBSD, OpenBSD)
- Capabilities aware application (Linux only)
