---
title: CLI Reference
description: A reference for the Trippy command line interface.
sidebar:
  order: 1
---

```text
A network diagnostic tool

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
          - pretty:   Generate a pretty text table report for N cycles
          - markdown: Generate a Markdown text table report for N cycles
          - csv:      Generate a CSV report for N cycles
          - json:     Generate a JSON report for N cycles
          - dot:      Generate a Graphviz DOT file for N cycles
          - flows:    Display all flows for N cycles
          - silent:   Do not generate any tracing output for N cycles

  -u, --unprivileged
          Trace without requiring elevated privileges on supported platforms
          [default: false]

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

      --icmp
          Trace using the ICMP protocol

  -F, --addr-family <ADDR_FAMILY>
          The address family [default: ipv4-then-ipv6]

          Possible values:
          - ipv4:           IPv4 only
          - ipv6:           IPv6 only
          - ipv6-then-ipv4: IPv6 with a fallback to IPv4
          - ipv4-then-ipv6: IPv4 with a fallback to IPv6
          - system:         If the OS resolver is being used then use the first IP address returned, 
                            otherwise lookup IPv4 with a fallback to IPv6

  -4, --ipv4
          Use IPv4 only

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
          The initial sequence number [default: 33434]

  -R, --multipath-strategy <MULTIPATH_STRATEGY>
          The Equal-cost Multi-Path routing strategy (UDP only) [default:
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
          The TOS (i.e. DSCP+ECN) IP header value (IPv4 only) [default: 0]

  -e, --icmp-extensions
          Parse ICMP extensions

      --read-timeout <READ_TIMEOUT>
          The socket read timeout [default: 10ms]

  -r, --dns-resolve-method <DNS_RESOLVE_METHOD>
          How to perform DNS queries [default: system]

          Possible values:
          - system:     Resolve using the OS resolver
          - resolv:     Resolve using the `/etc/resolv.conf` DNS configuration
          - google:     Resolve using the Google `8.8.8.8` DNS service
          - cloudflare: Resolve using the Cloudflare `1.1.1.1` DNS service

  -y, --dns-resolve-all
          Trace to all IPs resolved from DNS lookup [default: false]

      --dns-timeout <DNS_TIMEOUT>
          The maximum time to wait to perform DNS queries [default: 5s]

      --dns-ttl <DNS_TTL>
          The time-to-live (TTL) of DNS entries [default: 300s]

  -z, --dns-lookup-as-info
          Lookup autonomous system (AS) information during DNS queries [default:
          false]

  -s, --max-samples <MAX_SAMPLES>
          The maximum number of samples to record per hop [default: 256]

      --max-flows <MAX_FLOWS>
          The maximum number of flows to record [default: 64]

  -a, --tui-address-mode <TUI_ADDRESS_MODE>
          How to render addresses [default: host]

          Possible values:
          - ip:   Show IP address only
          - host: Show reverse-lookup DNS hostname only
          - both: Show both IP address and reverse-lookup DNS hostname

      --tui-as-mode <TUI_AS_MODE>
          How to render autonomous system (AS) information [default: asn]

          Possible values:
          - asn:          Show the ASN
          - prefix:       Display the AS prefix
          - country-code: Display the country code
          - registry:     Display the registry name
          - allocated:    Display the allocated date
          - name:         Display the AS name

      --tui-custom-columns <TUI_CUSTOM_COLUMNS>
          Custom columns to be displayed in the TUI hops table [default:
          holsravbwdt]

      --tui-icmp-extension-mode <TUI_ICMP_EXTENSION_MODE>
          How to render ICMP extensions [default: off]

          Possible values:
          - off:  Do not show `icmp` extensions
          - mpls: Show MPLS label(s) only
          - full: Show full `icmp` extension data for all known extensions
          - all:  Show full `icmp` extension data for all classes

      --tui-geoip-mode <TUI_GEOIP_MODE>
          How to render GeoIp information [default: short]

          Possible values:
          - off:      Do not display GeoIp data
          - short:    Show short format
          - long:     Show long format
          - location: Show latitude and Longitude format

  -M, --tui-max-addrs <TUI_MAX_ADDRS>
          The maximum number of addresses to show per hop [default: auto]

      --tui-preserve-screen
          Preserve the screen on exit [default: false]

      --tui-refresh-rate <TUI_REFRESH_RATE>
          The TUI refresh rate [default: 100ms]

      --tui-privacy-max-ttl <TUI_PRIVACY_MAX_TTL>
          The maximum ttl of hops which will be masked for privacy [default: none]

          If set, the source IP address and hostname will also be hidden.

      --tui-locale <TUI_LOCALE>
          The locale to use for the TUI [default: auto]

      --tui-timezone <TUI_TIMEZONE>
          The timezone to use for the TUI [default: auto]

          The timezone must be a valid IANA timezone identifier.

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
          The supported MaxMind or IPinfo GeoIp mmdb file

      --generate <GENERATE>
          Generate shell completion

          [possible values: bash, elvish, fish, powershell, zsh]

      --generate-man
          Generate ROFF man page

      --print-config-template
          Print a template toml config file and exit

      --print-locales
          Print all available TUI locales and exit

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

:::note
Trippy command line arguments may be given in any order and my occur both before and after the targets.
:::
