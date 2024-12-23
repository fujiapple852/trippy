---
title: Recommended Tracing Settings
description: Recommended settings for Trippy.
sidebar:
  order: 3
---

Trippy provides a variety of configurable features which can be used to perform different types of analysis. The choice
of settings will depend on the analysis you wish to perform and the environment in which you are working. This guide
lists some common options along with some basic guidance on when they might be appropriate.

:::note
The Windows `tracert` tool uses ICMP by default, whereas most Unix `traceroute` tools use UDP by default.
:::

## ICMP

By default Trippy will run an ICMP trace to the target. This will typically produce a consistent path to the target (a
single flow) for each round of tracing which makes it easy to read and analyse. This is a useful mode for general
network troubleshooting.

However, many routers are configured to rate-limit ICMP traffic which can make it difficult to get an accurate picture
of packet loss. In addition, ICMP traffic is not typically subject to ECMP routing and so may not reflect the path that
would taken by other protocols such as UDP and TCP.

To run a simple ICMP trace:

```shell
trip example.com
```

Due to the rate-limiting of ICMP traffic, some people prefer to hide the `Loss%` and `Recv` columns in the Tui as
these are easy to misinterpret.

```shell
trip example.com --tui-custom-columns hosavbwdt
```

These settings can be made permanent by adding them to the Trippy configuration file:

```toml
[tui]
custom-columns = "hosavbwdt"
```

:::note
The `Sts` column shows different color codes to reflect packet loss at intermediate vs the target hop, see the
[Column Reference](/reference/column) for more information.
:::

#### UDP/Dublin with fixed ports

UDP tracing provides a more realistic view of the path taken by traffic that is subject to ECMP routing.

Setting a fixed target port in the range 33434-33534 may allow Trippy to determine that the probe has reached the target
as many routers and firewalls are configured to allow UDP probes in that range and will respond with a Destination
Unreachable response.

However, running a UDP trace with a fixed target port and a variable source port will typically result in different
paths being followed for each probe within each round of tracing. This can make it difficult to interpret the output as
different hosts will reply for a given hop (time-to-live) across rounds.

By using the `dublin` ECMP strategy, which encodes the sequence number in the IP `identifier` field, Trippy can fix both
the source and target ports, typically resulting in a _single_ path for each probe within each round of tracing.

:::note
UDP/Dublin for IPv6 encodes the sequence number as the payload length as the IP `identifier` field is not available in
IPv6.
:::

:::note
Keep in mind that every probe is an _independent trial_ and each may traverse a completely different path. In practice,
ICMP probes often follow a single path, whereas the path of UDP and TCP probes is typically determined by the 5-tuple of
protocol, source and destination IP addresses and ports.

Also beware that the return path may not be the same as the forward path, and may also differ for each probe. Strategies
such as `dublin` and `paris` assist in controlling the path taken by the forward probes, but do not help control the
return path. Therefore it is recommended to run a trace in both directions to get a complete picture.
:::

To run a UDP trace with fixed source and target ports using the `dublin` ECMP strategy:

```shell
trip example.com --udp --multipath-strategy dublin --source-port 5000 --target-port 33434
```

:::note
The source port can be any valid port number, but the target port should usually be in the range 33434-33534 or whatever
range is open to UDP probes on the target host.
:::

These settings can be made permanent by adding them to the Trippy configuration file:

```toml
[strategy]
protocol = "udp"
multipath-strategy = "dublin"
source-port = 5000
target-port = 33434
```

## UDP/Dublin with fixed target port and variable source port

As an extension to the above, if you do not fix the source port when using the `dublin` ECMP strategy, Trippy will
vary the source port per _round_ of tracing (i.e. each probe within a given round will share the same source port, and
the source port will vary for each round). This will typically result in the _same_ path being followed for _each_ probe
within a given round, but _different_ paths being followed for each round.

These individual flows can be explored in the Trippy Tui by pressing the `toggle-flows` key binding (`f` key by
default).

Adding the columns `Seq`, `Sprt` and `Dprt` to the Tui will show the sequence number, source port and destination port
respectively which makes this easier to visualize.

```shell
trip example.com --udp --multipath-strategy dublin --target-port 33434 --tui-custom-columns holsravbwdtSPQ
```

These settings can be made permanent by adding them to the Trippy configuration file:

```toml
[strategy]
protocol = "udp"
multipath-strategy = "dublin"
target-port = 33434

[tui]
custom-columns = "holsravbwdtSPQ"
```

To make the flows easier to visualize, you can generate a Graphviz DOT file report of all tracing flows:

```shell
trip example.com --udp --multipath-strategy dublin --target-port 33434 -m dot -C 5
```

## UDP/Paris

UDP with the `paris` ECMP strategy offers the same benefits as the `dublin` strategy with fixed ports and can be used
in the same way.

They differ in the way they encode the sequence number in the probe. The `dublin` strategy uses the IP `identifier`
field, whereas the `paris` strategy uses the UDP `checksum` field.

To run a UDP trace with fixed source and target ports using the `paris` ECMP strategy:

```shell
trip example.com --udp --multipath-strategy paris --source-port 5000 --target-port 33434
```

The `paris` strategy does not work behind NAT as the UDP `checksum` field is typically modified by NAT devices.
Therefore the `dublin` strategy is recommended when NAT is present.

:::note
Trippy can detect the presence of NAT devices in some circumstances when using the `dublin` strategy and the `Nat`
column can be shown in the Tui to indicate when NAT is detected. See the [Column Reference](/reference/column) for more
information.
:::

#### TCP

TCP tracing is similar to UDP tracing in that it provides a more realistic view of the path taken by traffic that is
subject to ECMP routing.

TCP tracing defaults to using a target port of 80 and sets the source port as the sequence number which will typically
result in a different path being followed for each probe within each round of tracing.

To run a TCP trace:

```shell
trip example.com --tcp
```

TCP tracing is useful for diagnosing issues with TCP connections and higher layer protocols such as HTTP. Often UDP
tracing can be used in place of TCP to diagnose IP layer network issues and, as it provides ways to control the path
taken by the probes, it is often preferred.

:::note
Trippy does not support the `dublin` or `paris` ECMP strategies for TCP tracing and so you cannot fix both the source
and target ports. See the [tracking issue](https://github.com/fujiapple852/trippy/issues/274) for details.
:::
