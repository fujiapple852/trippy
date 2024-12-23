---
title: Frequently Asked Questions
description: Frequently asked questions about Trippy.
sidebar:
  order: 5
---

## Why does Trippy show "Awaiting data..."?

:::caution
If you are using Windows you _must_ [configure](/guides/windows_firewall)
the Windows Defender firewall to allow incoming ICMP traffic
:::

When Trippy shows “Awaiting data...” it means that it has received zero responses for the probes sent in a trace. This
indicates that either probes are not being sent or, more typically, responses are not being received.

Check that local and network firewalls allow ICMP traffic and that the system `traceroute` (or `tracert.exe` on
Windows) works as expected. Note that on Windows, even if `tracert.exe` works as expected, you
_must_ [configure](/guides/windows_firewall) the Windows Defender
firewall to allow incoming ICMP traffic.

For deeper diagnostics you can run tools such as https://www.wireshark.org and https://www.tcpdump.org to verify that
icmp requests and responses are being send and received.

<a name="windows-defender"></a>
