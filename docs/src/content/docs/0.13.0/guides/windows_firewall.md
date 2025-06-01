---
title: Windows Defender Firewall
description: Allow incoming ICMP traffic in the Windows Defender firewall.
sidebar:
  order: 4
slug: 0.13.0/guides/windows_firewall
---

The Windows Defender firewall rule can be created using PowerShell.

```shell
New-NetFirewallRule -DisplayName "ICMPv4 Trippy Allow" -Name ICMPv4_TRIPPY_ALLOW -Protocol ICMPv4 -Action Allow
New-NetFirewallRule -DisplayName "ICMPv6 Trippy Allow" -Name ICMPv6_TRIPPY_ALLOW -Protocol ICMPv6 -Action Allow
```

The rules can be enabled as follows:

```shell
Enable-NetFirewallRule ICMPv4_TRIPPY_ALLOW
Enable-NetFirewallRule ICMPv6_TRIPPY_ALLOW
```

The rules can be disabled as follows:

```shell
Disable-NetFirewallRule ICMPv4_TRIPPY_ALLOW
Disable-NetFirewallRule ICMPv6_TRIPPY_ALLOW
```

There is a [step-by-step guide to manually configure the Windows Defender firewall rule](https://github.com/fujiapple852/trippy/issues/578#issuecomment-1565149826).
