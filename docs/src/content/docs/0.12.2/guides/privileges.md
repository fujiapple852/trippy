---
title: Privileges
description: A reference for the Trippy privileges.
sidebar:
  order: 2
slug: 0.12.2/guides/privileges
---

Trippy normally requires elevated privileges due to the use of raw sockets. Enabling the required privileges for your
platform can be achieved in several ways, as outlined below. Trippy can also be used without elevated privileged on
certain platforms, with some limitations.

## Unix

1: Run as `root` user via `sudo`:

```shell
sudo trip example.com
```

2: `chown` `trip` as the `root` user and set the `setuid` bit:

```shell
sudo chown root $(which trip) && sudo chmod +s $(which trip)
```

3: [Linux only] Set the `CAP_NET_RAW` capability:

```shell
sudo setcap CAP_NET_RAW+p $(which trip)
```

:::note
Trippy is a capability aware application and will add `CAP_NET_RAW` to the effective set if it is present in the allowed
set. Trippy will drop all capabilities after creating the raw sockets.
:::

## Windows

Trippy must be run with Administrator privileges on Windows.

## Unprivileged mode

Trippy allows running in an unprivileged mode for all tracing modes (`ICMP`, `UDP` and `TCP`) on platforms which support
that feature.

:::note
Unprivileged mode is currently only supported on macOS. Linux support is possible and may be added in the future.
Unprivileged mode is not supported on NetBSD, FreeBSD or Windows as these platforms do not support the `IPPROTO_ICMP`
socket type. See [#101](https://github.com/fujiapple852/trippy/issues/101) for further information.
:::

The unprivileged mode can be enabled by adding the `--unprivileged` (`-u`) command line flag or by adding the
`unprivileged` entry in the `trippy` section of the [configuration file](/0.12.2/reference/configuration):

```toml
[trippy]
unprivileged = true
```

:::note
The `paris` and `dublin` `ECMP` strategies are not supported in unprivileged mode as these require manipulating the
`UDP` and `IP` and headers which in turn requires the use of a raw socket.
:::
