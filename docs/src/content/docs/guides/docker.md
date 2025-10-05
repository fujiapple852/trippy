---
title: Run Trippy with Docker
description: Learn how to run the Trippy CLI from the official Docker image.
sidebar:
  order: 5
---

Trippy is distributed as the [`fujiapple/trippy`](https://hub.docker.com/r/fujiapple/trippy/) image on Docker Hub. The
image bundles the `trip` binary compiled against Alpine Linux and configures it as the container entrypoint.

## Quick start

Run the image interactively and pass any CLI arguments directly after the image name:

:::note
Because the entrypoint already invokes `trip`, you should not repeat the binary name.
:::

```shell
docker run -it --rm fujiapple/trippy example.com
```

To display the built-in help you can pass standard flags:

```shell
docker run -it --rm fujiapple/trippy --help
```

## Configuration

To provide a configuration file, mount host directories into the root of the container:

```shell
docker run -it --rm -v "/path/to/trippy.toml:/trippy.toml" fujiapple/trippy example.com
```

## Networking considerations

Trippy uses raw sockets to send probes. On Linux hosts Docker grants the required `CAP_NET_RAW` capability by
default, so no additional flags are needed.

When running inside more restrictive container runtimes ensure that the container retains this capability:

```shell
docker run -it --rm --cap-add=NET_RAW fujiapple/trippy example.com
```

:::caution
Docker Desktop for macOS has a known limitations with raw sockets. In particular, it resets the `ttl` field on outgoing
packets to 64. As a result, intermediate hops are not discovered when tracing from a macOS host via Docker.
:::
