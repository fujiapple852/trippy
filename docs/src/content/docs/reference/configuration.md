---
title: Configuration Reference
description: A reference for customizing the Trippy configuration.
sidebar:
  order: 2
---

Trippy can be configured with via command line arguments or an optional configuration file. If a given configuration
item is specified in both the configuration file and via a command line argument then the latter will take precedence.

The configuration file location may be provided to Trippy via the `-c` (`--config-file`) argument. If not provided,
Trippy will attempt to locate a `trippy.toml` or `.trippy.toml` configuration file in one of the following locations:

- The current directory
- The user home directory
- the XDG config directory (Unix only): `$XDG_CONFIG_HOME` or `~/.config`
- the XDG app config directory (Unix only): `$XDG_CONFIG_HOME/trippy` or `~/.config/trippy`
- the Windows data directory (Windows only): `%APPDATA%`

A template configuration file
for [0.13.0](https://github.com/fujiapple852/trippy/blob/0.13.0/trippy-config-sample.toml) is available to
download, or can be generated with the following command:

```shell
trip --print-config-template > trippy.toml
```
