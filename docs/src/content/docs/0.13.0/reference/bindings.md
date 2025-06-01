---
title: Key Bindings Reference
description: A reference for customizing the Trippy TUI key bindings.
sidebar:
  order: 3
slug: 0.13.0/reference/bindings
---

The following table lists the default Tui command key bindings. These can be overridden with the `--tui-key-bindings`
command line option or in the `bindings` section of the configuration file.

| Command                    | Description                                     | Default   |
| -------------------------- | ----------------------------------------------- | --------- |
| `toggle-help`              | Toggle help                                     | `h`       |
| `toggle-help-alt`          | Toggle help (alternative binding)               | `?`       |
| `toggle-settings`          | Toggle settings                                 | `s`       |
| `toggle-settings-tui`      | Open settings (Tui tab)                         | `1`       |
| `toggle-settings-trace`    | Open settings (Trace tab)                       | `2`       |
| `toggle-settings-dns`      | Open settings (Dns tab)                         | `3`       |
| `toggle-settings-geoip`    | Open settings (GeoIp tab)                       | `4`       |
| `toggle-settings-bindings` | Open settings (Bindings tab)                    | `5`       |
| `toggle-settings-theme`    | Open settings (Theme tab)                       | `6`       |
| `toggle-settings-columns`  | Open settings (Columns tab)                     | `7`       |
| `next-hop`                 | Select next hop                                 | `down`    |
| `previous-hop`             | Select previous hop                             | `up`      |
| `next-trace`               | Select next trace                               | `right`   |
| `previous-trace`           | Select previous trace                           | `left`    |
| `next-hop-address`         | Select next hop address                         | `.`       |
| `previous-hop-address`     | Select previous hop address                     | `,`       |
| `address-mode-ip`          | Show IP address only                            | `i`       |
| `address-mode-host`        | Show hostname only                              | `n`       |
| `address-mode-both`        | Show both IP address and hostname               | `b`       |
| `toggle-freeze`            | Toggle freezing the display                     | `ctrl+f`  |
| `toggle-chart`             | Toggle the chart                                | `c`       |
| `toggle-map`               | Toggle the GeoIp map                            | `m`       |
| `toggle-flows`             | Toggle the flows                                | `f`       |
| `expand-privacy`           | Expand hop privacy                              | `p`       |
| `contract-privacy`         | Contract hop privacy                            | `o`       |
| `expand-hosts`             | Expand the hosts shown per hop                  | `]`       |
| `expand-hosts-max`         | Expand the hosts shown per hop to the maximum   | `}`       |
| `contract-hosts`           | Contract the hosts shown per hop                | `[`       |
| `contract-hosts-min`       | Contract the hosts shown per hop to the minimum | `{`       |
| `chart-zoom-in`            | Zoom in the chart                               | `=`       |
| `chart-zoom-out`           | Zoom out the chart                              | `-`       |
| `clear-trace-data`         | Clear all trace data                            | `ctrl+r`  |
| `clear-dns-cache`          | Flush the DNS cache                             | `ctrl+k`  |
| `clear-selection`          | Clear the current selection                     | `esc`     |
| `toggle-as-info`           | Toggle AS info display                          | `z`       |
| `toggle-hop-details`       | Toggle hop details                              | `d`       |
| `quit`                     | Quit the application                            | `q`       |
| `quit-preserve-screen`     | Quit the application and preserve the screen    | `shift+q` |

The supported modifiers are: `shift`, `ctrl`, `alt`, `super`, `hyper` & `meta`. Multiple modifiers may be specified, for
example `ctrl+shift+b`.
