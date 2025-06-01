---
title: Theme Reference
description: A reference for customizing the Trippy TUI theme.
sidebar:
  order: 5
slug: 0.13.0/reference/theme
---

The following table lists the default Tui color theme. These can be overridden with the `--tui-theme-colors` command
line option or in the `theme-colors` section of the configuration file.

| Item                                 | Description                                               | Default      |
| ------------------------------------ | --------------------------------------------------------- | ------------ |
| `bg-color`                           | The default background color                              | `Black`      |
| `border-color`                       | The default color of borders                              | `Gray`       |
| `text-color`                         | The default color of text                                 | `Gray`       |
| `tab-text-color`                     | The color of the text in traces tabs                      | `Green`      |
| `hops-table-header-bg-color`         | The background color of the hops table header             | `White`      |
| `hops-table-header-text-color`       | The color of text in the hops table header                | `Black`      |
| `hops-table-row-active-text-color`   | The color of text of active rows in the hops table        | `Gray`       |
| `hops-table-row-inactive-text-color` | The color of text of inactive rows in the hops table      | `DarkGray`   |
| `hops-chart-selected-color`          | The color of the selected series in the hops chart        | `Green`      |
| `hops-chart-unselected-color`        | The color of the unselected series in the hops chart      | `Gray`       |
| `hops-chart-axis-color`              | The color of the axis in the hops chart                   | `DarkGray`   |
| `frequency-chart-bar-color`          | The color of bars in the frequency chart                  | `Green`      |
| `frequency-chart-text-color`         | The color of text in the bars of the frequency chart      | `Gray`       |
| `flows-chart-bar-selected-color`     | The color of the selected flow bar in the flows chart     | `Green`      |
| `flows-chart-bar-unselected-color`   | The color of the unselected flow bar in the flows chart   | `DarkGray`   |
| `flows-chart-text-current-color`     | The color of the current flow text in the flows chart     | `LightGreen` |
| `flows-chart-text-non-current-color` | The color of the non-current flow text in the flows chart | `White`      |
| `samples-chart-color`                | The color of the samples chart                            | `Yellow`     |
| `samples-chart-lost-color`           | The color of the samples chart for lost probes            | `Red`        |
| `help-dialog-bg-color`               | The background color of the help dialog                   | `Blue`       |
| `help-dialog-text-color`             | The color of the text in the help dialog                  | `Gray`       |
| `settings-dialog-bg-color`           | The background color of the settings dialog               | `blue`       |
| `settings-tab-text-color`            | The color of the text in settings dialog tabs             | `green`      |
| `settings-table-header-text-color`   | The color of text in the settings table header            | `black`      |
| `settings-table-header-bg-color`     | The background color of the settings table header         | `white`      |
| `settings-table-row-text-color`      | The color of text of rows in the settings table           | `gray`       |
| `map-world-color`                    | The color of the map world diagram                        | `white`      |
| `map-radius-color`                   | The color of the map accuracy radius circle               | `yellow`     |
| `map-selected-color`                 | The color of the map selected item box                    | `green`      |
| `map-info-panel-border-color`        | The color of border of the map info panel                 | `gray`       |
| `map-info-panel-bg-color`            | The background color of the map info panel                | `black`      |
| `map-info-panel-text-color`          | The color of text in the map info panel                   | `gray`       |
| `info-bar-bg-color`                  | The background color of the information bar               | `white`      |
| `info-bar-text-color`                | The color of text in the information bar                  | `black`      |

The supported [ANSI colors](https://en.wikipedia.org/wiki/ANSI_escape_code#Colors) are:

- `Black`, `Red`, `Green`, `Yellow`, `Blue`, `Magenta`, `Cyan`, `Gray`, `DarkGray`, `LightRed`, `LightGreen`,
  `LightYellow`, `LightBlue`, `LightMagenta`, `LightCyan`, `White`

In addition, CSS [named colors](https://developer.mozilla.org/en-US/docs/Web/CSS/named-color) (i.e. SkyBlue) and raw hex
values (i.e. ffffff) may be used but note that these are only supported on some platforms and terminals and may not
render correctly elsewhere.

Color names are case-insensitive and may contain dashes.
