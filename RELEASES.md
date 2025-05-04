# Release Notes

Release notes for Trippy 0.6.0 onwards. See also the [CHANGELOG](CHANGELOG.md).

# 0.13.0

## Highlights

The 0.13.0 release of Trippy includes several enhancements related to Type of Service (`ToS`) and adds new `Dscp` and
`Ecn` columns.

It also includes improvements to the TUI such as allowing a custom timezone to be set and adding the ability to read the
configuration file from the XDG app config directory. The `json` report has been enriched with start and end timestamps.

This release includes a number of bug fixes. For Windows users in particular, this release includes several important
stability improvements.

The release also introduces a new `system` address family option, which will become the new default in the next major
release.

Finally, Trippy now has a dedicated website and a logo!

### Type of Service (DSCP/ECN) Improvements

Trippy allows setting the Type of Service (`ToS`) for IPv4 via the `--tos` (`-Q`) command-line argument (or via the
configuration file). The `ToS` value is the second byte of the `IPv4` header and encodes the Differentiated Services
Code Point (`DSCP`) and Explicit Congestion Notification (`ECN`) fields.

Setting the `ToS` on outgoing probe packets can influence the Quality of Service (`QoS`) used by the network devices
along the path.

Probe responses received from the hops along the path include the `ToS` values in the Original Datagram (the `IPv4`/
`IPv6` header of the probe packet nested inside the `ICMP` error). Examining the `ToS` value from the Original Datagram
can provide useful insight into the `QoS` treatment of the probe packets by network devices along the path.

This release of Trippy adds two new columns to display the `DSCP` & `ECN` values, which are derived from the `ToS` value
from the Original Datagram for each hop. The new columns are:

- `Dscp` (`K`): The Differentiated Services Code Point (`DSCP`) of the Original Datagram for a hop
- `Ecn` (`M`): The Explicit Congestion Notification (`ECN`) of the Original Datagram for a hop

The `Dscp` and `Ecn` columns are decoded from the `ToS` field of the Original Datagram. If no `ToS` value is present,
then the columns will show `na`. Note that these columns show the most recent `ToS` value received from the hop and
may therefore change between rounds.

Well-known `DSCP` values are displayed as follows:

- Default Forwarding (`DF`) aka Best Effort aka Class Selector 0 (`CS0`)
- Assured Forwarding (`AFn`)
- Class Selector (`CSn`)
- High Priority Expedited Forwarding (`EF`)
- Voice Admit (`VA`)
- Lower Effort (`LE`)

Unknown `DSCP` values are displayed as a hexadecimal value.

The `ECN` value is displayed as follows:

- Not ECN-Capable Transport (`NotECT`)
- ECN Capable Transport(1) (`ECT1`)
- ECN Capable Transport(0) (`ECT0`)
- Congestion Experienced (`CE`)

These columns are hidden by default but can be enabled as needed. For more details, see
the [Column Reference](https://trippy.rs/reference/column).

The following example sets the `ToS` to be `224`, which is a `DSCP` value of `CS7` (0x38) and an `ECN` value of
`NotECT` (0x0), and enables the new columns:

```shell
trip example.com --tos 224 --tui-custom-columns holsravbwdtKM
```

The following screenshot shows the example trace:

<img width="60%" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.13.0/dscp_ecn.png"/>

The `ToS` field of the Original Datagram has also been added to the `json` output format as a decimal value.

See [#1539](https://github.com/fujiapple852/trippy/issues/1539) for details.

This release also adds support for setting the `IPv6` Traffic Class (which encodes the `DSCP` & `ECN` values in the same
way as `IPv4`) via the same `--tos` (`-Q`) command-line argument (or via the configuration file). Note that setting the
`IPv6` Traffic Class is not currently supported on Windows.
See [#202](https://github.com/fujiapple852/trippy/issues/202) for details.

Finally, a bug which caused the `--tos` (`-Q`) command-line argument to be ignored for `IPv4/UDP` tracing has been
fixed in this release. See [#1540](https://github.com/fujiapple852/trippy/issues/1540) for details.

### Custom TUI Timezone

Trippy shows the wall-clock time in the header of the TUI. Currently, this is set to show the local timezone of the
system running Trippy. This can be problematic for users who are running Trippy in a container or on a remote system
that uses a different timezone.

This release adds the ability to set a custom timezone for the TUI using the `--tui-timezone` command-line argument (or
via the configuration file). The timezone can be set to any valid IANA timezone identifier, such as `UTC`,
`America/New_York`, or `Europe/London`.

The following example sets the timezone to `UTC`:

```shell
trip example.com --tui-timezone UTC
```

This can be made permanent by setting the `tui-timezone` value in the `tui` section of the configuration file:

```toml
[tui]
tui-timezone = "UTC"
```

See [#1513](https://github.com/fujiapple852/trippy/issues/1513) for details.

### XDG App Config Directory

Trippy will now attempt to locate a `trippy.toml` or `.trippy.toml` config file in the XDG app config directory
(i.e. `$XDG_CONFIG_HOME/trippy` or `~/.config/trippy`) in addition to existing locations.

This allows users to store their Trippy configuration files in a dedicated directory for Trippy, separate from other
applications.

The full list of locations Trippy will check for a `trippy.toml` or `.trippy.toml` config file is as
follows:

- the current directory
- the user home directory
- the XDG config directory (Unix only): `$XDG_CONFIG_HOME` or `~/.config`
- the XDG app config directory (Unix only): `$XDG_CONFIG_HOME/trippy` or `~/.config/trippy`
- the Windows data directory (Windows only): `%APPDATA%`

See [#1528](https://github.com/fujiapple852/trippy/issues/1528) for details.

### System Address Family

Trippy supports tracing for both `IPv4` and `IPv6` address families. If the tracing target is supplied as a hostname,
Trippy will attempt to resolve the hostname to a single `IPv4` or `IPv6` address. If the hostname resolves to both,
Trippy will use the address family (`--addr-family`) configuration to determine which address family
to use.

The possible values for `--addr-family` are:

- `ipv4` - Lookup IPv4 only
- `ipv6` - Lookup IPv6 only
- `ipv6-then-ipv4` - Lookup IPv6 with a fallback to IPv4
- `ipv4-then-ipv6` - Lookup IPv4 with a fallback to IPv6 [default]

The current default value for `--addr-family` is `ipv4-then-ipv6`, which means that if the hostname resolves to both
`IPv4` and `IPv6` addresses, Trippy will prefer the `IPv4` address family.

Some users find the default behavior undesirable, as it can lead to unexpected results when the hostname resolves to a
different address family than the one used by other applications on the system.

This release adds a new value for `--addr-family` called `system`. This value defers the choice of address family to the
first address returned by OS resolver. This means that if the hostname resolves to both `IPv4` and `IPv6` addresses, the
OS resolver will determine which address family to use based on the OS configuration.

Note that if the `--addr-family` value is set to `system` and the `--dns-resolve-method` is set to any value _other_
than `system` (i.e. `resolv`, `cloudflare` or `google`), then the address family lookup will effectively default to
`ipv6-then-ipv4`.

> **Important**: The default value for `--addr-family` will change to become `system` in the next major release of
> Trippy (0.14.0). This will be a breaking change for users who rely on the current default value of `ipv4-then-ipv6`.

See [#1469](https://github.com/fujiapple852/trippy/issues/1469) for details.

### Remove Address Family "downgrade" for Dublin Strategy

Currently, the address families `ipv4-then-ipv6` and `ipv6-then-ipv4` are silently _downgraded_ to `ipv4` when the
`dublin` ECMP strategy is used. This behaviour was previously necessary, as Trippy did not support the `dublin` ECMP
strategy for `IPv6`. However, Trippy has supported the `dublin` ECMP strategy for `IPv6` since version 0.10.0. As a
result, this release removes the address family _downgrade_ for the `dublin` ECMP strategy.

See [#1476](https://github.com/fujiapple852/trippy/issues/1476) for details.

### Windows Stability Improvements

This release includes several stability improvements for Windows. It fixes several known or potential issues that
could cause crashes or memory corruption. It is recommended that all Windows users upgrade to this release.

See the following issues for details:

- Memory corruption on Windows ([#1527](https://github.com/fujiapple852/trippy/issues/1527))
- Socket being closed twice on Windows ([#1443](https://github.com/fujiapple852/trippy/issues/1443))
- Potential crash on Windows for adapters without unicast
  addresses ([#1547](https://github.com/fujiapple852/trippy/issues/1547))
- Potential use-after-free when discovering source address on
  Windows ([#1558](https://github.com/fujiapple852/trippy/issues/1558))

### Start and End Timestamps in JSON report

The Trippy `json` report mode has been enhanced to show the start and end timestamps for the trace. These timestamps are
shown in UTC using RFC 3339 format.

The following example runs a trace to `example.com` for a single round and outputs the results in `json` format:

```shell
trip example.com -m json -C 1
```

The `info` section of the output now includes the `start_timestamp` and `end_timestamp` fields:

```json
{
  "info": {
    "target": {
      "ip": "23.192.228.80",
      "hostname": "example.com"
    },
    "start_timestamp": "2025-05-04T09:50:10.383221Z",
    "end_timestamp": "2025-05-04T09:50:11.392039Z"
  }
}
```

See [#1510](https://github.com/fujiapple852/trippy/issues/1510) for details.

### Reduce Tracing Verbosity

The `trippy-core` crate logging is overly verbose. This release reduces all `#[instrument]` annotations from the default
`info` level to the `trace` level. It also removes some tracing annotations and, in some cases, adds new ones.

There are now no `info` level logs and only a handful of `debug` level logs:

- Log the channel config when a channel is created (typically just once)
- Log the strategy config when the tracer is started (typically just once)
- Log each probe sent and received during a round (typically a handful per round)

For application users there is no change; however the default logging level (`--log-filter trippy=debug`) used when `-v`
is passed will now show substantially fewer logs. Users can set `--log-filter trippy=trace` to see a logging level
similar to the previous default.

See [#1482](https://github.com/fujiapple852/trippy/issues/1482) for details.

### Bug Fixes

This release fixes a bug where ICMP packets larger than 256 bytes could cause a tracer panic.
See [#1561](https://github.com/fujiapple852/trippy/issues/1561) for details.

It also adds a handful of missing configuration options to the settings dialog.
See [#1541](https://github.com/fujiapple852/trippy/issues/1541) for details.

### Trippy Website & Logo

Trippy now has a dedicated website: https://trippy.rs

The website is now the primary source of documentation. My thanks to @orhun for building the https://binsider.dev
website which I ~~took inspiration from~~ shamelessly copied for Trippy.

Along with the new website, Trippy (finally!) has a logo:

<img src="https://raw.githubusercontent.com/fujiapple852/trippy/master/docs/src/assets/Trippy-Vertical-DarkMode.svg#gh-dark-mode-only" width="200">
<img src="https://raw.githubusercontent.com/fujiapple852/trippy/master/docs/src/assets/Trippy-Vertical.svg#gh-light-mode-only" width="200"><br>

With thanks to [Harun Ocaksiz Design](https://www.instagram.com/harunocaksiz).

See [#100](https://github.com/fujiapple852/trippy/issues/100) for details.

### New Distribution Packages

Trippy has been added to the Void Linux package repository (with thanks to @icp1994!):

[![Void Linux x86_64 package](https://repology.org/badge/version-for-repo/void_x86_64/trippy.svg)](https://github.com/void-linux/void-packages/tree/master/srcpkgs/trippy)

```shell
xbps-install -S trippy
```

Trippy was also added to ALT Sisyphus package repository (with thanks
to [Aleksandr Voyt](https://packages.altlinux.org/en/sisyphus/maintainers/sobue)!)

[![ALT Sisyphus package](https://repology.org/badge/version-for-repo/altsisyphus/trippy.svg)](https://packages.altlinux.org/en/sisyphus/srpms/trippy/)

```shell
apt-get install trippy
```

Finally, Trippy has been added to the Chimera Linux package repository (with thanks to @ttyyls!):

[![Chimera Linux package](https://repology.org/badge/version-for-repo/chimera/trippy.svg)](https://github.com/chimera-linux/cports/tree/master/user/trippy)

```shell
apk add trippy
```

### Thanks

My thanks to all Trippy contributors, package maintainers, translators and community members.

Feel free to drop by the Trippy Zulip room for a chat:

[![project chat](https://img.shields.io/badge/zulip-join_chat-brightgreen.svg)](https://trippy.zulipchat.com/)

Happy Tracing!

# 0.12.2

## Highlights

This maintenance release of Trippy fixes a bug introduced in 0.12.0 which causes a tracer panic if `--first-ttl` is
set to be greater than one. The release also addresses a longstanding bug which causes `--dns-resolve-method resolv` to
ignore any value provided for `--addr-family` and therefore always use the default value of `ipv4`. Finally the help
text for `--addr-family` has been corrected.

See the main [0.12.0](https://github.com/fujiapple852/trippy/releases/tag/0.12.0) release note.

# 0.12.1

## Highlights

This maintenance release of Trippy fixes a bug which prevented translations from working in Docker and also divests all
internal use of `yaml` dependencies which were problematic to maintain on some platforms (thanks to @nc7s).

See the main [0.12.0](https://github.com/fujiapple852/trippy/releases/tag/0.12.0) release note.

# 0.12.0

## Highlights

The latest release of Trippy brings both cosmetic and functional improvements to the TUI, new columns, new distribution
packages, and a number of bug fixes.

The TUI has been updated to include a new _information bar_ at the bottom of the screen which allows for the header to
be shortened and simplified. The sample history chart has been enhanced to highlight missing probes and the presentation
of source and target addresses has also been simplified.

As well as these cosmetic changes, the TUI has gained support for internationalization (i18n) and the ability to
adjust the hop privacy setting dynamically.

This release introduces three new columns, which provide novel heuristics for measuring _forward loss_ and _backward
loss_, that are designed to assist users in interpreting the status of the trace.

Finally, this update includes new distribution packages for Debian and Ubuntu and addresses a number of bugs.

### TUI Information Bar

The TUI now includes an _information bar_ at the bottom of the screen, replacing the previous `Config` line in the
header. This change shortens the header by one line, optimizing space usage while keeping the overall vertical space of
the TUI unchanged.

The main TUI screen now appears as shown below (120x40 terminal size):

<img width="60%" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.12.0/main_screen.png"/>

The left-hand side of the information bar displays a selection of static configuration items (in order):

- The address family and tracing protocol, e.g., `IPv4/ICMP`
- The privilege level, either `privileged` or `unprivileged`
- The locale, e.g., English (`en`), French (`fr`), etc.

The right-hand side of the information bar displays a selection of adjustable configuration items (in order):

- A toggle controlling whether `ASN` information is displayed (`□ ASN` for disabled, `■ ASN` for enabled)
- A toggle controlling whether hop detail mode is enabled (`□ detail` for disabled, `■ detail` for enabled)
- A toggle controlling whether hostnames, IP addresses, or both are displayed (`host`, `ip`, or `both`)
- The maximum `ttl` value for hop privacy, shown as `-` (privacy disabled) or a number (0, 1, 2, etc.)
- The maximum number of hosts displayed per hop, shown as `-` (automatic) or a number (1, 2, etc.)

In the above screenshot, the information bar indicates the trace is using `IPv4/ICMP`, is running in `privileged` mode,
the locale is English (`en`), `ASN` information is displayed, hop detail mode is disabled, hostnames are displayed, the
hop privacy maximum `ttl` is 2, and the maximum number of hosts per hop is set to automatic.

> **Note**: The information bar displays only a small number of important settings. All other settings can be viewed in
> the settings dialog, which can be opened by pressing `s` (default key binding).

The theme colors of the information bar can be customized using the `info-bar-bg-color` and `info-bar-text-color` theme
items. Refer to the [Theme Reference](https://github.com/fujiapple852/trippy#theme-reference) for more details.

Thanks to @c-git for their valuable feedback in refining the design of the information bar.

See [#1349](https://github.com/fujiapple852/trippy/issues/1349) for details.

### Sample History Missing Probes

Trippy displays a history of samples for each hop as a chart at the bottom of the TUI display. Each vertical line in the
chart corresponds to one sample, representing the value of the `Last` column.

Previously, if a probe was lost, the sample for that round would be shown as a blank vertical line. Starting with this
release, Trippy now highlights lost probes using a full vertical line in red (default theme color), making them easier
to identify.

<img width="60%" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.12.0/lost_probes.png"/>

The theme color for regular samples can be configured using the existing `samples-chart-color` configuration option.
Additionally, the theme color for lost probes can now be customized using the new `samples-chart-lost-color`
configuration option. For more details, see
the [Theme Reference](https://github.com/fujiapple852/trippy#theme-reference).

See [#1247](https://github.com/fujiapple852/trippy/issues/1247) for further details.

### Source and Target Address Display Improvements

This release simplifies the display of the source and target addresses in the `Target` line in the header of the TUI.

The `Target` line has been updated such that, for both the source and destination addresses, the hostname is only shown
if it differs from the IP address.

For the destination address:

- If the user supplies a target hostname, it is resolved to an IP address, and both the IP address and the _provided_
  hostname are shown.
- If the user supplies an IP address, a reverse DNS hostname lookup is attempted. If successful, both the IP address and
  the _first resolved_ hostname are shown; otherwise, only the IP address is displayed.

For the source address:

- A reverse DNS hostname lookup is attempted. If successful, both the IP address and the _first resolved_ hostname are
  shown; otherwise, only the IP address is displayed.

For example, when the user supplies an IP address as the tracing target, the `Target` line in the header is now shown as
follows:

```
Target: 192.168.1.21 -> 93.184.215.14 (example.com)
```

See [#1363](https://github.com/fujiapple852/trippy/issues/1363) for details.

### Adjustable Hop Privacy Mode Settings

Trippy includes a privacy feature designed to hide sensitive information, such as IP addresses and GeoIP data, for all
hops up to a configurable maximum `ttl` via the `tui-privacy-max-ttl` configuration option.

Previously, the privacy feature could only be toggled on or off within the TUI using the `toggle-privacy` command and
only if `tui-privacy-max-ttl` was configured _before_ Trippy was started.

In this release, the `toggle-privacy` command has been deprecated and replaced by two new TUI commands,
`expand-privacy` (bound to the `p` key by default) and `contract-privacy` (bound to the `o` key by default).

The `expand-privacy` command increases the `tui-privacy-max-ttl` value up to the maximum number of hops in the current
trace and the `contract-privacy` command decreases the `tui-privacy-max-ttl` value to the minimum value, which disables
privacy mode.

See [#1347](https://github.com/fujiapple852/trippy/issues/1347) for more details.

This release also repurposes the meaning of `tui-privacy-max-ttl` when set to `0`. Previously, a value of `0` indicated
that no hops should be hidden. Starting from this release, a value of `0` will indicate that the source of the trace, as
shown in the `Target` line of the header, should be hidden.

Values of `1` or greater retain their existing behavior but will now also hide the source of the trace in addition to
the specified number of hops.

As a result of this change, the default value for `tui-privacy-max-ttl` has been updated:

- If not explicitly set (via a command-line argument or the configuration file), nothing will be hidden by default.
- If explicitly set to `0` (the previous default), the source of the trace will be hidden.

See [#1365](https://github.com/fujiapple852/trippy/issues/1365) for details.

### Preserve Screen on Exit

Trippy previously supported the `--tui-preserve-screen` command-line flag, which could be used to prevent the terminal
screen from being cleared when Trippy exits. This feature is useful for users who wish to review trace results after
exiting the application. However, the flag had to be set before starting Trippy and could not be toggled during a trace.

This release introduces the `quit-preserve-screen` TUI command (bound to the `shift+q` key by default). This command
allows users to quit Trippy without clearing the terminal screen, regardless of whether the `--tui-preserve-screen` flag
is set.

See [#1382](https://github.com/fujiapple852/trippy/issues/1382) for details.

### TUI Internationalization (i18n)

The Trippy TUI has been translated into multiple languages. This includes all text displayed in the TUI across all
screens and dialogs, as well as GeoIP location data shown on the world map.

The TUI will automatically detect the system locale and use the corresponding translations if available. The locale can
be overridden using the `--tui-locale` configuration option.

Locales can be specified for a language or a combination of language and region. For example a general locale can be
created for English (`en`) and specific regional locales can be created, such as United Kingdom English (`en-UK`) and
United States English (`en-US`).

If the user's chosen full locale (`language-region`) is not available, Trippy will fall back to using the locale for the
language only, if it exists. For example if the user sets the locale to `en-AU`, which is not currently defined in
Trippy, it will fall back to the `en` locale, which is defined.

If the user's chosen locale does not exist at all, Trippy will fall back to English (`en`).

Locales are generally added for the language only unless there is a specific need for region-based translations.

Some caveats to be aware of:

- The configuration file, command-line options, and most error messages are not translated.
- Many common abbreviated technical terms, such as `IPv4` and `ASN`, are not translated.

The following example sets the TUI locale to be Chinese (`zh`):

```shell
trip example.com --tui-locale zh
```

This can be made permanent by setting the `tui-locale` value in the `tui` section of the configuration file:

```toml
[tui]
tui-locale = "zh"
```

The following screenshot shows the TUI with the locale set to Chinese (`zh`):

<img width="60%" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.12.0/help_screen_zh.png"/>

The list of available locales can be printed using the `--print-locales` flag:

```shell
trip --print-locales
```

As of this release, the following locales are available:

- Chinese (`zh`)
- English (`en`)
- French (`fr`)
- German (`de`)
- Italian (`it`)
- Portuguese (`pt`)
- Russian (`ru`)
- Spanish (`es`)
- Swedish (`sv`)
- Turkish (`tr`)

See [#1319](https://github.com/fujiapple852/trippy/issues/1319), [#1357](https://github.com/fujiapple852/trippy/issues/1357), [#1336](https://github.com/fujiapple852/trippy/issues/1336)
and the [Locale Reference](https://github.com/fujiapple852/trippy#locale-reference) for more details.

Corrections to existing translations or the addition of new translations are always welcome. See
the [tracking issue](https://github.com/fujiapple852/trippy/issues/506) for the status of each translation and details
on how to contribute.

Adding these translations has been a significant effort and I would like to express a huge _thank you_ (谢谢! Merci!
Danke! Grazie! Obrigado! Спасибо! Gracias! Tack! Teşekkürler!) to @0323pin, @arda-guler, @histrio, @josueBarretogit,
@one, @orhun, @peshay, @ricott1, @sxyazi, @ulissesf, and @zarkdav for all of their time and effort adding and reviewing
translations for this release.

### Forward and Backward Packet Loss Heuristics

In line with most classic traceroute tools, Trippy displays the number of probes sent (`Snd`), received (`Recv`), and a
loss percentage (`Loss%`) for each hop. However, many routers are configured to rate-limit or even drop ICMP traffic.
This can lead to false positives for packet loss, particularly for intermediate hops, as the lack of a response from
such hops does not typically indicate genuine packet loss. This is a common source of confusion for users interpreting
trace results.

Trippy already provides a color-coded status column (`Sts`), that considers both packet loss percentage and whether the
hop is the target of the trace, to try and assist users in interpreting the status of each hop. While this feature is
helpful, it does not make it clear _why_ a hop has a particular status nor help users interpret the overall status of
the trace.

To further assist users, this release of Trippy introduces a pair of novel heuristics to measure _forward loss_ and
_backward loss_. Informally, _forward loss_ indicates whether the loss of a probe is the _cause_ of subsequent losses
and _backward loss_ indicates whether the loss of a probe is the _result_ of a prior loss on the path.

More precisely:

- _forward loss_ for probe `P` in round `R` occurs when probe `P` is lost in round `R` and _all_ subsequent probes
  within round `R` are also lost.
- _backward loss_ for probe `P` in round `R` occurs when probe `P` is lost in round `R` and _any_ prior probe within
  round `R` has _forward loss_.

These heuristics are encoded in three new columns:

- `Floss` (`F`): The number of probes with _forward loss_
- `Bloss` (`B`): The number of probes with _backward loss_
- `Floss%` (`D`): The percentage of probes with _forward loss_

These columns are hidden by default but can be enabled as needed. For more details, see
the [Column Reference](https://github.com/fujiapple852/trippy#column-reference).

The following screenshot shows an example trace with the new columns enabled:

<img width="60%" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.12.0/floss_bloss.png"/>

In the following (contrived) example, after initially discovering the target (`10.0.0.105`) during the first round,
genuine packet loss occurs in _all_ subsequent rounds at the third hop. This means that no probes on the common path are
able to get beyond the third hop.

```
╭Hops───────────────────────────────────────────────────────────────╮
│#    Host         Loss%    Snd     Recv    Floss   Bloss   Floss%  │
│1    10.0.0.101   0.0%     96      96      0       0       0.0%    │
│2    10.0.0.102   0.0%     96      96      0       0       0.0%    │
│3    No response  100.0%   96      0       95      0       98.9%   │
│4    No response  100.0%   96      0       0       95      0.0%    │
│5    10.0.0.105   99.0%    96      1       0       95      0.0%    │
```

From this we can determine that the loss at the third hop is classified as _forward loss_ because all subsequent
probes (4th and 5th) in the same round are also lost. We can also conclude that the 4th and 5th hops have _backward
loss_ starting from round two, as in those rounds a prior hop (the third hop) has _forward loss_.

Note the difference between the traditional `Loss%` column and the new `Floss%` column. The `Loss%` column indicates
packet loss at several hops (3rd, 4th, and 5th). In contrast, the `Floss%` column helps us determine that the true
packet loss most likely occurs at the 3rd hop.

It is important to stress that this technique is a _heuristic_, and both _false positives_ and _false negatives_ are
possible. Some specific caveats to be aware of include:

- Every probe sent in every round is an _independent trial_, meaning there is no guarantee that all probes within a
  given round will follow the same path (or "flow"). The concept of "forward loss" and "backward loss" assumes that all
  probes followed a single path. This assumption is typically met (but not guaranteed) when using tracing strategies
  such as ICMP, UDP/Dublin, or UDP/Paris.
- Any given host on the path may drop packets for only a subset of probes sent within a round, either due to rate
  limiting or genuine intermittent packet loss. This could result in a false positive for "forward loss" at a given hop
  if all subsequent hops in the round exhibit packet loss that is not genuine. For example, in the scenario above, the
  hop with `ttl=3` could be incorrectly deemed to have "forward loss" if observed loss from hops `ttl=4` and `ttl=5` is
  not genuine (e.g., caused by rate-limiting).
- A false positive for "backward loss" could occur at a hop experiencing genuine packet loss if a previous hop on the
  path has "forward loss" that is not genuine. In the scenario above, if the hop with `ttl=4` has genuine packet loss,
  it will still be marked with "backward loss" due to the "forward loss" at `ttl=3`.

Despite these caveats, the addition of _forward loss_ and _backward loss_ heuristics aims to help users more accurately
interpret trace outputs. However, these heuristics should be considered experimental and may be subject to change in
future releases.

See [#860](https://github.com/fujiapple852/trippy/issues/860) for details.

### Bug Fixes

The previous release of Trippy introduced a bug ([#1290](https://github.com/fujiapple852/trippy/issues/1290)) that
caused reverse DNS lookups to be enqueued multiple times when the `dns-ttl` expired, potentially leading to the hostname
being displayed as `Timeout: xxx` for a brief period.

A long-standing bug ([#1398](https://github.com/fujiapple852/trippy/issues/1398)) which caused the TUI sample history
and frequency charts to ignore sub-millisecond samples has been fixed.

This release fixes a bug ([#1287](https://github.com/fujiapple852/trippy/issues/1287)) that caused the tracer to panic
when parsing certain ICMP extensions with malformed lengths.

It also resolves an issue ([#1289](https://github.com/fujiapple852/trippy/issues/1289)) where the ICMP extensions mode
was not being displayed in the TUI settings dialog.

A bug ([#1375](https://github.com/fujiapple852/trippy/issues/1375)) that caused the cursor to not move to the bottom of
the screen when exiting while preserving the screen has also been fixed.

Finally, this release fixes a bug ([#1327](https://github.com/fujiapple852/trippy/issues/1327)) that caused Trippy to
incorrectly reject the value `ip` for the `tui-address-mode` configuration option (thanks to @c-git).

### New Distribution Packages

Trippy is now available in Debian 13 (`trixie`) and later (with thanks to @nc7s!).

[![Debian 13 package](https://repology.org/badge/version-for-repo/debian_13/trippy.svg)](https://tracker.debian.org/pkg/trippy)

```shell
apt install trippy
```

See ([#1312](https://github.com/fujiapple852/trippy/issues/1312)) for details.

The official Trippy PPA for Ubuntu is now also available for the `noble` distribution.

[![Ubuntu PPA](https://img.shields.io/badge/Ubuntu%20PPA-0.12.0-brightgreen)](https://launchpad.net/~fujiapple/+archive/ubuntu/trippy/+packages)

```shell
sudo add-apt-repository ppa:fujiapple/trippy
sudo apt update && apt install trippy
```

See ([#1308](https://github.com/fujiapple852/trippy/issues/1308)) for details.

You can find the full list of [distributions](https://github.com/fujiapple852/trippy/tree/master#distributions) in the
documentation.

### Thanks

My thanks to all Trippy contributors, package maintainers, translators and community members.

Feel free to drop by the Trippy Zulip room for a chat:

[![project chat](https://img.shields.io/badge/zulip-join_chat-brightgreen.svg)](https://trippy.zulipchat.com/)

Happy Tracing!

# 0.11.0

## Highlights

This release of Trippy adds NAT detection for IPv4/UDP/Dublin tracing, a new public API, reverse DNS lookup cache
time-to-live, transient error handling for IPv4, a new ROFF manual page generator, several new columns, improved error
messages and a revamped help dialog with settings tab hotkeys.

There are two breaking changes, a new initial sequence number is used which impacts the default behavior of UDP tracing
and two configuration fields have been renamed and moved.

Finally, there are a handful of bug fixes and two new distribution packages, Chocolatey for Windows and an official PPA
for Ubuntu and Debian based distributions.

### NAT Detection for IPv4/UDP/Dublin

When tracing with the Dublin tracing strategy for IPv4/UDP, Trippy can now detect the presence of NAT (Network Address
Translation) devices on the path.

[RFC 3022 section 4.3](https://datatracker.ietf.org/doc/html/rfc3022#section-4.3) requires that "NAT to be completely
transparent to the host" however in practice some fully compliant NAT devices leave behind a telltale sign that Trippy
can use.

Trippy will indicate if a NAT device has been detected by adding `[NAT]` at the end of the hostname. There is also a
new (hidden by default) column, `Nat`, which can be enabled to show the NAT status per hop.

<img width="60%" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.11.0/nat_detection.png"/>

NAT devices are detected by observing a difference in the _expected_ and _actual_ checksum of the UDP packet that is
returned as the part of the Original Datagram in the ICMP Time Exceeded message. If they differ then it indicates that a
NAT device has modified the packet. This happens because the NAT device must recalculate the UDP checksum after
modifying the packet (i.e. translating the source port) and so the checksum in the UDP packet that is nested in the ICMP
error may not, depending on the device, match the original checksum.

To help illustrate the technique, consider sending the following IPv4/UDP packet (note the UDP `Checksum B` here):

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │             
|Version|  IHL  |Type of Service|          Total Length         | │             
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │             
|         Identification        |Flags|     Fragment Offset     | │             
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │             
|  Time to Live |    Protocol   |            Checksum A         | │ IPv4 Header 
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │             
|                         Source Address                        | │             
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │             
|                      Destination Address                      | │             
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │             
                                                                                
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │             
|          Source Port          |        Destination Port       | │             
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │ UDP Header  
|             Length            |            Checksum B         | │             
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │
```

Trippy expect to receive an IPv4/ICMP `TimeExceeded` (or other) error which contains the Original Datagram (OD) IPv4/UDP
packet that was sent above with `Checksum B'` in the Original Datagram (OD) IPv4/UDP packet:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │                                    
|Version|  IHL  |Type of Service|          Total Length         | │                                    
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │                                    
|         Identification        |Flags|     Fragment Offset     | │                                    
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │                                    
|  Time to Live |    Protocol   |            Checksum C         | │ IPv4 Header                        
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │                                    
|                         Source Address                        | │                                    
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │                                    
|                      Destination Address                      | │                                    
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │                                    
                                                                                                       
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │                                    
|      Type     |      Code     |            Checksum D         | │                                    
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │ IPv4 Payload (ICMP TE Header)      
|                             Unused                            | │                                    
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │                                    
                                                                  │                                    
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │ │                                  
|Version|  IHL  |Type of Service|          Total Length         | │ │                                  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │ │                                  
|         Identification        |Flags|     Fragment Offset     | │ │                                  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │ │                                  
|  Time to Live |    Protocol   |            Checksum A'        | │ │ ICMP TE Payload (OD IPv4 Header) 
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │ │                                  
|                         Source Address                        | │ │                                  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │ │                                  
|                      Destination Address                      | │ │                                  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │ │                                  
                                                                  │ │                                  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │ │ │                                
|          Source Port          |        Destination Port       | │ │ │                                
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │ │ │ OD IPv4 Payload (UDP header)   
|             Length            |            Checksum B'        | │ │ │                                
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ │ │ │
```

If `Checksum B'` in the UDP packet nested in the ICMP error does not match `Checksum B` in the UDP packet that was sent
then Trippy can infer that a NAT device is present.

This technique allows for the detection of NAT at the first hop. To detect multiple NAT devices along the path, Trippy
must also check for _changes_ in the observed checksum between consecutive hops, as changes to the UDP checksum will "
carry forward" to subsequent hops. This requires taking care to account for hops that do not respond. This is only
possible when using the Dublin tracing strategy, as it does not modify the UDP header per probe; therefore, the
checksums are expected to remain constant, allowing changes in the checksum between hops to be detected.

Note that this method cannot detect all types of NAT devices and so should be used in conjunction with other methods
where possible.

See the [issue](https://github.com/fujiapple852/trippy/issues/1104) for more details.

### Public API

Trippy has been designed primarily as a standalone _tool_, however it is built on top of a number of useful libraries,
such as the core tracer, DNS resolver and more. These libraries have always existed but were tightly integrated into the
tool and were not designed for use by third party crates.

This release introduces the Trippy public API which can be used to build custom tools on top of the Trippy libraries.

The full set of libraries exposed is:

| Crate                                                | Description                                          |
| ---------------------------------------------------- | ---------------------------------------------------- |
| [trippy](https://docs.rs/trippy)                     | Common entrypoint crate                              |
| [trippy-core](https://docs.rs/trippy-core)           | The core Trippy tracing functionality                |
| [trippy-packet](https://docs.rs/trippy-packet)       | Packet wire formats and packet parsing functionality |
| [trippy-dns](https://docs.rs/trippy-dns)             | Perform forward and reverse lazy DNS resolution      |
| [trippy-privilege](https://docs.rs/trippy-privilege) | Discover platform privileges                         |
| [trippy-tui](https://docs.rs/trippy-tui)             | The Trippy terminal user interface                   |

To use the Trippy public API you should add the common entrypoint `trippy` crate to your `Cargo.toml` file and then
enable the desired features. Note that the `trippy` crate includes `tui` as a default feature and so you should disable
default features when using it as a library. Alternatively, it is also possible to add the crates individually.

For example, to use the core Trippy tracing functionality you would add the `trippy` crate, disable default features and
enable the `core` feature:

```toml
[dependencies]
trippy = { version = "0.11.0", default-features = false, features = ["core"] }
```

The `hello-world` example below demonstrates how to use the Trippy public API to perform a simple trace and print the
results of each round:

```rust
use std::str::FromStr;
use trippy::core::Builder;

fn main() -> anyhow::Result<()> {
    let addr = std::net::IpAddr::from_str("1.1.1.1")?;
    Builder::new(addr)
        .build()?
        .run_with(|round| println!("{:?}", round))?;
    Ok(())
}
```

Whilst Trippy adheres to [Semantic Versioning](https://semver.org/), the public API is not yet considered stable and may
change in future releases.

See [crates](crates/README.md) and the usage [examples](examples/README.md) for more information.

### New Initial Sequence

For UDP tracing, by default, Trippy uses a fixed source port and a variable destination port which is set from the
sequence number, starting from an initial sequence of 33000 and incremented for each probe, eventually wrapping around.

By [convention](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers), many devices on the internet allow UDP
probes to ports in the range 33434..=33534 and will return a `DestinationUnreachable` ICMP error, which can be used to
confirm that the target has been reached. Since Trippy does not use destination ports in this range for UDP probes by
default, the target host will typically not respond with an ICMP error, and so Trippy cannot know that the target was
reached, and must therefore show the hop as unknown.

Another issue with this default setup is that the sequence number will eventually enter the range 33434..=33534 at which
point the target will _begin_ to respond with the `DestinationUnreachable` ICMP error. However, there is no guarantee
that the probe sent for sequence 33434 (i.e., the first one for which the target host will be able to respond) will be
for the minimum time-to-live (ttl) required to reach the target. This leads to confusing output, which is hard for users
to interpret. See [issue](https://github.com/fujiapple852/trippy/issues/1203) for more details.

These issues can be avoided today, either by changing the initial sequence number to be in the range 33434..=33534 by
setting the `--initial-sequence` flag or by using a fixed destination port (and therefore a variable source port) in the
same range by setting the `--target-port` flag.

In the following example, the initial sequence number is set to 33434:

```shell
trip example.com --udp --initial-sequence 33434
```

This can be made permanent by setting the `initial-sequence` value in the `strategy` section of the configuration file:

```toml
[strategy]
initial-sequence = 33434
```

In the following example, the destination port is set to 33434:

```shell
trip example.com --udp --target-port 33434
```

This can be made permanent by setting the `target-port` value in the `strategy` section of the configuration file:

```toml
[strategy]
target-port = 33434
```

As the default behavior in Trippy leads to these confusing issues, this release modifies the default sequence number to
be 33434. This is a **breaking change** and will impact users who rely on the old default initial sequence number.

This change introduces a new problem, albeit a lesser one: UDP traces will now begin with a destination port of 33434
and so `DestinationUnreachable` ICMP errors will typically be returned by the target immediately. However, eventually
the sequence number will move _beyond_ the range 33434..=33534 and so the target host will _stop_ responding
with `DestinationUnreachable` ICMP errors. This leads to the appearance that the target has started dropping packets.
While this is technically correct, this is not desirable behavior as the target has not really disappeared.

It is therefore recommended to _always_ fix the `target-port` to be in the range 33434..=33534 for UDP tracing and allow
the source port to vary instead. This may become the default behavior for UDP tracing in a future release; that would
represent a significant difference in default behavior compared to most traditional Unix traceroute tools, which vary
the destination port by default.

### Reverse DNS Lookup Cache Time-to-live

Trippy performs a reverse DNS lookup for each host encountered during the trace and the resulting hostnames are cached
indefinitely. This can lead to stale hostnames being displayed in the TUI if they change after the trace has begun.

Note that the DNS cache can be flushed manually by pressing `ctrl+k` (default key binding) in the TUI.

Starting from this release, the reverse DNS cache can be configured to expire after a certain time to live. By default
this is set to be 5 minutes (300 seconds) and can be configured using the `--dns-ttl` flag or the `dns-ttl`
configuration option.

The following example sets the DNS cache time-to-live to 30 seconds:

```shell
trip example.com --dns-ttl 30s
```

This can be made permanent by setting the `dns-ttl` value in the `dns` section of the configuration file:

```toml
[dns]
dns-ttl = "30s"
```

### Transient Error Handling for IPv4

Trippy records the number of probes sent and the number of probes received for each hop and uses this information to
calculate packet loss. Any probe that is _successfully_ sent for which no response is received is considered lost.

Currently, if a probe cannot be sent for any reason, then Trippy will crash and show a BSOD. This is not typically an
issue, as such failures imply a local issue with the host network configuration rather than an issue with the target or
any intermediate hops.

However, it is possible that a probe may fail to send for a transient reason, such as a temporary local host issue, and
so it would be useful to be able to handle such errors gracefully. A common example would be running Trippy on a host
and during the trace disabling the network interface.

Starting from this release, Trippy will continue the trace even if a probe fails to send and will instead show a warning
to the user in the TUI about the number of probe failures. A new column (hidden by default), `Fail`, has also been added
to the TUI to show the number of probes that failed to send for each hop.

<img width="60%" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.11.0/fails.png"/>

This has been implemented for macOS, Linux and Windows for IPv4 only. Support for IPv6 and other platforms will be added
in future releases.

See the [tracking issue](https://github.com/fujiapple852/trippy/issues/1238) for more details.

### Generate ROFF Man Page

Trippy can now generate manual pages in ROFF format. This can be useful for users who wish to install Trippy on systems
which do not have a package manager or for users who wish to install Trippy from source. It can also be used by package
maintainers to generate manual pages for their distribution.

The following command generates a ROFF manual page for Trippy:

```shell
trip --generate-man > /path/to/man/pages/trip.1
```

### New Columns

This release introduced several new columns, all of which are hidden by default. These are:

- `Type`: The ICMP packet type for the last probe for the hop
- `Code`: The ICMP packet code for the last probe for the hop
- `Nat`: The NAT detection status for the hop
- `Fail`: The number of probes which failed to send for the hop

The following shows the `Type` and `Code` columns:

<img width="60%" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.11.0/type_code_columns.png"/>

See the [Column Reference](https://github.com/fujiapple852/trippy#column-reference) for a full list of all available
columns.

### Settings Dialog Tab Hotkeys

The settings dialog can be accessed by pressing `s` (default key binding) and users can navigate between the tabs using
the left and right arrow keys (default key bindings). This release introduces hotkeys to allow users to jump directly to
a specific tab by pressing `1`-`7` (default key bindings).

See the [Key Bindings Reference](https://github.com/fujiapple852/trippy#key-bindings-reference) for details.

### Help Dialog Revamped

The existing Trippy help dialog shows a hardcoded list of key bindings which may not reflect the actual key bindings the
user has configured. Trippy shows the correct key bindings in the settings dialog which can be accessed by
pressing `s` (default key binding) and navigating to the Bindings tab. Therefore, the key bindings in the help dialog
are both potentially incorrect and redundant.

This release revamps the help dialog and includes instructions on how to access the key bindings from the settings
dialog as well as some other useful information.

<img width="60%" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.11.0/new_help_dialog.png"/>

### Improved Error Messages

Error reporting has been improved for parameters such as `--min-round-duration` (`-i`). Previously, if an invalid
duration was provided, the following error would be reported:

```shell
$ trip example.com -i 0.05
Error: invalid character at 1
```

Starting from this release, such error will instead be shown as:

```shell
$ trip example.com -i 0.05
error: invalid value '0.05' for '--min-round-duration <MIN_ROUND_DURATION>': expected time unit (i.e. 100ms, 2s, 1000us)

For more information, try '--help'.
```

This covers all "duration" parameters, namely:

- `min_round_duration`
- `max_round_duration`
- `grace_duration`
- `read_timeout`
- `dns_timeout`
- `tui_refresh_rate`

### Renamed Configuration

The following configuration fields have been renamed and moved from the `[tui]` to the `[strategy]` section in the
configuration file:

- `tui-max-samples` -> `max-samples`
- `tui-max-flows` -> `max-flows`

This is a **breaking change**. Attempting to use the legacy field names will result in an error pointing to the new
name.

The following example shows the error reported if the old names are used from the command line:

```shell
error: unexpected argument '--tui-max-samples' found

  tip: a similar argument exists: '--max-samples'
```

The following examples shows the error reported if the ld names are used from the configuration file:

```shell
Error: tui-max-samples in [tui] section is deprecated, use max-samples in [strategy] section instead
```

### Bug Fixes

This release fixes a bug where `DestinationUnreachable` ICMP errors were assumed to have been sent by the target host,
whereas they may also be sent by an intermediate hop.

Another fix addresses an issue where the TUI would calculate the maximum number of hops to display based on the maximum
observed across all rounds rather than for the latest round.

Finally, a minor bug was fixed where `AddressInUse` and `AddrNotAvailable` errors were being conflated.

### New Distribution Packages

Trippy has been added to the Chocolatey community repository (with thanks to @Aurocosh!):

[![Chocolatey package](https://repology.org/badge/version-for-repo/chocolatey/trippy.svg)](https://community.chocolatey.org/packages/trippy)

```shell
choco install trippy
```

Trippy also has an official PPA for Ubuntu and Debian based distributions (with thanks to @zarkdav!):

[![Ubuntu PPA](https://img.shields.io/badge/Ubuntu%20PPA-0.11.0-brightgreen)](https://launchpad.net/~fujiapple/+archive/ubuntu/trippy/+packages)

```shell
sudo add-apt-repository ppa:fujiapple/trippy
sudo apt update && apt install trippy
```

You can find the full list of [distributions](https://github.com/fujiapple852/trippy/tree/master#distributions) in the
documentation.

### Thanks

My thanks to all Trippy contributors, package maintainers and community members.

Feel free to drop by the new Trippy Zulip room for a chat:

[![project chat](https://img.shields.io/badge/zulip-join_chat-brightgreen.svg)](https://trippy.zulipchat.com/)

Happy Tracing!

# 0.10.0

## Highlights

The first release of 2024 is packed with new features, such as customizable columns, jitter calculations, Dublin tracing
strategy for IPv6/UDP, support for IPinfo GeoIp files, enhanced DNS resolution with IPv6/IPv4 fallback and CSS named
colors for the TUI as well as a number of bug fixes. Since the last release there has also been a significant
improvement in automated testing, notably the introduction of TUN based simulation testing for IPv4.

### Customize Columns

#### Customize Columns in TUI

It is now possible to customize which columns are shown in the TUI and to adjust the order in which they are displayed.
This customization can be made from within the TUI or via configuration.

To customize the columns from the TUI you must open the settings dialog (`s` key) and navigating to the new `Columns`
tab (left and right arrow keys). From this tab you can select the desired column (up and down arrow keys) and toggle the
column visibility on and off (`c` key) or move it left (`,` key) or right (`.` key) in the list of columns.

<img width="60%" alt="columns" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.10.0/columns_settings.png">

You can supply the full list of columns, in the desired order, using the new `--tui-custom-columns` command line
argument. The following example specifies the standard list of columns in the default order:

```shell
trip example.com --tui-custom-columns holsravbwdt
```

Alternatively, to make the changes permanent you may add the `tui-custom-columns` entry to the `tui` section of the
Trippy configuration file:

```toml
[tui]
tui-custom-columns = "holsravbwdt"
```

Note that the value of `tui-custom-columns` can be seen in the corresponding field of the `Tui` tab of the settings
dialog and will reflect any changes made to the column order and visibility via the Tui. This can be useful as you may
copy this value and use it in the configuration file directly.

<img width="60%" alt="tui-custom-columns" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.10.0/tui_settings.png">

#### New Columns

This release also introduced several new columns, all of which are hidden by default. These are:

- Last source port: The source port for last probe for the hop
- Last destination port: The destination port for last probe for the hop
- Last sequence number: The sequence number for the last probe for the hop
- Jitter columns: see the "Calculate and Display Jitter" section below

See the [Column Reference](https://github.com/fujiapple852/trippy#column-reference) for a full list of all available
columns.

#### Column Layout Improvement

The column layout algorithm used in the hop table has been improved to allow the maximum possible space for the `Host`
column. The width of the `Host` column is now calculated dynamically based on the terminal width and the set of columns
currently configured.

### Calculate and Display Jitter

Trippy can now calculate and display a variety of measurements related to _jitter_ for each hop. Jitter is a measurement
of the difference in round trip time between consecutive probes. Specifically, the following new calculated values are
available in Trippy `0.10.0`:

- Jitter: The round-trip-time (RTT) difference between consecutive rounds for the hop
- Average Jitter: The average jitter of all probes for the hop
- Maximum Jitter: The maximum jitter of all probes for the hop
- Inter-arrival Jitter: The smoothed jitter value of all probes for the hop

These values are always calculated and are included in the `json` report. These may also be displayed as columns in the
TUI, however they are not shown by default. To enabled these columns in the TUI, please see
the [Column Reference](https://github.com/fujiapple852/trippy#column-reference).

<img width="60%" alt="jitter" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.10.0/jitter_columns.png">

### Dublin Tracing Strategy for IPv6/UDP

The addition of support for the [dublin](https://github.com/insomniacslk/dublin-traceroute) tracing strategy for
IPv6/UDP marks the completion of a multi-release journey to provide support for both Dublin
and [paris](https://github.com/libparistraceroute/libparistraceroute/wiki/Checksum) tracing strategies for both IPv4/UDP
and IPv6/UDP.

As a reminder, unlike classic traceroute and MTR, these alternative tracing strategies do not encode the probe sequence
number in either the src or dest port of the UDP packet, but instead use other protocol and address family specific
techniques. Specifically, the Dublin tracing strategy for IPv6/UDP varies the length of the UDP payload for this
purpose.

By doing so, these strategies are able to keep the src and dest ports fixed which makes it much more likely (though not
guaranteed) that each round of tracing will follow the same path through the network (note that this is not true for the
return path).

The following command runs an IPv6/UDP trace using the Dublin tracing strategy with fixed src and dest ports:

```shell
trip example.com --udp -6 -R dublin -S 5000 -P 3500
```

Note that, for both Paris and Dublin tracing strategies, if you fix either the src or dest ports (but _not_ both) then
Trippy will vary the unfixed port _per round_ rather than _per hop_. This has the effect that all probes _within_ a
round will likely follow the same network path but probes _between_ round will follow different paths. This can be
useful in conjunction with flows (`f` key) to visualize the various paths packet flow through the network. See
this [issue](https://github.com/fujiapple852/trippy/issues/1007) for more details.

<img width="60%" alt="ipv6_dublin" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.10.0/dublin_ipv6_src_dest_seq_columns.png">

With UDP support for the Paris and Dublin tracing strategies now complete, what remains is adding support for these for
the TCP protocol. Refer to the [ECMP tracking issue](https://github.com/fujiapple852/trippy/issues/274) for details.

### IPinfo GeoIp Provider

Trippy currently supports the ability to lookup and display GeoIp information from MMDB files, but prior to `0.10.0`
only the [MaxMind](https://www.maxmind.com) "GeoLite2 City" (and lite) MMDB files were supported. This release
introduces support for the "IP to Country + ASN Database" and "IP to Geolocation Extended Database" MMDB files
from [IPinfo](https://ipinfo.io).

The "IP to Country + ASN Database" MMDB file provided by IPinfo can be used as follows:

```shell
trip example.com --geoip-mmdb-file /path/to/country_asn.mmdb --tui-geoip-mode short
```

These settings can be made permanent by setting the following values in the `tui` section of the configuration file:

```toml
[tui]
geoip-mmdb-file = "/path/to/country_asn.mmdb"
tui-geoip-mode = "short"
```

### Enhanced DNS Resolution with IPv4/IPv6 Fallback

When provided with a DNS name such as `example.com` Trippy tries to resolve it to an IPv4 or an IPv6 address and fails
if no such IP exists for the configured `addr-family` mode, which must be either IPv4 or IPv6.

Starting from version `0.10.0`, Trippy can be configured to support `ipv4-then-ipv6` and `ipv6-then-ipv4` modes
for `addr-family`. In the new `ipv4-then-ipv6` mode Trippy will first attempt to resolve the given hostname to an IPv4
address and, if no such address exists, it will attempt to resolve to an IPv6 address and only fail if neither are
available (and the opposite for the new `ipv6-then-ipv4` mode). The `addr-family` mode may also be set to be `ipv4`
or `ipv6` for IPv4 only and IPv6 only respectively.

To set the `addr-family` to be IPv6 with fallback to IPv4 you can set the `--addr-family` command line parameter:

```shell
trip example.com --addr-family ipv6-then-ipv4
```

To make the change permanent you can set the `addr-family` value in the `strategy` section of the configuration file:

```toml
[strategy]
addr-family = "ipv6-then-ipv4"
```

Note that Trippy supports both the `addr-family` entry in the configuration file and also the `--ipv4` (`-4`)
and `--ipv6` (`-6`) command line flags, all of which are optional. The command line flags (which are mutually exclusive)
take precedence over the config file entry and if neither are provided there it defaults to `ipv4-then-ipv6`.

### Extended Colors in TUI

Trippy allows the theme to be customized and supports the
named [ANSI colors](https://en.wikipedia.org/wiki/ANSI_escape_code#Colors):

Black, Red, Green, Yellow, Blue, Magenta, Cyan, Gray, DarkGray, LightRed, LightGreen, LightYellow, LightBlue,
LightMagenta, LightCyan, White

The `0.10.0` release adds support for CSS [named colors](https://developer.mozilla.org/en-US/docs/Web/CSS/named-color) (
e.g. SkyBlue). Note that these are only supported on some platforms and terminals and may not render correctly
elsewhere.

See the [Theme Reference](https://github.com/fujiapple852/trippy#theme-reference)

### Simulation Testing

Manually testing all Trippy features in all modes and on all supported platforms is an increasingly time consuming and
error prone activity. Since the last release a significant effort has been made to increase the testing coverage,
including unit and integration testing.

In particular, the introduction of simulation testing allows for full end-to-end testing of all modes and features on
Linux, macOS and Windows without the need to mock or stub any behaviour _within_ Trippy.

This is achieved by creating a [TUN](https://en.wikipedia.org/wiki/TUN/TAP) device to simulate the behavior of network
nodes, responding to various pre-configured scenarios like packet loss and out-of-order arrivals.

Whilst not a change that directly benefits end users, this new testing approach should reduce the effort needed to test
each release of Trippy and help improve the overall reliability of the tool.

Note that the simulation testing is currently only supported for IPv4. See
the [Integration Testing](https://github.com/fujiapple852/trippy/issues/759) tracking issue for more details.

### Thanks

My thanks to all Trippy contributors, package maintainers and community members.

Feel free to drop by the Trippy Matrix room for a chat:

[![#trippy-dev:matrix.org](https://img.shields.io/badge/matrix/trippy-dev:matrix.org-blue)](https://matrix.to/#/#trippy-dev:matrix.org)

Happy Tracing!

# 0.9.0

## Highlights

Trippy `0.9.0` introduces many new features, including tracing flows and ICMP extensions, the expansion of support for
the Paris tracing strategy to encompass IPv6/UDP, an unprivileged execution mode for macOS, a hop privacy mode and many
more. Additionally, this release includes several important bug fixes along with a range of new distribution packages.

### Tracing Flows

#### Flow ID

A tracing flow represents the sequence of hosts traversed from the source to the target. Trippy is now able to identify
individual flows within a trace and assign each a unique flow id. Trippy calculate a flow id for each round of tracing,
based on the sequence of hosts which responded during that round, taking care to account for rounds in which only a
subset of hosts responded. Tracing statistics, such as packet loss % and average RTT are recorded on a per-flow basis as
well as being aggregated across all flow.

Tracing flows adds to the existing capabilities provided by Trippy to assist
with [ECMP](https://en.wikipedia.org/wiki/Equal-cost_multi-path_routing) (Equal-Cost Multi-Path Routing) when tracing
with UDP and TCP protocols. Some of these capabilities, such as
the [paris](https://github.com/libparistraceroute/libparistraceroute/wiki/Checksum)
and [dublin](https://github.com/insomniacslk/dublin-traceroute) tracing strategies, are designed to _restrict_ tracing
to a single flow, whilst others, such as the hop detail navigation mode (introduce in the last release) and tracing
flows, are designed to help _visualize_ tracing data in the presence of multiple flows. See
the `0.8.0` [release note](https://github.com/fujiapple852/trippy/releases/tag/0.8.0) for other such capabilities.

#### Tracing Flows in the TUI

The TUI has been enhanced with a new mode to help visualise flows. This can be toggled on and off with
the `toggle-flows` command (bound to the `f` key by default).

When toggled on, this mode display flow information as a chart in a new panel above the hops table. Flows can be
selected by using the left and right arrow keys (default key bindings). Flows are sorted by the number of rounds in
which a given flow id was observed, with the most frequent flow ids shown on the left. When entering this mode flow id 1
is selected automatically. The selected flow acts as a filter for the other parts of the TUI, including the hops table,
chart and maps views which only show data relevant to that specific flow.

<img width="60%" alt="flows" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.9.0/flows.png">

When toggled off, Trippy behaves as it did in previous versions where aggregated statistics (across all flows) are
shown. Note that per-flow data is always recorded, the toggle only influences how the data is displayed.

The number of flows visible in the TUI is limited and can be controlled by the `tui-max-flows` configuration items which
can be set via the command line or via the configuration file. By default up to 64 flows are shown.

The flows panel, as with all other parts of the TUI, can also be themed, see
the [theme reference](https://github.com/fujiapple852/trippy#theme-reference) for details.

#### Flow Reports

As well as visualising flows in the TUI, Trippy `0.9.0` introduces two new reports which make use of the tracing flow
data.

The new `flows` report mode records and print all flows observed during tracing.

The following command will run a TCP trace for 10 round and report all of the flows observed:

```shell
trip example.com --tcp -m flows -C 10
```

Sample output (truncated) showing three unique flows:

```text
flow 1: 192.168.1.1, 10.193.232.245, 218.102.40.38, 10.195.41.9, 172.217.27.14
flow 2: 192.168.1.1, 10.193.232.245, 218.102.40.22, 10.195.41.17, 172.217.27.14
flow 3: 192.168.1.1, 10.193.232.245, 218.102.40.38, 10.195.41.1, 172.217.27.14
```

Another new report, `dot`, outputs a [GraphViz](https://graphviz.org/) [`DOT`](https://graphviz.org/doc/info/lang.html)
format chart of all hosts observed during tracing.

The following command will run a TCP trace for 10 round and output a graph of flows in `DOT` format:

```shell
trip example.com --tcp -m dot -C 10
```

If you have a tool such as `dot` (Graphviz) installed you can use this to rendered the output in various formats, such
as PNG:

```shell
trip example.com --tcp -m dot -C 10 | dot -Tpng > path.png
```

Sample output:

<img width="60%" alt="dot" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.9.0/dot.png">

### ICMP Extensions

#### Parsing Extensions

Trippy `0.9.0` adds the ability to parse and display ICMP Multi-Part Messages (aka extensions). It supports both
compliant and non-compliant ICMP extensions as defined
in [section 5 of rfc4884](https://www.rfc-editor.org/rfc/rfc4884#section-5).

Trippy is able to parse and render any generic Extension Object but is also able to parse some well known Object
Classes, notably the MPLS class.

Support
for [additional classes](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xml#icmp-parameters-ext-classes)
will be added to future versions of Trippy, see the ICMP
Extensions [tracking issue](https://github.com/fujiapple852/trippy/issues/33).

Parsing of ICMP extensions can be enabled by setting the `--icmp-extensions` (`-e`) command line flag or by adding
the `icmp-extensions` entry in the `strategy` section of the configuration file:

```toml
[strategy]
icmp-extensions = true
```

#### ICMP Extensions in the TUI

The TUI has been enhanced to display ICMP extensions in both the normal and hop detail navigation modes.

In normal mode, ICMP extensions are not shown by default but can be enabled by setting the `--tui-icmp-extension-mode`
command line flag or by adding the `tui-icmp-extension-mode` entry in the `tui` section of the configuration file:

```toml
[tui]
tui-icmp-extension-mode = "full"
```

This can be set to `off` (do not show ICMP extension data), `mpls` (shows a list of MPLS label(s) per hop), `full` (
shows all details of all extensions, such as `ttl`, `exp` and `bos` for MPLS) or `all` (the same as `full` but also
shows `class`, `subtype` and `bytes` for unknown extension objects).

The following screenshot shows ICMP extensions in normal mode with `tui-icmp-extension-mode` set to be `mpls`:

<img width="60%" alt="extensions" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.9.0/extensions.png">

In hop detail mode, the full details of all ICMP extension objects are always shown if parsing of ICMP extensions is
enabled.

The following screenshot shows ICMP extensions in hop detail mode:

<img width="60%" alt="extensions_detail" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.9.0/extensions_detail.png">

#### ICMP Extensions in Reports

ICMP extension information is also included the `json` and `stream` report modes.

Sample output for a single hop from the `json` report:

```json
{
  "ttl": 14,
  "hosts": [
    {
      "ip": "129.250.3.125",
      "hostname": "ae-4.r25.sttlwa01.us.bb.gin.ntt.net"
    }
  ],
  "extensions": [
    {
      "mpls": {
        "members": [
          {
            "label": 91106,
            "exp": 0,
            "bos": 1,
            "ttl": 1
          }
        ]
      }
    }
  ],
  "loss_pct": "0.00",
  "sent": 1,
  "last": "178.16",
  "recv": 1,
  "avg": "178.16",
  "best": "178.16",
  "worst": "178.16",
  "stddev": "0.00"
}
```

### Paris Tracing Strategy for IPv6/UDP

The work to support the remaining [paris](https://github.com/libparistraceroute/libparistraceroute/wiki/Checksum)
and [dublin](https://github.com/insomniacslk/dublin-traceroute) tracing modes continues in this release with the
addition of support for the Paris tracing strategy for IPv6/UDP.

As a reminder, unlike classic traceroute and MTR, these alternative tracing strategies do not encode the probe sequence
number in either the src or dest port of the UDP or TCP packet, but instead use other protocol and address family
specific techniques. Specifically, the Paris tracing strategy for IPv6/UDP utilizes the UDP checksum for this purposes
and manipulates the UDP payload to ensure packets remind valid.

By doing so, these strategies are able to keep the src and dest ports fixed which makes it much more likely (though not
guaranteed) that each round of tracing will follow the same path through the network (note that this is _not_ true for
the return path).

The following command runs a IPv6/UDP trace using the `paris` tracing strategy with fixed src and dest ports:

```shell
trip example.com --udp -6 -R paris -S 5000 -P 3500
```

Refer to the [tracking issue](https://github.com/fujiapple852/trippy/issues/274) for details of the work remaining to
support all ECMP strategies for both UDP and TCP for IPv4 and IPv6.

### Unprivileged Mode

Trippy normally requires elevated privileges due to the use of raw sockets. Enabling the required privileges for a given
platform can be achieved in several ways as in described
the [privileges](https://github.com/fujiapple852/trippy#privileges) section of the documentation.

This release of Trippy adds the ability to run _without_ elevated privileged on a subset of platforms, but with some
limitations which are described below.

The unprivileged mode can be enabled by adding the `--unprivileged` (`-u`) command line flag or by adding
the `unprivileged` entry in the `trippy` section of the configuration file:

```toml
[trippy]
unprivileged = true
```

The following command runs a trace in unprivileged mode:

```shell
trip example.com -u
```

Unprivileged mode is currently only supported on macOS. Linux support is possible and may be added in the future.
Unprivileged mode is not supported on NetBSD, OpenBSD, FreeBSD or Windows as these platforms do not support
the `IPPROTO_ICMP` socket type.

Unprivileged mode does not support the `paris` or `dublin` tracing strategies as these require raw sockets in order to
manipulate the UDP and IP header respectively.

See [#101](https://github.com/fujiapple852/trippy/issues/101) for further information.

### Resolve All DNS

Trippy can be provided with either an IP address or a hostname as the target for tracing. Trippy will resolve hostnames
to IP addresses via DNS lookup (using the configured DNS resolver, see the existing `--dns-resolve-method` flag) and
pick an arbitrary IP address from those returned.

Trippy also has the ability to trace to several targets simultaneously (for the ICMP protocol only) and can be provided
with a list of IP addresses and hostnames.

Trippy `0.9.0` combined these features and introduces a convenience flag `--dns-resolve-all` which resolves a given
hostname to all IP addresses and will begin to trace to all of them simultaneously.

<img width="60%" alt="dns_resolve_all" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.9.0/dns_resolve_all.png">

### Hop Privacy

At times it is desirable to share tracing information with others to help with diagnostics of a network problem. These
traces can contain sensitive information, such as IP addresses, hostnames and GeoIp details of the internet facing hops.
Users often wish to avoid exposing this data and are forced to redact the tracing output or screenshots.

Trippy `0.9.0` adds a new privacy feature, which hides all sensitive information for a configurable number of hops in
the hops table, chart and GeoIP world map.

The following screenshot shows the world map view with the sensitive information of some hops hidden:

<img width="60%" alt="privacy" src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.9.0/privacy.png">

The following command will hide all sensitive information for the first 3 hops (ttl 1, 2 & 3) in the TUI:

```shell
trip example.com --tui-privacy-max-ttl 3
```

This can also be made the default behaviour by setting the value in the Trippy configuration file:

```toml
[tui]
tui-privacy-max-ttl = 3
```

From within the TUI the privacy mode can be toggled on and off using the `toggle-privacy` TUI command (bound to the `p`
key by default).

Note the toggle is only available if `tui-privacy-max-ttl` is configured to be non-zero. Privacy mode is entered
automatically on startup to avoid any accidental exposure of sensitive data, such as when sharing a screen.

### Print Config Template

The `0.8.0` release of Trippy introduced
a [configuration file](https://github.com/fujiapple852/trippy#configuration-reference) and provided a sample
configuration file you could download. This release adds a command which generates a configuration template appropriate
for the specific version of Trippy.

The following command generates a `trippy.toml` configuration file with all possible configuration options specified and
set to their default values:

```shell
trip --print-config-template > trippy.toml
```

### Alternative Help Key Binding

Can't decide whether you want to use `h` or `?` to display help information? Well fear not, Trippy now supports
an `toggle-help-alt` TUI command (bound to the `?` key by default) in additional to the existing `toggle-help` TUI
command (bound to the `h` key by default).

### Improvements to Reports

This release fixes a bug that prevented reverse DNS lookup from working in all reporting modes.

The list of IPs associated with a given hop have also been added to the `csv` and all tabular reports. ICMP extension
data has also been included in several reports.

Note that these are breaking change as the output of the reports has changed.

### New Binary Asset Downloads

The list of operating systems, CPU architectures and environments which have pre-build binary assets available for
download has been greatly expanded for the `0.9.0` release.

This includes assets for Linux, macOS, Windows, NetBSD and FreeBSD. Assets are available for `x86_64`, `aarch64`
and `arm7` and includes builds for various environments such as `gnu` and `musl` where appropriate. There are also
pre-build `RPM` and `deb` downloads available. See
the [Binary Asset Download](https://github.com/fujiapple852/trippy#binary-asset-download) section for a full list.

Note that Trippy `0.9.0` has only been [tested](https://github.com/fujiapple852/trippy/issues/836) on a small subset of
these platforms.

### New Distribution Packages

Since the last release Trippy has been added as an official WinGet package (kudos to @mdanish-kh and
@BrandonWanHuanSheng!) and can be installed as follows:

```shell
winget install trippy
```

Trippy has also been added to the scoop `Main` bucket (thanks to @StarsbySea!) and can be installed as follows:

```shell
scoop install trippy
```

You can find the full list of [distributions](https://github.com/fujiapple852/trippy/tree/master#distributions) in the
documentation.

### Thanks

My thanks to all Trippy contributors, package maintainers and community members.

Feel free to drop by the Trippy Matrix room for a chat:

[![#trippy-dev:matrix.org](https://img.shields.io/badge/matrix/trippy-dev:matrix.org-blue)](https://matrix.to/#/#trippy-dev:matrix.org)

Happy Tracing!

## New Contributors

- @c-git made their first contribution in https://github.com/fujiapple852/trippy/pull/632
- @trkelly23 made their first contribution in https://github.com/fujiapple852/trippy/pull/788

# 0.8.0

## Highlights

The `0.8.0` release of Trippy brings several new features, UX enhancements, and quality of life improvements, as well as
various small fixes and other minor improvements.

#### Hop Detail Navigation

Trippy offers various mechanisms to visualize [ECMP](https://en.wikipedia.org/wiki/Equal-cost_multi-path_routing) (
Equal-Cost Multi-Path Routing) when tracing with UDP and TCP protocols. Features include displaying all hosts for a
given hop in a scrollable table, limiting the number of hosts shown per hop (showing the % of traffic for each host),
and greying out hops that are not part of a specific tracing round.

Despite these helpful features, visualizing a complete trace can be challenging when there are numerous hosts for some
hops, which is common in environments where ECMP is heavily utilized.

This release enhances ECMP visualization support by introducing a hop detail navigation mode, which can be toggled on
and off by pressing `d` (default key binding). This mode displays multiline information for the selected hop only,
including IP, hostname, AS, and GeoIP details about a single host for the hop. Users can navigate forward and backward
between hosts in a given hop by pressing `,` and `.` (default key bindings), respectively.

<img src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.8.0/hop_details.png" width="60%">

In addition to visualizing ECMP, Trippy also supports alternative tracing strategies to assist with ECMP routing, which
are described below.

#### Paris Tracing Strategy

Trippy already supports both classic and [dublin](https://github.com/insomniacslk/dublin-traceroute) tracing strategies,
and this release adds support for the [paris](https://github.com/libparistraceroute/libparistraceroute/wiki/Checksum)
tracing strategy for the UDP protocol.

Unlike classic traceroute and MTR, these alternative tracing strategies do not encode the probe sequence number in
either the src or dest port of the UDP or TCP packet, but instead use other protocol and address family specific
techniques.

This means that every probe in a trace can share common values for the src & dest hosts and ports which, when combined
with the protocol, is typically what is used to making traffic route decisions in ECMP routing. This means that these
alternative tracing strategies significantly increase the likelihood that the same path is followed for each probe in a
trace (but not the return path!) in the presence of ECMP routing.

The following command runs a UDP trace using the new `paris` tracing strategy with fixed src and dest ports (the src and
dest hosts and the protocol are always fixed) and will therefore likely follow a common path for each probe in the
trace:

```shell
trip www.example.com --udp -R paris -S 5000 -P 3500
```

Future Trippy versions will build upon these strategies and further improve the ability to control and visualize ECMP
routing, refer to the [tracking issue](https://github.com/fujiapple852/trippy/issues/274) for further details.

#### GeoIp Information & Interactive Map

Trippy now supports the ability to look up and display GeoIP information from a user-provided
MaxMind [GeoLite2 City database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data). This information is
displayed per host in the hop table (for both normal and new detail navigation modes) and can be shown in various
formats. For example, short form like "San Jose, CA, US" or long form like "San Jose, California, United States, North
America," or latitude, longitude, and accuracy radius like "37.3512, -121.8846 (~20km)".

The following command enables GeoIP lookup from the provided `GeoLite2-City.mmdb` file and will show long form locations
in the hop table:

```shell
trip example.com --geoip-mmdb-file GeoLite2-City.mmdb --tui-geoip-mode long
```

Additionally, Trippy features a new interactive map screen that can be toggled on and off by pressing `m` (default key
binding). This screen displays a world map and plots the location of all hosts for all hops in the current trace, as
well as highlighting the location of the selected hop.

<img src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.8.0/world_map.png" width="60%">

#### Autonomous System Display Enhancements

Trippy has long offered the ability to look up and display AS information. This release makes this feature more flexible
by allowing different AS details to be shown in the hops table, including AS number, AS name, prefix CIDR, and registry
details.

<img src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.8.0/as_info.png" width="60%">

The following command enables AS lookup and will display the prefix CIDR for each host in the TUI:

```shell
trip example.com -z true -r resolv --tui-as-mode prefix
```

This release also fixes a limitation in earlier versions of Trippy that prevented the lookup of AS information for IP
addresses without a corresponding `PTR` DNS record.

#### UI Cleanup & Configuration Dialog

The number of configurable parameters in Trippy has grown significantly, surpassing the number that can be comfortably
displayed in the TUI header section. Previous Trippy versions displayed an arbitrarily chosen subset of these
parameters, many of which have limited value for users and consume valuable screen space.

This release introduces a new interactive settings dialog that can be toggled on and off with `s` (default key binding)
to display all configured parameters. The TUI header has also been cleaned up to show only the most relevant
information, specifically the protocol and address family, the AS info toggle, the hop details toggle, and the max-hosts
setting.

<img src="https://raw.githubusercontent.com/fujiapple852/trippy/master/assets/0.8.0/settings.png" width="60%">

#### Configuration File

The previous Trippy release introduced the ability to customize the TUI color theme and key bindings, both of which
could be specified by command-line arguments. While functional, this method is inconvenient when configuring a large
number of colors or keys.

This release adds support for a Trippy configuration file, allowing for persistent storage of color themes, key
bindings, and all other configuration items supported by Trippy.

For a sample configuration file showing all possible configurable items that are available, see
the [configuration reference](https://github.com/fujiapple852/trippy#configuration-reference) for details.

#### Shell Completions

This release enables the generation of shell completions for various shells, including bash, zsh, PowerShell, and fish,
using the new `--generate` command-line flag.

The following command will generate and store shell completions for the fish shell:

```shell
trip --generate fish > ~/.config/fish/completions/trip.fish
```

#### Improved Error Reporting & Debug Logging

This release adds a number of command-line flags to enable debug logging, enhancing the ability to diagnose failures.
For example, the following command can be used to run tracing with no output, except for debug output in a format
suitable to be displayed with `chrome://tracing` or similar tools:

```shell
trip www.example.com -m silent -v --log-format chrome
```

Socket errors have also been augmented with contextual information, such as the socket address for a bind failure, to
help with the diagnosis of issues.

#### New Distribution Packages

Trippy is now also available as a Nix package (@figsoda), a FreeBSD port (@ehaupt) and a Windows Scoop package. This
release also re-enables support for a `musl` binary which was disabled in `0.7.0` due to a bug in a critical library
used by Trippy.

See [distributions](https://github.com/fujiapple852/trippy#distributions) for the full list of available packages.

My thanks, as ever, to all Trippy contributors!

## New Contributors

- @utkarshgupta137 made their first contribution in https://github.com/fujiapple852/trippy/pull/537

# 0.7.0

## Highlights

The major highlight of the 0.7.0 release of Trippy is the addition of full support for Windows, for all tracing modes
and protocols! 🎉. This has been many months in the making and is thanks to the hard work and perseverance of @zarkdav.

This release also sees the introduction of custom Tui themes and key bindings, `deb` and `rpm` package releases, as well
as several important bug fixes.

My thanks to all the contributors!

# 0.6.0

## Highlights

The first official release of Trippy!
