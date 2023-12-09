use crate::backend::trace::Hop;
use crate::config::{AddressMode, AsMode, GeoIpMode, IcmpExtensionMode};
use crate::frontend::columns::{Column, Columns};
use crate::frontend::config::TuiConfig;
use crate::frontend::theme::Theme;
use crate::frontend::tui_app::TuiApp;
use crate::geoip::{GeoIpCity, GeoIpLookup};
use itertools::Itertools;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, BorderType, Borders, Cell, Row, Table};
use ratatui::Frame;
use std::net::IpAddr;
use std::rc::Rc;
use trippy::dns::{AsInfo, DnsEntry, DnsResolver, Resolved, Resolver, Unresolved};
use trippy::tracing::{Extension, Extensions, MplsLabelStackMember, UnknownExtension};

/// Render the table of data about the hops.
///
/// For each hop, we show:
///
/// - The time-to-live (indexed from 1) at this hop (`#`)
/// - The host(s) reported at this hop (`Host`)
/// - The packet loss % for all probes at this hop (`Loss%`)
/// - The number of requests sent for all probes at this hop (`Snt`)
/// - The number of replies received for all probes at this hop (`Recv`)
/// - The round-trip time of the most recent probe at this hop (`Last`)
/// - The average round-trip time for all probes at this hop (`Avg`)
/// - The best round-trip time for all probes at this hop (`Best`)
/// - The worst round-trip time for all probes at this hop (`Wrst`)
/// - The standard deviation round-trip time for all probes at this hop (`StDev`)
/// - The status of this hop (`Sts`)
pub fn render(f: &mut Frame<'_>, app: &mut TuiApp, rect: Rect) {
    let config = &app.tui_config;
    let widths = get_column_widths(&config.tui_columns);
    let header = render_table_header(app.tui_config.theme, &config.tui_columns);
    let selected_style = Style::default().add_modifier(Modifier::REVERSED);
    let rows = app.tracer_data().hops(app.selected_flow).iter().map(|hop| {
        render_table_row(
            app,
            hop,
            &app.resolver,
            &app.geoip_lookup,
            &app.tui_config,
            &config.tui_columns,
        )
    });
    let table = Table::new(rows)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(app.tui_config.theme.border_color))
                .title("Hops"),
        )
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg_color)
                .fg(app.tui_config.theme.text_color),
        )
        .highlight_style(selected_style)
        .widths(widths.as_slice());
    f.render_stateful_widget(table, rect, &mut app.table_state);
}

/// Render the table header.
fn render_table_header(theme: Theme, table_columns: &Columns) -> Row<'static> {
    let header_cells = table_columns.0.iter().map(|c| {
        Cell::from(c.to_string()).style(Style::default().fg(theme.hops_table_header_text_color))
    });
    Row::new(header_cells)
        .style(Style::default().bg(theme.hops_table_header_bg_color))
        .height(1)
        .bottom_margin(0)
}

/// Render a single row in the table of hops.
fn render_table_row(
    app: &TuiApp,
    hop: &Hop,
    dns: &DnsResolver,
    geoip_lookup: &GeoIpLookup,
    config: &TuiConfig,
    custom_columns: &Columns,
) -> Row<'static> {
    let is_selected_hop = app
        .selected_hop()
        .map(|h| h.ttl() == hop.ttl())
        .unwrap_or_default();
    let is_in_round = app.tracer_data().is_in_round(hop, app.selected_flow);
    let (_, row_height) = if is_selected_hop && app.show_hop_details {
        render_hostname_with_details(app, hop, dns, geoip_lookup, config)
    } else {
        render_hostname(app, hop, dns, geoip_lookup)
    };
    let cells: Vec<Cell<'_>> = custom_columns
        .0
        .iter()
        .map(|column| {
            new_cell(
                *column,
                is_selected_hop,
                app,
                hop,
                dns,
                geoip_lookup,
                config,
            )
        })
        .collect();
    let row_color = if is_in_round {
        config.theme.hops_table_row_active_text_color
    } else {
        config.theme.hops_table_row_inactive_text_color
    };
    Row::new(cells)
        .height(row_height)
        .bottom_margin(0)
        .style(Style::default().fg(row_color))
}
///Returns a Cell matched on short char of the Column
fn new_cell(
    column: Column,
    is_selected_hop: bool,
    app: &TuiApp,
    hop: &Hop,
    dns: &DnsResolver,
    geoip_lookup: &GeoIpLookup,
    config: &TuiConfig,
) -> Cell<'static> {
    let is_target = app.tracer_data().is_target(hop, app.selected_flow);
    match column {
        Column::Ttl => render_ttl_cell(hop),
        Column::Host => {
            let (host_cell, _) = if is_selected_hop && app.show_hop_details {
                render_hostname_with_details(app, hop, dns, geoip_lookup, config)
            } else {
                render_hostname(app, hop, dns, geoip_lookup)
            };
            host_cell
        }
        Column::LossPct => render_loss_pct_cell(hop),
        Column::Sent => render_total_sent_cell(hop),
        Column::Received => render_total_recv_cell(hop),
        Column::Last => render_last_cell(hop),
        Column::Average => render_avg_cell(hop),
        Column::Best => render_best_cell(hop),
        Column::Worst => render_worst_cell(hop),
        Column::StdDev => render_stddev_cell(hop),
        Column::Status => render_status_cell(hop, is_target),
    }
}
fn render_ttl_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(format!("{}", hop.ttl()))
}

fn render_loss_pct_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(format!("{:.1}%", hop.loss_pct()))
}

fn render_total_sent_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(format!("{}", hop.total_sent()))
}

fn render_total_recv_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(format!("{}", hop.total_recv()))
}

fn render_avg_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(if hop.total_recv() > 0 {
        format!("{:.1}", hop.avg_ms())
    } else {
        String::default()
    })
}

fn render_last_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(
        hop.last_ms()
            .map(|last| format!("{last:.1}"))
            .unwrap_or_default(),
    )
}

fn render_best_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(
        hop.best_ms()
            .map(|best| format!("{best:.1}"))
            .unwrap_or_default(),
    )
}

fn render_worst_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(
        hop.worst_ms()
            .map(|worst| format!("{worst:.1}"))
            .unwrap_or_default(),
    )
}

fn render_stddev_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(if hop.total_recv() > 1 {
        format!("{:.1}", hop.stddev_ms())
    } else {
        String::default()
    })
}

fn render_status_cell(hop: &Hop, is_target: bool) -> Cell<'static> {
    let lost = hop.total_sent() - hop.total_recv();
    Cell::from(match (lost, is_target) {
        (lost, target) if target && lost == hop.total_sent() => "🔴",
        (lost, target) if target && lost > 0 => "🟡",
        (lost, target) if !target && lost == hop.total_sent() => "🟤",
        (lost, target) if !target && lost > 0 => "🔵",
        _ => "🟢",
    })
}

/// Render hostname table cell (normal mode).
fn render_hostname(
    app: &TuiApp,
    hop: &Hop,
    dns: &DnsResolver,
    geoip_lookup: &GeoIpLookup,
) -> (Cell<'static>, u16) {
    let (hostname, count) = if hop.total_recv() > 0 {
        if app.hide_private_hops && app.tui_config.privacy_max_ttl >= hop.ttl() {
            (String::from("**Hidden**"), 1)
        } else {
            match app.tui_config.max_addrs {
                None => {
                    let hostnames = hop
                        .addrs_with_counts()
                        .map(|(addr, &freq)| {
                            format_address(addr, freq, hop, dns, geoip_lookup, &app.tui_config)
                        })
                        .join("\n");
                    let count = hop.addr_count().clamp(1, u8::MAX as usize);
                    (hostnames, count as u16)
                }
                Some(max_addr) => {
                    let hostnames = hop
                        .addrs_with_counts()
                        .sorted_unstable_by_key(|(_, &cnt)| cnt)
                        .rev()
                        .take(max_addr as usize)
                        .map(|(addr, &freq)| {
                            format_address(addr, freq, hop, dns, geoip_lookup, &app.tui_config)
                        })
                        .join("\n");
                    let count = hop.addr_count().clamp(1, max_addr as usize);
                    (hostnames, count as u16)
                }
            }
        }
    } else {
        (String::from("No response"), 1)
    };
    (Cell::from(hostname), count)
}

/// Perform a reverse DNS lookup for an address and format the result.
fn format_address(
    addr: &IpAddr,
    freq: usize,
    hop: &Hop,
    dns: &DnsResolver,
    geoip_lookup: &GeoIpLookup,
    config: &TuiConfig,
) -> String {
    let addr_fmt = match config.address_mode {
        AddressMode::IP => addr.to_string(),
        AddressMode::Host => {
            if config.lookup_as_info {
                let entry = dns.lazy_reverse_lookup_with_asinfo(*addr);
                format_dns_entry(entry, true, config.as_mode)
            } else {
                let entry = dns.lazy_reverse_lookup(*addr);
                format_dns_entry(entry, false, config.as_mode)
            }
        }
        AddressMode::Both => {
            let hostname = if config.lookup_as_info {
                let entry = dns.lazy_reverse_lookup_with_asinfo(*addr);
                format_dns_entry(entry, true, config.as_mode)
            } else {
                let entry = dns.lazy_reverse_lookup(*addr);
                format_dns_entry(entry, false, config.as_mode)
            };
            format!("{hostname} ({addr})")
        }
    };
    let exp_fmt = format_extensions(config, hop);
    let geo_fmt = match config.geoip_mode {
        GeoIpMode::Off => None,
        GeoIpMode::Short => geoip_lookup
            .lookup(*addr)
            .unwrap_or_default()
            .map(|geo| geo.short_name()),
        GeoIpMode::Long => geoip_lookup
            .lookup(*addr)
            .unwrap_or_default()
            .map(|geo| geo.long_name()),
        GeoIpMode::Location => geoip_lookup
            .lookup(*addr)
            .unwrap_or_default()
            .map(|geo| geo.location()),
    };
    let freq_fmt = if hop.addr_count() > 1 {
        Some(format!(
            "{:.1}%",
            (freq as f64 / hop.total_recv() as f64) * 100_f64
        ))
    } else {
        None
    };
    let mut address = addr_fmt;
    if let Some(geo) = geo_fmt.as_deref() {
        address.push_str(&format!(" [{geo}]"));
    }
    if let Some(exp) = exp_fmt {
        address.push_str(&format!(" [{exp}]"));
    }
    if let Some(freq) = freq_fmt {
        address.push_str(&format!(" [{freq}]"));
    }
    address
}

/// Format a `DnsEntry` with or without `AS` information (if available)
fn format_dns_entry(dns_entry: DnsEntry, lookup_as_info: bool, as_mode: AsMode) -> String {
    match dns_entry {
        DnsEntry::Resolved(Resolved::Normal(_, hosts)) => hosts.join(" "),
        DnsEntry::Resolved(Resolved::WithAsInfo(_, hosts, asinfo)) => {
            if lookup_as_info && !asinfo.asn.is_empty() {
                format!("{} {}", format_asinfo(&asinfo, as_mode), hosts.join(" "))
            } else {
                hosts.join(" ")
            }
        }
        DnsEntry::NotFound(Unresolved::Normal(ip)) | DnsEntry::Pending(ip) => format!("{ip}"),
        DnsEntry::NotFound(Unresolved::WithAsInfo(ip, asinfo)) => {
            if lookup_as_info && !asinfo.asn.is_empty() {
                format!("{} {}", format_asinfo(&asinfo, as_mode), ip)
            } else {
                format!("{ip}")
            }
        }
        DnsEntry::Failed(ip) => format!("Failed: {ip}"),
        DnsEntry::Timeout(ip) => format!("Timeout: {ip}"),
    }
}

/// Format `AsInfo` based on the `ASDisplayMode`.
fn format_asinfo(asinfo: &AsInfo, as_mode: AsMode) -> String {
    match as_mode {
        AsMode::Asn => format!("AS{}", asinfo.asn),
        AsMode::Prefix => format!("AS{} [{}]", asinfo.asn, asinfo.prefix),
        AsMode::CountryCode => format!("AS{} [{}]", asinfo.asn, asinfo.cc),
        AsMode::Registry => format!("AS{} [{}]", asinfo.asn, asinfo.registry),
        AsMode::Allocated => format!("AS{} [{}]", asinfo.asn, asinfo.allocated),
        AsMode::Name => format!("AS{} [{}]", asinfo.asn, asinfo.name),
    }
}

/// Format `icmp` extensions.
fn format_extensions(config: &TuiConfig, hop: &Hop) -> Option<String> {
    if let Some(extensions) = hop.extensions() {
        match config.icmp_extension_mode {
            IcmpExtensionMode::Off => None,
            IcmpExtensionMode::Mpls => format_extensions_mpls(extensions),
            IcmpExtensionMode::Full => format_extensions_full(extensions),
            IcmpExtensionMode::All => Some(format_extensions_all(extensions)),
        }
    } else {
        None
    }
}

/// Format MPLS extensions as: `labels: 12345, 6789`.
///
/// If not MPLS extensions are present then None is returned.
fn format_extensions_mpls(extensions: &Extensions) -> Option<String> {
    let labels = extensions
        .extensions
        .iter()
        .filter_map(|ext| match ext {
            Extension::Unknown(_) => None,
            Extension::Mpls(stack) => Some(stack),
        })
        .flat_map(|ext| &ext.members)
        .map(|mem| mem.label)
        .format(", ")
        .to_string();
    if labels.is_empty() {
        None
    } else {
        Some(format!("labels: {labels}"))
    }
}

/// Format all known extensions with full details.
///
/// For MPLS: `mpls(label=48320, ttl=1, exp=0, bos=1), mpls(...)`
fn format_extensions_full(extensions: &Extensions) -> Option<String> {
    let formatted = extensions
        .extensions
        .iter()
        .filter_map(|ext| match ext {
            Extension::Unknown(_) => None,
            Extension::Mpls(stack) => Some(stack),
        })
        .flat_map(|ext| &ext.members)
        .map(format_ext_mpls_stack_member)
        .format(", ")
        .to_string();
    if formatted.is_empty() {
        None
    } else {
        Some(formatted)
    }
}

/// Format a list all known and unknown extensions with full details.
///
/// `mpls(label=48320, ttl=1, exp=0, bos=1), mpls(label=...), unknown(class=1, sub=1, object=0b c8 c1 01), ...`
fn format_extensions_all(extensions: &Extensions) -> String {
    extensions
        .extensions
        .iter()
        .flat_map(|ext| match ext {
            Extension::Unknown(unknown) => vec![format_ext_unknown(unknown)],
            Extension::Mpls(stack) => stack
                .members
                .iter()
                .map(format_ext_mpls_stack_member)
                .collect::<Vec<_>>(),
        })
        .format(", ")
        .to_string()
}

/// Format a MPLS `icmp` extension object.
pub fn format_ext_mpls_stack_member(member: &MplsLabelStackMember) -> String {
    format!(
        "mpls(label={}, ttl={}, exp={}, bos={})",
        member.label, member.ttl, member.exp, member.bos
    )
}

/// Format an unknown `icmp` extension object.
pub fn format_ext_unknown(unknown: &UnknownExtension) -> String {
    format!(
        "unknown(class={}, subtype={}, object={:02x})",
        unknown.class_num,
        unknown.class_subtype,
        unknown.bytes.iter().format(" ")
    )
}

/// Render hostname table cell (detailed mode).
fn render_hostname_with_details(
    app: &TuiApp,
    hop: &Hop,
    dns: &DnsResolver,
    geoip_lookup: &GeoIpLookup,
    config: &TuiConfig,
) -> (Cell<'static>, u16) {
    let rendered = if hop.total_recv() > 0 {
        if app.hide_private_hops && config.privacy_max_ttl >= hop.ttl() {
            String::from("**Hidden**")
        } else {
            let index = app.selected_hop_address;
            format_details(hop, index, dns, geoip_lookup, config)
        }
    } else {
        String::from("No response")
    };
    (Cell::from(rendered), 7)
}

/// Format hop details.
fn format_details(
    hop: &Hop,
    offset: usize,
    dns: &DnsResolver,
    geoip_lookup: &GeoIpLookup,
    config: &TuiConfig,
) -> String {
    let Some(addr) = hop.addrs().nth(offset) else {
        return format!("Error: no addr for index {offset}");
    };
    let count = hop.addr_count();
    let index = offset + 1;
    let geoip = geoip_lookup.lookup(*addr).unwrap_or_default();
    let dns_entry = if config.lookup_as_info {
        dns.lazy_reverse_lookup_with_asinfo(*addr)
    } else {
        dns.lazy_reverse_lookup(*addr)
    };
    let ext = hop.extensions();
    match dns_entry {
        DnsEntry::Pending(addr) => {
            fmt_details_line(addr, index, count, None, None, geoip, ext, config)
        }
        DnsEntry::Resolved(Resolved::WithAsInfo(addr, hosts, asinfo)) => fmt_details_line(
            addr,
            index,
            count,
            Some(hosts),
            Some(asinfo),
            geoip,
            ext,
            config,
        ),
        DnsEntry::NotFound(Unresolved::WithAsInfo(addr, asinfo)) => fmt_details_line(
            addr,
            index,
            count,
            Some(vec![]),
            Some(asinfo),
            geoip,
            ext,
            config,
        ),
        DnsEntry::Resolved(Resolved::Normal(addr, hosts)) => {
            fmt_details_line(addr, index, count, Some(hosts), None, geoip, ext, config)
        }
        DnsEntry::NotFound(Unresolved::Normal(addr)) => {
            fmt_details_line(addr, index, count, Some(vec![]), None, geoip, ext, config)
        }
        DnsEntry::Failed(ip) => {
            format!("Failed: {ip}")
        }
        DnsEntry::Timeout(ip) => {
            format!("Timeout: {ip}")
        }
    }
}

/// Format hostname detail lines.
///
/// Format as follows:
///
/// ```
/// 172.217.24.78 [1 of 2]
/// Host: hkg07s50-in-f14.1e100.net
/// AS Name: AS15169 GOOGLE, US
/// AS Info: 142.250.0.0/15 arin 2012-05-24
/// Geo: United States, North America
/// Pos: 37.751, -97.822 (~1000km)
/// Ext: [mpls(label=48268, ttl=1, exp=0, bos=1)]
/// ```
#[allow(clippy::too_many_arguments)]
fn fmt_details_line(
    addr: IpAddr,
    index: usize,
    count: usize,
    hostnames: Option<Vec<String>>,
    asinfo: Option<AsInfo>,
    geoip: Option<Rc<GeoIpCity>>,
    extensions: Option<&Extensions>,
    config: &TuiConfig,
) -> String {
    let as_formatted = match (config.lookup_as_info, asinfo) {
        (false, _) => "AS Name: <not enabled>\nAS Info: <not enabled>".to_string(),
        (true, None) => "AS Name: <awaited>\nAS Info: <awaited>".to_string(),
        (true, Some(info)) if info.asn.is_empty() => {
            "AS Name: <not found>\nAS Info: <not found>".to_string()
        }
        (true, Some(info)) => format!(
            "AS Name: AS{} {}\nAS Info: {} {} {}",
            info.asn, info.name, info.prefix, info.registry, info.allocated
        ),
    };
    let hosts_rendered = if let Some(hosts) = hostnames {
        if hosts.is_empty() {
            "Host: <not found>".to_string()
        } else {
            format!("Host: {}", hosts.join(" "))
        }
    } else {
        "Host: <awaited>".to_string()
    };
    let geoip_formatted = if let Some(geo) = geoip {
        let (lat, long, radius) = geo.coordinates().unwrap_or_default();
        format!(
            "Geo: {}\nPos: {}, {} (~{}km)",
            geo.long_name(),
            lat,
            long,
            radius
        )
    } else {
        "Geo: <not found>\nPos: <not found>".to_string()
    };
    let ext_formatted = if let Some(extensions) = extensions {
        format!("Ext: [{}]", format_extensions_all(extensions))
    } else {
        "Ext: <none>".to_string()
    };
    format!("{addr} [{index} of {count}]\n{hosts_rendered}\n{as_formatted}\n{geoip_formatted}\n{ext_formatted}")
}
fn get_column_widths(columns: &Columns) -> Vec<Constraint> {
    columns
        .0
        .iter()
        .map(|c| Constraint::Percentage(c.width_pct()))
        .collect()
}
