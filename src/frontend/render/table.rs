use crate::backend::Hop;
use crate::config::{AddressMode, AsMode, GeoIpMode};
use crate::dns::{AsInfo, DnsEntry, DnsResolver, Resolved, Unresolved};
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
use trippy::tracing::Extension;

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
    let header = render_table_header(app.tui_config.theme);
    let selected_style = Style::default().add_modifier(Modifier::REVERSED);
    let rows =
        app.tracer_data().hops().iter().map(|hop| {
            render_table_row(app, hop, &app.resolver, &app.geoip_lookup, &app.tui_config)
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
        .widths(&TABLE_WIDTH);
    f.render_stateful_widget(table, rect, &mut app.table_state);
}

/// Render the table header.
fn render_table_header(theme: Theme) -> Row<'static> {
    let header_cells = TABLE_HEADER
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(theme.hops_table_header_text_color)));
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
) -> Row<'static> {
    let is_selected_hop = app
        .selected_hop()
        .map(|h| h.ttl() == hop.ttl())
        .unwrap_or_default();
    let is_target = app.tracer_data().is_target(hop);
    let is_in_round = app.tracer_data().is_in_round(hop);
    let ttl_cell = render_ttl_cell(hop);
    let (hostname_cell, row_height) = if is_selected_hop && app.show_hop_details {
        render_hostname_with_details(app, hop, dns, geoip_lookup, config)
    } else {
        render_hostname(hop, dns, geoip_lookup, config)
    };
    let loss_pct_cell = render_loss_pct_cell(hop);
    let total_sent_cell = render_total_sent_cell(hop);
    let total_recv_cell = render_total_recv_cell(hop);
    let last_cell = render_last_cell(hop);
    let avg_cell = render_avg_cell(hop);
    let best_cell = render_best_cell(hop);
    let worst_cell = render_worst_cell(hop);
    let stddev_cell = render_stddev_cell(hop);
    let status_cell = render_status_cell(hop, is_target);
    let cells = [
        ttl_cell,
        hostname_cell,
        loss_pct_cell,
        total_sent_cell,
        total_recv_cell,
        last_cell,
        avg_cell,
        best_cell,
        worst_cell,
        stddev_cell,
        status_cell,
    ];
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
    hop: &Hop,
    dns: &DnsResolver,
    geoip_lookup: &GeoIpLookup,
    config: &TuiConfig,
) -> (Cell<'static>, u16) {
    let (hostname, count) = if hop.total_recv() > 0 {
        match config.max_addrs {
            None => {
                let hostnames = hop
                    .addrs_with_counts()
                    .map(|(addr, &freq)| format_address(addr, freq, hop, dns, geoip_lookup, config))
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
                    .map(|(addr, &freq)| format_address(addr, freq, hop, dns, geoip_lookup, config))
                    .join("\n");
                let count = hop.addr_count().clamp(1, max_addr as usize);
                (hostnames, count as u16)
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
            let hostname = if config.lookup_as_info {
                let entry = dns.lazy_reverse_lookup_with_asinfo(*addr);
                format_dns_entry(entry, true, config.as_mode)
            } else {
                let entry = dns.lazy_reverse_lookup(*addr);
                format_dns_entry(entry, false, config.as_mode)
            };

            // TODO just a hack for now...
            if let Some(extensions) = hop.extensions() {
                let mpls = extensions
                    .extensions
                    .iter()
                    .map(|ext| match ext {
                        Extension::Unknown => todo!(),
                        Extension::Mpls(mpls) => mpls
                            .members
                            .iter()
                            .map(|member| {
                                format!("[MPLS label: {}, ttl: {}]", member.label, member.ttl)
                            })
                            .join("\n"),
                    })
                    .join("\n");
                format!("{hostname} {mpls}")
            } else {
                hostname
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
    match geo_fmt {
        Some(geo) if hop.addr_count() > 1 => {
            format!(
                "{} [{}] [{:.1}%]",
                addr_fmt,
                geo,
                (freq as f64 / hop.total_recv() as f64) * 100_f64
            )
        }
        Some(geo) => {
            format!("{addr_fmt} [{geo}]")
        }
        None if hop.addr_count() > 1 => {
            format!(
                "{} [{:.1}%]",
                addr_fmt,
                (freq as f64 / hop.total_recv() as f64) * 100_f64
            )
        }
        None => addr_fmt,
    }
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

/// Render hostname table cell (detailed mode).
fn render_hostname_with_details(
    app: &TuiApp,
    hop: &Hop,
    dns: &DnsResolver,
    geoip_lookup: &GeoIpLookup,
    config: &TuiConfig,
) -> (Cell<'static>, u16) {
    let (rendered, count) = if hop.total_recv() > 0 {
        let index = app.selected_hop_address;
        format_details(hop, index, dns, geoip_lookup, config)
    } else {
        (String::from("No response"), 1)
    };
    let cell = Cell::from(rendered);
    (cell, count)
}

/// Format hop details.
fn format_details(
    hop: &Hop,
    offset: usize,
    dns: &DnsResolver,
    geoip_lookup: &GeoIpLookup,
    config: &TuiConfig,
) -> (String, u16) {
    let Some(addr) = hop.addrs().nth(offset) else {
        return (format!("Error: no addr for index {offset}"), 1);
    };
    let count = hop.addr_count();
    let index = offset + 1;
    let geoip = geoip_lookup.lookup(*addr).unwrap_or_default();

    if config.lookup_as_info {
        let dns_entry = dns.lazy_reverse_lookup_with_asinfo(*addr);
        match dns_entry {
            DnsEntry::Pending(addr) => {
                let details = fmt_details_with_asn(addr, index, count, None, None, geoip);
                (details, 6)
            }
            DnsEntry::Resolved(Resolved::WithAsInfo(addr, hosts, asinfo)) => {
                let details =
                    fmt_details_with_asn(addr, index, count, Some(hosts), Some(asinfo), geoip);
                (details, 6)
            }
            DnsEntry::NotFound(Unresolved::WithAsInfo(addr, asinfo)) => {
                let details =
                    fmt_details_with_asn(addr, index, count, Some(vec![]), Some(asinfo), geoip);
                (details, 6)
            }
            DnsEntry::Failed(ip) => {
                let details = format!("Failed: {ip}");
                (details, 1)
            }
            DnsEntry::Timeout(ip) => {
                let details = format!("Timeout: {ip}");
                (details, 1)
            }
            DnsEntry::Resolved(Resolved::Normal(_, _))
            | DnsEntry::NotFound(Unresolved::Normal(_)) => unreachable!(),
        }
    } else {
        let dns_entry = dns.lazy_reverse_lookup(*addr);
        match dns_entry {
            DnsEntry::Pending(addr) => {
                let details = fmt_details_no_asn(addr, index, count, None, geoip);
                (details, 3)
            }
            DnsEntry::Resolved(Resolved::Normal(addr, hosts)) => {
                let details = fmt_details_no_asn(addr, index, count, Some(hosts), geoip);
                (details, 3)
            }
            DnsEntry::NotFound(Unresolved::Normal(addr)) => {
                let details = fmt_details_no_asn(addr, index, count, Some(vec![]), geoip);
                (details, 3)
            }
            DnsEntry::Failed(ip) => {
                let details = format!("Failed: {ip}");
                (details, 1)
            }
            DnsEntry::Timeout(ip) => {
                let details = format!("Timeout: {ip}");
                (details, 1)
            }
            DnsEntry::Resolved(Resolved::WithAsInfo(_, _, _))
            | DnsEntry::NotFound(Unresolved::WithAsInfo(_, _)) => unreachable!(),
        }
    }
}

/// Format hostname details with AS information.
///
/// Format as follows:
///
/// ```
/// 172.217.24.78 [1 of 2]
/// Host: hkg07s50-in-f14.1e100.net
/// AS Name: AS15169 GOOGLE, US
/// AS Info: 142.250.0.0/15 arin 2012-05-24
/// ```
///
/// If `hostnames` or `asinfo` is `None` it is rendered as `<pending>`
/// If `hostnames` or `asinfo` is `Some(vec![])` it is rendered as `<not found>`
fn fmt_details_with_asn(
    addr: IpAddr,
    index: usize,
    count: usize,
    hostnames: Option<Vec<String>>,
    asinfo: Option<AsInfo>,
    geoip: Option<Rc<GeoIpCity>>,
) -> String {
    let as_formatted = if let Some(info) = asinfo {
        if info.asn.is_empty() {
            "AS Name: <not found>\nAS Info: <not found>".to_string()
        } else {
            format!(
                "AS Name: AS{} {}\nAS Info: {} {} {}",
                info.asn, info.name, info.prefix, info.registry, info.allocated
            )
        }
    } else {
        "AS Name: <awaited>\nAS Info: <awaited>".to_string()
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
    format!("{addr} [{index} of {count}]\n{hosts_rendered}\n{as_formatted}\n{geoip_formatted}")
}

/// Format hostname details without AS information.
///
/// Format as follows:
///
/// ```
/// 172.217.24.78 [1 of 2]
/// Host: hkg07s50-in-f14.1e100.net
/// ```
///
/// If `hostnames` is `None` it is rendered as `<pending>`
/// If `hostnames` is `Some(vec![])` it is rendered as `<not found>`
fn fmt_details_no_asn(
    addr: IpAddr,
    index: usize,
    count: usize,
    hostnames: Option<Vec<String>>,
    geoip: Option<Rc<GeoIpCity>>,
) -> String {
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
    format!("{addr} [{index} of {count}]\n{hosts_rendered}\n{geoip_formatted}")
}

const TABLE_HEADER: [&str; 11] = [
    "#", "Host", "Loss%", "Snt", "Recv", "Last", "Avg", "Best", "Wrst", "StDev", "Sts",
];

const TABLE_WIDTH: [Constraint; 11] = [
    Constraint::Percentage(3),
    Constraint::Percentage(42),
    Constraint::Percentage(5),
    Constraint::Percentage(5),
    Constraint::Percentage(5),
    Constraint::Percentage(5),
    Constraint::Percentage(5),
    Constraint::Percentage(5),
    Constraint::Percentage(5),
    Constraint::Percentage(5),
    Constraint::Percentage(5),
];
