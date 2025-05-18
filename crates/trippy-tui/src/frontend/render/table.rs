use crate::config::{AddressMode, AsMode, GeoIpMode, IcmpExtensionMode};
use crate::frontend::columns::{ColumnType, Columns};
use crate::frontend::config::TuiConfig;
use crate::frontend::theme::Theme;
use crate::frontend::tui_app::TuiApp;
use crate::geoip::{GeoIpCity, GeoIpLookup};
use crate::t;
use itertools::Itertools;
use ratatui::layout::Rect;
use ratatui::prelude::Line;
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, BorderType, Borders, Cell, Row, Table};
use ratatui::Frame;
use std::fmt::Write;
use std::net::IpAddr;
use std::rc::Rc;
use trippy_core::{
    Dscp, Ecn, Extension, Extensions, IcmpPacketType, MplsLabelStackMember, UnknownExtension,
};
use trippy_core::{Hop, NatStatus};
use trippy_dns::{AsInfo, DnsEntry, DnsResolver, Resolved, Resolver, Unresolved};

/// Render the table of data about the hops.
///
/// For each hop, we show by default:
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
///
/// Optional columns that can be added:
///
/// - The current jitter i.e. round-trip difference with the last round-trip ('Jttr')
/// - The average jitter time for all probes at this hop ('Javg')
/// - The worst round-trip jitter time for all probes at this hop ('Jmax')
/// - The smoothed jitter value for all probes at this hop ('Jinta')
pub fn render(f: &mut Frame<'_>, app: &mut TuiApp, rect: Rect) {
    let config = &app.tui_config;
    let widths = config.tui_columns.constraints(rect);
    let header = render_table_header(app.tui_config.theme, &config.tui_columns);
    let selected_style = Style::default().add_modifier(Modifier::REVERSED);
    let rows = app
        .tracer_data()
        .hops_for_flow(app.selected_flow)
        .iter()
        .map(|hop| {
            render_table_row(
                app,
                hop,
                &app.resolver,
                &app.geoip_lookup,
                &app.tui_config,
                &config.tui_columns,
            )
        });
    let table = Table::new(rows, widths.as_slice())
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(app.tui_config.theme.border))
                .title(Line::raw(t!("title_hops"))),
        )
        .style(
            Style::default()
                .bg(app.tui_config.theme.bg)
                .fg(app.tui_config.theme.text),
        )
        .row_highlight_style(selected_style)
        .column_spacing(1);
    f.render_stateful_widget(table, rect, &mut app.table_state);
}

/// Render the table header.
fn render_table_header(theme: Theme, table_columns: &Columns) -> Row<'static> {
    let header_cells = table_columns.columns().map(|c| {
        Cell::from(c.typ.to_string()).style(Style::default().fg(theme.hops_table_header_text))
    });
    Row::new(header_cells)
        .style(Style::default().bg(theme.hops_table_header_bg))
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
    let is_selected_hop = app.selected_hop().is_some_and(|h| h.ttl() == hop.ttl());
    let is_in_round = app.tracer_data().is_in_round(hop, app.selected_flow);
    let (_, row_height) = if is_selected_hop && app.show_hop_details {
        render_hostname_with_details(app, hop, dns, geoip_lookup, config)
    } else {
        render_hostname(app, hop, dns, geoip_lookup)
    };
    let cells: Vec<Cell<'_>> = custom_columns
        .columns()
        .map(|column| {
            new_cell(
                column.typ,
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
        config.theme.hops_table_row_active_text
    } else {
        config.theme.hops_table_row_inactive_text
    };
    Row::new(cells)
        .height(row_height)
        .bottom_margin(0)
        .style(Style::default().fg(row_color))
}

///Returns a Cell matched on short char of the Column
fn new_cell(
    column: ColumnType,
    is_selected_hop: bool,
    app: &TuiApp,
    hop: &Hop,
    dns: &DnsResolver,
    geoip_lookup: &GeoIpLookup,
    config: &TuiConfig,
) -> Cell<'static> {
    let is_target = app.tracer_data().is_target(hop, app.selected_flow);
    let total_recv = hop.total_recv();
    match column {
        ColumnType::Ttl => render_usize_cell(hop.ttl().into()),
        ColumnType::Host => {
            let (host_cell, _) = if is_selected_hop && app.show_hop_details {
                render_hostname_with_details(app, hop, dns, geoip_lookup, config)
            } else {
                render_hostname(app, hop, dns, geoip_lookup)
            };
            host_cell
        }
        ColumnType::LossPct => render_pct_cell(hop.loss_pct()),
        ColumnType::Sent => render_usize_cell(hop.total_sent()),
        ColumnType::Received => render_usize_cell(hop.total_recv()),
        ColumnType::Failed => render_usize_cell(hop.total_failed()),
        ColumnType::Last => render_float_cell(hop.last_ms(), 1, total_recv),
        ColumnType::Average => render_avg_cell(hop),
        ColumnType::Best => render_float_cell(hop.best_ms(), 1, total_recv),
        ColumnType::Worst => render_float_cell(hop.worst_ms(), 1, total_recv),
        ColumnType::StdDev => render_stddev_cell(hop),
        ColumnType::Status => render_status_cell(hop, is_target),
        ColumnType::Jitter => render_float_cell(hop.jitter_ms(), 1, total_recv),
        ColumnType::Javg => render_float_cell(Some(hop.javg_ms()), 1, total_recv),
        ColumnType::Jmax => render_float_cell(hop.jmax_ms(), 1, total_recv),
        ColumnType::Jinta => render_float_cell(Some(hop.jinta()), 1, total_recv),
        ColumnType::LastSrcPort => render_port_cell(hop.last_src_port()),
        ColumnType::LastDestPort => render_port_cell(hop.last_dest_port()),
        ColumnType::LastSeq => render_usize_cell(usize::from(hop.last_sequence())),
        ColumnType::LastIcmpPacketType => render_icmp_packet_type_cell(hop.last_icmp_packet_type()),
        ColumnType::LastIcmpPacketCode => render_icmp_packet_code_cell(hop.last_icmp_packet_type()),
        ColumnType::LastNatStatus => render_nat_cell(hop.last_nat_status()),
        ColumnType::Floss => render_usize_cell(hop.total_forward_loss()),
        ColumnType::Bloss => render_usize_cell(hop.total_backward_loss()),
        ColumnType::FlossPct => render_pct_cell(hop.forward_loss_pct()),
        ColumnType::Dscp => render_dscp_cell(hop.dscp()),
        ColumnType::Ecn => render_ecn_cell(hop.ecn()),
    }
}

fn render_usize_cell(value: usize) -> Cell<'static> {
    Cell::from(format!("{value}"))
}

fn render_nat_cell(value: NatStatus) -> Cell<'static> {
    Cell::from(match value {
        NatStatus::NotApplicable => t!("na"),
        NatStatus::NotDetected => t!("no"),
        NatStatus::Detected => t!("yes"),
    })
}

fn render_pct_cell(value: f64) -> Cell<'static> {
    Cell::from(format!("{value:.1}%"))
}

fn render_avg_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(if hop.total_recv() > 0 {
        format!("{:.1}", hop.avg_ms())
    } else {
        String::default()
    })
}

fn render_stddev_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(if hop.total_recv() > 1 {
        format!("{:.1}", hop.stddev_ms())
    } else {
        String::default()
    })
}

fn render_float_cell(value: Option<f64>, places: usize, total_recv: usize) -> Cell<'static> {
    Cell::from(if total_recv > 0 {
        value.map(|v| format!("{v:.places$}")).unwrap_or_default()
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

fn render_icmp_packet_type_cell(icmp_packet_type: Option<IcmpPacketType>) -> Cell<'static> {
    match icmp_packet_type {
        None => Cell::from("n/a"),
        Some(IcmpPacketType::TimeExceeded(_)) => Cell::from("TE"),
        Some(IcmpPacketType::EchoReply(_)) => Cell::from("ER"),
        Some(IcmpPacketType::Unreachable(_)) => Cell::from("DU"),
        Some(IcmpPacketType::NotApplicable) => Cell::from("NA"),
    }
}

fn render_icmp_packet_code_cell(icmp_packet_type: Option<IcmpPacketType>) -> Cell<'static> {
    match icmp_packet_type {
        Some(
            IcmpPacketType::Unreachable(code)
            | IcmpPacketType::TimeExceeded(code)
            | IcmpPacketType::EchoReply(code),
        ) => Cell::from(format!("{}", code.0)),
        _ => Cell::from(t!("na")),
    }
}

fn render_port_cell(port: u16) -> Cell<'static> {
    if port > 0 {
        Cell::from(format!("{port}"))
    } else {
        Cell::from(t!("na"))
    }
}

fn render_dscp_cell(dscp: Option<Dscp>) -> Cell<'static> {
    match dscp {
        Some(Dscp::DF) => Cell::from("DF"),
        Some(Dscp::AF11) => Cell::from("AF11"),
        Some(Dscp::AF12) => Cell::from("AF12"),
        Some(Dscp::AF13) => Cell::from("AF13"),
        Some(Dscp::AF21) => Cell::from("AF21"),
        Some(Dscp::AF22) => Cell::from("AF22"),
        Some(Dscp::AF23) => Cell::from("AF23"),
        Some(Dscp::AF31) => Cell::from("AF31"),
        Some(Dscp::AF32) => Cell::from("AF32"),
        Some(Dscp::AF33) => Cell::from("AF33"),
        Some(Dscp::AF41) => Cell::from("AF41"),
        Some(Dscp::AF42) => Cell::from("AF42"),
        Some(Dscp::AF43) => Cell::from("AF43"),
        Some(Dscp::CS1) => Cell::from("CS1"),
        Some(Dscp::CS2) => Cell::from("CS2"),
        Some(Dscp::CS3) => Cell::from("CS3"),
        Some(Dscp::CS4) => Cell::from("CS4"),
        Some(Dscp::CS5) => Cell::from("CS5"),
        Some(Dscp::CS6) => Cell::from("CS6"),
        Some(Dscp::CS7) => Cell::from("CS7"),
        Some(Dscp::EF) => Cell::from("EF"),
        Some(Dscp::VA) => Cell::from("VA"),
        Some(Dscp::LE) => Cell::from("LE"),
        Some(Dscp::Other(other)) => Cell::from(format!("0x{other:02x}")),
        None => Cell::from(t!("na")),
    }
}

fn render_ecn_cell(ecn: Option<Ecn>) -> Cell<'static> {
    match ecn {
        Some(Ecn::NotECT) => Cell::from("NotECT"),
        Some(Ecn::ECT1) => Cell::from("ECT1"),
        Some(Ecn::ECT0) => Cell::from("ECT0"),
        Some(Ecn::CE) => Cell::from("CE"),
        None => Cell::from(t!("na")),
    }
}

/// Render hostname table cell (normal mode).
fn render_hostname(
    app: &TuiApp,
    hop: &Hop,
    dns: &DnsResolver,
    geoip_lookup: &GeoIpLookup,
) -> (Cell<'static>, u16) {
    let (hostname, count) = if hop.total_recv() > 0 {
        if app.tui_config.privacy_max_ttl >= Some(hop.ttl()) {
            (format!("**{}**", t!("hidden")), 1)
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
                        .sorted_unstable_by_key(|&(_, cnt)| cnt)
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
        (format!("{}", t!("no_response")), 1)
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
        AddressMode::Ip => addr.to_string(),
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
    let nat = match hop.last_nat_status() {
        NatStatus::Detected => Some("NAT"),
        _ => None,
    };
    let mut address = addr_fmt;
    if let Some(geo) = geo_fmt.as_deref() {
        let _ = write!(address, " [{geo}]");
    }
    if let Some(exp) = exp_fmt {
        let _ = write!(address, " [{exp}]");
    }
    if let Some(nat) = nat {
        let _ = write!(address, " [{nat}]");
    }
    if let Some(freq) = freq_fmt {
        let _ = write!(address, " [{freq}]");
    }
    address
}

/// Format a `DnsEntry` with or without autonomous system (AS) information (if available)
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
        DnsEntry::Failed(ip) => format!("{}: {ip}", t!("dns_failed")),
        DnsEntry::Timeout(ip) => format!("{}: {ip}", t!("dns_timeout")),
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
        Some(format!("{}: {labels}", t!("labels")))
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
/// `mpls(label=48320, ttl=1, exp=0, bos=1), unknown(class=1, sub=1, object=0b c8 c1 01), ...`
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
        if config.privacy_max_ttl >= Some(hop.ttl()) {
            format!("**{}**", t!("hidden"))
        } else {
            let index = app.selected_hop_address;
            format_details(hop, index, dns, geoip_lookup, config)
        }
    } else {
        format!("{}", t!("no_response"))
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
    let nat = hop.last_nat_status();
    match dns_entry {
        DnsEntry::Pending(addr) => {
            fmt_details_line(addr, index, count, None, None, geoip, ext, nat, config)
        }
        DnsEntry::Resolved(Resolved::WithAsInfo(addr, hosts, asinfo)) => fmt_details_line(
            addr,
            index,
            count,
            Some(hosts),
            Some(asinfo),
            geoip,
            ext,
            nat,
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
            nat,
            config,
        ),
        DnsEntry::Resolved(Resolved::Normal(addr, hosts)) => fmt_details_line(
            addr,
            index,
            count,
            Some(hosts),
            None,
            geoip,
            ext,
            nat,
            config,
        ),
        DnsEntry::NotFound(Unresolved::Normal(addr)) => fmt_details_line(
            addr,
            index,
            count,
            Some(vec![]),
            None,
            geoip,
            ext,
            nat,
            config,
        ),
        DnsEntry::Failed(ip) => {
            format!("{}: {ip}", t!("dns_failed"))
        }
        DnsEntry::Timeout(ip) => {
            format!("{}: {ip}", t!("dns_timeout"))
        }
    }
}

/// Format hostname detail lines.
///
/// Format as follows:
///
/// ```text
/// 172.217.24.78 [1 of 2]
/// Host: hkg07s50-in-f14.1e100.net
/// AS Name: AS15169 GOOGLE, US
/// AS Info: 142.250.0.0/15 arin 2012-05-24
/// Geo: United States, North America
/// Pos: 37.751, -97.822 (~1000km)
/// Ext: [mpls(label=48268, ttl=1, exp=0, bos=1)]
/// ```
#[expect(clippy::too_many_arguments)]
fn fmt_details_line(
    addr: IpAddr,
    index: usize,
    count: usize,
    hostnames: Option<Vec<String>>,
    asinfo: Option<AsInfo>,
    geoip: Option<Rc<GeoIpCity>>,
    extensions: Option<&Extensions>,
    nat: NatStatus,
    config: &TuiConfig,
) -> String {
    let as_fmt = match (config.lookup_as_info, asinfo) {
        (false, _) => format!(
            "AS {}: <{}>\nAS {}: <{}>",
            t!("name"),
            t!("not_enabled"),
            t!("info"),
            t!("not_enabled")
        ),
        (true, None) => format!(
            "AS {}: <{}>\nAS {}: <{}>",
            t!("name"),
            t!("info"),
            t!("awaited"),
            t!("awaited")
        ),
        (true, Some(info)) if info.asn.is_empty() => {
            format!(
                "AS {}: <{}>\nAS {}: <{}>",
                t!("name"),
                t!("not_found"),
                t!("info"),
                t!("not_found")
            )
        }
        (true, Some(info)) => format!(
            "AS {}: AS{} {}\nAS {}: {} {} {}",
            t!("name"),
            info.asn,
            info.name,
            t!("info"),
            info.prefix,
            info.registry,
            info.allocated
        ),
    };
    let hosts_rendered = if let Some(hosts) = hostnames {
        if hosts.is_empty() {
            format!("{}: <{}>", t!("host"), t!("not_found"))
        } else {
            format!("{}: {}", t!("host"), hosts.join(" "))
        }
    } else {
        format!("{}: <{}>", t!("host"), t!("awaited"))
    };
    let geoip_fmt = if let Some(geo) = geoip {
        let (lat, long, radius) = geo.coordinates().unwrap_or_default();
        format!(
            "{}: {}\n{}: {}, {} (~{}{})",
            t!("geo"),
            geo.long_name(),
            t!("pos"),
            lat,
            long,
            radius,
            t!("kilometer"),
        )
    } else {
        format!(
            "{}: <{}>\n{}: <{}>",
            t!("geo"),
            t!("not_found"),
            t!("pos"),
            t!("not_found")
        )
    };
    let ext_fmt = if let Some(extensions) = extensions {
        format!("{}: [{}]", t!("ext"), format_extensions_all(extensions))
    } else {
        format!("{}: <{}>", t!("ext"), t!("none"))
    };
    let nat_fmt = match nat {
        NatStatus::Detected => " [NAT]",
        _ => "",
    };
    format!(
        "{addr}{nat_fmt} [{index} of {count}]\n{hosts_rendered}\n{as_fmt}\n{geoip_fmt}\n{ext_fmt}"
    )
}
