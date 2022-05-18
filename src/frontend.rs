use crate::backend::Hop;
use crate::config::{AddressMode, DnsResolveMethod};
use crate::dns::{DnsEntry, Resolved};
use crate::{DnsResolver, Trace, TraceInfo};
use chrono::SecondsFormat;
use crossterm::event::KeyModifiers;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use itertools::Itertools;
use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use trippy::tracing::PortDirection;
use tui::layout::{Alignment, Direction, Rect};
use tui::text::{Span, Spans};
use tui::widgets::{BarChart, BorderType, Clear, Paragraph, Sparkline, TableState, Tabs};
use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table},
    Frame, Terminal,
};

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

const LAYOUT_WITHOUT_TABS: [Constraint; 3] = [
    Constraint::Length(5),
    Constraint::Min(10),
    Constraint::Length(6),
];

const LAYOUT_WITH_TABS: [Constraint; 4] = [
    Constraint::Length(5),
    Constraint::Length(3),
    Constraint::Min(10),
    Constraint::Length(6),
];

const HELP_LINES: [&str; 14] = [
    "[up] & [down]    - select hop",
    "[left] & [right] - select trace",
    "[esc]            - clear selection",
    "f                - toggle freeze display",
    "Ctrl+r           - reset statistics",
    "Ctrl+k           - flush DNS cache",
    "i                - show IP only",
    "n                - show hostname only",
    "b                - show both IP and hostname",
    "[ & ]            - expand & collapse hosts",
    "{ & }            - expand & collapse hosts to max and min",
    "z                - toggle AS information (if available)",
    "h                - toggle help",
    "q                - quit",
];

/// Tui configuration.
#[derive(Debug)]
pub struct TuiConfig {
    /// Refresh rate.
    refresh_rate: Duration,
    /// Preserve screen on exit.
    preserve_screen: bool,
    /// How to render addresses.
    address_mode: AddressMode,
    /// Lookup `AS` information.
    lookup_as_info: bool,
    /// The maximum number of addresses to show per hop.
    max_addrs: Option<u8>,
    /// The maximum number of samples to record per hop.
    max_samples: usize,
}

impl TuiConfig {
    pub fn new(
        refresh_rate: Duration,
        preserve_screen: bool,
        address_mode: AddressMode,
        lookup_as_info: bool,
        max_addrs: Option<u8>,
        max_samples: usize,
    ) -> Self {
        Self {
            refresh_rate,
            preserve_screen,
            address_mode,
            lookup_as_info,
            max_addrs,
            max_samples,
        }
    }
}

struct TuiApp {
    selected_tracer_data: Trace,
    trace_info: Vec<TraceInfo>,
    tui_config: TuiConfig,
    table_state: TableState,
    trace_selected: usize,
    resolver: DnsResolver,
    show_help: bool,
    frozen_start: Option<SystemTime>,
}

impl TuiApp {
    fn new(tui_config: TuiConfig, resolver: DnsResolver, trace_info: Vec<TraceInfo>) -> Self {
        Self {
            selected_tracer_data: Trace::new(tui_config.max_samples),
            trace_info,
            tui_config,
            table_state: TableState::default(),
            trace_selected: 0,
            resolver,
            show_help: false,
            frozen_start: None,
        }
    }

    fn tracer_data(&self) -> &Trace {
        &self.selected_tracer_data
    }

    fn snapshot_trace_data(&mut self) {
        self.selected_tracer_data = self.trace_info[self.trace_selected].data.read().clone();
    }

    fn clear_trace_data(&mut self) {
        *self.trace_info[self.trace_selected].data.write() =
            Trace::new(self.tui_config.max_samples);
    }

    fn tracer_config(&self) -> &TraceInfo {
        &self.trace_info[self.trace_selected]
    }

    fn clamp_selected_hop(&mut self) {
        let hop_count = self.tracer_data().hops().len();
        if let Some(selected) = self.table_state.selected() {
            if selected > hop_count - 1 {
                self.table_state.select(Some(hop_count - 1));
            }
        }
    }

    fn next_hop(&mut self) {
        let hop_count = self.tracer_data().hops().len();
        if hop_count == 0 {
            return;
        }
        let max_index = 0.max(hop_count.saturating_sub(1));
        let i = match self.table_state.selected() {
            Some(i) => {
                if i < max_index {
                    i + 1
                } else {
                    i
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn previous_hop(&mut self) {
        let hop_count = self.tracer_data().hops().len();
        if hop_count == 0 {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i > 0 {
                    i - 1
                } else {
                    i
                }
            }
            None => 0.max(hop_count.saturating_sub(1)),
        };
        self.table_state.select(Some(i));
    }

    fn next_trace(&mut self) {
        if self.trace_selected < self.trace_info.len() - 1 {
            self.trace_selected += 1;
        }
    }

    fn previous_trace(&mut self) {
        if self.trace_selected > 0 {
            self.trace_selected -= 1;
        };
    }

    fn clear(&mut self) {
        self.table_state.select(None);
    }

    fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }

    fn toggle_freeze(&mut self) {
        self.frozen_start = match self.frozen_start {
            None => Some(SystemTime::now()),
            Some(_) => None,
        };
    }

    fn toggle_asinfo(&mut self) {
        self.tui_config.lookup_as_info = !self.tui_config.lookup_as_info;
    }

    fn expand_hosts(&mut self) {
        self.tui_config.max_addrs = match self.tui_config.max_addrs {
            None => Some(1),
            Some(i) if i < self.max_hosts() => Some(i + 1),
            Some(i) => Some(i),
        }
    }

    fn contract_hosts(&mut self) {
        self.tui_config.max_addrs = match self.tui_config.max_addrs {
            Some(i) if i > 1 => Some(i - 1),
            _ => None,
        }
    }

    fn expand_hosts_max(&mut self) {
        self.tui_config.max_addrs = Some(self.max_hosts());
    }

    fn contract_hosts_min(&mut self) {
        self.tui_config.max_addrs = Some(1);
    }

    /// The maximum number of hosts per hop for the currently selected trace.
    fn max_hosts(&self) -> u8 {
        self.selected_tracer_data
            .hops()
            .iter()
            .map(|h| h.addrs().count())
            .max()
            .and_then(|i| u8::try_from(i).ok())
            .unwrap_or_default()
    }
}

/// Run the frontend TUI.
pub fn run_frontend(
    traces: Vec<TraceInfo>,
    tui_config: TuiConfig,
    resolver: DnsResolver,
) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let preserve_screen = tui_config.preserve_screen;
    let res = run_app(&mut terminal, traces, tui_config, resolver);
    disable_raw_mode()?;
    if !preserve_screen {
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    }
    terminal.show_cursor()?;
    if let Err(err) = res {
        println!("{:?}", err);
    }
    Ok(())
}

fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    trace_info: Vec<TraceInfo>,
    tui_config: TuiConfig,
    resolver: DnsResolver,
) -> io::Result<()> {
    let mut app = TuiApp::new(tui_config, resolver, trace_info);
    loop {
        if app.frozen_start == None {
            app.snapshot_trace_data();
            app.clamp_selected_hop();
        };
        terminal.draw(|f| render_app(f, &mut app))?;
        if event::poll(app.tui_config.refresh_rate)? {
            if let Event::Key(key) = event::read()? {
                match (key.code, key.modifiers) {
                    (KeyCode::Char('q'), _) if !app.show_help => return Ok(()),
                    (KeyCode::Char('q'), _) if app.show_help => app.toggle_help(),
                    (KeyCode::Char('h'), _) => app.toggle_help(),
                    (KeyCode::Char('f'), _) if !app.show_help => app.toggle_freeze(),
                    (KeyCode::Char('r'), KeyModifiers::CONTROL) if !app.show_help => {
                        app.clear();
                        app.clear_trace_data();
                    }
                    (KeyCode::Char('k'), KeyModifiers::CONTROL) if !app.show_help => {
                        app.resolver.flush();
                    }
                    (KeyCode::Down, _) if !app.show_help => app.next_hop(),
                    (KeyCode::Up, _) if !app.show_help => app.previous_hop(),
                    (KeyCode::Esc, _) if !app.show_help => app.clear(),
                    (KeyCode::Esc, _) if app.show_help => app.toggle_help(),
                    (KeyCode::Left, _) if !app.show_help => {
                        app.previous_trace();
                        app.clear();
                    }
                    (KeyCode::Right, _) if !app.show_help => {
                        app.next_trace();
                        app.clear();
                    }
                    (KeyCode::Char('i'), _) if !app.show_help => {
                        app.tui_config.address_mode = AddressMode::IP;
                    }
                    (KeyCode::Char('n'), _) if !app.show_help => {
                        app.tui_config.address_mode = AddressMode::Host;
                    }
                    (KeyCode::Char('b'), _) if !app.show_help => {
                        app.tui_config.address_mode = AddressMode::Both;
                    }
                    (KeyCode::Char('z'), _) if !app.show_help => {
                        match app.resolver.config().resolve_method {
                            DnsResolveMethod::Resolv
                            | DnsResolveMethod::Google
                            | DnsResolveMethod::Cloudflare => {
                                app.toggle_asinfo();
                                app.resolver.flush();
                            }
                            DnsResolveMethod::System => {}
                        }
                    }
                    (KeyCode::Char('{'), _) if !app.show_help => app.contract_hosts_min(),
                    (KeyCode::Char('}'), _) if !app.show_help => app.expand_hosts_max(),
                    (KeyCode::Char('['), _) if !app.show_help => app.contract_hosts(),
                    (KeyCode::Char(']'), _) if !app.show_help => app.expand_hosts(),
                    _ => {}
                }
            }
        }
    }
}

/// Render the application main screen.
///
/// The layout of the TUI is as follows:
///
///  ____________________________________
/// |               Header               |
///  ------------------------------------
/// |                Tabs                |
///  ------------------------------------
/// |                                    |
/// |                                    |
/// |                                    |
/// |               Hops                 |
/// |                                    |
/// |                                    |
/// |                                    |
///  ------------------------------------
/// |     History     |    Frequency     |
/// |                 |                  |
///  ------------------------------------
///
/// Header - the title, configuration, destination, clock and keyboard controls
/// Tab - a tab for each target being traced (only shown if > 1 target requested)
/// Hops - a table where each row represents a single hop (time-to-live) in the trace
/// History - a graph of historic round-trip ping samples for the target host
/// Frequency - a histogram of sample frequencies by round-trip time for the target host
///
/// On startup a splash screen is shown in place of the hops table, until the completion of the first round.
fn render_app<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp) {
    let constraints = if app.trace_info.len() > 1 {
        LAYOUT_WITH_TABS.as_slice()
    } else {
        LAYOUT_WITHOUT_TABS.as_slice()
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints.as_ref())
        .split(f.size());
    render_header(f, app, chunks[0]);
    if app.trace_info.len() > 1 {
        render_tabs(f, app, chunks[1]);
        render_body(f, chunks[2], app);
        render_footer(f, chunks[3], app);
    } else {
        render_body(f, chunks[1], app);
        render_footer(f, chunks[2], app);
    }
}

/// Render the title, config, target, clock and keyboard controls.
fn render_header<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp, rect: Rect) {
    let header_block = Block::default()
        .title(format!(" Trippy v{} ", clap::crate_version!()))
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .style(Style::default());
    let now = chrono::Local::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let clock_span = Spans::from(Span::raw(now));
    let help_span = Spans::from(vec![
        Span::styled("h", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("elp "),
        Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("uit"),
    ]);
    let right_spans = vec![clock_span, help_span];
    let right = Paragraph::new(right_spans)
        .style(Style::default())
        .block(header_block.clone())
        .alignment(Alignment::Right);
    let protocol = &app.tracer_config().protocol.to_string();
    let dns = format_dns_method(app.resolver.config().resolve_method);
    let as_info = match app.resolver.config().resolve_method {
        DnsResolveMethod::System => String::from("n/a"),
        DnsResolveMethod::Resolv | DnsResolveMethod::Google | DnsResolveMethod::Cloudflare => {
            if app.tui_config.lookup_as_info {
                String::from("on")
            } else {
                String::from("off")
            }
        }
    };
    let interval = humantime::format_duration(app.tracer_config().min_round_duration);
    let grace = humantime::format_duration(app.tracer_config().grace_duration);
    let first_ttl = app.tracer_config().first_ttl;
    let max_ttl = app.tracer_config().max_ttl;
    let max_hosts = app
        .tui_config
        .max_addrs
        .map_or_else(|| String::from("auto"), |m| m.to_string());
    let source = render_source(app);
    let dest = render_destination(app);
    let target = format!("{} -> {}", source, dest);
    let left_spans = vec![
        Spans::from(vec![
            Span::styled("Target: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(target),
        ]),
        Spans::from(vec![
            Span::styled("Config: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!("protocol={} dns={} as-info={} interval={} grace={} start-ttl={} max-ttl={} max-hosts={}",
                              protocol, dns, as_info, interval, grace, first_ttl, max_ttl, max_hosts))]),
        Spans::from(vec![
            Span::styled("Status: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(if let Some(start) = app.frozen_start {
                format!(
                    "Frozen ({})",
                    humantime::format_duration(Duration::from_secs(
                        start.elapsed().unwrap_or_default().as_secs()
                    ))
                )
            } else {
                String::from("Running")
            }),
            Span::raw(format!(
                ", discovered {} hops",
                app.tracer_data().hops().len()
            )),
        ]),
    ];

    let left = Paragraph::new(left_spans)
        .style(Style::default())
        .block(header_block)
        .alignment(Alignment::Left);
    f.render_widget(right, rect);
    f.render_widget(left, rect);
}

/// Render the source address of the trace.
fn render_source(app: &mut TuiApp) -> String {
    let src_hostname = app.resolver.reverse_lookup(app.tracer_config().source_addr);
    let src_addr = app.tracer_config().source_addr;
    match app.tracer_config().port_direction {
        PortDirection::None => {
            format!("{} ({})", src_hostname, src_addr)
        }
        PortDirection::FixedDest(_) => {
            format!("{}:* ({}:*)", src_hostname, src_addr)
        }
        PortDirection::FixedSrc(src) | PortDirection::FixedBoth(src, _) => {
            format!("{}:{} ({}:{})", src_hostname, src.0, src_addr, src.0)
        }
    }
}

/// Render the destination address.
fn render_destination(app: &mut TuiApp) -> String {
    let dest_hostname = &app.tracer_config().target_hostname;
    let dest_addr = app.tracer_config().target_addr;
    match app.tracer_config().port_direction {
        PortDirection::None => {
            format!("{} ({})", dest_hostname, dest_addr)
        }
        PortDirection::FixedSrc(_) => {
            format!("{}:* ({}:*)", dest_hostname, dest_addr)
        }
        PortDirection::FixedDest(dest) | PortDirection::FixedBoth(_, dest) => {
            format!("{}:{} ({}:{})", dest_hostname, dest.0, dest_addr, dest.0)
        }
    }
}

/// Format the `DnsResolveMethod`.
fn format_dns_method(resolve_method: DnsResolveMethod) -> String {
    match resolve_method {
        DnsResolveMethod::System => String::from("system"),
        DnsResolveMethod::Resolv => String::from("resolv"),
        DnsResolveMethod::Google => String::from("google"),
        DnsResolveMethod::Cloudflare => String::from("cloudflare"),
    }
}

/// Render the tabs, one per trace.
fn render_tabs<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp, rect: Rect) {
    let tabs_block = Block::default()
        .title("Traces")
        .title_alignment(Alignment::Left)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .style(Style::default());
    let titles: Vec<_> = app
        .trace_info
        .iter()
        .map(|trace| {
            Spans::from(Span::styled(
                &trace.target_hostname,
                Style::default().fg(Color::Green),
            ))
        })
        .collect();
    let tabs = Tabs::new(titles)
        .block(tabs_block.clone())
        .select(app.trace_selected)
        .style(Style::default())
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(Color::Black),
        );
    f.render_widget(tabs, rect);
}

/// Render the body.
///
/// This is the table of hop data or, if there is no data, the splash screen.
fn render_body<B: Backend>(f: &mut Frame<'_, B>, rec: Rect, app: &mut TuiApp) {
    if app.tracer_data().hops().is_empty() {
        render_splash(f, rec);
    } else {
        render_table(f, app, rec);
    }
}

/// Render the splash screen.
///
/// This is shown on startup whilst we await the first round of data to be available.
fn render_splash<B: Backend>(f: &mut Frame<'_, B>, rect: Rect) {
    let chunks = Layout::default()
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(rect);
    let block = Block::default()
        .title("Hops")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .style(Style::default());
    let splash = vec![
        r#" _____    _                "#,
        r#"|_   _| _(_)_ __ _ __ _  _ "#,
        r#"  | || '_| | '_ \ '_ \ || |"#,
        r#"  |_||_| |_| .__/ .__/\_, |"#,
        r#"           |_|  |_|   |__/ "#,
        "",
        "Awaiting data...",
    ];
    let spans: Vec<_> = splash
        .into_iter()
        .map(|line| Spans::from(Span::styled(line, Style::default())))
        .collect();
    let paragraph = Paragraph::new(spans).alignment(Alignment::Center);
    f.render_widget(block, rect);
    f.render_widget(paragraph, chunks[1]);
}

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
fn render_table<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp, rect: Rect) {
    let header = render_table_header();
    let selected_style = Style::default().add_modifier(Modifier::REVERSED);
    let rows = app.tracer_data().hops().iter().map(|hop| {
        render_table_row(
            hop,
            &app.resolver,
            app.tracer_data().is_target(hop),
            app.tui_config.address_mode,
            app.tui_config.lookup_as_info,
            app.tui_config.max_addrs,
        )
    });
    let table = Table::new(rows)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title("Hops"),
        )
        .highlight_style(selected_style)
        .widths(&TABLE_WIDTH);
    f.render_stateful_widget(table, rect, &mut app.table_state);
}

/// Render the table header.
fn render_table_header() -> Row<'static> {
    let header_cells = TABLE_HEADER
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Black)));
    Row::new(header_cells)
        .style(Style::default().bg(Color::White))
        .height(1)
        .bottom_margin(0)
}

/// Render a single row in the table of hops.
fn render_table_row(
    hop: &Hop,
    dns: &DnsResolver,
    is_target: bool,
    address_mode: AddressMode,
    lookup_as_info: bool,
    max_addr: Option<u8>,
) -> Row<'static> {
    let ttl_cell = render_ttl_cell(hop);
    let hostname_cell = render_hostname_cell(hop, dns, address_mode, lookup_as_info, max_addr);
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
    let row_height = hop
        .addr_count()
        .min(max_addr.unwrap_or(u8::MAX) as usize)
        .max(1) as u16;
    Row::new(cells).height(row_height).bottom_margin(0)
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

fn render_hostname_cell(
    hop: &Hop,
    dns: &DnsResolver,
    address_mode: AddressMode,
    lookup_as_info: bool,
    max_addr: Option<u8>,
) -> Cell<'static> {
    /// Format a `DnsEntry` with or without `AS` information (if available)
    fn format_dns_entry(dns_entry: DnsEntry, lookup_as_info: bool) -> String {
        match dns_entry {
            DnsEntry::Resolved(Resolved::Normal(_, hosts)) => hosts.join(" "),
            DnsEntry::Resolved(Resolved::WithAsInfo(_, hosts, asinfo)) => {
                if lookup_as_info {
                    format!("AS{} {}", asinfo.asn, hosts.join(" "))
                } else {
                    hosts.join(" ")
                }
            }
            DnsEntry::Pending(ip) | DnsEntry::NotFound(ip) => format!("{}", ip),
            DnsEntry::Failed(ip) => format!("Failed: {}", ip),
            DnsEntry::Timeout(ip) => format!("Timeout: {}", ip),
        }
    }
    /// Perform a reverse DNS lookup for an address and format the result.
    fn format_address(
        addr: &IpAddr,
        freq: usize,
        hop: &Hop,
        dns: &DnsResolver,
        address_mode: AddressMode,
        lookup_as_info: bool,
    ) -> String {
        let addr_fmt = match address_mode {
            AddressMode::IP => addr.to_string(),
            AddressMode::Host => {
                if lookup_as_info {
                    let entry = dns.reverse_lookup_with_asinfo(*addr);
                    format_dns_entry(entry, true)
                } else {
                    let entry = dns.reverse_lookup(*addr);
                    format_dns_entry(entry, false)
                }
            }
            AddressMode::Both => {
                let hostname = if lookup_as_info {
                    let entry = dns.reverse_lookup_with_asinfo(*addr);
                    format_dns_entry(entry, true)
                } else {
                    let entry = dns.reverse_lookup(*addr);
                    format_dns_entry(entry, false)
                };
                format!("{} ({})", hostname, addr)
            }
        };

        if hop.addr_count() > 1 {
            format!(
                "{} [{:.1}%]",
                addr_fmt,
                (freq as f64 / hop.total_recv() as f64) * 100_f64
            )
        } else {
            addr_fmt
        }
    }

    Cell::from(if hop.total_recv() > 0 {
        match max_addr {
            None => hop
                .addrs_with_counts()
                .map(|(addr, &freq)| {
                    format_address(addr, freq, hop, dns, address_mode, lookup_as_info)
                })
                .join("\n"),
            Some(max_addr) => hop
                .addrs_with_counts()
                .sorted_unstable_by_key(|(_, &cnt)| cnt)
                .rev()
                .take(max_addr as usize)
                .map(|(addr, &freq)| {
                    format_address(addr, freq, hop, dns, address_mode, lookup_as_info)
                })
                .join("\n"),
        }
    } else {
        String::from("No response")
    })
}

fn render_last_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(
        hop.last_ms()
            .map(|last| format!("{:.1}", last))
            .unwrap_or_default(),
    )
}

fn render_best_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(
        hop.best_ms()
            .map(|best| format!("{:.1}", best))
            .unwrap_or_default(),
    )
}

fn render_worst_cell(hop: &Hop) -> Cell<'static> {
    Cell::from(
        hop.worst_ms()
            .map(|worst| format!("{:.1}", worst))
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

/// Render the footer.
///
/// This contains the history and frequency charts.
fn render_footer<B: Backend>(f: &mut Frame<'_, B>, rec: Rect, app: &mut TuiApp) {
    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(75), Constraint::Percentage(25)].as_ref())
        .split(rec);
    render_history(f, app, bottom_chunks[0]);
    render_ping_frequency(f, app, bottom_chunks[1]);
    if app.show_help {
        render_help(f);
    }
}

/// Render the ping history for the final hop which is typically the target.
fn render_history<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp, rect: Rect) {
    let target_hop = app.table_state.selected().map_or_else(
        || app.tracer_data().target_hop(),
        |s| &app.tracer_data().hops()[s],
    );
    let data = target_hop
        .samples()
        .iter()
        .take(rect.width as usize)
        .map(|s| (s.as_secs_f64() * 1000_f64) as u64)
        .collect::<Vec<_>>();
    let history = Sparkline::default()
        .block(
            Block::default()
                .title(format!("Samples #{}", target_hop.ttl()))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        )
        .data(&data)
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(history, rect);
}

/// Render a histogram of ping frequencies.
fn render_ping_frequency<B: Backend>(f: &mut Frame<'_, B>, app: &mut TuiApp, rect: Rect) {
    let target_hop = app.table_state.selected().map_or_else(
        || app.tracer_data().target_hop(),
        |s| &app.tracer_data().hops()[s],
    );
    let freq_data = sample_frequency(target_hop.samples());
    let freq_data_ref: Vec<_> = freq_data.iter().map(|(b, c)| (b.as_str(), *c)).collect();
    let barchart = BarChart::default()
        .block(
            Block::default()
                .title(format!("Frequency #{}", target_hop.ttl()))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        )
        .data(freq_data_ref.as_slice())
        .bar_width(4)
        .bar_gap(1)
        .bar_style(Style::default().fg(Color::Green))
        .value_style(
            Style::default()
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(barchart, rect);
}

/// Render help
fn render_help<B: Backend>(f: &mut Frame<'_, B>) {
    let block = Block::default()
        .title(" Controls ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::Blue))
        .border_type(BorderType::Double);
    let control_spans: Vec<_> = HELP_LINES.iter().map(|&line| Spans::from(line)).collect();
    let control = Paragraph::new(control_spans)
        .style(Style::default())
        .block(block.clone())
        .alignment(Alignment::Left);
    let area = centered_rect(50, 40, f.size());
    f.render_widget(Clear, area);
    f.render_widget(block, area);
    f.render_widget(control, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}

/// Return the frequency % grouped by sample duration.
fn sample_frequency(samples: &[Duration]) -> Vec<(String, u64)> {
    let sample_count = samples.len();
    let mut count_by_duration: BTreeMap<u128, u64> = BTreeMap::new();
    for sample in samples {
        if sample.as_millis() > 0 {
            *count_by_duration.entry(sample.as_millis()).or_default() += 1;
        }
    }
    count_by_duration
        .iter()
        .map(|(ping, count)| {
            let ping = format!("{}", ping);
            let freq_pct = ((*count as f64 / sample_count as f64) * 100_f64) as u64;
            (ping, freq_pct)
        })
        .collect()
}
