use crate::config::AddressMode;
use crate::frontend::binding::CTRL_C;
use crate::geoip::GeoIpLookup;
use crate::TraceInfo;
pub use config::TuiConfig;
use crossterm::event::KeyEventKind;
use crossterm::{
    event::{self, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    Terminal,
};
use std::io;
use trippy::dns::DnsResolver;
use tui_app::TuiApp;

mod binding;
mod config;
mod render;
mod theme;
mod tui_app;

/// Run the frontend TUI.
pub fn run_frontend(
    traces: Vec<TraceInfo>,
    tui_config: TuiConfig,
    resolver: DnsResolver,
    geoip_lookup: GeoIpLookup,
) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        disable_raw_mode().expect("disable_raw_mode");
        execute!(io::stdout(), LeaveAlternateScreen).expect("execute LeaveAlternateScreen");
        original_hook(panic);
    }));
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let preserve_screen = tui_config.preserve_screen;
    let res = run_app(&mut terminal, traces, tui_config, resolver, geoip_lookup);
    disable_raw_mode()?;
    if !preserve_screen {
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    }
    terminal.show_cursor()?;
    if let Err(err) = res {
        println!("{err:?}");
    }
    Ok(())
}

fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    trace_info: Vec<TraceInfo>,
    tui_config: TuiConfig,
    resolver: DnsResolver,
    geoip_lookup: GeoIpLookup,
) -> io::Result<()> {
    let mut app = TuiApp::new(tui_config, resolver, geoip_lookup, trace_info);
    loop {
        if app.frozen_start.is_none() {
            app.snapshot_trace_data();
            app.clamp_selected_hop();
        };
        terminal.draw(|f| render::app::render(f, &mut app))?;
        if event::poll(app.tui_config.refresh_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    let bindings = &app.tui_config.bindings;
                    if app.show_help {
                        if bindings.toggle_help.check(key)
                            || bindings.toggle_help_alt.check(key)
                            || bindings.clear_selection.check(key)
                            || bindings.quit.check(key)
                        {
                            app.toggle_help();
                        }
                    } else if app.show_settings {
                        if bindings.toggle_settings.check(key)
                            || bindings.clear_selection.check(key)
                            || bindings.quit.check(key)
                        {
                            app.toggle_settings();
                        } else if bindings.previous_trace.check(key) {
                            app.previous_settings_tab();
                        } else if bindings.next_trace.check(key) {
                            app.next_settings_tab();
                        } else if bindings.next_hop.check(key) {
                            app.next_settings_item();
                        } else if bindings.previous_hop.check(key) {
                            app.previous_settings_item();
                        }
                    } else if bindings.toggle_help.check(key) || bindings.toggle_help_alt.check(key)
                    {
                        app.toggle_help();
                    } else if bindings.toggle_settings.check(key) {
                        app.toggle_settings();
                    } else if bindings.next_hop.check(key) {
                        app.next_hop();
                    } else if bindings.previous_hop.check(key) {
                        app.previous_hop();
                    } else if bindings.previous_trace.check(key) {
                        app.previous_trace();
                        app.clear();
                    } else if bindings.next_trace.check(key) {
                        app.next_trace();
                        app.clear();
                    } else if bindings.next_hop_address.check(key) {
                        app.next_hop_address();
                    } else if bindings.previous_hop_address.check(key) {
                        app.previous_hop_address();
                    } else if bindings.address_mode_ip.check(key) {
                        app.tui_config.address_mode = AddressMode::IP;
                    } else if bindings.address_mode_host.check(key) {
                        app.tui_config.address_mode = AddressMode::Host;
                    } else if bindings.address_mode_both.check(key) {
                        app.tui_config.address_mode = AddressMode::Both;
                    } else if bindings.toggle_freeze.check(key) {
                        app.toggle_freeze();
                    } else if bindings.toggle_chart.check(key) {
                        app.toggle_chart();
                    } else if bindings.toggle_map.check(key) {
                        app.toggle_map();
                    } else if bindings.contract_hosts_min.check(key) {
                        app.contract_hosts_min();
                    } else if bindings.expand_hosts_max.check(key) {
                        app.expand_hosts_max();
                    } else if bindings.contract_hosts.check(key) {
                        app.contract_hosts();
                    } else if bindings.expand_hosts.check(key) {
                        app.expand_hosts();
                    } else if bindings.chart_zoom_in.check(key) {
                        app.zoom_in();
                    } else if bindings.chart_zoom_out.check(key) {
                        app.zoom_out();
                    } else if bindings.clear_trace_data.check(key) {
                        app.clear();
                        app.clear_trace_data();
                    } else if bindings.clear_dns_cache.check(key) {
                        app.resolver.flush();
                    } else if bindings.clear_selection.check(key) {
                        app.clear();
                    } else if bindings.toggle_as_info.check(key) {
                        app.toggle_asinfo();
                    } else if bindings.toggle_hop_details.check(key) {
                        app.toggle_hop_details();
                    } else if bindings.quit.check(key) || CTRL_C.check(key) {
                        return Ok(());
                    }
                }
            }
        }
    }
}
