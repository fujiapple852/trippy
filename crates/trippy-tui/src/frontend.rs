use crate::app::TraceInfo;
use crate::config::AddressMode;
use crate::frontend::binding::CTRL_C;
use crate::geoip::GeoIpLookup;
pub use config::TuiConfig;
use crossterm::event::KeyEventKind;
use crossterm::{
    event::{self, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::layout::Position;
use ratatui::{
    backend::{Backend, CrosstermBackend},
    DefaultTerminal, Terminal,
};
use std::io;
use trippy_dns::DnsResolver;
use tui_app::TuiApp;

mod binding;
mod columns;
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
    let mut app = TuiApp::new(tui_config, resolver, geoip_lookup, traces);
    let res = run_app(&mut terminal, &mut app);
    disable_raw_mode()?;
    if preserve_screen || matches!(res, Ok(ExitAction::PreserveScreen)) {
        terminal.set_cursor_position(Position::new(0, terminal.size()?.height))?;
        terminal.backend_mut().append_lines(1)?;
    } else {
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    }
    terminal.show_cursor()?;
    if let Err(err) = res {
        println!("{err:?}");
    }
    Ok(())
}

/// The exit action to take when the frontend exits.
enum ExitAction {
    /// Exit the frontend normally.
    Normal,
    /// Preserve the screen on exit.
    PreserveScreen,
}

#[expect(clippy::too_many_lines)]
fn run_app(terminal: &mut DefaultTerminal, app: &mut TuiApp) -> io::Result<ExitAction> {
    loop {
        if app.frozen_start.is_none() {
            app.snapshot_trace_data();
            app.clamp_selected_hop();
            app.update_order_flow_counts();
        }
        terminal.draw(|f| render::app::render(f, app))?;
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
                        } else if bindings.toggle_settings.check(key) {
                            app.toggle_help();
                            app.toggle_settings();
                        } else if bindings.toggle_settings_tui.check(key) {
                            app.toggle_help();
                            app.show_settings_columns(0);
                        } else if bindings.toggle_settings_trace.check(key) {
                            app.toggle_help();
                            app.show_settings_columns(1);
                        } else if bindings.toggle_settings_dns.check(key) {
                            app.toggle_help();
                            app.show_settings_columns(2);
                        } else if bindings.toggle_settings_geoip.check(key) {
                            app.toggle_help();
                            app.show_settings_columns(3);
                        } else if bindings.toggle_settings_bindings.check(key) {
                            app.toggle_help();
                            app.show_settings_columns(4);
                        } else if bindings.toggle_settings_theme.check(key) {
                            app.toggle_help();
                            app.show_settings_columns(5);
                        } else if bindings.toggle_settings_columns.check(key) {
                            app.toggle_help();
                            app.show_settings_columns(6);
                        }
                    } else if app.show_settings {
                        if bindings.toggle_settings.check(key)
                            || bindings.clear_selection.check(key)
                            || bindings.quit.check(key)
                        {
                            app.toggle_settings();
                        } else if bindings.toggle_settings_tui.check(key) {
                            app.show_settings_columns(0);
                        } else if bindings.toggle_settings_trace.check(key) {
                            app.show_settings_columns(1);
                        } else if bindings.toggle_settings_dns.check(key) {
                            app.show_settings_columns(2);
                        } else if bindings.toggle_settings_geoip.check(key) {
                            app.show_settings_columns(3);
                        } else if bindings.toggle_settings_bindings.check(key) {
                            app.show_settings_columns(4);
                        } else if bindings.toggle_settings_theme.check(key) {
                            app.show_settings_columns(5);
                        } else if bindings.toggle_settings_columns.check(key) {
                            app.show_settings_columns(6);
                        } else if bindings.previous_trace.check(key) {
                            app.previous_settings_tab();
                        } else if bindings.next_trace.check(key) {
                            app.next_settings_tab();
                        } else if bindings.next_hop.check(key) {
                            app.next_settings_item();
                        } else if bindings.previous_hop.check(key) {
                            app.previous_settings_item();
                        } else if bindings.toggle_chart.check(key) {
                            app.toggle_column_visibility();
                        } else if bindings.next_hop_address.check(key) {
                            app.move_column_down();
                        } else if bindings.previous_hop_address.check(key) {
                            app.move_column_up();
                        }
                    } else if bindings.toggle_help.check(key) || bindings.toggle_help_alt.check(key)
                    {
                        app.toggle_help();
                    } else if bindings.toggle_settings.check(key) {
                        app.toggle_settings();
                    } else if bindings.toggle_settings_tui.check(key) {
                        app.show_settings_columns(0);
                    } else if bindings.toggle_settings_trace.check(key) {
                        app.show_settings_columns(1);
                    } else if bindings.toggle_settings_dns.check(key) {
                        app.show_settings_columns(2);
                    } else if bindings.toggle_settings_geoip.check(key) {
                        app.show_settings_columns(3);
                    } else if bindings.toggle_settings_bindings.check(key) {
                        app.show_settings_columns(4);
                    } else if bindings.toggle_settings_theme.check(key) {
                        app.show_settings_columns(5);
                    } else if bindings.toggle_settings_columns.check(key) {
                        app.show_settings_columns(6);
                    } else if bindings.next_hop.check(key) {
                        app.next_hop();
                    } else if bindings.previous_hop.check(key) {
                        app.previous_hop();
                    } else if bindings.previous_trace.check(key) {
                        if app.show_flows {
                            app.previous_flow();
                        } else {
                            app.previous_trace();
                        }
                    } else if bindings.next_trace.check(key) {
                        if app.show_flows {
                            app.next_flow();
                        } else {
                            app.next_trace();
                        }
                    } else if bindings.next_hop_address.check(key) {
                        app.next_hop_address();
                    } else if bindings.previous_hop_address.check(key) {
                        app.previous_hop_address();
                    } else if bindings.address_mode_ip.check(key) {
                        app.tui_config.address_mode = AddressMode::Ip;
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
                    } else if bindings.toggle_flows.check(key) {
                        app.toggle_flows();
                    } else if bindings.expand_privacy.check(key) {
                        app.expand_privacy();
                    } else if bindings.contract_privacy.check(key) {
                        app.contract_privacy();
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
                        return Ok(ExitAction::Normal);
                    } else if bindings.quit_preserve_screen.check(key) {
                        return Ok(ExitAction::PreserveScreen);
                    }
                }
            }
        }
    }
}
