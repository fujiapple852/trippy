#![allow(
    clippy::struct_excessive_bools,
    clippy::cast_sign_loss,
    clippy::struct_field_names
)]
#![forbid(unsafe_code)]

use crate::config::TrippyAction;
use clap::Parser;
use config::Args;
use std::process;
use trippy_privilege::Privilege;

mod app;
mod config;
mod frontend;
mod geoip;
mod locale;
mod print;
mod report;
mod util;

/// Run the Trippy application.
pub fn trippy() -> anyhow::Result<()> {
    let args = Args::parse();
    let privilege = Privilege::acquire_privileges()?;
    let pid = u16::try_from(process::id() % u32::from(u16::MAX))?;
    match TrippyAction::from(args, &privilege, pid)? {
        TrippyAction::Trippy(cfg) => app::run_trippy(&cfg, pid)?,
        TrippyAction::PrintTuiThemeItems => print::print_tui_theme_items(),
        TrippyAction::PrintTuiBindingCommands => print::print_tui_binding_commands(),
        TrippyAction::PrintConfigTemplate => print::print_config_template(),
        TrippyAction::PrintManPage => print::print_man_page()?,
        TrippyAction::PrintShellCompletions(shell) => print::print_shell_completions(shell)?,
        TrippyAction::PrintLocales => print::print_locales(),
    }
    Ok(())
}
