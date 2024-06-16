#![warn(clippy::all, clippy::pedantic, clippy::nursery, rust_2018_idioms)]
#![allow(
    clippy::module_name_repetitions,
    clippy::redundant_field_names,
    clippy::struct_field_names,
    clippy::option_if_let_else,
    clippy::missing_const_for_fn,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::redundant_pub_crate,
    clippy::struct_excessive_bools,
    clippy::cognitive_complexity,
    clippy::option_option
)]
#![forbid(unsafe_code)]

use crate::config::TrippyAction;
use clap::Parser;
use config::Args;
use std::process;
use trippy_privilege::Privilege;

mod app;
mod backend;
mod config;
mod frontend;
mod geoip;
mod print;
mod report;
mod util;

fn main() -> anyhow::Result<()> {
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
    }
    Ok(())
}
