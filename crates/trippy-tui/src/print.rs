use crate::config::{Args, TuiCommandItem, TuiThemeItem};
use crate::locale::available_locales;
use clap::CommandFactory;
use clap_complete::Shell;
use std::process;
use strum::VariantNames;

pub fn print_tui_theme_items() {
    println!("{}", tui_theme_items());
    process::exit(0);
}

pub fn print_tui_binding_commands() {
    println!("{}", tui_binding_commands());
    process::exit(0);
}

pub fn print_config_template() {
    println!("{}", include_str!("../trippy-config-sample.toml"));
    process::exit(0);
}

pub fn print_shell_completions(shell: Shell) -> anyhow::Result<()> {
    println!("{}", shell_completions(shell)?);
    process::exit(0);
}

pub fn print_man_page() -> anyhow::Result<()> {
    println!("{}", man_page()?);
    process::exit(0);
}

pub fn print_locales() {
    println!("TUI locales: {}", available_locales().join(", "));
    process::exit(0);
}

fn tui_theme_items() -> String {
    format!(
        "TUI theme color items: {}",
        TuiThemeItem::VARIANTS.join(", ")
    )
}

fn tui_binding_commands() -> String {
    format!(
        "TUI binding commands: {}",
        TuiCommandItem::VARIANTS.join(", ")
    )
}

fn shell_completions(shell: Shell) -> anyhow::Result<String> {
    let mut cmd = Args::command();
    let name = cmd.get_name().to_string();
    let mut buffer: Vec<u8> = vec![];
    clap_complete::generate(shell, &mut cmd, name, &mut buffer);
    Ok(String::from_utf8(buffer)?)
}

fn man_page() -> anyhow::Result<String> {
    let cmd = Args::command();
    let mut buffer: Vec<u8> = vec![];
    clap_mangen::Man::new(cmd).render(&mut buffer)?;
    Ok(String::from_utf8(buffer)?)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::util::{insta, remove_whitespace};
    use test_case::test_case;

    #[test_case(&tui_theme_items(), "tui theme items match"; "tui theme items match")]
    #[test_case(&tui_binding_commands(), "tui binding commands match"; "tui binding commands match")]
    #[test_case(&shell_completions(Shell::Bash).unwrap(), "generate bash shell completions"; "generate bash shell completions")]
    #[test_case(&shell_completions(Shell::Elvish).unwrap(), "generate elvish shell completions"; "generate elvish shell completions")]
    #[test_case(&shell_completions(Shell::Fish).unwrap(), "generate fish shell completions"; "generate fish shell completions")]
    #[test_case(&shell_completions(Shell::PowerShell).unwrap(), "generate powershell shell completions"; "generate powershell shell completions")]
    #[test_case(&shell_completions(Shell::Zsh).unwrap(), "generate zsh shell completions"; "generate zsh shell completions")]
    #[test_case(&man_page().unwrap(), "generate man page"; "generate man page")]
    fn test_output(actual: &str, name: &str) {
        insta(name, || {
            insta::assert_snapshot!(remove_whitespace(actual.to_string()));
        });
    }
}
