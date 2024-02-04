use super::*;
use test_case::test_case;

#[test_case("tui_theme_items.txt", &tui_theme_items(); "tui theme items match")]
#[test_case("tui_binding_commands.txt", &tui_binding_commands(); "tui binding commands match")]
#[test_case("completions_bash.txt", &shell_completions(Shell::Bash).unwrap(); "generate bash shell completions")]
#[test_case("completions_elvish.txt", &shell_completions(Shell::Elvish).unwrap(); "generate elvish shell completions")]
#[test_case("completions_fish.txt", &shell_completions(Shell::Fish).unwrap(); "generate fish shell completions")]
#[test_case("completions_powershell.txt", &shell_completions(Shell::PowerShell).unwrap(); "generate powershell shell completions")]
#[test_case("completions_zsh.txt", &shell_completions(Shell::Zsh).unwrap(); "generate zsh shell completions")]
fn test_output(snapshot_name: &str, actual: &str) {
    insta::assert_snapshot!(snapshot_name, actual);
}
