//! `completions` subcommand: emit shell completion script to stdout.
//!
//! Supported shells: `bash`, `zsh`, `fish`, `powershell`, `elvish`.
//!
//! # Example
//!
//! ```sh
//! # Bash
//! zuit completions bash > ~/.local/share/bash-completion/completions/zuit
//!
//! # Zsh
//! zuit completions zsh > ~/.zfunc/_zuit
//!
//! # Fish
//! zuit completions fish > ~/.config/fish/completions/zuit.fish
//! ```

use clap::CommandFactory;
use clap_complete::Shell;

use crate::cli::Cli;

/// Generates a shell completion script and writes it to stdout.
///
/// Always returns exit code `0`.
///
/// # Errors
///
/// This function is infallible — `clap_complete::generate` writes to `stdout()`
/// which only fails on broken pipes (silently ignored at the OS level). The
/// `anyhow::Result<i32>` return type keeps this handler's signature uniform
/// with every other subcommand handler in `main.rs`.
#[allow(clippy::unnecessary_wraps)] // Result<i32> required for uniform match arm type
pub fn run(shell: Shell) -> anyhow::Result<i32> {
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_string();
    clap_complete::generate(shell, &mut cmd, bin_name, &mut std::io::stdout());
    Ok(0)
}
