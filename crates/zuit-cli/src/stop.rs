//! `zuit stop`: stop the running scan-history daemon.

use anyhow::{Context as _, Result};

/// Runs the `stop` subcommand.
///
/// Sends SIGTERM to the daemon recorded in `~/.zuit/daemon.json` and
/// removes the file.  Exits successfully (code 0) even if no daemon is
/// running (idempotent).
///
/// # Errors
///
/// Returns an error if `HOME` is unset or if the daemon's process name
/// does not match `"zuit"` (recycled-PID guard).
pub fn run() -> Result<i32> {
    let home = home_dir()?;
    zuit_show::daemon::stop(&home).context("stopping daemon")?;
    println!("zuit daemon stopped");
    Ok(0)
}

fn home_dir() -> Result<std::path::PathBuf> {
    std::env::var_os("HOME")
        .map(|h| std::path::PathBuf::from(h).join(".zuit"))
        .context("HOME not set")
}
