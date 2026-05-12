//! `zuit status`: print the scan-history daemon status.

use anyhow::{Context as _, Result};

/// Runs the `status` subcommand.
///
/// Inspects `~/.zuit/daemon.json` and performs a live healthz probe to
/// determine whether the daemon is running, stale, or absent.
///
/// # Errors
///
/// Returns an error if `HOME` is unset.
pub fn run() -> Result<i32> {
    let home = home_dir()?;
    let version = env!("CARGO_PKG_VERSION");

    match zuit_show::daemon::inspect(&home, version, |info| {
        Ok(zuit_show::daemon::probe_healthz(info.port, version))
    }) {
        zuit_show::daemon::DaemonStatus::NotRunning => {
            println!("not running");
        }
        zuit_show::daemon::DaemonStatus::Running(info) => {
            println!(
                "running\n  pid: {}\n  port: {}\n  url: http://127.0.0.1:{}\n  started_at: {}\n  version: {}",
                info.pid, info.port, info.port, info.started_at, info.zuit_version
            );
        }
        zuit_show::daemon::DaemonStatus::Stale(info) => {
            println!(
                "stale daemon (pid {} dead or healthz failed) — run `zuit show` to restart",
                info.pid
            );
        }
    }
    Ok(0)
}

fn home_dir() -> Result<std::path::PathBuf> {
    std::env::var_os("HOME")
        .map(|h| std::path::PathBuf::from(h).join(".zuit"))
        .context("HOME not set")
}
