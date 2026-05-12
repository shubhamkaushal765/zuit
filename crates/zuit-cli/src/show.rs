//! `zuit show`: start the daemon if needed, then open the browser.

use anyhow::{Context as _, Result};
use zuit_show::daemon::{self, DaemonStatus};

/// Runs the `show` subcommand.
///
/// If the daemon is already running the browser is opened immediately.
/// Otherwise a fresh daemon is spawned via a double-fork and the browser
/// is opened once the daemon is confirmed healthy.
///
/// # Errors
///
/// Returns an error if `HOME` is unset, if the fork syscall fails, or if
/// the daemon does not become healthy within the 2-second startup budget.
pub fn run() -> Result<i32> {
    let home = home_dir()?;

    // Ensure the home directory exists before daemon::spawn tries to write
    // daemon.json; create_dir_all is idempotent.
    std::fs::create_dir_all(&home)
        .with_context(|| format!("creating zuit home directory {}", home.display()))?;

    let version = env!("CARGO_PKG_VERSION");

    match daemon::inspect(&home, version, |info| {
        Ok(daemon::probe_healthz(info.port, version))
    }) {
        DaemonStatus::Running(info) => {
            let url = format!("http://127.0.0.1:{}", info.port);
            println!("zuit daemon running at {url}");
            let _ = webbrowser::open(&url);
            Ok(0)
        }
        DaemonStatus::Stale(_) | DaemonStatus::NotRunning => {
            // Per spec §7.1 step 3: SIGTERM any stale PID and unlink the file
            // before spawning a replacement. `kill_stale` is a no-op when the
            // file is missing.
            daemon::kill_stale(&home);

            let home_clone = home.clone();
            let version_str = version.to_owned();
            let info = daemon::spawn(&home, version, move |port| {
                let store = std::sync::Arc::new(zuit_show::HistoryStore::open(home_clone));
                let _handle =
                    zuit_show::start(&format!("127.0.0.1:{port}"), store, version_str)?;
                // The server worker thread is alive; block here until SIGTERM.
                // _handle is dropped on process exit, triggering stop().
                std::thread::park();
                Ok(())
            })
            .context("spawning daemon")?;

            let url = format!("http://127.0.0.1:{}", info.port);
            println!("zuit daemon started at {url} (pid {})", info.pid);
            let _ = webbrowser::open(&url);
            Ok(0)
        }
    }
}

fn home_dir() -> Result<std::path::PathBuf> {
    std::env::var_os("HOME")
        .map(|h| std::path::PathBuf::from(h).join(".zuit"))
        .context("HOME not set")
}
