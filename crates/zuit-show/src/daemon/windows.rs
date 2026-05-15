//! Daemon stub for non-Unix targets (currently exercised on Windows).
//!
//! The real daemon uses a POSIX double-fork plus `SIGTERM`/`SIGKILL` signals
//! (see [`super::unix`] on Unix builds), neither of which has a faithful
//! equivalent on Windows. Rather than gating the `show` / `status` / `stop`
//! CLI surface behind `#[cfg(unix)]` — which would require parallel CLI
//! plumbing and would surprise users by silently dropping commands — we ship
//! a stub with the same public types and functions so the binary links and
//! the commands report a clear "not supported" status at runtime.
//!
//! Behaviour:
//! - [`inspect`] always returns [`DaemonStatus::NotRunning`] (no daemon can
//!   exist on this target).
//! - [`probe_healthz`] always returns `false` (no daemon to probe).
//! - [`kill_stale`] is a no-op.
//! - [`stop`] is an idempotent no-op returning `Ok(())` (matches the Unix
//!   "file missing" branch).
//! - [`spawn`] / [`spawn_with_listener`] return an
//!   [`std::io::ErrorKind::Unsupported`] error so `zuit show` exits cleanly.

use serde::{Deserialize, Serialize};
use std::net::TcpListener;
use std::path::Path;

/// Persisted daemon registration. Kept structurally identical to the Unix
/// variant so JSON written by a Unix daemon would still deserialize on a
/// Windows host (useful for shared-home setups behind WSL, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DaemonInfo {
    /// Process id of the running daemon.
    pub pid: i32,
    /// TCP port bound on `127.0.0.1`.
    pub port: u16,
    /// RFC-3339 start time (second precision, UTC).
    pub started_at: String,
    /// `cargo`-derived version of the `zuit` binary that started it.
    pub zuit_version: String,
}

/// Result of `zuit status`. Mirrors the Unix variant — Windows can only ever
/// produce [`DaemonStatus::NotRunning`] from [`inspect`].
#[derive(Debug)]
pub enum DaemonStatus {
    /// No daemon record exists (the only status reachable on Windows).
    NotRunning,
    /// Present for API parity with the Unix module; never produced on Windows.
    Running(DaemonInfo),
    /// Present for API parity with the Unix module; never produced on Windows.
    Stale(DaemonInfo),
}

/// Inspect daemon state. Always returns [`DaemonStatus::NotRunning`] on
/// Windows because the daemon cannot be spawned on this target.
///
/// The `healthz_ok` callback is accepted (and ignored) to keep the signature
/// identical to the Unix implementation so the CLI can call it unconditionally.
pub fn inspect(
    _home: &Path,
    _expected_version: &str,
    _healthz_ok: impl FnOnce(&DaemonInfo) -> Result<bool, std::io::Error>,
) -> DaemonStatus {
    DaemonStatus::NotRunning
}

/// HTTP healthz probe. Returns `false` on Windows: no daemon can exist for
/// this binary to talk to.
#[must_use]
pub fn probe_healthz(_port: u16, _expected_version: &str) -> bool {
    false
}

/// Best-effort stale cleanup. No-op on Windows.
pub fn kill_stale(_home: &Path) {}

/// Stop the daemon. No-op on Windows (idempotent success — matches the Unix
/// "no daemon.json present" branch).
///
/// # Errors
///
/// Never returns an error on Windows; the `Result` is kept for API parity.
pub fn stop(_home: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

/// Spawn the daemon (legacy port-callback variant). Unsupported on Windows.
///
/// # Errors
///
/// Always returns an [`std::io::ErrorKind::Unsupported`] error.
pub fn spawn<F>(_home: &Path, _version: &str, _serve: F) -> Result<DaemonInfo, std::io::Error>
where
    F: FnOnce(u16) -> std::io::Result<()> + Send + 'static,
{
    Err(unsupported_error())
}

/// Spawn the daemon (race-free listener variant). Unsupported on Windows.
///
/// # Errors
///
/// Always returns an [`std::io::ErrorKind::Unsupported`] error.
pub fn spawn_with_listener<F>(
    _home: &Path,
    _version: &str,
    _serve: F,
) -> Result<DaemonInfo, std::io::Error>
where
    F: FnOnce(TcpListener) -> std::io::Result<()> + Send + 'static,
{
    Err(unsupported_error())
}

fn unsupported_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the zuit show daemon is not supported on Windows; \
         the rest of the CLI (analyze, lsp, watch, etc.) works normally",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dummy_home() -> PathBuf {
        PathBuf::from("C:\\does-not-exist\\zuit-stub-test")
    }

    #[test]
    fn inspect_is_always_not_running() {
        let s = inspect(&dummy_home(), "0.1.0", |_| Ok(true));
        assert!(matches!(s, DaemonStatus::NotRunning));
    }

    #[test]
    fn probe_healthz_is_always_false() {
        assert!(!probe_healthz(31415, "0.1.0"));
    }

    #[test]
    fn stop_is_idempotent_noop() {
        // Stop should succeed even when no daemon exists and the path is bogus.
        stop(&dummy_home()).expect("stop must not error on the stub");
    }

    #[test]
    fn kill_stale_does_not_panic() {
        // No assertion beyond "this does not panic" — kill_stale is best-effort.
        kill_stale(&dummy_home());
    }

    #[test]
    fn spawn_returns_unsupported_error() {
        let err = spawn(&dummy_home(), "0.1.0", |_port| Ok(())).expect_err("must be unsupported");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }

    #[test]
    fn spawn_with_listener_returns_unsupported_error() {
        let err = spawn_with_listener(&dummy_home(), "0.1.0", |_listener| Ok(()))
            .expect_err("must be unsupported");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
}
