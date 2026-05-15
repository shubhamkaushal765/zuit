//! Daemon lifecycle: PID file, double-fork, healthz reuse. See spec §7.
//!
//! Unix-only implementation. The parent [`daemon`](super) module gates this
//! behind `#[cfg(unix)]` and exposes a [stub](super::windows) on other targets.
// The double-fork sequence (POSIX daemon idiom) requires two `unsafe { fork() }` calls.
// `nix::unistd::fork` is marked unsafe because forking a multi-threaded process is
// hazardous; we call it only before any threads are spawned, making it sound.
// The workspace lint is configured via Cargo (not a source-level `#![forbid]`), so
// this module-level allow is a valid override per the Rust lint delegation rules.
#![allow(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};

use nix::sys::signal::{Signal, kill};
use nix::unistd::{ForkResult, Pid, dup2_stderr, dup2_stdin, dup2_stdout, fork, setsid};

// ──────────────────────────────────────────────────────────────────────────────
// Public types
// ──────────────────────────────────────────────────────────────────────────────

/// Persisted daemon registration: `~/.zuit/daemon.json`.
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

/// Result of `zuit status`.
#[derive(Debug)]
pub enum DaemonStatus {
    /// `daemon.json` does not exist (or is unreadable / unparseable).
    NotRunning,
    /// `daemon.json` exists, PID alive, healthz returns 200 with matching version.
    Running(DaemonInfo),
    /// `daemon.json` exists but PID is dead OR version mismatch OR healthz failed.
    Stale(DaemonInfo),
}

// ──────────────────────────────────────────────────────────────────────────────
// Status inspection
// ──────────────────────────────────────────────────────────────────────────────

/// Pure-ish status inspector.
///
/// The caller passes a `healthz_ok` callback so tests can simulate a healthy
/// or unhealthy daemon without a live HTTP server.
pub fn inspect(
    home: &Path,
    expected_version: &str,
    healthz_ok: impl FnOnce(&DaemonInfo) -> Result<bool, std::io::Error>,
) -> DaemonStatus {
    let path = home.join("daemon.json");
    let Ok(bytes) = std::fs::read(&path) else {
        return DaemonStatus::NotRunning;
    };
    let Ok(info): Result<DaemonInfo, _> = serde_json::from_slice(&bytes) else {
        return DaemonStatus::NotRunning;
    };
    if !is_alive(info.pid) {
        return DaemonStatus::Stale(info);
    }
    if info.zuit_version != expected_version {
        return DaemonStatus::Stale(info);
    }
    match healthz_ok(&info) {
        Ok(true) => DaemonStatus::Running(info),
        _ => DaemonStatus::Stale(info),
    }
}

fn is_alive(pid: i32) -> bool {
    kill(Pid::from_raw(pid), None).is_ok()
}

// ──────────────────────────────────────────────────────────────────────────────
// Healthz probe (production helper)
// ──────────────────────────────────────────────────────────────────────────────

/// HTTP GET `http://127.0.0.1:<port>/api/healthz` with a 1-second timeout.
///
/// Returns `true` only when the response is `{ok: true, version: <expected>}`.
///
/// Uses `into_string()` + `serde_json::from_str` so that ureq's `json` feature
/// (disabled via `default-features = false`) is not required.
#[must_use]
pub fn probe_healthz(port: u16, expected_version: &str) -> bool {
    let url = format!("http://127.0.0.1:{port}/api/healthz");
    let Ok(resp) = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(1))
        .call()
    else {
        return false;
    };
    let Ok(text) = resp.into_string() else {
        return false;
    };
    let Ok(body): Result<serde_json::Value, _> = serde_json::from_str(&text) else {
        return false;
    };
    body.get("ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        && body.get("version").and_then(serde_json::Value::as_str) == Some(expected_version)
}

// ──────────────────────────────────────────────────────────────────────────────
// Stale cleanup
// ──────────────────────────────────────────────────────────────────────────────

/// Best-effort SIGTERM of a stale daemon PID, with the same ownership check as
/// [`stop`]. Errors are swallowed — this is a cleanup step, not a guarantee.
pub fn kill_stale(home: &Path) {
    let path = home.join("daemon.json");
    let Ok(bytes) = std::fs::read(&path) else {
        return;
    };
    let Ok(info): Result<DaemonInfo, _> = serde_json::from_slice(&bytes) else {
        let _ = std::fs::remove_file(&path);
        return;
    };
    if comm_matches(info.pid, "zuit") {
        let _ = kill(Pid::from_raw(info.pid), Signal::SIGTERM);
    }
    let _ = std::fs::remove_file(&path);
}

// ──────────────────────────────────────────────────────────────────────────────
// Full stop
// ──────────────────────────────────────────────────────────────────────────────

/// SIGTERM the daemon with an ownership check; SIGKILL fallback after 2 s;
/// remove `daemon.json`. Idempotent — no-op when the file is missing.
///
/// # Errors
///
/// Returns an error when the comm-name check refuses to signal (recycled PID)
/// or when the JSON in `daemon.json` is malformed.
pub fn stop(home: &Path) -> Result<(), std::io::Error> {
    let path = home.join("daemon.json");
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(()); // not running — idempotent
    };
    let info: DaemonInfo =
        serde_json::from_slice(&bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
    if !comm_matches(info.pid, "zuit") {
        return Err(std::io::Error::other(format!(
            "refusing to SIGTERM pid {}: process name does not contain 'zuit' \
             (recorded version: {})",
            info.pid, info.zuit_version,
        )));
    }
    let _ = kill(Pid::from_raw(info.pid), Signal::SIGTERM);
    // Poll up to 2 s (40 × 50 ms).
    for _ in 0..40 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        if kill(Pid::from_raw(info.pid), None).is_err() {
            break;
        }
    }
    // SIGKILL fallback if still alive.
    if kill(Pid::from_raw(info.pid), None).is_ok() {
        let _ = kill(Pid::from_raw(info.pid), Signal::SIGKILL);
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Double-fork spawn (legacy port-based — kept for CLI backwards compatibility)
// ──────────────────────────────────────────────────────────────────────────────

/// Spawn the daemon via a double-fork.
///
/// This is the **legacy** variant whose `serve` callback receives the
/// OS-assigned port number.  The grandchild binds a probe `TcpListener` to
/// discover a free port, **drops it**, writes `daemon.json`, and then passes
/// the port number to `serve`.  `serve` must re-bind the same port, which
/// introduces a brief TOCTOU window.
///
/// Kept for backwards compatibility with `zuit-cli/src/show.rs`.
/// Prefer [`spawn_with_listener`] for new call sites — it is race-free.
///
/// The parent polls `daemon.json` for up to 2 s (50 ms × 40), then verifies
/// that healthz returns a matching version, and returns the [`DaemonInfo`].
///
/// # Errors
///
/// Returns an error when the fork syscall fails, when `daemon.json` does not
/// appear within the 2 s budget, or when the healthz probe fails.
pub fn spawn<F>(home: &Path, version: &str, serve: F) -> Result<DaemonInfo, std::io::Error>
where
    F: FnOnce(u16) -> std::io::Result<()> + Send + 'static,
{
    let home_buf: PathBuf = home.to_path_buf();
    let version_str: String = version.to_owned();

    // ── Fork #1 ──────────────────────────────────────────────────────────────
    // SAFETY: nix::unistd::fork is the standard POSIX entry point; no Rust
    // async runtime is active (zuit-show is fully synchronous), so no
    // mutex-locked state can be inherited in a broken half-locked state.
    let first_fork = unsafe { fork() }.map_err(|e| std::io::Error::other(e.to_string()))?;

    match first_fork {
        ForkResult::Parent { .. } => wait_for_daemon_json(home),

        ForkResult::Child => {
            // ── Child: create new session then fork again ─────────────────────
            let _ = setsid();

            // SAFETY: same reasoning as fork #1.
            let second_fork = unsafe { fork() };
            match second_fork {
                Ok(ForkResult::Child) => {
                    // ── Grandchild ────────────────────────────────────────────
                    grandchild_main_port(&home_buf, version_str, serve);
                    // grandchild_main_port only returns on error; exit non-zero.
                    std::process::exit(1);
                }
                _ => {
                    // First child (intermediate) exits immediately so the
                    // grandchild is re-parented to init/launchd.
                    std::process::exit(0);
                }
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Double-fork spawn (race-free listener-based variant)
// ──────────────────────────────────────────────────────────────────────────────

/// Race-free variant of [`spawn`].
///
/// The grandchild:
/// 1. Redirects stdin/stdout/stderr to `/dev/null` (stderr → `daemon.log`).
/// 2. Binds `127.0.0.1:0` and **holds** the live `TcpListener`.
/// 3. Reads the assigned port from `local_addr()`.
/// 4. Atomically writes `daemon.json`.
/// 5. Calls `serve(listener)` — no re-bind, no TOCTOU window.
///
/// # Errors
///
/// Returns an error when the fork syscall fails, when `daemon.json` does not
/// appear within the 2 s budget, or when the healthz probe fails.
pub fn spawn_with_listener<F>(
    home: &Path,
    version: &str,
    serve: F,
) -> Result<DaemonInfo, std::io::Error>
where
    F: FnOnce(TcpListener) -> std::io::Result<()> + Send + 'static,
{
    let home_buf: PathBuf = home.to_path_buf();
    let version_str: String = version.to_owned();

    // ── Fork #1 ──────────────────────────────────────────────────────────────
    // SAFETY: nix::unistd::fork is the standard POSIX entry point; no Rust
    // async runtime is active (zuit-show is fully synchronous), so no
    // mutex-locked state can be inherited in a broken half-locked state.
    let first_fork = unsafe { fork() }.map_err(|e| std::io::Error::other(e.to_string()))?;

    match first_fork {
        ForkResult::Parent { .. } => wait_for_daemon_json(home),

        ForkResult::Child => {
            // ── Child: create new session then fork again ─────────────────────
            let _ = setsid();

            // SAFETY: same reasoning as fork #1.
            let second_fork = unsafe { fork() };
            match second_fork {
                Ok(ForkResult::Child) => {
                    // ── Grandchild ────────────────────────────────────────────
                    grandchild_main_listener(&home_buf, version_str, serve);
                    std::process::exit(1);
                }
                _ => {
                    std::process::exit(0);
                }
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Shared parent-side logic
// ──────────────────────────────────────────────────────────────────────────────

/// Poll for `daemon.json` (up to 2 s), then verify healthz.
fn wait_for_daemon_json(home: &Path) -> Result<DaemonInfo, std::io::Error> {
    let json_path = home.join("daemon.json");
    let mut info_opt: Option<DaemonInfo> = None;
    for _ in 0..40 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        if let Ok(bytes) = std::fs::read(&json_path)
            && let Ok(info) = serde_json::from_slice::<DaemonInfo>(&bytes)
        {
            info_opt = Some(info);
            break;
        }
    }
    let info = info_opt.ok_or_else(|| {
        std::io::Error::other("daemon did not write daemon.json within the 2-second budget")
    })?;
    // Probe healthz to confirm the server is ready.
    if !probe_healthz(info.port, &info.zuit_version) {
        // Best-effort cleanup.
        let _ = kill(Pid::from_raw(info.pid), Signal::SIGTERM);
        let _ = std::fs::remove_file(&json_path);
        return Err(std::io::Error::other(
            "daemon started but healthz probe failed",
        ));
    }
    Ok(info)
}

// ──────────────────────────────────────────────────────────────────────────────
// Grandchild variants
// ──────────────────────────────────────────────────────────────────────────────

/// Grandchild logic (legacy port-based variant).
///
/// Binds `127.0.0.1:0`, **drops** the listener, writes `daemon.json`, then
/// calls `serve(port)`.  There is a brief TOCTOU window between the drop and
/// `serve`'s re-bind.  Use [`grandchild_main_listener`] to avoid this.
fn grandchild_main_port<F>(home: &Path, version: String, serve: F)
where
    F: FnOnce(u16) -> std::io::Result<()>,
{
    // Redirect stdin/stdout/stderr to /dev/null BEFORE any other work so the
    // parent's pipes (e.g. assert_cmd's stdout pipe) receive EOF immediately.
    // stderr is then reopened to daemon.log for troubleshooting.
    redirect_stdio(home);

    // Bind :0 to let the OS assign a port, record it, then drop the listener.
    // serve() will re-bind the same port.  There is a brief TOCTOU window.
    let port = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => match listener.local_addr() {
            Ok(addr) => {
                let p = addr.port();
                drop(listener); // release the port for serve() to re-bind
                p
            }
            Err(_) => std::process::exit(1),
        },
        Err(_) => std::process::exit(1),
    };

    let started_at = rfc3339_now_seconds();
    let info = DaemonInfo {
        pid: std::process::id().cast_signed(),
        port,
        started_at,
        zuit_version: version,
    };
    if write_daemon_json(home, &info).is_err() {
        std::process::exit(1);
    }

    // This call blocks until SIGTERM or a fatal error.
    let _ = serve(port);
    // The server never deletes daemon.json on shutdown (invariant §11).
}

/// Grandchild logic (race-free listener-based variant).
///
/// Binds `127.0.0.1:0`, **holds** the live listener across the `daemon.json`
/// write, then passes it to `serve`.  No TOCTOU window.
fn grandchild_main_listener<F>(home: &Path, version: String, serve: F)
where
    F: FnOnce(TcpListener) -> std::io::Result<()>,
{
    redirect_stdio(home);

    // Bind and hold the listener — never drop it before handing to serve().
    let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
        std::process::exit(1)
    };
    let Ok(local_addr) = listener.local_addr() else {
        std::process::exit(1)
    };
    let port = local_addr.port();

    // Write daemon.json atomically.
    let started_at = rfc3339_now_seconds();
    let info = DaemonInfo {
        pid: std::process::id().cast_signed(),
        port,
        started_at,
        zuit_version: version,
    };
    if write_daemon_json(home, &info).is_err() {
        std::process::exit(1);
    }

    // Pass the live listener — tiny_http takes ownership, no re-bind occurs.
    let _ = serve(listener);
    // The server never deletes daemon.json on shutdown (invariant §11).
}

/// Dup `/dev/null` over stdin and stdout; reopen stderr to `daemon.log`.
///
/// All errors are silently ignored — if redirection fails the grandchild
/// continues running, just without proper fd isolation.
fn redirect_stdio(home: &Path) {
    use std::fs::OpenOptions;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;

    // /dev/null for stdin (fd 0) and stdout (fd 1).
    if let Ok(null) = OpenOptions::new().read(true).write(true).open("/dev/null") {
        let _ = dup2_stdin(&null);
        let _ = dup2_stdout(&null);
    }

    // daemon.log for stderr (fd 2).  Mode 0o600 so only the owner can read it.
    let log_path = home.join("daemon.log");
    let log_result = {
        #[cfg(unix)]
        {
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&log_path)
        }
        #[cfg(not(unix))]
        {
            OpenOptions::new().create(true).append(true).open(&log_path)
        }
    };
    if let Ok(log) = log_result {
        let _ = dup2_stderr(&log);
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// daemon.json atomic write (SEC-H hardened)
// ──────────────────────────────────────────────────────────────────────────────

fn write_daemon_json(home: &Path, info: &DaemonInfo) -> Result<(), std::io::Error> {
    // SEC-H: create the directory with mode 0o700 so only the owner can read it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(home)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(home)?;
    }

    let dest = home.join("daemon.json");
    let tmp = home.join("daemon.json.tmp");
    let bytes = serde_json::to_vec(info).map_err(|e| std::io::Error::other(e.to_string()))?;
    {
        // SEC-H: open the temp file with mode 0o600.
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt as _;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &dest)?;
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

fn rfc3339_now_seconds() -> String {
    let now = time::OffsetDateTime::now_utc();
    let fmt = time::format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]Z")
        .expect("invariant: format description is valid");
    now.format(&fmt).expect("invariant: now formats cleanly")
}

/// Check whether the process named by `pid` has a comm/name containing
/// `expected_substr`. Used as an ownership guard before signalling.
///
/// - Linux: reads `/proc/<pid>/comm`.
/// - macOS: runs `ps -p <pid> -o comm=`.
/// - Other Unix: conservatively returns `false`.
fn comm_matches(pid: i32, expected_substr: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        let p = format!("/proc/{pid}/comm");
        if let Ok(s) = std::fs::read_to_string(&p) {
            return s.trim().contains(expected_substr);
        }
        false
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output();
        if let Ok(out) = out {
            let s = String::from_utf8_lossy(&out.stdout);
            return s.trim().contains(expected_substr);
        }
        false
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (pid, expected_substr);
        false
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn status_not_running_when_no_file() {
        let tmp = TempDir::new().unwrap();
        let s = inspect(tmp.path(), "x", |_| Ok(false));
        assert!(matches!(s, DaemonStatus::NotRunning));
    }

    #[test]
    fn status_stale_when_pid_dead() {
        let tmp = TempDir::new().unwrap();
        let info = DaemonInfo {
            pid: 999_999, // assume dead in test env
            port: 1,
            started_at: "2026-05-04T00:00:00Z".into(),
            zuit_version: "x".into(),
        };
        std::fs::write(
            tmp.path().join("daemon.json"),
            serde_json::to_vec(&info).unwrap(),
        )
        .unwrap();
        let s = inspect(tmp.path(), "x", |_| Ok(false));
        assert!(matches!(s, DaemonStatus::Stale(_)));
    }

    #[test]
    fn status_running_when_pid_alive_and_healthz_ok() {
        let tmp = TempDir::new().unwrap();
        let info = DaemonInfo {
            pid: std::process::id().cast_signed(),
            port: 1,
            started_at: "2026-05-04T00:00:00Z".into(),
            zuit_version: "x".into(),
        };
        std::fs::write(
            tmp.path().join("daemon.json"),
            serde_json::to_vec(&info).unwrap(),
        )
        .unwrap();
        let s = inspect(tmp.path(), "x", |i| {
            assert_eq!(i.pid, std::process::id().cast_signed());
            Ok(true)
        });
        assert!(matches!(s, DaemonStatus::Running(_)));
    }

    #[test]
    fn status_stale_when_version_mismatch() {
        let tmp = TempDir::new().unwrap();
        let info = DaemonInfo {
            pid: std::process::id().cast_signed(),
            port: 1,
            started_at: "2026-05-04T00:00:00Z".into(),
            zuit_version: "old-version".into(),
        };
        std::fs::write(
            tmp.path().join("daemon.json"),
            serde_json::to_vec(&info).unwrap(),
        )
        .unwrap();
        // "new-version" does not match "old-version" → Stale.
        let s = inspect(tmp.path(), "new-version", |_| Ok(true));
        assert!(matches!(s, DaemonStatus::Stale(_)));
    }

    #[test]
    fn status_not_running_when_file_is_corrupt() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("daemon.json"), b"not-json").unwrap();
        let s = inspect(tmp.path(), "x", |_| Ok(true));
        assert!(matches!(s, DaemonStatus::NotRunning));
    }

    // SEC-H: verify write_daemon_json creates the directory with mode 0o700.
    #[test]
    #[cfg(unix)]
    fn write_daemon_json_creates_dir_with_mode_0o700() {
        use std::os::unix::fs::PermissionsExt as _;
        let outer = TempDir::new().unwrap();
        let home = outer.path().join("zuit_home");
        let info = DaemonInfo {
            pid: 42,
            port: 9999,
            started_at: "2026-05-06T00:00:00Z".into(),
            zuit_version: "test".into(),
        };
        write_daemon_json(&home, &info).unwrap();
        let meta = std::fs::metadata(&home).unwrap();
        // Directory mode bits: 0o40700 (type bits | rwx------).
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    }
}
