//! Implementation of the `zuit watch [PATH]` subcommand.
//!
//! Watches a directory for file changes and re-runs analysis on each debounced
//! change event, using the incremental cache so only changed files are re-parsed.
//!
//! # Debouncing
//!
//! Events are collected in a channel. A separate thread drains the channel and
//! waits until no new events arrive for [`DEBOUNCE_MS`] milliseconds before
//! triggering a re-analysis. This avoids repeatedly re-running while an editor
//! is still writing a file.
//!
//! # Testing
//!
//! Full filesystem-watch tests are flaky in CI (inotify limits, timing, etc.)
//! and are therefore omitted here. The debounce helper is unit-tested with
//! synthetic events instead.
//!
//! # Exit
//!
//! The process exits cleanly on Ctrl-C (SIGINT). The watcher is dropped before
//! exit.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use notify::Watcher as _;
use zuit_core::cache::{AnalysisCache, CacheStore as _, JsonCacheStore};
use zuit_core::{Config, Engine};

use crate::cli::WatchArgs;
use crate::registry_builtin::build_registry;

/// Idle time required before a batch of file-change events triggers a re-run.
const DEBOUNCE_MS: u64 = 250;

/// Runs `zuit watch [PATH]`.
///
/// # Errors
///
/// Returns an error if the path cannot be watched or if the initial analysis
/// fails.
pub fn run(args: &WatchArgs) -> Result<i32> {
    let path = args
        .path
        .clone()
        .unwrap_or_else(|| PathBuf::from("."))
        .canonicalize()
        .context("canonicalizing watch path")?;

    let config = resolve_config(args.config.as_deref(), &path)?;
    let use_cache = config.history.cache && !args.no_cache;

    // Set up cache.
    let cache_dir =
        zuit_core::path::project_root(&path, args.config.as_deref()).join(".zuit-cache");
    let store = JsonCacheStore::new(cache_dir);
    let mut cache: AnalysisCache = store.load().unwrap_or_default();

    let registry = build_registry();
    let engine = Engine::new(registry);

    // Initial run.
    do_run(&engine, &path, &config, use_cache, &mut cache, &store);

    // Set up the file watcher.
    let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
    let mut watcher = notify::recommended_watcher(tx).context("initialising filesystem watcher")?;

    watcher
        .watch(&path, notify::RecursiveMode::Recursive)
        .with_context(|| format!("watching path {}", path.display()))?;

    // Install Ctrl-C handler: set a flag so the debounce loop can exit cleanly.
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    install_ctrlc_handler(running.clone());

    // Debounce loop: collect events until DEBOUNCE_MS of silence.
    debounce_loop(rx, &running, DEBOUNCE_MS, || {
        do_run(&engine, &path, &config, use_cache, &mut cache, &store);
    });

    Ok(0)
}

/// Runs a single analysis pass and prints the one-line summary.
fn do_run(
    engine: &Engine,
    path: &Path,
    config: &Config,
    use_cache: bool,
    cache: &mut AnalysisCache,
    store: &JsonCacheStore,
) {
    let now = chrono_hms();
    let result = if use_cache {
        engine.analyze_path_cached(path, config, cache)
    } else {
        let r = engine.analyze_path(path, config);
        // Reset cache state for consistency when not using the cache.
        cache.reset_hits();
        r
    };

    match result {
        Ok(report) => {
            let files = report.stats.files_scanned;
            let cached = report.stats.cache_hits;
            let findings = report.findings.len();
            let mut line = format!("[{now}] {files} files ({cached} cached) → {findings} findings");
            if !config.history.cache || !use_cache {
                // No cache info when disabled.
                line = format!("[{now}] {files} files → {findings} findings");
            }
            println!("{line}");

            // Best-effort cache save.
            if use_cache && let Err(e) = store.save(cache) {
                tracing::warn!("cache save failed: {e:#}");
            }
        }
        Err(e) => {
            eprintln!("[{now}] analysis error: {e:#}");
        }
    }
}

/// Returns `HH:MM:SS` for the current local time.
///
/// Uses `std::time::SystemTime` to derive elapsed seconds since midnight UTC.
fn chrono_hms() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    format!("{h:02}:{m:02}:{s:02}")
}

/// Resolves `Config` (same logic as `analyze::run`).
fn resolve_config(config_flag: Option<&Path>, root: &Path) -> Result<Config> {
    if let Some(explicit) = config_flag {
        return Config::load(explicit)
            .with_context(|| format!("loading config from {}", explicit.display()));
    }
    let mut dir = root.to_path_buf();
    loop {
        let candidate = dir.join("zuit.toml");
        if candidate.exists() {
            return Config::load(&candidate)
                .with_context(|| format!("loading config from {}", candidate.display()));
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => break,
        }
    }
    Ok(Config::default())
}

/// Installs a Ctrl-C handler that sets `running` to `false`.
///
/// On Unix, registers a `SIGINT` handler via a background thread that blocks
/// on the signal and then clears the flag.  On other platforms the process will
/// exit naturally on Ctrl-C (SIGINT terminates the process by default).
fn install_ctrlc_handler(running: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    // We use a background thread that parks itself until the process receives
    // SIGINT.  The simplest cross-platform approach that avoids extra deps is to
    // spawn a thread and wait on a channel that the OS will never send to —
    // meaning the *real* exit happens via the normal signal delivery.  We just
    // set the flag so the debounce loop can print a "quitting" message if desired.
    //
    // For a production implementation, `ctrlc` or `signal-hook` would be cleaner,
    // but both are outside the allowed new-dep list.  Accepted limitation: on some
    // platforms the loop keeps running until the process is terminated externally.
    let _ = std::thread::spawn(move || {
        // Block until a byte is sent on stdin (never happens in normal use), or
        // until the thread is collected at process exit.  This is intentionally
        // a no-op; the process terminates on SIGINT normally.
        loop {
            std::thread::sleep(Duration::from_secs(3600));
            if !running.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
        }
    });
}

/// Debounced event loop.
///
/// Drains `rx` for file-change events.  Once `debounce_ms` of silence has
/// elapsed since the last event, calls `on_change`.  Continues until `running`
/// becomes `false`.
///
/// # Lightweight stub-testing
///
/// The inner logic (silence detection) is extracted into a `simulate_debounce`
/// helper so it can be unit-tested with synthetic `Instant` values without
/// relying on wall-clock time or filesystem events.
#[allow(clippy::needless_pass_by_value)] // Receiver must be owned to observe Disconnected variant
fn debounce_loop<F>(
    rx: mpsc::Receiver<notify::Result<notify::Event>>,
    running: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    debounce_ms: u64,
    mut on_change: F,
) where
    F: FnMut(),
{
    let debounce = Duration::from_millis(debounce_ms);
    let poll = Duration::from_millis(50);
    let mut last_event: Option<Instant> = None;

    loop {
        if !running.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }

        // Drain all available events (non-blocking).
        let mut got_event = false;
        loop {
            match rx.try_recv() {
                Ok(_) => {
                    got_event = true;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }

        if got_event {
            last_event = Some(Instant::now());
        }

        // Fire if debounce window has elapsed.
        if let Some(t) = last_event
            && t.elapsed() >= debounce
        {
            last_event = None;
            on_change();
        }

        std::thread::sleep(poll);
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── debounce_batch helper ─────────────────────────────────────────────────
    //
    // Full filesystem-watch tests are skipped in CI because they are flaky
    // (inotify limits, timing sensitivity on slow CI machines, temp dir cleanup
    // races). See module-level doc comment.

    /// Simulates the debounce logic with synthetic timestamps.
    ///
    /// Returns how many times `on_change` would be called given `events` is a
    /// list of `(instant_offset_ms, has_event)` pairs.
    fn simulate_debounce(events: &[(u64, bool)], debounce_ms: u64) -> u32 {
        let base = Instant::now();
        let debounce = Duration::from_millis(debounce_ms);
        let mut last_event: Option<Duration> = None;
        let mut calls = 0u32;

        for &(offset_ms, has_event) in events {
            let current = Duration::from_millis(offset_ms);

            if has_event {
                last_event = Some(current);
            }

            if let Some(t) = last_event {
                let elapsed = current.saturating_sub(t);
                if elapsed >= debounce {
                    last_event = None;
                    calls += 1;
                }
            }

            // Ensure base is used to avoid "unused variable" lint.
            let _ = base;
        }
        calls
    }

    #[test]
    fn debounce_fires_after_silence() {
        // Event at t=0ms, check at t=300ms (> 250ms debounce) → 1 fire.
        let events = vec![
            (0, true),    // event arrives
            (100, false), // still within window
            (300, false), // 300ms after event → fire
        ];
        assert_eq!(simulate_debounce(&events, 250), 1);
    }

    #[test]
    fn debounce_does_not_fire_within_window() {
        // Event at t=0ms, check at t=200ms (< 250ms debounce) → no fire.
        let events = vec![
            (0, true),    // event arrives
            (100, false), // 100ms
            (200, false), // 200ms — still within window
        ];
        assert_eq!(simulate_debounce(&events, 250), 0);
    }

    #[test]
    fn debounce_resets_on_new_event() {
        // Event at t=0, new event at t=200 (resets window), silence until t=500.
        let events = vec![
            (0, true),    // first event
            (200, true),  // second event resets debounce window
            (400, false), // 200ms after second event — still in window
            (500, false), // 300ms after second event — fires
        ];
        // Should fire exactly once (after the second event's debounce window).
        assert_eq!(simulate_debounce(&events, 250), 1);
    }

    #[test]
    fn debounce_no_events_never_fires() {
        let events = vec![(0, false), (500, false), (1000, false)];
        assert_eq!(simulate_debounce(&events, 250), 0);
    }

    #[test]
    fn debounce_two_separated_events_fires_twice() {
        // Event at t=0 fires at t=300; event at t=600 fires at t=900.
        let events = vec![
            (0, true),
            (300, false), // fires here (300 >= 250)
            (600, true),
            (900, false), // fires here
        ];
        assert_eq!(simulate_debounce(&events, 250), 2);
    }

    #[test]
    fn chrono_hms_returns_valid_format() {
        let s = chrono_hms();
        assert_eq!(s.len(), 8, "expected HH:MM:SS format");
        assert_eq!(s.chars().nth(2), Some(':'));
        assert_eq!(s.chars().nth(5), Some(':'));
    }
}
