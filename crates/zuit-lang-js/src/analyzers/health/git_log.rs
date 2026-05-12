//! Real-`git` integration for [`crate::manifest::GitLog`] population.
//!
//! The single public entry point, [`collect`], runs three short `git` commands
//! and converts their output into a [`GitLog`] value.  All callers should treat
//! a `None` return as "git unavailable" and emit no findings rather than an
//! error — keeping the test suite deterministic without a real repository.
//!
//! # WHY: no timeout wrapper
//! The plan suggests a 10-second timeout, but `std::process::Command::output()`
//! already blocks until the child exits.  Adding an async or thread-based
//! timeout here would pull in an executor or unsafe thread-kill logic.  `git
//! log` / `git for-each-ref` on a local repo are consistently sub-second even
//! on large histories; the cost of a pathological repo (e.g. 100 000 commits)
//! is borne once per engine run via the `OnceLock` cache on `JsManifest`.
//! A future phase can wrap the subprocess with a `SIGKILL` thread if needed.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::manifest::GitLog;

/// Invokes `git` in `root` and returns a populated [`GitLog`], or `None` if:
///
/// - `<root>/.git` does not exist (not a git repository), or
/// - the `git` binary is not on `PATH`, or
/// - any `git` subprocess fails or produces unparseable output.
///
/// # WHY: returns `None` on any failure
/// HEALTH analyzers silently emit zero findings when `git_log` is `None`.
/// The plan originally called for a `HEALTH/git-unavailable` Info finding, but
/// emitting that finding requires an analyzer context (rule id, location, …)
/// that `git_log::collect` does not have.  Keeping this function pure (no
/// `Finding` construction) makes it easier to test in isolation and keeps the
/// "unavailable" signal as a documented deviation — tracked here rather than
/// adding a new rule id in this phase.
#[must_use]
pub fn collect(root: &Path) -> Option<GitLog> {
    // Guard 1: must be a git repository.
    if !root.join(".git").exists() {
        return None;
    }

    // Guard 2: `git` must be on PATH.
    if which::which("git").is_err() {
        return None;
    }

    let authors = collect_authors(root)?;
    let days_since_last_commit = collect_days_since_last_commit(root);
    let days_since_last_tag = collect_days_since_last_tag(root);

    Some(GitLog {
        authors,
        days_since_last_commit,
        days_since_last_tag,
    })
}

/// Runs `git log --format=%ae` and returns the list of author e-mails.
fn collect_authors(root: &Path) -> Option<Vec<String>> {
    let output = std::process::Command::new("git")
        .args(["log", "--format=%ae"])
        .current_dir(root)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let authors: Vec<String> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect();

    Some(authors)
}

/// Runs `git log -1 --format=%ct` and converts the epoch to "days since now".
fn collect_days_since_last_commit(root: &Path) -> Option<u32> {
    let output = std::process::Command::new("git")
        .args(["log", "-1", "--format=%ct"])
        .current_dir(root)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    epoch_to_days_ago(String::from_utf8_lossy(&output.stdout).trim())
}

/// Runs `git for-each-ref` to find the most-recent tag epoch, returning days
/// since that tag, or `None` if no tags exist or the command fails.
fn collect_days_since_last_tag(root: &Path) -> Option<u32> {
    let output = std::process::Command::new("git")
        .args([
            "for-each-ref",
            "--sort=-creatordate",
            "--count=1",
            "--format=%(creatordate:unix)",
            "refs/tags",
        ])
        .current_dir(root)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let trimmed = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if trimmed.is_empty() {
        return None;
    }

    epoch_to_days_ago(&trimmed)
}

/// Converts a Unix epoch string into "whole days elapsed since now".
fn epoch_to_days_ago(epoch_str: &str) -> Option<u32> {
    let epoch_secs: u64 = epoch_str.trim().parse().ok()?;
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();

    let elapsed = now_secs.saturating_sub(epoch_secs);
    u32::try_from(elapsed / 86_400).ok()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn collect_returns_none_for_non_git_dir() {
        let dir = TempDir::new().expect("tempdir");
        // No .git directory — must return None regardless of git availability.
        let result = collect(dir.path());
        assert!(
            result.is_none(),
            "expected None for non-git dir, got {result:?}"
        );
    }

    #[test]
    fn epoch_to_days_ago_zero_for_now() {
        // An epoch very close to "now" should return 0 days.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time must be after epoch")
            .as_secs();
        let result = epoch_to_days_ago(&now.to_string());
        assert_eq!(result, Some(0), "epoch == now should be 0 days ago");
    }

    #[test]
    fn epoch_to_days_ago_known_past() {
        // 10 days * 86_400 seconds/day before "now".
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time must be after epoch")
            .as_secs();
        let ten_days_ago = now.saturating_sub(10 * 86_400);
        let result = epoch_to_days_ago(&ten_days_ago.to_string());
        assert_eq!(result, Some(10), "10 days ago should return Some(10)");
    }

    #[test]
    fn epoch_to_days_ago_invalid_string_returns_none() {
        assert_eq!(epoch_to_days_ago("not-a-number"), None);
        assert_eq!(epoch_to_days_ago(""), None);
    }
}
