//! HEALTH — Project Health rule family for Rust crates.
//!
//! All rules are `AnalyzerKind::ProjectLevel` with
//! `Dimension::Custom("project_health")`.  They derive signals from local
//! `git log` output (via `git_log::collect_git_log`) and the project
//! filesystem.  No network calls are made.
//!
//! ## Git unavailability
//!
//! When git is unavailable (no `.git` directory, `git` binary missing, timeout,
//! etc.) **only** `HEALTH001` emits a single `HEALTH/git-unavailable` Info
//! finding.  The remaining four analyzers return an empty `Vec` in that case,
//! so the user sees exactly one informational notice rather than five.
//!
//! ## Configuration
//!
//! `git_history_window_days` (default 365) controls how far back the commit
//! window reaches.  This is currently a compile-time default in each analyzer
//! struct; config-table wiring is deferred to a later phase.

pub mod git_log;
pub mod health001_single_author;
pub mod health002_stale_release;
pub mod health003_low_bus_factor;
pub mod health004_commit_stale;
pub mod health005_changelog_missing;

pub use health001_single_author::Health001SingleAuthor;
pub use health002_stale_release::Health002StaleRelease;
pub use health003_low_bus_factor::Health003LowBusFactor;
pub use health004_commit_stale::Health004CommitStale;
pub use health005_changelog_missing::Health005ChangelogMissing;

use zuit_core::{
    AnalyzerId, Dimension, Finding, Location, Project, Severity,
    span::{ByteOffset, LineCol, Span},
};

// ── Shared constants ──────────────────────────────────────────────────────────

/// Default git history look-back window in days.
pub(crate) const DEFAULT_WINDOW_DAYS: u32 = 365;

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Builds a project-level [`Finding`] anchored to the project root (line 1,
/// col 1 of `Cargo.toml` if it exists, else a synthetic `"."` path).
pub(crate) fn health_finding(
    project: &Project,
    rule_id: &'static str,
    severity: Severity,
    message: String,
    suggestion: Option<String>,
) -> Finding {
    let file = {
        let ct = project.root.join("Cargo.toml");
        if ct.exists() {
            ct.strip_prefix(&project.root).unwrap_or(&ct).to_path_buf()
        } else {
            std::path::PathBuf::from(".")
        }
    };

    Finding {
        analyzer: AnalyzerId::new(rule_id),
        dimension: Dimension::Custom("project_health".to_string()),
        rule_id: rule_id.to_string(),
        severity,
        message,
        location: Location {
            file,
            span: Span::new(ByteOffset(0), ByteOffset(0)),
            start: LineCol::new(1, 1),
            end: LineCol::new(1, 1),
        },
        suggestion,
        references: vec![],
        cwe: vec![],
        owasp: vec![],
    }
}

/// Builds the `HEALTH/git-unavailable` Info finding.  Emitted only by
/// `HEALTH001` when git log collection fails.
pub(crate) fn git_unavailable_finding(project: &Project, reason: &str) -> Finding {
    health_finding(
        project,
        "HEALTH/git-unavailable",
        Severity::Info,
        format!(
            "Git is unavailable in this project; HEALTH001\u{2013}HEALTH004 checks are skipped. \
             Reason: {reason}"
        ),
        Some(
            "Ensure the project is in a git repository and `git` is installed on PATH.".to_string(),
        ),
    )
}
