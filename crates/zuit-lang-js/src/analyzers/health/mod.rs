//! Project-health analyzers (`HEALTH` family).
//!
//! All rules in this module operate at `AnalyzerKind::ProjectLevel` with
//! `SupportedLanguages::All`. They read the git commit history via
//! `git_log::collect`, which is cached on `crate::manifest::JsManifest`
//! so `git` runs at most once per project per engine run.
//!
//! Rules that cannot obtain a `GitLog` (no `.git` directory, no `git` binary)
//! silently return zero findings. This keeps the test suite deterministic and
//! avoids noisy "unavailable" findings when analysing non-git projects.

pub(crate) mod git_log;
mod health001_single_author;
mod health002_stale_release;
mod health003_low_bus_factor;
mod health004_commit_stale;
mod health005_changelog_missing;

pub use health001_single_author::Health001SingleAuthorAnalyzer;
pub use health002_stale_release::Health002StaleReleaseAnalyzer;
pub use health003_low_bus_factor::Health003LowBusFactorAnalyzer;
pub use health004_commit_stale::Health004CommitStaleAnalyzer;
pub use health005_changelog_missing::Health005ChangelogMissingAnalyzer;

use crate::manifest::{GitLog, JsManifest};

/// Returns a reference to the lazily-populated [`GitLog`] for `manifest`.
///
/// Calls [`git_log::collect`] on first access and caches the result in
/// `manifest.git_log`. Subsequent calls return the cached value without
/// spawning any subprocess.
pub(crate) fn manifest_git_log(manifest: &JsManifest) -> Option<&GitLog> {
    manifest
        .git_log
        .get_or_init(|| git_log::collect(&manifest.root))
        .as_ref()
}
