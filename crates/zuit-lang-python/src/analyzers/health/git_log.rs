//! Git log collection: commits + tags for HEALTH analyzers.
//!
//! The `collect_git_log` function shells out to `git` via
//! `std::process::Command` (no shell, no panic).  It respects a configurable
//! look-back window and a 30-second timeout.  If `.git` is absent, `git` is not
//! on `PATH`, or the command fails for any reason, an `Err(std::io::Error)` is
//! returned.
//!
//! The `GitLog` struct (and its sub-types) intentionally carry a
//! `#[cfg(test)]`-gated `new_for_test` constructor so unit tests can inject
//! deterministic fixture data without invoking real git.

use std::io;
use std::path::Path;

use time::OffsetDateTime;
use time::format_description::well_known::Iso8601;

// ── Public types ──────────────────────────────────────────────────────────────

/// All git-derived data needed by the HEALTH analyzer family.
///
/// Constructed at most once per project per engine run; cached behind a
/// `OnceLock` on [`crate::manifest::PythonManifest`].
#[derive(Debug, Clone)]
pub(crate) struct GitLog {
    /// All commits within the history window, most-recent first.
    pub commits: Vec<Commit>,
    /// All tags found in the repository, most-recent first.
    pub tags: Vec<Tag>,
}

/// A single git commit as reported by `git log`.
#[derive(Debug, Clone)]
pub(crate) struct Commit {
    /// Author email (from `%ae`), used as the canonical identity.
    pub author: String,
    /// Commit author timestamp (ISO-8601 strict).
    pub date: OffsetDateTime,
}

/// A single git tag as reported by `git tag --sort=-creatordate`.
#[derive(Debug, Clone)]
pub(crate) struct Tag {
    /// Short tag name (e.g. `"v1.2.3"`).
    pub name: String,
    /// Tag creation date.
    pub date: OffsetDateTime,
}

// ── Test-only constructor ─────────────────────────────────────────────────────

#[cfg(test)]
impl GitLog {
    /// Constructs a [`GitLog`] from caller-supplied data for unit tests.
    /// Never invokes `git`.
    pub(crate) fn new_for_test(commits: Vec<Commit>, tags: Vec<Tag>) -> Self {
        Self { commits, tags }
    }
}

#[cfg(test)]
impl Commit {
    pub(crate) fn new_for_test(author: impl Into<String>, date: OffsetDateTime) -> Self {
        Self {
            author: author.into(),
            date,
        }
    }
}

#[cfg(test)]
impl Tag {
    pub(crate) fn new_for_test(name: impl Into<String>, date: OffsetDateTime) -> Self {
        Self {
            name: name.into(),
            date,
        }
    }
}

// ── Public function ───────────────────────────────────────────────────────────

/// Invokes `git log` and `git tag` inside `project_root` and returns the
/// parsed results.
///
/// `window_days` controls how far back `git log --since=<N> days ago` reaches.
/// Returns `Err` if:
/// - there is no `.git` directory at `project_root`,
/// - `git` is not on `PATH`,
/// - either subprocess exits non-zero or times out,
/// - stdout cannot be decoded as UTF-8.
pub(crate) fn collect_git_log(project_root: &Path, window_days: u32) -> io::Result<GitLog> {
    // Quick pre-check: require a .git directory so we fail fast without
    // spawning a process on non-git trees.
    if !project_root.join(".git").exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            ".git directory not found",
        ));
    }

    let since = format!("{window_days} days ago");

    // ── git log ───────────────────────────────────────────────────────────────
    let log_output = run_git(
        project_root,
        &[
            "log",
            "--pretty=format:%ae|%aI",
            &format!("--since={since}"),
        ],
    )?;

    let commits = parse_log_output(&log_output);

    // ── git tag ───────────────────────────────────────────────────────────────
    let tag_output = run_git(
        project_root,
        &[
            "tag",
            "--sort=-creatordate",
            "--format=%(refname:short)|%(creatordate:iso-strict)",
        ],
    )?;

    let tags = parse_tag_output(&tag_output);

    Ok(GitLog { commits, tags })
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn run_git(cwd: &Path, args: &[&str]) -> io::Result<String> {
    use crate::analyzers::external::Outcome;
    use crate::analyzers::external::run_with_limits;

    match run_with_limits("git", args, cwd, 8 * 1024 * 1024, 30) {
        Outcome::Ok(bytes) => String::from_utf8(bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("git output is not UTF-8: {e}"),
            )
        }),
        Outcome::Timeout => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "git command timed out after 30 s",
        )),
        Outcome::OutputTooLarge => Err(io::Error::other("git output exceeded 8 MiB cap")),
        Outcome::SpawnFailed(msg) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("failed to spawn git: {msg}"),
        )),
    }
}

fn parse_log_output(output: &str) -> Vec<Commit> {
    let mut commits = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((author, date_str)) = line.split_once('|') else {
            continue; // skip malformed lines
        };
        let Ok(date) = OffsetDateTime::parse(date_str, &Iso8601::DEFAULT) else {
            continue; // skip unparseable dates
        };
        commits.push(Commit {
            author: author.to_string(),
            date,
        });
    }
    commits
}

fn parse_tag_output(output: &str) -> Vec<Tag> {
    let mut tags = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, date_str)) = line.split_once('|') else {
            continue;
        };
        let Ok(date) = OffsetDateTime::parse(date_str, &Iso8601::DEFAULT) else {
            continue;
        };
        tags.push(Tag {
            name: name.to_string(),
            date,
        });
    }
    tags
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_output_gives_empty_vecs() {
        let commits = parse_log_output("");
        assert!(commits.is_empty());
        let tags = parse_tag_output("");
        assert!(tags.is_empty());
    }

    #[test]
    fn parse_log_skips_malformed_lines() {
        let output = "no-pipe-here\nalice@example.com|2024-01-01T00:00:00+00:00\n";
        let commits = parse_log_output(output);
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].author, "alice@example.com");
    }

    #[test]
    fn parse_tag_skips_malformed_lines() {
        let output = "v1.0|2024-06-01T12:00:00+00:00\nbad-line\n";
        let tags = parse_tag_output(output);
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].name, "v1.0");
    }

    /// Smoke test: `collect_git_log` must not panic on a non-git tempdir.
    #[cfg(unix)]
    #[test]
    fn collect_git_log_no_git_dir_returns_err() {
        let dir = tempfile::TempDir::new().unwrap();
        let result = collect_git_log(dir.path(), 365);
        assert!(result.is_err(), "expected Err when .git is absent, got Ok");
    }
}
