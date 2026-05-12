//! `HEALTH004-commit-stale` — emits when the most recent commit is older than
//! `stale_commit_days` days (default 180).
//!
//! A project with no commits for six months may be abandoned or unmaintained.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::{DEFAULT_WINDOW_DAYS, health_finding};

const RULE_ID: &str = "HEALTH004-commit-stale";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/HEALTH004-commit-stale.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `HEALTH004` when the most recent commit is older than
/// `stale_commit_days` days.
pub struct Health004CommitStale {
    /// Look-back window passed to `git log --since` (days; default 365).
    pub window_days: u32,
    /// Age threshold for "stale" in days (default 180).
    pub stale_commit_days: u32,
}

impl Default for Health004CommitStale {
    fn default() -> Self {
        Self {
            window_days: DEFAULT_WINDOW_DAYS,
            stale_commit_days: 180,
        }
    }
}

impl zuit_core::Analyzer for Health004CommitStale {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("project_health".to_string())
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn kind(&self) -> AnalyzerKind {
        AnalyzerKind::ProjectLevel
    }

    fn analyze_file(
        &self,
        _ctx: &AnalysisContext<'_>,
        _file: &zuit_core::ParsedFile,
    ) -> Vec<Finding> {
        Vec::new()
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        let manifest = manifest_for(project);
        let Ok(log) = manifest.git_log(project, self.window_days) else {
            return Vec::new();
        };

        if log.commits.is_empty() {
            // No commits in window — may itself indicate staleness, but we
            // can't determine the last commit date, so skip.
            return Vec::new();
        }

        // Commits are most-recent first.
        let newest = &log.commits[0];
        let now = time::OffsetDateTime::now_utc();
        let age_days = (now - newest.date).whole_days();

        if age_days <= i64::from(self.stale_commit_days) {
            return Vec::new();
        }

        vec![health_finding(
            project,
            RULE_ID,
            Severity::Medium,
            format!(
                "Stale commits: the most recent commit is {age_days} days old \
                 (threshold: {} days). The project may be abandoned or on a \
                 long maintenance hiatus.",
                self.stale_commit_days,
            ),
            Some(
                "If the project is still maintained, push a commit (even a version \
                 bump or dependency update) to signal activity."
                    .to_string(),
            ),
        )]
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::health::git_log::{Commit, GitLog};
    use zuit_core::{Analyzer, Config, Project};
    use time::OffsetDateTime;

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    fn days_ago(n: i64) -> OffsetDateTime {
        now() - time::Duration::days(n)
    }

    fn run_with_log(log: GitLog) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            b"[package]\nname = \"x\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();

        let project = Project::new(dir.path(), vec![]);
        let manifest = crate::manifest::manifest_for(&project);
        manifest.inject_git_log_for_test(Ok(log));

        let analyzer = Health004CommitStale::default();
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn health004_stale_commit_positive() {
        let log = GitLog::new_for_test(
            vec![Commit::new_for_test("alice@example.com", days_ago(200))],
            vec![],
        );
        let findings = run_with_log(log);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 HEALTH004 finding: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, "HEALTH004-commit-stale");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn health004_recent_commit_clean() {
        let log = GitLog::new_for_test(
            vec![Commit::new_for_test("alice@example.com", days_ago(1))],
            vec![],
        );
        let findings = run_with_log(log);
        assert!(
            findings.is_empty(),
            "recent commit should not trigger HEALTH004: {findings:#?}"
        );
    }

    #[test]
    fn health004_no_git_silently_skips() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            b"[package]\nname = \"x\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();

        let project = Project::new(dir.path(), vec![]);
        let manifest = crate::manifest::manifest_for(&project);
        manifest.inject_git_log_for_test(Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no git",
        )));
        let analyzer = Health004CommitStale::default();
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);
        assert!(
            findings.is_empty(),
            "must be silent without git: {findings:#?}"
        );
    }
}
