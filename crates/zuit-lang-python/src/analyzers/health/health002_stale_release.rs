//! `HEALTH002-stale-release` — emits when the most recent git tag is older than
//! `stale_release_days` (default 365).
//!
//! A project that has not had a release in over a year may be abandoned or
//! unmaintained.  This is derived from local git tag dates, not `PyPI`.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::{DEFAULT_WINDOW_DAYS, health_finding};

const RULE_ID: &str = "HEALTH002-stale-release";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/HEALTH002-stale-release.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `HEALTH002` when no tag is found within `stale_release_days`.
pub struct Health002StaleRelease {
    /// Git history window for log collection (days; default 365).
    pub window_days: u32,
    /// Threshold for "stale" — tag must be newer than this many days (default 365).
    pub stale_release_days: u32,
}

impl Default for Health002StaleRelease {
    fn default() -> Self {
        Self {
            window_days: DEFAULT_WINDOW_DAYS,
            stale_release_days: 365,
        }
    }
}

impl zuit_core::Analyzer for Health002StaleRelease {
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
            // HEALTH001 already emits git-unavailable; we stay silent.
            return Vec::new();
        };

        if log.tags.is_empty() {
            // No tags at all — emit stale-release finding.
            return vec![health_finding(
                project,
                RULE_ID,
                Severity::Medium,
                format!(
                    "No git tags found. Projects should tag releases so consumers can \
                     pin to stable versions. Consider tagging a release if one has \
                     been made within the last {} days.",
                    self.stale_release_days,
                ),
                Some(
                    "Run `git tag v1.0.0 && git push --tags` to publish your first release tag."
                        .to_string(),
                ),
            )];
        }

        // Tags are most-recent first; check the newest tag.
        let newest_tag = &log.tags[0];
        let now = time::OffsetDateTime::now_utc();
        let age_days = (now - newest_tag.date).whole_days();

        if age_days <= i64::from(self.stale_release_days) {
            return Vec::new();
        }

        vec![health_finding(
            project,
            RULE_ID,
            Severity::Medium,
            format!(
                "Stale release: most recent git tag '{}' is {} days old (threshold: {} days). \
                 The project may be unmaintained.",
                newest_tag.name, age_days, self.stale_release_days,
            ),
            Some(
                "Tag a new release with `git tag vX.Y.Z && git push --tags` to signal \
                 active maintenance."
                    .to_string(),
            ),
        )]
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::health::git_log::{Commit, GitLog, Tag};
    use std::io::Write as _;
    use time::OffsetDateTime;
    use zuit_core::{Analyzer, Config, Project};

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    fn days_ago(n: i64) -> OffsetDateTime {
        now() - time::Duration::days(n)
    }

    fn run_with_log(log: GitLog) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        f.write_all(b"[project]\nname = \"x\"\nversion = \"1.0\"\n")
            .unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();

        let project = Project::new(dir.path(), vec![]);
        let manifest = crate::manifest::manifest_for(&project);
        manifest.inject_git_log_for_test(Ok(log));

        let analyzer = Health002StaleRelease::default();
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    /// Plan test 1: tag 400 days old → one HEALTH002 Medium.
    #[test]
    fn health002_stale_release_positive() {
        let log = GitLog::new_for_test(
            vec![Commit::new_for_test("alice@example.com", days_ago(400))],
            vec![Tag::new_for_test("v1.0.0", days_ago(400))],
        );
        let findings = run_with_log(log);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 HEALTH002 finding: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, "HEALTH002-stale-release");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    /// Plan test 2: tag 30 days ago → 0 findings.
    #[test]
    fn health002_recent_release_clean() {
        let log = GitLog::new_for_test(
            vec![Commit::new_for_test("alice@example.com", days_ago(30))],
            vec![Tag::new_for_test("v1.0.0", days_ago(30))],
        );
        let findings = run_with_log(log);
        assert!(
            findings.is_empty(),
            "expected 0 findings with recent tag: {findings:#?}"
        );
    }

    #[test]
    fn health002_no_tags_emits_finding() {
        let log = GitLog::new_for_test(
            vec![Commit::new_for_test("alice@example.com", days_ago(10))],
            vec![],
        );
        let findings = run_with_log(log);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "HEALTH002-stale-release");
    }

    #[test]
    fn health002_no_git_silently_skips() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        f.write_all(b"[project]\nname = \"x\"\nversion = \"1.0\"\n")
            .unwrap();

        let project = Project::new(dir.path(), vec![]);
        let analyzer = Health002StaleRelease::default();
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);
        assert!(
            findings.is_empty(),
            "HEALTH002 must be silent when git is unavailable: {findings:#?}"
        );
    }
}
