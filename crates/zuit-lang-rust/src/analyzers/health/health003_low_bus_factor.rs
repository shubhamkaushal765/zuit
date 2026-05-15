//! `HEALTH003-low-bus-factor` — emits when there are ≤ 2 distinct commit
//! authors in the configured history window.
//!
//! A project with very few distinct contributors has a low bus factor: if one
//! or two authors become unavailable, the project may stall.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::{DEFAULT_WINDOW_DAYS, health_finding};

const RULE_ID: &str = "HEALTH003-low-bus-factor";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/HEALTH003-low-bus-factor.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `HEALTH003` when ≤ 2 distinct authors contributed in
/// the history window.
pub struct Health003LowBusFactor {
    /// Look-back window in days (default 365).
    pub window_days: u32,
    /// Maximum number of distinct authors that triggers the rule (default 2).
    pub bus_factor_threshold: usize,
}

impl Default for Health003LowBusFactor {
    fn default() -> Self {
        Self {
            window_days: DEFAULT_WINDOW_DAYS,
            bus_factor_threshold: 2,
        }
    }
}

impl zuit_core::Analyzer for Health003LowBusFactor {
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
            return Vec::new();
        }

        let distinct_authors: std::collections::HashSet<&str> =
            log.commits.iter().map(|c| c.author.as_str()).collect();
        let count = distinct_authors.len();

        if count > self.bus_factor_threshold {
            return Vec::new();
        }

        vec![health_finding(
            project,
            RULE_ID,
            Severity::Low,
            format!(
                "Low bus factor: only {count} distinct author(s) contributed in the last \
                 {window} days (threshold: >{threshold}). The project is at risk if \
                 any contributor becomes unavailable.",
                window = self.window_days,
                threshold = self.bus_factor_threshold,
            ),
            Some(
                "Actively recruit co-maintainers, document the contribution process, \
                 and lower the barrier to first contributions."
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
        std::fs::write(
            dir.path().join("Cargo.toml"),
            b"[package]\nname = \"x\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();

        let project = Project::new(dir.path(), vec![]);
        let manifest = crate::manifest::manifest_for(&project);
        manifest.inject_git_log_for_test(Ok(log));

        let analyzer = Health003LowBusFactor::default();
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    /// Plan test: 50 commits all from one author → one HEALTH003.
    #[test]
    fn health003_bus_factor_one_author() {
        let commits: Vec<Commit> = (0..50)
            .map(|i| Commit::new_for_test("alice@example.com", days_ago(i)))
            .collect();
        let log = GitLog::new_for_test(commits, vec![]);
        let findings = run_with_log(log);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 HEALTH003 finding: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, "HEALTH003-low-bus-factor");
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn health003_five_distinct_authors_clean() {
        let commits = vec![
            Commit::new_for_test("alice@example.com", days_ago(1)),
            Commit::new_for_test("bob@example.com", days_ago(2)),
            Commit::new_for_test("carol@example.com", days_ago(3)),
            Commit::new_for_test("dave@example.com", days_ago(4)),
            Commit::new_for_test("eve@example.com", days_ago(5)),
        ];
        let log = GitLog::new_for_test(commits, vec![]);
        let findings = run_with_log(log);
        assert!(
            findings.is_empty(),
            "5 distinct authors should pass: {findings:#?}"
        );
    }

    #[test]
    fn health003_no_git_silently_skips() {
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
        let analyzer = Health003LowBusFactor::default();
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);
        assert!(
            findings.is_empty(),
            "must be silent without git: {findings:#?}"
        );
    }
}
