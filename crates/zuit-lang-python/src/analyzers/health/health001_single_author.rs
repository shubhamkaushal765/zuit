//! `HEALTH001-single-author` — emits when one author is responsible for > 50%
//! of commits in the configured git history window.
//!
//! A project dominated by a single contributor is at high bus-factor risk:
//! if that author becomes unavailable the project may stall.
//!
//! When git is unavailable this analyzer emits exactly one
//! `HEALTH/git-unavailable` Info finding (the remaining HEALTH analyzers
//! return empty in that case to avoid repeating the notice).

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::{DEFAULT_WINDOW_DAYS, git_unavailable_finding, health_finding};

const RULE_ID: &str = "HEALTH001-single-author";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/HEALTH001-single-author.md",
    cwe: &[],
    owasp: &[],
};

// ── Analyzer ──────────────────────────────────────────────────────────────────

/// Analyzer that emits `HEALTH001` when > 50% of commits share one author.
pub struct Health001SingleAuthor {
    /// Look-back window in days (default: 365).
    pub window_days: u32,
}

impl Default for Health001SingleAuthor {
    fn default() -> Self {
        Self {
            window_days: DEFAULT_WINDOW_DAYS,
        }
    }
}

impl zuit_core::Analyzer for Health001SingleAuthor {
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
        let git_log = manifest.git_log(project, self.window_days);

        let log = match git_log {
            Ok(log) => log,
            Err(e) => {
                return vec![git_unavailable_finding(project, e)];
            }
        };

        if log.commits.is_empty() {
            return Vec::new();
        }

        // Count commits per author.
        let total = log.commits.len();
        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for commit in &log.commits {
            *counts.entry(commit.author.as_str()).or_insert(0) += 1;
        }

        let Some((top_author, &top_count)) = counts.iter().max_by_key(|&(_, &v)| v) else {
            return Vec::new();
        };

        if top_count * 2 <= total {
            // top author has ≤ 50%
            return Vec::new();
        }

        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let pct = (top_count as f64 / total as f64 * 100.0) as u32;

        vec![health_finding(
            project,
            RULE_ID,
            Severity::Medium,
            format!(
                "Single-author dominance: '{top_author}' authored {top_count}/{total} \
                 ({pct}%) commits in the last {window} days. Projects with one dominant \
                 contributor carry high bus-factor risk.",
                window = self.window_days,
            ),
            Some(
                "Add co-maintainers, document the contribution process, and consider \
                 inviting trusted contributors to share ownership."
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
    use std::io::Write as _;
    use time::OffsetDateTime;

    fn make_analyzer() -> Health001SingleAuthor {
        Health001SingleAuthor::default()
    }

    fn run_with_log(log: GitLog, pyproject: bool) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        if pyproject {
            let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
            f.write_all(b"[project]\nname = \"x\"\nversion = \"1.0\"\n")
                .unwrap();
        }
        // Inject .git so manifest picks it up (not actually used — we bypass via mock)
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();

        // No clear_cache() here: tempfile gives unique dirs, avoiding collisions.
        let project = Project::new(dir.path(), vec![]);
        let manifest = crate::manifest::manifest_for(&project);
        manifest.inject_git_log_for_test(Ok(log));

        let analyzer = make_analyzer();
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    fn days_ago(n: i64) -> OffsetDateTime {
        now() - time::Duration::days(n)
    }

    #[test]
    fn health001_single_author_positive() {
        // All 10 commits from one author → HEALTH001
        let commits: Vec<Commit> = (0..10)
            .map(|i| Commit::new_for_test("alice@example.com", days_ago(i)))
            .collect();
        let log = GitLog::new_for_test(commits, vec![]);
        let findings = run_with_log(log, true);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "HEALTH001-single-author");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn health001_two_equal_authors_clean() {
        // 5 commits each → 50% each → no finding
        let mut commits: Vec<Commit> = (0..5)
            .map(|i| Commit::new_for_test("alice@example.com", days_ago(i)))
            .collect();
        commits.extend((0..5).map(|i| Commit::new_for_test("bob@example.com", days_ago(i + 5))));
        let log = GitLog::new_for_test(commits, vec![]);
        let findings = run_with_log(log, true);
        assert!(
            findings.is_empty(),
            "expected 0 HEALTH001 findings: {findings:#?}"
        );
    }

    #[test]
    fn health001_healthy_baseline_no_git_dir() {
        // No .git directory → git-unavailable Info, not HEALTH001
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        f.write_all(b"[project]\nname = \"x\"\nversion = \"1.0\"\n")
            .unwrap();

        let project = Project::new(dir.path(), vec![]);
        let analyzer = make_analyzer();
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_project(&ctx, &project);
        // Should be exactly one git-unavailable Info finding
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "HEALTH/git-unavailable");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn health001_empty_commits_clean() {
        let log = GitLog::new_for_test(vec![], vec![]);
        let findings = run_with_log(log, true);
        assert!(findings.is_empty());
    }
}
