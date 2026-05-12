//! `HEALTH004-commit-stale` — flags repositories whose most recent commit is
//! older than 180 days.
//!
//! A long gap since the last commit may indicate an abandoned or unmaintained
//! project. This is a Medium-severity project-health finding. The check is
//! silently skipped when `days_since_last_commit` is `None` (empty repository).

use std::path::Path;

use zuit_core::span::{ByteOffset, LineCol, Location, Span};
use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, AnalyzerKind, Dimension, Finding, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
};

use crate::manifest::GitLog;

const RULE_ID: &str = "HEALTH004-commit-stale";

/// Threshold: more than this many days without a commit → finding.
const STALE_COMMIT_DAYS: u32 = 180;

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/HEALTH004-commit-stale.md",
    cwe: &[],
    owasp: &[],
};

/// Zero-width location anchored at the project root.
fn root_location(root: &Path) -> Location {
    let zero = Span::new(ByteOffset(0), ByteOffset(0));
    Location {
        file: root.to_path_buf(),
        span: zero,
        start: LineCol::new(1, 1),
        end: LineCol::new(1, 1),
    }
}

/// Pure evaluation logic — unit-testable without a real project or git repo.
///
/// Returns one finding if `days_since_last_commit > 180`. Returns an empty vec
/// when the commit age is below the threshold or when the history is empty.
pub(crate) fn evaluate(git_log: &GitLog, root: &Path) -> Vec<Finding> {
    let Some(days) = git_log.days_since_last_commit else {
        // No commits at all → skip silently.
        return vec![];
    };

    if days <= STALE_COMMIT_DAYS {
        return vec![];
    }

    vec![Finding {
        analyzer: AnalyzerId::new(RULE_ID),
        dimension: Dimension::Custom("project_health".to_string()),
        rule_id: RULE_ID.to_string(),
        severity: Severity::Medium,
        message: format!(
            "Most recent commit is {days} days old (threshold: {STALE_COMMIT_DAYS}). \
             The project may no longer be actively maintained."
        ),
        location: root_location(root),
        suggestion: Some(
            "Verify that the project is still actively maintained before adopting it.".to_string(),
        ),
        references: vec![],
        cwe: META.cwe_vec(),
        owasp: META.owasp_vec(),
    }]
}

/// Analyzer that emits `HEALTH004-commit-stale` when the most recent commit
/// is older than 180 days.
pub struct Health004CommitStaleAnalyzer;

impl Analyzer for Health004CommitStaleAnalyzer {
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

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, _file: &ParsedFile) -> Vec<Finding> {
        vec![]
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        let manifest = crate::manifest::get_or_load(&project.root);
        let Some(git_log) = super::manifest_git_log(&manifest) else {
            return vec![];
        };
        evaluate(git_log, &project.root)
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        PathBuf::from("/tmp/test-root")
    }

    #[test]
    fn health004_stale_commit_positive() {
        // Last commit is 200 days ago → above the 180-day threshold → 1 finding.
        let log = GitLog::for_tests(vec![], Some(200), None);
        let findings = evaluate(&log, &root());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn health004_recent_commit_clean() {
        // Last commit is 30 days ago → below threshold → 0 findings.
        let log = GitLog::for_tests(vec![], Some(30), None);
        let findings = evaluate(&log, &root());
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn health004_exactly_threshold_is_clean() {
        // Exactly 180 days → not strictly greater → 0 findings.
        let log = GitLog::for_tests(vec![], Some(180), None);
        let findings = evaluate(&log, &root());
        assert!(findings.is_empty(), "exactly 180 days must not trigger");
    }

    #[test]
    fn health004_no_commits_skipped() {
        // None commit age → silently skipped → 0 findings.
        let log = GitLog::for_tests(vec![], None, None);
        let findings = evaluate(&log, &root());
        assert!(findings.is_empty(), "absent commit age must not trigger");
    }

    #[test]
    fn health004_one_day_over_threshold() {
        let log = GitLog::for_tests(vec![], Some(181), None);
        let findings = evaluate(&log, &root());
        assert_eq!(findings.len(), 1, "181 days must trigger");
    }

    #[test]
    fn health004_finding_message_contains_day_count() {
        let log = GitLog::for_tests(vec![], Some(200), None);
        let findings = evaluate(&log, &root());
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains("200"),
            "message should include day count: {}",
            findings[0].message
        );
    }
}
