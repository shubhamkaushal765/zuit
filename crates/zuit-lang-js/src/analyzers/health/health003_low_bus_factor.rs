//! `HEALTH003-low-bus-factor` — flags repositories with 2 or fewer distinct
//! commit authors.
//!
//! A project with very few contributors is at high risk if those contributors
//! become unavailable. This is a Low-severity project-health finding.
//!
//! # WHY: no window filtering
//! The plan mentions a configurable `git_history_window_days` parameter, but
//! the `Config` struct has no JS-specific section in this phase. All authors
//! in the full `GitLog` are counted. The deviation will be resolved when the
//! `[javascript]` config section lands (Phase 6).

use std::collections::HashSet;
use std::path::Path;

use zuit_core::span::{ByteOffset, LineCol, Location, Span};
use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, AnalyzerKind, Dimension, Finding, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
};

use crate::manifest::GitLog;

const RULE_ID: &str = "HEALTH003-low-bus-factor";

/// Threshold: ≤ this many distinct authors → finding.
const BUS_FACTOR_THRESHOLD: usize = 2;

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/HEALTH003-low-bus-factor.md",
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
/// Returns one finding if the number of distinct authors in `git_log.authors`
/// is ≤ 2.  Returns an empty vec for an empty log or 3+ distinct authors.
pub(crate) fn evaluate(git_log: &GitLog, root: &Path) -> Vec<Finding> {
    let authors = &git_log.authors;
    if authors.is_empty() {
        return vec![];
    }

    let distinct: HashSet<&str> = authors.iter().map(String::as_str).collect();
    let count = distinct.len();

    if count > BUS_FACTOR_THRESHOLD {
        return vec![];
    }

    vec![Finding {
        analyzer: AnalyzerId::new(RULE_ID),
        dimension: Dimension::Custom("project_health".to_string()),
        rule_id: RULE_ID.to_string(),
        severity: Severity::Low,
        message: format!(
            "Only {count} distinct commit author(s) found (threshold: >{BUS_FACTOR_THRESHOLD}). \
             Bus factor is very low."
        ),
        location: root_location(root),
        suggestion: Some("Broaden the contributor base to reduce bus-factor risk.".to_string()),
        references: vec![],
        cwe: META.cwe_vec(),
        owasp: META.owasp_vec(),
    }]
}

/// Analyzer that emits `HEALTH003-low-bus-factor` when commit history has
/// 2 or fewer distinct authors.
pub struct Health003LowBusFactorAnalyzer;

impl Analyzer for Health003LowBusFactorAnalyzer {
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
    fn health003_bus_factor_one_author() {
        // 50 commits all from one author → bus factor = 1 → 1 finding.
        let authors = vec!["solo@example.com".to_string(); 50];
        let log = GitLog::for_tests(authors, Some(10), None);
        let findings = evaluate(&log, &root());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn health003_two_authors_emits_finding() {
        // 2 distinct authors is still ≤ 2 → finding.
        let authors: Vec<String> = vec!["a@x".to_string(); 25]
            .into_iter()
            .chain(vec!["b@x".to_string(); 25])
            .collect();
        let log = GitLog::for_tests(authors, Some(5), None);
        let findings = evaluate(&log, &root());
        assert_eq!(findings.len(), 1, "two authors must still trigger");
    }

    #[test]
    fn health003_three_authors_clean() {
        // 3 distinct authors → above threshold → 0 findings.
        let authors: Vec<String> = ["a@x", "b@x", "c@x"]
            .iter()
            .flat_map(|e| std::iter::repeat_n(e.to_string(), 10))
            .collect();
        let log = GitLog::for_tests(authors, Some(5), None);
        let findings = evaluate(&log, &root());
        assert!(
            findings.is_empty(),
            "3 authors must not trigger: {findings:#?}"
        );
    }

    #[test]
    fn health003_empty_log_no_finding() {
        let log = GitLog::for_tests(vec![], None, None);
        let findings = evaluate(&log, &root());
        assert!(findings.is_empty(), "empty log must produce no findings");
    }

    #[test]
    fn health003_finding_message_contains_count() {
        let authors = vec!["x@x".to_string(); 10];
        let log = GitLog::for_tests(authors, None, None);
        let findings = evaluate(&log, &root());
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains('1'),
            "message should contain distinct count: {}",
            findings[0].message
        );
    }

    #[test]
    fn health003_many_authors_clean() {
        let authors: Vec<String> = (0..10).map(|i| format!("user{i}@example.com")).collect();
        let log = GitLog::for_tests(authors, Some(1), None);
        let findings = evaluate(&log, &root());
        assert!(findings.is_empty(), "10 authors must not trigger");
    }
}
