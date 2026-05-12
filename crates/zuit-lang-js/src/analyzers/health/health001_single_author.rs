//! `HEALTH001-single-author` — flags repositories where a single author
//! accounts for more than 50% of all commits.
//!
//! A highly concentrated commit history is a bus-factor signal: if that one
//! author becomes unavailable the project may stall. This is a Low-severity
//! project-health indicator.
//!
//! # WHY: no window filtering
//! The plan mentions a configurable `git_history_window_days` parameter, but
//! the `Config` struct has no JS-specific section in this phase. Rather than
//! adding dead configuration plumbing, all authors in the full `GitLog` are
//! counted. The deviation is documented here and will be resolved when the
//! `[javascript]` config section lands (Phase 6).

use std::collections::HashMap;
use std::path::Path;

use zuit_core::span::{ByteOffset, LineCol, Location, Span};
use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, AnalyzerKind, Dimension, Finding, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
};

use crate::manifest::GitLog;

const RULE_ID: &str = "HEALTH001-single-author";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/HEALTH001-single-author.md",
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
/// Returns one finding if a single author accounts for >50 % of all commits in
/// `git_log.authors`.  Returns an empty vec otherwise.
pub(crate) fn evaluate(git_log: &GitLog, root: &Path) -> Vec<Finding> {
    let authors = &git_log.authors;
    let total = authors.len();
    if total == 0 {
        return vec![];
    }

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for author in authors {
        *counts.entry(author.as_str()).or_insert(0) += 1;
    }

    let max_count = counts.values().copied().max().unwrap_or(0);
    // >50 % means strictly more than half.
    if max_count * 2 <= total {
        return vec![];
    }

    let top_author = counts
        .iter()
        .max_by_key(|&(_, v)| v)
        .map_or("<unknown>", |(k, _)| *k);

    vec![Finding {
        analyzer: AnalyzerId::new(RULE_ID),
        dimension: Dimension::Custom("project_health".to_string()),
        rule_id: RULE_ID.to_string(),
        severity: Severity::Low,
        message: format!(
            "Single author ({top_author}) made {max_count} of {total} commits ({}%); \
             bus factor is very low.",
            max_count * 100 / total
        ),
        location: root_location(root),
        suggestion: Some(
            "Encourage additional contributors to reduce bus-factor risk.".to_string(),
        ),
        references: vec![],
        cwe: META.cwe_vec(),
        owasp: META.owasp_vec(),
    }]
}

/// Analyzer that emits `HEALTH001-single-author` when one author dominates
/// the commit history.
pub struct Health001SingleAuthorAnalyzer;

impl Analyzer for Health001SingleAuthorAnalyzer {
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
    fn single_author_majority_emits_one_low() {
        // 6 out of 10 commits from the same author → >50 % → finding.
        let authors: Vec<String> = std::iter::repeat_n("alice@example.com".to_string(), 6)
            .chain(std::iter::repeat_n("bob@example.com".to_string(), 4))
            .collect();
        let log = GitLog::for_tests(authors, Some(10), None);
        let findings = evaluate(&log, &root());
        assert_eq!(findings.len(), 1, "expected 1 finding, got {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn exactly_half_is_not_majority() {
        // 5 of 10 is exactly 50% — NOT >50%, so no finding.
        let authors: Vec<String> = std::iter::repeat_n("alice@example.com".to_string(), 5)
            .chain(std::iter::repeat_n("bob@example.com".to_string(), 5))
            .collect();
        let log = GitLog::for_tests(authors, Some(10), None);
        let findings = evaluate(&log, &root());
        assert!(findings.is_empty(), "50%% must not trigger: {findings:#?}");
    }

    #[test]
    fn diverse_authors_no_finding() {
        // 4 authors with 25 % each — no single majority.
        let authors: Vec<String> = ["a@x", "b@x", "c@x", "d@x"]
            .iter()
            .flat_map(|e| std::iter::repeat_n(e.to_string(), 25))
            .collect();
        let log = GitLog::for_tests(authors, Some(10), None);
        let findings = evaluate(&log, &root());
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn empty_log_no_finding() {
        let log = GitLog::for_tests(vec![], Some(0), None);
        let findings = evaluate(&log, &root());
        assert!(findings.is_empty(), "empty log must produce no findings");
    }

    #[test]
    fn all_commits_same_author_emits_finding() {
        let authors = vec!["solo@example.com".to_string(); 50];
        let log = GitLog::for_tests(authors, Some(5), None);
        let findings = evaluate(&log, &root());
        assert_eq!(findings.len(), 1, "100%% single author must trigger");
    }

    #[test]
    fn finding_message_contains_percentage() {
        let authors: Vec<String> = std::iter::repeat_n("x@x".to_string(), 8)
            .chain(std::iter::repeat_n("y@x".to_string(), 2))
            .collect();
        let log = GitLog::for_tests(authors, None, None);
        let findings = evaluate(&log, &root());
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains('%'),
            "message should show percentage: {}",
            findings[0].message
        );
    }
}
