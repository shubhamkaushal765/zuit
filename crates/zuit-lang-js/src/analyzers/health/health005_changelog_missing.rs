//! `HEALTH005-changelog-missing` — flags projects with no `CHANGELOG*` or
//! `HISTORY*` file at the project root.
//!
//! A changelog documents user-visible changes between releases and helps
//! consumers audit what changed before upgrading. Its absence is a Low-severity
//! packaging-hygiene signal. The check is case-insensitive and matches any file
//! extension (e.g. `CHANGELOG.md`, `CHANGELOG.txt`, `HISTORY.rst`).

use std::path::Path;

use zuit_core::span::{ByteOffset, LineCol, Location, Span};
use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, AnalyzerKind, Dimension, Finding, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
};

const RULE_ID: &str = "HEALTH005-changelog-missing";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/HEALTH005-changelog-missing.md",
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

/// Returns `true` if `root` contains at least one file whose name starts with
/// `changelog` or `history` (case-insensitive), regardless of extension.
///
/// Only direct children of `root` are examined; the search does not recurse
/// into subdirectories.
pub(crate) fn has_changelog(root: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let lower = name.to_string_lossy().to_lowercase();
        if lower.starts_with("changelog") || lower.starts_with("history") {
            return true;
        }
    }
    false
}

/// Pure evaluation logic — unit-testable without a real git repo.
///
/// Returns one finding if no `CHANGELOG*` or `HISTORY*` file exists at `root`.
pub(crate) fn evaluate(root: &Path) -> Vec<Finding> {
    if has_changelog(root) {
        return vec![];
    }

    vec![Finding {
        analyzer: AnalyzerId::new(RULE_ID),
        dimension: Dimension::Custom("project_health".to_string()),
        rule_id: RULE_ID.to_string(),
        severity: Severity::Low,
        message: "No CHANGELOG* or HISTORY* file found at the project root. \
                  Consumers cannot easily audit what changed between releases."
            .to_string(),
        location: root_location(root),
        suggestion: Some(
            "Add a CHANGELOG.md (or HISTORY.md) that records user-visible changes \
             for each release."
                .to_string(),
        ),
        references: vec!["https://keepachangelog.com/".to_string()],
        cwe: META.cwe_vec(),
        owasp: META.owasp_vec(),
    }]
}

/// Analyzer that emits `HEALTH005-changelog-missing` when no changelog file
/// is present at the project root.
pub struct Health005ChangelogMissingAnalyzer;

impl Analyzer for Health005ChangelogMissingAnalyzer {
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
        evaluate(&project.root)
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn health005_changelog_missing() {
        // Empty temp directory — no changelog file → 1 finding.
        let dir = TempDir::new().expect("tempdir");
        let findings = evaluate(dir.path());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn health005_changelog_present_clean() {
        // Write a CHANGELOG.md → 0 findings.
        let dir = TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join("CHANGELOG.md"), "# Changelog\n").expect("write changelog");
        let findings = evaluate(dir.path());
        assert!(
            findings.is_empty(),
            "CHANGELOG.md must suppress the finding"
        );
    }

    #[test]
    fn health005_changelog_txt_variant_clean() {
        // CHANGELOG.txt also counts.
        let dir = TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join("CHANGELOG.txt"), "changes\n").expect("write changelog");
        let findings = evaluate(dir.path());
        assert!(
            findings.is_empty(),
            "CHANGELOG.txt must suppress the finding"
        );
    }

    #[test]
    fn health005_history_file_clean() {
        // HISTORY.rst also counts.
        let dir = TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join("HISTORY.rst"), "history\n").expect("write history");
        let findings = evaluate(dir.path());
        assert!(findings.is_empty(), "HISTORY.rst must suppress the finding");
    }

    #[test]
    fn health005_case_insensitive_lowercase_clean() {
        // changelog.md (lowercase) also counts.
        let dir = TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join("changelog.md"), "# log\n").expect("write changelog");
        let findings = evaluate(dir.path());
        assert!(
            findings.is_empty(),
            "lowercase changelog.md must suppress the finding"
        );
    }

    #[test]
    fn health005_unrelated_files_do_not_suppress() {
        // Only README and package.json — no changelog → 1 finding.
        let dir = TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join("README.md"), "# readme\n").expect("write readme");
        std::fs::write(dir.path().join("package.json"), r#"{"name":"x"}"#).expect("write pkg");
        let findings = evaluate(dir.path());
        assert_eq!(findings.len(), 1, "unrelated files must not suppress");
    }

    #[test]
    fn health005_has_changelog_true_for_changelog_md() {
        let dir = TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join("CHANGELOG.md"), "").expect("write");
        assert!(has_changelog(dir.path()));
    }

    #[test]
    fn health005_has_changelog_false_for_empty_dir() {
        let dir = TempDir::new().expect("tempdir");
        assert!(!has_changelog(dir.path()));
    }
}
