//! `DOC002-todo-fixme` — flags TODO and FIXME markers in comments.
//!
//! Scans all comments (not doc-comments) in a file and emits a finding for each
//! occurrence of a case-insensitive whole-word `TODO` or `FIXME` marker.

use std::sync::OnceLock;

use regex::Regex;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages, span::Location,
};

/// Rule ID for the TODO/FIXME check.
pub const RULE_ID: &str = "DOC002-todo-fixme";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Info,
    doc_path: "docs/rules/DOC002-todo-fixme.md",
    cwe: &["CWE-546"],
    owasp: &[],
};

/// Returns the compiled regex for TODO and FIXME markers.
/// Matches case-insensitively and requires whole-word boundaries.
fn todo_fixme_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(r"(?i)\b(TODO|FIXME)\b").expect("invariant: TODO/FIXME pattern is valid")
    })
}

/// Analyzer that flags TODO and FIXME markers in comments.
#[derive(Debug, Default)]
pub struct TodoFixmeAnalyzer;

impl Analyzer for TodoFixmeAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Documentation
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let source = file.source();
        let index = file.index();
        let regex = todo_fixme_pattern();

        let mut findings = Vec::new();

        for comment in &index.comments {
            // Find all matches of TODO or FIXME in this comment's text.
            for mat in regex.find_iter(&comment.text) {
                let matched_marker = &comment.text[mat.start()..mat.end()];
                let message = format!("{matched_marker} marker in comment");
                let (start_lc, end_lc) = source.span_to_linecols(comment.span);

                findings.push(Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Documentation,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Info,
                    message,
                    location: Location {
                        file: source.path.clone(),
                        span: comment.span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some("Address this TODO or FIXME marker before merge.".to_string()),
                    references: vec![],
                    cwe: META.cwe_vec(),
                    owasp: META.owasp_vec(),
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Config, Language, SourceFile};
    use std::sync::Arc;

    fn rust_parse(path: &str, source: &str) -> ParsedFile {
        let src = Arc::new(SourceFile::new(path, source.as_bytes().to_vec()));
        zuit_lang_rust::RustLanguage
            .parse(src)
            .expect("rust parse failed")
    }

    fn python_parse(path: &str, source: &str) -> ParsedFile {
        let src = Arc::new(SourceFile::new(path, source.as_bytes().to_vec()));
        zuit_lang_python::PythonLanguage
            .parse(src)
            .expect("python parse failed")
    }

    fn make_ctx(config: &Config) -> AnalysisContext<'_> {
        AnalysisContext::new(config)
    }

    // ── Rust positive: todo_fixme fixture should produce ≥ 2 findings ────────

    #[test]
    fn rust_todo_fixme_positive() {
        let source = include_str!("../../../fixtures/rust/todo_fixme/lib.rs");
        let file = rust_parse("fixtures/rust/todo_fixme/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = TodoFixmeAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.len() >= 2,
            "expected ≥2 DOC002 findings for todo_fixme Rust fixture, got {}",
            findings.len()
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Rust negative: healthy fixture should produce 0 findings ─────────────

    #[test]
    fn rust_healthy_todo_fixme_negative() {
        let source = include_str!("../../../fixtures/rust/healthy/lib.rs");
        let file = rust_parse("fixtures/rust/healthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = TodoFixmeAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 DOC002 findings for healthy Rust fixture, got {findings:#?}"
        );
    }

    // ── Python positive: todo_fixme fixture should produce ≥ 2 findings ──────

    #[test]
    fn python_todo_fixme_positive() {
        let source = include_str!("../../../fixtures/python/todo_fixme/main.py");
        let file = python_parse("fixtures/python/todo_fixme/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = TodoFixmeAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.len() >= 2,
            "expected ≥2 DOC002 findings for todo_fixme Python fixture, got {}",
            findings.len()
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Python negative: healthy fixture should produce 0 findings ──────────

    #[test]
    fn python_healthy_todo_fixme_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = TodoFixmeAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 DOC002 findings for healthy Python fixture, got {findings:#?}"
        );
    }
}
