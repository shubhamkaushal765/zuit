//! `MAINT001-cyclomatic` — flags functions whose cyclomatic complexity exceeds
//! a configurable threshold.
//!
//! The complexity value is taken directly from the `SemanticIndex`; the analyzer
//! never re-walks the native AST.

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages, span::Location,
};

/// Rule ID for the cyclomatic-complexity check.
pub const RULE_ID: &str = "MAINT001-cyclomatic";

/// Default cyclomatic complexity threshold; functions at or below this value
/// are not flagged.
const DEFAULT_THRESHOLD: u32 = 10;

/// Static metadata for this rule. Holds the CWE mapping that is propagated
/// to every emitted [`Finding`] and surfaced by `zuit list analyzers`.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/MAINT001-cyclomatic.md",
    cwe: &["CWE-1121"],
    owasp: &[],
};

/// Analyzer that flags functions exceeding the cyclomatic complexity threshold.
///
/// The threshold is read from `[rules.MAINT001-cyclomatic] threshold` in
/// `zuit.toml`; the default is 10.
#[derive(Debug, Default)]
pub struct CyclomaticAnalyzer;

impl Analyzer for CyclomaticAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Maintainability
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let threshold = ctx.config.rule_threshold(RULE_ID, DEFAULT_THRESHOLD);
        let source = file.source();
        let index = file.index();

        index
            .functions
            .iter()
            .filter(|f| f.complexity.cyclomatic > threshold)
            .map(|f| {
                // Use the function's body_span for the finding location, falling
                // back to the full span if the body_span is degenerate.
                let span = if f.body_span.is_empty() {
                    f.span
                } else {
                    f.body_span
                };
                let (start_lc, end_lc) = source.span_to_linecols(span);
                let name = f.name.as_deref().unwrap_or("<anonymous>");
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Maintainability,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "function `{name}` has cyclomatic complexity {} (threshold {threshold})",
                        f.complexity.cyclomatic,
                    ),
                    location: Location {
                        file: source.path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Break this function into smaller, single-purpose helpers.".to_string(),
                    ),
                    references: vec![],
                    cwe: META.cwe_vec(),
                    owasp: META.owasp_vec(),
                }
            })
            .collect()
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

    // ── Rust positive: unhealthy fixture should produce ≥ 1 finding ──────────

    #[test]
    fn rust_unhealthy_cyclomatic_positive() {
        let source = include_str!("../../../fixtures/rust/unhealthy/lib.rs");
        let file = rust_parse("fixtures/rust/unhealthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CyclomaticAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 MAINT001 finding for unhealthy Rust fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Rust negative: healthy fixture should produce 0 findings ─────────────

    #[test]
    fn rust_healthy_cyclomatic_negative() {
        let source = include_str!("../../../fixtures/rust/healthy/lib.rs");
        let file = rust_parse("fixtures/rust/healthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CyclomaticAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT001 findings for healthy Rust fixture, got {findings:#?}"
        );
    }

    // ── Python positive: unhealthy fixture should produce ≥ 1 finding ────────

    #[test]
    fn python_unhealthy_cyclomatic_positive() {
        let source = include_str!("../../../fixtures/python/unhealthy/main.py");
        let file = python_parse("fixtures/python/unhealthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CyclomaticAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 MAINT001 finding for unhealthy Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Python negative: healthy fixture should produce 0 findings ───────────

    #[test]
    fn python_healthy_cyclomatic_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CyclomaticAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT001 findings for healthy Python fixture, got {findings:#?}"
        );
    }
}
