//! `MAINT005-deep-nesting` — flags functions whose maximum nesting depth exceeds
//! a configurable threshold.
//!
//! The nesting depth value is taken directly from the `SemanticIndex`; the analyzer
//! never re-walks the native AST.

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages, span::Location,
};

/// Rule ID for the deep nesting check.
pub const RULE_ID: &str = "MAINT005-deep-nesting";

/// Default maximum nesting depth threshold; functions at or below this value
/// are not flagged.
const DEFAULT_THRESHOLD: u32 = 4;

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/MAINT005-deep-nesting.md",
    cwe: &["CWE-1124"],
    owasp: &[],
};

/// Analyzer that flags functions exceeding the maximum nesting depth threshold.
///
/// The threshold is read from `[rules.MAINT005-deep-nesting] threshold` in
/// `zuit.toml`; the default is 4.
#[derive(Debug, Default)]
pub struct DeepNestingAnalyzer;

impl Analyzer for DeepNestingAnalyzer {
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
            .filter(|f| f.complexity.max_nesting > threshold)
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
                        "function `{name}` has maximum nesting depth {} (threshold {threshold})",
                        f.complexity.max_nesting,
                    ),
                    location: Location {
                        file: source.path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Reduce nesting by extracting inner logic into helper functions."
                            .to_string(),
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

    // ── Rust positive: deep_nesting fixture should produce ≥ 1 finding ──────────

    #[test]
    fn rust_deep_nesting_positive() {
        let source = include_str!("../../../fixtures/rust/deep_nesting/lib.rs");
        let file = rust_parse("fixtures/rust/deep_nesting/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = DeepNestingAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 MAINT005 finding for deep_nesting Rust fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Rust negative: healthy fixture should produce 0 findings ─────────────

    #[test]
    fn rust_healthy_deep_nesting_negative() {
        let source = include_str!("../../../fixtures/rust/healthy/lib.rs");
        let file = rust_parse("fixtures/rust/healthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = DeepNestingAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT005 findings for healthy Rust fixture, got {findings:#?}"
        );
    }

    // ── Python positive: deep_nesting fixture should produce ≥ 1 finding ────────

    #[test]
    fn python_deep_nesting_positive() {
        let source = include_str!("../../../fixtures/python/deep_nesting/main.py");
        let file = python_parse("fixtures/python/deep_nesting/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = DeepNestingAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 MAINT005 finding for deep_nesting Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Python negative: healthy fixture should produce 0 findings ───────────

    #[test]
    fn python_healthy_deep_nesting_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = DeepNestingAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT005 findings for healthy Python fixture, got {findings:#?}"
        );
    }
}
