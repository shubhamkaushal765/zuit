//! `MAINT003-fn-length` — flags functions whose body spans more than a
//! configurable number of lines.
//!
//! The length is calculated as `end_line - start_line + 1` using the body's
//! source span. Empty bodies fall back to the full declaration span.

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages, span::Location,
};

/// Rule ID for the function length check.
pub const RULE_ID: &str = "MAINT003-fn-length";

/// Default function length threshold in lines; functions at or below this value
/// are not flagged.
const DEFAULT_THRESHOLD: u32 = 80;

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/MAINT003-fn-length.md",
    cwe: &["CWE-1121"],
    owasp: &[],
};

/// Analyzer that flags functions whose body exceeds the line-count threshold.
///
/// The threshold is read from `[rules.MAINT003-fn-length] threshold` in
/// `zuit.toml`; the default is 80 lines.
#[derive(Debug, Default)]
pub struct FnLengthAnalyzer;

impl Analyzer for FnLengthAnalyzer {
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
            .filter_map(|f| {
                // Use body_span if non-empty, otherwise fall back to full span.
                let span = if f.body_span.is_empty() {
                    f.span
                } else {
                    f.body_span
                };

                let (start_lc, end_lc) = source.span_to_linecols(span);
                let body_length = end_lc.line - start_lc.line + 1;

                if body_length > threshold {
                    let name = f.name.as_deref().unwrap_or("<anonymous>");
                    Some(Finding {
                        analyzer: AnalyzerId::new(RULE_ID),
                        dimension: Dimension::Maintainability,
                        rule_id: RULE_ID.to_string(),
                        severity: Severity::Low,
                        message: format!(
                            "function `{name}` has a body of {body_length} lines (threshold {threshold})",
                        ),
                        location: Location {
                            file: source.path.clone(),
                            span,
                            start: start_lc,
                            end: end_lc,
                        },
                        suggestion: Some(
                            "Break this function into smaller, focused helpers.".to_string(),
                        ),
                        references: vec![],
                        cwe: META.cwe_vec(),
                        owasp: META.owasp_vec(),
                    })
                } else {
                    None
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

    // ── Rust positive: long_fn fixture should produce ≥ 1 finding ─────────

    #[test]
    fn rust_long_fn_positive() {
        let source = include_str!("../../../fixtures/rust/long_fn/lib.rs");
        let file = rust_parse("fixtures/rust/long_fn/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FnLengthAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 MAINT003 finding for long_fn Rust fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Rust negative: healthy fixture should produce 0 findings ──────────

    #[test]
    fn rust_healthy_fn_length_negative() {
        let source = include_str!("../../../fixtures/rust/healthy/lib.rs");
        let file = rust_parse("fixtures/rust/healthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FnLengthAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT003 findings for healthy Rust fixture, got {findings:#?}"
        );
    }

    // ── Python positive: long_fn fixture should produce ≥ 1 finding ───────

    #[test]
    fn python_long_fn_positive() {
        let source = include_str!("../../../fixtures/python/long_fn/main.py");
        let file = python_parse("fixtures/python/long_fn/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FnLengthAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 MAINT003 finding for long_fn Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Python negative: healthy fixture should produce 0 findings ────────

    #[test]
    fn python_healthy_fn_length_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FnLengthAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT003 findings for healthy Python fixture, got {findings:#?}"
        );
    }
}
