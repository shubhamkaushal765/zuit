//! `MAINT007-return-complexity` — flags functions with too many return
//! statements (CWE-1121).
//!
//! ## Detection strategy
//!
//! For every [`FunctionLike`] in the [`SemanticIndex`], read
//! `complexity.returns`. If it exceeds the configured threshold
//! (default 4), emit one finding at the function's span start.
//!
//! ## Configuration
//!
//! ```toml
//! [rules."MAINT007-return-complexity"]
//! threshold = 4   # default
//! ```
//!
//! [`FunctionLike`]: zuit_core::FunctionLike
//! [`SemanticIndex`]: zuit_core::SemanticIndex

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages,
    span::{Location, Span},
};

/// Rule ID for the return-complexity check.
pub const RULE_ID: &str = "MAINT007-return-complexity";

/// Default maximum number of return statements before a finding is emitted.
const DEFAULT_THRESHOLD: u32 = 4;

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/MAINT007-return-complexity.md",
    cwe: &["CWE-1121"],
    owasp: &[],
};

/// Analyzer that detects functions with an excessive number of return statements.
#[derive(Debug, Default)]
pub struct ReturnComplexityAnalyzer;

impl Analyzer for ReturnComplexityAnalyzer {
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
        let mut findings = Vec::new();

        for func in &index.functions {
            if func.complexity.returns <= threshold {
                continue;
            }

            let name = func.name.as_deref().unwrap_or("<anonymous>");
            let returns = func.complexity.returns;

            // Anchor the finding at the function declaration start.
            let span = Span::new(func.span.start, func.span.start);
            let (start_lc, end_lc) = source.span_to_linecols(span);

            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Maintainability,
                rule_id: RULE_ID.to_string(),
                severity: Severity::Low,
                message: format!(
                    "function `{name}` has {returns} return statements (threshold: {threshold})"
                ),
                location: Location {
                    file: source.path.clone(),
                    span,
                    start: start_lc,
                    end: end_lc,
                },
                suggestion: Some(
                    "Extract early-exit logic into helper functions or restructure with \
                     guard clauses to reduce the number of return paths."
                        .to_string(),
                ),
                references: vec![],
                cwe: META.cwe_vec(),
                owasp: META.owasp_vec(),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use zuit_core::{Config, Language, SourceFile};

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

    fn js_parse(path: &str, source: &str) -> ParsedFile {
        let src = Arc::new(SourceFile::new(path, source.as_bytes().to_vec()));
        zuit_lang_js::JsLanguage
            .parse(src)
            .expect("js parse failed")
    }

    fn make_ctx(config: &Config) -> AnalysisContext<'_> {
        AnalysisContext::new(config)
    }

    // ── Rust positive ─────────────────────────────────────────────────────────

    #[test]
    fn rust_return_complexity_positive() {
        let source = include_str!("../../../fixtures/rust/return_complexity/lib.rs");
        let file = rust_parse("fixtures/rust/return_complexity/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = ReturnComplexityAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 MAINT007 finding for return_complexity Rust fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings should have a suggestion"
        );
    }

    // ── Rust negative ─────────────────────────────────────────────────────────

    #[test]
    fn rust_low_returns_negative() {
        let source = include_str!("../../../fixtures/rust/low_returns/lib.rs");
        let file = rust_parse("fixtures/rust/low_returns/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = ReturnComplexityAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT007 findings for low_returns Rust fixture, got {findings:#?}"
        );
    }

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_return_complexity_positive() {
        let source = include_str!("../../../fixtures/python/return_complexity/main.py");
        let file = python_parse("fixtures/python/return_complexity/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = ReturnComplexityAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 MAINT007 finding for return_complexity Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Python negative ───────────────────────────────────────────────────────

    #[test]
    fn python_low_returns_negative() {
        let source = include_str!("../../../fixtures/python/low_returns/main.py");
        let file = python_parse("fixtures/python/low_returns/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = ReturnComplexityAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT007 findings for low_returns Python fixture, got {findings:#?}"
        );
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_return_complexity_positive() {
        let source = include_str!("../../../fixtures/js/return_complexity/main.ts");
        let file = js_parse("fixtures/js/return_complexity/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = ReturnComplexityAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 MAINT007 finding for return_complexity JS fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── JS negative ───────────────────────────────────────────────────────────

    #[test]
    fn js_low_returns_negative() {
        let source = include_str!("../../../fixtures/js/low_returns/main.ts");
        let file = js_parse("fixtures/js/low_returns/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = ReturnComplexityAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT007 findings for low_returns JS fixture, got {findings:#?}"
        );
    }

    // ── threshold config ──────────────────────────────────────────────────────

    #[test]
    fn threshold_config_respected() {
        // With threshold=99, even return_complexity fixture should be clean.
        let source = include_str!("../../../fixtures/rust/return_complexity/lib.rs");
        let file = rust_parse("fixtures/rust/return_complexity/lib.rs", source);
        let config =
            Config::from_toml_str("[rules.\"MAINT007-return-complexity\"]\nthreshold = 99")
                .expect("valid toml");
        let ctx = make_ctx(&config);
        let findings = ReturnComplexityAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "threshold=99 should suppress all findings, got {findings:#?}"
        );
    }
}
