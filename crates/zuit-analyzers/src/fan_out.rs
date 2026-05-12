//! `CPLX001-fan-out` — flags files whose distinct import count exceeds a
//! configurable threshold.
//!
//! **Fan-out** is the per-file out-degree in the module dependency graph: the
//! number of distinct modules a file depends on directly.  High fan-out
//! indicates that a file has too many responsibilities and is a sign of
//! insufficient modular decomposition.
//!
//! The count is computed by collecting unique `Import.path` values from
//! `SemanticIndex::imports` into a `HashSet`.  Languages that expand a single
//! statement into multiple `Import` entries (e.g. Python's
//! `from os import path, getcwd`) still produce the correct distinct count
//! because deduplication is done on the full path string, not on the
//! originating statement span.
//!
//! ## Configuration
//!
//! ```toml
//! [rules.CPLX001-fan-out]
//! threshold = 20
//! ```
//!
//! The default threshold is **20**.

use std::collections::HashSet;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages,
    span::{ByteOffset, Location, Span},
};

/// Rule ID for the fan-out check.
pub const RULE_ID: &str = "CPLX001-fan-out";

/// Default fan-out threshold; files at or below this value are not flagged.
const DEFAULT_THRESHOLD: u32 = 20;

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/CPLX001-fan-out.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that flags files exceeding the distinct import count threshold.
///
/// The threshold is read from `[rules.CPLX001-fan-out] threshold` in
/// `zuit.toml`; the default is 20.
#[derive(Debug, Default)]
pub struct FanOutAnalyzer;

impl Analyzer for FanOutAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Complexity
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

        // Deduplicate by path to avoid double-counting multi-name imports such
        // as `from foo import a, b` in Python (which the frontend records as two
        // `Import` entries with the same path prefix).
        let distinct: HashSet<&str> = index.imports.iter().map(|i| i.path.as_str()).collect();
        let count = u32::try_from(distinct.len()).unwrap_or(u32::MAX);

        if count > threshold {
            let total_bytes = source.len();
            let span = Span::new(
                ByteOffset(0),
                ByteOffset(u32::try_from(total_bytes).unwrap_or(u32::MAX)),
            );
            let (start_lc, end_lc) = source.span_to_linecols(span);

            vec![Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Complexity,
                rule_id: RULE_ID.to_string(),
                severity: Severity::Low,
                message: format!("file imports {count} distinct modules (threshold {threshold})"),
                location: Location {
                    file: source.path.clone(),
                    span,
                    start: start_lc,
                    end: end_lc,
                },
                suggestion: Some(
                    "Reduce module fan-out by extracting cohesive submodules or \
                     removing transitively-unused imports."
                        .to_string(),
                ),
                references: vec![],
                cwe: META.cwe_vec(),
                owasp: META.owasp_vec(),
            }]
        } else {
            vec![]
        }
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

    fn js_parse(path: &str, source: &str) -> ParsedFile {
        let src = Arc::new(SourceFile::new(path, source.as_bytes().to_vec()));
        zuit_lang_js::JsLanguage
            .parse(src)
            .expect("js parse failed")
    }

    fn make_ctx(config: &Config) -> AnalysisContext<'_> {
        AnalysisContext::new(config)
    }

    // ── Rust positive: fan_out fixture has > 20 distinct imports ─────────────

    #[test]
    fn rust_fan_out_positive() {
        let source = include_str!("../../../fixtures/rust/fan_out/lib.rs");
        let file = rust_parse("fixtures/rust/fan_out/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FanOutAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 CPLX001 finding for fan_out Rust fixture"
        );
        assert_eq!(findings.len(), 1, "expected exactly 1 finding per file");
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Rust negative: healthy fixture produces 0 findings ───────────────────

    #[test]
    fn rust_healthy_fan_out_negative() {
        let source = include_str!("../../../fixtures/rust/healthy/lib.rs");
        let file = rust_parse("fixtures/rust/healthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FanOutAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 CPLX001 findings for healthy Rust fixture, got {findings:#?}"
        );
    }

    // ── Python positive: fan_out fixture has > 20 distinct imports ───────────

    #[test]
    fn python_fan_out_positive() {
        let source = include_str!("../../../fixtures/python/fan_out/main.py");
        let file = python_parse("fixtures/python/fan_out/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FanOutAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 CPLX001 finding for fan_out Python fixture"
        );
        assert_eq!(findings.len(), 1, "expected exactly 1 finding per file");
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Python negative: healthy fixture produces 0 findings ─────────────────

    #[test]
    fn python_healthy_fan_out_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FanOutAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 CPLX001 findings for healthy Python fixture, got {findings:#?}"
        );
    }

    // ── JS positive: fan_out fixture has > 20 distinct imports ───────────────

    #[test]
    fn js_fan_out_positive() {
        let source = include_str!("../../../fixtures/js/fan_out/main.ts");
        let file = js_parse("fixtures/js/fan_out/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FanOutAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 CPLX001 finding for fan_out JS fixture"
        );
        assert_eq!(findings.len(), 1, "expected exactly 1 finding per file");
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── JS negative: healthy fixture produces 0 findings ─────────────────────

    #[test]
    fn js_healthy_fan_out_negative() {
        let source = include_str!("../../../fixtures/js/healthy/main.ts");
        let file = js_parse("fixtures/js/healthy/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FanOutAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 CPLX001 findings for healthy JS fixture, got {findings:#?}"
        );
    }
}
