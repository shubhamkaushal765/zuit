//! `TEST005-assert-count` — flags test functions that contain more than a
//! configurable number of assertions.
//!
//! ## Detection strategy
//!
//! For every function in the [`SemanticIndex`] that has `is_test == true`,
//! the source slice covered by `body_span` is searched for assertion tokens
//! using the same compiled regex as [`crate::no_asserts`].  If the count
//! exceeds the threshold, one finding is emitted at the function's span start.
//!
//! ## Configuration
//!
//! ```toml
//! [rules."TEST005-assert-count"]
//! threshold = 10   # default
//! ```
//!
//! [`SemanticIndex`]: zuit_core::SemanticIndex

use std::sync::OnceLock;

use regex::Regex;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages,
    span::{Location, Span},
};

/// Rule ID for the assert-count check.
pub const RULE_ID: &str = "TEST005-assert-count";

/// Default maximum assertion count before a finding is emitted.
const DEFAULT_THRESHOLD: u32 = 10;

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/TEST005-assert-count.md",
    cwe: &[],
    owasp: &[],
};

/// Returns the compiled regex that matches any known assertion token.
///
/// Re-uses the same pattern as `no_asserts.rs` — ordering from most-specific
/// to least-specific to avoid partial matches.
pub(crate) fn assertion_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(
            r"(?:assert(?:_eq|_ne)?!|panic!|assertEqual|assertTrue|assertFalse|assertIn|assertIs\b|chai\.expect|sinon\.assert|jest\.|should\.|expect\b|assert\b)",
        )
        .expect("invariant: assertion pattern is valid")
    })
}

/// Analyzer that detects test functions with an excessive number of assertions.
#[derive(Debug, Default)]
pub struct AssertCountAnalyzer;

impl Analyzer for AssertCountAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::TestSmell
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
        let src_str = source.as_str();
        let index = file.index();
        let pattern = assertion_pattern();
        let mut findings = Vec::new();

        for func in &index.functions {
            if !func.is_test {
                continue;
            }

            // Extract the body slice covered by body_span.
            let body_start = func.body_span.start.0 as usize;
            let body_end = func.body_span.end.0 as usize;
            let body_end = body_end.min(src_str.len());

            if body_start >= src_str.len() || body_start > body_end {
                continue;
            }

            let body_slice = &src_str[body_start..body_end];
            let count = pattern.find_iter(body_slice).count();

            #[allow(clippy::cast_possible_truncation)]
            if count as u32 <= threshold {
                continue;
            }

            let name = func.name.as_deref().unwrap_or("<anonymous>");
            let span = Span::new(func.span.start, func.span.start);
            let (start_lc, end_lc) = source.span_to_linecols(span);

            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::TestSmell,
                rule_id: RULE_ID.to_string(),
                severity: Severity::Low,
                message: format!(
                    "test function `{name}` has {count} assertions (threshold: {threshold})"
                ),
                location: Location {
                    file: source.path.clone(),
                    span,
                    start: start_lc,
                    end: end_lc,
                },
                suggestion: Some(
                    "Split into multiple smaller, focused test functions — \
                     each verifying a single behaviour."
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
    fn rust_assert_count_positive() {
        let source = include_str!("../../../fixtures/rust/assert_count/lib.rs");
        let file = rust_parse("fixtures/rust/assert_count/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = AssertCountAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 TEST005 finding for assert_count Rust fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings should have a suggestion"
        );
    }

    // ── Rust negative ─────────────────────────────────────────────────────────

    #[test]
    fn rust_few_asserts_negative() {
        let source = include_str!("../../../fixtures/rust/few_asserts/lib.rs");
        let file = rust_parse("fixtures/rust/few_asserts/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = AssertCountAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST005 findings for few_asserts Rust fixture, got {findings:#?}"
        );
    }

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_assert_count_positive() {
        let source = include_str!("../../../fixtures/python/assert_count/main.py");
        let file = python_parse("fixtures/python/assert_count/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = AssertCountAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 TEST005 finding for assert_count Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Python negative ───────────────────────────────────────────────────────

    #[test]
    fn python_few_asserts_negative() {
        let source = include_str!("../../../fixtures/python/few_asserts/main.py");
        let file = python_parse("fixtures/python/few_asserts/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = AssertCountAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST005 findings for few_asserts Python fixture, got {findings:#?}"
        );
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_assert_count_positive() {
        let source = include_str!("../../../fixtures/js/assert_count/main.ts");
        let file = js_parse("fixtures/js/assert_count/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = AssertCountAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 TEST005 finding for assert_count JS fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── JS negative ───────────────────────────────────────────────────────────

    #[test]
    fn js_few_asserts_negative() {
        let source = include_str!("../../../fixtures/js/few_asserts/main.ts");
        let file = js_parse("fixtures/js/few_asserts/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = AssertCountAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST005 findings for few_asserts JS fixture, got {findings:#?}"
        );
    }
}
