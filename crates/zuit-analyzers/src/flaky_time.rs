//! `TEST004-flaky-time` — detects test functions that rely on time or
//! randomness, which can cause intermittent ("flaky") failures.
//!
//! ## Detection strategy
//!
//! For every [`FunctionLike`] in the [`SemanticIndex`] with `is_test == true`,
//! the raw source slice covered by `body_span` is scanned for any of the
//! following tokens:
//!
//! | Token | Context |
//! |---|---|
//! | `sleep` | `time.sleep` (Python), `Thread::sleep` (Rust) |
//! | `setTimeout` | JavaScript / TypeScript |
//! | `Date.now()` | JavaScript / TypeScript |
//! | `SystemTime::now()` | Rust |
//! | `Instant::now()` | Rust |
//! | `time.time()` | Python |
//! | `time.sleep` | Python |
//! | `Math.random` | JavaScript / TypeScript |
//! | `random.random` | Python |
//! | `rand::random` | Rust |
//!
//! One finding per unique token match (deduped per function) is emitted at the
//! function's start span.
//!
//! ## CWE
//!
//! CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
//!
//! [`FunctionLike`]: zuit_core::FunctionLike
//! [`SemanticIndex`]: zuit_core::SemanticIndex

use std::collections::HashSet;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages,
    span::{Location, Span},
};

/// Rule ID for the flaky-time check.
pub const RULE_ID: &str = "TEST004-flaky-time";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/TEST004-flaky-time.md",
    cwe: &["CWE-362"],
    owasp: &[],
};

/// Tokens that indicate time/randomness usage in a test body.
///
/// Checked as plain substring matches; order is most-specific first so that
/// e.g. `Instant::now()` is reported before the shorter `sleep` substring.
const FLAKY_TOKENS: &[&str] = &[
    "SystemTime::now()",
    "Instant::now()",
    "Date.now()",
    "time.time()",
    "time.sleep",
    "setTimeout",
    "Math.random",
    "random.random",
    "rand::random",
    "sleep",
];

/// Analyzer that detects test functions referencing time or randomness.
#[derive(Debug, Default)]
pub struct FlakyTimeAnalyzer;

impl Analyzer for FlakyTimeAnalyzer {
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

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let source = file.source();
        let src_str = source.as_str();
        let index = file.index();
        let mut findings = Vec::new();

        for func in &index.functions {
            if !func.is_test {
                continue;
            }

            let body_start = func.body_span.start.0 as usize;
            let body_end = func.body_span.end.0 as usize;
            let body_end = body_end.min(src_str.len());

            if body_start >= src_str.len() || body_start > body_end {
                continue;
            }

            let body_slice = &src_str[body_start..body_end];
            let name = func.name.as_deref().unwrap_or("<anonymous>");

            // Collect unique token matches, deduped per function.
            let mut seen: HashSet<&str> = HashSet::new();
            for &token in FLAKY_TOKENS {
                if body_slice.contains(token) && seen.insert(token) {
                    let span = Span::new(func.span.start, func.span.start);
                    let (start_lc, end_lc) = source.span_to_linecols(span);

                    findings.push(Finding {
                        analyzer: AnalyzerId::new(RULE_ID),
                        dimension: Dimension::TestSmell,
                        rule_id: RULE_ID.to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "test function `{name}` uses `{token}`, which can cause flaky results"
                        ),
                        location: Location {
                            file: source.path.clone(),
                            span,
                            start: start_lc,
                            end: end_lc,
                        },
                        suggestion: Some(
                            "Avoid time/randomness in tests; use dependency injection, \
                             fixed seeds, or a test-clock abstraction instead."
                                .to_string(),
                        ),
                        references: vec![],
                        cwe: META.cwe_vec(),
                        owasp: META.owasp_vec(),
                    });
                }
            }
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
    fn rust_flaky_time_positive() {
        let source = include_str!("../../../fixtures/rust/flaky_time/lib.rs");
        let file = rust_parse("fixtures/rust/flaky_time/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FlakyTimeAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 TEST004 finding for flaky_time Rust fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings should have a suggestion"
        );
    }

    // ── Rust negative ─────────────────────────────────────────────────────────

    #[test]
    fn rust_not_flaky_time_negative() {
        let source = include_str!("../../../fixtures/rust/not_flaky_time/lib.rs");
        let file = rust_parse("fixtures/rust/not_flaky_time/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FlakyTimeAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST004 findings for not_flaky_time Rust fixture, got {findings:#?}"
        );
    }

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_flaky_time_positive() {
        let source = include_str!("../../../fixtures/python/flaky_time/main.py");
        let file = python_parse("fixtures/python/flaky_time/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FlakyTimeAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 TEST004 finding for flaky_time Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Python negative ───────────────────────────────────────────────────────

    #[test]
    fn python_not_flaky_time_negative() {
        let source = include_str!("../../../fixtures/python/not_flaky_time/main.py");
        let file = python_parse("fixtures/python/not_flaky_time/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FlakyTimeAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST004 findings for not_flaky_time Python fixture, got {findings:#?}"
        );
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_flaky_time_positive() {
        let source = include_str!("../../../fixtures/js/flaky_time/main.ts");
        let file = js_parse("fixtures/js/flaky_time/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FlakyTimeAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 TEST004 finding for flaky_time JS fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── JS negative ───────────────────────────────────────────────────────────

    #[test]
    fn js_not_flaky_time_negative() {
        let source = include_str!("../../../fixtures/js/not_flaky_time/main.ts");
        let file = js_parse("fixtures/js/not_flaky_time/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FlakyTimeAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST004 findings for not_flaky_time JS fixture, got {findings:#?}"
        );
    }
}
