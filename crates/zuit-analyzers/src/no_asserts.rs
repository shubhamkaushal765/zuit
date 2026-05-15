//! `TEST002-no-asserts` — flags test files that contain no detected assertions.
//!
//! A file is examined only if it contains at least one function with
//! `is_test = true` in the [`zuit_core::SemanticIndex`]. If it has test
//! functions but the raw source contains no assertion token matching the
//! combined assertion regex, a single finding spanning the whole file is
//! emitted.
//!
//! ## Recognised assertion tokens
//!
//! The regex covers assertion idioms from Python, Rust, and JavaScript/TypeScript:
//!
//! | Token | Language |
//! |---|---|
//! | `assert` | Python built-in, generic |
//! | `assert_eq!` | Rust macro |
//! | `assert_ne!` | Rust macro |
//! | `panic!` | Rust macro |
//! | `assertEqual` | Python `unittest` |
//! | `assertTrue` | Python `unittest` |
//! | `assertFalse` | Python `unittest` |
//! | `assertIn` | Python `unittest` |
//! | `assertIs` | Python `unittest` |
//! | `expect` | Jest / Chai / generic |
//! | `should.` | Chai `should`-style |
//! | `chai.expect` | Chai explicit |
//! | `sinon.assert` | Sinon.JS |
//! | `jest.` | Jest utilities |

use std::sync::OnceLock;

use regex::Regex;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages,
    span::{ByteOffset, Location, Span},
};

/// Rule ID for the no-asserts check.
pub const RULE_ID: &str = "TEST002-no-asserts";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/TEST002-no-asserts.md",
    cwe: &[],
    owasp: &[],
};

/// Returns the compiled regex that matches any known assertion token.
///
/// The alternation is ordered from most-specific (multi-character tokens that
/// would otherwise partially match a shorter alternative) to least-specific.
fn assertion_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(
            r"(?:assert(?:_eq|_ne)?!|panic!|assertEqual|assertTrue|assertFalse|assertIn|assertIs\b|chai\.expect|sinon\.assert|jest\.|should\.|expect\b|assert\b)",
        )
        .expect("invariant: assertion pattern is valid")
    })
}

/// Analyzer that detects test files containing no assertion tokens.
#[derive(Debug, Default)]
pub struct NoAssertsAnalyzer;

impl Analyzer for NoAssertsAnalyzer {
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
        let index = file.index();

        // Only examine files that contain at least one test function.
        if !index.functions.iter().any(|f| f.is_test) {
            return vec![];
        }

        let source = file.source();
        let src_str = source.as_str();

        // If any assertion token appears anywhere in the source, the file is fine.
        if assertion_pattern().is_match(src_str) {
            return vec![];
        }

        // No assertions found: emit one file-spanning finding.
        let total_bytes = source.len();
        let span = Span::new(
            ByteOffset(0),
            ByteOffset(u32::try_from(total_bytes).unwrap_or(u32::MAX)),
        );
        let (start_lc, end_lc) = source.span_to_linecols(span);

        vec![Finding {
            analyzer: AnalyzerId::new(RULE_ID),
            dimension: Dimension::TestSmell,
            rule_id: RULE_ID.to_string(),
            severity: Severity::Medium,
            message: "test file contains no detected assertions".to_string(),
            location: Location {
                file: source.path.clone(),
                span,
                start: start_lc,
                end: end_lc,
            },
            suggestion: Some(
                "Add at least one explicit assertion (assert / expect / assertEqual / etc.) \
                 so failures are visible in the test runner."
                    .to_string(),
            ),
            references: vec![],
            cwe: META.cwe_vec(),
            owasp: META.owasp_vec(),
        }]
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

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_no_asserts_positive() {
        let source = include_str!("../../../fixtures/python/no_asserts/main.py");
        let file = python_parse("fixtures/python/no_asserts/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = NoAssertsAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 TEST002 finding for no_asserts Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Python negative (with_asserts) ────────────────────────────────────────

    #[test]
    fn python_with_asserts_negative() {
        let source = include_str!("../../../fixtures/python/with_asserts/main.py");
        let file = python_parse("fixtures/python/with_asserts/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = NoAssertsAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST002 findings for with_asserts Python fixture, got {findings:#?}"
        );
    }

    // ── Python negative (healthy — no test functions) ─────────────────────────

    #[test]
    fn python_healthy_no_asserts_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = NoAssertsAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST002 findings for healthy Python fixture (no test fns), got {findings:#?}"
        );
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_no_asserts_positive() {
        let source = include_str!("../../../fixtures/js/no_asserts/main.ts");
        let file = js_parse("fixtures/js/no_asserts/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = NoAssertsAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 TEST002 finding for no_asserts JS fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── JS negative (with_asserts) ────────────────────────────────────────────

    #[test]
    fn js_with_asserts_negative() {
        let source = include_str!("../../../fixtures/js/with_asserts/main.ts");
        let file = js_parse("fixtures/js/with_asserts/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = NoAssertsAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST002 findings for with_asserts JS fixture, got {findings:#?}"
        );
    }

    // ── JS negative (healthy — no test functions) ─────────────────────────────

    #[test]
    fn js_healthy_no_asserts_negative() {
        let source = include_str!("../../../fixtures/js/healthy/main.ts");
        let file = js_parse("fixtures/js/healthy/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = NoAssertsAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST002 findings for healthy JS fixture (no test fns), got {findings:#?}"
        );
    }

    // ── Rust positive ─────────────────────────────────────────────────────────

    #[test]
    fn rust_no_asserts_positive() {
        let source = include_str!("../../../fixtures/rust/no_asserts/lib.rs");
        let file = rust_parse("fixtures/rust/no_asserts/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = NoAssertsAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 TEST002 finding for no_asserts Rust fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Rust negative (with_asserts) ──────────────────────────────────────────

    #[test]
    fn rust_with_asserts_negative() {
        let source = include_str!("../../../fixtures/rust/with_asserts/lib.rs");
        let file = rust_parse("fixtures/rust/with_asserts/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = NoAssertsAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST002 findings for with_asserts Rust fixture, got {findings:#?}"
        );
    }

    // ── Rust negative (healthy — no test functions) ────────────────────────────

    #[test]
    fn rust_healthy_no_asserts_negative() {
        let source = include_str!("../../../fixtures/rust/healthy/lib.rs");
        let file = rust_parse("fixtures/rust/healthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = NoAssertsAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST002 findings for healthy Rust fixture (no test fns), got {findings:#?}"
        );
    }
}
