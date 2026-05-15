//! `TEST003-skipped` — detects skip markers for tests in source files.
//!
//! The raw source text is scanned line-by-line for well-known skip / ignore
//! decorators and pragmas across Rust, Python, and JavaScript/TypeScript. One
//! finding is emitted per match, located at the byte range of the matched line.
//!
//! ## Recognised markers
//!
//! | Language | Marker | Example |
//! |---|---|---|
//! | Rust | `#[ignore]` | `#[ignore]` |
//! | Rust | `#[ignore = "…"]` | `#[ignore = "not yet implemented"]` |
//! | Python | `@pytest.mark.skip` | `@pytest.mark.skip` |
//! | Python | `@unittest.skip` | `@unittest.skip` |
//! | Python | `@skip` | `@skip` |
//! | JavaScript | `it.skip(` | `it.skip("name", …)` |
//! | JavaScript | `describe.skip(` | `describe.skip("name", …)` |
//! | JavaScript | `xit(` | `xit("name", …)` |
//! | JavaScript | `xdescribe(` | `xdescribe("name", …)` |
//! | JavaScript | `test.skip(` | `test.skip("name", …)` |

use std::sync::OnceLock;

use regex::Regex;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages,
    span::{ByteOffset, LineCol, Location, Span},
};

/// Rule ID for the skipped-test check.
pub const RULE_ID: &str = "TEST003-skipped";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Info,
    doc_path: "docs/rules/TEST003-skipped.md",
    cwe: &[],
    owasp: &[],
};

/// Returns the compiled regex that matches any recognised skip / ignore marker
/// at the start of a line (after optional leading whitespace).
///
/// The `(?m)` flag makes `^` match at the start of each line rather than only
/// the start of the whole string, so a single `find_iter` pass over the whole
/// file source is sufficient.
fn skip_marker_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(
            r#"(?m)^\s*(?:#\[ignore(?:\s*(?:\([^)]*\)|=\s*"[^"]*"))?\]|@pytest\.mark\.skip\b|@unittest\.skip\b|@skip\b|it\.skip\(|describe\.skip\(|xit\(|xdescribe\(|test\.skip\()"#,
        )
        .expect("invariant: skip-marker pattern is valid")
    })
}

/// Extracts the first non-whitespace token from a matched slice for use in the
/// finding message.
///
/// For example, `"  #[ignore]"` → `"#[ignore]"`.
fn extract_token(matched: &str) -> &str {
    matched.trim()
}

/// Analyzer that detects skip / ignore markers in test source files.
#[derive(Debug, Default)]
pub struct SkippedAnalyzer;

impl Analyzer for SkippedAnalyzer {
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
        let regex = skip_marker_pattern();

        regex
            .find_iter(src_str)
            .map(|mat| {
                let token = extract_token(mat.as_str()).to_string();

                // Compute the byte span of the matched region (the whole
                // leading-whitespace + marker slice) and convert to LineCol.
                let start_offset = ByteOffset(u32::try_from(mat.start()).unwrap_or(u32::MAX));
                let end_offset = ByteOffset(u32::try_from(mat.end()).unwrap_or(u32::MAX));
                let span = Span::new(start_offset, end_offset);
                let start_lc: LineCol = source.offset_to_linecol(start_offset);
                let end_lc: LineCol = source.offset_to_linecol(end_offset);

                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::TestSmell,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Info,
                    message: format!("skipped or ignored test marker: {token}"),
                    location: Location {
                        file: source.path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Re-enable the test or delete it; \
                         long-lived skipped tests rot silently."
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

    // ── Python positive (≥ 2 markers) ─────────────────────────────────────────

    #[test]
    fn python_skipped_positive() {
        let source = include_str!("../../../fixtures/python/skipped/main.py");
        let file = python_parse("fixtures/python/skipped/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SkippedAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.len() >= 2,
            "expected ≥2 TEST003 findings for skipped Python fixture, got {}",
            findings.len()
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Python negative (healthy) ─────────────────────────────────────────────

    #[test]
    fn python_healthy_skipped_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SkippedAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST003 findings for healthy Python fixture, got {findings:#?}"
        );
    }

    // ── JS positive (≥ 2 markers) ─────────────────────────────────────────────

    #[test]
    fn js_skipped_positive() {
        let source = include_str!("../../../fixtures/js/skipped/main.ts");
        let file = js_parse("fixtures/js/skipped/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SkippedAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.len() >= 2,
            "expected ≥2 TEST003 findings for skipped JS fixture, got {}",
            findings.len()
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── JS negative (healthy) ─────────────────────────────────────────────────

    #[test]
    fn js_healthy_skipped_negative() {
        let source = include_str!("../../../fixtures/js/healthy/main.ts");
        let file = js_parse("fixtures/js/healthy/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SkippedAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST003 findings for healthy JS fixture, got {findings:#?}"
        );
    }

    // ── Rust positive (≥ 2 markers) ───────────────────────────────────────────

    #[test]
    fn rust_skipped_positive() {
        let source = include_str!("../../../fixtures/rust/skipped/lib.rs");
        let file = rust_parse("fixtures/rust/skipped/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SkippedAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.len() >= 2,
            "expected ≥2 TEST003 findings for skipped Rust fixture, got {}",
            findings.len()
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Rust negative (healthy) ───────────────────────────────────────────────

    #[test]
    fn rust_healthy_skipped_negative() {
        let source = include_str!("../../../fixtures/rust/healthy/lib.rs");
        let file = rust_parse("fixtures/rust/healthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SkippedAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST003 findings for healthy Rust fixture, got {findings:#?}"
        );
    }
}
