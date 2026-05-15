//! `MAINT004-file-length` — flags files whose total line count exceeds
//! a configurable threshold.
//!
//! The line count is obtained from `SourceFile::line_count()`, and the finding
//! location spans the entire file from byte 0 to the end.

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages,
    span::{ByteOffset, Location, Span},
};

/// Rule ID for the file-length check.
pub const RULE_ID: &str = "MAINT004-file-length";

/// Default file length threshold; files at or below this line count
/// are not flagged.
const DEFAULT_THRESHOLD: u32 = 600;

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/MAINT004-file-length.md",
    cwe: &["CWE-1080"],
    owasp: &[],
};

/// Analyzer that flags files exceeding the line-count threshold.
///
/// The threshold is read from `[rules.MAINT004-file-length] threshold` in
/// `zuit.toml`; the default is 600 lines.
#[derive(Debug, Default)]
pub struct FileLengthAnalyzer;

impl Analyzer for FileLengthAnalyzer {
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
        let line_count = source.line_count();

        if line_count > threshold {
            let total_bytes = source.len();
            let span = Span::new(
                ByteOffset(0),
                ByteOffset(u32::try_from(total_bytes).unwrap_or(u32::MAX)),
            );
            let (start_lc, end_lc) = source.span_to_linecols(span);

            vec![Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Maintainability,
                rule_id: RULE_ID.to_string(),
                severity: Severity::Low,
                message: format!("file has {line_count} lines (threshold {threshold})"),
                location: Location {
                    file: source.path.clone(),
                    span,
                    start: start_lc,
                    end: end_lc,
                },
                suggestion: Some(
                    "Consider splitting this file into smaller, more focused modules.".to_string(),
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
    use proptest::prelude::*;
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

    fn make_ctx(config: &Config) -> AnalysisContext<'_> {
        AnalysisContext::new(config)
    }

    // ── Rust positive: long_file fixture should produce 1 finding ──────────

    #[test]
    fn rust_long_file_positive() {
        let source = include_str!("../../../fixtures/rust/long_file/lib.rs");
        let file = rust_parse("fixtures/rust/long_file/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FileLengthAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 MAINT004 finding for long Rust fixture"
        );
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 finding for long file"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Rust negative: healthy fixture should produce 0 findings ─────────────

    #[test]
    fn rust_healthy_file_negative() {
        let source = include_str!("../../../fixtures/rust/healthy/lib.rs");
        let file = rust_parse("fixtures/rust/healthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FileLengthAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT004 findings for healthy Rust fixture, got {findings:#?}"
        );
    }

    // ── Python positive: long_file fixture should produce 1 finding ────────

    #[test]
    fn python_long_file_positive() {
        let source = include_str!("../../../fixtures/python/long_file/main.py");
        let file = python_parse("fixtures/python/long_file/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FileLengthAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 MAINT004 finding for long Python fixture"
        );
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 finding for long file"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Python negative: healthy fixture should produce 0 findings ───────────

    #[test]
    fn python_healthy_file_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = FileLengthAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT004 findings for healthy Python fixture, got {findings:#?}"
        );
    }

    // ── property tests ────────────────────────────────────────────────────────
    //
    // Properties that must hold for any generated source, regardless of the
    // exact line content.  Cases are kept at 50 to stay fast in CI.

    /// Build a Rust `ParsedFile` from a synthesised source consisting of
    /// `line_count` trivial lines.
    fn rust_file_from_lines(line_count: usize) -> ParsedFile {
        // Each line is a valid (if trivial) Rust comment so that syn can parse
        // the source without errors.
        let source = "// line\n".repeat(line_count);
        rust_parse("generated.rs", &source)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        /// For any source whose line count is strictly less than the threshold,
        /// `FileLengthAnalyzer` must emit no finding.
        #[test]
        fn no_finding_when_lines_below_threshold(
            // Generate a line count in [0, DEFAULT_THRESHOLD).
            line_count in 0usize..DEFAULT_THRESHOLD as usize,
        ) {
            let file = rust_file_from_lines(line_count);
            let config = Config::default();
            let ctx = make_ctx(&config);
            let findings = FileLengthAnalyzer.analyze_file(&ctx, &file);
            prop_assert!(
                findings.is_empty(),
                "expected no finding for {line_count} lines (threshold {}), got {:?}",
                DEFAULT_THRESHOLD, findings,
            );
        }

        /// For any source whose line count strictly exceeds the threshold,
        /// `FileLengthAnalyzer` must emit exactly one finding with rule_id
        /// `MAINT004-file-length`.
        #[test]
        fn exactly_one_finding_when_lines_above_threshold(
            // Generate a line count in (DEFAULT_THRESHOLD, DEFAULT_THRESHOLD + 300].
            extra in 1usize..=300,
        ) {
            let line_count = DEFAULT_THRESHOLD as usize + extra;
            let file = rust_file_from_lines(line_count);
            let config = Config::default();
            let ctx = make_ctx(&config);
            let findings = FileLengthAnalyzer.analyze_file(&ctx, &file);
            prop_assert_eq!(
                findings.len(), 1,
                "expected exactly 1 finding for {} lines (threshold {}), got {:?}",
                line_count, DEFAULT_THRESHOLD, findings,
            );
            prop_assert_eq!(
                findings[0].rule_id.as_str(), RULE_ID,
                "finding rule_id must be {}",
                RULE_ID,
            );
        }

        /// The finding's span must start at byte 0 and cover the whole file:
        /// `span.start == 0` and `span.end == source_len`.
        #[test]
        fn finding_span_covers_whole_file(
            extra in 1usize..=100,
        ) {
            let line_count = DEFAULT_THRESHOLD as usize + extra;
            let source = "// line\n".repeat(line_count);
            let file = rust_parse("generated.rs", &source);
            let config = Config::default();
            let ctx = make_ctx(&config);
            let findings = FileLengthAnalyzer.analyze_file(&ctx, &file);
            prop_assert_eq!(findings.len(), 1);
            let span = findings[0].location.span;
            prop_assert_eq!(span.start.0, 0, "span must start at byte 0");
            prop_assert_eq!(
                span.end.0 as usize, source.len(),
                "span.end must equal source length {}",
                source.len(),
            );
        }
    }
}
