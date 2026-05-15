//! `MAINT006-too-many-params` — flags functions/methods with too many parameters.
//!
//! The parameter count is taken directly from the `SemanticIndex`; the analyzer
//! never re-walks the native AST.  Functions with more parameters than the
//! configured threshold are flagged.

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages, span::Location,
};

/// Rule ID for the too-many-params check.
pub const RULE_ID: &str = "MAINT006-too-many-params";

/// Default parameter count threshold; functions with at most this many
/// parameters are not flagged.
const DEFAULT_THRESHOLD: u32 = 5;

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/MAINT006-too-many-params.md",
    cwe: &["CWE-1121"],
    owasp: &[],
};

/// Analyzer that flags functions/methods with more parameters than the threshold.
///
/// Construct with [`TooManyParamsAnalyzer::new`] (default threshold of 5) or
/// [`TooManyParamsAnalyzer::with_threshold`] to use a custom limit.  The
/// threshold may also be overridden project-wide via
/// `[rules.MAINT006-too-many-params] threshold` in `zuit.toml`; when both
/// are set, the `zuit.toml` value wins.
#[derive(Debug)]
pub struct TooManyParamsAnalyzer {
    threshold: u32,
}

impl TooManyParamsAnalyzer {
    /// Creates a new `TooManyParamsAnalyzer` with the default threshold of 5.
    #[must_use]
    pub fn new() -> Self {
        Self {
            threshold: DEFAULT_THRESHOLD,
        }
    }

    /// Creates a new `TooManyParamsAnalyzer` with the given threshold.
    ///
    /// Functions whose parameter count **strictly exceeds** `threshold` are
    /// flagged.
    #[must_use]
    pub fn with_threshold(threshold: u32) -> Self {
        Self { threshold }
    }
}

impl Default for TooManyParamsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for TooManyParamsAnalyzer {
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
        let threshold = ctx.config.rule_threshold(RULE_ID, self.threshold);
        let source = file.source();
        let index = file.index();

        index
            .functions
            .iter()
            .filter_map(|f| {
                if f.param_count > threshold {
                    let name = f.name.as_deref().unwrap_or("<anonymous>");
                    let span = f.span;
                    let (start_lc, end_lc) = source.span_to_linecols(span);
                    let message = if f.name.is_some() {
                        format!(
                            "function `{name}` has {count} parameters (threshold: {threshold})",
                            count = f.param_count,
                        )
                    } else {
                        format!(
                            "<anonymous> function has {count} parameters (threshold: {threshold})",
                            count = f.param_count,
                        )
                    };
                    Some(Finding {
                        analyzer: AnalyzerId::new(RULE_ID),
                        dimension: Dimension::Maintainability,
                        rule_id: RULE_ID.to_string(),
                        severity: Severity::Low,
                        message,
                        location: Location {
                            file: source.path.clone(),
                            span,
                            start: start_lc,
                            end: end_lc,
                        },
                        suggestion: Some(
                            "Consider grouping related parameters into a dedicated struct or builder."
                                .to_string(),
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

    // ── Rust positive: function with 6 params triggers ────────────────────────

    #[test]
    fn rust_too_many_params_positive() {
        let source = r"
pub fn many_params(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> i32 {
    a + b + c + d + e + f
}
";
        let file = rust_parse("src/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = TooManyParamsAnalyzer::new().analyze_file(&ctx, &file);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 MAINT006 finding for 6-param Rust function, got {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert!(
            findings[0].message.contains("many_params"),
            "message should mention function name; got: {}",
            findings[0].message
        );
        assert!(
            findings[0].message.contains('6'),
            "message should mention param count; got: {}",
            findings[0].message
        );
    }

    // ── Rust negative: function with 5 params does NOT trigger at default threshold

    #[test]
    fn rust_at_threshold_negative() {
        let source = r"
pub fn five_params(a: i32, b: i32, c: i32, d: i32, e: i32) -> i32 {
    a + b + c + d + e
}
";
        let file = rust_parse("src/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = TooManyParamsAnalyzer::new().analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT006 findings for 5-param Rust function (at threshold), got {findings:#?}"
        );
    }

    // ── Rust negative: healthy fixture produces 0 findings ────────────────────

    #[test]
    fn rust_healthy_negative() {
        let source = include_str!("../../../fixtures/rust/healthy/lib.rs");
        let file = rust_parse("fixtures/rust/healthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = TooManyParamsAnalyzer::new().analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT006 findings for healthy Rust fixture, got {findings:#?}"
        );
    }

    // ── Python positive: function with 7 params triggers ─────────────────────

    #[test]
    fn python_too_many_params_positive() {
        let source = r"
def many_params(a, b, c, d, e, f, g):
    return a + b + c + d + e + f + g
";
        let file = python_parse("main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = TooManyParamsAnalyzer::new().analyze_file(&ctx, &file);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 MAINT006 finding for 7-param Python function, got {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert!(
            findings[0].message.contains("many_params"),
            "message should mention function name; got: {}",
            findings[0].message
        );
        assert!(
            findings[0].message.contains('7'),
            "message should mention param count; got: {}",
            findings[0].message
        );
    }

    // ── Python negative: healthy fixture produces 0 findings ─────────────────

    #[test]
    fn python_healthy_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = TooManyParamsAnalyzer::new().analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT006 findings for healthy Python fixture, got {findings:#?}"
        );
    }

    // ── Configurable threshold: with_threshold(3) makes 4-param function trigger

    #[test]
    fn configurable_threshold_triggers() {
        let source = r"
pub fn four_params(a: i32, b: i32, c: i32, d: i32) -> i32 {
    a + b + c + d
}
";
        let file = rust_parse("src/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = TooManyParamsAnalyzer::with_threshold(3).analyze_file(&ctx, &file);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 MAINT006 finding for 4-param function with threshold=3, got {findings:#?}"
        );
        assert!(
            findings[0].message.contains("threshold: 3"),
            "message should mention threshold 3; got: {}",
            findings[0].message
        );
    }

    // ── Configurable threshold: with_threshold(3) does NOT flag 3-param function

    #[test]
    fn configurable_threshold_no_trigger_at_limit() {
        let source = r"
pub fn three_params(a: i32, b: i32, c: i32) -> i32 {
    a + b + c
}
";
        let file = rust_parse("src/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = TooManyParamsAnalyzer::with_threshold(3).analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 findings for 3-param function with threshold=3, got {findings:#?}"
        );
    }

    // ── JS/TS positive: function with 6 params triggers ───────────────────────

    #[test]
    fn js_too_many_params_positive() {
        let source = r"
export function manyParams(a: number, b: number, c: number, d: number, e: number, f: number): number {
    return a + b + c + d + e + f;
}
";
        let file = js_parse("main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = TooManyParamsAnalyzer::new().analyze_file(&ctx, &file);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 MAINT006 finding for 6-param JS function, got {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert!(
            findings[0].message.contains("manyParams"),
            "message should mention function name; got: {}",
            findings[0].message
        );
    }

    // ── JS/TS arrow function positive: arrow with 6 params triggers ───────────

    #[test]
    fn js_arrow_fn_too_many_params_positive() {
        let source = r"
const manyArrow = (a: number, b: number, c: number, d: number, e: number, f: number): number => {
    return a + b + c + d + e + f;
};
";
        let file = js_parse("main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = TooManyParamsAnalyzer::new().analyze_file(&ctx, &file);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 MAINT006 finding for 6-param arrow function, got {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── Emits exactly one finding per offending function ──────────────────────

    #[test]
    fn one_finding_per_offending_function() {
        let source = r"
pub fn many_a(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> i32 { a }
pub fn many_b(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> i32 { a }
pub fn ok_fn(a: i32, b: i32) -> i32 { a }
";
        let file = rust_parse("src/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = TooManyParamsAnalyzer::new().analyze_file(&ctx, &file);
        assert_eq!(
            findings.len(),
            2,
            "expected exactly 2 MAINT006 findings (one per offending function), got {findings:#?}"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }
}
