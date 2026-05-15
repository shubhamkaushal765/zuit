//! `MAINT002-cognitive` — flags functions whose cognitive complexity exceeds
//! a configurable threshold.
//!
//! The complexity value is taken directly from the `SemanticIndex`; the
//! analyzer never re-walks the native AST.
//!
//! Cognitive complexity uses the Sonar variant, which differs from cyclomatic
//! complexity by adding a **nesting penalty**: a control-flow construct that is
//! already inside another adds an extra +1 per nesting level.  This makes the
//! metric a better proxy for human understandability than the raw path count.
//! The per-language counting rules are documented in the module-level docs of
//! each frontend:
//!
//! - Rust: [`zuit_lang_rust::complexity`](../../../zuit-lang-rust/src/complexity.rs)
//! - Python: [`zuit_lang_python::complexity`](../../../zuit-lang-python/src/complexity.rs)
//! - JS/TS: [`zuit_lang_js::complexity`](../../../zuit-lang-js/src/complexity.rs)

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages, span::Location,
};

/// Rule ID for the cognitive-complexity check.
pub const RULE_ID: &str = "MAINT002-cognitive";

/// Default cognitive complexity threshold; functions at or below this value
/// are not flagged.
const DEFAULT_THRESHOLD: u32 = 15;

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/MAINT002-cognitive.md",
    cwe: &["CWE-1121"],
    owasp: &[],
};

/// Analyzer that flags functions exceeding the cognitive complexity threshold.
///
/// The threshold is read from `[rules.MAINT002-cognitive] threshold` in
/// `zuit.toml`; the default is 15.
#[derive(Debug, Default)]
pub struct CognitiveAnalyzer;

impl Analyzer for CognitiveAnalyzer {
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
            .filter(|f| f.complexity.cognitive > threshold)
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
                        "function `{name}` has cognitive complexity {} (threshold {threshold})",
                        f.complexity.cognitive,
                    ),
                    location: Location {
                        file: source.path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Reduce nesting depth by extracting helper functions or \
                         applying early-return / guard-clause patterns."
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

    // ── Rust positive: cognitive fixture has a function with cognitive > 15 ──

    #[test]
    fn rust_cognitive_positive() {
        let source = include_str!("../../../fixtures/rust/cognitive/lib.rs");
        let file = rust_parse("fixtures/rust/cognitive/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CognitiveAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 MAINT002 finding for cognitive Rust fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings
                .iter()
                .all(|f| f.cwe.iter().any(|c| c == "CWE-1121")),
            "expected CWE-1121 in finding.cwe"
        );
    }

    // ── Rust negative: healthy fixture produces 0 findings ───────────────────

    #[test]
    fn rust_healthy_cognitive_negative() {
        let source = include_str!("../../../fixtures/rust/healthy/lib.rs");
        let file = rust_parse("fixtures/rust/healthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CognitiveAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT002 findings for healthy Rust fixture, got {findings:#?}"
        );
    }

    // ── Python positive: cognitive fixture has a function with cognitive > 15 ─

    #[test]
    fn python_cognitive_positive() {
        let source = include_str!("../../../fixtures/python/cognitive/main.py");
        let file = python_parse("fixtures/python/cognitive/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CognitiveAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 MAINT002 finding for cognitive Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Python negative: healthy fixture produces 0 findings ─────────────────

    #[test]
    fn python_healthy_cognitive_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CognitiveAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT002 findings for healthy Python fixture, got {findings:#?}"
        );
    }

    // ── JS positive: cognitive fixture has a function with cognitive > 15 ────

    #[test]
    fn js_cognitive_positive() {
        let source = include_str!("../../../fixtures/js/cognitive/main.ts");
        let file = js_parse("fixtures/js/cognitive/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CognitiveAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 MAINT002 finding for cognitive JS fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── JS negative: healthy fixture produces 0 findings ─────────────────────

    #[test]
    fn js_healthy_cognitive_negative() {
        let source = include_str!("../../../fixtures/js/healthy/main.ts");
        let file = js_parse("fixtures/js/healthy/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CognitiveAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT002 findings for healthy JS fixture, got {findings:#?}"
        );
    }
}
