//! `MAINT012-dead-store` — flags writes to local variables whose value is
//! never read before being overwritten or going out of scope (JavaScript/TypeScript).
//!
//! # Detection
//!
//! Reads the pre-extracted [`crate::native_ast::JsAst::dead_stores`] populated
//! at parse time by the walker.  Each site represents a variable declaration
//! or assignment whose name does not appear in any later identifier reference
//! in the same function scope.

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

/// The stable rule ID.
const RULE_ID: &str = "MAINT012-dead-store";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/MAINT012-dead-store.md",
    cwe: &["CWE-563"],
    owasp: &[],
};

/// Analyzer that emits `MAINT012-dead-store` for dead local variable writes
/// in JavaScript/TypeScript source files.
pub struct JsDeadStoreAnalyzer;

impl zuit_core::Analyzer for JsDeadStoreAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Maintainability
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::Only(smallvec![LanguageId("javascript")])
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let Some(ast) = crate::try_js_ast(file) else {
            return Vec::new();
        };

        let source = file.source();
        let file_path = source.path.clone();

        ast.dead_stores
            .iter()
            .map(|ds| {
                let (start_lc, end_lc) = source.span_to_linecols(ds.span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Maintainability,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Low,
                    message: format!(
                        "variable `{}` is written but its value is never read \
                         (dead store, CWE-563)",
                        ds.name
                    ),
                    location: Location {
                        file: file_path.clone(),
                        span: ds.span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Remove the assignment if the value is unused, or read it \
                         before it is overwritten. Prefix with `_` to silence this \
                         warning for intentionally unused variables."
                            .to_string(),
                    ),
                    references: vec!["https://cwe.mitre.org/data/definitions/563.html".to_string()],
                    cwe: META.cwe_vec(),
                    owasp: META.owasp_vec(),
                }
            })
            .collect()
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse as js_parse;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, LanguageId, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.ts", src.as_bytes().to_vec()));
        let parsed = js_parse::parse(source).expect("parse failed");
        let analyzer = JsDeadStoreAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_overwritten_before_read() {
        // First `x = 1` is dead: overwritten by `x = 2` without read.
        let src = "function f() { let x = 1; x = 2; return x; }";
        let findings = analyze(src);
        assert!(
            !findings.is_empty(),
            "expected ≥1 finding; got: {findings:#?}"
        );
        assert!(
            findings.iter().any(|f| f.rule_id == RULE_ID),
            "expected MAINT012 finding; got: {findings:#?}"
        );
    }

    #[test]
    fn flags_const_never_read() {
        let src = "function f() { const unused = 42; return null; }";
        let findings = analyze(src);
        assert!(
            !findings.is_empty(),
            "expected ≥1 finding; got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_when_read_after_write() {
        let src = "function f() { let x = 1; return x; }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "x is read — must not fire; got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_underscore_prefix() {
        let src = "function f() { let _x = 1; return null; }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "underscore-prefixed name must be skipped; got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_for_of_loop_var() {
        let src = "function f(arr) { for (let x of arr) { /* */ } }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "for-of loop var must be skipped; got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_destructure_when_used() {
        // Both `a` and `b` are used — must not flag.
        let src = "function f(obj) { const { a, b } = obj; return a + b; }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "destructure with both names used must not fire; got: {findings:#?}"
        );
    }

    // ── CWE tag check ─────────────────────────────────────────────────────────

    #[test]
    fn cwe_tag_is_cwe_563() {
        let src = "function f() { const unused = 42; return null; }";
        let findings = analyze(src);
        assert!(!findings.is_empty());
        assert!(
            findings[0].cwe.iter().any(|c| c == "CWE-563"),
            "expected CWE-563; got: {:?}",
            findings[0].cwe
        );
    }

    #[test]
    fn supported_languages_is_javascript_only() {
        let analyzer = JsDeadStoreAnalyzer;
        assert!(
            analyzer
                .supported_languages()
                .supports(LanguageId("javascript"))
        );
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
    }
}
