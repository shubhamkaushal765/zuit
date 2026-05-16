//! `MAINT010-infinite-loop-no-exit` — flags `while (true) {}` and `for (;;) {}`
//! loops whose body, recursively excluding nested loops and function bodies,
//! contains no `break`, `return`, `throw`, or call to `process.exit`.
//!
//! # Detection
//!
//! Reads the pre-extracted `JsAst::infinite_loops`
//! populated at parse time by the walker.  Each span represents a `while (true)`
//! or `for (;;)` keyword whose body has no exit path at the same nesting depth.

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

/// The stable rule ID.
const RULE_ID: &str = "MAINT010-infinite-loop-no-exit";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/MAINT010-infinite-loop-no-exit.md",
    cwe: &["CWE-835"],
    owasp: &[],
};

/// Analyzer that emits `MAINT010-infinite-loop-no-exit` for `while (true)` and
/// `for (;;)` loops with no exit path in JavaScript/TypeScript source files.
pub struct JsInfiniteLoopNoExitAnalyzer;

impl zuit_core::Analyzer for JsInfiniteLoopNoExitAnalyzer {
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

        ast.infinite_loops
            .iter()
            .map(|&span| {
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Maintainability,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::High,
                    message: "infinite loop (`while (true)` or `for (;;)`) has no reachable \
                              exit (`break`, `return`, `throw`, or `process.exit`); \
                              this will spin forever (CWE-835)"
                        .to_string(),
                    location: Location {
                        file: file_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Add a `break`, `return`, or `throw` inside the loop body. \
                         If the loop is intentionally infinite (e.g. a server event loop), \
                         add a comment explaining why."
                            .to_string(),
                    ),
                    references: vec!["https://cwe.mitre.org/data/definitions/835.html".to_string()],
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
        let analyzer = JsInfiniteLoopNoExitAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_while_true_no_exit() {
        let src = "while (true) { x++; }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn flags_for_forever_no_exit() {
        let src = "for (;;) { x++; }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_while_true_with_break() {
        let src = "while (true) { if (x) break; }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "while (true) with break should not fire; got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_while_true_with_return() {
        let src = "function f() { while (true) { return; } }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "while (true) with return should not fire; got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_for_forever_with_throw() {
        let src = r#"for (;;) { throw new Error("x"); }"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "for (;;) with throw should not fire; got: {findings:#?}"
        );
    }

    // ── CWE tag check ─────────────────────────────────────────────────────────

    #[test]
    fn cwe_tag_is_cwe_835() {
        let src = "while (true) { x++; }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].cwe.iter().any(|c| c == "CWE-835"),
            "expected CWE-835 in finding.cwe, got: {:?}",
            findings[0].cwe
        );
    }

    #[test]
    fn supported_languages_is_javascript_only() {
        let analyzer = JsInfiniteLoopNoExitAnalyzer;
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
