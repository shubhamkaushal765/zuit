//! `MAINT010-infinite-loop-no-exit` — flags unconditional `loop {}` bodies that
//! contain no reachable exit (`break`, `return`, `panic!`, `unreachable!`,
//! `todo!`, `unimplemented!`) at the same loop nesting depth.
//!
//! # Detection
//!
//! Reads the pre-extracted `RustAst::infinite_loops` populated
//! at parse time by the `Extractor` visitor.  Each span represents a `loop`
//! keyword whose body, after excluding nested loops and closures, contains no
//! `break`, `return`, or exit macro.

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

/// Analyzer that emits `MAINT010-infinite-loop-no-exit` for `loop {}` bodies
/// with no exit path in Rust source files.
pub struct InfiniteLoopNoExitAnalyzer;

impl zuit_core::Analyzer for InfiniteLoopNoExitAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Maintainability
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::Only(smallvec![LanguageId("rust")])
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let Some(ast) = crate::try_rust_ast(file) else {
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
                    message: "`loop` has no reachable exit (`break`, `return`, or \
                              diverging call); this will spin forever (CWE-835)"
                        .to_string(),
                    location: Location {
                        file: file_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Add a `break` or `return` inside the loop body, or use a \
                         condition to control termination. If the loop is intentionally \
                         infinite (e.g. an event loop), add a comment explaining why."
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
    use crate::parse as rust_parse;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, LanguageId, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.rs", src.as_bytes().to_vec()));
        let parsed = rust_parse::parse(source).expect("parse failed");
        let analyzer = InfiniteLoopNoExitAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests (must fire) ────────────────────────────────────────────

    #[test]
    fn flags_pure_increment_loop() {
        let src = "fn f() { let mut x = 0i32; loop { x += 1; } }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn flags_loop_with_function_call_no_exit() {
        let src = "fn foo() -> i32 { 42 } fn f() { loop { let _ = foo(); } }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_outer_loop_when_inner_loop_has_break() {
        // inner break belongs to inner loop; outer loop is still infinite
        let src = "fn f() { loop { loop { break; } } }";
        let findings = analyze(src);
        // The outer loop has no exit, so it should fire.
        // The inner loop has a break, so it should NOT fire.
        let outer_fires = findings.iter().any(|f| f.rule_id == RULE_ID);
        assert!(
            outer_fires,
            "outer loop with no exit should fire; got: {findings:#?}"
        );
        // The inner loop has a break — it must NOT produce a finding.
        // Since inner loop fires only if it has no exit, and it has `break`,
        // the total should be exactly 1 (only the outer).
        assert_eq!(
            findings.len(),
            1,
            "only outer loop should fire (inner has break); got: {findings:#?}"
        );
    }

    #[test]
    fn flags_outer_loop_when_for_loop_has_break_inside() {
        // for-loop break does not exit the enclosing `loop`
        let src = "fn f() { loop { for _ in 0..10 { break; } } }";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "outer loop with no exit should fire; got: {findings:#?}"
        );
    }

    #[test]
    fn flags_loop_with_closure_returning() {
        // closure's `return` does not exit the enclosing loop
        let src = "fn f() { loop { let _g = || { return 1i32; }; } }";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "closure return should not count as loop exit; got: {findings:#?}"
        );
    }

    // ── negative tests (must NOT fire) ────────────────────────────────────────

    #[test]
    fn does_not_flag_loop_with_break() {
        let src = "fn f(x: bool) { loop { if x { break; } } }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "loop with break should not fire; got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_loop_with_return() {
        let src = "fn f() { loop { return; } }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "loop with return should not fire; got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_loop_with_panic() {
        let src = r#"fn f() { loop { panic!("done"); } }"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "loop with panic! should not fire; got: {findings:#?}"
        );
    }

    // ── CWE tag check ─────────────────────────────────────────────────────────

    #[test]
    fn cwe_tag_is_cwe_835() {
        let src = "fn f() { loop { let _ = 1; } }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].cwe.iter().any(|c| c == "CWE-835"),
            "expected CWE-835 in finding.cwe, got: {:?}",
            findings[0].cwe
        );
    }

    #[test]
    fn supported_languages_is_rust_only() {
        let analyzer = InfiniteLoopNoExitAnalyzer;
        assert!(analyzer.supported_languages().supports(LanguageId("rust")));
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
    }
}
