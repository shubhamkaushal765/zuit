//! `MAINT016-unreachable-code` — flags statements that appear after a
//! terminating statement in the same block (Rust).
//!
//! # Detection
//!
//! Reads the pre-extracted `RustAst::unreachable_stmts` populated at parse
//! time by the `Extractor` visitor.  For each block, the extractor records the
//! byte span of the **first** dead statement that follows a terminator; the
//! analyzer emits one finding per such span.
//!
//! # Terminating statements (Rust)
//!
//! - `return …;` / `return;`
//! - `break;` / `break 'label;`
//! - `continue;` / `continue 'label;`
//! - `panic!(…)`, `unreachable!(…)`, `todo!(…)`, `unimplemented!(…)`
//!
//! # Scope
//!
//! The rule fires only within a single `syn::Block`.  Dead code after an
//! `if { return; }` in the *outer* block is not flagged (because it is
//! reachable when the condition is false).  Nested blocks are walked
//! recursively by the extractor visitor, so an inner `{ return; x; }` does
//! emit a finding for `x;`.
//!
//! # CWE
//!
//! CWE-561 (Dead Code).

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

/// The stable rule ID.
const RULE_ID: &str = "MAINT016-unreachable-code";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/MAINT016-unreachable-code.md",
    cwe: &["CWE-561"],
    owasp: &[],
};

/// Analyzer that emits `MAINT016-unreachable-code` for statements that follow
/// a terminating statement in the same Rust block.
pub struct UnreachableCodeAnalyzer;

impl zuit_core::Analyzer for UnreachableCodeAnalyzer {
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

        ast.unreachable_stmts
            .iter()
            .map(|&span| {
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Maintainability,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Low,
                    message: "statement is unreachable (follows a terminating statement in the \
                               same block)"
                        .to_string(),
                    location: Location {
                        file: file_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Remove or relocate this statement; it can never be executed because a \
                         `return`, `break`, `continue`, or diverging macro precedes it in the \
                         same block."
                            .to_string(),
                    ),
                    references: vec!["https://cwe.mitre.org/data/definitions/561.html".to_string()],
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
        let analyzer = UnreachableCodeAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_stmt_after_return() {
        // `return; x;` → 1 finding pointing at `x;`
        let src = "fn f() -> i32 { return 1; let x = 2; x }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn flags_stmt_after_panic() {
        // `panic!(); x;` → 1 finding
        let src = r#"fn f() { panic!("oops"); let x = 1; }"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_stmt_after_todo() {
        // `todo!(); x;` → 1 finding
        let src = "fn f() -> i32 { todo!(); let x = 1; x }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_stmt_after_break_in_loop() {
        // `break; x;` inside `loop { … }` → 1 finding
        let src = "fn f() { loop { break; let x = 1; } }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn multiple_dead_stmts_emit_one_finding() {
        // Multiple dead stmts after `return` → still 1 finding (not 3).
        let src = "fn f() -> i32 { return 1; let a = 1; let b = 2; let c = 3; a + b + c }";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 finding, got: {findings:#?}"
        );
    }

    #[test]
    fn nested_block_dead_code_flagged() {
        // `{ return; x; } y;` → 1 finding (the `x;` in inner block). `y;` outside is reachable.
        let src = "fn f() { { return; let x = 1; } let y = 2; let _ = y; }";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for inner block dead code, got: {findings:#?}"
        );
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn no_finding_when_return_in_if_branch() {
        // `if cond { return; } x;` → 0 findings (the dead-code rule only fires
        // within the same block as the terminator; the outer block is reached
        // when `cond` is false).
        let src = "fn f(cond: bool) -> i32 { if cond { return 1; } let x = 2; x }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "return inside if-branch should not flag outer stmt, got: {findings:#?}"
        );
    }

    #[test]
    fn no_finding_when_no_dead_code() {
        let src = "fn f() -> i32 { let x = 1; x + 1 }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "no dead code → 0 findings, got: {findings:#?}"
        );
    }

    #[test]
    fn flags_stmt_after_unreachable_macro() {
        let src = "fn f() { unreachable!(); let x = 1; }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_stmt_after_unimplemented_macro() {
        let src = "fn f() -> i32 { unimplemented!(); let x = 1; x }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn supported_languages_is_rust_only() {
        let analyzer = UnreachableCodeAnalyzer;
        assert!(analyzer.supported_languages().supports(LanguageId("rust")));
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("javascript"))
        );
    }
}
