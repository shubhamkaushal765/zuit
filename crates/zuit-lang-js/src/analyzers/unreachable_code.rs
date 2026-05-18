//! `MAINT016-unreachable-code` — flags statements that appear after a
//! terminating statement in the same block (JavaScript/TypeScript).
//!
//! # Detection
//!
//! Reads the pre-extracted `JsAst::unreachable_stmts` populated at parse
//! time by the walker.  For each function body and block statement, the walker
//! records the byte span of the **first** dead statement that follows a
//! terminator.
//!
//! # Terminating statements (JS/TS)
//!
//! - `return …;` / `return;`
//! - `throw expr;`
//! - `break;` / `break label;`
//! - `continue;` / `continue label;`
//!
//! # Scope
//!
//! The rule fires only within a single flat block.  Dead code after
//! `if (cond) { return; }` in the *outer* block is not flagged (reachable
//! when `cond` is false).  Nested function bodies are walked by the walker,
//! so inner-function dead code emits separate findings.
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
/// a terminating statement in the same JS/TS block.
pub struct JsUnreachableCodeAnalyzer;

impl zuit_core::Analyzer for JsUnreachableCodeAnalyzer {
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
                         `return`, `throw`, `break`, or `continue` precedes it in the same block."
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
    use crate::parse as js_parse;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, LanguageId, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.ts", src.as_bytes().to_vec()));
        let parsed = js_parse::parse(source).expect("parse failed");
        let analyzer = JsUnreachableCodeAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_stmt_after_return() {
        let src = "function f() { return 1; const x = 2; }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn flags_stmt_after_throw() {
        let src = "function f() { throw new Error('x'); console.log(1); }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_stmt_after_break_in_loop() {
        let src = "function f() { for (;;) { break; console.log(1); } }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn typescript_variant_works() {
        // TypeScript function declaration parsed the same way.
        let src = "function f(x: number): number { return x; const y: number = 2; }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn no_finding_when_return_in_if_block() {
        // `if (cond) { return; } x;` → 0 findings (outer block reachable when cond false)
        let src = "function f(cond) { if (cond) { return; } const x = 1; }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "return inside if-block should not flag outer stmt, got: {findings:#?}"
        );
    }

    #[test]
    fn no_finding_when_no_dead_code() {
        let src = "function f() { const x = 1; return x + 1; }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "no dead code → 0 findings, got: {findings:#?}"
        );
    }

    #[test]
    fn supported_languages_is_javascript_only() {
        let analyzer = JsUnreachableCodeAnalyzer;
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
        assert!(!analyzer.supported_languages().supports(LanguageId("rust")));
    }
}
