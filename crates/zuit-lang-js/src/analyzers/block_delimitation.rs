//! `STYLE001-block-delimitation` — flags ASI hazards where a `return`,
//! `continue`, or `break` without an argument/label is immediately followed
//! (exactly one newline) by a statement that silently becomes unreachable or
//! mis-parsed (CWE-483).

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

/// The stable rule ID.
const RULE_ID: &str = "STYLE001-block-delimitation";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/STYLE001-block-delimitation.md",
    cwe: &["CWE-483"],
    owasp: &[],
};

/// Analyzer that emits `STYLE001-block-delimitation` for JS/TS constructs
/// where ASI silently inserts a semicolon after `return`, `continue`, or
/// `break`, causing the following expression to be unreachable or mis-parsed.
pub struct JsBlockDelimitationAnalyzer;

impl zuit_core::Analyzer for JsBlockDelimitationAnalyzer {
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

        ast.asi_hazards
            .iter()
            .map(|site| {
                let span = site.span;
                let (start_lc, end_lc) = source.span_to_linecols(span);
                let (message, suggestion) = match site.kind {
                    crate::native_ast::JsAsiHazardKind::ReturnExpr => (
                        "ASI inserts `;` after `return`; the expression on the following line is \
                         unreachable. Move the expression onto the same line as `return`, or wrap \
                         it in parens starting on the `return` line."
                            .to_string(),
                        "Move the return value to the same line: `return value;`, or open a \
                         parenthesis on the `return` line: `return (\n  value\n);`."
                            .to_string(),
                    ),
                    crate::native_ast::JsAsiHazardKind::ContinueLabel => (
                        "ASI inserts `;` after `continue`; the identifier on the following line \
                         is discarded as an orphan expression. Move the label to the same line \
                         as `continue`."
                            .to_string(),
                        "Move the label to the same line: `continue label;`.".to_string(),
                    ),
                    crate::native_ast::JsAsiHazardKind::BreakLabel => (
                        "ASI inserts `;` after `break`; the identifier on the following line is \
                         discarded as an orphan expression. Move the label to the same line \
                         as `break`."
                            .to_string(),
                        "Move the label to the same line: `break label;`.".to_string(),
                    ),
                };
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Maintainability,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Medium,
                    message,
                    location: Location {
                        file: file_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(suggestion),
                    references: vec!["https://cwe.mitre.org/data/definitions/483.html".to_string()],
                    cwe: META.cwe_vec(),
                    owasp: META.owasp_vec(),
                }
            })
            .collect()
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(dead_code, unused_imports)]
mod tests {
    use super::*;
    use crate::parse as js_parse;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, LanguageId, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.ts", src.as_bytes().to_vec()));
        let parsed = js_parse::parse(source).expect("parse failed");
        let analyzer = JsBlockDelimitationAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests (RED state: stub returns empty Vec, so these FAIL) ─────

    #[test]
    fn flags_return_followed_by_expr() {
        let src = "function f() { return\n  v;\n}";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert!(
            findings[0].message.contains("return"),
            "message should mention 'return', got: {}",
            findings[0].message
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_return_followed_by_call_expr() {
        let src = "function f() { return\n  foo();\n}";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_return_followed_by_member_expr() {
        let src = "function f() { return\n  obj.x;\n}";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_return_followed_by_ts_as_cast() {
        let src = "function f() { return\n  x as Foo;\n}";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_continue_followed_by_identifier() {
        let src = "for (;;) { continue\n  label;\n}";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert!(
            findings[0].message.contains("continue"),
            "message should mention 'continue', got: {}",
            findings[0].message
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_break_followed_by_identifier() {
        let src = "for (;;) { break\n  label;\n}";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert!(
            findings[0].message.contains("break"),
            "message should mention 'break', got: {}",
            findings[0].message
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_inside_arrow_function() {
        let src = "const f = () => { return\n  v;\n};";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_inside_async_function() {
        let src = "async function f() { return\n  v;\n}";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── negative tests (already PASS in RED state: stub returns empty Vec) ─────

    #[test]
    fn no_flag_blank_line_between_return_and_expr() {
        // Two newlines between return and expr — blank line suppresses.
        let src = "function f() { return\n\n  v;\n}";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected 0 findings, got: {findings:#?}"
        );
    }

    #[test]
    fn no_flag_explicit_return_argument() {
        // return has an explicit argument — no ASI hazard.
        let src = "function f() { return v;\n  expr;\n}";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected 0 findings, got: {findings:#?}"
        );
    }

    #[test]
    fn no_flag_return_followed_by_var_decl() {
        // Next stmt is a VariableDeclaration — not an ExpressionStatement.
        let src = "function f() { return\n  var x = 1;\n}";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected 0 findings, got: {findings:#?}"
        );
    }

    #[test]
    fn no_flag_return_followed_by_return() {
        // Next stmt is a ReturnStatement — not an ExpressionStatement.
        let src = "function f() { return\n  return 1;\n}";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected 0 findings, got: {findings:#?}"
        );
    }

    #[test]
    fn no_flag_return_as_last_stmt() {
        // return is the last statement in its block — no following stmt.
        let src = "function f() { return\n}";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected 0 findings, got: {findings:#?}"
        );
    }

    #[test]
    fn no_flag_continue_with_explicit_label() {
        // continue already has an explicit label — no ASI hazard.
        let src = "for (;;) { continue outer;\n  expr;\n}";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected 0 findings, got: {findings:#?}"
        );
    }

    #[test]
    fn no_flag_continue_followed_by_call() {
        // Next stmt is CallExpression, not Identifier — carve-out (P2).
        let src = "for (;;) { continue\n  foo();\n}";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected 0 findings, got: {findings:#?}"
        );
    }

    #[test]
    fn no_flag_comment_intervening_known_limit() {
        // Comment between return and expr counts as >=2 newlines — suppressed.
        let src = "function f() { return\n  // hint\n  v;\n}";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected 0 findings, got: {findings:#?}"
        );
    }
}

// ── adversarial tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use crate::parse as js_parse;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.ts", src.as_bytes().to_vec()));
        let parsed = js_parse::parse(source).expect("parse failed");
        let analyzer = JsBlockDelimitationAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    fn analyze_tsx(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.tsx", src.as_bytes().to_vec()));
        let parsed = js_parse::parse(source).expect("parse failed");
        let analyzer = JsBlockDelimitationAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── A1: CRLF line endings ─────────────────────────────────────────────────
    // \r\n counts as one newline (the \n is counted; \r is transparent).
    // Positive test — expected to FAIL in RED state.
    #[test]
    fn adversarial_crlf_line_endings() {
        let src = "function f() { return\r\n  v;\r\n}";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "CRLF: expected 1 finding, got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── A2: Unicode identifier after return ───────────────────────────────────
    // Positive test — expected to FAIL in RED state.
    #[test]
    fn adversarial_unicode_identifier_after_return() {
        let src = "function f() { return\n  り;\n}";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "Unicode ident: expected 1 finding, got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── A3: Generator yield — out of scope, no finding ───────────────────────
    // Negative test — already PASSES in RED state.
    #[test]
    fn adversarial_generator_yield_not_flagged() {
        let src = "function* g() { yield\n  v;\n}";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "yield is out of scope for v1; expected 0 findings, got: {findings:#?}"
        );
    }

    // ── A4: Nested if around hazard ───────────────────────────────────────────
    // Positive test — expected to FAIL in RED state.
    #[test]
    fn adversarial_nested_if_around_hazard() {
        let src = "function f() { if (c) { return\n  v; }\n}";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "Nested if: expected 1 finding, got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── A5: Try/catch body ────────────────────────────────────────────────────
    // Positive test — expected to FAIL in RED state.
    #[test]
    fn adversarial_try_catch_body() {
        let src = "function f() { try { return\n  v; } catch (e) {} }";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "Try/catch: expected 1 finding, got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── A6: TS class method body ──────────────────────────────────────────────
    // Positive test — expected to FAIL in RED state.
    #[test]
    fn adversarial_ts_class_method_body() {
        let src = "class Foo { bar() { return\n  v;\n} }";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "TS class method: expected 1 finding, got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── A7: JSX return ────────────────────────────────────────────────────────
    // Positive test — expected to FAIL in RED state.
    #[test]
    fn adversarial_jsx_return() {
        let src = "function f() { return\n  <Foo />;\n}";
        let findings = analyze_tsx(src);
        assert_eq!(
            findings.len(),
            1,
            "JSX: expected 1 finding, got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── A8: Template literal next stmt ───────────────────────────────────────
    // Positive test — expected to FAIL in RED state.
    #[test]
    fn adversarial_template_literal_next_stmt() {
        let src = "function f() { return\n  `tpl`;\n}";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "Template literal: expected 1 finding, got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── A9: Empty body — no panic ─────────────────────────────────────────────
    // Negative test — already PASSES in RED state.
    #[test]
    fn adversarial_empty_body_no_panic() {
        let src = "function f() { }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "Empty body: expected 0 findings, got: {findings:#?}"
        );
    }

    // ── A10: Object-method shorthand ──────────────────────────────────────────
    // Positive test — object literal method shorthand body is a function body
    // and must be walked like any other block.
    #[test]
    fn adversarial_object_method_shorthand() {
        let src = "const o = { method() { return\n  v;\n} };";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "object-method shorthand should flag");
        assert_eq!(findings[0].rule_id, "STYLE001-block-delimitation");
    }

    // ── A11: Explicit-semicolon `return;` followed by expr on next line ───────
    // `return;` has argument:None, but the user wrote an explicit `;`, so there
    // is no ASI hazard.  After the fix, has_trailing_semicolon suppresses this.
    #[test]
    fn adversarial_explicit_semicolon_return_suppressed() {
        // "return;" has explicit ';' — the intent is unambiguous; ASI did NOT
        // insert anything.  Must NOT fire.
        let src = "function f() { return;\n  expr;\n}";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            0,
            "explicit `return;` should not flag (no ASI hazard). findings: {findings:#?}"
        );
    }

    // ── A12: Switch case consequent — now detected ───────────────────────────
    // `return\nexpr` inside a switch-case consequent must be detected after the
    // fix adds check_asi_hazards(&case.consequent, …) in the SwitchStatement handler.
    #[test]
    fn adversarial_switch_case_consequent_flags() {
        let src = "function f(x) {\n  switch (x) {\n    case 1:\n      return\n      v;\n  }\n}";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "switch-case consequent should flag ASI hazard; got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── A12b: Explicit-semicolon `continue;` — suppressed ────────────────────
    #[test]
    fn no_flag_explicit_semicolon_continue() {
        let src = "for (;;) { continue;\n  label;\n}";
        let findings = analyze(src);
        assert_eq!(findings.len(), 0, "explicit `continue;` should not flag");
    }

    // ── A12c: Explicit-semicolon `break;` — suppressed ───────────────────────
    #[test]
    fn no_flag_explicit_semicolon_break() {
        let src = "for (;;) { break;\n  label;\n}";
        let findings = analyze(src);
        assert_eq!(findings.len(), 0, "explicit `break;` should not flag");
    }

    // ── A13: Three blank lines between return and expr — no flag ─────────────
    // newlines_between == 4 (three blank lines ≥ 2) → suppressed. Pin behavior.
    #[test]
    fn adversarial_many_blank_lines_suppressed() {
        let src = "function f() { return\n\n\n\n  v;\n}";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "3 blank lines should suppress; got: {findings:#?}"
        );
    }

    // ── A14: return followed by IfStatement — non-ExpressionStatement carve-out
    // The carve-out for next-stmt being non-ExpressionStatement must hold for
    // IfStatement (not just VariableDeclaration / return). Pin behavior.
    #[test]
    fn adversarial_return_followed_by_if_no_flag() {
        let src = "function f() { return\n  if (c) { x(); }\n}";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "return + IfStatement should NOT flag; got: {findings:#?}"
        );
    }

    // ── A15: Async generator — yield out of scope, no flag ───────────────────
    // spec §2 explicitly defers `yield`. Pin that async generators also don't fire.
    #[test]
    fn adversarial_async_generator_yield_not_flagged() {
        let src = "async function* g() { yield\n  v;\n}";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "async generator yield is out of scope for v1; got: {findings:#?}"
        );
    }

    // ── A16: Multiple hazards in the same function — count == 2 ──────────────
    // Two independent return-expr hazards in the same block should each fire.
    #[test]
    fn adversarial_multiple_hazards_same_function() {
        // Two hazards in different nested blocks of the same outer function.
        let src = "function f(b) {\n  if (b) { return\n    a; }\n  else { return\n    c; }\n}";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            2,
            "two hazards should produce 2 findings; got: {findings:#?}"
        );
    }
}
