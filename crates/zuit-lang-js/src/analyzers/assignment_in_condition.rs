//! `BUG001-assignment-in-condition` — flags assignment expressions that appear
//! in the *test* position of conditional statements in JavaScript/TypeScript
//! source files (CWE-480).
//!
//! # Detection
//!
//! Reads the pre-extracted `JsAst::assignment_in_conditions` populated at
//! parse time by the walker.
//!
//! # Flagged constructs
//!
//! Any assignment expression (`=`, `+=`, `-=`, `*=`, `/=`, etc.) in the test
//! slot of:
//!
//! - `if (x = 1) { … }` → 1 finding
//! - `while (x = nextChunk()) { … }` → 1 finding
//! - `do { … } while (x = next())` → 1 finding
//! - `for (let i = 0; x = step(); i++) { … }` → 1 finding (test slot only)
//! - `cond ? (consequent) : (alternate)` — assignment in test of a conditional
//!   expression
//!
//! # Skips
//!
//! Following `ESLint`'s `no-cond-assign` `"except-parens"` default, an
//! assignment wrapped in an **extra** pair of parentheses is **not** flagged:
//! `if ((x = 1))` is the documented "I really mean it" pattern.
//!
//! # Languages
//!
//! JavaScript and TypeScript only (`LanguageId("javascript")`).  Python's
//! parser rejects `if (x = 1)` outright; Rust uses `let` patterns where this
//! issue cannot arise.

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

/// The stable rule ID.
const RULE_ID: &str = "BUG001-assignment-in-condition";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/BUG001-assignment-in-condition.md",
    cwe: &["CWE-480"],
    owasp: &[],
};

/// Analyzer that emits `BUG001-assignment-in-condition` for assignment
/// expressions found in condition/test positions in JavaScript/TypeScript
/// source files.
pub struct JsAssignmentInConditionAnalyzer;

impl zuit_core::Analyzer for JsAssignmentInConditionAnalyzer {
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

        ast.assignment_in_conditions
            .iter()
            .map(|site| {
                let span = site.span;
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Maintainability,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "assignment expression (`{}`) in condition — did you mean `==` or `===`?",
                        site.operator
                    ),
                    location: Location {
                        file: file_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Replace the assignment with a comparison (`==` or `===`), or \
                         wrap the intentional assignment in extra parentheses \
                         (`if ((x = getValue()))`) to silence this warning."
                            .to_string(),
                    ),
                    references: vec!["https://cwe.mitre.org/data/definitions/480.html".to_string()],
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
        let analyzer = JsAssignmentInConditionAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_if_simple_assign() {
        let src = "if (x = 1) { doSomething(); }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains('='));
    }

    #[test]
    fn flags_while_assign() {
        let src = "while (x = nextChunk()) { process(x); }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_do_while_assign() {
        let src = "do { process(x); } while (x = next());";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_for_test_slot_only() {
        // init `i = 0` is a VariableDeclaration — NOT a finding.
        // test `x = step()` IS a finding.
        // update `i++` is not an assignment expression — NOT a finding.
        let src = "for (let i = 0; x = step(); i++) { }";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 finding (test slot only), got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_compound_assign_in_if() {
        let src = "if (x += 1) { ok(); }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert!(
            findings[0].message.contains("+="),
            "message should name the operator: {}",
            findings[0].message
        );
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_equality_check() {
        let src = "if (x == 1) { doSomething(); }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "== should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_strict_equality() {
        let src = "if (x === 1) { doSomething(); }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "=== should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_assignment_outside_condition() {
        let src = "let x = 1; if (x) { doSomething(); }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "plain variable declaration should not be flagged, got: {findings:#?}"
        );
    }

    /// `ESLint` `no-cond-assign` `"except-parens"` carve-out:
    /// `if ((x = 1))` wraps the assignment in extra parens — this is the
    /// documented "I really mean it" idiom and must not be flagged.
    #[test]
    fn does_not_flag_parenthesized_assignment_in_if() {
        let src = "if ((x = getValue())) { use(x); }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "double-paren assignment carve-out should suppress the finding, \
             got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_ternary_assignment_in_branch() {
        // The ternary *test* is `cond`, not an assignment.
        // The assignments are in the branch positions, not the test — not flagged.
        let src = "cond ? (a = b) : c;";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "assignment in ternary branch position should not be flagged, \
             got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_ternary_where_assignment_is_the_whole_expr() {
        // `x = 1 ? a : b` — the assignment is NOT inside a condition; the
        // ternary's test is `1`, which is a numeric literal.
        let src = "x = 1 ? a : b;";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "assignment outside test position should not be flagged, \
             got: {findings:#?}"
        );
    }

    /// TypeScript cast: `if (x = getValue() as number)` still flags because
    /// the TS `as`-expression wraps an `AssignmentExpression`, not the other way
    /// around — wait, actually the parser sees the whole `x = getValue() as
    /// number` as a single `AssignmentExpression` (the RHS is a `TSAsExpression`).
    /// So the test expression itself is an `AssignmentExpression` — must flag.
    #[test]
    fn flags_typescript_cast_in_condition() {
        let src = "if (x = getValue() as number) { use(x); }";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "TS-cast RHS should not suppress the BUG001 finding, got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn supported_languages_is_javascript_only() {
        let analyzer = JsAssignmentInConditionAnalyzer;
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
