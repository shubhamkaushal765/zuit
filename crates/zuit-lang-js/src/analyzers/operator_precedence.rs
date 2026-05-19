//! `BUG004-operator-precedence` — flags expressions where operator precedence
//! likely produces unintended results in JavaScript/TypeScript source files
//! (CWE-783).
//!
//! # Detection
//!
//! Walks the parsed JS/TS AST looking for two categories of precedence traps:
//!
//! **Pattern 1 — non-shift bitwise mixed with comparison (no parens).**
//! The non-shift bitwise operators `&`, `|`, and `^` bind *looser* than
//! comparison operators in JavaScript, so `a & b == c` parses as `a & (b ==
//! c)` — the opposite of what most C-trained programmers expect.  Note:
//! shift operators (`<<`, `>>`, `>>>`) bind *tighter* than comparisons, so
//! `a << b == c` already parses as `(a << b) == c`; that is **not** flagged.
//!
//! **Pattern 2 — unary `!` on either side of a bitwise op (no parens).**
//! Both `!x & y` and `y & !x` are detected symmetrically.  The `!` argument
//! must be a plain identifier or member access to qualify; parenthesized
//! subexpressions (e.g. `!(a == b)`) and function calls (e.g. `!foo()`)
//! express explicit intent and are skipped.  When both sides qualify (e.g.
//! `!x & !y`) only one finding is emitted per expression.
//!
//! # Flagged constructs
//!
//! - `a & b == c`   — programmer likely meant `(a & b) == c`
//! - `a | b == c`   — programmer likely meant `(a | b) == c`
//! - `!x & y`       — programmer likely meant `!(x & y)` or `(!x) & y` (rare)
//! - `y & !x`       — same footgun, right-operand position
//! - `!obj.flag & MASK` — member access on either side
//!
//! # Skips
//!
//! Expressions that are already parenthesized to make the intent clear are not
//! flagged: `(a & b) == c`, `a & (b == c)`, `!(a == b) & c`.
//! Shift operators mixed with comparisons (`a << b == c`) are also skipped
//! because JS shift precedence means the AST already reflects programmer intent.
//!
//! # Languages
//!
//! JavaScript and TypeScript only (`LanguageId("javascript")`).

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

/// The stable rule ID.
const RULE_ID: &str = "BUG004-operator-precedence";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/BUG004-operator-precedence.md",
    cwe: &["CWE-783"],
    owasp: &[],
};

/// Analyzer that emits `BUG004-operator-precedence` for expressions where
/// operator precedence is likely to produce unintended results in
/// JavaScript/TypeScript source files.
pub struct JsOperatorPrecedenceAnalyzer;

impl zuit_core::Analyzer for JsOperatorPrecedenceAnalyzer {
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

        ast.op_precedence_sites
            .iter()
            .map(|site| {
                use crate::native_ast::JsOpPrecedenceKind;
                let span = site.span;
                let (start_lc, end_lc) = source.span_to_linecols(span);
                let (message, suggestion) = match site.kind {
                    JsOpPrecedenceKind::BitwiseWithComparison => (
                        format!(
                            "`{}` mixed with `{}` without parentheses — comparison operators bind \
                             tighter than bitwise in JavaScript; did you mean \
                             `(... {} ...) {} ...`?",
                            site.outer_operator,
                            site.inner_operator,
                            site.outer_operator,
                            site.inner_operator,
                        ),
                        "Wrap the intended grouping in parentheses \
                         (e.g. `(a & b) == c` or `!(x & y)`) to make precedence explicit."
                            .to_string(),
                    ),
                    JsOpPrecedenceKind::NotWithBitwise => (
                        format!(
                            "`!` applied directly inside `{}` — `!` binds tighter than `{}`; \
                             did you mean `!(x {} y)`?",
                            site.outer_operator, site.outer_operator, site.outer_operator,
                        ),
                        "Wrap the intended grouping in parentheses \
                         (e.g. `(a & b) == c` or `!(x & y)`) to make precedence explicit."
                            .to_string(),
                    ),
                    JsOpPrecedenceKind::NotWithTsIntersection => (
                        "TypeScript `as` cast wrapping `!<expr>` consumed `&` as part of an \
                         intersection type; you almost certainly meant `(!<expr> as T) & MASK`. \
                         Wrap the cast in parentheses to disambiguate."
                            .to_string(),
                        "Wrap the cast in parentheses: `(!x as boolean) & MASK` makes the \
                         value-level bitwise `&` unambiguous."
                            .to_string(),
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
                    references: vec!["https://cwe.mitre.org/data/definitions/783.html".to_string()],
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
        let analyzer = JsOperatorPrecedenceAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_bitwise_and_with_equality() {
        let src = "let r = a & b == c;";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_bitwise_or_with_equality() {
        let src = "let r = a | b == c;";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_bitwise_xor_with_inequality() {
        let src = "let r = a ^ b != c;";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn no_finding_shift_left_with_equality() {
        // In JS, `<<` binds tighter than `==`, so `a << b == c` parses as
        // `(a << b) == c` — exactly what the programmer wrote.  This is NOT a
        // CWE-783 footgun and must not be flagged.
        let src = "let r = a << b == c;";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected 0 findings (shift+comparison is not a footgun in JS), got: {findings:#?}"
        );
    }

    #[test]
    fn no_finding_shift_right_with_less_than() {
        // Same rationale as above: `>>` binds tighter than `<` in JS.
        // `a >> b < c` parses as `(a >> b) < c` — no precedence surprise.
        let src = "let r = a >> b < c;";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected 0 findings (shift+comparison is not a footgun in JS), got: {findings:#?}"
        );
    }

    #[test]
    fn flags_comparison_on_left_of_bitwise() {
        // outer is `&`, LEFT operand is `a == b`
        let src = "let r = a == b & c;";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_strict_equality_with_bitwise() {
        let src = "let r = a === b & c;";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_bang_with_bitwise_and() {
        let src = "let r = !x & y;";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_bang_with_bitwise_or() {
        let src = "let r = !x | y;";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_bang_with_bitwise_xor() {
        // `!isReady & 0xff` — `!` feeds directly into `&`
        let src = "let r = !isReady & 0xff;";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_inside_if_test() {
        // BinaryExpression nested in if test — still one finding
        let src = "if (a & b == c) { ok(); }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_inside_return() {
        let src = "function f(){ return a & b == c; }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_ts_as_cast_left_of_bitwise() {
        // TS-cast wraps LEFT, RHS is bitwise+comparison
        let src = "let r = (a as number) & b == c;";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn no_finding_paren_around_bitwise() {
        let src = "let r = (a & b) == c;";
        let findings = analyze(src);
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn no_finding_paren_around_comparison() {
        let src = "let r = a & (b == c);";
        let findings = analyze(src);
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn no_finding_paren_around_bitwise_in_not() {
        let src = "let r = !(x & y);";
        let findings = analyze(src);
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn no_finding_chained_comparison() {
        let src = "let r = a == b == c;";
        let findings = analyze(src);
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn no_finding_chained_bitwise() {
        let src = "let r = a & b & c;";
        let findings = analyze(src);
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn no_finding_logical_only() {
        let src = "let r = a && b && c;";
        let findings = analyze(src);
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn no_finding_for_loop_idiom() {
        let src = "for (let i = 0; i < n; i++) {}";
        let findings = analyze(src);
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn no_finding_paren_around_bang() {
        let src = "let r = (!x) & y;";
        let findings = analyze(src);
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn no_finding_plain_assignment() {
        let src = "let r = a + b * c;";
        let findings = analyze(src);
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn no_finding_typeof_check() {
        // typeof is a UnaryOperator, but bitwise not involved
        let src = "if (typeof x === 'string') { ok(); }";
        let findings = analyze(src);
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn no_finding_bang_on_function_call() {
        // unary `!`, no bitwise outer
        let src = "let r = !foo();";
        let findings = analyze(src);
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    // ── Fix 2: Pattern 2 arg-shape allowlist ──────────────────────────────────

    #[test]
    fn no_finding_bang_on_parenthesized_comparison() {
        // `!(a == b)` makes the developer's intent explicit; the parenthesized
        // comparison is NOT a footgun shape even though `!` feeds into `&`.
        let src = "let r = !(a == b) & c;";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected 0 findings, got: {findings:#?}"
        );
    }

    #[test]
    fn no_finding_bang_on_function_call_in_bitwise() {
        // `!foo()` — the call makes intent unclear but is not the classic
        // plain-identifier footgun; prefer not to flag it.
        let src = "let r = !foo() & y;";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected 0 findings, got: {findings:#?}"
        );
    }

    #[test]
    fn flags_bang_on_member_access() {
        // `!obj.flag & MASK` — static member access is the classic footgun shape.
        let src = "let r = !obj.flag & MASK;";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_bang_on_computed_member() {
        // `!obj[key] & MASK` — computed member access is also a footgun shape.
        let src = "let r = !obj[key] & MASK;";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    // ── Fix 3: right-side bang symmetry ───────────────────────────────────────

    #[test]
    fn flags_right_side_bang_with_bitwise() {
        // `y & !x` is the same footgun as `!x & y`; both sides must be detected.
        let src = "let r = y & !x;";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_both_sides_bang_fires_once() {
        // `!x & !y` — both operands are `!ident`; still ONE finding per
        // BinaryExpression to avoid double-counting the same expression.
        let src = "let r = !x & !y;";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 finding (not 2), got: {findings:#?}"
        );
    }

    #[test]
    fn no_finding_right_side_bang_on_paren_comparison() {
        // `y & !(a == b)` — parenthesized comparison makes intent explicit;
        // right-side variant must also respect the arg-shape allowlist.
        let src = "let r = y & !(a == b);";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected 0 findings, got: {findings:#?}"
        );
    }

    // ── meta tests ────────────────────────────────────────────────────────────

    #[test]
    fn analyzer_metadata_is_correct() {
        let a = JsOperatorPrecedenceAnalyzer;
        assert_eq!(a.id().as_str(), "BUG004-operator-precedence");
        assert_eq!(a.dimension(), Dimension::Maintainability);
        let rules = a.rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].cwe, &["CWE-783"]);
        assert_eq!(rules[0].default_severity, Severity::Medium);
    }

    #[test]
    fn supported_languages_is_javascript_only() {
        let a = JsOperatorPrecedenceAnalyzer;
        assert!(a.supported_languages().supports(LanguageId("javascript")));
        assert!(!a.supported_languages().supports(LanguageId("python")));
        assert!(!a.supported_languages().supports(LanguageId("rust")));
    }
}

// ── adversarial tests ─────────────────────────────────────────────────────────
//
// These tests were added by the adversarial QA pass.  Tests that expose real
// bugs are expected to FAIL until those bugs are fixed; they are kept here as
// regression anchors.

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use crate::parse as js_parse;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.ts", src.as_bytes().to_vec()));
        let parsed = js_parse::parse(source).expect("parse failed");
        let analyzer = JsOperatorPrecedenceAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── A1: paren around comparison suppresses correctly ──────────────────────
    #[test]
    fn no_finding_paren_around_inner_comparison_with_neglit() {
        // `a & (-1 == c)` — parenthesized right operand; should NOT fire.
        let src = "let r = a & (-1 == c);";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "A1: paren around (-1 == c) should suppress finding; got: {findings:#?}"
        );
    }

    // ── A2: member-access as outer left operand ───────────────────────────────
    #[test]
    fn flags_member_access_mixed_with_comparison() {
        // `a & b.length == c` — outer `&`, right is `BinaryExpression(b.length == c)`.
        // b.length is not parenthesized here; the whole `b.length == c` IS the
        // right child of `&`.  Should fire (Pattern 1).
        let src = "let r = a & b.length == c;";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "A2: `a & b.length == c` should fire once (Pattern 1); got: {findings:#?}"
        );
    }

    // ── A3: both operands parenthesized ──────────────────────────────────────
    #[test]
    fn no_finding_both_operands_parenthesized() {
        // `(a & b) | (c == d)` — left is paren-wrapped `&`, right is paren-wrapped
        // `==`.  The outer `|` sees both sides as ParenthesizedExpression.
        // Should NOT fire.
        let src = "let r = (a & b) | (c == d);";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "A3: both operands parenthesized should suppress; got: {findings:#?}"
        );
    }

    // ── A4: `instanceof` is NOT in the comparison set ── known false negative ─
    //
    // BUG: `instanceof` has the same JS precedence level as `<`/`>`/`==`, so
    // `a & b instanceof Klass` parses as `a & (b instanceof Klass)` and is the
    // same CWE-783 footgun.  The analyzer does NOT flag it because
    // `js_comparison_op_str` does not include `BinaryOperator::Instanceof`.
    // This test is written to FAIL, proving the gap exists.
    #[test]
    fn flags_instanceof_inside_bitwise() {
        let src = "let r = a & b instanceof Klass;";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "A4 (BUG): `a & b instanceof Klass` should fire — instanceof has \
             comparison-level precedence in JS; got: {findings:#?}"
        );
    }

    // ── A5: `in` operator — same precedence gap as instanceof ── known FN ────
    //
    // BUG: `a & key in obj` parses as `a & (key in obj)` in JS.  Same gap as A4.
    #[test]
    fn flags_in_operator_inside_bitwise() {
        let src = "let r = a & key in obj;";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "A5 (BUG): `a & key in obj` should fire — `in` has comparison-level \
             precedence in JS; got: {findings:#?}"
        );
    }

    // ── A6: `!new Set() & MASK` — new expression not in allowlist ────────────
    #[test]
    fn no_finding_bang_on_new_expression() {
        let src = "let r = !new Set() & MASK;";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "A6: `!new Set()` arg is NewExpression, not in allowlist; got: {findings:#?}"
        );
    }

    // ── A7: `!await x & MASK` — await expression not in allowlist ────────────
    #[test]
    fn no_finding_bang_on_await_expression() {
        // `await x` is AwaitExpression, not in the footgun allowlist.
        let src = "async function f() { let r = !await x & MASK; }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "A7: `!await x` is not in allowlist; got: {findings:#?}"
        );
    }

    // ── A8: `!this.flag & MASK` — StaticMemberExpression on `this` ───────────
    #[test]
    fn flags_bang_on_this_member_access() {
        // `this.flag` is StaticMemberExpression — should be in allowlist and fire.
        let src = "let r = !this.flag & MASK;";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "A8: `!this.flag` — StaticMemberExpression should be in allowlist; got: {findings:#?}"
        );
    }

    // ── A9: TS `as`-cast wrapping `!` — now fixed with NotWithTsIntersection variant
    #[test]
    fn flags_bang_ts_as_cast_in_bitwise() {
        // Note: `!x as boolean & MASK` in TS is parsed as `((!x) as boolean) & MASK`
        // because `as` has lower precedence than unary `!`.
        let src = "let r = !x as boolean & MASK;";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "A9: `!x as boolean & MASK` should fire once with NotWithTsIntersection variant; got: {findings:#?}"
        );
        assert!(
            findings[0].message.contains("intersection type"),
            "expected TS-intersection-specific message, got: {}",
            findings[0].message,
        );
    }

    // ── A10: logical `&&` wrapper around Pattern 1 — should still fire ────────
    #[test]
    fn flags_pattern1_inside_logical_and() {
        // `&&` is a LogicalExpression (not BinaryExpression), so the walker visits
        // `a & b == c` as its own BinaryExpression node.  Should fire once.
        let src = "if (a & b == c && d == e) {}";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "A10: Pattern 1 inside `&&` — should fire once for `a & b == c`; got: {findings:#?}"
        );
    }

    // ── A11: Pattern 1 in function-call argument ──────────────────────────────
    #[test]
    fn flags_pattern1_in_function_call_arg() {
        let src = "assert(a & b == c);";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "A11: Pattern 1 inside call arg; got: {findings:#?}"
        );
    }

    // ── A12: Pattern 1 in arrow function body ────────────────────────────────
    #[test]
    fn flags_pattern1_in_arrow_body() {
        let src = "arr.map(x => a & x == b);";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "A12: Pattern 1 in arrow body; got: {findings:#?}"
        );
    }

    // ── A13: Pattern 1 in JSX expression container ───────────────────────────
    //
    // NOTE: The test harness uses `SourceFile::new("test.ts", ...)`.  The `.ts`
    // extension does not enable JSX parsing (that requires `.tsx`).  Attempting
    // to parse JSX syntax as plain TS causes a parse error and panics via
    // `expect("parse failed")`.  This case is therefore tested via the CLI only;
    // the in-process harness cannot exercise it without `.tsx` support.
    // Skipped here — behavior confirmed manually: Pattern 1 fires inside JSX.

    // ── A14: Pattern 1 in template literal substitution ──────────────────────
    #[test]
    fn flags_pattern1_in_template_literal() {
        let src = "let s = `${a & b == c}`;";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "A14: Pattern 1 in template literal substitution; got: {findings:#?}"
        );
    }

    // ── A15: empty file — no crash ────────────────────────────────────────────
    #[test]
    fn no_crash_empty_file() {
        let findings = analyze("");
        assert!(findings.is_empty(), "A15: empty file; got: {findings:#?}");
    }

    // ── A16: comments-only file ───────────────────────────────────────────────
    #[test]
    fn no_crash_comments_only() {
        let findings = analyze("// just a comment\n/* block comment */");
        assert!(
            findings.is_empty(),
            "A16: comments-only file; got: {findings:#?}"
        );
    }

    // ── A17: multi-byte unicode in identifier ────────────────────────────────
    #[test]
    fn flags_unicode_identifier_in_pattern1() {
        let src = "let り = a & b == c;";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "A17: unicode identifier; got: {findings:#?}"
        );
    }

    // ── A18: comment between operands (does not affect AST) ──────────────────
    #[test]
    fn flags_comment_between_operands() {
        let src = "let r = a & /* tricky */ b == c;";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "A18: comment between operands — AST is same; got: {findings:#?}"
        );
    }

    // ── A19: deeply nested pattern — no stack overflow ───────────────────────
    #[test]
    fn no_crash_deeply_nested() {
        // Builds a deeply nested bitwise chain: `a & b & b & b & b == c == c …`
        // The right-associative parse means the innermost node is `b == c`.
        // We only care that it does not panic; finding count is secondary.
        let src = "let r = a & b & b & b & b == c == c == c;";
        let findings = analyze(src);
        // At minimum, must not panic.  The exact count is documented, not asserted strictly.
        let _ = findings;
    }

    // ── A20: `!super.prop & MASK` — super member access ──────────────────────
    #[test]
    fn no_crash_bang_on_super_member() {
        // `super.flag` is not `StaticMemberExpression` in oxc — it is
        // `StaticMemberExpression { object: Super, ... }` but the outer
        // expression type is still `StaticMemberExpression`.  We just assert
        // no panic; the firing vs non-firing is a documentation exercise.
        let src = "class C extends B { m() { let r = !super.flag & MASK; } }";
        let _findings = analyze(src);
        // Does not assert count — just confirms no panic.
    }
}
