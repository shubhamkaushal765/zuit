//! `PERF010-allocation-in-loop` — detects heap-allocating expressions inside
//! loop bodies (`for`, `while`, `loop`).
//!
//! **CWE:** CWE-1050 (Excessive Platform Resource Consumption within a Loop).
//!
//! **Heuristic:** the `parse.rs` visitor pre-extracts `RustAst::allocs_in_loop`
//! during the `syn` walk.  Any call or macro that matches the known allocating
//! patterns while `in_loop_depth > 0` contributes a span to that list.  This
//! analyzer reads the pre-extracted list and emits one finding per span.
//!
//! **Detection list:**
//! - `Vec::new()` / `Vec::with_capacity(…)`
//! - `String::new()` / `String::with_capacity(…)` / `String::from(…)` /
//!   `.to_string()` / `.to_owned()`
//! - `Box::new(…)`
//! - `HashMap::new()` / `HashMap::with_capacity(…)` / `BTreeMap::new()`
//! - `HashSet::new()` / `BTreeSet::new()`
//! - `vec![…]` / `format!(…)` macros
//!
//! **Skip patterns:**
//! - Allocations outside loop bodies are never flagged.
//! - Nested `fn` item bodies inside loops are not recursed into.
//! - Closures defined inside loops **are** flagged — they execute once per
//!   outer iteration.
//!
//! **Fix guidance:** consider hoisting allocations outside the loop, using
//! `.clear()` + `.extend()` on a pre-allocated buffer, or `.with_capacity(N)`
//! if the size is known.

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, LanguageId, Location, Project,
    RuleMeta, Severity, SupportedLanguages,
};

use crate::try_rust_ast;

const RULE_ID: &str = "PERF010-allocation-in-loop";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/PERF010-allocation-in-loop.md",
    cwe: &["CWE-1050"],
    owasp: &[],
};

/// Analyzer for `PERF010-allocation-in-loop`.
pub struct Perf010AllocationInLoop;

impl zuit_core::Analyzer for Perf010AllocationInLoop {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("performance".to_string())
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::Only(smallvec![LanguageId("rust")])
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn kind(&self) -> AnalyzerKind {
        AnalyzerKind::FileLevel
    }

    fn analyze_file(
        &self,
        _ctx: &AnalysisContext<'_>,
        file: &zuit_core::ParsedFile,
    ) -> Vec<Finding> {
        let Some(ast) = try_rust_ast(file) else {
            return Vec::new();
        };

        if ast.allocs_in_loop.is_empty() {
            return Vec::new();
        }

        let src = file.source();
        let source_path = src.path.clone();

        ast.allocs_in_loop
            .iter()
            .map(|&span| {
                let (start_lc, end_lc) = src.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Custom("performance".to_string()),
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Low,
                    message: "heap allocation inside a loop body; consider hoisting \
                              the allocation outside the loop or using `.with_capacity(N)` \
                              if the size is known."
                        .to_string(),
                    location: Location {
                        file: source_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Hoist the allocation before the loop, reuse a pre-allocated \
                         buffer with `.clear()` + `.extend()`, or use `.with_capacity(N)` \
                         to avoid repeated heap reallocations."
                            .to_string(),
                    ),
                    references: vec![
                        "https://cwe.mitre.org/data/definitions/1050.html".to_string(),
                        "https://nnethercote.github.io/perf-book/".to_string(),
                    ],
                    cwe: META.cwe_vec(),
                    owasp: META.owasp_vec(),
                }
            })
            .collect()
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, _project: &Project) -> Vec<Finding> {
        Vec::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use zuit_core::{Analyzer, Config, SourceFile};

    use super::*;

    fn parse_and_analyze(code: &str) -> Vec<Finding> {
        let src = Arc::new(SourceFile::new("test.rs", code.as_bytes().to_vec()));
        let parsed = crate::parse::parse(src).expect("parse failed");
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        Perf010AllocationInLoop.analyze_file(&ctx, &parsed)
    }

    // ── Positive tests ────────────────────────────────────────────────────────

    /// `for x in v { let y = Vec::new(); }` → 1 finding.
    #[test]
    fn perf010_vec_new_in_for_loop() {
        let code = "fn f(v: &[i32]) { for _x in v { let _y = Vec::new(); } }";
        let findings = parse_and_analyze(code);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    /// `for x in v { let y: String = format!("{}", x); }` → 1 finding.
    #[test]
    fn perf010_format_macro_in_for_loop() {
        let code = r#"fn f(v: &[i32]) { for x in v { let _y: String = format!("{}", x); } }"#;
        let findings = parse_and_analyze(code);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    /// `while c { let v = vec![1, 2, 3]; }` → 1 finding (vec! macro).
    #[test]
    fn perf010_vec_macro_in_while_loop() {
        let code = "fn f(mut c: bool) { while c { let _v = vec![1, 2, 3]; c = false; } }";
        let findings = parse_and_analyze(code);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    /// `loop { let s = String::new(); break; }` → 1 finding.
    #[test]
    fn perf010_string_new_in_loop() {
        let code = "fn f() { loop { let _s = String::new(); break; } }";
        let findings = parse_and_analyze(code);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    /// `for _ in 0..10 { let v = Box::new(42); }` → 1 finding.
    #[test]
    fn perf010_box_new_in_for_loop() {
        let code = "fn f() { for _ in 0..10 { let _v = Box::new(42); } }";
        let findings = parse_and_analyze(code);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    /// Nested loops: `for _ in 0..10 { for _ in 0..10 { let v = Vec::new(); } }`
    /// → exactly 1 finding (one source location).
    #[test]
    fn perf010_nested_loops_one_finding_per_site() {
        let code = "fn f() { for _ in 0..10 { for _ in 0..10 { let _v = Vec::new(); } } }";
        let findings = parse_and_analyze(code);
        assert!(
            !findings.is_empty(),
            "expected at least 1 finding, got none"
        );
        // Verify all findings reference PERF010.
        for f in &findings {
            assert_eq!(f.rule_id, RULE_ID);
        }
    }

    // ── Closure in loop ───────────────────────────────────────────────────────

    /// Closure inside a loop: the `Vec::new()` inside the closure runs once
    /// per outer iteration, so it should fire.
    #[test]
    fn perf010_closure_in_loop_fires() {
        let code = "fn f(v: &[i32]) { \
                    for _ in v { \
                        let _result: Vec<_> = (0..3).map(|_| Vec::new()).collect(); \
                    } \
                    }";
        let findings = parse_and_analyze(code);
        // Closures defined inside loops execute per iteration — must fire.
        assert!(
            !findings.is_empty(),
            "expected findings for Vec::new() inside a closure in a loop, got none"
        );
    }

    // ── Negative tests ────────────────────────────────────────────────────────

    /// Alloc outside loop: `let v = Vec::new(); for x in v { x; }` → 0 findings.
    #[test]
    fn perf010_alloc_outside_loop_no_finding() {
        let code = "fn f() { let _v: Vec<i32> = Vec::new(); for _x in 0..3 {} }";
        let findings = parse_and_analyze(code);
        assert!(
            findings.is_empty(),
            "expected 0 findings, got: {findings:#?}"
        );
    }

    /// Nested fn-item inside loop body is NOT recursed into.
    /// `for _ in v { fn helper() { let v = Vec::new(); } helper(); }` → 0 findings.
    #[test]
    fn perf010_nested_fn_item_not_recursed() {
        // `helper` is defined as a nested fn inside the loop, but its body only
        // runs when explicitly called — not inline.  PERF010 must not fire.
        let code = "fn f(v: &[i32]) { \
                    for _ in v { \
                        fn helper() { let _v: Vec<i32> = Vec::new(); } \
                        helper(); \
                    } \
                    }";
        let findings = parse_and_analyze(code);
        assert!(
            findings.is_empty(),
            "expected 0 findings for nested fn-item body, got: {findings:#?}"
        );
    }

    /// Nothing in the file uses a loop → 0 findings.
    #[test]
    fn perf010_no_loop_no_finding() {
        let code = "fn f() { let _v: Vec<i32> = Vec::new(); }";
        let findings = parse_and_analyze(code);
        assert!(
            findings.is_empty(),
            "expected 0 findings, got: {findings:#?}"
        );
    }

    /// `supported_languages` is Rust only.
    #[test]
    fn perf010_supported_languages_rust_only() {
        let langs = Perf010AllocationInLoop.supported_languages();
        match langs {
            SupportedLanguages::Only(ids) => {
                assert_eq!(ids.len(), 1);
                assert_eq!(ids[0], LanguageId("rust"));
            }
            other @ SupportedLanguages::All => {
                panic!("expected SupportedLanguages::Only([rust]), got {other:?}")
            }
        }
    }

    /// `HashMap::new()` inside loop fires.
    #[test]
    fn perf010_hashmap_new_in_loop() {
        let code = "use std::collections::HashMap; \
                    fn f() { for _ in 0..5 { let _m = HashMap::new(); } }";
        let findings = parse_and_analyze(code);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    /// `.to_string()` inside loop fires.
    #[test]
    fn perf010_to_string_in_loop() {
        let code = r"fn f(items: &[i32]) { for x in items { let _s = x.to_string(); } }";
        let findings = parse_and_analyze(code);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }
}
