//! `MAINT011-active-debug-code` — flags active debug-code calls in Python
//! source files.
//!
//! # Detection
//!
//! Flags call expressions whose callee is:
//! - `print(…)` — bare name
//! - `pprint(…)` — bare name
//! - `breakpoint()` — bare name
//! - `pdb.set_trace()` — attribute call (any `Attribute { attr: "set_trace" }`
//!   whose value is a `Name("pdb")`)
//!
//! # Skips
//!
//! - Any call that appears inside an `if __name__ == "__main__":` guard (the
//!   body of such an `If` statement, checked by comparing the test expression
//!   to the `__name__ == "__main__"` pattern).
//! - `print` calls with a `file=` keyword argument whose value is not `None`
//!   are **not** excluded by this rule (the conservative choice — they may
//!   still be debug noise).

use rustpython_parser::ast::{CmpOp, Constant, Expr, ExprCompare, Ranged, Stmt};
use rustpython_parser::text_size::TextRange;
use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, Span},
};

/// The stable rule ID.
const RULE_ID: &str = "MAINT011-active-debug-code";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/MAINT011-active-debug-code.md",
    cwe: &["CWE-489"],
    owasp: &[],
};

/// Analyzer that emits `MAINT011-active-debug-code` for debug-code calls in
/// Python source files.
///
/// Severity: **Medium** / Confidence: **High** for all flagged patterns.
pub struct ActiveDebugCodeAnalyzer;

impl zuit_core::Analyzer for ActiveDebugCodeAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Maintainability
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::Only(smallvec![LanguageId("python")])
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let Some(ast) = crate::try_python_ast(file) else {
            return Vec::new();
        };

        let source = file.source();
        let file_path = source.path.clone();
        let mut findings = Vec::new();

        check_stmts(&ast.body, source, &file_path, false, &mut findings);
        findings
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Returns `true` when `test` matches the `__name__ == "__main__"` pattern
/// (or `"__main__" == __name__`).
fn is_main_guard(test: &Expr) -> bool {
    let Expr::Compare(ExprCompare {
        left,
        ops,
        comparators,
        ..
    }) = test
    else {
        return false;
    };
    if ops.len() != 1 || ops[0] != CmpOp::Eq {
        return false;
    }
    let Some(right) = comparators.first() else {
        return false;
    };
    let is_name_dunder = |e: &Expr| matches!(e, Expr::Name(n) if n.id.as_str() == "__name__");
    let is_main_str = |e: &Expr| {
        matches!(
            e,
            Expr::Constant(c) if matches!(&c.value, Constant::Str(s) if s.as_str() == "__main__")
        )
    };
    (is_name_dunder(left) && is_main_str(right)) || (is_main_str(left) && is_name_dunder(right))
}

fn emit(
    call_range: TextRange,
    func_name: &str,
    severity: Severity,
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    let start_off = ByteOffset(call_range.start().to_u32());
    let end_off = ByteOffset(call_range.end().to_u32());
    let span = Span::new(start_off, end_off);
    let (start_lc, end_lc) = source.span_to_linecols(span);
    findings.push(Finding {
        analyzer: AnalyzerId::new(RULE_ID),
        dimension: Dimension::Maintainability,
        rule_id: RULE_ID.to_string(),
        severity,
        message: format!("debug call `{func_name}` should not be present in production code"),
        location: Location {
            file: file_path.to_path_buf(),
            span,
            start: start_lc,
            end: end_lc,
        },
        suggestion: Some(
            "Remove or guard this call behind a conditional or logging framework \
             before shipping to production."
                .to_string(),
        ),
        references: vec!["https://cwe.mitre.org/data/definitions/489.html".to_string()],
        cwe: META.cwe_vec(),
        owasp: META.owasp_vec(),
    });
}

/// Returns the debug-call name and severity if `expr` is a flagged call,
/// otherwise `None`.
fn classify_debug_call(expr: &Expr) -> Option<(&'static str, Severity)> {
    let Expr::Call(call) = expr else {
        return None;
    };
    match call.func.as_ref() {
        Expr::Name(n) => match n.id.as_str() {
            "print" => Some(("print", Severity::Medium)),
            "pprint" => Some(("pprint", Severity::Medium)),
            "breakpoint" => Some(("breakpoint", Severity::Medium)),
            _ => None,
        },
        Expr::Attribute(attr) => {
            if attr.attr.as_str() == "set_trace"
                && let Expr::Name(obj) = attr.value.as_ref()
                && obj.id.as_str() == "pdb"
            {
                return Some(("pdb.set_trace", Severity::Medium));
            }
            None
        }
        _ => None,
    }
}

fn check_stmts(
    stmts: &[Stmt],
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    in_main_guard: bool,
    findings: &mut Vec<Finding>,
) {
    for stmt in stmts {
        check_stmt(stmt, source, file_path, in_main_guard, findings);
    }
}

#[allow(clippy::too_many_lines)]
fn check_stmt(
    stmt: &Stmt,
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    in_main_guard: bool,
    findings: &mut Vec<Finding>,
) {
    match stmt {
        Stmt::Expr(e) => check_expr(&e.value, source, file_path, in_main_guard, findings),
        Stmt::Assign(a) => {
            check_expr(&a.value, source, file_path, in_main_guard, findings);
        }
        Stmt::AugAssign(a) => {
            check_expr(&a.value, source, file_path, in_main_guard, findings);
        }
        Stmt::AnnAssign(a) => {
            if let Some(v) = &a.value {
                check_expr(v, source, file_path, in_main_guard, findings);
            }
        }
        Stmt::Return(r) => {
            if let Some(v) = &r.value {
                check_expr(v, source, file_path, in_main_guard, findings);
            }
        }
        Stmt::If(s) => {
            let child_in_main = in_main_guard || is_main_guard(&s.test);
            check_stmts(&s.body, source, file_path, child_in_main, findings);
            check_stmts(&s.orelse, source, file_path, in_main_guard, findings);
        }
        Stmt::For(s) => {
            check_stmts(&s.body, source, file_path, in_main_guard, findings);
            check_stmts(&s.orelse, source, file_path, in_main_guard, findings);
        }
        Stmt::AsyncFor(s) => {
            check_stmts(&s.body, source, file_path, in_main_guard, findings);
            check_stmts(&s.orelse, source, file_path, in_main_guard, findings);
        }
        Stmt::While(s) => {
            check_expr(&s.test, source, file_path, in_main_guard, findings);
            check_stmts(&s.body, source, file_path, in_main_guard, findings);
        }
        Stmt::FunctionDef(f) => {
            check_stmts(&f.body, source, file_path, in_main_guard, findings);
        }
        Stmt::AsyncFunctionDef(f) => {
            check_stmts(&f.body, source, file_path, in_main_guard, findings);
        }
        Stmt::ClassDef(c) => {
            check_stmts(&c.body, source, file_path, in_main_guard, findings);
        }
        Stmt::With(s) => {
            check_stmts(&s.body, source, file_path, in_main_guard, findings);
        }
        Stmt::AsyncWith(s) => {
            check_stmts(&s.body, source, file_path, in_main_guard, findings);
        }
        Stmt::Try(s) => {
            check_stmts(&s.body, source, file_path, in_main_guard, findings);
            for handler in &s.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                check_stmts(&h.body, source, file_path, in_main_guard, findings);
            }
            check_stmts(&s.orelse, source, file_path, in_main_guard, findings);
            check_stmts(&s.finalbody, source, file_path, in_main_guard, findings);
        }
        Stmt::TryStar(s) => {
            check_stmts(&s.body, source, file_path, in_main_guard, findings);
            for handler in &s.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                check_stmts(&h.body, source, file_path, in_main_guard, findings);
            }
        }
        _ => {}
    }
}

fn check_expr(
    expr: &Expr,
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    in_main_guard: bool,
    findings: &mut Vec<Finding>,
) {
    if let Some((name, sev)) = classify_debug_call(expr)
        && !in_main_guard
    {
        emit(expr.range(), name, sev, source, file_path, findings);
        // Still recurse into the arguments even for flagged calls, so that
        // nested debug calls are also caught.
    }

    // Recurse into sub-expressions to catch debug calls inside conditions,
    // assignments, etc.
    match expr {
        Expr::Call(call) => {
            check_expr(&call.func, source, file_path, in_main_guard, findings);
            for arg in &call.args {
                check_expr(arg, source, file_path, in_main_guard, findings);
            }
            for kw in &call.keywords {
                check_expr(&kw.value, source, file_path, in_main_guard, findings);
            }
        }
        Expr::BoolOp(e) => {
            for v in &e.values {
                check_expr(v, source, file_path, in_main_guard, findings);
            }
        }
        Expr::BinOp(e) => {
            check_expr(&e.left, source, file_path, in_main_guard, findings);
            check_expr(&e.right, source, file_path, in_main_guard, findings);
        }
        Expr::UnaryOp(e) => check_expr(&e.operand, source, file_path, in_main_guard, findings),
        Expr::IfExp(e) => {
            check_expr(&e.test, source, file_path, in_main_guard, findings);
            check_expr(&e.body, source, file_path, in_main_guard, findings);
            check_expr(&e.orelse, source, file_path, in_main_guard, findings);
        }
        Expr::List(e) => {
            for elt in &e.elts {
                check_expr(elt, source, file_path, in_main_guard, findings);
            }
        }
        Expr::Tuple(e) => {
            for elt in &e.elts {
                check_expr(elt, source, file_path, in_main_guard, findings);
            }
        }
        Expr::Attribute(e) => check_expr(&e.value, source, file_path, in_main_guard, findings),
        Expr::Subscript(e) => {
            check_expr(&e.value, source, file_path, in_main_guard, findings);
            check_expr(&e.slice, source, file_path, in_main_guard, findings);
        }
        Expr::Starred(e) => check_expr(&e.value, source, file_path, in_main_guard, findings),
        Expr::Compare(e) => {
            check_expr(&e.left, source, file_path, in_main_guard, findings);
            for c in &e.comparators {
                check_expr(c, source, file_path, in_main_guard, findings);
            }
        }
        Expr::Await(e) => check_expr(&e.value, source, file_path, in_main_guard, findings),
        _ => {}
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::PythonLanguage;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, Language, LanguageId, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.py", src.as_bytes().to_vec()));
        let lang = PythonLanguage;
        let parsed = lang.parse(source).expect("parse failed");
        let analyzer = ActiveDebugCodeAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_print_call() {
        let src = "x = 1\nprint(x)\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_pprint_call() {
        let src = "from pprint import pprint\npprint({'key': 'value'})\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_breakpoint_call() {
        let src = "x = compute()\nbreakpoint()\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_pdb_set_trace() {
        let src = "import pdb\npdb.set_trace()\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_print_in_main_guard() {
        let src = "if __name__ == '__main__':\n    print('hello')\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "print inside __main__ guard should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_main_guard_reversed() {
        // '__main__' == __name__ is also a valid main guard
        let src = "if '__main__' == __name__:\n    print('hello')\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "print inside reversed __main__ guard should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_logging_call() {
        // `logging.info` is not a debug call
        let src = "import logging\nlogging.info('starting')\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "logging.info should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn flags_print_outside_main_guard_even_with_guard_present() {
        // print outside the guard must still be flagged
        let src = "print('debug')\nif __name__ == '__main__':\n    print('main')\n";
        let findings = analyze(src);
        // Only the first print (outside guard) should be flagged
        assert_eq!(
            findings.len(),
            1,
            "only print outside main guard should be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn supported_languages_is_python_only() {
        let analyzer = ActiveDebugCodeAnalyzer;
        assert!(
            analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
        assert!(!analyzer.supported_languages().supports(LanguageId("rust")));
    }
}
