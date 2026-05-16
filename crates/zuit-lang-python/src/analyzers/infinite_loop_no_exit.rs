//! `MAINT010-infinite-loop-no-exit` — flags Python `while True:` loops whose
//! body, recursively excluding nested loops and function/class bodies, contains
//! no `break`, `return`, `raise`, or call to `sys.exit` / `exit` / `os._exit`.
//!
//! # Detection
//!
//! Walks the full `ModModule` AST recursively.  For each `Stmt::While` whose
//! test is a `Constant(Bool(true))` literal, runs a recursive body scan that
//! *stops descending* into nested `While`, `For`, `AsyncFor`, `FunctionDef`,
//! `AsyncFunctionDef`, or `ClassDef` bodies.  If the scan finds no exit
//! statement, a finding is emitted at the `while` keyword span.

use rustpython_parser::ast::{Constant, Expr, ExprConstant, Ranged, Stmt};
use rustpython_parser::text_size::TextRange;
use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, Span},
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

/// Analyzer that emits `MAINT010-infinite-loop-no-exit` for Python
/// `while True:` loops with no exit path.
pub struct InfiniteLoopNoExitAnalyzer;

impl zuit_core::Analyzer for InfiniteLoopNoExitAnalyzer {
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

        check_stmts(&ast.body, source, &file_path, &mut findings);
        findings
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Returns `true` if the `while` test is the literal `True`.
fn is_true_literal(expr: &Expr) -> bool {
    if let Expr::Constant(ExprConstant {
        value: Constant::Bool(true),
        ..
    }) = expr
    {
        return true;
    }
    false
}

/// Returns `true` if any statement in `stmts`, recursively (excluding nested
/// loop / function / class bodies), constitutes an exit.
///
/// Exits counted:
/// - `Stmt::Break`
/// - `Stmt::Return`
/// - `Stmt::Raise`
/// - Call to `exit(...)`, `sys.exit(...)`, `os._exit(...)`
fn body_has_exit(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_has_exit)
}

fn stmt_has_exit(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Break(_) | Stmt::Return(_) | Stmt::Raise(_) => true,
        Stmt::Expr(e) => expr_is_exit_call(&e.value),
        // Recurse into if/try/with — they don't create a new loop scope.
        Stmt::If(s) => body_has_exit(&s.body) || body_has_exit(&s.orelse),
        Stmt::With(s) => body_has_exit(&s.body),
        Stmt::AsyncWith(s) => body_has_exit(&s.body),
        Stmt::Try(s) => {
            body_has_exit(&s.body)
                || body_has_exit(&s.orelse)
                || body_has_exit(&s.finalbody)
                || s.handlers.iter().any(|h| {
                    let rustpython_parser::ast::ExceptHandler::ExceptHandler(eh) = h;
                    body_has_exit(&eh.body)
                })
        }
        Stmt::TryStar(s) => {
            body_has_exit(&s.body)
                || s.handlers.iter().any(|h| {
                    let rustpython_parser::ast::ExceptHandler::ExceptHandler(eh) = h;
                    body_has_exit(&eh.body)
                })
        }
        // STOP descending into nested loop / fn / class bodies (and everything else).
        // Their break/return is scoped to the inner body.
        _ => false,
    }
}

/// Returns `true` if the expression is a call to a known exit function:
/// - `exit(...)` — bare name
/// - `sys.exit(...)` — attribute call on `sys`
/// - `os._exit(...)` — attribute call on `os`
fn expr_is_exit_call(expr: &Expr) -> bool {
    match expr {
        Expr::Call(call) => match &*call.func {
            Expr::Name(n) => n.id.as_str() == "exit",
            Expr::Attribute(attr) => {
                let method = attr.attr.as_str();
                if method == "exit" || method == "_exit" {
                    // Accept any receiver object named `sys` or `os`.
                    if let Expr::Name(obj) = &*attr.value {
                        return obj.id.as_str() == "sys" || obj.id.as_str() == "os";
                    }
                }
                false
            }
            _ => false,
        },
        _ => false,
    }
}

fn emit(
    range: TextRange,
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    let span = Span::new(
        ByteOffset(range.start().to_u32()),
        ByteOffset(range.end().to_u32()),
    );
    let (start_lc, end_lc) = source.span_to_linecols(span);
    findings.push(Finding {
        analyzer: AnalyzerId::new(RULE_ID),
        dimension: Dimension::Maintainability,
        rule_id: RULE_ID.to_string(),
        severity: Severity::High,
        message: "`while True:` loop has no reachable exit (`break`, `return`, \
                  `raise`, or `sys.exit`); this will spin forever (CWE-835)"
            .to_string(),
        location: Location {
            file: file_path.to_path_buf(),
            span,
            start: start_lc,
            end: end_lc,
        },
        suggestion: Some(
            "Add a `break`, `return`, or `raise` inside the loop body to ensure \
             the loop terminates. If the loop is intentionally infinite (e.g. a \
             server event loop), add a comment explaining why."
                .to_string(),
        ),
        references: vec!["https://cwe.mitre.org/data/definitions/835.html".to_string()],
        cwe: META.cwe_vec(),
        owasp: META.owasp_vec(),
    });
}

fn check_stmts(
    stmts: &[Stmt],
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    for stmt in stmts {
        check_stmt(stmt, source, file_path, findings);
    }
}

fn check_stmt(
    stmt: &Stmt,
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    match stmt {
        Stmt::While(w) => {
            if is_true_literal(&w.test) && !body_has_exit(&w.body) {
                emit(w.range(), source, file_path, findings);
            }
            // Always recurse into the body so nested `while True:` loops
            // are also checked (they are separate loop scopes).
            check_stmts(&w.body, source, file_path, findings);
            check_stmts(&w.orelse, source, file_path, findings);
        }
        // Recurse into nested scopes (same pattern as MAINT009).
        Stmt::FunctionDef(f) => check_stmts(&f.body, source, file_path, findings),
        Stmt::AsyncFunctionDef(f) => check_stmts(&f.body, source, file_path, findings),
        Stmt::ClassDef(c) => check_stmts(&c.body, source, file_path, findings),
        Stmt::If(s) => {
            check_stmts(&s.body, source, file_path, findings);
            check_stmts(&s.orelse, source, file_path, findings);
        }
        Stmt::For(s) => {
            check_stmts(&s.body, source, file_path, findings);
            check_stmts(&s.orelse, source, file_path, findings);
        }
        Stmt::AsyncFor(s) => {
            check_stmts(&s.body, source, file_path, findings);
            check_stmts(&s.orelse, source, file_path, findings);
        }
        Stmt::With(s) => check_stmts(&s.body, source, file_path, findings),
        Stmt::AsyncWith(s) => check_stmts(&s.body, source, file_path, findings),
        Stmt::Try(s) => {
            check_stmts(&s.body, source, file_path, findings);
            for handler in &s.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                check_stmts(&h.body, source, file_path, findings);
            }
            check_stmts(&s.orelse, source, file_path, findings);
            check_stmts(&s.finalbody, source, file_path, findings);
        }
        Stmt::TryStar(s) => {
            check_stmts(&s.body, source, file_path, findings);
            for handler in &s.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                check_stmts(&h.body, source, file_path, findings);
            }
        }
        Stmt::Match(m) => {
            for case in &m.cases {
                check_stmts(&case.body, source, file_path, findings);
            }
        }
        _ => {}
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::PythonLanguage;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, Language, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.py", src.as_bytes().to_vec()));
        let lang = PythonLanguage;
        let parsed = lang.parse(source).expect("parse failed");
        let analyzer = InfiniteLoopNoExitAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_while_true_no_exit() {
        let src = "x = 0\nwhile True:\n    x += 1\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn flags_outer_while_true_when_inner_while_has_break() {
        // inner break belongs to inner loop; outer has no exit
        let src = "x = 0\nwhile True:\n    while x:\n        break\n";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "outer while True with no exit should fire; got: {findings:#?}"
        );
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_while_true_with_break() {
        let src = "x = True\nwhile True:\n    if x:\n        break\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "while True with break should not fire; got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_while_true_with_return() {
        let src = "def f():\n    while True:\n        return None\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "while True with return should not fire; got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_while_not_true_literal() {
        let src = "x = 1\nwhile x > 0:\n    pass\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "while with non-True test should not fire; got: {findings:#?}"
        );
    }

    // ── CWE tag check ─────────────────────────────────────────────────────────

    #[test]
    fn cwe_tag_is_cwe_835() {
        let src = "while True:\n    pass\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].cwe.iter().any(|c| c == "CWE-835"),
            "expected CWE-835 in finding.cwe, got: {:?}",
            findings[0].cwe
        );
    }

    #[test]
    fn supported_languages_is_python_only() {
        let analyzer = InfiniteLoopNoExitAnalyzer;
        assert!(
            analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
        assert!(!analyzer.supported_languages().supports(LanguageId("rust")));
    }
}
