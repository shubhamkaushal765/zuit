//! `MAINT016-unreachable-code` — flags statements that appear after a
//! terminating statement in the same block (Python).
//!
//! # Detection
//!
//! Recursively walks every function/method body via the live `ModModule` AST
//! (Python retains the full parsed tree).  For each block (`Vec<Stmt>`), we
//! find the first terminating statement and report the first following
//! statement as dead code — unless it is a `pass` statement (which is
//! idiomatic and already covered by ruff).
//!
//! # Terminating statements (Python)
//!
//! - `Stmt::Return`
//! - `Stmt::Raise`
//! - `Stmt::Break`
//! - `Stmt::Continue`
//!
//! # Scope
//!
//! The rule fires only within a single flat block.  Dead code after
//! `if cond: return` in the *outer* block is not flagged (reachable when
//! `cond` is false).  Nested function bodies are walked recursively.
//!
//! # CWE
//!
//! CWE-561 (Dead Code).

use rustpython_parser::ast::{Ranged, Stmt};
use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, Span},
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
/// a terminating statement in the same Python block.
pub struct UnreachableCodeAnalyzer;

impl zuit_core::Analyzer for UnreachableCodeAnalyzer {
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
        let Some(module) = crate::try_python_ast(file) else {
            return Vec::new();
        };

        let source = file.source();
        let file_path = source.path.clone();

        let mut findings = Vec::new();
        collect_from_stmts(&module.body, &mut findings);

        findings
            .into_iter()
            .map(|span| {
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
                         `return`, `raise`, `break`, or `continue` precedes it in the same block."
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

// ── helpers ───────────────────────────────────────────────────────────────────

/// Walk module-level statements, recursing into structural containers and
/// function/class bodies.
fn collect_from_stmts(stmts: &[Stmt], out: &mut Vec<Span>) {
    for stmt in stmts {
        collect_from_stmt(stmt, out);
    }
}

fn collect_from_stmt(stmt: &Stmt, out: &mut Vec<Span>) {
    match stmt {
        // Recurse into function and async function bodies.
        Stmt::FunctionDef(f) => {
            check_block(&f.body, out);
            collect_from_stmts(&f.body, out);
        }
        Stmt::AsyncFunctionDef(f) => {
            check_block(&f.body, out);
            collect_from_stmts(&f.body, out);
        }
        // Class body may contain methods.
        Stmt::ClassDef(c) => {
            collect_from_stmts(&c.body, out);
        }
        // Structural containers: recurse without checking the container itself.
        Stmt::If(s) => {
            check_block(&s.body, out);
            collect_from_stmts(&s.body, out);
            check_block(&s.orelse, out);
            collect_from_stmts(&s.orelse, out);
        }
        Stmt::For(s) => {
            check_block(&s.body, out);
            collect_from_stmts(&s.body, out);
            check_block(&s.orelse, out);
            collect_from_stmts(&s.orelse, out);
        }
        Stmt::AsyncFor(s) => {
            check_block(&s.body, out);
            collect_from_stmts(&s.body, out);
            check_block(&s.orelse, out);
            collect_from_stmts(&s.orelse, out);
        }
        Stmt::While(s) => {
            check_block(&s.body, out);
            collect_from_stmts(&s.body, out);
            check_block(&s.orelse, out);
            collect_from_stmts(&s.orelse, out);
        }
        Stmt::With(s) => {
            check_block(&s.body, out);
            collect_from_stmts(&s.body, out);
        }
        Stmt::AsyncWith(s) => {
            check_block(&s.body, out);
            collect_from_stmts(&s.body, out);
        }
        Stmt::Try(s) => {
            check_block(&s.body, out);
            collect_from_stmts(&s.body, out);
            for handler in &s.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                check_block(&h.body, out);
                collect_from_stmts(&h.body, out);
            }
            check_block(&s.orelse, out);
            collect_from_stmts(&s.orelse, out);
            check_block(&s.finalbody, out);
            collect_from_stmts(&s.finalbody, out);
        }
        Stmt::TryStar(s) => {
            check_block(&s.body, out);
            collect_from_stmts(&s.body, out);
            for handler in &s.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                check_block(&h.body, out);
                collect_from_stmts(&h.body, out);
            }
        }
        _ => {}
    }
}

/// Returns `true` if `stmt` is a terminating statement.
fn is_terminating(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Return(_) | Stmt::Raise(_) | Stmt::Break(_) | Stmt::Continue(_)
    )
}

/// Returns `true` if `stmt` is a `pass` statement.
fn is_pass(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Pass(_))
}

/// Scans `block` for the first terminating statement and, if a non-pass
/// statement follows it, pushes the span of that first dead statement onto
/// `out`.
fn check_block(block: &[Stmt], out: &mut Vec<Span>) {
    let Some(term_idx) = block.iter().position(is_terminating) else {
        return;
    };
    // Find the first non-pass statement after the terminator.
    let first_dead = block[term_idx + 1..].iter().find(|s| !is_pass(s));
    if let Some(dead_stmt) = first_dead {
        let range = dead_stmt.range();
        out.push(Span::new(
            ByteOffset(range.start().to_u32()),
            ByteOffset(range.end().to_u32()),
        ));
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
        let analyzer = UnreachableCodeAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_stmt_after_return() {
        let src = "
def f():
    return 1
    x = 2
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn flags_stmt_after_raise() {
        let src = "
def f():
    raise ValueError('x')
    print(1)
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_stmt_after_break_in_while_body() {
        let src = "
def f():
    while True:
        break
        x = 1
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn no_finding_for_if_with_return_in_branch() {
        // `if cond: return 1` → 0 findings (outer block is reached when cond is false)
        let src = "
def f(cond):
    if cond:
        return 1
    return 2
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "return inside if-branch should not flag outer stmt, got: {findings:#?}"
        );
    }

    #[test]
    fn pass_after_return_is_not_flagged() {
        // `pass` after `return` is idiomatic / commonly generated; do not flag.
        let src = "
def f():
    return 1
    pass
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "pass after return should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn nested_function_dead_code_flagged() {
        let src = "
def outer():
    def inner():
        return 1
        x = 2
    return inner
";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for dead code in inner fn, got: {findings:#?}"
        );
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn no_finding_when_no_dead_code() {
        let src = "
def f():
    x = 1
    return x
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "no dead code → 0 findings, got: {findings:#?}"
        );
    }

    #[test]
    fn supported_languages_is_python_only() {
        let analyzer = UnreachableCodeAnalyzer;
        assert!(
            analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
        assert!(!analyzer.supported_languages().supports(LanguageId("rust")));
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("javascript"))
        );
    }
}
