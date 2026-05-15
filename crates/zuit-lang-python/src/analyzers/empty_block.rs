//! `MAINT013-empty-block` — flags control-flow blocks whose body is empty
//! (contains only `pass` or `...`) in Python source files.
//!
//! # Detection
//!
//! Flags `If`, `For`, `While`, and `Try` statements whose body is a single
//! `Pass` statement or a single `Constant::Ellipsis` expression statement.
//!
//! # Skips
//!
//! - Methods decorated with `@abstractmethod` or `@overload`.
//! - Bodies that are ellipsis-only inside a class derived from `Protocol`.
//!   (Best-effort: checks the enclosing class bases for the name `Protocol`.)
//! - `For`/`While` `orelse` clauses (they are rarely empty and not a smell).

use rustpython_parser::ast::{
    Constant, Expr, ExprConstant, Ranged, Stmt, StmtExpr, StmtFor, StmtIf, StmtTry, StmtWhile,
};
use rustpython_parser::text_size::TextRange;
use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, Span},
};

/// The stable rule ID.
const RULE_ID: &str = "MAINT013-empty-block";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/MAINT013-empty-block.md",
    cwe: &["CWE-1071"],
    owasp: &[],
};

/// Analyzer that emits `MAINT013-empty-block` for empty control-flow blocks
/// in Python source files.
///
/// Severity: **Low**. Empty `if`/`for`/`while`/`try` blocks are almost always
/// leftover scaffolding or forgotten logic branches and reduce code clarity.
pub struct EmptyBlockAnalyzer;

impl zuit_core::Analyzer for EmptyBlockAnalyzer {
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

/// Returns `true` if `stmts` is a body that counts as "empty" for this rule:
/// - Single `pass` statement.
/// - Single expression statement whose value is `...` (Ellipsis).
fn is_empty_body(stmts: &[Stmt]) -> bool {
    match stmts {
        [Stmt::Pass(_)] => true,
        [Stmt::Expr(StmtExpr { value, .. })] => {
            if let Expr::Constant(ExprConstant {
                value: Constant::Ellipsis,
                ..
            }) = value.as_ref()
            {
                return true;
            }
            false
        }
        _ => false,
    }
}

/// Returns `true` if any decorator in `decorator_list` is `abstractmethod` or
/// `overload` (bare name or `abc.abstractmethod` / `typing.overload`).
fn has_stub_decorator(decorators: &[Expr]) -> bool {
    decorators.iter().any(|d| match d {
        Expr::Name(n) => matches!(n.id.as_str(), "abstractmethod" | "overload"),
        Expr::Attribute(a) => matches!(a.attr.as_str(), "abstractmethod" | "overload"),
        _ => false,
    })
}

/// Returns `true` if the class body contains a base named `Protocol`
/// (bare or `typing.Protocol`).
fn class_derives_protocol(bases: &[Expr]) -> bool {
    bases.iter().any(|b| match b {
        Expr::Name(n) => n.id.as_str() == "Protocol",
        Expr::Attribute(a) => a.attr.as_str() == "Protocol",
        _ => false,
    })
}

fn emit(
    stmt_range: TextRange,
    kind: &str,
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    let start_off = ByteOffset(stmt_range.start().to_u32());
    let end_off = ByteOffset(stmt_range.end().to_u32());
    let span = Span::new(start_off, end_off);
    let (start_lc, end_lc) = source.span_to_linecols(span);
    findings.push(Finding {
        analyzer: AnalyzerId::new(RULE_ID),
        dimension: Dimension::Maintainability,
        rule_id: RULE_ID.to_string(),
        severity: Severity::Low,
        message: format!(
            "empty `{kind}` body — add implementation or a `pass` comment explaining the intent"
        ),
        location: Location {
            file: file_path.to_path_buf(),
            span,
            start: start_lc,
            end: end_lc,
        },
        suggestion: Some(
            "Either fill in the block body or add an explanatory comment to `pass`.".to_string(),
        ),
        references: vec!["https://cwe.mitre.org/data/definitions/1071.html".to_string()],
        cwe: META.cwe_vec(),
        owasp: META.owasp_vec(),
    });
}

fn check_stmts(
    stmts: &[Stmt],
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    in_protocol_class: bool,
    findings: &mut Vec<Finding>,
) {
    for stmt in stmts {
        check_stmt(stmt, source, file_path, in_protocol_class, findings);
    }
}

#[allow(clippy::too_many_lines, clippy::collapsible_match)]
fn check_stmt(
    stmt: &Stmt,
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    in_protocol_class: bool,
    findings: &mut Vec<Finding>,
) {
    match stmt {
        Stmt::If(StmtIf {
            body, orelse, test, ..
        }) => {
            if is_empty_body(body) {
                emit(test.range(), "if", source, file_path, findings);
            } else {
                check_stmts(body, source, file_path, in_protocol_class, findings);
            }
            // recurse into else/elif chain
            check_stmts(orelse, source, file_path, in_protocol_class, findings);
        }

        Stmt::For(StmtFor { body, target, .. }) => {
            if is_empty_body(body) {
                emit(target.range(), "for", source, file_path, findings);
            } else {
                check_stmts(body, source, file_path, in_protocol_class, findings);
            }
        }

        Stmt::While(StmtWhile { body, test, .. }) => {
            if is_empty_body(body) {
                emit(test.range(), "while", source, file_path, findings);
            } else {
                check_stmts(body, source, file_path, in_protocol_class, findings);
            }
        }

        Stmt::Try(StmtTry {
            body,
            handlers,
            orelse,
            finalbody,
            ..
        }) => {
            if is_empty_body(body) {
                // Emit on the first keyword position of the try; best effort is
                // to use the range of the first handler or the whole try range.
                if let Some(handler) = handlers.first() {
                    let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                    emit(h.range(), "try", source, file_path, findings);
                }
            } else {
                check_stmts(body, source, file_path, in_protocol_class, findings);
            }
            for handler in handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                check_stmts(&h.body, source, file_path, in_protocol_class, findings);
            }
            check_stmts(orelse, source, file_path, in_protocol_class, findings);
            check_stmts(finalbody, source, file_path, in_protocol_class, findings);
        }

        // Functions: recurse into body, but skip if decorated with stub decorators
        // or if we are inside a Protocol class (ellipsis bodies are intentional).
        Stmt::FunctionDef(f) => {
            if !(has_stub_decorator(&f.decorator_list)
                || in_protocol_class && is_empty_body(&f.body))
            {
                check_stmts(&f.body, source, file_path, false, findings);
            }
        }

        Stmt::AsyncFunctionDef(f) => {
            if !(has_stub_decorator(&f.decorator_list)
                || in_protocol_class && is_empty_body(&f.body))
            {
                check_stmts(&f.body, source, file_path, false, findings);
            }
        }

        Stmt::ClassDef(c) => {
            let is_protocol = class_derives_protocol(&c.bases);
            check_stmts(&c.body, source, file_path, is_protocol, findings);
        }

        Stmt::With(s) => {
            check_stmts(&s.body, source, file_path, in_protocol_class, findings);
        }
        Stmt::AsyncWith(s) => {
            check_stmts(&s.body, source, file_path, in_protocol_class, findings);
        }
        Stmt::AsyncFor(s) => {
            if is_empty_body(&s.body) {
                emit(s.target.range(), "for", source, file_path, findings);
            } else {
                check_stmts(&s.body, source, file_path, in_protocol_class, findings);
            }
        }
        // Other statements have no block bodies to check.
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
        let analyzer = EmptyBlockAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_empty_if_body() {
        let src = "x = 1\nif x:\n    pass\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_empty_if_with_ellipsis() {
        let src = "x = 1\nif x:\n    ...\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_empty_for_body() {
        let src = "for i in range(10):\n    pass\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_empty_while_body() {
        let src = "while True:\n    pass\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_nonempty_if() {
        let src = "x = 1\nif x:\n    print(x)\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected no findings, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_nonempty_for() {
        let src = "for i in range(10):\n    print(i)\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected no findings, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_abstractmethod_body() {
        let src = "from abc import abstractmethod\nclass Base:\n    @abstractmethod\n    def foo(self) -> None:\n        pass\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "abstractmethod body should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_overload_body() {
        let src = "from typing import overload\nclass Foo:\n    @overload\n    def bar(self, x: int) -> int:\n        ...\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "overload body should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_protocol_method_body() {
        let src = "from typing import Protocol\nclass MyProto(Protocol):\n    def method(self) -> None:\n        ...\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "Protocol method body should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn supported_languages_is_python_only() {
        let analyzer = EmptyBlockAnalyzer;
        assert!(
            analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
        assert!(!analyzer.supported_languages().supports(LanguageId("rust")));
    }
}
