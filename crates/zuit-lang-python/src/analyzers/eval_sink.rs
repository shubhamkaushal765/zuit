//! `SEC002-eval-sink` — detects bare calls to `eval`, `exec`, and `__import__`
//! in Python source files.
//!
//! # Heuristic note
//!
//! This analyzer matches **bare name** calls only (e.g. `eval(...)`,
//! `exec(...)`, `__import__(...)`). It does **not** track aliases or imports,
//! so code such as:
//! ```python
//! my_eval = eval
//! my_eval("dangerous")          # NOT detected
//! builtins.eval("dangerous")    # NOT detected
//! ```
//! will not be flagged. Full alias-tracking would require dataflow analysis,
//! which is out of scope for v1.

use rustpython_parser::ast::{Expr, Ranged, Stmt};
use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, Span},
};

/// The stable rule ID for this analyzer.
const RULE_ID: &str = "SEC002-eval-sink";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/SEC002-eval-sink.md",
    cwe: &["CWE-95"],
    owasp: &["A03:2021"],
};

/// Analyzer that emits `SEC002-eval-sink` for calls to `eval`, `exec`, and
/// `__import__` in Python source files.
///
/// Severity: **High**. These builtins execute arbitrary code at runtime and
/// are a common vector for code-injection attacks when fed user-controlled
/// input.
pub struct EvalSinkAnalyzer;

impl zuit_core::Analyzer for EvalSinkAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Security
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

// ── helpers ──────────────────────────────────────────────────────────────────

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
        Stmt::Expr(e) => check_expr(&e.value, source, file_path, findings),
        Stmt::Assign(a) => check_expr(&a.value, source, file_path, findings),
        Stmt::AugAssign(a) => check_expr(&a.value, source, file_path, findings),
        Stmt::AnnAssign(a) => {
            if let Some(v) = &a.value {
                check_expr(v, source, file_path, findings);
            }
        }
        Stmt::Return(r) => {
            if let Some(v) = &r.value {
                check_expr(v, source, file_path, findings);
            }
        }
        Stmt::FunctionDef(f) => check_stmts(&f.body, source, file_path, findings),
        Stmt::AsyncFunctionDef(f) => check_stmts(&f.body, source, file_path, findings),
        Stmt::ClassDef(c) => check_stmts(&c.body, source, file_path, findings),
        Stmt::If(s) => {
            check_expr(&s.test, source, file_path, findings);
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
        Stmt::While(s) => {
            check_expr(&s.test, source, file_path, findings);
            check_stmts(&s.body, source, file_path, findings);
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
        _ => {}
    }
}

#[allow(clippy::too_many_lines)]
fn check_expr(
    expr: &Expr,
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    match expr {
        Expr::Call(call) => {
            // Check callee for bare name match.
            if let Expr::Name(name) = call.func.as_ref() {
                let n = name.id.as_str();
                if matches!(n, "eval" | "exec" | "__import__") {
                    // Span covers the entire call expression.
                    let range = call.range();
                    let start_off = ByteOffset(range.start().to_u32());
                    let end_off = ByteOffset(range.end().to_u32());
                    let span = Span::new(start_off, end_off);
                    let (start_lc, end_lc) = source.span_to_linecols(span);
                    findings.push(Finding {
                        analyzer: AnalyzerId::new(RULE_ID),
                        dimension: Dimension::Security,
                        rule_id: RULE_ID.to_string(),
                        severity: Severity::High,
                        message: format!(
                            "call to `{n}` is a code-injection sink; \
                             never pass untrusted input"
                        ),
                        location: Location {
                            file: file_path.to_path_buf(),
                            span,
                            start: start_lc,
                            end: end_lc,
                        },
                        suggestion: Some(
                            "Replace with a safer alternative: use `ast.literal_eval` \
                             for data, or restrict the global/local namespaces if \
                             dynamic eval is truly required."
                                .to_string(),
                        ),
                        references: vec![
                            "https://cwe.mitre.org/data/definitions/95.html".to_string(),
                        ],
                        cwe: META.cwe_vec(),
                        owasp: META.owasp_vec(),
                    });
                }
            }
            // Recurse into sub-expressions.
            check_expr(&call.func, source, file_path, findings);
            for arg in &call.args {
                check_expr(arg, source, file_path, findings);
            }
            for kw in &call.keywords {
                check_expr(&kw.value, source, file_path, findings);
            }
        }
        Expr::BoolOp(e) => {
            for v in &e.values {
                check_expr(v, source, file_path, findings);
            }
        }
        Expr::BinOp(e) => {
            check_expr(&e.left, source, file_path, findings);
            check_expr(&e.right, source, file_path, findings);
        }
        Expr::UnaryOp(e) => check_expr(&e.operand, source, file_path, findings),
        Expr::Lambda(lam) => check_expr(&lam.body, source, file_path, findings),
        Expr::IfExp(e) => {
            check_expr(&e.test, source, file_path, findings);
            check_expr(&e.body, source, file_path, findings);
            check_expr(&e.orelse, source, file_path, findings);
        }
        Expr::Dict(e) => {
            for k in e.keys.iter().flatten() {
                check_expr(k, source, file_path, findings);
            }
            for v in &e.values {
                check_expr(v, source, file_path, findings);
            }
        }
        Expr::Set(e) => {
            for elt in &e.elts {
                check_expr(elt, source, file_path, findings);
            }
        }
        Expr::ListComp(e) => {
            check_expr(&e.elt, source, file_path, findings);
            for comp in &e.generators {
                check_expr(&comp.iter, source, file_path, findings);
                for cond in &comp.ifs {
                    check_expr(cond, source, file_path, findings);
                }
            }
        }
        Expr::SetComp(e) => {
            check_expr(&e.elt, source, file_path, findings);
            for comp in &e.generators {
                check_expr(&comp.iter, source, file_path, findings);
                for cond in &comp.ifs {
                    check_expr(cond, source, file_path, findings);
                }
            }
        }
        Expr::GeneratorExp(e) => {
            check_expr(&e.elt, source, file_path, findings);
            for comp in &e.generators {
                check_expr(&comp.iter, source, file_path, findings);
                for cond in &comp.ifs {
                    check_expr(cond, source, file_path, findings);
                }
            }
        }
        Expr::DictComp(e) => {
            check_expr(&e.key, source, file_path, findings);
            check_expr(&e.value, source, file_path, findings);
            for comp in &e.generators {
                check_expr(&comp.iter, source, file_path, findings);
                for cond in &comp.ifs {
                    check_expr(cond, source, file_path, findings);
                }
            }
        }
        Expr::Await(e) => check_expr(&e.value, source, file_path, findings),
        Expr::Yield(e) => {
            if let Some(v) = &e.value {
                check_expr(v, source, file_path, findings);
            }
        }
        Expr::YieldFrom(e) => check_expr(&e.value, source, file_path, findings),
        Expr::Compare(e) => {
            check_expr(&e.left, source, file_path, findings);
            for c in &e.comparators {
                check_expr(c, source, file_path, findings);
            }
        }
        Expr::Attribute(e) => check_expr(&e.value, source, file_path, findings),
        Expr::Subscript(e) => {
            check_expr(&e.value, source, file_path, findings);
            check_expr(&e.slice, source, file_path, findings);
        }
        Expr::Starred(e) => check_expr(&e.value, source, file_path, findings),
        Expr::List(e) => {
            for elt in &e.elts {
                check_expr(elt, source, file_path, findings);
            }
        }
        Expr::Tuple(e) => {
            for elt in &e.elts {
                check_expr(elt, source, file_path, findings);
            }
        }
        Expr::NamedExpr(e) => check_expr(&e.value, source, file_path, findings),
        // Leaves: Name, Constant, JoinedStr, FormattedValue, Slice — no calls.
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
        let analyzer = EvalSinkAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    #[test]
    fn zero_findings_on_healthy_fixture() {
        let src = include_str!("../../../../fixtures/python/healthy/main.py");
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected no findings on healthy fixture, got: {findings:#?}"
        );
    }

    #[test]
    fn detects_eval_in_unhealthy_fixture() {
        let src = include_str!("../../../../fixtures/python/unhealthy/main.py");
        let findings = analyze(src);
        let eval_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("`eval`"))
            .collect();
        assert!(
            !eval_findings.is_empty(),
            "expected at least one eval finding, got none. All: {findings:#?}"
        );
    }

    #[test]
    fn detects_exec_in_unhealthy_fixture() {
        let src = include_str!("../../../../fixtures/python/unhealthy/main.py");
        let findings = analyze(src);
        let exec_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("`exec`"))
            .collect();
        assert!(
            !exec_findings.is_empty(),
            "expected at least one exec finding, got none. All: {findings:#?}"
        );
    }

    #[test]
    fn at_least_two_findings_on_unhealthy() {
        let src = include_str!("../../../../fixtures/python/unhealthy/main.py");
        let findings = analyze(src);
        assert!(
            findings.len() >= 2,
            "expected >=2 findings, got {}: {findings:#?}",
            findings.len()
        );
    }

    #[test]
    fn finding_has_correct_location() {
        // "result = eval(user_input)\n"
        //  0123456789  ^-- eval starts at byte 9
        let src = "result = eval(user_input)\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected exactly 1 finding");
        let f = &findings[0];
        assert_eq!(f.rule_id, RULE_ID);
        assert_eq!(f.severity, Severity::High);
        // The span covers the full call expression eval(user_input)
        // which starts at byte 9.
        assert_eq!(f.location.span.start.0, 9, "span should start at byte 9");
        assert_eq!(f.location.start.line, 1);
    }

    #[test]
    fn detects_import_builtin() {
        let findings = analyze("mod = __import__('os')\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`__import__`"));
    }

    #[test]
    fn no_finding_for_safe_calls() {
        let findings = analyze("x = print('hello')\ny = len([1,2,3])\n");
        assert!(
            findings.is_empty(),
            "got unexpected findings: {findings:#?}"
        );
    }

    #[test]
    fn supported_languages_is_python_only() {
        let analyzer = EvalSinkAnalyzer;
        let sl = analyzer.supported_languages();
        assert!(sl.supports(LanguageId("python")));
        assert!(!sl.supports(LanguageId("rust")));
    }

    #[test]
    fn eval_finding_has_suggestion() {
        let findings = analyze("result = eval(user_input)\n");
        assert!(!findings.is_empty(), "expected at least one finding");
        assert!(
            findings[0].suggestion.is_some(),
            "eval finding should have a suggestion"
        );
    }
}
