//! `SEC016-dangerous-function` — flags calls to inherently dangerous Python
//! built-ins and stdlib functions (CWE-242).
//!
//! # Detection
//!
//! Flags call expressions whose callee resolves to one of the following:
//!
//! - `eval(...)` — bare name call. Arbitrary code execution.
//! - `exec(...)` — bare name call. Arbitrary code execution.
//! - `os.system(...)` — attribute call. Spawns a shell and is impossible to
//!   harden against argument injection.
//!
//! # Relationship to other rules
//!
//! There is **deliberate overlap** with `SEC002-eval-sink` (CWE-94) and
//! `SEC003-shell-injection` (CWE-78). `SEC016` reports the same call sites
//! under CWE-242 ("Use of Inherently Dangerous Function"), which is the
//! taxonomy a maintenance-focused review will look for. Suppress one
//! dimension via `[rules."SEC016-dangerous-function"] severity = "ignore"`
//! if the duplicate is noisy in a given codebase.
//!
//! # Languages
//!
//! Python only.

use rustpython_parser::ast::{Expr, Stmt};
use rustpython_parser::text_size::TextRange;
use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, Span},
};

/// The stable rule ID.
const RULE_ID: &str = "SEC016-dangerous-function";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/SEC016-dangerous-function.md",
    cwe: &["CWE-242"],
    owasp: &["A03:2021"],
};

/// Analyzer that emits `SEC016-dangerous-function` for inherently dangerous
/// Python built-in and stdlib calls.
pub struct DangerousFunctionAnalyzer;

impl zuit_core::Analyzer for DangerousFunctionAnalyzer {
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
        walk_stmts(&ast.body, source, &file_path, &mut findings);
        findings
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn walk_stmts(
    stmts: &[Stmt],
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    for stmt in stmts {
        walk_stmt(stmt, source, file_path, findings);
    }
}

fn walk_stmt(
    stmt: &Stmt,
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    match stmt {
        Stmt::Expr(e) => walk_expr(&e.value, source, file_path, findings),
        Stmt::Assign(a) => walk_expr(&a.value, source, file_path, findings),
        Stmt::AugAssign(a) => walk_expr(&a.value, source, file_path, findings),
        Stmt::AnnAssign(a) => {
            if let Some(v) = &a.value {
                walk_expr(v, source, file_path, findings);
            }
        }
        Stmt::Return(r) => {
            if let Some(v) = &r.value {
                walk_expr(v, source, file_path, findings);
            }
        }
        Stmt::If(s) => {
            walk_expr(&s.test, source, file_path, findings);
            walk_stmts(&s.body, source, file_path, findings);
            walk_stmts(&s.orelse, source, file_path, findings);
        }
        Stmt::For(s) => walk_stmts(&s.body, source, file_path, findings),
        Stmt::AsyncFor(s) => walk_stmts(&s.body, source, file_path, findings),
        Stmt::While(s) => {
            walk_expr(&s.test, source, file_path, findings);
            walk_stmts(&s.body, source, file_path, findings);
        }
        Stmt::FunctionDef(f) => walk_stmts(&f.body, source, file_path, findings),
        Stmt::AsyncFunctionDef(f) => walk_stmts(&f.body, source, file_path, findings),
        Stmt::ClassDef(c) => walk_stmts(&c.body, source, file_path, findings),
        Stmt::With(s) => walk_stmts(&s.body, source, file_path, findings),
        Stmt::AsyncWith(s) => walk_stmts(&s.body, source, file_path, findings),
        Stmt::Try(s) => {
            walk_stmts(&s.body, source, file_path, findings);
            for handler in &s.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                walk_stmts(&h.body, source, file_path, findings);
            }
            walk_stmts(&s.orelse, source, file_path, findings);
            walk_stmts(&s.finalbody, source, file_path, findings);
        }
        _ => {}
    }
}

fn walk_expr(
    expr: &Expr,
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    if let Some(name) = classify_dangerous(expr) {
        let Expr::Call(call) = expr else {
            return;
        };
        emit(call.range, name, source, file_path, findings);
    }

    match expr {
        Expr::Call(call) => {
            walk_expr(&call.func, source, file_path, findings);
            for arg in &call.args {
                walk_expr(arg, source, file_path, findings);
            }
            for kw in &call.keywords {
                walk_expr(&kw.value, source, file_path, findings);
            }
        }
        Expr::BoolOp(e) => {
            for v in &e.values {
                walk_expr(v, source, file_path, findings);
            }
        }
        Expr::BinOp(e) => {
            walk_expr(&e.left, source, file_path, findings);
            walk_expr(&e.right, source, file_path, findings);
        }
        Expr::UnaryOp(e) => walk_expr(&e.operand, source, file_path, findings),
        Expr::IfExp(e) => {
            walk_expr(&e.test, source, file_path, findings);
            walk_expr(&e.body, source, file_path, findings);
            walk_expr(&e.orelse, source, file_path, findings);
        }
        Expr::Compare(e) => {
            walk_expr(&e.left, source, file_path, findings);
            for c in &e.comparators {
                walk_expr(c, source, file_path, findings);
            }
        }
        Expr::Attribute(e) => walk_expr(&e.value, source, file_path, findings),
        Expr::Subscript(e) => {
            walk_expr(&e.value, source, file_path, findings);
            walk_expr(&e.slice, source, file_path, findings);
        }
        Expr::Starred(e) => walk_expr(&e.value, source, file_path, findings),
        Expr::Await(e) => walk_expr(&e.value, source, file_path, findings),
        _ => {}
    }
}

fn classify_dangerous(expr: &Expr) -> Option<&'static str> {
    let Expr::Call(call) = expr else {
        return None;
    };
    match call.func.as_ref() {
        Expr::Name(n) => match n.id.as_str() {
            "eval" => Some("eval"),
            "exec" => Some("exec"),
            _ => None,
        },
        Expr::Attribute(a) => {
            if a.attr.as_str() == "system"
                && let Expr::Name(obj) = a.value.as_ref()
                && obj.id.as_str() == "os"
            {
                return Some("os.system");
            }
            None
        }
        _ => None,
    }
}

fn emit(
    range: TextRange,
    name: &str,
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
        dimension: Dimension::Security,
        rule_id: RULE_ID.to_string(),
        severity: Severity::Medium,
        message: format!(
            "call to inherently dangerous function `{name}` — there is no safe way to use it on untrusted input"
        ),
        location: Location {
            file: file_path.to_path_buf(),
            span,
            start: start_lc,
            end: end_lc,
        },
        suggestion: Some(
            "Replace with a safer alternative: for `eval`/`exec` use `ast.literal_eval`, \
             a parser, or explicit dispatch; for `os.system` use `subprocess.run([...], shell=False)` \
             with the command as a list of arguments."
                .to_string(),
        ),
        references: vec!["https://cwe.mitre.org/data/definitions/242.html".to_string()],
        cwe: META.cwe_vec(),
        owasp: META.owasp_vec(),
    });
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
        let parsed = PythonLanguage.parse(source).expect("parse failed");
        let analyzer = DangerousFunctionAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    #[test]
    fn flags_eval_call() {
        let src = "result = eval(user_input)\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].dimension, Dimension::Security);
        assert!(findings[0].message.contains("eval"));
    }

    #[test]
    fn flags_exec_call() {
        let src = "exec(code_str)\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("exec"));
    }

    #[test]
    fn flags_os_system_call() {
        let src = "import os\nos.system('ls -la')\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].message.contains("os.system"));
    }

    #[test]
    fn flags_nested_dangerous_call_inside_function() {
        let src = "def handler(payload):\n    return eval(payload)\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_each_dangerous_call_once() {
        let src = "import os\neval('1')\nexec('1')\nos.system('cmd')\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 3, "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_safe_alternatives() {
        let src = r#"
import ast
import subprocess

result = ast.literal_eval("[1, 2, 3]")
subprocess.run(["ls", "-la"], shell=False, check=True)
"#;
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn does_not_flag_attribute_with_different_module() {
        // `myobj.system(...)` is NOT `os.system(...)`.
        let src = "myobj.system('foo')\n";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn does_not_flag_eval_as_attribute() {
        // `model.eval()` (PyTorch idiom) is NOT the dangerous bare-name `eval`.
        let src = "model.eval()\n";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn references_include_cwe_242() {
        let src = "eval('1')\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].cwe.contains(&"CWE-242".to_string()));
    }

    #[test]
    fn supported_languages_is_python_only() {
        let analyzer = DangerousFunctionAnalyzer;
        assert!(
            analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
        assert!(!analyzer.supported_languages().supports(LanguageId("rust")));
    }
}
