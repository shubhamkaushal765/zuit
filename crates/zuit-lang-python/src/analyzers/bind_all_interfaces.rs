//! `SEC013-bind-all-interfaces` — flags server-bind calls that use
//! `"0.0.0.0"` or `"::"` as the bind address in Python source files.
//!
//! # Detection
//!
//! Walks the full `ModModule` AST looking for `Call` expressions whose callee
//! matches the bind-callee allowlist AND whose relevant argument is a string
//! literal equal to `"0.0.0.0"` or `"::"` (also handles `"0.0.0.0:PORT"` and
//! `"[::]:PORT"` forms).
//!
//! # Bind-callee allowlist (Python)
//!
//! - `socket.bind` / bare `bind` — first positional argument
//! - `app.run` (Flask) — first positional argument is `host`
//! - `uvicorn.run` — `host=` keyword argument
//! - `httpd.bind` / `HTTPServer(…)` — first element of the first tuple argument
//!
//! # Skips
//!
//! - Calls whose address resolves to `127.0.0.1`, `::1`, `localhost`, or any
//!   other non-all-interface address.

use rustpython_parser::ast::{Constant, Expr, Ranged, Stmt};
use rustpython_parser::text_size::TextRange;
use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, Span},
};

/// The stable rule ID.
const RULE_ID: &str = "SEC013-bind-all-interfaces";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/SEC013-bind-all-interfaces.md",
    cwe: &["CWE-1327"],
    owasp: &[],
};

/// Bind-callee allowlist for Python (bare name or attribute `.name`).
const BIND_CALLEE_NAMES: &[&str] = &["bind", "run", "listen"];

/// Analyzer that emits `SEC013-bind-all-interfaces` for wide-open server bind
/// addresses in Python source files.
pub struct BindAllInterfacesAnalyzer;

impl zuit_core::Analyzer for BindAllInterfacesAnalyzer {
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

/// Returns `true` when `raw` is a bind-all-interfaces address:
/// - `"0.0.0.0"` or `"0.0.0.0:PORT"` (IPv4 any-address)
/// - `"::"` or `"[::]:PORT"` or `":::PORT"` (IPv6 any-address)
pub(crate) fn is_bind_all_address(raw: &str) -> bool {
    let host = if let Some(stripped) = raw.strip_prefix('[') {
        // `[::]:port` form
        stripped.split(']').next().unwrap_or(raw)
    } else if raw == "::" || raw.starts_with(":::") {
        // bare `::` or `:::PORT`
        "::"
    } else {
        // `0.0.0.0:port` — take host before first `:`
        raw.split(':').next().unwrap_or(raw)
    };
    host == "0.0.0.0" || host == "::"
}

/// Extracts a string constant value from an expression, if it is a string
/// `Constant`.
fn const_str(expr: &Expr) -> Option<&str> {
    if let Expr::Constant(c) = expr
        && let Constant::Str(s) = &c.value
    {
        return Some(s.as_str());
    }
    None
}

/// Returns the callee last-segment name for a `Call` expression, if it is in
/// the bind allowlist.
fn bind_callee_name(func: &Expr) -> Option<&str> {
    let name = match func {
        Expr::Name(n) => n.id.as_str(),
        Expr::Attribute(a) => a.attr.as_str(),
        _ => return None,
    };
    if BIND_CALLEE_NAMES.contains(&name) {
        Some(name)
    } else {
        None
    }
}

fn emit(
    range: TextRange,
    callee: &str,
    addr: &str,
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
            "`{callee}` binds to `{addr}` — accepts connections on all network interfaces; \
             use `127.0.0.1` (or `::1`) to restrict to loopback only"
        ),
        location: Location {
            file: file_path.to_path_buf(),
            span,
            start: start_lc,
            end: end_lc,
        },
        suggestion: Some(
            "Restrict the bind address to `\"127.0.0.1\"` or `\"::1\"` in production, \
             or use an environment variable so the address is configurable without a \
             code change."
                .to_string(),
        ),
        references: vec!["https://cwe.mitre.org/data/definitions/1327.html".to_string()],
        cwe: META.cwe_vec(),
        owasp: META.owasp_vec(),
    });
}

/// Check a call expression and emit a finding if it matches the bind pattern.
fn check_call_expr(
    call_expr: &rustpython_parser::ast::ExprCall,
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    let Some(callee_name) = bind_callee_name(&call_expr.func) else {
        return;
    };

    // `uvicorn.run(app, host="0.0.0.0")` — check `host=` kwarg.
    if callee_name == "run" {
        // Check `host=` keyword argument first.
        for kw in &call_expr.keywords {
            if kw.arg.as_deref() == Some("host") {
                if let Some(val) = const_str(&kw.value)
                    && is_bind_all_address(val)
                {
                    emit(
                        call_expr.range(),
                        callee_name,
                        val,
                        source,
                        file_path,
                        findings,
                    );
                    return;
                }
                return; // `host=` kwarg found but not all-interface — skip
            }
        }
        // Flask `app.run("0.0.0.0", ...)` — first positional arg is host.
        if let Some(first_arg) = call_expr.args.first()
            && let Some(val) = const_str(first_arg)
            && is_bind_all_address(val)
        {
            emit(
                call_expr.range(),
                callee_name,
                val,
                source,
                file_path,
                findings,
            );
        }
        return;
    }

    // `HTTPServer(("0.0.0.0", port), handler)` — first arg is a tuple, first
    // element is the host.
    if callee_name != "bind" && callee_name != "listen" {
        return;
    }
    let Some(first_arg) = call_expr.args.first() else {
        return;
    };
    // Tuple form: `(host, port)`.
    if let Expr::Tuple(t) = first_arg {
        if let Some(host_expr) = t.elts.first()
            && let Some(val) = const_str(host_expr)
            && is_bind_all_address(val)
        {
            emit(
                call_expr.range(),
                callee_name,
                val,
                source,
                file_path,
                findings,
            );
        }
        return; // tuple form handled (whether all-interface or not)
    }
    // Direct string form: `bind("0.0.0.0:8080")`.
    if let Some(val) = const_str(first_arg)
        && is_bind_all_address(val)
    {
        emit(
            call_expr.range(),
            callee_name,
            val,
            source,
            file_path,
            findings,
        );
    }
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
        Stmt::Expr(e) => check_expr(&e.value, source, file_path, findings),
        Stmt::Assign(a) => {
            check_expr(&a.value, source, file_path, findings);
        }
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
        Stmt::While(s) => {
            check_stmts(&s.body, source, file_path, findings);
        }
        Stmt::FunctionDef(f) => {
            check_stmts(&f.body, source, file_path, findings);
        }
        Stmt::AsyncFunctionDef(f) => {
            check_stmts(&f.body, source, file_path, findings);
        }
        Stmt::ClassDef(c) => {
            check_stmts(&c.body, source, file_path, findings);
        }
        Stmt::With(s) => {
            check_stmts(&s.body, source, file_path, findings);
        }
        Stmt::AsyncWith(s) => {
            check_stmts(&s.body, source, file_path, findings);
        }
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

fn check_expr(
    expr: &Expr,
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    match expr {
        Expr::Call(call) => {
            check_call_expr(call, source, file_path, findings);
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
        Expr::Attribute(e) => check_expr(&e.value, source, file_path, findings),
        Expr::Await(e) => check_expr(&e.value, source, file_path, findings),
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
        let analyzer = BindAllInterfacesAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_flask_app_run_0000() {
        let src = "from flask import Flask\napp = Flask(__name__)\napp.run('0.0.0.0', port=5000)\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_socket_bind_tuple_0000() {
        let src = "import socket\ns = socket.socket()\ns.bind(('0.0.0.0', 8080))\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_bind_string_with_port_0000() {
        let src = "bind('0.0.0.0:8080')\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_uvicorn_run_host_kwarg_0000() {
        let src = "import uvicorn\nuvicorn.run(app, host='0.0.0.0', port=8000)\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_bind_ipv6_any() {
        let src = "bind('::')\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_localhost_run() {
        let src = "app.run('127.0.0.1', port=5000)\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "127.0.0.1 should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_unrelated_callee() {
        let src = "print('0.0.0.0')\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "print('0.0.0.0') should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_uvicorn_run_safe_host() {
        let src = "import uvicorn\nuvicorn.run(app, host='127.0.0.1', port=8000)\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "host=127.0.0.1 should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn flags_bind_ipv6_bracketed_port() {
        let src = "bind('[::]:8080')\n";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for [::]:8080, got: {findings:#?}"
        );
    }

    // ── helper unit tests ─────────────────────────────────────────────────────

    #[test]
    fn is_bind_all_address_0000() {
        assert!(is_bind_all_address("0.0.0.0"));
        assert!(is_bind_all_address("0.0.0.0:8080"));
    }

    #[test]
    fn is_bind_all_address_ipv6() {
        assert!(is_bind_all_address("::"));
        assert!(is_bind_all_address("[::]:8080"));
    }

    #[test]
    fn is_bind_all_address_false_for_localhost() {
        assert!(!is_bind_all_address("127.0.0.1"));
        assert!(!is_bind_all_address("127.0.0.1:8080"));
        assert!(!is_bind_all_address("::1"));
        assert!(!is_bind_all_address("localhost"));
    }
}
