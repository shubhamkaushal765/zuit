//! `SEC015-log-injection` — flags logging calls that may concatenate untrusted
//! input without sanitization, enabling log injection (CWE-117).
//!
//! # Detection
//!
//! Walks the full `ModModule` AST recursively, tracking enclosing function
//! parameters. A finding fires when ALL of:
//!
//! 1. The call is a known logging function:
//!    `logger.debug`, `logger.info`, `logger.warning`, `logger.error`,
//!    `logger.critical`, `logger.exception`, `logger.log`,
//!    `logging.debug`, `logging.info`, `logging.warning`, `logging.error`,
//!    `logging.critical`, `logging.exception`, `logging.log`,
//!    `log.debug`, `log.info`, `log.warning`, `log.error`, etc.
//!
//! 2. The first argument is a string or bytes literal/template containing a
//!    placeholder marker: `{}`, `%s`, `%d`, `%r`, `%v`.
//!    OR the first argument is not a string literal and there are ≥ 2 args
//!    (best-effort concatenation).
//!
//! 3. A subsequent argument (leading identifier) is EITHER:
//!    - In the request-style allowlist (case-insensitive):
//!      `req`, `request`, `params`, `body`, `query`, `ctx`, `context`,
//!      `input`, `user_input`, `payload`, `headers`, `cookies`, `args`,
//!      `kwargs`, `event`, `data`
//!    - OR appears in the immediately enclosing function's parameter list.

use rustpython_parser::ast::{Expr, ExprAttribute, ExprCall, Ranged, Stmt};
use rustpython_parser::text_size::TextRange;
use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, Span},
};

/// The stable rule ID.
const RULE_ID: &str = "SEC015-log-injection";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/SEC015-log-injection.md",
    cwe: &["CWE-117"],
    owasp: &[],
};

/// Known logging object names (case-insensitive last segment).
const LOG_OBJECT_NAMES: &[&str] = &["logger", "logging", "log"];

/// Known logging method names.
const LOG_METHOD_NAMES: &[&str] = &[
    "debug",
    "info",
    "warning",
    "error",
    "critical",
    "exception",
    "log",
];

/// Placeholder markers that indicate format-string interpolation.
const PLACEHOLDER_MARKERS: &[&str] = &["%s", "%d", "%r", "%v", "{}"];

/// Request-style identifier names (case-insensitive).
const REQUEST_LIKE: &[&str] = &[
    "req",
    "request",
    "params",
    "body",
    "query",
    "ctx",
    "context",
    "input",
    "user_input",
    "payload",
    "headers",
    "cookies",
    "args",
    "kwargs",
    "event",
    "data",
];

/// Returns `true` when `name` (lowercased) is request-like.
fn is_request_like(name: &str) -> bool {
    let lower = name.to_lowercase();
    REQUEST_LIKE.iter().any(|&r| r == lower)
}

/// Returns `true` when `s` contains a placeholder marker.
fn has_placeholder(s: &str) -> bool {
    PLACEHOLDER_MARKERS.iter().any(|&m| s.contains(m))
}

/// Extracts the leading identifier name from an expression.
///
/// For `req`, returns `"req"`.
/// For `req.body`, returns `"req"`.
/// For `req.body.strip()`, returns `"req"`.
fn leading_ident(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Name(n) => Some(n.id.as_str()),
        Expr::Attribute(a) => leading_ident(&a.value),
        Expr::Call(c) => leading_ident(&c.func),
        Expr::Subscript(s) => leading_ident(&s.value),
        _ => None,
    }
}

/// Returns `true` if the call expression is a known logging function.
fn is_log_call(call: &ExprCall) -> bool {
    let Expr::Attribute(attr) = call.func.as_ref() else {
        return false;
    };
    let ExprAttribute {
        value,
        attr: method,
        ..
    } = attr;
    // Check method name
    let method_name = method.as_str();
    if !LOG_METHOD_NAMES.contains(&method_name) {
        return false;
    }
    // Check object name (last segment)
    let obj_name = match value.as_ref() {
        Expr::Name(n) => n.id.as_str().to_lowercase(),
        Expr::Attribute(a) => a.attr.as_str().to_lowercase(),
        _ => return false,
    };
    LOG_OBJECT_NAMES.iter().any(|&n| n == obj_name)
}

/// Checks whether the first arg has a placeholder or is a non-string (best-effort).
///
/// Also returns `true` when the first arg is a `.format(...)` call on a string
/// literal containing `{}` — handles `logger.info("msg {}".format(req.body))`.
fn first_arg_has_placeholder(call: &ExprCall) -> bool {
    let Some(first) = call.args.first() else {
        return false;
    };
    match first {
        Expr::Constant(c) => {
            if let rustpython_parser::ast::Constant::Str(s) = &c.value {
                has_placeholder(s)
            } else {
                false
            }
        }
        // JoinedStr (f-string) — treat as having a placeholder if it has any values
        Expr::JoinedStr(j) => !j.values.is_empty(),
        // `"template {}".format(arg)` — method call on a string literal containing `{}`
        Expr::Call(inner_call) => {
            if let Expr::Attribute(attr) = inner_call.func.as_ref()
                && attr.attr.as_str() == "format"
                && let Expr::Constant(c) = attr.value.as_ref()
                && let rustpython_parser::ast::Constant::Str(s) = &c.value
            {
                return has_placeholder(s);
            }
            // Non-string first arg with ≥2 total args: best-effort
            call.args.len() >= 2
        }
        // Non-string first arg with ≥2 total args: best-effort
        _ => call.args.len() >= 2,
    }
}

/// Returns the leading identifier of a subsequent argument if it is
/// request-like or in `fn_params`.
///
/// Also inspects `.format(...)` arguments embedded in the first arg.
fn has_tainted_arg(call: &ExprCall, fn_params: &[String]) -> bool {
    // Special case: `logger.info("msg {}".format(req.body))` — first arg is the format call
    if let Some(first) = call.args.first()
        && let Expr::Call(inner_call) = first
        && let Expr::Attribute(attr) = inner_call.func.as_ref()
        && attr.attr.as_str() == "format"
    {
        // Check args of the inner .format() call
        for arg in &inner_call.args {
            if let Some(ident) = leading_ident(arg) {
                let lower = ident.to_lowercase();
                if is_request_like(&lower) {
                    return true;
                }
                if fn_params.iter().any(|p| p.as_str() == ident) {
                    return true;
                }
            }
        }
        for kw in &inner_call.keywords {
            if let Some(ident) = leading_ident(&kw.value) {
                let lower = ident.to_lowercase();
                if is_request_like(&lower) {
                    return true;
                }
                if fn_params.iter().any(|p| p.as_str() == ident) {
                    return true;
                }
            }
        }
    }

    // Check args after the first (standard case: logger.info("msg %s", req))
    for arg in call.args.iter().skip(1) {
        if let Some(ident) = leading_ident(arg) {
            let lower = ident.to_lowercase();
            if is_request_like(&lower) {
                return true;
            }
            if fn_params.iter().any(|p| p.as_str() == ident) {
                return true;
            }
        }
    }
    // Also check keyword args
    for kw in &call.keywords {
        if let Some(ident) = leading_ident(&kw.value) {
            let lower = ident.to_lowercase();
            if is_request_like(&lower) {
                return true;
            }
            if fn_params.iter().any(|p| p.as_str() == ident) {
                return true;
            }
        }
    }
    false
}

/// Analyzer that emits `SEC015-log-injection` for potential log injection
/// vulnerabilities in Python source files.
pub struct LogInjectionAnalyzer;

impl zuit_core::Analyzer for LogInjectionAnalyzer {
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

        check_stmts(&ast.body, &[], source, &file_path, &mut findings);
        findings
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

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
        dimension: Dimension::Security,
        rule_id: RULE_ID.to_string(),
        severity: Severity::Medium,
        message: "log injection: logging call passes unsanitized user-controlled input; \
                  sanitize or escape the value before logging"
            .to_string(),
        location: Location {
            file: file_path.to_path_buf(),
            span,
            start: start_lc,
            end: end_lc,
        },
        suggestion: Some(
            "Sanitize input before logging: strip newlines and control characters, \
             or use structured logging fields instead of format strings."
                .to_string(),
        ),
        references: vec!["https://cwe.mitre.org/data/definitions/117.html".to_string()],
        cwe: META.cwe_vec(),
        owasp: META.owasp_vec(),
    });
}

fn check_stmts(
    stmts: &[Stmt],
    fn_params: &[String],
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    for stmt in stmts {
        check_stmt(stmt, fn_params, source, file_path, findings);
    }
}

fn check_stmt(
    stmt: &Stmt,
    fn_params: &[String],
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    match stmt {
        Stmt::Expr(e) => {
            check_expr(&e.value, fn_params, source, file_path, findings);
        }
        Stmt::Assign(a) => {
            check_expr(&a.value, fn_params, source, file_path, findings);
        }
        Stmt::AnnAssign(a) => {
            if let Some(val) = &a.value {
                check_expr(val, fn_params, source, file_path, findings);
            }
        }
        Stmt::FunctionDef(f) => {
            // Collect this function's parameter names for inner scope
            let params = collect_fn_params(&f.args);
            check_stmts(&f.body, &params, source, file_path, findings);
            // Also check decorators at outer scope
            for dec in &f.decorator_list {
                check_expr(dec, fn_params, source, file_path, findings);
            }
        }
        Stmt::AsyncFunctionDef(f) => {
            let params = collect_fn_params(&f.args);
            check_stmts(&f.body, &params, source, file_path, findings);
            for dec in &f.decorator_list {
                check_expr(dec, fn_params, source, file_path, findings);
            }
        }
        Stmt::ClassDef(c) => check_stmts(&c.body, fn_params, source, file_path, findings),
        Stmt::If(s) => {
            check_expr(&s.test, fn_params, source, file_path, findings);
            check_stmts(&s.body, fn_params, source, file_path, findings);
            check_stmts(&s.orelse, fn_params, source, file_path, findings);
        }
        Stmt::For(s) => {
            check_stmts(&s.body, fn_params, source, file_path, findings);
            check_stmts(&s.orelse, fn_params, source, file_path, findings);
        }
        Stmt::AsyncFor(s) => {
            check_stmts(&s.body, fn_params, source, file_path, findings);
            check_stmts(&s.orelse, fn_params, source, file_path, findings);
        }
        Stmt::While(s) => {
            check_stmts(&s.body, fn_params, source, file_path, findings);
        }
        Stmt::With(s) => check_stmts(&s.body, fn_params, source, file_path, findings),
        Stmt::AsyncWith(s) => check_stmts(&s.body, fn_params, source, file_path, findings),
        Stmt::Return(r) => {
            if let Some(val) = &r.value {
                check_expr(val, fn_params, source, file_path, findings);
            }
        }
        Stmt::Try(s) => {
            check_stmts(&s.body, fn_params, source, file_path, findings);
            for handler in &s.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                check_stmts(&h.body, fn_params, source, file_path, findings);
            }
            check_stmts(&s.orelse, fn_params, source, file_path, findings);
            check_stmts(&s.finalbody, fn_params, source, file_path, findings);
        }
        Stmt::TryStar(s) => {
            check_stmts(&s.body, fn_params, source, file_path, findings);
            for handler in &s.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                check_stmts(&h.body, fn_params, source, file_path, findings);
            }
        }
        _ => {}
    }
}

fn check_expr(
    expr: &Expr,
    fn_params: &[String],
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    match expr {
        Expr::Call(call) => {
            // Check if it's a logging call
            if is_log_call(call)
                && first_arg_has_placeholder(call)
                && has_tainted_arg(call, fn_params)
            {
                emit(call.range(), source, file_path, findings);
            }
            // Recurse into sub-expressions (args, keyword args, func)
            check_expr(&call.func, fn_params, source, file_path, findings);
            for arg in &call.args {
                check_expr(arg, fn_params, source, file_path, findings);
            }
            for kw in &call.keywords {
                check_expr(&kw.value, fn_params, source, file_path, findings);
            }
        }
        Expr::Attribute(a) => check_expr(&a.value, fn_params, source, file_path, findings),
        Expr::BoolOp(b) => {
            for val in &b.values {
                check_expr(val, fn_params, source, file_path, findings);
            }
        }
        Expr::BinOp(b) => {
            check_expr(&b.left, fn_params, source, file_path, findings);
            check_expr(&b.right, fn_params, source, file_path, findings);
        }
        Expr::IfExp(i) => {
            check_expr(&i.test, fn_params, source, file_path, findings);
            check_expr(&i.body, fn_params, source, file_path, findings);
            check_expr(&i.orelse, fn_params, source, file_path, findings);
        }
        Expr::Dict(d) => {
            for key in d.keys.iter().flatten() {
                check_expr(key, fn_params, source, file_path, findings);
            }
            for val in &d.values {
                check_expr(val, fn_params, source, file_path, findings);
            }
        }
        Expr::List(l) => {
            for elt in &l.elts {
                check_expr(elt, fn_params, source, file_path, findings);
            }
        }
        Expr::Tuple(t) => {
            for elt in &t.elts {
                check_expr(elt, fn_params, source, file_path, findings);
            }
        }
        Expr::Subscript(s) => {
            check_expr(&s.value, fn_params, source, file_path, findings);
            check_expr(&s.slice, fn_params, source, file_path, findings);
        }
        Expr::Lambda(l) => {
            check_expr(&l.body, fn_params, source, file_path, findings);
        }
        _ => {}
    }
}

/// Extracts parameter names from a function's argument list.
fn collect_fn_params(args: &rustpython_parser::ast::Arguments) -> Vec<String> {
    let mut params = Vec::new();
    for arg in &args.posonlyargs {
        params.push(arg.def.arg.to_string());
    }
    for arg in &args.args {
        params.push(arg.def.arg.to_string());
    }
    for arg in &args.kwonlyargs {
        params.push(arg.def.arg.to_string());
    }
    if let Some(vararg) = &args.vararg {
        params.push(vararg.arg.to_string());
    }
    if let Some(kwarg) = &args.kwarg {
        params.push(kwarg.arg.to_string());
    }
    params
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
        let analyzer = LogInjectionAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_format_placeholder_with_req_body() {
        // logger.info("user said {}".format(req.body)) — pattern + req identifier
        let src = "def view(req):\n    logger.info(\"user said {}\".format(req.body))\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_printf_style_with_req_body() {
        // logger.info("user: %s", req.body) — printf-style + req identifier
        let src = "def view(req):\n    logger.info(\"user: %s\", req.body)\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_logging_module_with_user_input_param() {
        let src = "def run(user_input):\n    logging.debug(\"received: %s\", user_input)\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_logger_with_fn_param() {
        // fn param `req` not in REQUEST_LIKE but is in the enclosing fn's params
        let src = "def view(req):\n    logger.warning(\"data: %s\", req)\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_no_placeholder_no_args() {
        let src = "def startup():\n    logger.info(\"startup complete\")\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "no-placeholder should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_placeholder_with_non_request_local() {
        // total is not request-style and not a param
        let src = "def report():\n    total = 42\n    logger.info(\"user count: %d\", total)\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "non-request local should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_non_logging_call() {
        let src = "def process(req):\n    print(\"processing: %s\", req)\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "print() should not be flagged, got: {findings:#?}"
        );
    }

    // ── CWE tag ───────────────────────────────────────────────────────────────

    #[test]
    fn cwe_tag_is_cwe_117() {
        let src = "def view(req):\n    logger.info(\"user: %s\", req.body)\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].cwe.iter().any(|c| c == "CWE-117"),
            "expected CWE-117 in finding.cwe, got: {:?}",
            findings[0].cwe
        );
    }

    #[test]
    fn supported_languages_is_python_only() {
        let analyzer = LogInjectionAnalyzer;
        assert!(
            analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
        assert!(!analyzer.supported_languages().supports(LanguageId("rust")));
    }
}
