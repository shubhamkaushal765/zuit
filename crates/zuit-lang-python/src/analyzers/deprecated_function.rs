//! `MAINT015-deprecated-function` — flags Python function and method
//! definitions that mark themselves as deprecated (CWE-477).
//!
//! # Detection
//!
//! A `def` (sync or async) is flagged when:
//!
//! 1. It is decorated with `@deprecated` (PEP 702, `typing_extensions.deprecated`
//!    or `warnings.deprecated`). Both bare-name and attribute-call forms are
//!    accepted: `@deprecated`, `@deprecated("reason")`, `@typing_extensions.deprecated`,
//!    `@warnings.deprecated`. **OR**
//! 2. Its body (recursively, excluding nested function/class definitions)
//!    contains a call to `warnings.warn(...)` whose second positional arg
//!    or `category=` keyword arg is `DeprecationWarning` or
//!    `PendingDeprecationWarning`.
//!
//! Each flagged definition produces exactly one finding, anchored at the
//! `def` keyword's source range.
//!
//! # Languages
//!
//! Python only.

use rustpython_parser::ast::{Expr, Stmt, StmtFunctionDef};
use rustpython_parser::text_size::TextRange;
use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, Span},
};

/// The stable rule ID.
const RULE_ID: &str = "MAINT015-deprecated-function";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/MAINT015-deprecated-function.md",
    cwe: &["CWE-477"],
    owasp: &[],
};

/// Analyzer that emits `MAINT015-deprecated-function` for Python function
/// definitions marked deprecated.
pub struct DeprecatedFunctionAnalyzer;

impl zuit_core::Analyzer for DeprecatedFunctionAnalyzer {
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
        walk(&ast.body, source, &file_path, &mut findings);
        findings
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn walk(
    stmts: &[Stmt],
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(f) => {
                check_fn(f, source, file_path, findings);
                walk(&f.body, source, file_path, findings);
            }
            Stmt::AsyncFunctionDef(f) => {
                // AsyncFunctionDef has the same field layout as FunctionDef.
                let pseudo = StmtFunctionDef {
                    range: f.range,
                    name: f.name.clone(),
                    args: f.args.clone(),
                    body: f.body.clone(),
                    decorator_list: f.decorator_list.clone(),
                    returns: f.returns.clone(),
                    type_comment: f.type_comment.clone(),
                    type_params: f.type_params.clone(),
                };
                check_fn(&pseudo, source, file_path, findings);
                walk(&f.body, source, file_path, findings);
            }
            Stmt::ClassDef(c) => walk(&c.body, source, file_path, findings),
            Stmt::If(s) => {
                walk(&s.body, source, file_path, findings);
                walk(&s.orelse, source, file_path, findings);
            }
            Stmt::Try(s) => {
                walk(&s.body, source, file_path, findings);
                for handler in &s.handlers {
                    let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                    walk(&h.body, source, file_path, findings);
                }
                walk(&s.orelse, source, file_path, findings);
                walk(&s.finalbody, source, file_path, findings);
            }
            Stmt::With(s) => walk(&s.body, source, file_path, findings),
            _ => {}
        }
    }
}

fn check_fn(
    f: &StmtFunctionDef,
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    let reason = if has_deprecated_decorator(&f.decorator_list) {
        Some("decorated with @deprecated")
    } else if body_calls_deprecation_warn(&f.body) {
        Some("body calls warnings.warn with DeprecationWarning")
    } else {
        None
    };
    if let Some(why) = reason {
        emit(f.range, f.name.as_str(), why, source, file_path, findings);
    }
}

fn has_deprecated_decorator(decorators: &[Expr]) -> bool {
    decorators.iter().any(is_deprecated_decorator)
}

fn is_deprecated_decorator(expr: &Expr) -> bool {
    match expr {
        Expr::Name(n) => n.id.as_str() == "deprecated",
        Expr::Attribute(a) => a.attr.as_str() == "deprecated",
        Expr::Call(c) => is_deprecated_decorator(&c.func),
        _ => false,
    }
}

fn body_calls_deprecation_warn(body: &[Stmt]) -> bool {
    body.iter().any(stmt_calls_deprecation_warn)
}

fn stmt_calls_deprecation_warn(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Expr(e) => expr_calls_deprecation_warn(&e.value),
        Stmt::If(s) => {
            body_calls_deprecation_warn(&s.body) || body_calls_deprecation_warn(&s.orelse)
        }
        Stmt::Try(s) => body_calls_deprecation_warn(&s.body),
        Stmt::With(s) => body_calls_deprecation_warn(&s.body),
        Stmt::For(s) => body_calls_deprecation_warn(&s.body),
        Stmt::While(s) => body_calls_deprecation_warn(&s.body),
        // Do not descend into nested function/class definitions — those are
        // separate scopes and will be checked independently by `walk`.
        _ => false,
    }
}

fn expr_calls_deprecation_warn(expr: &Expr) -> bool {
    let Expr::Call(call) = expr else {
        return false;
    };
    let is_warn = match call.func.as_ref() {
        Expr::Attribute(a) => a.attr.as_str() == "warn",
        Expr::Name(n) => n.id.as_str() == "warn",
        _ => false,
    };
    if !is_warn {
        return false;
    }
    // Second positional argument or `category=` keyword.
    if let Some(arg) = call.args.get(1)
        && expr_is_deprecation_warning(arg)
    {
        return true;
    }
    call.keywords
        .iter()
        .filter(|kw| kw.arg.as_ref().is_some_and(|a| a.as_str() == "category"))
        .any(|kw| expr_is_deprecation_warning(&kw.value))
}

fn expr_is_deprecation_warning(expr: &Expr) -> bool {
    match expr {
        Expr::Name(n) => {
            matches!(
                n.id.as_str(),
                "DeprecationWarning" | "PendingDeprecationWarning"
            )
        }
        Expr::Attribute(a) => {
            matches!(
                a.attr.as_str(),
                "DeprecationWarning" | "PendingDeprecationWarning"
            )
        }
        _ => false,
    }
}

fn emit(
    range: TextRange,
    fn_name: &str,
    reason: &str,
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
        severity: Severity::Medium,
        message: format!(
            "function `{fn_name}` is marked deprecated ({reason}) — schedule for removal"
        ),
        location: Location {
            file: file_path.to_path_buf(),
            span,
            start: start_lc,
            end: end_lc,
        },
        suggestion: Some(
            "Plan a removal milestone for this deprecated function and migrate callers \
             to the supported replacement."
                .to_string(),
        ),
        references: vec!["https://cwe.mitre.org/data/definitions/477.html".to_string()],
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
        let analyzer = DeprecatedFunctionAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    #[test]
    fn flags_bare_deprecated_decorator() {
        let src = "from typing_extensions import deprecated\n\n@deprecated\ndef old():\n    pass\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_called_deprecated_decorator() {
        let src = "from typing_extensions import deprecated\n\n@deprecated('use new() instead')\ndef old():\n    pass\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_attribute_deprecated_decorator() {
        let src = "import typing_extensions\n\n@typing_extensions.deprecated('use new()')\ndef old():\n    pass\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_warnings_warn_with_deprecation_positional() {
        let src = "import warnings\n\ndef old():\n    warnings.warn('old() is gone', DeprecationWarning)\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_warnings_warn_with_category_kwarg() {
        let src = "import warnings\n\ndef old():\n    warnings.warn('old() is gone', category=DeprecationWarning)\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_pending_deprecation_warning() {
        let src =
            "import warnings\n\ndef old():\n    warnings.warn('soon', PendingDeprecationWarning)\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_async_deprecated_function() {
        let src =
            "from typing_extensions import deprecated\n\n@deprecated\nasync def old():\n    pass\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_method_in_class_deprecated() {
        let src = "from typing_extensions import deprecated\n\nclass C:\n    @deprecated\n    def old(self):\n        pass\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_each_deprecated_function_once() {
        let src = "from typing_extensions import deprecated\n\n@deprecated\ndef a():\n    pass\n\n@deprecated\ndef b():\n    pass\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 2, "expected 2 findings, got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_plain_function() {
        let src = "def good():\n    return 42\n";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn does_not_flag_non_deprecation_warning() {
        let src = "import warnings\n\ndef old():\n    warnings.warn('careful', UserWarning)\n";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn does_not_flag_warnings_warn_with_no_category() {
        let src = "import warnings\n\ndef old():\n    warnings.warn('something')\n";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn does_not_flag_warnings_warn_in_nested_function_body_against_outer() {
        // The nested function (`nested_old`) IS flagged because it calls
        // warnings.warn with DeprecationWarning. The outer (`outer`) is NOT
        // flagged because we don't descend into nested defs for the body check.
        let src = "import warnings\n\ndef outer():\n    def nested_old():\n        warnings.warn('nested', DeprecationWarning)\n";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding (nested only), got: {findings:#?}"
        );
        assert!(findings[0].message.contains("nested_old"));
    }

    #[test]
    fn supported_languages_is_python_only() {
        let analyzer = DeprecatedFunctionAnalyzer;
        assert!(
            analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
        assert!(!analyzer.supported_languages().supports(LanguageId("rust")));
    }
}
