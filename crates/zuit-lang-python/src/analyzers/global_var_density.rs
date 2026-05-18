//! `MAINT018-global-var-density` — fires when a Python file declares too many
//! mutable globals via `global` statements inside function bodies.
//!
//! # Detection
//!
//! Recursively walks every `FunctionDef` / `AsyncFunctionDef` body (including
//! methods inside `ClassDef`s and arbitrarily nested functions).  Top-level
//! `global` statements (at module scope) are ignored — Python developers never
//! write them there, and the interpreter treats them as no-ops.
//!
//! Every `Stmt::Global` contributes one count unit per name in its name list
//! (e.g. `global a, b` counts as 2).  When the cumulative count across all
//! function bodies meets or exceeds the configured threshold a single finding
//! is emitted.
//!
//! The finding location points at the first `global` statement encountered
//! (in `Ranged` span order, i.e. source order).
//!
//! # Configuration
//!
//! ```toml
//! [rules."MAINT018-global-var-density"]
//! threshold = 3   # default; fire when total name count >= threshold
//! ```

use rustpython_parser::ast::{Ranged, Stmt};
use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, Span},
};

/// The stable rule ID.
const RULE_ID: &str = "MAINT018-global-var-density";

/// Default threshold: fire when the file's total global-name count meets or
/// exceeds this value.
const DEFAULT_THRESHOLD: u32 = 3;

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/MAINT018-global-var-density.md",
    cwe: &["CWE-1108"],
    owasp: &[],
};

/// Analyzer that emits `MAINT018-global-var-density` when a Python source file
/// contains too many names declared via `global` statements inside function
/// bodies.
///
/// Severity: **Low** / Dimension: **Maintainability** / CWE-1108.
pub struct GlobalVarDensityAnalyzer;

impl zuit_core::Analyzer for GlobalVarDensityAnalyzer {
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

    fn analyze_file(&self, ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let Some(module) = crate::try_python_ast(file) else {
            return Vec::new();
        };

        let threshold = ctx.config.rule_threshold(RULE_ID, DEFAULT_THRESHOLD);
        let source = file.source();
        let file_path = source.path.clone();

        let mut total_count: u32 = 0;
        let mut first_span: Option<Span> = None;

        // Walk module-level statements looking for function/class defs.
        // `global` statements at module scope are intentionally skipped.
        collect_from_stmts(&module.body, &mut total_count, &mut first_span);

        if total_count < threshold {
            return Vec::new();
        }

        // At this point we have a first_span because total_count >= threshold >= 1.
        let span = first_span.expect("invariant: total_count >= threshold >= 1");
        let (start_lc, end_lc) = source.span_to_linecols(span);

        vec![Finding {
            analyzer: AnalyzerId::new(RULE_ID),
            dimension: Dimension::Maintainability,
            rule_id: RULE_ID.to_string(),
            severity: Severity::Low,
            message: format!(
                "file declares {total_count} mutable globals — consider reducing global state"
            ),
            location: Location {
                file: file_path,
                span,
                start: start_lc,
                end: end_lc,
            },
            suggestion: Some(
                "Encapsulate module-level state in a class, pass it as arguments, \
                 or use a dataclass / NamedTuple for shared configuration."
                    .to_string(),
            ),
            references: vec!["https://cwe.mitre.org/data/definitions/1108.html".to_string()],
            cwe: META.cwe_vec(),
            owasp: META.owasp_vec(),
        }]
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Walk a statement list, recursing into structural containers (class/if/for/
/// while/with/try) and descending into function bodies to count `global` stmts.
fn collect_from_stmts(stmts: &[Stmt], total: &mut u32, first: &mut Option<Span>) {
    for stmt in stmts {
        collect_from_stmt(stmt, total, first);
    }
}

fn collect_from_stmt(stmt: &Stmt, total: &mut u32, first: &mut Option<Span>) {
    match stmt {
        // Enter function bodies — this is where `global` is meaningful.
        Stmt::FunctionDef(f) => {
            collect_globals_in_function(&f.body, total, first);
        }
        Stmt::AsyncFunctionDef(f) => {
            collect_globals_in_function(&f.body, total, first);
        }
        // Recurse into class bodies; they may contain methods (FunctionDefs).
        Stmt::ClassDef(c) => {
            collect_from_stmts(&c.body, total, first);
        }
        // Structural containers that may enclose function definitions.
        Stmt::If(s) => {
            collect_from_stmts(&s.body, total, first);
            collect_from_stmts(&s.orelse, total, first);
        }
        Stmt::For(s) => {
            collect_from_stmts(&s.body, total, first);
            collect_from_stmts(&s.orelse, total, first);
        }
        Stmt::AsyncFor(s) => {
            collect_from_stmts(&s.body, total, first);
            collect_from_stmts(&s.orelse, total, first);
        }
        Stmt::While(s) => {
            collect_from_stmts(&s.body, total, first);
            collect_from_stmts(&s.orelse, total, first);
        }
        Stmt::With(s) => collect_from_stmts(&s.body, total, first),
        Stmt::AsyncWith(s) => collect_from_stmts(&s.body, total, first),
        Stmt::Try(s) => {
            collect_from_stmts(&s.body, total, first);
            for handler in &s.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                collect_from_stmts(&h.body, total, first);
            }
            collect_from_stmts(&s.orelse, total, first);
            collect_from_stmts(&s.finalbody, total, first);
        }
        Stmt::TryStar(s) => {
            collect_from_stmts(&s.body, total, first);
            for handler in &s.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                collect_from_stmts(&h.body, total, first);
            }
        }
        // All other statement kinds are not containers of function defs.
        _ => {}
    }
}

/// Walk the body of a function (or async function), counting every
/// `Stmt::Global` and recording the span of the first one found.
/// Also recurses into nested function defs and structural containers so that
/// inner functions are visited too.
fn collect_globals_in_function(body: &[Stmt], total: &mut u32, first: &mut Option<Span>) {
    for stmt in body {
        match stmt {
            Stmt::Global(g) => {
                *total += u32::try_from(g.names.len()).unwrap_or(u32::MAX);
                if first.is_none() {
                    let range = g.range();
                    *first = Some(Span::new(
                        ByteOffset(range.start().to_u32()),
                        ByteOffset(range.end().to_u32()),
                    ));
                }
            }
            // Nested function / async function — recurse.
            Stmt::FunctionDef(f) => {
                collect_globals_in_function(&f.body, total, first);
            }
            Stmt::AsyncFunctionDef(f) => {
                collect_globals_in_function(&f.body, total, first);
            }
            // Class inside a function — its methods are also functions.
            Stmt::ClassDef(c) => {
                collect_from_stmts(&c.body, total, first);
            }
            // Structural containers inside the function body.
            Stmt::If(s) => {
                collect_globals_in_function(&s.body, total, first);
                collect_globals_in_function(&s.orelse, total, first);
            }
            Stmt::For(s) => {
                collect_globals_in_function(&s.body, total, first);
                collect_globals_in_function(&s.orelse, total, first);
            }
            Stmt::AsyncFor(s) => {
                collect_globals_in_function(&s.body, total, first);
                collect_globals_in_function(&s.orelse, total, first);
            }
            Stmt::While(s) => {
                collect_globals_in_function(&s.body, total, first);
                collect_globals_in_function(&s.orelse, total, first);
            }
            Stmt::With(s) => collect_globals_in_function(&s.body, total, first),
            Stmt::AsyncWith(s) => collect_globals_in_function(&s.body, total, first),
            Stmt::Try(s) => {
                collect_globals_in_function(&s.body, total, first);
                for handler in &s.handlers {
                    let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                    collect_globals_in_function(&h.body, total, first);
                }
                collect_globals_in_function(&s.orelse, total, first);
                collect_globals_in_function(&s.finalbody, total, first);
            }
            Stmt::TryStar(s) => {
                collect_globals_in_function(&s.body, total, first);
                for handler in &s.handlers {
                    let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                    collect_globals_in_function(&h.body, total, first);
                }
            }
            _ => {}
        }
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
        analyze_with_config(src, &Config::default())
    }

    fn analyze_with_config(src: &str, config: &Config) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.py", src.as_bytes().to_vec()));
        let lang = PythonLanguage;
        let parsed = lang.parse(source).expect("parse failed");
        let analyzer = GlobalVarDensityAnalyzer;
        let ctx = AnalysisContext::new(config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive: at/above threshold ─────────────────────────────────────────

    #[test]
    fn flags_when_count_equals_threshold() {
        // 3 individual names across 3 functions — equals default threshold of 3.
        let src = "
def f():
    global a

def g():
    global b

def h():
    global c
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn flags_when_single_statement_with_multiple_names() {
        // One function with `global a, b, c` = 3 names — equals threshold.
        let src = "
def f():
    global a, b, c
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        let msg = &findings[0].message;
        assert!(
            msg.contains("3 mutable globals"),
            "message should contain count=3, got: {msg}"
        );
    }

    #[test]
    fn flags_when_count_above_threshold() {
        // Multiple functions, total names = 5.
        let src = "
def f():
    global a, b

def g():
    global c, d, e
";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 finding, got: {findings:#?}"
        );
        let msg = &findings[0].message;
        assert!(
            msg.contains("5 mutable globals"),
            "message should contain count=5, got: {msg}"
        );
    }

    // ── below threshold: no finding ───────────────────────────────────────────

    #[test]
    fn silent_when_count_below_threshold() {
        // 2 names across functions — below default threshold of 3.
        let src = "
def f():
    global a

def g():
    global b
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "should not fire below threshold, got: {findings:#?}"
        );
    }

    #[test]
    fn silent_when_no_global_statements() {
        let src = "
def f():
    x = 1

def g():
    y = 2
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "no globals should not fire, got: {findings:#?}"
        );
    }

    // ── comment containing 'global' not counted (AST-level) ──────────────────

    #[test]
    fn comment_with_global_word_not_counted() {
        // Comments are stripped by the parser — AST has no global stmts here.
        let src = "
def f():
    # global x
    # global y, z
    x = 1
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "comments should not be counted, got: {findings:#?}"
        );
    }

    // ── config-overridden threshold ───────────────────────────────────────────

    #[test]
    fn custom_threshold_5_does_not_fire_at_4() {
        let src = "
def f():
    global a, b

def g():
    global c, d
";
        let mut config = Config::default();
        config
            .rules
            .entry(RULE_ID.to_string())
            .or_default()
            .threshold = Some(5);
        let findings = analyze_with_config(src, &config);
        assert!(
            findings.is_empty(),
            "should not fire at 4 when threshold=5, got: {findings:#?}"
        );
    }

    #[test]
    fn custom_threshold_5_fires_at_5() {
        let src = "
def f():
    global a, b

def g():
    global c, d, e
";
        let mut config = Config::default();
        config
            .rules
            .entry(RULE_ID.to_string())
            .or_default()
            .threshold = Some(5);
        let findings = analyze_with_config(src, &config);
        assert_eq!(
            findings.len(),
            1,
            "should fire at exactly 5 when threshold=5, got: {findings:#?}"
        );
    }

    // ── nested functions ──────────────────────────────────────────────────────

    #[test]
    fn counts_globals_inside_nested_functions() {
        // Outer function contains inner function with `global x, y, z` → fires.
        let src = "
def outer():
    def inner():
        global x, y, z
    inner()
";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for global in nested function, got: {findings:#?}"
        );
        let msg = &findings[0].message;
        assert!(
            msg.contains("3 mutable globals"),
            "message should contain count=3, got: {msg}"
        );
    }

    // ── class methods ─────────────────────────────────────────────────────────

    #[test]
    fn counts_globals_inside_methods_of_classes() {
        // Class with a method containing `global a, b, c` → fires.
        let src = "
class Foo:
    def method(self):
        global a, b, c
";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for global inside class method, got: {findings:#?}"
        );
        let msg = &findings[0].message;
        assert!(
            msg.contains("3 mutable globals"),
            "message should contain count=3, got: {msg}"
        );
    }

    // ── module-level globals are ignored ──────────────────────────────────────

    #[test]
    fn module_level_globals_not_counted() {
        // Module-scope `global` is a no-op in Python; we must not count it.
        let src = "
global a, b, c, d, e
x = 1
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "module-level global stmts must not be counted, got: {findings:#?}"
        );
    }

    // ── supported languages ───────────────────────────────────────────────────

    #[test]
    fn supported_languages_is_python_only() {
        let analyzer = GlobalVarDensityAnalyzer;
        assert!(
            analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
        assert!(!analyzer.supported_languages().supports(LanguageId("rust")));
        assert!(!analyzer.supported_languages().supports(LanguageId("js")));
    }
}
