//! `MAINT012-dead-store` — flags writes to local variables whose value is
//! never read before being overwritten or going out of scope (Python).
//!
//! # Detection
//!
//! Walks every `FunctionDef` / `AsyncFunctionDef` at any nesting depth.
//! For each function body (not including nested function / class bodies):
//!
//! 1. Collect every `Name { ctx: Store }` (writes) and `Name { ctx: Load }`
//!    (reads) with their byte offsets.
//! 2. Skip names starting with `_`.
//! 3. Skip stores inside `Try`/`ExceptHandler`/`Finally` blocks.
//! 4. Skip augmented assignments (`x += 1`) — those are also loads.
//! 5. Skip `For` target stores (loop-variable convention).
//! 6. A store is "dead" when NO `Load` of the same name appears **after**
//!    (byte offset strictly greater than) the store within the same function.
//! 7. Flag the **first** dead store per `(function, name)` pair.

use rustpython_parser::ast::{Expr, ExprContext, Ranged, Stmt};
use rustpython_parser::text_size::TextRange;
use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, Span},
};

/// The stable rule ID.
const RULE_ID: &str = "MAINT012-dead-store";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/MAINT012-dead-store.md",
    cwe: &["CWE-563"],
    owasp: &[],
};

/// Analyzer that emits `MAINT012-dead-store` for dead local variable writes.
pub struct DeadStoreAnalyzer;

impl zuit_core::Analyzer for DeadStoreAnalyzer {
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

        check_stmts(&module.body, source, &file_path, &mut findings);
        findings
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// A single name-reference occurrence (store or load) with its byte offset.
#[derive(Debug, Clone)]
struct NameRef {
    name: String,
    offset: u32,
}

/// A dead store candidate: the name and span of the write.
#[derive(Debug, Clone)]
struct DeadStore {
    name: String,
    span: TextRange,
}

/// Walk statements at module or function-body level, recursing into nested
/// function defs and class defs.
fn check_stmts(
    stmts: &[Stmt],
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(f) => {
                check_function_body(&f.body, source, file_path, findings);
            }
            Stmt::AsyncFunctionDef(f) => {
                check_function_body(&f.body, source, file_path, findings);
            }
            Stmt::ClassDef(c) => {
                check_stmts(&c.body, source, file_path, findings);
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
            Stmt::Match(m) => {
                for case in &m.cases {
                    check_stmts(&case.body, source, file_path, findings);
                }
            }
            _ => {}
        }
    }
}

/// Check a single function body for dead stores, then recurse into nested
/// function / async function / class defs.
fn check_function_body(
    body: &[Stmt],
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    let mut stores: Vec<DeadStore> = Vec::new();
    let mut loads: Vec<NameRef> = Vec::new();
    let mut augmented_names: std::collections::HashSet<String> = std::collections::HashSet::new();

    collect_from_stmts(body, &mut stores, &mut loads, &mut augmented_names, false);

    // Filter out augmented-assignment names.
    let stores: Vec<DeadStore> = stores
        .into_iter()
        .filter(|s| !augmented_names.contains(&s.name))
        .collect();

    let mut emitted: std::collections::HashSet<String> = std::collections::HashSet::new();

    for store in &stores {
        if emitted.contains(&store.name) {
            continue;
        }
        let store_off = store.span.start().to_u32();

        // Find the earliest read of this name after this store.
        let first_read_after = loads
            .iter()
            .filter(|lr| lr.name == store.name && lr.offset > store_off)
            .map(|lr| lr.offset)
            .min();
        // Find the earliest subsequent store to this name after this store.
        let next_store_after = stores
            .iter()
            .filter(|s| s.name == store.name && s.span.start().to_u32() > store_off)
            .map(|s| s.span.start().to_u32())
            .min();
        // Dead when: no read at all, OR a later store comes before the first read.
        let is_dead = match (first_read_after, next_store_after) {
            (None, _) => true,
            (Some(read_off), Some(next_off)) => next_off < read_off,
            (Some(_), None) => false,
        };

        if is_dead {
            emitted.insert(store.name.clone());
            let span = Span::new(
                ByteOffset(store.span.start().to_u32()),
                ByteOffset(store.span.end().to_u32()),
            );
            let (start_lc, end_lc) = source.span_to_linecols(span);
            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Maintainability,
                rule_id: RULE_ID.to_string(),
                severity: Severity::Low,
                message: format!(
                    "variable `{}` is written but its value is never read \
                     (dead store, CWE-563)",
                    store.name
                ),
                location: Location {
                    file: file_path.to_path_buf(),
                    span,
                    start: start_lc,
                    end: end_lc,
                },
                suggestion: Some(
                    "Remove the assignment if the value is unused, or read it \
                     before it is overwritten. Prefix with `_` to silence this \
                     warning for intentionally unused variables."
                        .to_string(),
                ),
                references: vec!["https://cwe.mitre.org/data/definitions/563.html".to_string()],
                cwe: META.cwe_vec(),
                owasp: META.owasp_vec(),
            });
        }
    }

    // Recurse into nested function / class defs.
    check_stmts(body, source, file_path, findings);
}

/// Collect stores and loads from `stmts`, stopping at nested function/class
/// boundaries.
fn collect_from_stmts(
    stmts: &[Stmt],
    stores: &mut Vec<DeadStore>,
    loads: &mut Vec<NameRef>,
    augmented_names: &mut std::collections::HashSet<String>,
    in_try: bool,
) {
    for stmt in stmts {
        collect_from_stmt(stmt, stores, loads, augmented_names, in_try);
    }
}

#[allow(clippy::too_many_lines)]
fn collect_from_stmt(
    stmt: &Stmt,
    stores: &mut Vec<DeadStore>,
    loads: &mut Vec<NameRef>,
    augmented_names: &mut std::collections::HashSet<String>,
    in_try: bool,
) {
    match stmt {
        Stmt::AugAssign(aa) => {
            if let Expr::Name(n) = &*aa.target {
                augmented_names.insert(n.id.to_string());
            }
            collect_loads(aa.value.as_ref(), loads);
        }
        Stmt::Assign(a) => {
            collect_loads(&a.value, loads);
            for target in &a.targets {
                collect_stores_from_expr(target, stores, in_try);
            }
        }
        Stmt::AnnAssign(a) => {
            if let Some(val) = &a.value {
                collect_loads(val.as_ref(), loads);
            }
            collect_stores_from_expr(&a.target, stores, in_try);
        }
        Stmt::Return(r) => {
            if let Some(val) = &r.value {
                collect_loads(val.as_ref(), loads);
            }
        }
        Stmt::Expr(e) => collect_loads(&e.value, loads),
        Stmt::Delete(d) => {
            for target in &d.targets {
                collect_loads(target, loads);
            }
        }
        Stmt::For(s) => {
            collect_loads(&s.iter, loads);
            collect_loads_from_expr(&s.target, loads);
            collect_from_stmts(&s.body, stores, loads, augmented_names, in_try);
            collect_from_stmts(&s.orelse, stores, loads, augmented_names, in_try);
        }
        Stmt::AsyncFor(s) => {
            collect_loads(&s.iter, loads);
            collect_loads_from_expr(&s.target, loads);
            collect_from_stmts(&s.body, stores, loads, augmented_names, in_try);
            collect_from_stmts(&s.orelse, stores, loads, augmented_names, in_try);
        }
        Stmt::Try(t) => {
            collect_from_stmts(&t.body, stores, loads, augmented_names, true);
            for handler in &t.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                collect_from_stmts(&h.body, stores, loads, augmented_names, true);
            }
            collect_from_stmts(&t.orelse, stores, loads, augmented_names, true);
            collect_from_stmts(&t.finalbody, stores, loads, augmented_names, true);
        }
        Stmt::TryStar(t) => {
            collect_from_stmts(&t.body, stores, loads, augmented_names, true);
            for handler in &t.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                collect_from_stmts(&h.body, stores, loads, augmented_names, true);
            }
        }
        Stmt::If(s) => {
            collect_loads(&s.test, loads);
            collect_from_stmts(&s.body, stores, loads, augmented_names, in_try);
            collect_from_stmts(&s.orelse, stores, loads, augmented_names, in_try);
        }
        Stmt::While(s) => {
            collect_loads(&s.test, loads);
            collect_from_stmts(&s.body, stores, loads, augmented_names, in_try);
            collect_from_stmts(&s.orelse, stores, loads, augmented_names, in_try);
        }
        Stmt::With(s) => {
            for item in &s.items {
                collect_loads(&item.context_expr, loads);
                if let Some(opt) = &item.optional_vars {
                    collect_stores_from_expr(opt, stores, in_try);
                }
            }
            collect_from_stmts(&s.body, stores, loads, augmented_names, in_try);
        }
        Stmt::AsyncWith(s) => {
            for item in &s.items {
                collect_loads(&item.context_expr, loads);
                if let Some(opt) = &item.optional_vars {
                    collect_stores_from_expr(opt, stores, in_try);
                }
            }
            collect_from_stmts(&s.body, stores, loads, augmented_names, in_try);
        }
        Stmt::Match(m) => {
            collect_loads(&m.subject, loads);
            for case in &m.cases {
                collect_from_stmts(&case.body, stores, loads, augmented_names, in_try);
            }
        }
        Stmt::Raise(r) => {
            if let Some(exc) = &r.exc {
                collect_loads(exc.as_ref(), loads);
            }
        }
        Stmt::Assert(a) => {
            collect_loads(&a.test, loads);
            if let Some(msg) = &a.msg {
                collect_loads(msg.as_ref(), loads);
            }
        }
        // STOP at nested function / class defs, and ignore everything else.
        _ => {}
    }
}

/// Collect store targets from an expression.
fn collect_stores_from_expr(expr: &Expr, stores: &mut Vec<DeadStore>, in_try: bool) {
    match expr {
        Expr::Name(n) if matches!(n.ctx, ExprContext::Store) && !in_try => {
            let name = n.id.to_string();
            if !name.starts_with('_') {
                stores.push(DeadStore {
                    name,
                    span: n.range(),
                });
            }
        }
        Expr::Tuple(t) => {
            for elt in &t.elts {
                collect_stores_from_expr(elt, stores, in_try);
            }
        }
        Expr::List(l) => {
            for elt in &l.elts {
                collect_stores_from_expr(elt, stores, in_try);
            }
        }
        Expr::Starred(s) => collect_stores_from_expr(&s.value, stores, in_try),
        _ => {}
    }
}

/// Convenience: collect loads from a borrowed expression.
fn collect_loads(expr: &Expr, loads: &mut Vec<NameRef>) {
    collect_loads_from_expr(expr, loads);
}

#[allow(clippy::too_many_lines)]
fn collect_loads_from_expr(expr: &Expr, loads: &mut Vec<NameRef>) {
    match expr {
        Expr::Name(n) if matches!(n.ctx, ExprContext::Load) => {
            loads.push(NameRef {
                name: n.id.to_string(),
                offset: n.range().start().to_u32(),
            });
        }
        Expr::BoolOp(b) => {
            for val in &b.values {
                collect_loads_from_expr(val, loads);
            }
        }
        Expr::BinOp(b) => {
            collect_loads_from_expr(&b.left, loads);
            collect_loads_from_expr(&b.right, loads);
        }
        Expr::UnaryOp(u) => collect_loads_from_expr(&u.operand, loads),
        Expr::IfExp(i) => {
            collect_loads_from_expr(&i.test, loads);
            collect_loads_from_expr(&i.body, loads);
            collect_loads_from_expr(&i.orelse, loads);
        }
        Expr::Dict(d) => {
            for key in d.keys.iter().flatten() {
                collect_loads_from_expr(key, loads);
            }
            for val in &d.values {
                collect_loads_from_expr(val, loads);
            }
        }
        Expr::Set(s) => {
            for elt in &s.elts {
                collect_loads_from_expr(elt, loads);
            }
        }
        Expr::ListComp(l) => {
            collect_loads_from_expr(&l.elt, loads);
            for comp in &l.generators {
                collect_loads_from_expr(&comp.iter, loads);
                for cond in &comp.ifs {
                    collect_loads_from_expr(cond, loads);
                }
            }
        }
        Expr::SetComp(s) => {
            collect_loads_from_expr(&s.elt, loads);
            for comp in &s.generators {
                collect_loads_from_expr(&comp.iter, loads);
                for cond in &comp.ifs {
                    collect_loads_from_expr(cond, loads);
                }
            }
        }
        Expr::DictComp(d) => {
            collect_loads_from_expr(&d.key, loads);
            collect_loads_from_expr(&d.value, loads);
            for comp in &d.generators {
                collect_loads_from_expr(&comp.iter, loads);
                for cond in &comp.ifs {
                    collect_loads_from_expr(cond, loads);
                }
            }
        }
        Expr::GeneratorExp(g) => {
            collect_loads_from_expr(&g.elt, loads);
            for comp in &g.generators {
                collect_loads_from_expr(&comp.iter, loads);
                for cond in &comp.ifs {
                    collect_loads_from_expr(cond, loads);
                }
            }
        }
        Expr::Await(a) => collect_loads_from_expr(&a.value, loads),
        Expr::Yield(y) => {
            if let Some(val) = &y.value {
                collect_loads_from_expr(val, loads);
            }
        }
        Expr::YieldFrom(y) => collect_loads_from_expr(&y.value, loads),
        Expr::Compare(c) => {
            collect_loads_from_expr(&c.left, loads);
            for cmp in &c.comparators {
                collect_loads_from_expr(cmp, loads);
            }
        }
        Expr::Call(c) => {
            collect_loads_from_expr(&c.func, loads);
            for arg in &c.args {
                collect_loads_from_expr(arg, loads);
            }
            for kw in &c.keywords {
                collect_loads_from_expr(&kw.value, loads);
            }
        }
        Expr::FormattedValue(f) => collect_loads_from_expr(&f.value, loads),
        Expr::JoinedStr(j) => {
            for val in &j.values {
                collect_loads_from_expr(val, loads);
            }
        }
        Expr::Attribute(a) => collect_loads_from_expr(&a.value, loads),
        Expr::Subscript(s) => {
            collect_loads_from_expr(&s.value, loads);
            collect_loads_from_expr(&s.slice, loads);
        }
        Expr::Starred(s) => collect_loads_from_expr(&s.value, loads),
        Expr::Tuple(t) => {
            for elt in &t.elts {
                collect_loads_from_expr(elt, loads);
            }
        }
        Expr::List(l) => {
            for elt in &l.elts {
                collect_loads_from_expr(elt, loads);
            }
        }
        Expr::Slice(s) => {
            if let Some(lower) = &s.lower {
                collect_loads_from_expr(lower, loads);
            }
            if let Some(upper) = &s.upper {
                collect_loads_from_expr(upper, loads);
            }
            if let Some(step) = &s.step {
                collect_loads_from_expr(step, loads);
            }
        }
        Expr::Lambda(l) => {
            collect_loads_from_expr(&l.body, loads);
        }
        Expr::NamedExpr(n) => {
            collect_loads_from_expr(&n.value, loads);
        }
        // Expr::Name with non-Load ctx, constants, and others.
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
        let analyzer = DeadStoreAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_overwritten_before_read() {
        let src = "def f():\n    x = 1\n    x = 2\n    return x\n";
        let findings = analyze(src);
        assert!(
            !findings.is_empty(),
            "expected ≥1 finding; got: {findings:#?}"
        );
        assert!(
            findings.iter().any(|f| f.rule_id == RULE_ID),
            "expected MAINT012 finding; got: {findings:#?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.cwe.iter().any(|c| c == "CWE-563")),
            "expected CWE-563 tag; got: {findings:#?}"
        );
    }

    #[test]
    fn flags_write_never_read() {
        let src = "def f():\n    unused = 42\n    return None\n";
        let findings = analyze(src);
        assert!(
            !findings.is_empty(),
            "expected ≥1 finding; got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_when_read_after_write() {
        let src = "def f():\n    x = 1\n    return x\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "x is read — must not fire; got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_underscore_prefix() {
        let src = "def f():\n    _x = 1\n    return None\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "underscore-prefixed name must be skipped; got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_for_loop_variable() {
        let src = "def f():\n    for x in range(10):\n        pass\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "for-loop variable must be skipped; got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_try_except_stores() {
        let src = concat!(
            "def f():\n",
            "    x = 1\n",
            "    try:\n",
            "        x = 2\n",
            "    except:\n",
            "        x = 3\n",
            "    return x\n",
        );
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "try/except stores must be skipped; got: {findings:#?}"
        );
    }

    // ── CWE tag check ─────────────────────────────────────────────────────────

    #[test]
    fn cwe_tag_is_cwe_563() {
        let src = "def f():\n    unused = 42\n    return None\n";
        let findings = analyze(src);
        assert!(!findings.is_empty());
        assert!(
            findings[0].cwe.iter().any(|c| c == "CWE-563"),
            "expected CWE-563; got: {:?}",
            findings[0].cwe
        );
    }

    #[test]
    fn supported_languages_is_python_only() {
        let analyzer = DeadStoreAnalyzer;
        assert!(
            analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
        assert!(!analyzer.supported_languages().supports(LanguageId("rust")));
    }
}
