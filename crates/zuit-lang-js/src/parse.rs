//! `oxc_parser`-backed parser entry point for [`crate::JsLanguage`].
//!
//! The arena (`oxc_allocator::Allocator`) and the parsed `Program<'a>` live
//! only for the duration of [`parse`]. Everything downstream of the frontend
//! reads through [`zuit_core::SemanticIndex`], which is built before the
//! arena is dropped (see [`crate::index::build_index`]).
//!
//! Additionally, [`parse`] walks the oxc AST once to extract [`crate::native_ast::JsAst`]
//! data (call sites of interest) before the arena is dropped.

use std::sync::Arc;

use oxc_allocator::Allocator;
use oxc_ast::ast::{Argument, Expression, Program, Statement};
use oxc_parser::Parser;
use oxc_span::SourceType;

use zuit_core::{ByteOffset, LanguageId, ParseError, ParsedFile, SourceFile, Span};

use crate::native_ast::{DomSinkKind, JsAst, JsCallSite, JsCallee, JsDomSink, JsImport};

/// Parses `source` as JavaScript or TypeScript and returns a populated
/// [`ParsedFile`].
///
/// Source-type detection (JS vs TS, JSX, module-vs-script) is delegated to
/// [`SourceType::from_path`]. Unknown extensions fall back to
/// [`SourceType::default`] (plain JS module).
///
/// # Errors
///
/// - [`ParseError::Encoding`] when the source bytes are not valid UTF-8
///   (`oxc_parser` only accepts `&str`).
/// - [`ParseError::Syntax`] when the parser bailed out (`panicked == true`).
///   Recoverable diagnostics are *not* errors: real-world JS/TS often has
///   benign issues (missing semicolons, etc.) and we still want analyzers to
///   run. The first label of the first reported diagnostic, if any, is
///   surfaced as the error span.
pub(crate) fn parse(source: Arc<SourceFile>) -> Result<ParsedFile, ParseError> {
    let text = std::str::from_utf8(source.bytes())
        .map_err(|_| ParseError::Encoding(source.path.clone()))?;

    let source_type = SourceType::from_path(&source.path).unwrap_or_else(|_| SourceType::default());

    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, text, source_type).parse();

    if ret.panicked {
        return Err(diagnostic_to_error(&source, &ret.errors));
    }

    let semantic_index = index_program(&ret.program, &source);

    // Walk the AST to extract call sites before the arena is dropped.
    let js_ast = extract_call_sites(&ret.program);

    Ok(ParsedFile::new(
        LanguageId("javascript"),
        source,
        semantic_index,
        Box::new(js_ast),
    ))
}

/// Indirection that lets `crate::index::build_index` borrow the arena-backed
/// `Program` and produce a [`zuit_core::SemanticIndex`] before the arena
/// is dropped.
fn index_program(program: &Program<'_>, source: &SourceFile) -> zuit_core::SemanticIndex {
    crate::index::build_index(program, source)
}

// ── call-site extraction ──────────────────────────────────────────────────────

/// Mutable accumulator threaded through the AST walk.
///
/// Holds every kind of pre-extracted data the JS frontend collects in a single
/// arena pass: call sites consumed by `SEC002-eval-sink`'s eval-style branch,
/// DOM sinks consumed by the same rule's DOM-XSS branch, static imports for
/// `PERF002-heavy-import`, and top-level call sites for
/// `PERF003-import-side-effect`. Adding a new extraction kind is a
/// struct-field addition and a couple of `push` calls in the walker.
struct WalkCtx {
    call_sites: Vec<JsCallSite>,
    dom_sinks: Vec<JsDomSink>,
    imports: Vec<JsImport>,
    top_level_calls: Vec<JsCallSite>,
    /// `true` while we are walking statements at module top-level (not inside
    /// any function or class body). Used to distinguish top-level calls from
    /// nested calls for `PERF003`.
    at_top_level: bool,
}

impl WalkCtx {
    fn new() -> Self {
        Self {
            call_sites: Vec::new(),
            dom_sinks: Vec::new(),
            imports: Vec::new(),
            top_level_calls: Vec::new(),
            at_top_level: true,
        }
    }
}

/// Walks the oxc AST and extracts all call/new-expression sites with bare
/// identifier callees and all DOM-based XSS sinks into a [`JsAst`].
///
/// We perform a hand-written recursive descent rather than using an oxc
/// visitor because:
/// 1. We only need to collect `CallExpression`, `NewExpression`,
///    `AssignmentExpression`, and a handful of JSX attribute nodes — a
///    targeted walk is simpler and faster than a full visitor pass.
/// 2. Avoids the lifetime complexity of hooking into oxc's visitor framework
///    while also building a mutable accumulator.
fn extract_call_sites(program: &Program<'_>) -> JsAst {
    let mut ctx = WalkCtx::new();

    // First pass: collect static import declarations (ES module `import` stmts).
    for stmt in &program.body {
        if let Statement::ImportDeclaration(decl) = stmt {
            ctx.imports.push(JsImport {
                source: decl.source.value.to_string(),
                span: oxc_span_to_core(decl.span),
            });
        }
    }

    // Second pass: walk all statements for call sites, DOM sinks, and
    // top-level require() calls.
    for stmt in &program.body {
        walk_stmt(stmt, &mut ctx);
    }
    JsAst {
        call_sites: ctx.call_sites,
        dom_sinks: ctx.dom_sinks,
        imports: ctx.imports,
        top_level_calls: ctx.top_level_calls,
    }
}

fn oxc_span_to_core(s: oxc_span::Span) -> Span {
    Span::new(ByteOffset(s.start), ByteOffset(s.end))
}

/// Classifies a member-call callee shape into a [`DomSinkKind`], if any.
///
/// Recognised patterns:
/// - `document.write(…)` → [`DomSinkKind::DocumentWrite`]
/// - `document.writeln(…)` → [`DomSinkKind::DocumentWriteln`]
/// - `<any>.insertAdjacentHTML(…)` → [`DomSinkKind::InsertAdjacentHtml`]
///
/// The receiver is only inspected for `document` to disambiguate
/// `document.write` from arbitrary `obj.write` calls; `insertAdjacentHTML`
/// is matched on method name alone since the receiver is always a DOM element.
fn dom_sink_kind_for_call(callee: &Expression<'_>) -> Option<DomSinkKind> {
    let Expression::StaticMemberExpression(member) = callee else {
        return None;
    };
    let prop = member.property.name.as_str();
    match prop {
        "insertAdjacentHTML" => Some(DomSinkKind::InsertAdjacentHtml),
        "write" | "writeln" => {
            // Only flag when the receiver is the bare identifier `document`.
            if let Expression::Identifier(id) = &member.object
                && id.name.as_str() == "document"
            {
                return Some(if prop == "write" {
                    DomSinkKind::DocumentWrite
                } else {
                    DomSinkKind::DocumentWriteln
                });
            }
            None
        }
        _ => None,
    }
}

/// Classifies an assignment target as a [`DomSinkKind`], if it is a member
/// expression ending in `.innerHTML` or `.outerHTML`.
fn dom_sink_kind_for_assignment_target(
    target: &oxc_ast::ast::AssignmentTarget<'_>,
) -> Option<DomSinkKind> {
    if let oxc_ast::ast::AssignmentTarget::StaticMemberExpression(m) = target {
        return match m.property.name.as_str() {
            "innerHTML" => Some(DomSinkKind::InnerHtml),
            "outerHTML" => Some(DomSinkKind::OuterHtml),
            _ => None,
        };
    }
    None
}

/// Returns `true` when the argument is a string literal or a no-substitution
/// template literal.
fn is_string_like(arg: &Argument<'_>) -> bool {
    let Some(expr) = arg.as_expression() else {
        return false;
    };
    match expr {
        Expression::StringLiteral(_) => true,
        Expression::TemplateLiteral(tpl) => tpl.expressions.is_empty(),
        _ => false,
    }
}

#[allow(clippy::too_many_lines)]
fn walk_stmt(stmt: &Statement<'_>, out: &mut WalkCtx) {
    match stmt {
        Statement::ExpressionStatement(es) => walk_expr(&es.expression, out),
        Statement::VariableDeclaration(v) => {
            for d in &v.declarations {
                if let Some(init) = &d.init {
                    walk_expr(init, out);
                }
            }
        }
        Statement::ReturnStatement(r) => {
            if let Some(arg) = &r.argument {
                walk_expr(arg, out);
            }
        }
        Statement::BlockStatement(b) => {
            for s in &b.body {
                walk_stmt(s, out);
            }
        }
        Statement::IfStatement(s) => {
            walk_expr(&s.test, out);
            walk_stmt(&s.consequent, out);
            if let Some(alt) = &s.alternate {
                walk_stmt(alt, out);
            }
        }
        Statement::WhileStatement(s) => {
            walk_expr(&s.test, out);
            walk_stmt(&s.body, out);
        }
        Statement::DoWhileStatement(s) => {
            walk_expr(&s.test, out);
            walk_stmt(&s.body, out);
        }
        Statement::ForStatement(s) => {
            if let Some(init) = &s.init {
                if let oxc_ast::ast::ForStatementInit::VariableDeclaration(v) = init {
                    for d in &v.declarations {
                        if let Some(e) = &d.init {
                            walk_expr(e, out);
                        }
                    }
                } else if let Some(e) = init.as_expression() {
                    walk_expr(e, out);
                }
            }
            if let Some(test) = &s.test {
                walk_expr(test, out);
            }
            if let Some(update) = &s.update {
                walk_expr(update, out);
            }
            walk_stmt(&s.body, out);
        }
        Statement::ForInStatement(s) => walk_stmt(&s.body, out),
        Statement::ForOfStatement(s) => walk_stmt(&s.body, out),
        Statement::SwitchStatement(s) => {
            walk_expr(&s.discriminant, out);
            for case in &s.cases {
                if let Some(test) = &case.test {
                    walk_expr(test, out);
                }
                for stmt in &case.consequent {
                    walk_stmt(stmt, out);
                }
            }
        }
        Statement::TryStatement(s) => {
            for st in &s.block.body {
                walk_stmt(st, out);
            }
            if let Some(handler) = &s.handler {
                for st in &handler.body.body {
                    walk_stmt(st, out);
                }
            }
            if let Some(fin) = &s.finalizer {
                for st in &fin.body {
                    walk_stmt(st, out);
                }
            }
        }
        Statement::ThrowStatement(t) => walk_expr(&t.argument, out),
        Statement::LabeledStatement(l) => walk_stmt(&l.body, out),
        Statement::FunctionDeclaration(f) => {
            let prev = out.at_top_level;
            out.at_top_level = false;
            if let Some(body) = &f.body {
                for s in &body.statements {
                    walk_stmt(s, out);
                }
            }
            out.at_top_level = prev;
        }
        Statement::ClassDeclaration(c) => {
            let prev = out.at_top_level;
            out.at_top_level = false;
            for elt in &c.body.body {
                if let oxc_ast::ast::ClassElement::MethodDefinition(m) = elt
                    && let Some(body) = &m.value.body
                {
                    for s in &body.statements {
                        walk_stmt(s, out);
                    }
                }
            }
            out.at_top_level = prev;
        }
        Statement::ExportNamedDeclaration(e) => {
            if let Some(decl) = &e.declaration {
                walk_decl(decl, out);
            }
        }
        Statement::ExportDefaultDeclaration(e) => {
            if let Some(expr) = e.declaration.as_expression() {
                walk_expr(expr, out);
            }
        }
        // break, continue, debugger, import declarations, TS decls — no calls.
        _ => {}
    }
}

fn walk_decl(decl: &oxc_ast::ast::Declaration<'_>, out: &mut WalkCtx) {
    match decl {
        oxc_ast::ast::Declaration::FunctionDeclaration(f) => {
            if let Some(body) = &f.body {
                for s in &body.statements {
                    walk_stmt(s, out);
                }
            }
        }
        oxc_ast::ast::Declaration::ClassDeclaration(c) => {
            for elt in &c.body.body {
                if let oxc_ast::ast::ClassElement::MethodDefinition(m) = elt
                    && let Some(body) = &m.value.body
                {
                    for s in &body.statements {
                        walk_stmt(s, out);
                    }
                }
            }
        }
        oxc_ast::ast::Declaration::VariableDeclaration(v) => {
            for d in &v.declarations {
                if let Some(init) = &d.init {
                    walk_expr(init, out);
                }
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_lines)]
fn walk_expr(expr: &Expression<'_>, out: &mut WalkCtx) {
    match expr {
        Expression::CallExpression(call) => {
            // Check if the callee is a bare identifier.
            if let Expression::Identifier(id) = &call.callee {
                let name = id.name.to_string();
                let first_arg_is_string = call.arguments.first().is_some_and(is_string_like);
                let first_arg_span =
                    call.arguments
                        .first()
                        .and_then(|a| a.as_expression())
                        .map(|e| {
                            use oxc_span::GetSpan;
                            oxc_span_to_core(e.span())
                        });
                let site = JsCallSite {
                    callee: JsCallee::Name(name.clone()),
                    span: oxc_span_to_core(call.span),
                    first_arg_is_string_literal: first_arg_is_string,
                    first_arg_span,
                };
                // Detect top-level `require("module")` calls for PERF002.
                if out.at_top_level
                    && name == "require"
                    && call.arguments.first().is_some_and(is_string_like)
                    && let Some(Argument::StringLiteral(s)) = call.arguments.first()
                {
                    out.imports.push(JsImport {
                        source: s.value.to_string(),
                        span: oxc_span_to_core(call.span),
                    });
                }
                // Record the top-level call for PERF003.
                if out.at_top_level {
                    out.top_level_calls.push(site.clone());
                }
                out.call_sites.push(site);
            }
            // Detect DOM sinks shaped as member-access calls
            // (`document.write(...)`, `el.insertAdjacentHTML(pos, html)`).
            if let Some(kind) = dom_sink_kind_for_call(&call.callee) {
                out.dom_sinks.push(JsDomSink {
                    kind,
                    span: oxc_span_to_core(call.span),
                });
            }
            // Recurse into callee (handles `Function('x')()` — the inner
            // `Function('x')` is the callee of the outer call).
            walk_expr(&call.callee, out);
            // Recurse into arguments.
            for arg in &call.arguments {
                if let Some(e) = arg.as_expression() {
                    walk_expr(e, out);
                }
            }
        }
        Expression::NewExpression(new_expr) => {
            // `new Function(...)` — check if the callee is a bare identifier.
            if let Expression::Identifier(id) = &new_expr.callee {
                let name = id.name.to_string();
                let first_arg_is_string = new_expr.arguments.first().is_some_and(is_string_like);
                let first_arg_span = new_expr
                    .arguments
                    .first()
                    .and_then(|a| a.as_expression())
                    .map(|e| {
                        use oxc_span::GetSpan;
                        oxc_span_to_core(e.span())
                    });
                out.call_sites.push(JsCallSite {
                    callee: JsCallee::New(name),
                    span: oxc_span_to_core(new_expr.span),
                    first_arg_is_string_literal: first_arg_is_string,
                    first_arg_span,
                });
            }
            // Recurse into arguments.
            for arg in &new_expr.arguments {
                if let Some(e) = arg.as_expression() {
                    walk_expr(e, out);
                }
            }
        }
        Expression::ArrowFunctionExpression(arrow) => {
            let prev = out.at_top_level;
            out.at_top_level = false;
            for stmt in &arrow.body.statements {
                walk_stmt(stmt, out);
            }
            out.at_top_level = prev;
        }
        Expression::FunctionExpression(f) => {
            let prev = out.at_top_level;
            out.at_top_level = false;
            if let Some(body) = &f.body {
                for s in &body.statements {
                    walk_stmt(s, out);
                }
            }
            out.at_top_level = prev;
        }
        Expression::ClassExpression(c) => {
            let prev = out.at_top_level;
            out.at_top_level = false;
            for elt in &c.body.body {
                if let oxc_ast::ast::ClassElement::MethodDefinition(m) = elt
                    && let Some(body) = &m.value.body
                {
                    for s in &body.statements {
                        walk_stmt(s, out);
                    }
                }
            }
            out.at_top_level = prev;
        }
        Expression::BinaryExpression(b) => {
            walk_expr(&b.left, out);
            walk_expr(&b.right, out);
        }
        Expression::LogicalExpression(l) => {
            walk_expr(&l.left, out);
            walk_expr(&l.right, out);
        }
        Expression::UnaryExpression(u) => walk_expr(&u.argument, out),
        Expression::ConditionalExpression(c) => {
            walk_expr(&c.test, out);
            walk_expr(&c.consequent, out);
            walk_expr(&c.alternate, out);
        }
        Expression::AssignmentExpression(a) => {
            // Detect `<expr>.innerHTML = …` / `<expr>.outerHTML = …`.
            //
            // We treat *any* assignment of those property names as a sink and
            // do not try to filter by RHS shape. Filtering trivial RHS values
            // (string literals with no interpolation) would require a second
            // analyzer-side check; for v1 we keep the parser dumb and the
            // analyzer simple — false positives on `el.innerHTML = ""` are
            // acceptable noise at severity High.
            if let Some(kind) = dom_sink_kind_for_assignment_target(&a.left) {
                out.dom_sinks.push(JsDomSink {
                    kind,
                    span: oxc_span_to_core(a.span),
                });
            }
            walk_expr(&a.right, out);
        }
        Expression::AwaitExpression(a) => walk_expr(&a.argument, out),
        Expression::YieldExpression(y) => {
            if let Some(arg) = &y.argument {
                walk_expr(arg, out);
            }
        }
        Expression::SequenceExpression(s) => {
            for e in &s.expressions {
                walk_expr(e, out);
            }
        }
        Expression::ParenthesizedExpression(p) => walk_expr(&p.expression, out),
        Expression::ArrayExpression(a) => {
            for elt in &a.elements {
                if let Some(e) = elt.as_expression() {
                    walk_expr(e, out);
                }
            }
        }
        Expression::ObjectExpression(o) => {
            for prop in &o.properties {
                if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop {
                    walk_expr(&p.value, out);
                }
            }
        }
        Expression::TaggedTemplateExpression(t) => {
            walk_expr(&t.tag, out);
            for e in &t.quasi.expressions {
                walk_expr(e, out);
            }
        }
        Expression::TemplateLiteral(t) => {
            for e in &t.expressions {
                walk_expr(e, out);
            }
        }
        // TS wrappers — unwrap and recurse
        Expression::TSAsExpression(e) => walk_expr(&e.expression, out),
        Expression::TSSatisfiesExpression(e) => walk_expr(&e.expression, out),
        Expression::TSNonNullExpression(e) => walk_expr(&e.expression, out),
        Expression::TSTypeAssertion(e) => walk_expr(&e.expression, out),
        Expression::TSInstantiationExpression(e) => walk_expr(&e.expression, out),
        // JSX — recurse into children so we find calls inside `{eval(...)}`.
        Expression::JSXElement(el) => {
            walk_jsx_attrs(&el.opening_element.attributes, out);
            walk_jsx_children(&el.children, out);
        }
        Expression::JSXFragment(frag) => {
            walk_jsx_children(&frag.children, out);
        }
        // Member expressions — NOT followed in v1 (no `obj.eval(...)` detection).
        // Literals, identifiers, this, super, meta-properties — no sub-expressions.
        _ => {}
    }
}

fn walk_jsx_attrs(attrs: &[oxc_ast::ast::JSXAttributeItem<'_>], out: &mut WalkCtx) {
    use oxc_ast::ast::{JSXAttributeItem, JSXAttributeName, JSXAttributeValue};

    for attr in attrs {
        if let JSXAttributeItem::Attribute(a) = attr {
            // Detect `dangerouslySetInnerHTML={…}`. Match the bare attribute
            // name only — namespaced JSX attributes are out of scope.
            if let JSXAttributeName::Identifier(ident) = &a.name
                && ident.name.as_str() == "dangerouslySetInnerHTML"
            {
                use oxc_span::GetSpan;
                out.dom_sinks.push(JsDomSink {
                    kind: DomSinkKind::DangerouslySetInnerHtml,
                    span: oxc_span_to_core(a.span()),
                });
            }
            if let Some(JSXAttributeValue::ExpressionContainer(ec)) = &a.value
                && let Some(e) = ec.expression.as_expression()
            {
                walk_expr(e, out);
            }
        }
    }
}

fn walk_jsx_children(children: &[oxc_ast::ast::JSXChild<'_>], out: &mut WalkCtx) {
    for child in children {
        match child {
            oxc_ast::ast::JSXChild::ExpressionContainer(ec) => {
                if let Some(e) = ec.expression.as_expression() {
                    walk_expr(e, out);
                }
            }
            oxc_ast::ast::JSXChild::Element(el) => {
                walk_jsx_attrs(&el.opening_element.attributes, out);
                walk_jsx_children(&el.children, out);
            }
            oxc_ast::ast::JSXChild::Fragment(frag) => {
                walk_jsx_children(&frag.children, out);
            }
            _ => {}
        }
    }
}

// ── error helpers ─────────────────────────────────────────────────────────────

/// Converts the first error in a panicking parse into a [`ParseError::Syntax`].
fn diagnostic_to_error(
    source: &SourceFile,
    errors: &[oxc_diagnostics::OxcDiagnostic],
) -> ParseError {
    let (message, span) = match errors.first() {
        Some(d) => {
            let span = d.labels.as_ref().and_then(|ls| ls.first()).map(|lbl| {
                let start = u32::try_from(lbl.offset()).unwrap_or(0);
                let len = u32::try_from(lbl.len()).unwrap_or(0);
                Span::new(ByteOffset(start), ByteOffset(start.saturating_add(len)))
            });
            (d.message.to_string(), span)
        }
        None => ("parse failed".to_string(), None),
    };
    ParseError::Syntax {
        file: source.path.clone(),
        message,
        span,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(path: &str, content: &str) -> Arc<SourceFile> {
        Arc::new(SourceFile::new(path, content.as_bytes().to_vec()))
    }

    #[test]
    fn parse_basic_js() {
        let pf = parse(src("a.js", "const x = 1;\n")).unwrap();
        assert_eq!(pf.language(), LanguageId("javascript"));
    }

    #[test]
    fn parse_basic_ts() {
        let pf = parse(src(
            "a.ts",
            "export interface Foo { x: number }\nexport const v: Foo = { x: 1 };",
        ))
        .unwrap();
        assert_eq!(pf.language(), LanguageId("javascript"));
    }

    #[test]
    fn parse_native_downcast_succeeds() {
        let pf = parse(src("a.js", "const x = 1;")).unwrap();
        assert!(pf.native::<JsAst>().is_some());
    }

    #[test]
    fn parse_empty_source_ok() {
        let pf = parse(src("a.js", ""));
        assert!(pf.is_ok());
    }

    #[test]
    fn parse_unknown_extension_falls_back_to_js() {
        // The engine wouldn't normally route `.weird` files here, but the
        // fallback should still produce a valid result for plain JS source.
        let pf = parse(src("a.weird", "const x = 1;\n"));
        assert!(pf.is_ok());
    }

    // ── JsAst call-site extraction tests ─────────────────────────────────────

    #[test]
    fn extracts_eval_call_site() {
        let pf = parse(src("a.js", "eval(x);")).unwrap();
        let ast = pf.native::<JsAst>().expect("invariant: JsAst present");
        assert_eq!(ast.call_sites.len(), 1);
        assert_eq!(ast.call_sites[0].callee, JsCallee::Name("eval".to_string()));
    }

    #[test]
    fn extracts_new_function_call_site() {
        let pf = parse(src("a.js", "new Function('return 1');")).unwrap();
        let ast = pf.native::<JsAst>().expect("invariant: JsAst present");
        assert_eq!(ast.call_sites.len(), 1);
        assert_eq!(
            ast.call_sites[0].callee,
            JsCallee::New("Function".to_string())
        );
        assert!(ast.call_sites[0].first_arg_is_string_literal);
    }

    #[test]
    fn first_arg_is_string_literal_true_for_string() {
        let pf = parse(src("a.js", r#"setTimeout("code()", 0);"#)).unwrap();
        let ast = pf.native::<JsAst>().expect("invariant: JsAst present");
        let site = ast
            .call_sites
            .iter()
            .find(|s| matches!(&s.callee, JsCallee::Name(n) if n == "setTimeout"))
            .expect("expected setTimeout call site");
        assert!(site.first_arg_is_string_literal);
    }

    #[test]
    fn first_arg_is_string_literal_true_for_no_sub_template() {
        let pf = parse(src("a.js", "setTimeout(`code()`, 0);")).unwrap();
        let ast = pf.native::<JsAst>().expect("invariant: JsAst present");
        let site = ast
            .call_sites
            .iter()
            .find(|s| matches!(&s.callee, JsCallee::Name(n) if n == "setTimeout"))
            .expect("expected setTimeout call site");
        assert!(site.first_arg_is_string_literal);
    }

    #[test]
    fn first_arg_is_string_literal_false_for_arrow_fn() {
        let pf = parse(src("a.js", "setTimeout(() => 1, 0);")).unwrap();
        let ast = pf.native::<JsAst>().expect("invariant: JsAst present");
        // The setTimeout call site should still be recorded (it's a bare
        // identifier call), but first_arg_is_string_literal must be false.
        let site = ast
            .call_sites
            .iter()
            .find(|s| matches!(&s.callee, JsCallee::Name(n) if n == "setTimeout"))
            .expect("expected setTimeout call site");
        assert!(!site.first_arg_is_string_literal);
    }

    #[test]
    fn template_with_substitution_is_not_string_literal() {
        // `setTimeout(\`code(${x})\`, 0)` — has substitution, must NOT be flagged.
        let pf = parse(src("a.js", "setTimeout(`code(${x})`, 0);")).unwrap();
        let ast = pf.native::<JsAst>().expect("invariant: JsAst present");
        let site = ast
            .call_sites
            .iter()
            .find(|s| matches!(&s.callee, JsCallee::Name(n) if n == "setTimeout"))
            .expect("expected setTimeout call site");
        assert!(!site.first_arg_is_string_literal);
    }

    #[test]
    fn member_call_not_recorded_as_bare_name() {
        // `window.eval(x)` — callee is a MemberExpression, not a bare Identifier.
        // It must NOT appear in call_sites.
        let pf = parse(src("a.js", "window.eval(x);")).unwrap();
        let ast = pf.native::<JsAst>().expect("invariant: JsAst present");
        let eval_sites: Vec<_> = ast
            .call_sites
            .iter()
            .filter(|s| matches!(&s.callee, JsCallee::Name(n) if n == "eval"))
            .collect();
        assert!(
            eval_sites.is_empty(),
            "member-access eval should not be in call_sites"
        );
    }

    #[test]
    fn no_call_sites_for_safe_code() {
        let pf = parse(src("a.ts", "const x = 1 + 2; console.log(x);")).unwrap();
        let ast = pf.native::<JsAst>().expect("invariant: JsAst present");
        // console.log is a member call, not a bare identifier call.
        assert!(
            ast.call_sites.is_empty(),
            "expected no call sites, got: {:#?}",
            ast.call_sites
        );
    }
}
