//! Builds a [`zuit_core::SemanticIndex`] by walking an `oxc_ast::Program`.
//!
//! Mapping rules:
//!
//! - `FunctionDeclaration` and `FunctionExpression` → [`FunctionKind::Function`]
//!   (or [`FunctionKind::Method`] when found inside a [`ClassBody`]).
//! - `ArrowFunctionExpression` → [`FunctionKind::ArrowFn`].
//! - `MethodDefinition` (`constructor`, `bar()`, `get x()`, `set x(v)`,
//!   `static foo()`) → [`FunctionKind::Method`]. Constructors keep their
//!   name as `"constructor"`.
//! - Visibility: anything reached through `ExportNamedDeclaration`,
//!   `ExportDefaultDeclaration`, or `ExportAllDeclaration` is
//!   [`Visibility::Public`]; otherwise top-level non-`export`s and any
//!   nested item are [`Visibility::Private`]. Names starting with `_` are
//!   demoted to private (matches the Python frontend's convention).
//! - `is_test = true` when the function name starts with `test_`.
//! - Imports: one [`Import`] per `ImportDeclaration`, with `path = source.value`.
//! - String literals: every `StringLiteral` and the static parts (`cooked`)
//!   of every `TemplateLiteral` quasi land in
//!   [`SemanticIndex::string_literals`].
//! - Comments and doc-comments come straight from `program.comments`. A block
//!   comment is treated as a doc-comment when [`oxc_ast::ast::Comment::is_jsdoc`]
//!   returns true. The link between a `JSDoc` comment and the item it documents
//!   is the comment's `attached_to` field, which oxc fills in with the start
//!   offset of the next token.
//! - TypeScript `interface`, `type`, and `enum` declarations land in
//!   [`SemanticIndex::types`] (both top-level and re-exported forms). Their
//!   [`TypeDecl::doc`] is populated when an attached `JSDoc` precedes them.

use std::collections::BTreeMap;

use oxc_ast::ast::{
    Class, ClassElement, Comment, Declaration, ExportDefaultDeclaration,
    ExportDefaultDeclarationKind, Expression, Function, FunctionType, MethodDefinitionKind,
    Program, PropertyKey, Statement, TSEnumDeclaration, TSInterfaceDeclaration,
    TSTypeAliasDeclaration, VariableDeclaration,
};
use oxc_span::Span as OxcSpan;

use zuit_core::{
    ByteOffset, Comment as CoreComment, DocComment, FunctionKind, FunctionLike, Import, NodeId,
    SemanticIndex, Span, StringLit, Suppression, TypeDecl, Visibility, parse_suppression_directive,
};

use crate::complexity;

/// Builds the semantic index for a parsed JS/TS `Program`.
pub(crate) fn build_index(
    program: &Program<'_>,
    source: &zuit_core::SourceFile,
) -> SemanticIndex {
    let mut ctx = IndexCtx::new(program);

    for stmt in &program.body {
        walk_top_level_stmt(stmt, &mut ctx, /* exported */ false);
    }

    extract_comments(program, source, &mut ctx);

    // Scan comments for suppression directives.
    extract_suppressions(source, &mut ctx.index);

    ctx.index
}

/// Scans the comments already extracted into `index.comments` and populates
/// `index.suppressions` with any `zuit: ignore` / `zuit: ignore-file`
/// directives found.
fn extract_suppressions(source: &zuit_core::SourceFile, index: &mut SemanticIndex) {
    let comment_data: Vec<(u32, String)> = index
        .comments
        .iter()
        .map(|c| (c.span.start.0, c.text.clone()))
        .collect();

    for (start_offset, text) in comment_data {
        if let Some((rule_ids, file_scoped)) = parse_suppression_directive(&text) {
            let line = source.offset_to_linecol(ByteOffset(start_offset)).line;
            for rule_id in rule_ids {
                index.suppressions.push(Suppression {
                    line,
                    rule_id,
                    file_scoped,
                });
            }
        }
    }
}

// ── bookkeeping ──────────────────────────────────────────────────────────────

struct IndexCtx<'p> {
    index: SemanticIndex,
    next_id: u32,
    /// Map from "token start offset" → `NodeId` of a `JSDoc` comment that
    /// `oxc_parser` already attached to that token. Lets us link function /
    /// type decls to their docstrings without scanning the source ourselves.
    jsdoc_by_attach: BTreeMap<u32, NodeId>,
    _program: std::marker::PhantomData<&'p ()>,
}

impl<'p> IndexCtx<'p> {
    fn new(_program: &Program<'p>) -> Self {
        Self {
            index: SemanticIndex::new(),
            next_id: 0,
            jsdoc_by_attach: BTreeMap::new(),
            _program: std::marker::PhantomData,
        }
    }

    fn alloc_id(&mut self) -> NodeId {
        let id = NodeId(self.next_id);
        self.next_id += 1;
        id
    }
}

fn span_of(s: OxcSpan) -> Span {
    Span::new(ByteOffset(s.start), ByteOffset(s.end))
}

// ── top-level walker ─────────────────────────────────────────────────────────

/// Walks a top-level statement, propagating `exported` so that the
/// `ExportNamedDeclaration` / `ExportDefaultDeclaration` wrappers translate
/// into `Visibility::Public` for the inner decl.
fn walk_top_level_stmt(stmt: &Statement<'_>, ctx: &mut IndexCtx<'_>, exported: bool) {
    match stmt {
        Statement::FunctionDeclaration(f) => {
            register_function(f, ctx, /* is_method */ false, exported);
        }
        Statement::ClassDeclaration(c) => {
            register_class(c, ctx, exported);
        }
        Statement::VariableDeclaration(v) => {
            register_variable_decl(v, ctx, exported);
        }
        Statement::ImportDeclaration(i) => {
            let id = ctx.alloc_id();
            ctx.index.imports.push(Import {
                id,
                path: i.source.value.to_string(),
                span: span_of(i.span),
            });
        }
        Statement::ExportNamedDeclaration(e) => {
            if let Some(decl) = &e.declaration {
                walk_top_level_decl(decl, ctx, /* exported */ true);
            }
            // Re-export form `export { x } from 'mod';` carries a `source`.
            if let Some(src) = &e.source {
                let id = ctx.alloc_id();
                ctx.index.imports.push(Import {
                    id,
                    path: src.value.to_string(),
                    span: span_of(e.span),
                });
            }
        }
        Statement::ExportDefaultDeclaration(e) => {
            register_export_default(e, ctx);
        }
        Statement::ExportAllDeclaration(e) => {
            let id = ctx.alloc_id();
            ctx.index.imports.push(Import {
                id,
                path: e.source.value.to_string(),
                span: span_of(e.span),
            });
        }
        Statement::TSInterfaceDeclaration(i) => {
            register_interface(i, ctx, exported);
        }
        Statement::TSTypeAliasDeclaration(t) => {
            register_type_alias(t, ctx, exported);
        }
        Statement::TSEnumDeclaration(e) => {
            register_enum(e, ctx, exported);
        }
        // Recurse into compound statements — JS lets you nest function
        // declarations inside blocks, and TS lets you put declarations inside
        // namespaces.
        Statement::BlockStatement(b) => {
            for s in &b.body {
                walk_top_level_stmt(s, ctx, false);
            }
        }
        Statement::IfStatement(s) => {
            walk_in_stmt(&s.consequent, ctx);
            if let Some(alt) = &s.alternate {
                walk_in_stmt(alt, ctx);
            }
        }
        Statement::ForStatement(s) => walk_in_stmt(&s.body, ctx),
        Statement::ForInStatement(s) => walk_in_stmt(&s.body, ctx),
        Statement::ForOfStatement(s) => walk_in_stmt(&s.body, ctx),
        Statement::WhileStatement(s) => walk_in_stmt(&s.body, ctx),
        Statement::DoWhileStatement(s) => walk_in_stmt(&s.body, ctx),
        Statement::TryStatement(s) => {
            for st in &s.block.body {
                walk_in_stmt(st, ctx);
            }
            if let Some(h) = &s.handler {
                for st in &h.body.body {
                    walk_in_stmt(st, ctx);
                }
            }
            if let Some(f) = &s.finalizer {
                for st in &f.body {
                    walk_in_stmt(st, ctx);
                }
            }
        }
        Statement::SwitchStatement(s) => {
            for case in &s.cases {
                for st in &case.consequent {
                    walk_in_stmt(st, ctx);
                }
            }
        }
        Statement::ExpressionStatement(es) => {
            collect_expr(&es.expression, ctx);
        }
        // Other statement variants (return, break, throw, …) carry no
        // declarations we care about.
        _ => {}
    }
}

/// `walk_top_level_stmt` for nested contexts (inside other statements or
/// blocks). Treats every reachable item as private (no `exported` flag).
fn walk_in_stmt(stmt: &Statement<'_>, ctx: &mut IndexCtx<'_>) {
    walk_top_level_stmt(stmt, ctx, false);
}

fn walk_top_level_decl(decl: &Declaration<'_>, ctx: &mut IndexCtx<'_>, exported: bool) {
    match decl {
        Declaration::FunctionDeclaration(f) => register_function(f, ctx, false, exported),
        Declaration::ClassDeclaration(c) => register_class(c, ctx, exported),
        Declaration::VariableDeclaration(v) => register_variable_decl(v, ctx, exported),
        Declaration::TSInterfaceDeclaration(i) => register_interface(i, ctx, exported),
        Declaration::TSTypeAliasDeclaration(t) => register_type_alias(t, ctx, exported),
        Declaration::TSEnumDeclaration(e) => register_enum(e, ctx, exported),
        // TSModuleDeclaration / TSImportEqualsDeclaration / TSGlobalDeclaration
        // are rare; not registering them keeps the v1 index simple.
        _ => {}
    }
}

fn register_export_default(e: &ExportDefaultDeclaration<'_>, ctx: &mut IndexCtx<'_>) {
    match &e.declaration {
        ExportDefaultDeclarationKind::FunctionDeclaration(f) => {
            register_function(f, ctx, false, /* exported */ true);
        }
        ExportDefaultDeclarationKind::ClassDeclaration(c) => {
            register_class(c, ctx, /* exported */ true);
        }
        ExportDefaultDeclarationKind::TSInterfaceDeclaration(i) => {
            register_interface(i, ctx, /* exported */ true);
        }
        // `export default <expr>;` — recurse for any contained string
        // literals / arrow functions / class expressions. The `inherit_variants!`
        // macro generates `as_expression()` for the inherited variants.
        other => {
            if let Some(expr) = other.as_expression() {
                collect_expr(expr, ctx);
            }
        }
    }
}

// ── functions / methods ──────────────────────────────────────────────────────

fn register_function(f: &Function<'_>, ctx: &mut IndexCtx<'_>, is_method: bool, exported: bool) {
    // `r#type == TSDeclareFunction` is just a type signature (`declare
    // function foo(): void;`) — no implementation, no complexity to compute.
    if matches!(
        f.r#type,
        FunctionType::TSDeclareFunction | FunctionType::TSEmptyBodyFunctionExpression
    ) {
        // Still register it with body_span == span so DOC001 can flag it.
        let name = f.id.as_ref().map(|i| i.name.to_string());
        let visibility = effective_visibility(name.as_deref(), exported);
        let kind = if is_method {
            FunctionKind::Method
        } else {
            FunctionKind::Function
        };
        let id = ctx.alloc_id();
        let doc = ctx.jsdoc_by_attach.get(&f.span.start).copied();
        ctx.index.functions.push(FunctionLike {
            id,
            kind,
            name,
            visibility,
            span: span_of(f.span),
            body_span: span_of(f.span),
            param_count: u32::try_from(f.params.items.len()).unwrap_or(u32::MAX),
            is_async: f.r#async,
            is_test: false,
            doc,
            complexity: zuit_core::ComplexityMetrics::default(),
            parent_name: None,
        });
        return;
    }

    let name = f.id.as_ref().map(|i| i.name.to_string());
    let body_span = f
        .body
        .as_ref()
        .map_or_else(|| span_of(f.span), |b| span_of(b.span));
    let metrics = f
        .body
        .as_ref()
        .map(|b| complexity::compute_function_complexity(&b.statements))
        .unwrap_or_default();
    let visibility = effective_visibility(name.as_deref(), exported);
    let kind = if is_method {
        FunctionKind::Method
    } else {
        FunctionKind::Function
    };
    let is_test = name.as_deref().is_some_and(|n| n.starts_with("test_"));
    let param_count = u32::try_from(f.params.items.len()).unwrap_or(u32::MAX);
    let doc = ctx.jsdoc_by_attach.get(&f.span.start).copied();

    let id = ctx.alloc_id();
    ctx.index.functions.push(FunctionLike {
        id,
        kind,
        name,
        visibility,
        span: span_of(f.span),
        body_span,
        param_count,
        is_async: f.r#async,
        is_test,
        doc,
        complexity: metrics,
        parent_name: None,
    });

    // Walk the body for nested decls and string literals.
    if let Some(body) = &f.body {
        for stmt in &body.statements {
            walk_in_stmt(stmt, ctx);
        }
    }
}

// ── classes ──────────────────────────────────────────────────────────────────

fn register_class(c: &Class<'_>, ctx: &mut IndexCtx<'_>, exported: bool) {
    let name =
        c.id.as_ref()
            .map_or_else(|| "<anonymous>".to_string(), |i| i.name.to_string());
    let visibility = effective_visibility(Some(&name), exported);
    let doc = ctx.jsdoc_by_attach.get(&c.span.start).copied();

    let id = ctx.alloc_id();
    ctx.index.types.push(TypeDecl {
        id,
        name,
        visibility,
        span: span_of(c.span),
        doc,
    });

    // Register methods.
    for elt in &c.body.body {
        if let ClassElement::MethodDefinition(m) = elt {
            let method_name = method_key_name(&m.key);
            let body_span = m
                .value
                .body
                .as_ref()
                .map_or_else(|| span_of(m.span), |b| span_of(b.span));
            let metrics = m
                .value
                .body
                .as_ref()
                .map(|b| complexity::compute_function_complexity(&b.statements))
                .unwrap_or_default();
            let is_test = method_name
                .as_deref()
                .is_some_and(|n| n.starts_with("test_"));
            let visibility_method = match method_name.as_deref() {
                Some(n) if n.starts_with('_') => Visibility::Private,
                Some(_) => Visibility::Public,
                None => Visibility::Private,
            };
            let param_count = u32::try_from(m.value.params.items.len()).unwrap_or(u32::MAX);
            // Methods can't carry their own JSDoc via `attached_to` reliably
            // because oxc attaches comments to *tokens*; a method's leading
            // JSDoc lands at the method's `m.span.start`.
            let doc = ctx.jsdoc_by_attach.get(&m.span.start).copied();
            let kind = match m.kind {
                MethodDefinitionKind::Constructor
                | MethodDefinitionKind::Method
                | MethodDefinitionKind::Get
                | MethodDefinitionKind::Set => FunctionKind::Method,
            };
            let id = ctx.alloc_id();
            ctx.index.functions.push(FunctionLike {
                id,
                kind,
                name: method_name,
                visibility: visibility_method,
                span: span_of(m.span),
                body_span,
                param_count,
                is_async: m.value.r#async,
                is_test,
                doc,
                complexity: metrics,
                parent_name: None,
            });

            if let Some(body) = &m.value.body {
                for stmt in &body.statements {
                    walk_in_stmt(stmt, ctx);
                }
            }
        }
    }
}

fn method_key_name(key: &PropertyKey<'_>) -> Option<String> {
    match key {
        PropertyKey::StaticIdentifier(id) => Some(id.name.to_string()),
        PropertyKey::PrivateIdentifier(id) => Some(format!("#{}", id.name)),
        // Computed keys (`["m"]`, `[Symbol.iterator]`, …) — no static name.
        _ => None,
    }
}

// ── variable declarations: arrow functions and string literals ───────────────

fn register_variable_decl(v: &VariableDeclaration<'_>, ctx: &mut IndexCtx<'_>, exported: bool) {
    for declarator in &v.declarations {
        // `const greet = (...) => { ... };` — pick up the arrow function and
        // give it the binding's name.
        let bound_name = match &declarator.id {
            oxc_ast::ast::BindingPattern::BindingIdentifier(id) => Some(id.name.to_string()),
            _ => None,
        };
        if let Some(init) = &declarator.init {
            register_named_expression(init, bound_name.as_deref(), exported, ctx, declarator.span);
        }
    }
}

fn register_named_expression(
    expr: &Expression<'_>,
    binding_name: Option<&str>,
    exported: bool,
    ctx: &mut IndexCtx<'_>,
    declarator_span: OxcSpan,
) {
    match expr {
        Expression::ArrowFunctionExpression(arrow) => {
            let name = binding_name.map(str::to_string);
            let visibility = effective_visibility(name.as_deref(), exported);
            let body_span = span_of(arrow.body.span);
            let metrics = complexity::compute_function_complexity(&arrow.body.statements);
            let is_test = name.as_deref().is_some_and(|n| n.starts_with("test_"));
            let param_count = u32::try_from(arrow.params.items.len()).unwrap_or(u32::MAX);
            // JSDoc on `const x = () => …;` attaches to the variable
            // declarator's start, not the arrow's.
            let doc = ctx.jsdoc_by_attach.get(&declarator_span.start).copied();

            let id = ctx.alloc_id();
            ctx.index.functions.push(FunctionLike {
                id,
                kind: FunctionKind::ArrowFn,
                name,
                visibility,
                span: span_of(arrow.span),
                body_span,
                param_count,
                is_async: arrow.r#async,
                is_test,
                doc,
                complexity: metrics,
                parent_name: None,
            });

            for stmt in &arrow.body.statements {
                walk_in_stmt(stmt, ctx);
            }
        }
        Expression::FunctionExpression(f) => {
            // `const greet = function(){}` — register as a Function but use
            // the binding name when the expression itself is anonymous.
            let name =
                f.id.as_ref()
                    .map(|i| i.name.to_string())
                    .or_else(|| binding_name.map(str::to_string));
            register_function_expression_inline(f, name, exported, ctx, declarator_span);
        }
        Expression::ClassExpression(c) => {
            register_class(c, ctx, exported);
        }
        // Recurse into the rest so we still pick up string literals etc.
        _ => collect_expr(expr, ctx),
    }
}

/// Registers a `FunctionExpression` (e.g. `const f = function(){}`) when the
/// binding gives it a name the function itself doesn't carry.
///
/// Mirrors [`register_function`] but takes the resolved name and the surrounding
/// declarator span (which is where the `JSDoc` comment, if any, attaches).
fn register_function_expression_inline(
    f: &Function<'_>,
    name: Option<String>,
    exported: bool,
    ctx: &mut IndexCtx<'_>,
    declarator_span: OxcSpan,
) {
    let visibility = effective_visibility(name.as_deref(), exported);
    let body_span = f
        .body
        .as_ref()
        .map_or_else(|| span_of(f.span), |b| span_of(b.span));
    let metrics = f
        .body
        .as_ref()
        .map(|b| complexity::compute_function_complexity(&b.statements))
        .unwrap_or_default();
    let is_test = name.as_deref().is_some_and(|n| n.starts_with("test_"));
    let param_count = u32::try_from(f.params.items.len()).unwrap_or(u32::MAX);
    let doc = ctx.jsdoc_by_attach.get(&declarator_span.start).copied();

    let id = ctx.alloc_id();
    ctx.index.functions.push(FunctionLike {
        id,
        kind: FunctionKind::Function,
        name,
        visibility,
        span: span_of(f.span),
        body_span,
        param_count,
        is_async: f.r#async,
        is_test,
        doc,
        complexity: metrics,
        parent_name: None,
    });

    if let Some(body) = &f.body {
        for stmt in &body.statements {
            walk_in_stmt(stmt, ctx);
        }
    }
}

// ── TS type / interface / enum ───────────────────────────────────────────────

fn register_interface(i: &TSInterfaceDeclaration<'_>, ctx: &mut IndexCtx<'_>, exported: bool) {
    let name = i.id.name.to_string();
    let visibility = effective_visibility(Some(&name), exported);
    let doc = ctx.jsdoc_by_attach.get(&i.span.start).copied();
    let id = ctx.alloc_id();
    ctx.index.types.push(TypeDecl {
        id,
        name,
        visibility,
        span: span_of(i.span),
        doc,
    });
}

fn register_type_alias(t: &TSTypeAliasDeclaration<'_>, ctx: &mut IndexCtx<'_>, exported: bool) {
    let name = t.id.name.to_string();
    let visibility = effective_visibility(Some(&name), exported);
    let doc = ctx.jsdoc_by_attach.get(&t.span.start).copied();
    let id = ctx.alloc_id();
    ctx.index.types.push(TypeDecl {
        id,
        name,
        visibility,
        span: span_of(t.span),
        doc,
    });
}

fn register_enum(e: &TSEnumDeclaration<'_>, ctx: &mut IndexCtx<'_>, exported: bool) {
    let name = e.id.name.to_string();
    let visibility = effective_visibility(Some(&name), exported);
    let doc = ctx.jsdoc_by_attach.get(&e.span.start).copied();
    let id = ctx.alloc_id();
    ctx.index.types.push(TypeDecl {
        id,
        name,
        visibility,
        span: span_of(e.span),
        doc,
    });
}

// ── expressions: string literal collection ──────────────────────────────────

#[allow(clippy::too_many_lines)]
fn collect_expr(expr: &Expression<'_>, ctx: &mut IndexCtx<'_>) {
    match expr {
        Expression::StringLiteral(s) => {
            let id = ctx.alloc_id();
            ctx.index.string_literals.push(StringLit {
                id,
                value: s.value.to_string(),
                span: span_of(s.span),
            });
        }
        Expression::TemplateLiteral(t) => {
            // Static parts only — interpolated bits are sub-expressions.
            for q in &t.quasis {
                if let Some(cooked) = q.value.cooked.as_ref() {
                    let id = ctx.alloc_id();
                    ctx.index.string_literals.push(StringLit {
                        id,
                        value: cooked.to_string(),
                        span: span_of(q.span),
                    });
                }
            }
            for e in &t.expressions {
                collect_expr(e, ctx);
            }
        }
        Expression::ArrowFunctionExpression(arrow) => {
            // Anonymous arrow somewhere inside an expression position
            // (callbacks, default values, etc.).
            let metrics = complexity::compute_function_complexity(&arrow.body.statements);
            let id = ctx.alloc_id();
            ctx.index.functions.push(FunctionLike {
                id,
                kind: FunctionKind::ArrowFn,
                name: None,
                visibility: Visibility::Private,
                span: span_of(arrow.span),
                body_span: span_of(arrow.body.span),
                param_count: u32::try_from(arrow.params.items.len()).unwrap_or(u32::MAX),
                is_async: arrow.r#async,
                is_test: false,
                doc: None,
                complexity: metrics,
                parent_name: None,
            });
            for stmt in &arrow.body.statements {
                walk_in_stmt(stmt, ctx);
            }
        }
        Expression::FunctionExpression(f) => {
            register_function(
                f, ctx, /* is_method */ false, /* exported */ false,
            );
        }
        Expression::ClassExpression(c) => register_class(c, ctx, false),
        Expression::CallExpression(c) => {
            collect_expr(&c.callee, ctx);
            for arg in &c.arguments {
                if let Some(e) = arg.as_expression() {
                    collect_expr(e, ctx);
                }
            }
        }
        Expression::NewExpression(c) => {
            collect_expr(&c.callee, ctx);
            for arg in &c.arguments {
                if let Some(e) = arg.as_expression() {
                    collect_expr(e, ctx);
                }
            }
        }
        Expression::ArrayExpression(a) => {
            for elt in &a.elements {
                if let Some(e) = elt.as_expression() {
                    collect_expr(e, ctx);
                }
            }
        }
        Expression::ObjectExpression(o) => {
            for prop in &o.properties {
                if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop {
                    collect_expr(&p.value, ctx);
                }
            }
        }
        Expression::BinaryExpression(b) => {
            collect_expr(&b.left, ctx);
            collect_expr(&b.right, ctx);
        }
        Expression::LogicalExpression(l) => {
            collect_expr(&l.left, ctx);
            collect_expr(&l.right, ctx);
        }
        Expression::UnaryExpression(u) => collect_expr(&u.argument, ctx),
        Expression::ConditionalExpression(c) => {
            collect_expr(&c.test, ctx);
            collect_expr(&c.consequent, ctx);
            collect_expr(&c.alternate, ctx);
        }
        Expression::AssignmentExpression(a) => collect_expr(&a.right, ctx),
        Expression::AwaitExpression(a) => collect_expr(&a.argument, ctx),
        Expression::YieldExpression(y) => {
            if let Some(arg) = &y.argument {
                collect_expr(arg, ctx);
            }
        }
        Expression::ParenthesizedExpression(p) => collect_expr(&p.expression, ctx),
        Expression::SequenceExpression(s) => {
            for e in &s.expressions {
                collect_expr(e, ctx);
            }
        }
        Expression::TSAsExpression(e) => collect_expr(&e.expression, ctx),
        Expression::TSSatisfiesExpression(e) => collect_expr(&e.expression, ctx),
        Expression::TSNonNullExpression(e) => collect_expr(&e.expression, ctx),
        Expression::TSTypeAssertion(e) => collect_expr(&e.expression, ctx),
        // Member / Identifier / This / literals other than strings: nothing to
        // do.
        _ => {}
    }
}

// ── visibility ───────────────────────────────────────────────────────────────

fn effective_visibility(name: Option<&str>, exported: bool) -> Visibility {
    if let Some(n) = name
        && n.starts_with('_')
    {
        return Visibility::Private;
    }
    if exported {
        Visibility::Public
    } else {
        Visibility::Private
    }
}

// ── comments + JSDoc ─────────────────────────────────────────────────────────

fn extract_comments(
    program: &Program<'_>,
    source: &zuit_core::SourceFile,
    ctx: &mut IndexCtx<'_>,
) {
    let bytes = source.as_str().as_bytes();
    for c in &program.comments {
        let span = span_of(c.span);
        let text = comment_text(c, bytes);
        let id = ctx.alloc_id();
        if c.is_jsdoc() {
            ctx.index.doc_comments.push(DocComment { id, text, span });
            ctx.jsdoc_by_attach.insert(c.attached_to, id);
        } else {
            ctx.index.comments.push(CoreComment { id, text, span });
        }
    }

    // We populated `jsdoc_by_attach` *after* we walked the AST above, so any
    // FunctionLike / TypeDecl that already exists in the index needs its
    // `doc` filled in retroactively.
    backfill_docs(ctx);
}

/// Links `JSDoc` comments to the function / type they document.
///
/// `oxc_parser` populates `Comment::attached_to` with the start byte of the
/// *token* the comment leads. For `/** doc */ export function foo() {}` the
/// token is `export`, but the `Function` AST node starts at `function`. The
/// `ExportNamedDeclaration` wrapper, in turn, starts at `export`. Rather than
/// thread two attach points through every registration call, we resolve the
/// linkage in one pass at the end:
///
/// 1. Walk the `JSDoc` table and, for each entry, find the function-or-type
///    whose `span.start` is the smallest value `>= attached_to`. That entry
///    "owns" the comment.
/// 2. Tolerate up to ~64 bytes of whitespace + modifiers (`export`, `async`,
///    `default`) between the comment and the documented item; further than
///    that and we assume the comment is unrelated.
fn backfill_docs(ctx: &mut IndexCtx<'_>) {
    /// Maximum gap (in bytes) between a `JSDoc`'s `attached_to` and the start
    /// of the documented item. 64 covers `export default async function` and
    /// generous indentation; beyond that the comment is almost certainly not
    /// for this item.
    const MAX_GAP: u32 = 64;

    // Build candidate-by-start lists once. We need fn / type span.starts
    // sorted ascending so we can binary-search the next item after each
    // attach point. Functions and types share the address space — both can
    // be the target of a JSDoc — so we merge them into a single list.
    enum Target {
        Function(usize),
        Type(usize),
    }
    let mut candidates: Vec<(u32, Target)> =
        Vec::with_capacity(ctx.index.functions.len() + ctx.index.types.len());
    for (i, f) in ctx.index.functions.iter().enumerate() {
        candidates.push((f.span.start.0, Target::Function(i)));
    }
    for (i, t) in ctx.index.types.iter().enumerate() {
        candidates.push((t.span.start.0, Target::Type(i)));
    }
    candidates.sort_by_key(|(s, _)| *s);

    for (attach, doc_id) in &ctx.jsdoc_by_attach {
        // Find the first candidate whose span.start >= attach.
        let idx = candidates.partition_point(|(s, _)| *s < *attach);
        if idx >= candidates.len() {
            continue;
        }
        let (start, ref target) = candidates[idx];
        if start.saturating_sub(*attach) > MAX_GAP {
            continue;
        }
        match target {
            Target::Function(i) => {
                if ctx.index.functions[*i].doc.is_none() {
                    ctx.index.functions[*i].doc = Some(*doc_id);
                }
            }
            Target::Type(i) => {
                if ctx.index.types[*i].doc.is_none() {
                    ctx.index.types[*i].doc = Some(*doc_id);
                }
            }
        }
    }
}

fn comment_text(c: &Comment, bytes: &[u8]) -> String {
    let span = c.content_span();
    let start = span.start as usize;
    let end = (span.end as usize).min(bytes.len());
    if start >= end {
        return String::new();
    }
    std::str::from_utf8(&bytes[start..end])
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse;
    use zuit_core::{FunctionKind, SourceFile, Visibility};
    use std::sync::Arc;

    fn idx_of(path: &str, code: &str) -> SemanticIndex {
        let src = Arc::new(SourceFile::new(path, code.as_bytes().to_vec()));
        parse(src).expect("parse failed").index().clone()
    }

    #[test]
    fn registers_simple_function() {
        let idx = idx_of("a.ts", "function foo() { return 1; }");
        assert_eq!(idx.functions.len(), 1);
        let f = &idx.functions[0];
        assert_eq!(f.name.as_deref(), Some("foo"));
        assert_eq!(f.kind, FunctionKind::Function);
        // Top-level non-export → Private.
        assert_eq!(f.visibility, Visibility::Private);
    }

    #[test]
    fn export_function_is_public() {
        let idx = idx_of("a.ts", "export function foo() {}");
        assert_eq!(idx.functions[0].visibility, Visibility::Public);
    }

    #[test]
    fn underscore_prefix_demotes_to_private_even_when_exported() {
        let idx = idx_of("a.ts", "export function _internal() {}");
        assert_eq!(idx.functions[0].visibility, Visibility::Private);
    }

    #[test]
    fn arrow_function_named_via_const_binding() {
        let idx = idx_of("a.ts", "export const greet = () => 1;");
        let f = idx
            .functions
            .iter()
            .find(|f| f.kind == FunctionKind::ArrowFn)
            .unwrap();
        assert_eq!(f.name.as_deref(), Some("greet"));
        assert_eq!(f.visibility, Visibility::Public);
    }

    #[test]
    fn class_declaration_emits_typedecl_and_methods() {
        let idx = idx_of(
            "a.ts",
            "export class Foo {\n  constructor() {}\n  bar() { return 1; }\n}",
        );
        assert!(idx.types.iter().any(|t| t.name == "Foo"));
        assert!(idx
            .functions
            .iter()
            .any(|f| f.kind == FunctionKind::Method && f.name.as_deref() == Some("constructor")));
        assert!(
            idx.functions
                .iter()
                .any(|f| f.kind == FunctionKind::Method && f.name.as_deref() == Some("bar"))
        );
    }

    #[test]
    fn imports_record_source_path() {
        let idx = idx_of("a.ts", "import { x } from 'foo/bar';\n");
        assert!(idx.imports.iter().any(|i| i.path == "foo/bar"));
    }

    #[test]
    fn ts_interface_and_type_alias_become_typedecls() {
        let idx = idx_of(
            "a.ts",
            "export interface I { x: number }\nexport type T = number;",
        );
        assert!(idx.types.iter().any(|t| t.name == "I"));
        assert!(idx.types.iter().any(|t| t.name == "T"));
    }

    #[test]
    fn jsdoc_links_through_export_keyword() {
        // Verifies the backfill: oxc attaches the JSDoc to `export`, but the
        // `Function` span starts at `function`. Linkage should still work.
        let idx = idx_of("a.ts", "/** Doc here. */\nexport function foo() {}");
        let foo = idx
            .functions
            .iter()
            .find(|f| f.name.as_deref() == Some("foo"))
            .unwrap();
        assert!(foo.doc.is_some(), "expected JSDoc to link through `export`");
    }

    #[test]
    fn line_comments_are_collected_separately_from_jsdoc() {
        let idx = idx_of(
            "a.ts",
            "// TODO: fixme\nexport function foo() { /** inline */ return 1; }",
        );
        assert!(
            idx.comments.iter().any(|c| c.text.contains("TODO")),
            "expected line comment in comments[]"
        );
    }

    #[test]
    fn string_literals_collected() {
        let idx = idx_of("a.ts", "const k = 'AKIAIOSFODNN7EXAMPLE';");
        assert!(
            idx.string_literals
                .iter()
                .any(|s| s.value == "AKIAIOSFODNN7EXAMPLE")
        );
    }

    #[test]
    fn template_literal_static_part_collected() {
        let idx = idx_of("a.ts", "const k = `secret-AKIA${suffix}`;");
        assert!(
            idx.string_literals.iter().any(|s| s.value.contains("AKIA")),
            "static template parts should reach string_literals"
        );
    }

    #[test]
    fn complexity_baseline_is_one() {
        let idx = idx_of("a.ts", "function f() { return 1; }");
        assert_eq!(idx.functions[0].complexity.cyclomatic, 1);
    }

    #[test]
    fn complexity_counts_if_and_logical_ops() {
        let idx = idx_of(
            "a.ts",
            "function f(a: number, b: number) { if (a && b) return 1; return 0; }",
        );
        // baseline 1 + if 1 + && 1 = 3
        assert_eq!(idx.functions[0].complexity.cyclomatic, 3);
    }

    #[test]
    fn healthy_fixture_no_visibility_misses() {
        let src = include_str!("../../../fixtures/js/healthy/main.ts");
        let idx = idx_of("fixtures/js/healthy/main.ts", src);
        // Public exports: greet, computeSum, fetchData, DataProcessor.
        // Private: _internalHelper, the constructor's private threshold field
        // (not a function), and the arrow inside `process(...)`.
        let public_named: Vec<_> = idx
            .functions
            .iter()
            .filter(|f| f.visibility == Visibility::Public)
            .filter_map(|f| f.name.as_deref())
            .collect();
        for needed in ["greet", "computeSum", "fetchData"] {
            assert!(
                public_named.contains(&needed),
                "missing public fn {needed}; got {public_named:?}"
            );
        }
        let private_named: Vec<_> = idx
            .functions
            .iter()
            .filter(|f| f.visibility == Visibility::Private)
            .filter_map(|f| f.name.as_deref())
            .collect();
        assert!(
            private_named.contains(&"_internalHelper"),
            "underscore-prefixed fn should be Private; got {private_named:?}"
        );
    }

    // ── suppression extraction tests ──────────────────────────────────────────

    #[test]
    fn suppression_directive_extracted_from_js_line_comment() {
        let idx = idx_of("a.ts", "// zuit: ignore MAINT003\nfunction foo() {}");
        assert_eq!(idx.suppressions.len(), 1);
        let s = &idx.suppressions[0];
        assert_eq!(s.rule_id, "MAINT003");
        assert_eq!(s.line, 1);
        assert!(!s.file_scoped);
    }

    #[test]
    fn suppression_directive_file_scoped_js() {
        let idx = idx_of("a.ts", "// zuit: ignore-file SEC001\nfunction foo() {}");
        assert_eq!(idx.suppressions.len(), 1);
        let s = &idx.suppressions[0];
        assert_eq!(s.rule_id, "SEC001");
        assert!(s.file_scoped);
    }

    #[test]
    fn suppression_comma_separated_js() {
        let idx = idx_of("a.ts", "// zuit: ignore RULE1,RULE2\nfunction foo() {}");
        assert_eq!(idx.suppressions.len(), 2);
        let ids: Vec<&str> = idx
            .suppressions
            .iter()
            .map(|s| s.rule_id.as_str())
            .collect();
        assert!(ids.contains(&"RULE1"));
        assert!(ids.contains(&"RULE2"));
    }

    #[test]
    fn regular_comment_does_not_produce_suppression_js() {
        let idx = idx_of("a.ts", "// TODO: fix this\nfunction foo() {}");
        assert!(idx.suppressions.is_empty());
    }
}
