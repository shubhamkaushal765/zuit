//! Builds a [`SemanticIndex`] by walking a `rustpython-parser` `ModModule` AST.
//!
//! Mapping rules:
//! - `FunctionDef` → [`FunctionKind::Function`] or [`FunctionKind::Method`]
//!   (Method when the function is directly inside a class body).
//! - `AsyncFunctionDef` → same as above but with `is_async = true`.
//! - `Lambda` expressions → [`FunctionKind::Lambda`], `name = None`.
//! - `is_test = true` when the function name starts with `test_` or the
//!   immediately-enclosing class name starts with `Test`.
//! - Visibility: name starting with `_` → [`Visibility::Private`]; otherwise
//!   [`Visibility::Public`].
//! - Docstrings: the first statement of a module / class / function body, when
//!   it is a bare string-expression (`Stmt::Expr` wrapping `Expr::Constant`
//!   with a `Constant::Str` value), is recorded as a [`DocComment`] linked to
//!   the enclosing item.
//! - Imports: `Import` and `ImportFrom` statements → [`SemanticIndex::imports`].
//! - String literals: `Constant::Str` nodes **not** already captured as
//!   docstrings → [`SemanticIndex::string_literals`].

use rustpython_parser::ast::Ranged;
use rustpython_parser::ast::{
    Comprehension, Expr, ExprLambda, ModModule, Stmt, StmtAsyncFunctionDef, StmtFunctionDef,
};

use zuit_core::{
    ByteOffset, Comment, DocComment, FunctionKind, FunctionLike, Import, ModuleDecl, NodeId,
    RegexLiteral, SemanticIndex, Span, StringLit, Suppression, TypeDecl, Visibility,
    parse_suppression_directive,
};

use crate::complexity;

/// Builds the [`SemanticIndex`] for `module`.
pub(crate) fn build_index(module: &ModModule, source: &zuit_core::SourceFile) -> SemanticIndex {
    let mut ctx = IndexCtx {
        index: SemanticIndex::new(),
        next_id: 0,
    };

    // Extract module-level docstring first.
    let module_doc_id = extract_docstring(&module.body, &mut ctx);
    // If there is a module-level docstring, add a fake ModuleDecl for the
    // module itself so consumers can find it.
    if module_doc_id.is_some() {
        let span = Span::new(ByteOffset(0), ByteOffset(0));
        let mod_id = ctx.alloc_id();
        ctx.index.modules.push(ModuleDecl {
            id: mod_id,
            name: "<module>".to_string(),
            span,
        });
    }

    // Walk top-level statements.
    walk_stmts(&module.body, &mut ctx, None, false);

    // Extract comments from source text
    extract_comments(source, &mut ctx);

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

// ── internal bookkeeping ────────────────────────────────────────────────────

struct IndexCtx {
    index: SemanticIndex,
    next_id: u32,
}

impl IndexCtx {
    fn alloc_id(&mut self) -> NodeId {
        let id = NodeId(self.next_id);
        self.next_id += 1;
        id
    }

    fn text_range_to_span(range: rustpython_parser::ast::text_size::TextRange) -> Span {
        Span::new(
            ByteOffset(range.start().to_u32()),
            ByteOffset(range.end().to_u32()),
        )
    }
}

// ── statement walker ────────────────────────────────────────────────────────

/// Walk a list of statements, registering functions, classes, imports, etc.
///
/// `enclosing_class` is `Some(class_name)` when the statements are the body of
/// a class definition.  `is_method_context` indicates the same thing for
/// function-kind resolution.
fn walk_stmts(
    stmts: &[Stmt],
    ctx: &mut IndexCtx,
    enclosing_class: Option<&str>,
    is_method_context: bool,
) {
    for stmt in stmts {
        walk_stmt(stmt, ctx, enclosing_class, is_method_context);
    }
}

// This function is a comprehensive AST statement dispatcher; its length is
// inherent to the number of Python statement variants.
#[allow(clippy::too_many_lines)]
fn walk_stmt(
    stmt: &Stmt,
    ctx: &mut IndexCtx,
    enclosing_class: Option<&str>,
    is_method_context: bool,
) {
    match stmt {
        Stmt::FunctionDef(f) => {
            register_function_def(f, ctx, enclosing_class, false, is_method_context);
        }
        Stmt::AsyncFunctionDef(f) => {
            register_async_function_def(f, ctx, enclosing_class, is_method_context);
        }
        Stmt::ClassDef(cls) => {
            let cls_name = cls.name.as_str();
            let span = IndexCtx::text_range_to_span(cls.range);

            // Extract class-level docstring.
            let doc_id = extract_docstring(&cls.body, ctx);

            let vis = if cls_name.starts_with('_') {
                Visibility::Private
            } else {
                Visibility::Public
            };

            let type_id = ctx.alloc_id();
            ctx.index.types.push(TypeDecl {
                id: type_id,
                name: cls_name.to_string(),
                visibility: vis,
                span,
                doc: doc_id,
            });

            // Walk class body; methods are in method context.
            walk_stmts(&cls.body, ctx, Some(cls_name), true);
        }
        Stmt::Import(imp) => {
            let span = IndexCtx::text_range_to_span(imp.range);
            for alias in &imp.names {
                let path = alias.name.as_str().to_string();
                let id = ctx.alloc_id();
                ctx.index.imports.push(Import { id, path, span });
            }
        }
        Stmt::ImportFrom(imp) => {
            let span = IndexCtx::text_range_to_span(imp.range);
            let module_prefix = imp
                .module
                .as_ref()
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            for alias in &imp.names {
                let path = if module_prefix.is_empty() {
                    alias.name.as_str().to_string()
                } else {
                    format!("{}.{}", module_prefix, alias.name.as_str())
                };
                let id = ctx.alloc_id();
                ctx.index.imports.push(Import { id, path, span });
            }
        }
        // Walk into compound statements to find nested functions / lambdas.
        Stmt::If(s) => {
            walk_stmts(&s.body, ctx, enclosing_class, is_method_context);
            walk_stmts(&s.orelse, ctx, enclosing_class, is_method_context);
        }
        Stmt::While(s) => {
            walk_stmts(&s.body, ctx, enclosing_class, is_method_context);
            walk_stmts(&s.orelse, ctx, enclosing_class, is_method_context);
        }
        Stmt::For(s) => {
            walk_stmts(&s.body, ctx, enclosing_class, is_method_context);
            walk_stmts(&s.orelse, ctx, enclosing_class, is_method_context);
        }
        Stmt::AsyncFor(s) => {
            walk_stmts(&s.body, ctx, enclosing_class, is_method_context);
            walk_stmts(&s.orelse, ctx, enclosing_class, is_method_context);
        }
        Stmt::With(s) => {
            walk_stmts(&s.body, ctx, enclosing_class, is_method_context);
        }
        Stmt::AsyncWith(s) => {
            walk_stmts(&s.body, ctx, enclosing_class, is_method_context);
        }
        Stmt::Try(s) => {
            walk_stmts(&s.body, ctx, enclosing_class, is_method_context);
            walk_stmts(&s.orelse, ctx, enclosing_class, is_method_context);
            walk_stmts(&s.finalbody, ctx, enclosing_class, is_method_context);
            for handler in &s.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                walk_stmts(&h.body, ctx, enclosing_class, is_method_context);
            }
        }
        Stmt::TryStar(s) => {
            walk_stmts(&s.body, ctx, enclosing_class, is_method_context);
            walk_stmts(&s.orelse, ctx, enclosing_class, is_method_context);
            walk_stmts(&s.finalbody, ctx, enclosing_class, is_method_context);
            for handler in &s.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                walk_stmts(&h.body, ctx, enclosing_class, is_method_context);
            }
        }
        Stmt::Expr(expr_stmt) => {
            // Collect non-docstring string literals at statement level.
            collect_string_literals_from_expr(&expr_stmt.value, ctx, false);
            collect_regex_literals_from_expr(&expr_stmt.value, ctx);
        }
        Stmt::Assign(assign) => {
            // Collect string literals and lambdas from assignment values.
            collect_string_literals_from_expr(&assign.value, ctx, false);
            collect_regex_literals_from_expr(&assign.value, ctx);
        }
        Stmt::AnnAssign(assign) => {
            if let Some(value) = &assign.value {
                collect_string_literals_from_expr(value, ctx, false);
                collect_regex_literals_from_expr(value, ctx);
            }
        }
        // All other statement kinds don't introduce new named items.
        _ => {}
    }
}

// ── function registration ───────────────────────────────────────────────────

fn register_function_def(
    f: &StmtFunctionDef,
    ctx: &mut IndexCtx,
    enclosing_class: Option<&str>,
    is_async: bool,
    is_method: bool,
) {
    let name = f.name.as_str();
    let span = IndexCtx::text_range_to_span(f.range);

    // Compute body span: from first statement start to end of last statement.
    let body_span = body_span_of(&f.body, span);

    // Docstring for this function.
    let doc_id = extract_docstring(&f.body, ctx);

    let vis = visibility_for(name);
    let kind = if is_method {
        FunctionKind::Method
    } else {
        FunctionKind::Function
    };

    let is_test = is_test_fn(name, enclosing_class);

    // Count parameters (excluding `self` / `cls` — those are not user args).
    let param_count = count_params(&f.args, is_method);

    let metrics = complexity::compute_function_complexity(&f.body);

    let fn_id = ctx.alloc_id();
    ctx.index.functions.push(FunctionLike {
        id: fn_id,
        kind,
        name: Some(name.to_string()),
        visibility: vis,
        span,
        body_span,
        param_count,
        is_async,
        is_test,
        doc: doc_id,
        complexity: metrics,
        parent_name: enclosing_class.map(str::to_string),
    });

    // Walk function body for nested definitions, skipping the first statement
    // if it was already captured as a docstring (to avoid double-recording it
    // as a string literal).
    let body_to_walk = if doc_id.is_some() && !f.body.is_empty() {
        &f.body[1..]
    } else {
        &f.body[..]
    };
    walk_stmts(body_to_walk, ctx, None, false);

    // Collect lambdas in default argument expressions.
    for arg in f
        .args
        .posonlyargs
        .iter()
        .chain(f.args.args.iter())
        .chain(f.args.kwonlyargs.iter())
    {
        if let Some(default) = &arg.default {
            collect_lambdas_and_strings(default, ctx);
        }
    }
}

fn register_async_function_def(
    f: &StmtAsyncFunctionDef,
    ctx: &mut IndexCtx,
    enclosing_class: Option<&str>,
    is_method: bool,
) {
    let name = f.name.as_str();
    let span = IndexCtx::text_range_to_span(f.range);
    let body_span = body_span_of_async(&f.body, span);
    let doc_id = extract_docstring(&f.body, ctx);
    let vis = visibility_for(name);
    let kind = if is_method {
        FunctionKind::Method
    } else {
        FunctionKind::Function
    };
    let is_test = is_test_fn(name, enclosing_class);
    let param_count = count_params(&f.args, is_method);
    let metrics = complexity::compute_function_complexity(&f.body);

    let fn_id = ctx.alloc_id();
    ctx.index.functions.push(FunctionLike {
        id: fn_id,
        kind,
        name: Some(name.to_string()),
        visibility: vis,
        span,
        body_span,
        param_count,
        is_async: true,
        is_test,
        doc: doc_id,
        complexity: metrics,
        parent_name: enclosing_class.map(str::to_string),
    });

    walk_stmts(&f.body, ctx, None, false);
}

fn register_lambda(lambda: &ExprLambda, ctx: &mut IndexCtx) {
    let span = IndexCtx::text_range_to_span(lambda.range);
    // Lambda body is a single expression; body_span == span.
    let param_count = count_params(&lambda.args, false);
    let metrics = complexity::compute_lambda_complexity(&lambda.body);

    let fn_id = ctx.alloc_id();
    ctx.index.functions.push(FunctionLike {
        id: fn_id,
        kind: FunctionKind::Lambda,
        name: None,
        visibility: Visibility::Private,
        span,
        body_span: span,
        param_count,
        is_async: false,
        is_test: false,
        doc: None,
        complexity: metrics,
        parent_name: None,
    });

    // Recurse into the lambda body for nested lambdas.
    collect_lambdas_and_strings(&lambda.body, ctx);
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// Returns `true` when `fn_name` should be tagged as a test function.
///
/// A function is a test when its name starts with `test_` **or** the immediately
/// enclosing class name starts with `Test`.
fn is_test_fn(fn_name: &str, enclosing_class: Option<&str>) -> bool {
    fn_name.starts_with("test_") || enclosing_class.is_some_and(|cls| cls.starts_with("Test"))
}

/// Maps a Python name to its [`Visibility`].
///
/// Names starting with `_` (single underscore, including dunder names like
/// `__init__`) are considered private.  All others are public.
fn visibility_for(name: &str) -> Visibility {
    if name.starts_with('_') {
        Visibility::Private
    } else {
        Visibility::Public
    }
}

/// Counts user-visible parameters, excluding the implicit `self` / `cls` that
/// appear as the first positional argument of methods.
fn count_params(args: &rustpython_parser::ast::Arguments, is_method: bool) -> u32 {
    let total = args.posonlyargs.len()
        + args.args.len()
        + args.kwonlyargs.len()
        + usize::from(args.vararg.is_some())
        + usize::from(args.kwarg.is_some());
    let subtract = usize::from(is_method && total > 0);
    // total is bounded by the number of AST nodes, which fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    {
        (total.saturating_sub(subtract)) as u32
    }
}

/// Computes the body span for a regular function's statement list.
fn body_span_of(body: &[Stmt], fn_span: Span) -> Span {
    if body.is_empty() {
        return fn_span;
    }
    let start = IndexCtx::text_range_to_span(body[0].range()).start;
    let end = IndexCtx::text_range_to_span(body[body.len() - 1].range()).end;
    Span::new(start, end)
}

/// Computes the body span for an async function's statement list.
fn body_span_of_async(body: &[Stmt], fn_span: Span) -> Span {
    body_span_of(body, fn_span)
}

// ── docstring extraction ────────────────────────────────────────────────────

/// If the first statement in `stmts` is a string-constant expression (a
/// docstring), records it as a [`DocComment`] and returns its [`NodeId`].
fn extract_docstring(stmts: &[Stmt], ctx: &mut IndexCtx) -> Option<NodeId> {
    let first = stmts.first()?;
    let Stmt::Expr(expr_stmt) = first else {
        return None;
    };
    let Expr::Constant(c) = expr_stmt.value.as_ref() else {
        return None;
    };
    let rustpython_parser::ast::Constant::Str(text) = &c.value else {
        return None;
    };
    let span = IndexCtx::text_range_to_span(expr_stmt.range);
    let id = ctx.alloc_id();
    ctx.index.doc_comments.push(DocComment {
        id,
        text: text.clone(),
        span,
    });
    Some(id)
}

// ── string literal collection ───────────────────────────────────────────────

/// Recursively collects non-docstring string literals from an expression.
///
/// `is_docstring_position` should be `true` only when the caller already
/// determined that this expression is a module/class/function docstring so we
/// can skip re-recording it.
// The length is inherent to the full enumeration of Python expression variants.
#[allow(clippy::too_many_lines)]
fn collect_string_literals_from_expr(expr: &Expr, ctx: &mut IndexCtx, is_docstring_position: bool) {
    match expr {
        Expr::Constant(c) => {
            if let rustpython_parser::ast::Constant::Str(text) = &c.value
                && !is_docstring_position
            {
                let span = IndexCtx::text_range_to_span(c.range);
                let id = ctx.alloc_id();
                ctx.index.string_literals.push(StringLit {
                    id,
                    value: text.clone(),
                    span,
                });
            }
        }
        Expr::BoolOp(e) => {
            for v in &e.values {
                collect_string_literals_from_expr(v, ctx, false);
            }
        }
        Expr::BinOp(e) => {
            collect_string_literals_from_expr(&e.left, ctx, false);
            collect_string_literals_from_expr(&e.right, ctx, false);
        }
        Expr::UnaryOp(e) => {
            collect_string_literals_from_expr(&e.operand, ctx, false);
        }
        Expr::IfExp(e) => {
            collect_string_literals_from_expr(&e.test, ctx, false);
            collect_string_literals_from_expr(&e.body, ctx, false);
            collect_string_literals_from_expr(&e.orelse, ctx, false);
        }
        Expr::Call(e) => {
            collect_string_literals_from_expr(&e.func, ctx, false);
            for arg in &e.args {
                collect_string_literals_from_expr(arg, ctx, false);
            }
            for kw in &e.keywords {
                collect_string_literals_from_expr(&kw.value, ctx, false);
            }
        }
        Expr::Attribute(e) => {
            collect_string_literals_from_expr(&e.value, ctx, false);
        }
        Expr::Subscript(e) => {
            collect_string_literals_from_expr(&e.value, ctx, false);
            collect_string_literals_from_expr(&e.slice, ctx, false);
        }
        Expr::List(e) => {
            for elt in &e.elts {
                collect_string_literals_from_expr(elt, ctx, false);
            }
        }
        Expr::Tuple(e) => {
            for elt in &e.elts {
                collect_string_literals_from_expr(elt, ctx, false);
            }
        }
        Expr::Dict(e) => {
            for k in e.keys.iter().flatten() {
                collect_string_literals_from_expr(k, ctx, false);
            }
            for v in &e.values {
                collect_string_literals_from_expr(v, ctx, false);
            }
        }
        Expr::Set(e) => {
            for elt in &e.elts {
                collect_string_literals_from_expr(elt, ctx, false);
            }
        }
        Expr::ListComp(e) => {
            collect_string_literals_from_expr(&e.elt, ctx, false);
            collect_generators(&e.generators, ctx);
        }
        Expr::SetComp(e) => {
            collect_string_literals_from_expr(&e.elt, ctx, false);
            collect_generators(&e.generators, ctx);
        }
        Expr::GeneratorExp(e) => {
            collect_string_literals_from_expr(&e.elt, ctx, false);
            collect_generators(&e.generators, ctx);
        }
        Expr::DictComp(e) => {
            collect_string_literals_from_expr(&e.key, ctx, false);
            collect_string_literals_from_expr(&e.value, ctx, false);
            collect_generators(&e.generators, ctx);
        }
        Expr::Lambda(lam) => {
            // Don't recurse into lambda body here; lambdas are registered
            // separately via collect_lambdas_and_strings.
            register_lambda(lam, ctx);
        }
        Expr::NamedExpr(e) => {
            collect_string_literals_from_expr(&e.value, ctx, false);
        }
        Expr::Starred(e) => {
            collect_string_literals_from_expr(&e.value, ctx, false);
        }
        Expr::Yield(e) => {
            if let Some(v) = &e.value {
                collect_string_literals_from_expr(v, ctx, false);
            }
        }
        Expr::YieldFrom(e) => {
            collect_string_literals_from_expr(&e.value, ctx, false);
        }
        Expr::Await(e) => {
            collect_string_literals_from_expr(&e.value, ctx, false);
        }
        Expr::Compare(e) => {
            collect_string_literals_from_expr(&e.left, ctx, false);
            for comp in &e.comparators {
                collect_string_literals_from_expr(comp, ctx, false);
            }
        }
        Expr::JoinedStr(_) | Expr::FormattedValue(_) | Expr::Name(_) | Expr::Slice(_) => {
            // No plain string literals here that we need to track.
        }
    }
}

fn collect_generators(generators: &[Comprehension], ctx: &mut IndexCtx) {
    for comp in generators {
        collect_string_literals_from_expr(&comp.iter, ctx, false);
        for cond in &comp.ifs {
            collect_string_literals_from_expr(cond, ctx, false);
        }
    }
}

/// Recursively finds lambdas and string literals in an expression, registering
/// lambdas and collecting string literals.
fn collect_lambdas_and_strings(expr: &Expr, ctx: &mut IndexCtx) {
    collect_string_literals_from_expr(expr, ctx, false);
}

/// The `re` module methods that accept a regex pattern as their first positional
/// argument.
const RE_METHODS: &[&str] = &[
    "compile",
    "match",
    "search",
    "findall",
    "fullmatch",
    "sub",
    "subn",
    "split",
    "finditer",
];

/// Scans an expression for `re.<method>(<str>, ...)` calls and pushes the
/// first string argument as a [`RegexLiteral`] into `ctx.index.regex_literals`.
///
/// Recurses into sub-expressions so that regex calls nested inside function
/// arguments, list literals, etc. are also caught.
fn collect_regex_literals_from_expr(expr: &Expr, ctx: &mut IndexCtx) {
    match expr {
        Expr::Call(call) => {
            // Check for `re.<method>(<str-literal>, ...)`.
            if let Expr::Attribute(attr) = call.func.as_ref()
                && let Expr::Name(name) = attr.value.as_ref()
                && name.id.as_str() == "re"
                && RE_METHODS.iter().any(|m| *m == attr.attr.as_str())
                && let Some(first_arg) = call.args.first()
                && let Expr::Constant(c) = first_arg
                && let rustpython_parser::ast::Constant::Str(text) = &c.value
            {
                let span = IndexCtx::text_range_to_span(call.range());
                let id = ctx.alloc_id();
                ctx.index.regex_literals.push(RegexLiteral {
                    id,
                    value: text.clone(),
                    span,
                });
            }
            // Always recurse into arguments to catch nested calls.
            collect_regex_literals_from_expr(&call.func, ctx);
            for arg in &call.args {
                collect_regex_literals_from_expr(arg, ctx);
            }
            for kw in &call.keywords {
                collect_regex_literals_from_expr(&kw.value, ctx);
            }
        }
        Expr::BoolOp(e) => {
            for v in &e.values {
                collect_regex_literals_from_expr(v, ctx);
            }
        }
        Expr::BinOp(e) => {
            collect_regex_literals_from_expr(&e.left, ctx);
            collect_regex_literals_from_expr(&e.right, ctx);
        }
        Expr::IfExp(e) => {
            collect_regex_literals_from_expr(&e.test, ctx);
            collect_regex_literals_from_expr(&e.body, ctx);
            collect_regex_literals_from_expr(&e.orelse, ctx);
        }
        Expr::List(e) => {
            for elt in &e.elts {
                collect_regex_literals_from_expr(elt, ctx);
            }
        }
        Expr::Tuple(e) => {
            for elt in &e.elts {
                collect_regex_literals_from_expr(elt, ctx);
            }
        }
        Expr::Set(e) => {
            for elt in &e.elts {
                collect_regex_literals_from_expr(elt, ctx);
            }
        }
        Expr::Subscript(e) => {
            collect_regex_literals_from_expr(&e.value, ctx);
            collect_regex_literals_from_expr(&e.slice, ctx);
        }
        Expr::Starred(e) => {
            collect_regex_literals_from_expr(&e.value, ctx);
        }
        Expr::UnaryOp(e) => {
            collect_regex_literals_from_expr(&e.operand, ctx);
        }
        Expr::Await(e) => collect_regex_literals_from_expr(&e.value, ctx),
        Expr::Yield(e) => {
            if let Some(v) = &e.value {
                collect_regex_literals_from_expr(v, ctx);
            }
        }
        Expr::YieldFrom(e) => collect_regex_literals_from_expr(&e.value, ctx),
        Expr::NamedExpr(e) => collect_regex_literals_from_expr(&e.value, ctx),
        _ => {}
    }
}

// ── comments extraction ───────────────────────────────────────────────────

/// Extracts `#` line comments from the source text.
///
/// Docstrings are surfaced separately via [`SemanticIndex::doc_comments`] and
/// never enter [`SemanticIndex::comments`].
///
/// **Limitation:** the scanner is not string-aware. A `#` inside a string
/// literal (e.g. `"#abc"`) will produce a spurious comment. Acceptable for
/// `DOC002-todo-fixme` because TODO/FIXME inside string payloads is rare;
/// will be replaced with a tokenizer-based extractor when other rules need
/// accurate comment data.
fn extract_comments(source: &zuit_core::SourceFile, ctx: &mut IndexCtx) {
    let bytes = source.as_str().as_bytes();
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    let mut i: u32 = 0;

    while i < len {
        if bytes[i as usize] != b'#' {
            i += 1;
            continue;
        }
        let start = i;
        i += 1;
        while i < len && bytes[i as usize] != b'\n' {
            i += 1;
        }
        let text = std::str::from_utf8(&bytes[(start + 1) as usize..i as usize])
            .unwrap_or("")
            .trim_start()
            .to_string();
        let id = ctx.alloc_id();
        ctx.index.comments.push(Comment {
            id,
            text,
            span: Span::new(ByteOffset(start), ByteOffset(i)),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::PythonLanguage;
    use rustpython_parser::{Parse, ast::ModModule};
    use std::sync::Arc;
    use zuit_core::Language;
    use zuit_core::{FunctionKind, SourceFile, Visibility};

    fn parse_and_index(src: &str) -> SemanticIndex {
        let source = Arc::new(SourceFile::new("test.py", src.as_bytes().to_vec()));
        let module = ModModule::parse(src, "<test>").expect("parse failed");
        build_index(&module, &source)
    }

    #[test]
    fn registers_simple_function() {
        let idx = parse_and_index("def foo():\n    pass\n");
        assert_eq!(idx.functions.len(), 1);
        let f = &idx.functions[0];
        assert_eq!(f.name.as_deref(), Some("foo"));
        assert_eq!(f.kind, FunctionKind::Function);
        assert_eq!(f.visibility, Visibility::Public);
        assert!(!f.is_async);
        assert!(!f.is_test);
    }

    #[test]
    fn registers_async_function() {
        let idx = parse_and_index("async def fetch():\n    pass\n");
        assert_eq!(idx.functions.len(), 1);
        let f = &idx.functions[0];
        assert!(f.is_async);
        assert_eq!(f.name.as_deref(), Some("fetch"));
    }

    #[test]
    fn private_function_underscore_prefix() {
        let idx = parse_and_index("def _helper():\n    pass\n");
        assert_eq!(idx.functions[0].visibility, Visibility::Private);
    }

    #[test]
    fn test_function_prefix() {
        let idx = parse_and_index("def test_something():\n    pass\n");
        assert!(idx.functions[0].is_test);
    }

    #[test]
    fn method_in_class_is_method_kind() {
        let idx = parse_and_index("class Foo:\n    def method(self):\n        pass\n");
        // One class, one function (the method).
        let method = idx
            .functions
            .iter()
            .find(|f| f.name.as_deref() == Some("method"))
            .unwrap();
        assert_eq!(method.kind, FunctionKind::Method);
    }

    #[test]
    fn test_class_makes_methods_is_test() {
        let idx = parse_and_index("class TestFoo:\n    def run(self):\n        pass\n");
        let run = idx
            .functions
            .iter()
            .find(|f| f.name.as_deref() == Some("run"))
            .unwrap();
        assert!(run.is_test);
    }

    #[test]
    fn docstring_linked_to_function() {
        let idx = parse_and_index("def foo():\n    \"\"\"My docstring.\"\"\"\n    pass\n");
        let f = &idx.functions[0];
        assert!(f.doc.is_some(), "function should have doc linked");
        let doc_id = f.doc.unwrap();
        let doc = idx.doc_comments.iter().find(|d| d.id == doc_id).unwrap();
        assert!(doc.text.contains("My docstring."));
    }

    #[test]
    fn imports_are_collected() {
        let idx = parse_and_index("import os\nfrom sys import path\n");
        assert!(idx.imports.iter().any(|i| i.path == "os"));
        assert!(idx.imports.iter().any(|i| i.path == "sys.path"));
    }

    #[test]
    fn string_literals_collected_not_docstrings() {
        let idx =
            parse_and_index("def foo():\n    \"\"\"docstring\"\"\"\n    x = \"not a docstring\"\n");
        // "not a docstring" should be in string_literals but "docstring" should not.
        assert!(
            idx.string_literals
                .iter()
                .any(|s| s.value == "not a docstring")
        );
        assert!(!idx.string_literals.iter().any(|s| s.value == "docstring"));
    }

    #[test]
    fn lambda_registered_as_lambda_kind() {
        let idx = parse_and_index("f = lambda x: x + 1\n");
        assert!(idx.functions.iter().any(|f| f.kind == FunctionKind::Lambda));
    }

    #[test]
    fn healthy_fixture_functions() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let idx = parse_and_index(source);
        // greet, compute_sum, fetch_data, _internal_helper, __init__, process
        // (DataProcessor is a class, not a function)
        let names: Vec<_> = idx
            .functions
            .iter()
            .filter_map(|f| f.name.as_deref())
            .collect();
        assert!(names.contains(&"greet"), "expected greet, got {names:?}");
        assert!(names.contains(&"compute_sum"), "expected compute_sum");
        assert!(names.contains(&"fetch_data"), "expected fetch_data");

        let greet = idx
            .functions
            .iter()
            .find(|f| f.name.as_deref() == Some("greet"))
            .unwrap();
        assert_eq!(greet.visibility, Visibility::Public);
        assert!(greet.doc.is_some(), "greet should have a docstring");

        let helper = idx
            .functions
            .iter()
            .find(|f| f.name.as_deref() == Some("_internal_helper"))
            .unwrap();
        assert_eq!(helper.visibility, Visibility::Private);

        let fetch = idx
            .functions
            .iter()
            .find(|f| f.name.as_deref() == Some("fetch_data"))
            .unwrap();
        assert!(fetch.is_async);
    }

    #[test]
    fn fixture_via_language_frontend() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let src = Arc::new(SourceFile::new("main.py", source.as_bytes().to_vec()));
        let lang = PythonLanguage;
        let pf = lang.parse(src).expect("should parse");
        let idx = pf.index();
        // Expect at least the 5 top-level functions.
        assert!(
            idx.functions.len() >= 5,
            "expected >=5 functions, got {}",
            idx.functions.len()
        );
    }

    // ── suppression extraction tests ──────────────────────────────────────────

    #[test]
    fn suppression_directive_extracted_from_hash_comment() {
        // The comment is on line 1.
        let idx = parse_and_index("# zuit: ignore MAINT003\ndef foo():\n    pass\n");
        assert_eq!(idx.suppressions.len(), 1);
        let s = &idx.suppressions[0];
        assert_eq!(s.rule_id, "MAINT003");
        assert_eq!(s.line, 1);
        assert!(!s.file_scoped);
    }

    #[test]
    fn suppression_directive_file_scoped_python() {
        let idx = parse_and_index("# zuit: ignore-file SEC001\ndef foo():\n    pass\n");
        assert_eq!(idx.suppressions.len(), 1);
        let s = &idx.suppressions[0];
        assert_eq!(s.rule_id, "SEC001");
        assert!(s.file_scoped);
    }

    #[test]
    fn suppression_comma_separated_python() {
        let idx = parse_and_index("# zuit: ignore RULE1,RULE2\ndef foo():\n    pass\n");
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
    fn regular_comment_does_not_produce_suppression_python() {
        let idx = parse_and_index("# TODO: fix this\ndef foo():\n    pass\n");
        assert!(idx.suppressions.is_empty());
    }

    // ── regex literal collection (SEC014-redos-regex) ─────────────────────────

    #[test]
    fn re_compile_produces_regex_literal() {
        let idx = parse_and_index("import re\nre.compile(r\"(a+)+\")\n");
        assert_eq!(
            idx.regex_literals.len(),
            1,
            "expected 1 regex literal, got {:?}",
            idx.regex_literals
                .iter()
                .map(|r| &r.value)
                .collect::<Vec<_>>()
        );
        assert_eq!(idx.regex_literals[0].value, "(a+)+");
    }

    #[test]
    fn re_search_produces_regex_literal() {
        let idx = parse_and_index("import re\nre.search(\"abc+\", text)\n");
        assert_eq!(idx.regex_literals.len(), 1);
        assert_eq!(idx.regex_literals[0].value, "abc+");
    }

    #[test]
    fn non_re_call_does_not_produce_regex_literal() {
        let idx = parse_and_index("import os\nos.path.join(\"a\", \"b\")\n");
        assert!(
            idx.regex_literals.is_empty(),
            "non-re call must not produce regex literals, got {:?}",
            idx.regex_literals
        );
    }
}
