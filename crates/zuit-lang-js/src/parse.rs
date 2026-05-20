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

use crate::native_ast::{
    DomSinkKind, JsAsiHazardKind, JsAsiHazardSite, JsAssignInCondSite, JsAssignmentSite, JsAst,
    JsBindCallSite, JsCallSite, JsCallee, JsCaseFallthrough, JsDeadStore, JsDebugKind, JsDomSink,
    JsImport, JsLiteralValue, JsLogCallSite, JsOpPrecedenceKind, JsOpPrecedenceSite, JsSwitchSite,
};

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
    let source_text: Arc<str> = Arc::from(text);
    let js_ast = extract_call_sites(&ret.program, source_text);

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
    /// Byte spans of empty blocks for `MAINT013-empty-block`.
    empty_blocks: Vec<Span>,
    /// Debug-code call sites for `MAINT011-active-debug-code`.
    debug_calls: Vec<(Span, JsDebugKind)>,
    /// Bind call sites for `SEC013-bind-all-interfaces`.
    bind_call_sites: Vec<JsBindCallSite>,
    /// Assignment sites for `SEC012-hardcoded-security-constant`.
    assignments: Vec<JsAssignmentSite>,
    /// Log call sites for `SEC015-log-injection`.
    log_calls: Vec<JsLogCallSite>,
    /// Stack of enclosing function parameter lists, for SEC015.
    current_fn_params: Vec<Vec<String>>,
    /// Switch statement sites for `MAINT009-missing-default-case`.
    switch_sites: Vec<JsSwitchSite>,
    /// Infinite loop spans for `MAINT010-infinite-loop-no-exit`.
    infinite_loops: Vec<Span>,
    /// Dead-store sites for `MAINT012-dead-store`.
    dead_stores: Vec<JsDeadStore>,
    /// Assignment-in-condition sites for `BUG001-assignment-in-condition`.
    assignment_in_conditions: Vec<JsAssignInCondSite>,
    /// First-dead-statement spans for `MAINT016-unreachable-code`.
    unreachable_stmts: Vec<Span>,
    /// Fall-through `case` sites for `BUG002-switch-fallthrough`.
    case_fallthroughs: Vec<JsCaseFallthrough>,
    /// Operator-precedence trap sites for `BUG004-operator-precedence`.
    op_precedence_sites: Vec<JsOpPrecedenceSite>,
    /// ASI hazard sites for `STYLE001-block-delimitation`.
    asi_hazards: Vec<JsAsiHazardSite>,
    /// Snapshot of the full source text. Needed by the BUG002 fallthrough
    /// detector to inspect the comment immediately before a `case` clause.
    source_text: Arc<str>,
}

impl WalkCtx {
    fn new(source_text: Arc<str>) -> Self {
        Self {
            call_sites: Vec::new(),
            dom_sinks: Vec::new(),
            imports: Vec::new(),
            top_level_calls: Vec::new(),
            at_top_level: true,
            empty_blocks: Vec::new(),
            debug_calls: Vec::new(),
            bind_call_sites: Vec::new(),
            assignments: Vec::new(),
            log_calls: Vec::new(),
            current_fn_params: Vec::new(),
            switch_sites: Vec::new(),
            infinite_loops: Vec::new(),
            dead_stores: Vec::new(),
            assignment_in_conditions: Vec::new(),
            unreachable_stmts: Vec::new(),
            case_fallthroughs: Vec::new(),
            op_precedence_sites: Vec::new(),
            asi_hazards: Vec::new(),
            source_text,
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
fn extract_call_sites(program: &Program<'_>, source_text: Arc<str>) -> JsAst {
    let mut ctx = WalkCtx::new(source_text);

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
    // STYLE001: detect ASI hazards at module/program top level.
    check_asi_hazards(&program.body, &ctx.source_text, &mut ctx.asi_hazards);
    for stmt in &program.body {
        walk_stmt(stmt, &mut ctx);
    }
    JsAst {
        call_sites: ctx.call_sites,
        dom_sinks: ctx.dom_sinks,
        imports: ctx.imports,
        top_level_calls: ctx.top_level_calls,
        empty_blocks: ctx.empty_blocks,
        debug_calls: ctx.debug_calls,
        bind_call_sites: ctx.bind_call_sites,
        assignments: ctx.assignments,
        log_calls: ctx.log_calls,
        switch_sites: ctx.switch_sites,
        infinite_loops: ctx.infinite_loops,
        dead_stores: ctx.dead_stores,
        assignment_in_conditions: ctx.assignment_in_conditions,
        unreachable_stmts: ctx.unreachable_stmts,
        case_fallthroughs: ctx.case_fallthroughs,
        op_precedence_sites: ctx.op_precedence_sites,
        asi_hazards: ctx.asi_hazards,
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

/// Bind-callee allowlist for `SEC013-bind-all-interfaces` (JS/TS).
///
/// These are the last segment names checked against both bare calls and the
/// method name of member-expression calls.
const BIND_CALLEE_NAMES: &[&str] = &["listen", "bind"];

/// Log object names for `SEC015-log-injection` (last-segment of object identifier).
const LOG_OBJECT_NAMES: &[&str] = &["console", "logger", "log"];

/// Log method names for `SEC015-log-injection`.
const LOG_METHOD_NAMES: &[&str] = &["log", "info", "debug", "warn", "error", "trace"];

/// If `callee` is a log-style member expression (object.method), returns
/// `Some("object.method")`, otherwise `None`.
fn log_callee_name(callee: &Expression<'_>) -> Option<String> {
    let Expression::StaticMemberExpression(member) = callee else {
        return None;
    };
    let method = member.property.name.as_str();
    if !LOG_METHOD_NAMES.contains(&method) {
        return None;
    }
    let obj_name = match &member.object {
        Expression::Identifier(id) => id.name.as_str().to_string(),
        Expression::StaticMemberExpression(m) => m.property.name.as_str().to_string(),
        _ => return None,
    };
    let obj_last = obj_name.split('.').next_back().unwrap_or(&obj_name);
    if LOG_OBJECT_NAMES.contains(&obj_last) {
        Some(format!("{obj_last}.{method}"))
    } else {
        None
    }
}

/// Extracts the leading identifier from a JS/TS expression.
fn js_leading_ident<'a>(expr: &'a Expression<'_>) -> Option<&'a str> {
    match expr {
        Expression::Identifier(id) => Some(id.name.as_str()),
        Expression::StaticMemberExpression(m) => js_leading_ident(&m.object),
        Expression::CallExpression(c) => js_leading_ident(&c.callee),
        Expression::ComputedMemberExpression(m) => js_leading_ident(&m.object),
        Expression::TSAsExpression(e) => js_leading_ident(&e.expression),
        Expression::TSNonNullExpression(e) => js_leading_ident(&e.expression),
        _ => None,
    }
}

/// Extracts parameter names from a JS/TS function formal parameter list.
fn collect_js_fn_params(params: &oxc_ast::ast::FormalParameters<'_>) -> Vec<String> {
    params
        .items
        .iter()
        .filter_map(|p| {
            if let oxc_ast::ast::BindingPattern::BindingIdentifier(id) = &p.pattern {
                Some(id.name.as_str().to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Extracts relevant data from a log call's argument list for SEC015.
///
/// Returns `(first_arg_string, first_arg_is_template_with_subst, arg_idents)`.
///
/// - `first_arg_string`: the string value of the first arg if it's a plain string literal.
/// - `first_arg_is_template_with_subst`: `true` if the first arg is a template literal with
///   at least one substitution expression.
/// - `arg_idents`: leading identifier names from subsequent args AND from template
///   literal substitution expressions (for template-literal detection).
fn extract_log_call_args(args: &[Argument<'_>]) -> (Option<String>, bool, Vec<String>) {
    let mut first_arg_string = None;
    let mut first_arg_is_template_with_subst = false;
    let mut arg_idents: Vec<String> = Vec::new();

    if let Some(first) = args.first() {
        match first.as_expression() {
            Some(Expression::StringLiteral(s)) => {
                first_arg_string = Some(s.value.to_string());
            }
            Some(Expression::TemplateLiteral(tpl)) if !tpl.expressions.is_empty() => {
                first_arg_is_template_with_subst = true;
                // Collect leading idents from template substitution expressions
                for expr in &tpl.expressions {
                    if let Some(ident) = js_leading_ident(expr) {
                        arg_idents.push(ident.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    // Collect leading idents from subsequent args
    for arg in args.iter().skip(1) {
        if let Some(expr) = arg.as_expression()
            && let Some(ident) = js_leading_ident(expr)
        {
            arg_idents.push(ident.to_string());
        }
    }

    (
        first_arg_string,
        first_arg_is_template_with_subst,
        arg_idents,
    )
}

/// Converts an oxc `Expression` to a [`JsLiteralValue`] if it is a plain literal.
///
/// Returns `None` for non-literal expressions (identifiers, calls, etc.).
fn expr_to_js_literal(expr: &Expression<'_>) -> Option<JsLiteralValue> {
    match expr {
        Expression::StringLiteral(s) => Some(JsLiteralValue::Str(s.value.to_string())),
        Expression::NumericLiteral(n) => {
            // Safe truncation: we only need integer-range values for SEC012.
            #[allow(clippy::cast_possible_truncation)]
            Some(JsLiteralValue::Int(n.value as i64))
        }
        Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::RegExpLiteral(_) => Some(JsLiteralValue::Other),
        // Unwrap parenthesised / TS wrapper expressions.
        Expression::ParenthesizedExpression(p) => expr_to_js_literal(&p.expression),
        Expression::TSAsExpression(e) => expr_to_js_literal(&e.expression),
        Expression::TSSatisfiesExpression(e) => expr_to_js_literal(&e.expression),
        Expression::TSNonNullExpression(e) => expr_to_js_literal(&e.expression),
        Expression::TSTypeAssertion(e) => expr_to_js_literal(&e.expression),
        _ => None,
    }
}

/// Returns the string value of the first argument of a call if it is a plain
/// string literal (not a template literal), for bind-all-interfaces detection.
fn first_string_arg_value<'a>(args: &'a [Argument<'a>]) -> Option<&'a str> {
    args.first().and_then(|a| {
        if let Some(Expression::StringLiteral(s)) = a.as_expression() {
            Some(s.value.as_str())
        } else {
            None
        }
    })
}

/// Returns `true` when the call's callee last segment is in the bind allowlist.
fn is_bind_callee_member(callee: &Expression<'_>) -> Option<String> {
    match callee {
        Expression::StaticMemberExpression(m) => {
            let name = m.property.name.as_str();
            if BIND_CALLEE_NAMES.contains(&name) {
                Some(name.to_string())
            } else {
                None
            }
        }
        Expression::Identifier(id) => {
            let name = id.name.as_str();
            if BIND_CALLEE_NAMES.contains(&name) {
                Some(name.to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Returns the [`JsDebugKind`] for a `console.log/debug/trace` call, if any.
///
/// Only flags `log`, `debug`, and `trace` — `error`, `warn`, and `info` are
/// intentionally excluded (legitimate in production error-reporting paths).
fn debug_kind_for_call(callee: &Expression<'_>) -> Option<JsDebugKind> {
    let Expression::StaticMemberExpression(member) = callee else {
        return None;
    };
    if let Expression::Identifier(obj) = &member.object
        && obj.name.as_str() == "console"
    {
        return match member.property.name.as_str() {
            "log" => Some(JsDebugKind::ConsoleLog),
            "debug" => Some(JsDebugKind::ConsoleDebug),
            "trace" => Some(JsDebugKind::ConsoleTrace),
            _ => None,
        };
    }
    None
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

// ── Unreachable-code helpers for MAINT016 ────────────────────────────────────

/// Returns `true` if `stmt` is a terminating statement for MAINT016.
///
/// Terminating: `return`, `throw`, `break`, `continue`.
fn is_js_terminating(stmt: &Statement<'_>) -> bool {
    matches!(
        stmt,
        Statement::ReturnStatement(_)
            | Statement::ThrowStatement(_)
            | Statement::BreakStatement(_)
            | Statement::ContinueStatement(_)
    )
}

// ── ASI-hazard helpers for STYLE001 ─────────────────────────────────────────

/// Counts the number of `\n` bytes between byte offsets `start` and `end` in
/// `src`. Defensive bounds: clamps to `src.len()` so an off-by-one in the
/// arena spans never panics.
#[allow(clippy::naive_bytecount)]
fn newlines_between(src: &str, start: u32, end: u32) -> usize {
    let bytes = src.as_bytes();
    let s = (start as usize).min(bytes.len());
    let e = (end as usize).min(bytes.len());
    if s >= e {
        return 0;
    }
    bytes[s..e].iter().filter(|&&b| b == b'\n').count()
}

/// Scans a flat slice of statements for adjacent pairs that form ASI hazards
/// and pushes a [`JsAsiHazardSite`] onto `out` for each one found.
///
/// The three patterns detected are:
/// 1. `return\nexpr;`  — `ReturnStatement(None)` + `ExpressionStatement`
/// 2. `continue\nident;` — `ContinueStatement{label:None}` + `ExpressionStatement(Identifier)`
/// 3. `break\nident;`   — `BreakStatement{label:None}` + `ExpressionStatement(Identifier)`
///
/// Invariant: exactly **one** `\n` must exist between `prev.span.end` and
/// `next.span.start` (no blank line, no same-line follow-up).
fn check_asi_hazards(stmts: &[Statement<'_>], src: &str, out: &mut Vec<JsAsiHazardSite>) {
    use oxc_span::GetSpan;
    for w in stmts.windows(2) {
        let prev = &w[0];
        let next = &w[1];
        let prev_end = prev.span().end;
        let next_start = next.span().start;
        if newlines_between(src, prev_end, next_start) != 1 {
            continue;
        }
        let prev_end = prev.span().end;
        let prev_span = oxc_span_to_core(prev.span());
        match (prev, next) {
            (Statement::ReturnStatement(r), Statement::ExpressionStatement(_))
                if r.argument.is_none() && !has_trailing_semicolon(src, prev_end) =>
            {
                out.push(JsAsiHazardSite {
                    span: prev_span,
                    kind: JsAsiHazardKind::ReturnExpr,
                });
            }
            (Statement::ContinueStatement(c), Statement::ExpressionStatement(es))
                if c.label.is_none()
                    && matches!(&es.expression, Expression::Identifier(_))
                    && !has_trailing_semicolon(src, prev_end) =>
            {
                out.push(JsAsiHazardSite {
                    span: prev_span,
                    kind: JsAsiHazardKind::ContinueLabel,
                });
            }
            (Statement::BreakStatement(b), Statement::ExpressionStatement(es))
                if b.label.is_none()
                    && matches!(&es.expression, Expression::Identifier(_))
                    && !has_trailing_semicolon(src, prev_end) =>
            {
                out.push(JsAsiHazardSite {
                    span: prev_span,
                    kind: JsAsiHazardKind::BreakLabel,
                });
            }
            _ => {}
        }
    }
}

/// Returns `true` when the source text immediately at or just before `span_end`
/// carries an explicit `;` (possibly with only horizontal whitespace between
/// the statement keyword and the semicolon, or between `span_end` and the `;`
/// when the parser's span stops at the keyword).
///
/// Two cases handled:
/// - **Case A** (span includes `;`): scan backward from `span_end` skipping
///   space/tab; if we hit `;` the user wrote it explicitly.
/// - **Case B** (span stops at keyword): scan forward from `span_end` skipping
///   space/tab; if the next non-whitespace byte is `;` it is explicit.
///
/// Never crosses a newline — only horizontal whitespace is skipped.
fn has_trailing_semicolon(src: &str, span_end: u32) -> bool {
    let bytes = src.as_bytes();
    // Case A: backward scan from span_end.
    let mut back = span_end as usize;
    while back > 0 {
        match bytes[back - 1] {
            b' ' | b'\t' => back -= 1,
            b';' => return true,
            _ => break,
        }
    }
    // Case B: forward scan from span_end.
    let mut fwd = span_end as usize;
    while fwd < bytes.len() {
        match bytes[fwd] {
            b' ' | b'\t' => fwd += 1,
            b';' => return true,
            _ => return false,
        }
    }
    false
}

/// Scans a flat slice of statements for the first terminator and, if a
/// statement follows it, pushes that first dead statement's span onto `out`.
///
/// One entry per block — never one per dead statement.
fn check_js_block_for_unreachable(stmts: &[Statement<'_>], out: &mut Vec<Span>) {
    let Some(term_idx) = stmts.iter().position(is_js_terminating) else {
        return;
    };
    if let Some(dead) = stmts.get(term_idx + 1) {
        use oxc_span::GetSpan;
        out.push(oxc_span_to_core(dead.span()));
    }
}

// ── Fall-through helpers for BUG002 ──────────────────────────────────────────

/// Returns `true` if the case's consequent ends with a terminating statement.
///
/// A single `BlockStatement` consequent is unwrapped: `case 1: { …; break; }`
/// is treated like a flat list ending in `break`.
fn case_consequent_is_terminating(consequent: &[Statement<'_>]) -> bool {
    if consequent.len() == 1
        && let Statement::BlockStatement(b) = &consequent[0]
    {
        return b.body.last().is_some_and(is_js_terminating);
    }
    consequent.last().is_some_and(is_js_terminating)
}

/// Returns `true` if the source text immediately before `next_case_start`
/// contains an ESLint-style `// falls through` / `/* fallthrough */` comment
/// (case-insensitive).  The walk skips whitespace between the comment and the
/// `case` keyword so the carve-out tolerates formatting variation.
fn has_fallthrough_carveout(source: &str, next_case_start: usize) -> bool {
    let prefix = source.get(..next_case_start).unwrap_or("");
    // Walk backwards over whitespace; then accept either:
    //   `// … falls through …`  (the rest of a line comment)
    //   `/* … fallthrough … */` (a block comment immediately before)
    let bytes = prefix.as_bytes();
    let mut i = bytes.len();
    // Skip trailing whitespace (including newlines).
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    if i == 0 {
        return false;
    }
    // Look for `*/` closer of a block comment.
    if i >= 2 && &bytes[i - 2..i] == b"*/" {
        // Find matching `/*`.
        if let Some(open) = prefix[..i - 2].rfind("/*") {
            let body = &prefix[open + 2..i - 2];
            return is_fallthrough_text(body);
        }
        return false;
    }
    // Otherwise look for a line comment on the previous line.
    // Find the start of the current line at position i.
    let line_start = prefix[..i].rfind('\n').map_or(0, |nl| nl + 1);
    let line = &prefix[line_start..i];
    if let Some(idx) = line.find("//") {
        let body = &line[idx + 2..];
        return is_fallthrough_text(body);
    }
    false
}

/// Returns `true` if `text` (a comment body) matches `falls?\s*through`
/// case-insensitively.  Implemented without regex to keep parse.rs lean.
fn is_fallthrough_text(text: &str) -> bool {
    let mut lower = text.to_ascii_lowercase();
    lower.retain(|c| !c.is_ascii_whitespace());
    // Now we just need a substring match. Both `fallthrough` and `fallsthrough`
    // collapse to `fallthrough` or `fallsthrough` after whitespace removal.
    lower.contains("fallthrough") || lower.contains("fallsthrough")
}

/// Returns `true` if the statement (or any nested statement, excluding nested
/// loop and function bodies) constitutes a loop exit:
/// - `BreakStatement`
/// - `ReturnStatement`
/// - `ThrowStatement`
/// - `CallExpression` to `process.exit(...)`
fn js_stmt_has_exit(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::BreakStatement(_)
        | Statement::ReturnStatement(_)
        | Statement::ThrowStatement(_) => true,
        Statement::ExpressionStatement(es) => js_expr_is_process_exit(&es.expression),
        // Recurse into blocks that don't create a new loop scope.
        Statement::BlockStatement(b) => b.body.iter().any(js_stmt_has_exit),
        Statement::IfStatement(s) => {
            js_stmt_has_exit(&s.consequent)
                || s.alternate.as_ref().is_some_and(|a| js_stmt_has_exit(a))
        }
        Statement::TryStatement(s) => {
            s.block.body.iter().any(js_stmt_has_exit)
                || s.handler
                    .as_ref()
                    .is_some_and(|h| h.body.body.iter().any(js_stmt_has_exit))
                || s.finalizer
                    .as_ref()
                    .is_some_and(|f| f.body.iter().any(js_stmt_has_exit))
        }
        Statement::LabeledStatement(l) => js_stmt_has_exit(&l.body),
        // STOP at nested loops, function bodies, and everything else —
        // their break/return is scoped to the inner body.
        _ => false,
    }
}

/// Returns `true` if `expr` is a call to `process.exit(...)`.
fn js_expr_is_process_exit(expr: &Expression<'_>) -> bool {
    if let Expression::CallExpression(call) = expr
        && let Expression::StaticMemberExpression(member) = &call.callee
        && member.property.name.as_str() == "exit"
        && let Expression::Identifier(obj) = &member.object
    {
        return obj.name.as_str() == "process";
    }
    false
}

// ── Dead-store extraction helpers for MAINT012 ───────────────────────────────

/// A write site within a function scope.
#[derive(Clone)]
struct JsWrite {
    name: String,
    offset: u32,
    span: Span,
}

/// Collect dead stores from a list of statements (a function body).
///
/// Returns a list of `JsDeadStore` entries for writes whose name does not
/// appear in any later `Identifier` reference within the same function body.
///
/// Rules applied:
/// - Skip names starting with `_`.
/// - Skip names from destructuring patterns.
/// - Skip `for (let x of …)` / `for (let x in …)` loop var declarators.
/// - Flag only writes whose name is NOT referenced later.
fn extract_dead_stores_from_fn_body(stmts: &[Statement<'_>]) -> Vec<JsDeadStore> {
    let mut writes: Vec<JsWrite> = Vec::new();
    let mut refs: Vec<(String, u32)> = Vec::new(); // (name, offset)

    collect_writes_from_stmts(stmts, &mut writes, &mut refs, false);
    collect_refs_from_stmts(stmts, &mut refs);

    // Flag a write W to name N when either:
    //   (a) no read of N occurs after W, OR
    //   (b) a later write W2 to N occurs before the first read of N after W
    //       (i.e. the value is overwritten before being read).
    let mut dead: Vec<JsDeadStore> = Vec::new();
    let mut emitted: std::collections::HashSet<String> = std::collections::HashSet::new();
    for write in &writes {
        if emitted.contains(&write.name) {
            continue;
        }
        // Find the earliest read of this name after this write.
        let first_read_after = refs
            .iter()
            .filter(|(n, off)| *n == write.name && *off > write.offset)
            .map(|(_, off)| *off)
            .min();
        // Find the earliest subsequent write to this name after this write.
        let next_write_after = writes
            .iter()
            .filter(|w| w.name == write.name && w.offset > write.offset)
            .map(|w| w.offset)
            .min();
        let is_dead = match (first_read_after, next_write_after) {
            // No read ever after this write → dead.
            (None, _) => true,
            // Read exists but a later write comes first → overwritten before read.
            (Some(read_off), Some(write_off)) => write_off < read_off,
            // Read exists and no overwriting write → value is used.
            (Some(_), None) => false,
        };
        if is_dead {
            emitted.insert(write.name.clone());
            dead.push(JsDeadStore {
                name: write.name.clone(),
                span: write.span,
            });
        }
    }
    dead
}

/// Collect write sites from statements (only declarations and bare assignments).
/// Does NOT recurse into nested function bodies.
/// `in_for_var` indicates we are inside a for-of/for-in variable declaration.
fn collect_writes_from_stmts(
    stmts: &[Statement<'_>],
    writes: &mut Vec<JsWrite>,
    refs: &mut Vec<(String, u32)>,
    in_for_var: bool,
) {
    for stmt in stmts {
        collect_writes_from_stmt(stmt, writes, refs, in_for_var);
    }
}

#[allow(clippy::too_many_lines)]
fn collect_writes_from_stmt(
    stmt: &Statement<'_>,
    writes: &mut Vec<JsWrite>,
    refs: &mut Vec<(String, u32)>,
    in_for_var: bool,
) {
    match stmt {
        Statement::VariableDeclaration(v) => {
            for d in &v.declarations {
                // Skip destructuring patterns.
                let is_destructure =
                    !matches!(&d.id, oxc_ast::ast::BindingPattern::BindingIdentifier(_));
                if is_destructure {
                    // Still collect refs from init.
                    if let Some(init) = &d.init {
                        collect_refs_from_expr(init, refs);
                    }
                    continue;
                }
                if let oxc_ast::ast::BindingPattern::BindingIdentifier(id) = &d.id {
                    let name = id.name.as_str().to_string();
                    // Skip underscore-prefixed and loop vars.
                    if !name.starts_with('_') && !in_for_var {
                        let span = oxc_span_to_core(v.span);
                        writes.push(JsWrite {
                            name,
                            offset: v.span.start,
                            span,
                        });
                    }
                    if let Some(init) = &d.init {
                        collect_refs_from_expr(init, refs);
                    }
                }
            }
        }
        Statement::ExpressionStatement(es) => {
            if let Expression::AssignmentExpression(a) = &es.expression {
                // Bare identifier LHS assignment.
                if let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(id) = &a.left {
                    let name = id.name.as_str().to_string();
                    if !name.starts_with('_') {
                        let span = oxc_span_to_core(a.span);
                        writes.push(JsWrite {
                            name,
                            offset: a.span.start,
                            span,
                        });
                    }
                }
                collect_refs_from_expr(&a.right, refs);
            } else {
                collect_refs_from_expr(&es.expression, refs);
            }
        }
        // Recurse into control-flow blocks (but not into function bodies).
        Statement::BlockStatement(b) => {
            collect_writes_from_stmts(&b.body, writes, refs, in_for_var);
        }
        Statement::IfStatement(s) => {
            collect_refs_from_expr(&s.test, refs);
            collect_writes_from_stmt(&s.consequent, writes, refs, in_for_var);
            if let Some(alt) = &s.alternate {
                collect_writes_from_stmt(alt, writes, refs, in_for_var);
            }
        }
        Statement::WhileStatement(s) => {
            collect_refs_from_expr(&s.test, refs);
            collect_writes_from_stmt(&s.body, writes, refs, in_for_var);
        }
        Statement::DoWhileStatement(s) => {
            collect_refs_from_expr(&s.test, refs);
            collect_writes_from_stmt(&s.body, writes, refs, in_for_var);
        }
        Statement::ForStatement(s) => {
            if let Some(init) = &s.init {
                if let oxc_ast::ast::ForStatementInit::VariableDeclaration(v) = init {
                    for d in &v.declarations {
                        if let oxc_ast::ast::BindingPattern::BindingIdentifier(id) = &d.id {
                            let name = id.name.as_str().to_string();
                            if !name.starts_with('_') {
                                let span = oxc_span_to_core(v.span);
                                writes.push(JsWrite {
                                    name,
                                    offset: v.span.start,
                                    span,
                                });
                            }
                        }
                        if let Some(e) = &d.init {
                            collect_refs_from_expr(e, refs);
                        }
                    }
                } else if let Some(e) = init.as_expression() {
                    collect_refs_from_expr(e, refs);
                }
            }
            if let Some(test) = &s.test {
                collect_refs_from_expr(test, refs);
            }
            if let Some(update) = &s.update {
                collect_refs_from_expr(update, refs);
            }
            collect_writes_from_stmt(&s.body, writes, refs, in_for_var);
        }
        // for-of and for-in: skip the loop variable declaration.
        Statement::ForOfStatement(s) => {
            collect_refs_from_expr(&s.right, refs);
            collect_writes_from_stmt(&s.body, writes, refs, false);
        }
        Statement::ForInStatement(s) => {
            collect_refs_from_expr(&s.right, refs);
            collect_writes_from_stmt(&s.body, writes, refs, false);
        }
        Statement::TryStatement(s) => {
            collect_writes_from_stmts(&s.block.body, writes, refs, in_for_var);
            if let Some(handler) = &s.handler {
                collect_writes_from_stmts(&handler.body.body, writes, refs, in_for_var);
            }
            if let Some(fin) = &s.finalizer {
                collect_writes_from_stmts(&fin.body, writes, refs, in_for_var);
            }
        }
        Statement::SwitchStatement(s) => {
            collect_refs_from_expr(&s.discriminant, refs);
            for case in &s.cases {
                if let Some(test) = &case.test {
                    collect_refs_from_expr(test, refs);
                }
                collect_writes_from_stmts(&case.consequent, writes, refs, in_for_var);
            }
        }
        Statement::ReturnStatement(r) => {
            if let Some(arg) = &r.argument {
                collect_refs_from_expr(arg, refs);
            }
        }
        Statement::ThrowStatement(t) => collect_refs_from_expr(&t.argument, refs),
        Statement::LabeledStatement(l) => {
            collect_writes_from_stmt(&l.body, writes, refs, in_for_var);
        }
        // STOP at nested function / class bodies, and ignore everything else.
        _ => {}
    }
}

/// Collect all `Identifier` references (reads) from an expression, recursively.
/// Does NOT recurse into nested function bodies (arrow fns, function exprs).
fn collect_refs_from_expr(expr: &Expression<'_>, refs: &mut Vec<(String, u32)>) {
    match expr {
        Expression::Identifier(id) => {
            refs.push((id.name.as_str().to_string(), id.span.start));
        }
        Expression::CallExpression(c) => {
            collect_refs_from_expr(&c.callee, refs);
            for arg in &c.arguments {
                if let Some(e) = arg.as_expression() {
                    collect_refs_from_expr(e, refs);
                }
            }
        }
        Expression::NewExpression(n) => {
            collect_refs_from_expr(&n.callee, refs);
            for arg in &n.arguments {
                if let Some(e) = arg.as_expression() {
                    collect_refs_from_expr(e, refs);
                }
            }
        }
        Expression::StaticMemberExpression(m) => {
            collect_refs_from_expr(&m.object, refs);
            // property is not a variable ref
        }
        Expression::ComputedMemberExpression(m) => {
            collect_refs_from_expr(&m.object, refs);
            collect_refs_from_expr(&m.expression, refs);
        }
        Expression::AssignmentExpression(a) => {
            // RHS is a load.
            collect_refs_from_expr(&a.right, refs);
            // LHS: if computed, also a load.
            if let oxc_ast::ast::AssignmentTarget::ComputedMemberExpression(m) = &a.left {
                collect_refs_from_expr(&m.object, refs);
                collect_refs_from_expr(&m.expression, refs);
            } else if let oxc_ast::ast::AssignmentTarget::StaticMemberExpression(m) = &a.left {
                collect_refs_from_expr(&m.object, refs);
            }
        }
        Expression::BinaryExpression(b) => {
            collect_refs_from_expr(&b.left, refs);
            collect_refs_from_expr(&b.right, refs);
        }
        Expression::LogicalExpression(l) => {
            collect_refs_from_expr(&l.left, refs);
            collect_refs_from_expr(&l.right, refs);
        }
        Expression::UnaryExpression(u) => collect_refs_from_expr(&u.argument, refs),
        Expression::ConditionalExpression(c) => {
            collect_refs_from_expr(&c.test, refs);
            collect_refs_from_expr(&c.consequent, refs);
            collect_refs_from_expr(&c.alternate, refs);
        }
        Expression::SequenceExpression(s) => {
            for e in &s.expressions {
                collect_refs_from_expr(e, refs);
            }
        }
        Expression::ArrayExpression(a) => {
            for elt in &a.elements {
                if let Some(e) = elt.as_expression() {
                    collect_refs_from_expr(e, refs);
                }
            }
        }
        Expression::ObjectExpression(o) => {
            for prop in &o.properties {
                if let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop {
                    collect_refs_from_expr(&p.value, refs);
                }
            }
        }
        Expression::TemplateLiteral(t) => {
            for e in &t.expressions {
                collect_refs_from_expr(e, refs);
            }
        }
        Expression::TaggedTemplateExpression(t) => {
            collect_refs_from_expr(&t.tag, refs);
            for e in &t.quasi.expressions {
                collect_refs_from_expr(e, refs);
            }
        }
        Expression::AwaitExpression(a) => collect_refs_from_expr(&a.argument, refs),
        Expression::YieldExpression(y) => {
            if let Some(arg) = &y.argument {
                collect_refs_from_expr(arg, refs);
            }
        }
        Expression::ParenthesizedExpression(p) => collect_refs_from_expr(&p.expression, refs),
        // TS wrappers.
        Expression::TSAsExpression(e) => collect_refs_from_expr(&e.expression, refs),
        Expression::TSSatisfiesExpression(e) => collect_refs_from_expr(&e.expression, refs),
        Expression::TSNonNullExpression(e) => collect_refs_from_expr(&e.expression, refs),
        Expression::TSTypeAssertion(e) => collect_refs_from_expr(&e.expression, refs),
        Expression::TSInstantiationExpression(e) => collect_refs_from_expr(&e.expression, refs),
        // STOP at nested function bodies — they have their own scope.
        // Everything else has no sub-expressions of interest.
        _ => {}
    }
}

/// Collect all `Identifier` references from a list of statements.
fn collect_refs_from_stmts(stmts: &[Statement<'_>], refs: &mut Vec<(String, u32)>) {
    for stmt in stmts {
        collect_refs_from_stmt(stmt, refs);
    }
}

fn collect_refs_from_stmt(stmt: &Statement<'_>, refs: &mut Vec<(String, u32)>) {
    match stmt {
        Statement::ExpressionStatement(es) => collect_refs_from_expr(&es.expression, refs),
        Statement::ReturnStatement(r) => {
            if let Some(arg) = &r.argument {
                collect_refs_from_expr(arg, refs);
            }
        }
        Statement::VariableDeclaration(v) => {
            for d in &v.declarations {
                if let Some(init) = &d.init {
                    collect_refs_from_expr(init, refs);
                }
            }
        }
        Statement::BlockStatement(b) => collect_refs_from_stmts(&b.body, refs),
        Statement::IfStatement(s) => {
            collect_refs_from_expr(&s.test, refs);
            collect_refs_from_stmt(&s.consequent, refs);
            if let Some(alt) = &s.alternate {
                collect_refs_from_stmt(alt, refs);
            }
        }
        Statement::WhileStatement(s) => {
            collect_refs_from_expr(&s.test, refs);
            collect_refs_from_stmt(&s.body, refs);
        }
        Statement::DoWhileStatement(s) => {
            collect_refs_from_expr(&s.test, refs);
            collect_refs_from_stmt(&s.body, refs);
        }
        Statement::ForStatement(s) => {
            if let Some(Some(e)) = s.init.as_ref().map(|i| i.as_expression()) {
                collect_refs_from_expr(e, refs);
            }
            if let Some(test) = &s.test {
                collect_refs_from_expr(test, refs);
            }
            if let Some(update) = &s.update {
                collect_refs_from_expr(update, refs);
            }
            collect_refs_from_stmt(&s.body, refs);
        }
        Statement::ForOfStatement(s) => {
            collect_refs_from_expr(&s.right, refs);
            collect_refs_from_stmt(&s.body, refs);
        }
        Statement::ForInStatement(s) => {
            collect_refs_from_expr(&s.right, refs);
            collect_refs_from_stmt(&s.body, refs);
        }
        Statement::TryStatement(s) => {
            collect_refs_from_stmts(&s.block.body, refs);
            if let Some(handler) = &s.handler {
                collect_refs_from_stmts(&handler.body.body, refs);
            }
            if let Some(fin) = &s.finalizer {
                collect_refs_from_stmts(&fin.body, refs);
            }
        }
        Statement::SwitchStatement(s) => {
            collect_refs_from_expr(&s.discriminant, refs);
            for case in &s.cases {
                if let Some(test) = &case.test {
                    collect_refs_from_expr(test, refs);
                }
                collect_refs_from_stmts(&case.consequent, refs);
            }
        }
        Statement::ThrowStatement(t) => collect_refs_from_expr(&t.argument, refs),
        Statement::LabeledStatement(l) => collect_refs_from_stmt(&l.body, refs),
        // STOP at nested function / class bodies, and ignore everything else.
        _ => {}
    }
}

/// Maps an [`oxc_ast::ast::AssignmentOperator`] to a static display string.
fn assignment_operator_str(op: oxc_ast::ast::AssignmentOperator) -> &'static str {
    use oxc_ast::ast::AssignmentOperator;
    match op {
        AssignmentOperator::Assign => "=",
        AssignmentOperator::Addition => "+=",
        AssignmentOperator::Subtraction => "-=",
        AssignmentOperator::Multiplication => "*=",
        AssignmentOperator::Division => "/=",
        AssignmentOperator::Remainder => "%=",
        AssignmentOperator::Exponential => "**=",
        AssignmentOperator::ShiftLeft => "<<=",
        AssignmentOperator::ShiftRight => ">>=",
        AssignmentOperator::ShiftRightZeroFill => ">>>=",
        AssignmentOperator::BitwiseOR => "|=",
        AssignmentOperator::BitwiseXOR => "^=",
        AssignmentOperator::BitwiseAnd => "&=",
        AssignmentOperator::LogicalAnd => "&&=",
        AssignmentOperator::LogicalOr => "||=",
        AssignmentOperator::LogicalNullish => "??=",
    }
}

/// Maps a [`oxc_ast::ast::BinaryOperator`] to a static display string if it is
/// a **non-shift** bitwise operator (`&`, `|`, `^`), or `None` otherwise.
///
/// Shift operators (`<<`, `>>`, `>>>`) bind **tighter** than comparison
/// operators in JavaScript, so `a << b == c` parses as `(a << b) == c` — the
/// programmer's intent is already reflected and no footgun exists.  Use
/// [`js_shift_op_str`] when you specifically need shift operators.
fn js_bitwise_non_shift_op_str(op: oxc_ast::ast::BinaryOperator) -> Option<&'static str> {
    use oxc_ast::ast::BinaryOperator;
    match op {
        BinaryOperator::BitwiseAnd => Some("&"),
        BinaryOperator::BitwiseOR => Some("|"),
        BinaryOperator::BitwiseXOR => Some("^"),
        _ => None,
    }
}

/// Maps a [`oxc_ast::ast::BinaryOperator`] to a static display string if it is
/// a bitwise shift operator (`<<`, `>>`, `>>>`), or `None` otherwise.
///
/// Kept separate from [`js_bitwise_non_shift_op_str`] because shifts bind
/// **tighter** than comparisons and therefore do **not** produce the CWE-783
/// footgun that `&`/`|`/`^` do when mixed with `==`/`<`/etc.
#[allow(dead_code)]
fn js_shift_op_str(op: oxc_ast::ast::BinaryOperator) -> Option<&'static str> {
    use oxc_ast::ast::BinaryOperator;
    match op {
        BinaryOperator::ShiftLeft => Some("<<"),
        BinaryOperator::ShiftRight => Some(">>"),
        BinaryOperator::ShiftRightZeroFill => Some(">>>"),
        _ => None,
    }
}

/// Maps a [`oxc_ast::ast::BinaryOperator`] to a static display string if it is
/// a comparison operator, or `None` otherwise.
fn js_comparison_op_str(op: oxc_ast::ast::BinaryOperator) -> Option<&'static str> {
    use oxc_ast::ast::BinaryOperator;
    match op {
        BinaryOperator::Equality => Some("=="),
        BinaryOperator::Inequality => Some("!="),
        BinaryOperator::StrictEquality => Some("==="),
        BinaryOperator::StrictInequality => Some("!=="),
        BinaryOperator::LessThan => Some("<"),
        BinaryOperator::LessEqualThan => Some("<="),
        BinaryOperator::GreaterThan => Some(">"),
        BinaryOperator::GreaterEqualThan => Some(">="),
        BinaryOperator::Instanceof => Some("instanceof"),
        BinaryOperator::In => Some("in"),
        _ => None,
    }
}

/// Returns `true` when the argument of a `!` unary expression is a "plain"
/// operand shape that makes the `!x & y` footgun ambiguous.
///
/// Only identifiers (`x`, `flag`) and member accesses (`obj.flag`, `obj[key]`)
/// qualify as footgun-worthy: the developer likely forgot that `!` binds
/// tighter than `&`/`|`/`^`.  Parenthesized expressions, calls, and literals
/// express explicit intent and are NOT flagged.
fn is_bang_arg_in_footgun_allowlist(expr: &Expression<'_>) -> bool {
    matches!(
        expr,
        Expression::Identifier(_)
            | Expression::StaticMemberExpression(_)
            | Expression::ComputedMemberExpression(_)
    )
}

/// Unwrap a TypeScript type assertion (`x as T`, `x satisfies T`, `<T>x`) to
/// the underlying expression.  Used by Pattern 2 to see through TS casts that
/// would otherwise mask a `!`-on-name footgun.
///
/// Note: `ParenthesizedExpression` is intentionally NOT unwrapped here — the
/// existing carve-out at the call site suppresses findings when the user has
/// explicitly added parens to disambiguate intent.
fn unwrap_ts_type_assertion<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    match expr {
        Expression::TSAsExpression(t) => unwrap_ts_type_assertion(&t.expression),
        Expression::TSSatisfiesExpression(t) => unwrap_ts_type_assertion(&t.expression),
        Expression::TSTypeAssertion(t) => unwrap_ts_type_assertion(&t.expression),
        _ => expr,
    }
}

/// Checks a `BinaryExpression` for operator-precedence traps and pushes a
/// [`JsOpPrecedenceSite`] onto `out.op_precedence_sites` when one is detected.
///
/// Two patterns are detected:
/// 1. Non-shift bitwise (`&`/`|`/`^`) mixed with a comparison op without
///    parens (either operand order).  Shift operators (`<<`/`>>`/`>>>`) are
///    explicitly excluded because they bind **tighter** than comparison
///    operators in JavaScript (`a << b == c` parses as `(a << b) == c`, which
///    is exactly what the programmer wrote — no footgun exists).
/// 2. `!ident` or `!member` as either operand of `&`/`|`/`^`: `!x & y` or
///    `y & !x`.  Both orderings are the same footgun.  When both sides qualify
///    (e.g. `!x & !y`) only one site is pushed to avoid double-counting.
///    The `!` argument must be an [`Identifier`], [`StaticMemberExpression`],
///    or [`ComputedMemberExpression`]; parenthesized subexpressions, calls, and
///    literals are accepted as expressing explicit intent and are NOT flagged.
fn check_op_precedence(b: &oxc_ast::ast::BinaryExpression<'_>, out: &mut WalkCtx) {
    use oxc_ast::ast::UnaryOperator;

    // Pattern 1: non-shift bitwise outer, comparison inner (either side).
    if let Some(outer_str) = js_bitwise_non_shift_op_str(b.operator) {
        for operand in [&b.left, &b.right] {
            if matches!(operand, Expression::ParenthesizedExpression(_)) {
                continue;
            }
            if let Expression::BinaryExpression(inner) = operand
                && let Some(inner_str) = js_comparison_op_str(inner.operator)
            {
                out.op_precedence_sites.push(JsOpPrecedenceSite {
                    span: oxc_span_to_core(b.span),
                    kind: JsOpPrecedenceKind::BitwiseWithComparison,
                    outer_operator: outer_str,
                    inner_operator: inner_str,
                });
                return;
            }
        }

        // Pattern 2: `!ident` / `!member` as either operand of `&`/`|`/`^`.
        // Check left side first; if it qualifies, emit once and return so that
        // `!x & !y` never produces two findings for the same BinaryExpression.
        // TS type-assertion wrappers (`as T`, `satisfies T`, `<T>x`) are
        // transparent to this check via `unwrap_ts_type_assertion`.
        let left_qualifies = !matches!(b.left, Expression::ParenthesizedExpression(_))
            && if let Expression::UnaryExpression(u) = unwrap_ts_type_assertion(&b.left) {
                u.operator == UnaryOperator::LogicalNot
                    && is_bang_arg_in_footgun_allowlist(&u.argument)
            } else {
                false
            };

        if left_qualifies {
            out.op_precedence_sites.push(JsOpPrecedenceSite {
                span: oxc_span_to_core(b.span),
                kind: JsOpPrecedenceKind::NotWithBitwise,
                outer_operator: outer_str,
                inner_operator: "!",
            });
            return;
        }

        // Check right side for the symmetric case (`y & !x`).
        let right_qualifies = !matches!(b.right, Expression::ParenthesizedExpression(_))
            && if let Expression::UnaryExpression(u) = unwrap_ts_type_assertion(&b.right) {
                u.operator == UnaryOperator::LogicalNot
                    && is_bang_arg_in_footgun_allowlist(&u.argument)
            } else {
                false
            };

        if right_qualifies {
            out.op_precedence_sites.push(JsOpPrecedenceSite {
                span: oxc_span_to_core(b.span),
                kind: JsOpPrecedenceKind::NotWithBitwise,
                outer_operator: outer_str,
                inner_operator: "!",
            });
        }
    }
    // Note: Pattern 1b (comparison outer, shift inner) has been intentionally
    // removed.  Shifts bind tighter than comparisons in JS, so the AST for
    // `a << b == c` is already `(a << b) == c` — the programmer's intent is
    // reflected and flagging it would be a false positive.
}

/// BUG004 Pattern 3: TypeScript `!ident as T & U` intersection-type trap.
///
/// In TypeScript, the `as` keyword has higher precedence than bitwise `&`
/// (both are given `Precedence::Compare = 13`, with `&` at `BitwiseAnd = 11`).
/// As a result, `!x as boolean & MASK` is parsed by oxc as:
///   `TSAsExpression { expression: !x, type: TSIntersectionType(boolean, MASK) }`
/// rather than the programmer's likely intention of:
///   `(!x as boolean) & MASK`  (bitwise AND with `MASK` as a value).
///
/// When the cast expression is a `!ident`/`!member` and the type annotation is
/// a `TSIntersectionType`, this is the same CWE-783 precedence footgun as
/// Pattern 2 — flag it with `NotWithBitwise`.
fn check_op_precedence_ts_as(e: &oxc_ast::ast::TSAsExpression<'_>, out: &mut WalkCtx) {
    use oxc_ast::ast::{TSType, UnaryOperator};

    // Only flag when the type annotation is an intersection type (T & U …).
    if !matches!(e.type_annotation, TSType::TSIntersectionType(_)) {
        return;
    }

    // The cast expression must be `!ident` or `!member`.
    let Expression::UnaryExpression(u) = &e.expression else {
        return;
    };
    if u.operator != UnaryOperator::LogicalNot {
        return;
    }
    if !is_bang_arg_in_footgun_allowlist(&u.argument) {
        return;
    }

    out.op_precedence_sites.push(JsOpPrecedenceSite {
        span: oxc_span_to_core(e.span),
        kind: JsOpPrecedenceKind::NotWithTsIntersection,
        outer_operator: "as",
        inner_operator: "!",
    });
}

/// If `expr` is an `AssignmentExpression` (but NOT a parenthesized one —
/// the `ESLint` `"except-parens"` carve-out), pushes a
/// [`JsAssignInCondSite`] onto `out.assignment_in_conditions`.
///
/// The carve-out: `if ((x = 1))` wraps the assignment in a
/// `ParenthesizedExpression` whose inner is an `AssignmentExpression`.  We
/// treat that as intentional and do not flag it.
fn check_assign_in_cond(expr: &Expression<'_>, out: &mut WalkCtx) {
    // Carve-out: `if ((x = 1))` — the outer paren makes intent explicit.
    if let Expression::ParenthesizedExpression(p) = expr
        && matches!(p.expression, Expression::AssignmentExpression(_))
    {
        return;
    }
    if let Expression::AssignmentExpression(a) = expr {
        out.assignment_in_conditions.push(JsAssignInCondSite {
            span: oxc_span_to_core(a.span),
            operator: assignment_operator_str(a.operator),
        });
    }
}

#[allow(clippy::too_many_lines)]
fn walk_stmt(stmt: &Statement<'_>, out: &mut WalkCtx) {
    match stmt {
        Statement::ExpressionStatement(es) => walk_expr(&es.expression, out),
        Statement::VariableDeclaration(v) => {
            for d in &v.declarations {
                if let Some(init) = &d.init {
                    // SEC012: capture `const/let/var name = <literal>`.
                    if let oxc_ast::ast::BindingPattern::BindingIdentifier(id) = &d.id
                        && let Some(lit) = expr_to_js_literal(init)
                    {
                        out.assignments.push(JsAssignmentSite {
                            lhs_name: id.name.to_lowercase(),
                            rhs_literal: lit,
                            span: oxc_span_to_core(v.span),
                        });
                    }
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
            // MAINT016: detect unreachable statements in this block.
            check_js_block_for_unreachable(&b.body, &mut out.unreachable_stmts);
            // STYLE001: detect ASI hazards in this block.
            check_asi_hazards(&b.body, &out.source_text, &mut out.asi_hazards);
            for s in &b.body {
                walk_stmt(s, out);
            }
        }
        Statement::IfStatement(s) => {
            // MAINT013: flag empty consequent block.
            if let Statement::BlockStatement(blk) = &s.consequent
                && blk.body.is_empty()
            {
                out.empty_blocks.push(oxc_span_to_core(s.span));
            }
            // BUG001: flag assignment in `if` test.
            check_assign_in_cond(&s.test, out);
            walk_expr(&s.test, out);
            walk_stmt(&s.consequent, out);
            if let Some(alt) = &s.alternate {
                walk_stmt(alt, out);
            }
        }
        Statement::WhileStatement(s) => {
            // MAINT013: flag empty while body.
            if let Statement::BlockStatement(blk) = &s.body
                && blk.body.is_empty()
            {
                out.empty_blocks.push(oxc_span_to_core(s.span));
            }
            // MAINT010: flag `while (true) { ... }` with no exit.
            if let Expression::BooleanLiteral(b) = &s.test
                && b.value
            {
                let body_stmts: Vec<&Statement<'_>> = match &s.body {
                    Statement::BlockStatement(blk) => blk.body.iter().collect(),
                    other => vec![other],
                };
                let has_exit = body_stmts.iter().any(|st| js_stmt_has_exit(st));
                if !has_exit {
                    out.infinite_loops.push(oxc_span_to_core(s.span));
                }
            }
            // BUG001: flag assignment in `while` test.
            check_assign_in_cond(&s.test, out);
            walk_expr(&s.test, out);
            walk_stmt(&s.body, out);
        }
        Statement::DoWhileStatement(s) => {
            // BUG001: flag assignment in `do-while` test.
            check_assign_in_cond(&s.test, out);
            walk_expr(&s.test, out);
            walk_stmt(&s.body, out);
        }
        Statement::ForStatement(s) => {
            // MAINT013: flag empty for body.
            if let Statement::BlockStatement(blk) = &s.body
                && blk.body.is_empty()
            {
                out.empty_blocks.push(oxc_span_to_core(s.span));
            }
            // MAINT010: flag `for (;;) { ... }` with no exit.
            if s.init.is_none() && s.test.is_none() && s.update.is_none() {
                let body_stmts: Vec<&Statement<'_>> = match &s.body {
                    Statement::BlockStatement(blk) => blk.body.iter().collect(),
                    other => vec![other],
                };
                let has_exit = body_stmts.iter().any(|st| js_stmt_has_exit(st));
                if !has_exit {
                    out.infinite_loops.push(oxc_span_to_core(s.span));
                }
            }
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
                // BUG001: flag assignment in `for` test.
                check_assign_in_cond(test, out);
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
            // MAINT009: record whether any case clause is `default:` (test == None).
            let has_default = s.cases.iter().any(|c| c.test.is_none());
            out.switch_sites.push(JsSwitchSite {
                has_default,
                span: oxc_span_to_core(s.span),
            });
            walk_expr(&s.discriminant, out);
            // BUG002: detect fall-through cases. Walk every case except the last.
            let total = s.cases.len();
            for (i, case) in s.cases.iter().enumerate() {
                if i + 1 < total
                    && !case.consequent.is_empty()
                    && !case_consequent_is_terminating(&case.consequent)
                {
                    // Carve-out: ESLint-style `// falls through` comment on
                    // a line immediately before the next case label.
                    let next_case_start = s.cases[i + 1].span.start as usize;
                    if !has_fallthrough_carveout(&out.source_text, next_case_start) {
                        out.case_fallthroughs.push(JsCaseFallthrough {
                            span: oxc_span_to_core(case.span),
                        });
                    }
                }
                if let Some(test) = &case.test {
                    walk_expr(test, out);
                }
                // STYLE001: detect ASI hazards in switch-case consequent slices.
                check_asi_hazards(&case.consequent, &out.source_text, &mut out.asi_hazards);
                for stmt in &case.consequent {
                    walk_stmt(stmt, out);
                }
            }
        }
        Statement::TryStatement(s) => {
            // STYLE001: detect ASI hazards in the try block body.
            check_asi_hazards(&s.block.body, &out.source_text, &mut out.asi_hazards);
            for st in &s.block.body {
                walk_stmt(st, out);
            }
            if let Some(handler) = &s.handler {
                // MAINT013: flag empty catch body, UNLESS the catch parameter
                // is absent or named `_` (intentional swallow idiom).
                // Intentional swallow: no param at all, or param named `_`.
                let is_intentional_swallow = match &handler.param {
                    None => true, // `catch {}` — intentional
                    Some(p) => matches!(
                        &p.pattern,
                        oxc_ast::ast::BindingPattern::BindingIdentifier(id)
                            if id.name.as_str() == "_"
                    ),
                };
                if handler.body.body.is_empty() && !is_intentional_swallow {
                    out.empty_blocks.push(oxc_span_to_core(handler.span));
                }
                // STYLE001: detect ASI hazards in the catch handler body.
                check_asi_hazards(&handler.body.body, &out.source_text, &mut out.asi_hazards);
                for st in &handler.body.body {
                    walk_stmt(st, out);
                }
            }
            if let Some(fin) = &s.finalizer {
                // STYLE001: detect ASI hazards in the finally body.
                check_asi_hazards(&fin.body, &out.source_text, &mut out.asi_hazards);
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
            // SEC015: push function params for log-injection param tracking.
            let params = collect_js_fn_params(&f.params);
            out.current_fn_params.push(params);
            if let Some(body) = &f.body {
                // MAINT012: extract dead stores for this function scope.
                let dead = extract_dead_stores_from_fn_body(&body.statements);
                out.dead_stores.extend(dead);
                // MAINT016: detect unreachable statements in this function body.
                check_js_block_for_unreachable(&body.statements, &mut out.unreachable_stmts);
                // STYLE001: detect ASI hazards in this function body.
                check_asi_hazards(&body.statements, &out.source_text, &mut out.asi_hazards);
                for s in &body.statements {
                    walk_stmt(s, out);
                }
            }
            out.current_fn_params.pop();
            out.at_top_level = prev;
        }
        Statement::ClassDeclaration(c) => {
            let prev = out.at_top_level;
            out.at_top_level = false;
            for elt in &c.body.body {
                if let oxc_ast::ast::ClassElement::MethodDefinition(m) = elt
                    && let Some(body) = &m.value.body
                {
                    // SEC015: push method params for log-injection param tracking.
                    let params = collect_js_fn_params(&m.value.params);
                    out.current_fn_params.push(params);
                    // MAINT012: extract dead stores for this method scope.
                    let dead = extract_dead_stores_from_fn_body(&body.statements);
                    out.dead_stores.extend(dead);
                    // MAINT016: detect unreachable statements in this method body.
                    check_js_block_for_unreachable(&body.statements, &mut out.unreachable_stmts);
                    // STYLE001: detect ASI hazards in this method body.
                    check_asi_hazards(&body.statements, &out.source_text, &mut out.asi_hazards);
                    for s in &body.statements {
                        walk_stmt(s, out);
                    }
                    out.current_fn_params.pop();
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
        // MAINT011: debugger statement.
        Statement::DebuggerStatement(d) => {
            out.debug_calls
                .push((oxc_span_to_core(d.span), JsDebugKind::DebuggerStmt));
        }
        // break, continue, import declarations, TS decls — no calls.
        _ => {}
    }
}

fn walk_decl(decl: &oxc_ast::ast::Declaration<'_>, out: &mut WalkCtx) {
    match decl {
        oxc_ast::ast::Declaration::FunctionDeclaration(f) => {
            let params = collect_js_fn_params(&f.params);
            out.current_fn_params.push(params);
            if let Some(body) = &f.body {
                // MAINT012: extract dead stores for this exported function scope.
                let dead = extract_dead_stores_from_fn_body(&body.statements);
                out.dead_stores.extend(dead);
                // MAINT016: detect unreachable statements in this exported function body.
                check_js_block_for_unreachable(&body.statements, &mut out.unreachable_stmts);
                // STYLE001: detect ASI hazards in this exported function body.
                check_asi_hazards(&body.statements, &out.source_text, &mut out.asi_hazards);
                for s in &body.statements {
                    walk_stmt(s, out);
                }
            }
            out.current_fn_params.pop();
        }
        oxc_ast::ast::Declaration::ClassDeclaration(c) => {
            for elt in &c.body.body {
                if let oxc_ast::ast::ClassElement::MethodDefinition(m) = elt
                    && let Some(body) = &m.value.body
                {
                    let params = collect_js_fn_params(&m.value.params);
                    out.current_fn_params.push(params);
                    // MAINT012: extract dead stores for this exported class method scope.
                    let dead = extract_dead_stores_from_fn_body(&body.statements);
                    out.dead_stores.extend(dead);
                    // MAINT016: detect unreachable statements in this exported class method.
                    check_js_block_for_unreachable(&body.statements, &mut out.unreachable_stmts);
                    // STYLE001: detect ASI hazards in this exported class method.
                    check_asi_hazards(&body.statements, &out.source_text, &mut out.asi_hazards);
                    for s in &body.statements {
                        walk_stmt(s, out);
                    }
                    out.current_fn_params.pop();
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
                let first_arg_string_value = call.arguments.first().and_then(|a| {
                    if let Some(Expression::StringLiteral(s)) = a.as_expression() {
                        Some(s.value.to_string())
                    } else {
                        None
                    }
                });
                let site = JsCallSite {
                    callee: JsCallee::Name(name.clone()),
                    span: oxc_span_to_core(call.span),
                    first_arg_is_string_literal: first_arg_is_string,
                    first_arg_span,
                    first_arg_string_value,
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
            // MAINT011: console.log / console.debug / console.trace
            // Excludes console.error, console.warn, console.info (legitimate).
            if let Some(debug_kind) = debug_kind_for_call(&call.callee) {
                out.debug_calls
                    .push((oxc_span_to_core(call.span), debug_kind));
            }
            // SEC013: detect bind-all-interfaces patterns.
            if let Some(callee_name) = is_bind_callee_member(&call.callee) {
                let raw_val = first_string_arg_value(&call.arguments);
                let first_arg_string_value = raw_val.map(str::to_string);
                out.bind_call_sites.push(JsBindCallSite {
                    callee_name,
                    first_arg_string_value,
                    span: oxc_span_to_core(call.span),
                });
            }
            // SEC015: detect log-injection patterns.
            if let Some(callee_name) = log_callee_name(&call.callee) {
                let enclosing_fn_params = out.current_fn_params.last().cloned().unwrap_or_default();
                let (first_arg_string, first_arg_is_template_with_subst, arg_idents) =
                    extract_log_call_args(&call.arguments);
                out.log_calls.push(JsLogCallSite {
                    callee_name,
                    first_arg_string,
                    first_arg_is_template_with_subst,
                    arg_idents,
                    enclosing_fn_params,
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
                let new_first_arg_string_value = new_expr.arguments.first().and_then(|a| {
                    if let Some(Expression::StringLiteral(s)) = a.as_expression() {
                        Some(s.value.to_string())
                    } else {
                        None
                    }
                });
                out.call_sites.push(JsCallSite {
                    callee: JsCallee::New(name),
                    span: oxc_span_to_core(new_expr.span),
                    first_arg_is_string_literal: first_arg_is_string,
                    first_arg_span,
                    first_arg_string_value: new_first_arg_string_value,
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
            let params = collect_js_fn_params(&arrow.params);
            out.current_fn_params.push(params);
            // MAINT012: extract dead stores for this arrow function scope.
            let dead = extract_dead_stores_from_fn_body(&arrow.body.statements);
            out.dead_stores.extend(dead);
            // STYLE001: detect ASI hazards in this arrow function body.
            check_asi_hazards(
                &arrow.body.statements,
                &out.source_text,
                &mut out.asi_hazards,
            );
            for stmt in &arrow.body.statements {
                walk_stmt(stmt, out);
            }
            out.current_fn_params.pop();
            out.at_top_level = prev;
        }
        Expression::FunctionExpression(f) => {
            let prev = out.at_top_level;
            out.at_top_level = false;
            let params = collect_js_fn_params(&f.params);
            out.current_fn_params.push(params);
            if let Some(body) = &f.body {
                // MAINT012: extract dead stores for this function expression scope.
                let dead = extract_dead_stores_from_fn_body(&body.statements);
                out.dead_stores.extend(dead);
                // STYLE001: detect ASI hazards in this function expression body.
                check_asi_hazards(&body.statements, &out.source_text, &mut out.asi_hazards);
                for s in &body.statements {
                    walk_stmt(s, out);
                }
            }
            out.current_fn_params.pop();
            out.at_top_level = prev;
        }
        Expression::ClassExpression(c) => {
            let prev = out.at_top_level;
            out.at_top_level = false;
            for elt in &c.body.body {
                if let oxc_ast::ast::ClassElement::MethodDefinition(m) = elt
                    && let Some(body) = &m.value.body
                {
                    let params = collect_js_fn_params(&m.value.params);
                    out.current_fn_params.push(params);
                    // MAINT012: extract dead stores for this class-expression method.
                    let dead = extract_dead_stores_from_fn_body(&body.statements);
                    out.dead_stores.extend(dead);
                    // STYLE001: detect ASI hazards in this class-expression method.
                    check_asi_hazards(&body.statements, &out.source_text, &mut out.asi_hazards);
                    for s in &body.statements {
                        walk_stmt(s, out);
                    }
                    out.current_fn_params.pop();
                }
            }
            out.at_top_level = prev;
        }
        Expression::BinaryExpression(b) => {
            check_op_precedence(b, out); // BUG004
            walk_expr(&b.left, out);
            walk_expr(&b.right, out);
        }
        Expression::LogicalExpression(l) => {
            walk_expr(&l.left, out);
            walk_expr(&l.right, out);
        }
        Expression::UnaryExpression(u) => walk_expr(&u.argument, out),
        Expression::ConditionalExpression(c) => {
            // BUG001: flag assignment in ternary test position.
            check_assign_in_cond(&c.test, out);
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
            // SEC012: capture `name = <literal>` assignment expressions.
            if let oxc_ast::ast::AssignmentTarget::AssignmentTargetIdentifier(id) = &a.left
                && let Some(lit) = expr_to_js_literal(&a.right)
            {
                out.assignments.push(JsAssignmentSite {
                    lhs_name: id.name.to_lowercase(),
                    rhs_literal: lit,
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
        Expression::TSAsExpression(e) => {
            // BUG004 Pattern 3: `!ident as T & U` — in TS, `as` has higher
            // precedence than `&`, so `!x as boolean & MASK` is parsed by
            // TypeScript as `!x as (boolean & MASK)` (an intersection type),
            // NOT as `(!x as boolean) & MASK` (bitwise AND with a value).
            // The programmer almost certainly meant the latter — this is the
            // same CWE-783 footgun as Pattern 2, just disguised at the type
            // level.  Flag it when:
            //   (a) the cast expression is a `!ident`/`!member`, AND
            //   (b) the type annotation is a TS intersection type (`T & U`).
            check_op_precedence_ts_as(e, out);
            walk_expr(&e.expression, out);
        }
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
