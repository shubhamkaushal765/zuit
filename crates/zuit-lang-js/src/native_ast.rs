//! Pre-extracted call-site data from the oxc AST for JS/TS files.
//!
//! The oxc parser allocates its AST in a bump arena (`oxc_allocator::Allocator`)
//! and every node borrows from that arena. Storing the arena-backed AST in
//! [`zuit_core::ParsedFile`] would require a self-referential type. Instead,
//! during [`crate::parse::parse`] we walk the AST once, copy the information
//! that JS-only analyzers need into a plain, heap-allocated [`JsAst`], and then
//! drop the arena. The result is `Send + Sync` with zero `unsafe` code.
//!
//! # What is extracted
//!
//! - Call-site information needed by `SEC002-eval-sink`:
//!   every call / `new`-expression whose callee is a bare identifier of interest.
//! - DOM-based XSS sinks: assignments to `.innerHTML`/`.outerHTML`, calls to
//!   `document.write`/`document.writeln`, and calls to `insertAdjacentHTML`.
//!   Stored in [`JsDomSink`] entries within [`JsAst::dom_sinks`].
//! - Static `import` declarations and `require()` calls at module scope for
//!   `PERF002-heavy-import`.  Stored in [`JsImport`] entries within
//!   [`JsAst::imports`].
//! - Top-level bare call expressions (calls not nested inside any function or
//!   class body) for `PERF003-import-side-effect`.  Stored as [`JsCallSite`]
//!   entries within [`JsAst::top_level_calls`].

use std::any::Any;

use zuit_core::{NativeAst, Span};

/// The callee shape of a call expression of interest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsCallee {
    /// Bare identifier call: `eval(...)`, `Function(...)`, `setTimeout(...)`.
    Name(String),
    /// `new`-expression: `new Function(...)` — stores the constructor name.
    New(String),
}

/// A single call expression of interest extracted from a JS/TS source file.
///
/// Only call sites whose callee is a bare identifier (or bare `new <Identifier>`)
/// are recorded; member calls such as `obj.eval(...)` are not captured in v1.
/// Member-expression callees (e.g. `app.listen(...)`) are captured in the
/// [`crate::native_ast::JsAst::bind_call_sites`] field for SEC013.
#[derive(Debug, Clone)]
pub struct JsCallSite {
    /// The callee shape.
    pub callee: JsCallee,
    /// Full byte span of the call/new expression.
    pub span: Span,
    /// `true` when the first argument is a string literal or a template literal
    /// with no substitution expressions.
    pub first_arg_is_string_literal: bool,
    /// Byte span of the first argument, if one exists.
    ///
    /// Populated for future analyzers that need to annotate the argument position
    /// directly. Not yet consumed by any v1 analyzer.
    #[allow(dead_code)]
    pub first_arg_span: Option<Span>,
    /// The string value of the first argument, if it is a string literal (not a
    /// template literal).
    ///
    /// Populated at parse time for `SEC013-bind-all-interfaces`. `None` when the
    /// first argument is absent, non-string, or a template literal.
    /// Not yet consumed by every v1 analyzer — suppress the `dead_code` lint.
    #[allow(dead_code)]
    pub first_arg_string_value: Option<String>,
}

/// The kind of DOM-based XSS sink that was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomSinkKind {
    /// Assignment to `.innerHTML`: `el.innerHTML = value`.
    InnerHtml,
    /// Assignment to `.outerHTML`: `el.outerHTML = value`.
    OuterHtml,
    /// Call to `document.write(...)`.
    DocumentWrite,
    /// Call to `document.writeln(...)`.
    DocumentWriteln,
    /// Call to `el.insertAdjacentHTML(position, html)`.
    InsertAdjacentHtml,
    /// JSX `dangerouslySetInnerHTML={...}` attribute.
    DangerouslySetInnerHtml,
}

/// A single DOM-based XSS sink extracted from a JS/TS source file.
#[derive(Debug, Clone)]
pub struct JsDomSink {
    /// The kind of DOM sink.
    pub kind: DomSinkKind,
    /// Byte span of the sink expression (assignment expression or call expression).
    pub span: Span,
}

/// A static `import` declaration or top-level `require()` call.
///
/// Populated during the AST walk for `PERF002-heavy-import`.
///
/// # Coverage
///
/// - `import foo from "source"` — ES module static import.
/// - `import "source"` — side-effect import.
/// - `const x = require("source")` — `CommonJS` require at module scope.
///
/// Dynamic `import()` calls and `require()` calls nested inside functions are
/// **not** included: only top-level (module-scope) imports are relevant for the
/// heavy-import heuristic.
#[derive(Debug, Clone)]
pub struct JsImport {
    /// The module specifier string, e.g. `"lodash"` or `"./utils"`.
    pub source: String,
    /// Byte span of the entire import declaration or require call expression.
    pub span: Span,
}

/// Kind of debug-code construct extracted for `MAINT011-active-debug-code`.
///
/// Defined in `zuit-lang-js` (not `zuit-core`) per the per-rule extractor
/// architecture decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsDebugKind {
    /// `debugger;` statement — always flagged (`Severity::Medium`).
    DebuggerStmt,
    /// `console.log(…)` call — flagged (`Severity::Low`).
    ConsoleLog,
    /// `console.debug(…)` call — flagged (`Severity::Low`).
    ConsoleDebug,
    /// `console.trace(…)` call — flagged (`Severity::Low`).
    ConsoleTrace,
}

/// A `switch` statement site extracted for `MAINT009-missing-default-case`.
///
/// Populated by the walker for every `SwitchStatement`.  A finding is emitted
/// when `!has_default`.
#[derive(Debug, Clone)]
pub struct JsSwitchSite {
    /// `true` if at least one `case` clause has `test: None` (i.e. `default:`).
    pub has_default: bool,
    /// Byte span of the `switch` statement.
    pub span: Span,
}

/// Pre-extracted data from a JS/TS source file stored in the [`zuit_core::ParsedFile`]
/// native slot.
///
/// Populated by [`crate::parse::parse`] from the oxc AST before the arena is
/// dropped. Language-specific analyzers retrieve this via
/// [`crate::try_js_ast`].
#[derive(Debug)]
pub struct JsAst {
    /// All call/new expressions with bare-identifier callees.
    pub call_sites: Vec<JsCallSite>,
    /// All DOM-based XSS sinks (innerHTML/outerHTML assignments,
    /// document.write/writeln calls, insertAdjacentHTML calls,
    /// dangerouslySetInnerHTML JSX attributes).
    pub dom_sinks: Vec<JsDomSink>,
    /// Static `import` declarations and top-level `require()` calls.
    ///
    /// Used by `PERF002-heavy-import`.
    pub imports: Vec<JsImport>,
    /// Bare call expressions at module top-level (not inside any function or
    /// class body).
    ///
    /// Used by `PERF003-import-side-effect` to detect side-effectful module
    /// initialisation code such as `console.log("loaded")` at the top of a
    /// file.
    pub top_level_calls: Vec<JsCallSite>,
    /// Byte spans of empty `BlockStatement` bodies reached from `IfStatement`,
    /// `ForStatement`, `WhileStatement`, or `CatchClause`.
    ///
    /// Used by `MAINT013-empty-block`.
    ///
    /// Empty `catch` clauses whose parameter is absent or named `_` are
    /// intentional swallow idioms and are **excluded**.
    pub empty_blocks: Vec<Span>,

    /// Active debug-code call sites for `MAINT011-active-debug-code`.
    ///
    /// Contains `(span, kind)` for each flagged construct:
    /// - `debugger;` → [`JsDebugKind::DebuggerStmt`] (`Severity::Medium`)
    /// - `console.log(…)` → [`JsDebugKind::ConsoleLog`] (`Severity::Low`)
    /// - `console.debug(…)` → [`JsDebugKind::ConsoleDebug`] (`Severity::Low`)
    /// - `console.trace(…)` → [`JsDebugKind::ConsoleTrace`] (`Severity::Low`)
    ///
    /// `console.error`, `console.warn`, and `console.info` are intentionally
    /// **excluded** (legitimate in production error paths).
    pub debug_calls: Vec<(Span, JsDebugKind)>,

    /// Server-bind call sites for `SEC013-bind-all-interfaces`.
    ///
    /// Each entry is `(callee_last_segment, first_arg_string_value, span)`.
    /// Only records calls whose callee last segment is in the bind allowlist AND
    /// whose first argument is a string literal. Member calls are included
    /// (e.g. `app.listen(...)`, `server.listen(...)`).
    pub bind_call_sites: Vec<JsBindCallSite>,

    /// Assignment sites for `SEC012-hardcoded-security-constant`.
    ///
    /// Populated for variable declarations and assignment expressions whose LHS
    /// is a bare identifier and whose RHS is a literal value.
    pub assignments: Vec<JsAssignmentSite>,

    /// Log call sites for `SEC015-log-injection`.
    ///
    /// Populated for `CallExpression`s with a logging callee shape
    /// (e.g. `logger.info(...)`, `console.log(...)`, `log.warn(...)`).
    pub log_calls: Vec<JsLogCallSite>,

    /// Switch statement sites for `MAINT009-missing-default-case`.
    ///
    /// Populated for every `SwitchStatement`.  The analyzer fires when
    /// `!has_default`.
    pub switch_sites: Vec<JsSwitchSite>,
}

/// A literal value extracted from an assignment/declaration RHS for SEC012.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields consumed by SEC012 analyzer
pub enum JsLiteralValue {
    /// A string literal value.
    Str(String),
    /// A numeric literal value (truncated to i64).
    Int(i64),
    /// Any other literal type (bool, null, regexp, template, etc.).
    Other,
}

/// An assignment site extracted for `SEC012-hardcoded-security-constant`.
///
/// Populated for variable declarations (`const`, `let`, `var`) and assignment
/// expressions whose LHS is a plain identifier matching a security keyword.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields consumed by SEC012 analyzer
pub struct JsAssignmentSite {
    /// The LHS identifier name (lowercased).
    pub lhs_name: String,
    /// The literal value of the RHS.
    pub rhs_literal: JsLiteralValue,
    /// Byte span of the assignment/declaration.
    pub span: Span,
}

/// A server-bind call site extracted for `SEC013-bind-all-interfaces`.
#[derive(Debug, Clone)]
pub struct JsBindCallSite {
    /// The last segment of the callee (e.g. `"listen"`, `"bind"`).
    pub callee_name: String,
    /// The string value of the first argument, if it is a plain string literal.
    pub first_arg_string_value: Option<String>,
    /// Full byte span of the call expression.
    pub span: Span,
}

/// A log call site extracted for `SEC015-log-injection`.
///
/// Populated for `CallExpression`s whose callee is a `MemberExpression` with
/// an object whose last-segment name is in `["console","logger","log"]` and
/// whose property name is in `["log","info","debug","warn","error","trace"]`.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields consumed by SEC015 analyzer
pub struct JsLogCallSite {
    /// The callee name as `"object.method"` (e.g. `"logger.info"`).
    pub callee_name: String,
    /// The string value of the first argument, if it is a plain string literal.
    pub first_arg_string: Option<String>,
    /// `true` when the first argument is a `TemplateLiteral` with at least one
    /// expression substitution.
    pub first_arg_is_template_with_subst: bool,
    /// Leading identifier names of arguments after the first, and of template
    /// expressions within the first arg (for template-literal detection).
    pub arg_idents: Vec<String>,
    /// Parameter names of the immediately enclosing function, if any.
    pub enclosing_fn_params: Vec<String>,
    /// Full byte span of the call expression.
    pub span: Span,
}

// JsAst contains only Vec<JsCallSite> and Vec<JsDomSink> where both hold plain
// Rust types (String, Span which is two u32, bool, Option). All are Send + Sync.
impl NativeAst for JsAst {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
