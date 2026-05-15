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
}

// JsAst contains only Vec<JsCallSite> and Vec<JsDomSink> where both hold plain
// Rust types (String, Span which is two u32, bool, Option). All are Send + Sync.
impl NativeAst for JsAst {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
