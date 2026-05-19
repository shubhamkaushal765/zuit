//! Rust parsing via `syn`.
//!
//! [`parse`] calls `syn::parse_file` and wraps the resulting `syn::File` in a
//! [`RustAst`] that implements [`NativeAst`].  Any `syn::Error` is mapped to
//! [`ParseError::Syntax`].
//!
//! # Thread-safety design (Bug 2 fix)
//!
//! `syn::File` is not `Send + Sync` because `proc_macro2` uses `Rc` internally
//! in its fallback tokeniser.  Rather than wrapping it in a `Mutex` and adding
//! manual `Send`/`Sync` impls, we pre-walk the AST at parse time and store
//! only the derived data (unsafe-construct spans) in `RustAst`.  The
//! `syn::File` is dropped immediately after walking, so `RustAst` contains
//! only plain `Vec` / `Span` values that are inherently `Send + Sync`.  This
//! avoids all `unsafe` code in the crate and aligns with `ARCH_SPEC` §3.

use std::any::Any;
use std::sync::Arc;

use zuit_core::Span;
use zuit_core::{NativeAst, ParseError, ParsedFile, SourceFile};

use crate::index::build_index;
use crate::span_util::proc_span_to_byte_span;

/// Pre-extracted data about every `unsafe` construct found in a Rust source
/// file.  Populated at parse time by walking the `syn::File` once.
#[derive(Debug, Clone)]
pub(crate) struct UnsafeItem {
    /// Real byte span pointing at the unsafe keyword / `fn` token.
    pub(crate) span: Span,
    /// Human-readable kind: `"block"`, `"fn"`, `"impl"`, or `"trait"`.
    pub(crate) label: &'static str,
}

/// A literal value extracted from an assignment RHS for SEC012.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields consumed by SEC012 analyzer once registered
pub(crate) enum RustLiteralValue {
    /// A string literal value.
    Str(String),
    /// A byte string literal value.
    Bytes(Vec<u8>),
    /// An integer literal value (truncated to i64).
    Int(i64),
    /// Any other literal type (bool, float, char, etc.).
    Other,
}

/// An assignment site extracted for `SEC012-hardcoded-security-constant`.
///
/// Populated by [`Extractor`] for `let`/`=` assignments and `const`/`static`
/// declarations whose LHS identifier name matches a security-keyword pattern.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields consumed by SEC012 analyzer
pub(crate) struct RustAssignmentSite {
    /// The LHS identifier name (lowercased).
    pub(crate) lhs_name: String,
    /// The literal value of the RHS.
    pub(crate) rhs_literal: RustLiteralValue,
    /// Byte span of the assignment/declaration.
    pub(crate) span: Span,
}

/// A log call site extracted for `SEC015-log-injection`.
///
/// Populated by [`Extractor`] for macro invocations named `trace`, `debug`,
/// `info`, `warn`, `error`, `log` (with or without `log::` / `tracing::` path
/// prefix).  Macro bodies are parsed via regex over the token-string (not a
/// full AST), which is noted in analyzer messages.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields consumed by SEC015 analyzer
pub(crate) struct RustLogCallSite {
    /// Last segment of the macro name (e.g. `"info"`, `"debug"`).
    pub(crate) callee_name: String,
    /// The first string literal found in the macro body, if any.
    pub(crate) first_arg_string: Option<String>,
    /// Identifier tokens that follow the first string argument (comma-separated).
    pub(crate) arg_idents: Vec<String>,
    /// Parameter names of the immediately enclosing function, if any.
    pub(crate) enclosing_fn_params: Vec<String>,
    /// Byte span of the macro invocation.
    pub(crate) span: Span,
}

/// A server-bind call site extracted for `SEC013-bind-all-interfaces`.
///
/// Populated by [`Extractor`] for function calls whose path last segment is in
/// the bind allowlist.  Stored in [`RustAst::bind_call_sites`].
#[derive(Debug, Clone)]
pub(crate) struct RustCallSite {
    /// Last segment of the callee path (e.g. `"bind"`, `"listen"`).
    pub(crate) callee_name: String,
    /// The literal string value of the first argument, if it is a plain string
    /// literal.  `None` when the first argument is absent or non-string.
    pub(crate) first_arg_string_value: Option<String>,
    /// Byte span of the call expression.
    pub(crate) span: Span,
}

/// Kind of scrutinee in a `match` expression, for `MAINT009-missing-default-case`.
///
/// Only `Literal` and `LowerPath` trigger a finding; `Other` scrutinees
/// (function calls, field accesses, method calls, etc.) are out of scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RustScrutineeKind {
    /// The scrutinee is a literal (e.g. `match 1 { … }`).
    Literal,
    /// The scrutinee is a simple path whose **final** segment starts with a
    /// lowercase ASCII letter (heuristic for local variables / non-enum paths).
    LowerPath,
    /// Any other expression shape — excluded from MAINT009 to avoid
    /// false-positives on enum matches.
    Other,
}

/// A `match` expression site extracted for `MAINT009-missing-default-case`.
///
/// Populated by [`Extractor`] inside `visit_expr_match`.  Only sites where
/// `!has_wildcard && (scrutinee_kind == Literal || scrutinee_kind == LowerPath)`
/// should emit a finding.
#[derive(Debug, Clone)]
pub(crate) struct RustMatchSite {
    /// Classification of the scrutinee expression.
    pub(crate) scrutinee_kind: RustScrutineeKind,
    /// `true` if any arm pattern is `_` (wildcard) or a `|`-pattern containing
    /// `_`.
    pub(crate) has_wildcard: bool,
    /// Byte span of the `match` keyword.
    pub(crate) span: Span,
}

/// Kind of debug-code macro call extracted for `MAINT011-active-debug-code`.
///
/// Defined here (not in `zuit-core`) per the per-rule extractor architecture
/// decision: language-specific enums stay in their language crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RustDebugKind {
    /// `dbg!(…)` — always flagged (`Severity::Medium`).
    Dbg,
    /// `println!(…)` — only flagged when config `MAINT011.flag_println = true`.
    Println,
    /// `eprintln!(…)` — only flagged when config `MAINT011.flag_println = true`.
    Eprintln,
}

/// The concrete native AST produced by the Rust frontend.
///
/// This type is `pub(crate)` so it is accessible to language-specific analyzers
/// within this crate (via [`crate::try_rust_ast`]) but invisible to external
/// crates (enforced by the Rust visibility rules, backed by the dependency
/// graph).
///
/// `syn::File` is not `Send + Sync`, so we do not store it here.  Instead, all
/// data needed by language-specific analyzers is pre-extracted during parsing
/// and stored as plain `Vec` values that are trivially `Send + Sync`.
pub(crate) struct RustAst {
    /// All `unsafe` constructs found in the file, with real byte spans.
    pub(crate) unsafe_items: Vec<UnsafeItem>,

    /// Spans of `unsafe { … }` blocks that have no `// SAFETY:` comment on the
    /// block itself or the line immediately above it.
    pub(crate) unsafe_blocks_without_safety: Vec<Span>,

    /// Spans of `pub` (or `pub(...)`) `unsafe fn` declarations.
    pub(crate) pub_unsafe_fns: Vec<Span>,

    /// Spans of call expressions whose path resolves to a transmute variant
    /// (`transmute`, `mem::transmute`, `std::mem::transmute`, etc.).
    pub(crate) transmute_calls: Vec<Span>,

    /// Spans of `pub fn` declarations whose signature contains `*const T` or
    /// `*mut T` in argument or return position.
    pub(crate) raw_ptr_pub_apis: Vec<Span>,

    /// Spans of functions whose body contains both an `unsafe` block AND a
    /// call to a known parser/decoder path (e.g. `from_utf8_unchecked`,
    /// `slice::from_raw_parts`, etc.).
    pub(crate) unsafe_with_parser_calls: Vec<Span>,

    /// Spans of `unsafe fn` items inside an `extern "…"` block that have no
    /// `SAFETY:` comment on the preceding line(s).
    pub(crate) extern_unsafe_fns_no_doc: Vec<Span>,

    /// Spans of `.clone()` calls that appear inside an iterator chain (a `syn`
    /// `Block` that also contains `.iter()`, `.into_iter()`, or `.iter_mut()`).
    ///
    /// **Heuristic:** populated by [`Extractor`] when a `Block` contains both
    /// an iter-start method call and a `.clone()` method call.  False-positives
    /// are acceptable for this performance hint.
    pub(crate) clone_in_iter_chains: Vec<Span>,

    /// Spans of empty blocks reached from `if`/`for`/`while` expressions.
    ///
    /// Populated by [`Extractor`] when a `syn::Block` that is the body of an
    /// `ExprIf`, `ExprForLoop`, or `ExprWhile` has zero statements.
    ///
    /// Empty `ExprLoop` is intentionally excluded (tracked by MAINT010).
    /// Empty function bodies are intentionally excluded (often intentional stubs).
    pub(crate) empty_blocks: Vec<Span>,

    /// Active debug-code macro invocations.
    ///
    /// Populated by [`Extractor`] for `MAINT011-active-debug-code`.
    /// Contains `(span, kind)` for each flagged macro call site:
    /// - `dbg!(…)` → [`RustDebugKind::Dbg`] (always flagged)
    /// - `println!(…)` → [`RustDebugKind::Println`] (only when `flag_println` enabled)
    /// - `eprintln!(…)` → [`RustDebugKind::Eprintln`] (only when `flag_println` enabled)
    pub(crate) debug_calls: Vec<(Span, RustDebugKind)>,

    /// Server-bind call sites for `SEC013-bind-all-interfaces`.
    ///
    /// Populated by [`Extractor`] for function-call expressions whose path last
    /// segment is in the bind allowlist (e.g. `TcpListener::bind`,
    /// `HttpServer::bind`, `Server::bind`, etc.).
    pub(crate) bind_call_sites: Vec<RustCallSite>,

    /// Assignment sites for `SEC012-hardcoded-security-constant`.
    ///
    /// Populated by [`Extractor`] for `let name = <literal>` bindings,
    /// `name = <literal>` assignments, and `const`/`static` declarations
    /// whose identifier name substring-matches a security keyword.
    pub(crate) assignments: Vec<RustAssignmentSite>,

    /// Log call sites for `SEC015-log-injection`.
    ///
    /// Populated by [`Extractor`] for macro invocations named `trace`, `debug`,
    /// `info`, `warn`, `error`, `log` (with/without `log::`/`tracing::` prefix).
    /// Macro bodies are parsed via regex over the token-string.
    pub(crate) log_calls: Vec<RustLogCallSite>,

    /// Spans of `pub struct` declarations that contain a raw pointer field
    /// (`*mut T` or `*const T`) without an accompanying `unsafe impl Send`
    /// declaration in the same file.
    ///
    /// Used by `ECO003-send-sync-violations-on-pub-types`.
    pub(crate) pub_struct_with_raw_ptr: Vec<Span>,

    /// Match expression sites for `MAINT009-missing-default-case`.
    ///
    /// Populated by [`Extractor`] for every `match` expression.  The analyzer
    /// fires when `!has_wildcard && scrutinee_kind != Other`.
    pub(crate) match_sites: Vec<RustMatchSite>,

    /// Spans of `loop {}` expressions with no reachable exit for
    /// `MAINT010-infinite-loop-no-exit`.
    ///
    /// Populated by [`Extractor`] for every `syn::ExprLoop` whose body,
    /// after excluding nested loops and closures, contains no `break`,
    /// `return`, or diverging macro (`panic!`, `unreachable!`, `todo!`,
    /// `unimplemented!`).
    pub(crate) infinite_loops: Vec<Span>,

    /// Dead `let` binding sites for `MAINT012-dead-store`.
    ///
    /// Populated by [`Extractor`] for each function body.  A binding is dead
    /// when the bound name (without leading `_`) does not appear in the
    /// stringified tail of the enclosing function block after the `let` site.
    ///
    /// Only simple immutable `let name = expr;` patterns are considered (no
    /// `let mut`, no destructuring, no shadowing chains).  See the dead-store
    /// analyzer for the full exclusion list.
    pub(crate) dead_stores: Vec<RustDeadStore>,

    /// `true` if the file contains any non-empty macro body (`Expr::Macro`
    /// with a non-empty token stream).
    ///
    /// Used by the Rust dead-store analyzer to early-return on files with
    /// macros, since macro bodies are opaque and may silently consume variable
    /// names without any syntactic `Identifier` reference.
    pub(crate) has_macro_body: bool,

    /// Spans of `pub static mut NAME: T = …;` declarations for
    /// `MAINT018-global-var-density`.
    ///
    /// Populated by [`Extractor`] inside `visit_item_static`.  Only items that
    /// are both `pub` (or `pub(restricted)`) **and** `mut` are included.
    /// Private `static mut` and immutable `pub static` are excluded.
    pub(crate) pub_static_muts: Vec<Span>,

    /// Spans of the **first dead statement** in each block that contains
    /// unreachable code, for `MAINT016-unreachable-code`.
    ///
    /// Populated by [`Extractor`] inside `visit_block`.  For each
    /// [`syn::Block`] we scan its `Stmt` list for the first terminating
    /// statement (`return`, `break`, `continue`, or a diverging macro such as
    /// `panic!`, `unreachable!`, `todo!`, `unimplemented!`).  If at least one
    /// non-`Pass`-equivalent statement follows, we record the byte span of
    /// that first dead statement.  One entry per block — never one per dead
    /// statement.
    pub(crate) unreachable_stmts: Vec<Span>,

    /// Spans of item declarations marked `#[deprecated]` for
    /// `MAINT015-deprecated-function`.
    ///
    /// Populated by [`Extractor`] inside the item-level visit methods
    /// (`visit_item_fn`, `visit_impl_item_fn`, `visit_trait_item_fn`,
    /// `visit_item_struct`, `visit_item_enum`, `visit_item_const`,
    /// `visit_item_static`, `visit_item_type`).  Each entry pairs a kind
    /// label (`"fn"`, `"struct"`, …) with the span of the item's defining
    /// keyword.
    pub(crate) deprecated_items: Vec<RustDeprecatedItem>,

    /// Call sites to inherently dangerous libc-family functions, for
    /// `SEC016-dangerous-function`. Recognised names (matched on the
    /// **last path segment** only): `gets`, `gets_s`, `strcpy`, `strcat`,
    /// `sprintf`, `vsprintf`, `scanf`, `wcscpy`, `wcscat`. Captures both
    /// `libc::gets(...)`, `::libc::gets(...)`, and bare `gets(...)`.
    pub(crate) dangerous_calls: Vec<RustDangerousCall>,

    /// Spans of heap-allocating expressions that appear inside loop bodies
    /// (`for`, `while`, or `loop`), for `PERF010-allocation-in-loop`.
    ///
    /// Populated by [`Extractor`] while `in_loop_depth > 0`.  Allocation
    /// sites detected:
    /// - `Vec::new()` / `Vec::with_capacity(…)` / `vec![]` macros
    /// - `String::new()` / `String::with_capacity(…)` / `String::from(…)`
    ///   / `.to_string()` / `.to_owned()` / `format!(…)` macro
    /// - `Box::new(…)`
    /// - `HashMap::new()` / `HashMap::with_capacity(…)` / `BTreeMap::new()`
    /// - `HashSet::new()` / `BTreeSet::new()`
    ///
    /// Closures defined inside loops are recursed into (they run once per
    /// outer iteration).  Nested `fn` item bodies are **not** recursed into
    /// (they only run when called, not inline).
    pub(crate) allocs_in_loop: Vec<Span>,
}

/// A dead-store site extracted for `MAINT012-dead-store` (Rust).
#[derive(Debug, Clone)]
pub(crate) struct RustDeadStore {
    /// The variable name that is written but never read.
    pub(crate) name: String,
    /// Byte span of the `let` binding.
    pub(crate) span: Span,
}

/// An item marked `#[deprecated]` for `MAINT015-deprecated-function` (Rust).
#[derive(Debug, Clone)]
pub(crate) struct RustDeprecatedItem {
    /// The item identifier (e.g. `"old_fn"`).
    pub(crate) name: String,
    /// Short kind label: `"fn"`, `"struct"`, `"enum"`, `"const"`, `"static"`,
    /// `"type"`, `"method"`, `"trait method"`.
    pub(crate) kind: &'static str,
    /// Byte span anchored at the item's defining keyword.
    pub(crate) span: Span,
}

/// A call site to a libc-family inherently dangerous function, extracted for
/// `SEC016-dangerous-function` (CWE-242).  Matched by the **last path segment**
/// only so both `libc::gets(...)` and `::libc::gets(...)` and bare `gets(...)`
/// flag the same way.
#[derive(Debug, Clone)]
pub(crate) struct RustDangerousCall {
    /// The function name (e.g. `"gets"`, `"strcpy"`).
    pub(crate) name: &'static str,
    /// Byte span of the callee path.
    pub(crate) span: Span,
}

// RustAst contains only Vec<UnsafeItem> where UnsafeItem holds Span (&'static str
// and two u32 values). No Rc, no raw pointers — these are Send + Sync by the
// standard library rules. The compiler derives these automatically; no unsafe
// impl is needed.
impl NativeAst for RustAst {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ── span → line number helper ─────────────────────────────────────────────────

/// Return the 1-indexed line number for a `proc_macro2::Span`.
fn span_line(raw: proc_macro2::Span) -> usize {
    raw.start().line
}

/// Return the raw text of line `line_no` (1-indexed) from `source`, or `""` if
/// out of range.
fn source_line(source: &SourceFile, line_no: usize) -> &str {
    if line_no == 0 {
        return "";
    }
    let text = source.as_str();
    let mut cur = 1usize;
    let mut start = 0usize;
    for (i, ch) in text.char_indices() {
        if cur == line_no {
            // scan forward to end of this line
            let end = text[i..].find('\n').map_or(text.len(), |n| i + n);
            return &text[start..end];
        }
        if ch == '\n' {
            cur += 1;
            start = i + 1;
        }
    }
    // last line (no trailing newline)
    if cur == line_no { &text[start..] } else { "" }
}

/// Returns `true` if `line` contains `// SAFETY:` or `/// SAFETY:` (case-
/// insensitive on the `safety` keyword).
fn has_safety_comment(line: &str) -> bool {
    let trimmed = line.trim();
    // Match `// SAFETY:` or `/// SAFETY:` (case-insensitive suffix)
    if let Some(rest) = trimmed
        .strip_prefix("//")
        .map(|r| r.trim_start_matches('/').trim_start())
    {
        return rest.to_ascii_lowercase().starts_with("safety:");
    }
    false
}

/// Bind-callee allowlist for `SEC013-bind-all-interfaces` (Rust).
///
/// These are the last segment names matched against the callee path.
const RUST_BIND_CALLEE_NAMES: &[&str] = &[
    "bind",
    "bind_addr",
    "new", // Hyper Server::new takes the address
];

/// Inherently dangerous libc-family function names for
/// `SEC016-dangerous-function` (CWE-242). Matched against the **last** path
/// segment, so both `libc::gets(...)` and bare `gets(...)` are detected.
///
/// These functions are unsafe by construction (unbounded copies, format-string
/// reads, no length checks); CWE-242 advises replacing all uses.
const RUST_DANGEROUS_CALLEE_NAMES: &[&str] = &[
    "gets", "gets_s", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "wcscpy", "wcscat",
];

/// Returns `true` when `raw` is a bind-all-interfaces address:
/// - `"0.0.0.0"` or `"0.0.0.0:PORT"` (IPv4 any-address)
/// - `"::"` or `"[::]:PORT"` or `":::PORT"` (IPv6 any-address)
pub(crate) fn is_bind_all_address_rust(raw: &str) -> bool {
    let host = if let Some(stripped) = raw.strip_prefix('[') {
        stripped.split(']').next().unwrap_or(raw)
    } else if raw == "::" || raw.starts_with(":::") {
        "::"
    } else {
        raw.split(':').next().unwrap_or(raw)
    };
    host == "0.0.0.0" || host == "::"
}

/// Known parser/decoder function name fragments that trigger SOUND005.
const PARSER_NAMES: &[&str] = &[
    "from_bytes",
    "from_raw",
    "parse_unchecked",
    "from_utf8_unchecked",
    "from_raw_parts",
    "from_raw_parts_mut",
    "from_utf8_unchecked",
    "from_ptr",
];

/// Returns `true` if any segment of the call path matches a known parser name.
fn is_parser_call(path: &syn::Path) -> bool {
    path.segments.iter().any(|seg| {
        let name = seg.ident.to_string();
        PARSER_NAMES.iter().any(|&p| name == p)
    })
}

/// Extracts a [`RustLiteralValue`] from a `syn::Expr` if it is a plain literal.
///
/// Returns `None` for non-literal expressions (identifiers, calls, etc.).
fn expr_to_rust_literal(expr: &syn::Expr) -> Option<RustLiteralValue> {
    // Unwrap reference and group expressions.
    let inner = match expr {
        syn::Expr::Group(g) => &g.expr,
        syn::Expr::Reference(r) => &r.expr,
        other => other,
    };
    if let syn::Expr::Lit(el) = inner {
        return match &el.lit {
            syn::Lit::Str(s) => Some(RustLiteralValue::Str(s.value())),
            syn::Lit::ByteStr(b) => Some(RustLiteralValue::Bytes(b.value())),
            syn::Lit::Int(i) => {
                let v = i.base10_parse::<i64>().unwrap_or(0);
                Some(RustLiteralValue::Int(v))
            }
            syn::Lit::Bool(_) | syn::Lit::Float(_) | syn::Lit::Char(_) | syn::Lit::Byte(_) => {
                Some(RustLiteralValue::Other)
            }
            _ => Some(RustLiteralValue::Other),
        };
    }
    None
}

/// Extracts the identifier name from a `let` pattern if it is a simple
/// `Pat::Ident` (not a destructure or wildcard).
fn local_pat_ident_name(pat: &syn::Pat) -> Option<String> {
    if let syn::Pat::Ident(pi) = pat {
        return Some(pi.ident.to_string());
    }
    // Also handle `Pat::Type` wrapping a `Pat::Ident` (annotated let).
    if let syn::Pat::Type(pt) = pat
        && let syn::Pat::Ident(pi) = &*pt.pat
    {
        return Some(pi.ident.to_string());
    }
    None
}

/// Returns `true` if the last path segment is `transmute`.
fn is_transmute_path(path: &syn::Path) -> bool {
    path.segments
        .last()
        .is_some_and(|seg| seg.ident == "transmute")
}

// ── Log-macro body parser (regex-style) for SEC015 ───────────────────────────

/// Log macro names for `SEC015-log-injection` detection.
const LOG_MACRO_NAMES_SEC015: &[&str] = &["trace", "debug", "info", "warn", "error", "log"];

/// Parses a log macro body token string (e.g. `"user: {}" , req`) into:
/// - The first string literal (content between `"…"`)
/// - Subsequent identifier tokens (comma-separated after the first arg)
///
/// This is a best-effort regex parse, not a full AST parse. Results are
/// approximate for complex expressions.
fn parse_log_macro_body(body: &str) -> (Option<String>, Vec<String>) {
    let body = body.trim();

    // Extract the first double-quoted string literal (handles escaped quotes).
    let first_arg_string = extract_first_string_literal(body);

    // Extract subsequent comma-separated leading identifiers.
    // Strategy: find the end of the first argument, then split remaining by `,`
    // and take the first identifier token of each part.
    let arg_idents = extract_arg_idents_after_first(body);

    (first_arg_string, arg_idents)
}

/// Extracts the content of the first `"..."` string literal in `body`.
fn extract_first_string_literal(body: &str) -> Option<String> {
    let start = body.find('"')?;
    let rest = &body[start + 1..];
    let mut result = String::new();
    let mut chars = rest.chars().peekable();
    loop {
        match chars.next()? {
            '\\' => {
                // Skip next char (escape sequence)
                chars.next();
            }
            '"' => return Some(result),
            c => result.push(c),
        }
    }
}

/// Extracts leading identifier names from arguments after the first argument
/// in a macro body string.
///
/// Splits by top-level commas (respecting brace/paren depth), skips the first
/// segment (the format string), and returns the first identifier token of each
/// remaining segment.
fn extract_arg_idents_after_first(body: &str) -> Vec<String> {
    let segments = split_top_level_commas(body);
    let mut idents = Vec::new();
    // Skip the first segment (format string / target)
    for seg in segments.into_iter().skip(1) {
        let seg = seg.trim();
        if let Some(ident) = first_ident_in(seg) {
            idents.push(ident);
        }
    }
    idents
}

/// Splits `s` by commas that are not inside `{…}`, `(…)`, or `[…]`.
fn split_top_level_commas(s: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    for ch in s.chars() {
        match ch {
            '(' | '{' | '[' => {
                depth += 1;
                current.push(ch);
            }
            ')' | '}' | ']' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                result.push(current.clone());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        result.push(current);
    }
    result
}

/// Extracts the first Rust identifier from a string slice.
fn first_ident_in(s: &str) -> Option<String> {
    // Skip leading whitespace and method-call/field-access chains to get the
    // root identifier.
    let s = s.trim();
    // If it starts with a non-identifier char, skip it
    let start = s.find(|c: char| c.is_ascii_alphabetic() || c == '_')?;
    let rest = &s[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(rest.len());
    let ident = &rest[..end];
    if ident.is_empty() {
        None
    } else {
        Some(ident.to_string())
    }
}

/// Extracts function parameter names from a `syn::Signature`.
fn collect_sig_params(sig: &syn::Signature) -> Vec<String> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(pt) => {
                if let syn::Pat::Ident(pi) = &*pt.pat {
                    Some(pi.ident.to_string())
                } else {
                    None
                }
            }
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}

// ── syn visitor for pre-extraction ───────────────────────────────────────────

use syn::spanned::Spanned;
use syn::visit::Visit;

struct Extractor<'src> {
    items: Vec<UnsafeItem>,
    unsafe_blocks_without_safety: Vec<Span>,
    pub_unsafe_fns: Vec<Span>,
    transmute_calls: Vec<Span>,
    raw_ptr_pub_apis: Vec<Span>,
    unsafe_with_parser_calls: Vec<Span>,
    extern_unsafe_fns_no_doc: Vec<Span>,
    clone_in_iter_chains: Vec<Span>,
    empty_blocks: Vec<Span>,
    debug_calls: Vec<(Span, RustDebugKind)>,
    bind_call_sites: Vec<RustCallSite>,
    assignments: Vec<RustAssignmentSite>,
    /// Log call sites for `SEC015-log-injection`.
    log_calls: Vec<RustLogCallSite>,
    /// Match expression sites for `MAINT009-missing-default-case`.
    match_sites: Vec<RustMatchSite>,

    /// Spans of infinite `loop {}` bodies for `MAINT010-infinite-loop-no-exit`.
    infinite_loops: Vec<Span>,

    /// Dead let-binding sites for `MAINT012-dead-store`.
    dead_stores: Vec<RustDeadStore>,

    /// Whether any non-empty macro body was encountered.
    has_macro_body: bool,

    /// Spans of `pub static mut` declarations for `MAINT018-global-var-density`.
    pub_static_muts: Vec<Span>,

    /// First-dead-statement spans for `MAINT016-unreachable-code`.
    unreachable_stmts: Vec<Span>,

    /// Heap-allocating expression spans inside loop bodies for `PERF010`.
    allocs_in_loop: Vec<Span>,

    /// Current loop nesting depth for `PERF010`.
    in_loop_depth: u32,

    /// Items marked `#[deprecated]` for `MAINT015-deprecated-function`.
    deprecated_items: Vec<RustDeprecatedItem>,

    /// Inherently dangerous libc-family call sites for `SEC016`.
    dangerous_calls: Vec<RustDangerousCall>,

    source: &'src SourceFile,
    /// `true` while inside an `extern "…"` block.
    in_foreign_mod: bool,
    /// Collect `pub struct` spans that have raw pointer fields.
    /// After file visit we check for `unsafe impl Send` to filter out false positives.
    pending_pub_struct_raw_ptr: Vec<Span>,
    /// Whether we've seen any `unsafe impl Send` in the file.
    has_unsafe_impl_send: bool,
    /// Stack of enclosing function parameter lists, for SEC015.
    current_fn_params: Vec<Vec<String>>,
}

impl<'src> Extractor<'src> {
    fn new(source: &'src SourceFile) -> Self {
        Self {
            items: Vec::new(),
            unsafe_blocks_without_safety: Vec::new(),
            pub_unsafe_fns: Vec::new(),
            transmute_calls: Vec::new(),
            raw_ptr_pub_apis: Vec::new(),
            unsafe_with_parser_calls: Vec::new(),
            extern_unsafe_fns_no_doc: Vec::new(),
            clone_in_iter_chains: Vec::new(),
            empty_blocks: Vec::new(),
            debug_calls: Vec::new(),
            bind_call_sites: Vec::new(),
            assignments: Vec::new(),
            log_calls: Vec::new(),
            match_sites: Vec::new(),
            infinite_loops: Vec::new(),
            dead_stores: Vec::new(),
            has_macro_body: false,
            pub_static_muts: Vec::new(),
            unreachable_stmts: Vec::new(),
            allocs_in_loop: Vec::new(),
            in_loop_depth: 0,
            deprecated_items: Vec::new(),
            dangerous_calls: Vec::new(),
            source,
            in_foreign_mod: false,
            pending_pub_struct_raw_ptr: Vec::new(),
            has_unsafe_impl_send: false,
            current_fn_params: Vec::new(),
        }
    }

    fn push_unsafe_item(&mut self, raw: proc_macro2::Span, label: &'static str) {
        let span = proc_span_to_byte_span(raw, self.source);
        self.items.push(UnsafeItem { span, label });
    }

    /// Returns `true` if `attrs` contains a `#[deprecated]` attribute,
    /// including the `#[deprecated(...)]` parameterised forms.
    fn has_deprecated_attr(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|attr| attr.path().is_ident("deprecated"))
    }

    fn record_deprecated(&mut self, raw: proc_macro2::Span, name: String, kind: &'static str) {
        let span = proc_span_to_byte_span(raw, self.source);
        self.deprecated_items
            .push(RustDeprecatedItem { name, kind, span });
    }

    fn is_pub(vis: &syn::Visibility) -> bool {
        matches!(
            vis,
            syn::Visibility::Public(_) | syn::Visibility::Restricted(_)
        )
    }

    /// Returns `true` if the struct's fields contain a raw pointer type.
    fn struct_has_raw_ptr_field(fields: &syn::Fields) -> bool {
        fn type_has_ptr(ty: &syn::Type) -> bool {
            match ty {
                syn::Type::Ptr(_) => true,
                syn::Type::Reference(r) => type_has_ptr(&r.elem),
                syn::Type::Slice(s) => type_has_ptr(&s.elem),
                syn::Type::Array(a) => type_has_ptr(&a.elem),
                syn::Type::Tuple(t) => t.elems.iter().any(type_has_ptr),
                _ => false,
            }
        }
        match fields {
            syn::Fields::Named(named) => named.named.iter().any(|f| type_has_ptr(&f.ty)),
            syn::Fields::Unnamed(unnamed) => unnamed.unnamed.iter().any(|f| type_has_ptr(&f.ty)),
            syn::Fields::Unit => false,
        }
    }

    fn sig_has_raw_ptr(sig: &syn::Signature) -> bool {
        fn type_has_ptr(ty: &syn::Type) -> bool {
            match ty {
                syn::Type::Ptr(_) => true,
                syn::Type::Reference(r) => type_has_ptr(&r.elem),
                syn::Type::Slice(s) => type_has_ptr(&s.elem),
                syn::Type::Array(a) => type_has_ptr(&a.elem),
                syn::Type::Tuple(t) => t.elems.iter().any(type_has_ptr),
                _ => false,
            }
        }
        let inputs_have_ptr = sig.inputs.iter().any(|arg| match arg {
            syn::FnArg::Typed(pt) => type_has_ptr(&pt.ty),
            syn::FnArg::Receiver(_) => false,
        });
        let output_has_ptr = match &sig.output {
            syn::ReturnType::Default => false,
            syn::ReturnType::Type(_, ty) => type_has_ptr(ty),
        };
        inputs_have_ptr || output_has_ptr
    }
}

// ── Body-level sub-visitor (for SOUND005) ────────────────────────────────────

/// Scans a function body for unsafe blocks and parser calls.
struct BodyScanner {
    has_unsafe_block: bool,
    has_parser_call: bool,
}

impl BodyScanner {
    fn new() -> Self {
        Self {
            has_unsafe_block: false,
            has_parser_call: false,
        }
    }
}

impl<'ast> Visit<'ast> for BodyScanner {
    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        self.has_unsafe_block = true;
        syn::visit::visit_expr_unsafe(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(ep) = &*node.func
            && is_parser_call(&ep.path)
        {
            self.has_parser_call = true;
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let name = node.method.to_string();
        if PARSER_NAMES.iter().any(|&p| name == p) {
            self.has_parser_call = true;
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

// ── Block scanner for PERF002 ────────────────────────────────────────────────

/// Scans a [`syn::Block`] and collects spans for iter-start method calls and
/// `.clone()` method calls.  Used by the PERF002 heuristic.
fn collect_method_calls_in_block(
    block: &syn::Block,
    iter_spans: &mut Vec<proc_macro2::Span>,
    clone_spans: &mut Vec<proc_macro2::Span>,
) {
    struct BlockMethodCollector<'a> {
        iter_spans: &'a mut Vec<proc_macro2::Span>,
        clone_spans: &'a mut Vec<proc_macro2::Span>,
    }

    impl<'ast> Visit<'ast> for BlockMethodCollector<'_> {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            let name = node.method.to_string();
            match name.as_str() {
                "iter" | "into_iter" | "iter_mut" => {
                    self.iter_spans.push(node.method.span());
                }
                "clone" => {
                    self.clone_spans.push(node.method.span());
                }
                _ => {}
            }
            syn::visit::visit_expr_method_call(self, node);
        }
    }

    let mut collector = BlockMethodCollector {
        iter_spans,
        clone_spans,
    };
    collector.visit_block(block);
}

// ── Unreachable-code helper for MAINT016 ─────────────────────────────────────

/// Macro names that unconditionally diverge / terminate execution.
const TERMINATING_MACROS_MAINT016: &[&str] = &["panic", "unreachable", "todo", "unimplemented"];

/// Returns `true` if `stmt` is a terminating statement for MAINT016.
///
/// Terminating statements are: `return`, `break`, `continue`, and invocations
/// of the four diverging macros (`panic!`, `unreachable!`, `todo!`,
/// `unimplemented!`).
fn is_terminating_stmt(stmt: &syn::Stmt) -> bool {
    match stmt {
        syn::Stmt::Expr(syn::Expr::Return(_) | syn::Expr::Break(_) | syn::Expr::Continue(_), _) => {
            true
        }
        syn::Stmt::Macro(m) => {
            let name = m
                .mac
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            TERMINATING_MACROS_MAINT016.contains(&name.as_str())
        }
        // Also handle bare macro expressions (not Stmt::Macro but Expr::Macro wrapped in Stmt::Expr).
        syn::Stmt::Expr(syn::Expr::Macro(em), _) => {
            let name = em
                .mac
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            TERMINATING_MACROS_MAINT016.contains(&name.as_str())
        }
        _ => false,
    }
}

/// Scans a block's statement list for the first terminating statement and
/// returns the byte span of the first following (dead) statement.
///
/// Returns `None` when the block has no terminating statement or when there
/// is no statement after the terminator.
fn first_dead_stmt_span(stmts: &[syn::Stmt], source: &SourceFile) -> Option<Span> {
    let term_idx = stmts.iter().position(is_terminating_stmt)?;
    // There must be at least one more statement after the terminator.
    let dead_stmt = stmts.get(term_idx + 1)?;
    let raw_span = stmt_proc_span(dead_stmt);
    Some(proc_span_to_byte_span(raw_span, source))
}

/// Returns the `proc_macro2::Span` for a `syn::Stmt`.
fn stmt_proc_span(stmt: &syn::Stmt) -> proc_macro2::Span {
    use syn::spanned::Spanned;
    match stmt {
        syn::Stmt::Local(l) => l.let_token.span,
        syn::Stmt::Item(i) => i.span(),
        syn::Stmt::Expr(e, _) => e.span(),
        syn::Stmt::Macro(m) => m.mac.path.span(),
    }
}

// ── PERF010 allocation-site detection ────────────────────────────────────────

/// Returns `true` if the call path matches a known heap-allocating constructor
/// that PERF010 tracks.
///
/// Matched patterns (by last-two-segment suffix where relevant):
/// - `Vec::new` / `Vec::with_capacity`
/// - `String::new` / `String::with_capacity` / `String::from`
/// - `Box::new`
/// - `HashMap::new` / `HashMap::with_capacity`
/// - `BTreeMap::new`
/// - `HashSet::new`
/// - `BTreeSet::new`
fn is_allocating_call_path(path: &syn::Path) -> bool {
    let segments: Vec<_> = path.segments.iter().collect();
    let n = segments.len();
    if n == 0 {
        return false;
    }
    let last = segments[n - 1].ident.to_string();
    // Single-segment shortcuts that are unambiguous.
    match last.as_str() {
        "new" | "with_capacity" => {
            // Needs a type qualifier to be interesting.
            if n < 2 {
                return false;
            }
            let ty = segments[n - 2].ident.to_string();
            matches!(
                ty.as_str(),
                "Vec" | "String" | "Box" | "HashMap" | "BTreeMap" | "HashSet" | "BTreeSet"
            )
        }
        "from" => {
            // `String::from(…)` — qualify by type segment.
            if n < 2 {
                return false;
            }
            let ty = segments[n - 2].ident.to_string();
            ty == "String"
        }
        _ => false,
    }
}

// ── Main visitor ─────────────────────────────────────────────────────────────

impl<'ast> Visit<'ast> for Extractor<'_> {
    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        self.push_unsafe_item(node.unsafe_token.span, "block");

        // SOUND001: check for // SAFETY: comment above the block
        let line = span_line(node.unsafe_token.span);
        let same_line = source_line(self.source, line);
        let prev_line = if line > 1 {
            source_line(self.source, line - 1)
        } else {
            ""
        };
        if !has_safety_comment(same_line) && !has_safety_comment(prev_line) {
            let span = proc_span_to_byte_span(node.unsafe_token.span, self.source);
            self.unsafe_blocks_without_safety.push(span);
        }

        syn::visit::visit_expr_unsafe(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        // MAINT015: function marked #[deprecated]?
        if Self::has_deprecated_attr(&node.attrs) {
            let name = node.sig.ident.to_string();
            self.record_deprecated(node.sig.fn_token.span, name, "fn");
        }

        if node.sig.unsafety.is_some() {
            self.push_unsafe_item(node.sig.fn_token.span, "fn");
        }

        // SOUND002: pub unsafe fn
        if node.sig.unsafety.is_some() && Self::is_pub(&node.vis) {
            let span = proc_span_to_byte_span(node.sig.fn_token.span, self.source);
            self.pub_unsafe_fns.push(span);
        }

        // SOUND004: pub fn with raw pointer in signature
        if Self::is_pub(&node.vis) && Self::sig_has_raw_ptr(&node.sig) {
            let span = proc_span_to_byte_span(node.sig.fn_token.span, self.source);
            self.raw_ptr_pub_apis.push(span);
        }

        // SOUND005: fn body with unsafe block AND parser call
        let mut scanner = BodyScanner::new();
        scanner.visit_block(&node.block);
        if scanner.has_unsafe_block && scanner.has_parser_call {
            let span = proc_span_to_byte_span(node.sig.fn_token.span, self.source);
            self.unsafe_with_parser_calls.push(span);
        }

        // MAINT012: scan for dead let bindings in this function body.
        let dead = scan_dead_stores_in_block(&node.block, self.source);
        self.dead_stores.extend(dead);

        // SEC015: push this function's parameter names for log-injection detection.
        let params = collect_sig_params(&node.sig);
        self.current_fn_params.push(params);
        syn::visit::visit_item_fn(self, node);
        self.current_fn_params.pop();
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if node.unsafety.is_some() {
            self.push_unsafe_item(node.impl_token.span, "impl");

            // ECO003: track `unsafe impl Send for X` declarations.
            if let Some((_, trait_path, _)) = &node.trait_ {
                let last = trait_path.segments.last().map(|s| s.ident.to_string());
                if last.as_deref() == Some("Send") {
                    self.has_unsafe_impl_send = true;
                }
            }
        }
        syn::visit::visit_item_impl(self, node);
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        if node.unsafety.is_some() {
            self.push_unsafe_item(node.trait_token.span, "trait");
        }
        syn::visit::visit_item_trait(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        // MAINT015: impl method marked #[deprecated]?
        if Self::has_deprecated_attr(&node.attrs) {
            let name = node.sig.ident.to_string();
            self.record_deprecated(node.sig.fn_token.span, name, "method");
        }

        if node.sig.unsafety.is_some() {
            self.push_unsafe_item(node.sig.fn_token.span, "fn");
        }

        // SOUND002: pub unsafe fn inside impl
        if node.sig.unsafety.is_some() && Self::is_pub(&node.vis) {
            let span = proc_span_to_byte_span(node.sig.fn_token.span, self.source);
            self.pub_unsafe_fns.push(span);
        }

        // SOUND004: pub fn with raw pointer inside impl
        if Self::is_pub(&node.vis) && Self::sig_has_raw_ptr(&node.sig) {
            let span = proc_span_to_byte_span(node.sig.fn_token.span, self.source);
            self.raw_ptr_pub_apis.push(span);
        }

        // SOUND005 inside impl methods
        let mut scanner = BodyScanner::new();
        scanner.visit_block(&node.block);
        if scanner.has_unsafe_block && scanner.has_parser_call {
            let span = proc_span_to_byte_span(node.sig.fn_token.span, self.source);
            self.unsafe_with_parser_calls.push(span);
        }

        // MAINT012: scan for dead let bindings in this impl method body.
        let dead = scan_dead_stores_in_block(&node.block, self.source);
        self.dead_stores.extend(dead);

        // SEC015: push this function's parameter names for log-injection detection.
        let params = collect_sig_params(&node.sig);
        self.current_fn_params.push(params);
        syn::visit::visit_impl_item_fn(self, node);
        self.current_fn_params.pop();
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        // MAINT015: trait method marked #[deprecated]?
        if Self::has_deprecated_attr(&node.attrs) {
            let name = node.sig.ident.to_string();
            self.record_deprecated(node.sig.fn_token.span, name, "trait method");
        }

        if node.sig.unsafety.is_some() {
            self.push_unsafe_item(node.sig.fn_token.span, "fn");
        }

        // MAINT012: scan for dead let bindings in trait method default bodies.
        if let Some(body) = &node.default {
            let dead = scan_dead_stores_in_block(body, self.source);
            self.dead_stores.extend(dead);
        }

        // SEC015: push this function's parameter names for log-injection detection.
        let params = collect_sig_params(&node.sig);
        self.current_fn_params.push(params);
        syn::visit::visit_trait_item_fn(self, node);
        self.current_fn_params.pop();
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast syn::ItemForeignMod) {
        let prev = self.in_foreign_mod;
        self.in_foreign_mod = true;
        syn::visit::visit_item_foreign_mod(self, node);
        self.in_foreign_mod = prev;
    }

    fn visit_foreign_item_fn(&mut self, node: &'ast syn::ForeignItemFn) {
        if self.in_foreign_mod && node.sig.unsafety.is_some() {
            // SOUND006: unsafe fn in extern block without SAFETY comment
            let line = span_line(node.sig.fn_token.span);
            let same_line = source_line(self.source, line);
            let prev_line = if line > 1 {
                source_line(self.source, line - 1)
            } else {
                ""
            };
            if !has_safety_comment(same_line) && !has_safety_comment(prev_line) {
                let span = proc_span_to_byte_span(node.sig.fn_token.span, self.source);
                self.extern_unsafe_fns_no_doc.push(span);
            }
        }
        syn::visit::visit_foreign_item_fn(self, node);
    }

    fn visit_block(&mut self, node: &'ast syn::Block) {
        // PERF002: detect clone-in-iter-chain heuristic.
        // Within a single Block, collect all method-call names; if both an
        // iter-start name and "clone" appear, flag the clone sites.
        let mut iter_spans: Vec<proc_macro2::Span> = Vec::new();
        let mut clone_spans: Vec<proc_macro2::Span> = Vec::new();
        collect_method_calls_in_block(node, &mut iter_spans, &mut clone_spans);
        if !iter_spans.is_empty() && !clone_spans.is_empty() {
            for raw in clone_spans {
                let span = proc_span_to_byte_span(raw, self.source);
                self.clone_in_iter_chains.push(span);
            }
        }

        // MAINT016: find the first terminating statement in this block and
        // record the byte span of the next statement (the first dead one).
        if let Some(dead_span) = first_dead_stmt_span(&node.stmts, self.source) {
            self.unreachable_stmts.push(dead_span);
        }

        syn::visit::visit_block(self, node);
    }

    // MAINT013: empty blocks in if/for/while expressions.
    // ExprLoop is intentionally excluded (MAINT010 handles it).
    // Function bodies are excluded (often intentional stubs).

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if node.then_branch.stmts.is_empty() {
            let span = proc_span_to_byte_span(node.if_token.span, self.source);
            self.empty_blocks.push(span);
        }
        syn::visit::visit_expr_if(self, node);
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        if node.body.stmts.is_empty() {
            let span = proc_span_to_byte_span(node.for_token.span, self.source);
            self.empty_blocks.push(span);
        }
        // PERF010: increment loop depth while visiting the body.
        self.in_loop_depth += 1;
        syn::visit::visit_expr_for_loop(self, node);
        self.in_loop_depth -= 1;
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        if node.body.stmts.is_empty() {
            let span = proc_span_to_byte_span(node.while_token.span, self.source);
            self.empty_blocks.push(span);
        }
        // PERF010: increment loop depth while visiting the body.
        self.in_loop_depth += 1;
        syn::visit::visit_expr_while(self, node);
        self.in_loop_depth -= 1;
    }

    // MAINT011: detect debug-code macros (dbg!, println!, eprintln!).
    // SEC015: detect log-injection in logging macros.
    // MAINT012: track whether any non-empty macro body appears (for dead-store suppression).
    // PERF010: detect allocating macros (vec!, format!) inside loop bodies.
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let name = node
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        let kind = match name.as_str() {
            "dbg" => Some(RustDebugKind::Dbg),
            "println" => Some(RustDebugKind::Println),
            "eprintln" => Some(RustDebugKind::Eprintln),
            _ => None,
        };
        if let Some(k) = kind {
            let span = proc_span_to_byte_span(node.path.span(), self.source);
            self.debug_calls.push((span, k));
        }

        // SEC015: detect log/tracing macro invocations.
        if LOG_MACRO_NAMES_SEC015.contains(&name.as_str()) {
            let span = proc_span_to_byte_span(node.path.span(), self.source);
            let body = node.tokens.to_string();
            let enclosing_fn_params = self.current_fn_params.last().cloned().unwrap_or_default();
            let (first_arg_string, arg_idents) = parse_log_macro_body(&body);
            self.log_calls.push(RustLogCallSite {
                callee_name: name.clone(),
                first_arg_string,
                arg_idents,
                enclosing_fn_params,
                span,
            });
        }

        // MAINT012: if this macro invocation has a non-empty token stream,
        // mark the file as having a macro body (opaque to dead-store analysis).
        if !node.tokens.is_empty() {
            self.has_macro_body = true;
        }

        // PERF010: flag allocating macros (`vec!`, `format!`) inside loop bodies.
        if self.in_loop_depth > 0 && matches!(name.as_str(), "vec" | "format") {
            let span = proc_span_to_byte_span(node.path.span(), self.source);
            self.allocs_in_loop.push(span);
        }

        syn::visit::visit_macro(self, node);
    }

    // SEC012: detect hardcoded security constants in `let`, assignment, `const`, `static`.

    fn visit_local(&mut self, node: &'ast syn::Local) {
        // `let name = <literal>` — LocalInit with a simple Ident pattern.
        if let Some(init) = &node.init
            && let Some(lit) = expr_to_rust_literal(&init.expr)
            && let Some(n) = local_pat_ident_name(&node.pat)
        {
            let span = proc_span_to_byte_span(node.let_token.span, self.source);
            self.assignments.push(RustAssignmentSite {
                lhs_name: n.to_lowercase(),
                rhs_literal: lit,
                span,
            });
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        // `name = <literal>` — only bare identifier LHS.
        if let syn::Expr::Path(ep) = &*node.left
            && let Some(seg) = ep.path.segments.last()
            && let Some(lit) = expr_to_rust_literal(&node.right)
        {
            let name = seg.ident.to_string();
            let span = proc_span_to_byte_span(node.left.span(), self.source);
            self.assignments.push(RustAssignmentSite {
                lhs_name: name.to_lowercase(),
                rhs_literal: lit,
                span,
            });
        }
        syn::visit::visit_expr_assign(self, node);
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        // MAINT015: const marked #[deprecated]?
        if Self::has_deprecated_attr(&node.attrs) {
            let n = node.ident.to_string();
            self.record_deprecated(node.const_token.span, n, "const");
        }
        let name = node.ident.to_string();
        if let Some(lit) = expr_to_rust_literal(&node.expr) {
            let span = proc_span_to_byte_span(node.const_token.span, self.source);
            self.assignments.push(RustAssignmentSite {
                lhs_name: name.to_lowercase(),
                rhs_literal: lit,
                span,
            });
        }
        syn::visit::visit_item_const(self, node);
    }

    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        // MAINT015: static marked #[deprecated]?
        if Self::has_deprecated_attr(&node.attrs) {
            let n = node.ident.to_string();
            self.record_deprecated(node.static_token.span, n, "static");
        }

        let name = node.ident.to_string();
        if let Some(lit) = expr_to_rust_literal(&node.expr) {
            let span = proc_span_to_byte_span(node.static_token.span, self.source);
            self.assignments.push(RustAssignmentSite {
                lhs_name: name.to_lowercase(),
                rhs_literal: lit,
                span,
            });
        }

        // MAINT018: track `pub static mut` declarations.
        if Self::is_pub(&node.vis) && matches!(node.mutability, syn::StaticMutability::Mut(_)) {
            let span = proc_span_to_byte_span(node.static_token.span, self.source);
            self.pub_static_muts.push(span);
        }

        syn::visit::visit_item_static(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        // MAINT015: struct marked #[deprecated]?
        if Self::has_deprecated_attr(&node.attrs) {
            let name = node.ident.to_string();
            self.record_deprecated(node.struct_token.span, name, "struct");
        }
        // ECO003: pub struct with raw pointer field.
        if Self::is_pub(&node.vis) && Self::struct_has_raw_ptr_field(&node.fields) {
            let span = proc_span_to_byte_span(node.struct_token.span, self.source);
            self.pending_pub_struct_raw_ptr.push(span);
        }
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        // MAINT015: enum marked #[deprecated]?
        if Self::has_deprecated_attr(&node.attrs) {
            let name = node.ident.to_string();
            self.record_deprecated(node.enum_token.span, name, "enum");
        }
        syn::visit::visit_item_enum(self, node);
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        // MAINT015: type alias marked #[deprecated]?
        if Self::has_deprecated_attr(&node.attrs) {
            let name = node.ident.to_string();
            self.record_deprecated(node.type_token.span, name, "type");
        }
        syn::visit::visit_item_type(self, node);
    }

    // MAINT009: detect `match` expressions without a wildcard arm.
    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        // Classify the scrutinee.
        let scrutinee_kind = match &*node.expr {
            syn::Expr::Lit(_) => RustScrutineeKind::Literal,
            syn::Expr::Path(ep) => {
                // Check the final path segment.
                if let Some(last) = ep.path.segments.last() {
                    let name = last.ident.to_string();
                    if name.starts_with(|c: char| c.is_ascii_lowercase()) {
                        RustScrutineeKind::LowerPath
                    } else {
                        RustScrutineeKind::Other
                    }
                } else {
                    RustScrutineeKind::Other
                }
            }
            _ => RustScrutineeKind::Other,
        };

        // Check if any arm pattern is a wildcard (`_`) or a `|`-pattern
        // containing `_`.
        let has_wildcard = node.arms.iter().any(|arm| pat_has_wildcard(&arm.pat));

        let span = proc_span_to_byte_span(node.match_token.span, self.source);
        self.match_sites.push(RustMatchSite {
            scrutinee_kind,
            has_wildcard,
            span,
        });

        syn::visit::visit_expr_match(self, node);
    }

    // MAINT010: detect `loop {}` with no reachable exit.
    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        let mut scanner = LoopExitScanner::new();
        scanner.visit_block(&node.body);
        if !scanner.has_exit {
            let span = proc_span_to_byte_span(node.loop_token.span, self.source);
            self.infinite_loops.push(span);
        }
        // PERF010: increment loop depth while visiting the body.
        self.in_loop_depth += 1;
        // Always recurse so nested loops are also checked.
        syn::visit::visit_expr_loop(self, node);
        self.in_loop_depth -= 1;
    }

    // PERF010: detect heap-allocating call expressions inside loop bodies.
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        // SOUND003: detect transmute calls
        // (already handled below — we call super after our own checks)

        // PERF010: check for allocating calls while inside a loop.
        if self.in_loop_depth > 0
            && let syn::Expr::Path(ep) = &*node.func
            && is_allocating_call_path(&ep.path)
        {
            let span = proc_span_to_byte_span(node.func.span(), self.source);
            self.allocs_in_loop.push(span);
        }

        // The original SOUND003 + SEC013 logic (previously in visit_expr_call
        // which we now override) — replicated here to preserve existing behaviour.
        if let syn::Expr::Path(ep) = &*node.func
            && is_transmute_path(&ep.path)
        {
            let span = proc_span_to_byte_span(ep.path.span(), self.source);
            self.transmute_calls.push(span);
        }

        // SEC016: detect inherently dangerous libc-family calls.
        if let syn::Expr::Path(ep) = &*node.func {
            let last_seg = ep
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            if let Some(&matched) = RUST_DANGEROUS_CALLEE_NAMES
                .iter()
                .find(|name| **name == last_seg.as_str())
            {
                let span = proc_span_to_byte_span(node.func.span(), self.source);
                self.dangerous_calls.push(RustDangerousCall {
                    name: matched,
                    span,
                });
            }
        }

        // SEC013: detect bind-all-interfaces call sites.
        if let syn::Expr::Path(ep) = &*node.func {
            let last_seg = ep
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            if RUST_BIND_CALLEE_NAMES.contains(&last_seg.as_str()) {
                let first_arg_string_value = node.args.first().and_then(|arg| {
                    if let syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(s),
                        ..
                    }) = arg
                    {
                        Some(s.value())
                    } else {
                        None
                    }
                });
                let span = proc_span_to_byte_span(node.func.span(), self.source);
                self.bind_call_sites.push(RustCallSite {
                    callee_name: last_seg,
                    first_arg_string_value,
                    span,
                });
            }
        }

        syn::visit::visit_expr_call(self, node);
    }

    // PERF010: detect `.to_string()` / `.to_owned()` method calls inside loops.
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if self.in_loop_depth > 0 {
            let method = node.method.to_string();
            if matches!(method.as_str(), "to_string" | "to_owned") {
                let span = proc_span_to_byte_span(node.method.span(), self.source);
                self.allocs_in_loop.push(span);
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    // PERF010: nested fn-item definitions inside loop bodies must NOT be
    // descended into — the fn body only runs when called, not inline.
    // We override visit_item_fn to save/restore the loop depth around it.
    // NOTE: visit_item_fn in syn::visit calls into the fn body; by zeroing the
    // depth before recursing we suppress PERF010 detection inside the fn body.
    // We restore after so outer loop context is maintained.
    //
    // We do this by overriding `visit_item` (which is called for inline items
    // such as `fn` definitions inside blocks) to zero the loop depth while
    // visiting any item kind that introduces a new call frame.
    fn visit_item(&mut self, node: &'ast syn::Item) {
        // For nested fn / impl / trait items, their bodies only run when
        // explicitly called — not inline.  Zero the loop depth while visiting
        // them so PERF010 doesn't fire inside their bodies.
        let saved_depth = self.in_loop_depth;
        match node {
            syn::Item::Fn(_) | syn::Item::Impl(_) | syn::Item::Trait(_) => {
                self.in_loop_depth = 0;
            }
            _ => {}
        }
        syn::visit::visit_item(self, node);
        self.in_loop_depth = saved_depth;
    }
}

/// Returns `true` if `pat` is `Pat::Wild` or a `Pat::Or` containing `Pat::Wild`.
fn pat_has_wildcard(pat: &syn::Pat) -> bool {
    match pat {
        syn::Pat::Wild(_) => true,
        syn::Pat::Or(po) => po.cases.iter().any(pat_has_wildcard),
        _ => false,
    }
}

// ── Loop-exit scanner for MAINT010 ───────────────────────────────────────────

/// Macro names that act as unconditional diverging calls (process exits).
const EXIT_MACRO_NAMES: &[&str] = &["panic", "unreachable", "todo", "unimplemented"];

/// A sub-visitor that scans a `loop {}` body for reachable exit statements at
/// the **same** nesting depth.
///
/// It overrides `visit_expr_loop`, `visit_expr_for_loop`, `visit_expr_while`,
/// and `visit_expr_closure` to **not** recurse into their bodies, so that a
/// `break` inside an inner `loop {}` or a `for` loop does not falsely indicate
/// that the outer loop can exit.  Similarly, a `return` inside a closure only
/// returns from the closure, not from the outer function.
struct LoopExitScanner {
    has_exit: bool,
}

impl LoopExitScanner {
    fn new() -> Self {
        Self { has_exit: false }
    }
}

impl<'ast> Visit<'ast> for LoopExitScanner {
    // `break` at this nesting level exits the current loop.
    fn visit_expr_break(&mut self, _node: &'ast syn::ExprBreak) {
        self.has_exit = true;
        // Do not recurse — break carries no further sub-expressions of interest.
    }

    // `return` at this nesting level exits the enclosing function (and thus the loop).
    fn visit_expr_return(&mut self, _node: &'ast syn::ExprReturn) {
        self.has_exit = true;
    }

    // A macro call that diverges (panic!, unreachable!, etc.) counts as an exit.
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let name = node
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if EXIT_MACRO_NAMES.contains(&name.as_str()) {
            self.has_exit = true;
        }
        // Do NOT call syn::visit::visit_macro here; macros have no further
        // interesting sub-structure for our purposes.
    }

    // STOP descending into nested `loop {}` — its break targets the inner loop.
    fn visit_expr_loop(&mut self, _node: &'ast syn::ExprLoop) {
        // Do not recurse.
    }

    // STOP descending into `for` loops — their break targets the for loop.
    fn visit_expr_for_loop(&mut self, _node: &'ast syn::ExprForLoop) {
        // Do not recurse.
    }

    // STOP descending into `while` loops — their break targets the while loop.
    fn visit_expr_while(&mut self, _node: &'ast syn::ExprWhile) {
        // Do not recurse.
    }

    // STOP descending into closures — their `return` and `break` do not exit
    // the enclosing loop.
    fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {
        // Do not recurse.
    }
}

// ── Dead-store scanner for MAINT012 ──────────────────────────────────────────

/// Scans a function body block for simple immutable `let name = expr;` bindings
/// and checks whether `name` appears in the token-stream text **after** the let
/// site.  Only `Pat::Ident` patterns with no `mutability` qualifier are
/// considered; destructuring and `let mut` patterns are skipped.
///
/// The scan is done by:
/// 1. Collecting all `syn::Local` nodes whose pattern is a simple `Pat::Ident`
///    and whose init is present (i.e. `let name = expr;`, not `let name;`).
/// 2. Skipping names that start with `_`.
/// 3. Skipping bindings where the same name appears in a *later* binding
///    (shadowing chain): the shadowed binding is not flagged.
/// 4. For each remaining binding, searching for the bare identifier string in
///    the source text after the binding's byte offset.  If absent, the binding
///    is dead.
fn scan_dead_stores_in_block(block: &syn::Block, source: &SourceFile) -> Vec<RustDeadStore> {
    /// A candidate binding: name + byte offset of the identifier in source.
    struct Candidate {
        name: String,
        let_offset: u32,
        span: Span,
    }

    // Walk the block and collect simple let bindings.
    let mut all_lets: Vec<Candidate> = Vec::new();
    for stmt in &block.stmts {
        if let syn::Stmt::Local(local) = stmt {
            // Must have an initialiser.
            if local.init.is_none() {
                continue;
            }
            // Must be a simple Pat::Ident with no mutability qualifier.
            let pat_ident = match &local.pat {
                syn::Pat::Ident(pi) if pi.mutability.is_none() => pi,
                syn::Pat::Type(pt) => {
                    if let syn::Pat::Ident(pi) = &*pt.pat {
                        if pi.mutability.is_some() {
                            continue;
                        }
                        pi
                    } else {
                        continue;
                    }
                }
                _ => continue,
            };
            let name = pat_ident.ident.to_string();
            // Skip leading-underscore names.
            if name.starts_with('_') {
                continue;
            }
            let raw_span = pat_ident.ident.span();
            let byte_span = proc_span_to_byte_span(raw_span, source);
            all_lets.push(Candidate {
                name,
                let_offset: byte_span.start.0,
                span: byte_span,
            });
        }
    }

    if all_lets.is_empty() {
        return Vec::new();
    }

    // Build the set of names that are shadowed (appear in a later let binding
    // for the same name).  We do NOT flag a binding if the same name is bound
    // again later in the same block (shadowing pattern).
    let shadowed: std::collections::HashSet<String> = {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut shadowed = std::collections::HashSet::new();
        // Walk in reverse order; if a name appears twice, the earlier one is shadowed.
        for c in all_lets.iter().rev() {
            if !seen.insert(c.name.clone()) {
                // Name was already seen (later occurrence) — the current one is shadowed.
                shadowed.insert(c.name.clone());
            }
        }
        shadowed
    };

    // Get the source text.
    let source_text = source.as_str();
    let source_bytes = source_text.as_bytes();

    let mut dead: Vec<RustDeadStore> = Vec::new();
    let mut emitted: std::collections::HashSet<String> = std::collections::HashSet::new();

    for candidate in &all_lets {
        // Skip shadowed bindings.
        if shadowed.contains(&candidate.name) {
            continue;
        }
        if emitted.contains(&candidate.name) {
            continue;
        }

        // Search for the bare identifier name in the source text AFTER the
        // let site (i.e. byte offset > candidate.let_offset).
        let search_start = (candidate.let_offset as usize).min(source_bytes.len());
        // Move past the binding itself to avoid matching the binding's own identifier.
        // Find the next occurrence of the name after `search_start`.
        let tail = &source_text[search_start..];

        // We need to find `name` as a whole word (not a substring of another identifier).
        let found = find_bare_ident_after(tail, &candidate.name);

        if !found {
            emitted.insert(candidate.name.clone());
            dead.push(RustDeadStore {
                name: candidate.name.clone(),
                span: candidate.span,
            });
        }
    }

    dead
}

/// Checks whether `name` appears as a bare (word-boundary-delimited) identifier
/// anywhere in `text` **after** the first occurrence of `name` itself.
///
/// Strategy: skip the first occurrence of `name` (the binding site), then
/// search for any later occurrence that is surrounded by non-identifier chars.
fn find_bare_ident_after(text: &str, name: &str) -> bool {
    let bytes = text.as_bytes();
    let name_bytes = name.as_bytes();
    let nlen = name_bytes.len();

    let mut pos = 0usize;
    let mut first_skipped = false;

    while pos + nlen <= bytes.len() {
        if bytes[pos..pos + nlen] == *name_bytes {
            // Check word boundaries.
            let before_ok = pos == 0 || !is_ident_char(bytes[pos - 1]);
            let after_ok = pos + nlen >= bytes.len() || !is_ident_char(bytes[pos + nlen]);
            if before_ok && after_ok {
                if first_skipped {
                    return true;
                }
                first_skipped = true;
                pos += nlen;
                continue;
            }
        }
        pos += 1;
    }
    false
}

/// Returns `true` if `c` is a valid Rust identifier character (ASCII subset).
fn is_ident_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

// ── entry point ───────────────────────────────────────────────────────────────

/// Parses Rust source text using `syn` and returns a [`ParsedFile`].
///
/// The resulting [`ParsedFile`] holds a [`RustAst`] as its native AST; use
/// [`crate::try_rust_ast`] to retrieve it.
///
/// # Errors
///
/// Returns [`ParseError::Syntax`] when `syn` rejects the input.
pub(crate) fn parse(source: Arc<SourceFile>) -> Result<ParsedFile, ParseError> {
    let text = source.as_str();
    let syn_file = syn::parse_file(text).map_err(|e| ParseError::Syntax {
        file: source.path.clone(),
        message: e.to_string(),
        span: None,
    })?;

    let index = build_index(&syn_file, &source);

    // Pre-extract all unsafe constructs while we still have the syn::File.
    // After this block, syn_file is dropped and RustAst holds only Send+Sync data.
    let native = {
        let mut extractor = Extractor::new(&source);
        extractor.visit_file(&syn_file);

        // ECO003: if any `unsafe impl Send` was found in this file, none of the
        // pending pub-struct-with-raw-ptr spans are flagged (conservative heuristic).
        let pub_struct_with_raw_ptr = if extractor.has_unsafe_impl_send {
            Vec::new()
        } else {
            extractor.pending_pub_struct_raw_ptr
        };

        Box::new(RustAst {
            unsafe_items: extractor.items,
            unsafe_blocks_without_safety: extractor.unsafe_blocks_without_safety,
            pub_unsafe_fns: extractor.pub_unsafe_fns,
            transmute_calls: extractor.transmute_calls,
            raw_ptr_pub_apis: extractor.raw_ptr_pub_apis,
            unsafe_with_parser_calls: extractor.unsafe_with_parser_calls,
            extern_unsafe_fns_no_doc: extractor.extern_unsafe_fns_no_doc,
            clone_in_iter_chains: extractor.clone_in_iter_chains,
            empty_blocks: extractor.empty_blocks,
            debug_calls: extractor.debug_calls,
            bind_call_sites: extractor.bind_call_sites,
            assignments: extractor.assignments,
            log_calls: extractor.log_calls,
            pub_struct_with_raw_ptr,
            match_sites: extractor.match_sites,
            infinite_loops: extractor.infinite_loops,
            dead_stores: extractor.dead_stores,
            has_macro_body: extractor.has_macro_body,
            pub_static_muts: extractor.pub_static_muts,
            unreachable_stmts: extractor.unreachable_stmts,
            deprecated_items: extractor.deprecated_items,
            dangerous_calls: extractor.dangerous_calls,
            allocs_in_loop: extractor.allocs_in_loop,
        })
    };

    Ok(ParsedFile::new(
        zuit_core::LanguageId("rust"),
        source,
        index,
        native,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_source(code: &str) -> Arc<SourceFile> {
        Arc::new(SourceFile::new("test.rs", code.as_bytes().to_vec()))
    }

    #[test]
    fn parses_valid_rust() {
        let src = make_source("fn hello() {}");
        let result = parse(src);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_error_on_invalid_syntax() {
        let src = make_source("fn x(");
        let result = parse(src);
        assert!(result.is_err());
        match result.unwrap_err() {
            ParseError::Syntax { .. } => {}
            other => panic!("expected Syntax, got {other}"),
        }
    }

    #[test]
    fn native_ast_accessible_via_try_rust_ast() {
        let src = make_source("fn hello() {}");
        let parsed = parse(src).unwrap();
        let ast = crate::try_rust_ast(&parsed);
        assert!(ast.is_some());
    }

    #[test]
    fn index_has_function_after_parse() {
        let src = make_source("fn hello() {}");
        let parsed = parse(src).unwrap();
        assert!(!parsed.index().functions.is_empty());
    }

    #[test]
    fn unsafe_items_pre_extracted() {
        let src = make_source("fn f() { unsafe { let _ = 1; } }");
        let parsed = parse(src).unwrap();
        let ast = crate::try_rust_ast(&parsed).unwrap();
        assert_eq!(ast.unsafe_items.len(), 1);
        assert_eq!(ast.unsafe_items[0].label, "block");
    }

    #[test]
    fn unsafe_block_without_safety_comment_extracted() {
        let src = make_source("fn f() { unsafe { let _ = 1; } }");
        let parsed = parse(src).unwrap();
        let ast = crate::try_rust_ast(&parsed).unwrap();
        assert_eq!(ast.unsafe_blocks_without_safety.len(), 1);
    }

    #[test]
    fn unsafe_block_with_safety_comment_not_extracted() {
        let src = make_source("fn f() {\n// SAFETY: ok\nunsafe { let _ = 1; }\n}");
        let parsed = parse(src).unwrap();
        let ast = crate::try_rust_ast(&parsed).unwrap();
        assert_eq!(ast.unsafe_blocks_without_safety.len(), 0);
    }

    #[test]
    fn pub_unsafe_fn_extracted() {
        let src = make_source("pub unsafe fn dangerous() {}");
        let parsed = parse(src).unwrap();
        let ast = crate::try_rust_ast(&parsed).unwrap();
        assert_eq!(ast.pub_unsafe_fns.len(), 1);
    }

    #[test]
    fn transmute_call_extracted() {
        let src =
            make_source("use std::mem; fn f() { let x: u32 = 0; let _: i32 = mem::transmute(x); }");
        let parsed = parse(src).unwrap();
        let ast = crate::try_rust_ast(&parsed).unwrap();
        assert_eq!(ast.transmute_calls.len(), 1);
    }

    #[test]
    fn raw_ptr_pub_api_extracted() {
        let src = make_source("pub fn f() -> *const u8 { std::ptr::null() }");
        let parsed = parse(src).unwrap();
        let ast = crate::try_rust_ast(&parsed).unwrap();
        assert_eq!(ast.raw_ptr_pub_apis.len(), 1);
    }
}
