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

    /// Spans of `pub struct` declarations that contain a raw pointer field
    /// (`*mut T` or `*const T`) without an accompanying `unsafe impl Send`
    /// declaration in the same file.
    ///
    /// Used by `ECO003-send-sync-violations-on-pub-types`.
    pub(crate) pub_struct_with_raw_ptr: Vec<Span>,
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

/// Returns `true` if the last path segment is `transmute`.
fn is_transmute_path(path: &syn::Path) -> bool {
    path.segments
        .last()
        .is_some_and(|seg| seg.ident == "transmute")
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

    source: &'src SourceFile,
    /// `true` while inside an `extern "…"` block.
    in_foreign_mod: bool,
    /// Collect `pub struct` spans that have raw pointer fields.
    /// After file visit we check for `unsafe impl Send` to filter out false positives.
    pending_pub_struct_raw_ptr: Vec<Span>,
    /// Whether we've seen any `unsafe impl Send` in the file.
    has_unsafe_impl_send: bool,
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
            source,
            in_foreign_mod: false,
            pending_pub_struct_raw_ptr: Vec::new(),
            has_unsafe_impl_send: false,
        }
    }

    fn push_unsafe_item(&mut self, raw: proc_macro2::Span, label: &'static str) {
        let span = proc_span_to_byte_span(raw, self.source);
        self.items.push(UnsafeItem { span, label });
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

        syn::visit::visit_item_fn(self, node);
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

        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        if node.sig.unsafety.is_some() {
            self.push_unsafe_item(node.sig.fn_token.span, "fn");
        }
        syn::visit::visit_trait_item_fn(self, node);
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

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        // SOUND003: detect transmute calls
        if let syn::Expr::Path(ep) = &*node.func
            && is_transmute_path(&ep.path)
        {
            let span = proc_span_to_byte_span(ep.path.span(), self.source);
            self.transmute_calls.push(span);
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
                // Extract the first argument string literal value, if any.
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
        syn::visit::visit_expr_for_loop(self, node);
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        if node.body.stmts.is_empty() {
            let span = proc_span_to_byte_span(node.while_token.span, self.source);
            self.empty_blocks.push(span);
        }
        syn::visit::visit_expr_while(self, node);
    }

    // MAINT011: detect debug-code macros (dbg!, println!, eprintln!).
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
        syn::visit::visit_macro(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        // ECO003: pub struct with raw pointer field.
        if Self::is_pub(&node.vis) && Self::struct_has_raw_ptr_field(&node.fields) {
            let span = proc_span_to_byte_span(node.struct_token.span, self.source);
            self.pending_pub_struct_raw_ptr.push(span);
        }
        syn::visit::visit_item_struct(self, node);
    }
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
            pub_struct_with_raw_ptr,
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
