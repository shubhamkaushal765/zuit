//! Build a [`SemanticIndex`] from a parsed `syn::File`.
//!
//! The visitor walks top-level items and impl blocks, collecting:
//! - `fn` items → [`FunctionLike`]
//! - `struct` / `enum` / `type` / `trait` items → [`TypeDecl`]
//! - `mod` items → [`ModuleDecl`]
//! - `use` items → [`Import`]
//! - string literals anywhere in item bodies → [`StringLit`]
//! - `///` / `/** */` doc attributes → [`DocComment`]
//! - `//` / `/* */` comments (non-doc) → [`Comment`]

use std::sync::Arc;

use syn::spanned::Spanned;
use syn::visit::Visit;

use zuit_core::{
    Comment, DocComment, FunctionKind, FunctionLike, Import, ModuleDecl, NodeId, RegexLiteral,
    SemanticIndex, Span, StringLit, Suppression, TypeDecl, Visibility, parse_suppression_directive,
    span::ByteOffset,
};

use crate::complexity;
use crate::span_util;

// ── public entry point ────────────────────────────────────────────────────────

/// Walk `file` and return a fully-populated [`SemanticIndex`].
pub(crate) fn build_index(file: &syn::File, source: &Arc<zuit_core::SourceFile>) -> SemanticIndex {
    let mut v = IndexVisitor::new(source.clone());
    v.visit_file(file);

    // Extract comments from source text
    extract_comments(source, &mut v.index);

    // Scan comments for suppression directives.
    extract_suppressions(source, &mut v.index);

    v.index
}

/// Scans the comments already extracted into `index.comments` and populates
/// `index.suppressions` with any `zuit: ignore` / `zuit: ignore-file`
/// directives found.
fn extract_suppressions(source: &Arc<zuit_core::SourceFile>, index: &mut SemanticIndex) {
    // Collect comment data to avoid borrowing issues.
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

/// Extracts regular `//` and `/* */` comments from source text.
///
/// Doc comments (`///`, `//!`, `/** */`, `/*! */`) are skipped here because
/// they are surfaced separately via [`SemanticIndex::doc_comments`].
///
/// **Limitation:** the scanner is not string-aware. A literal containing `//`
/// or `/*` (e.g. `"http://x"`) will produce a spurious comment. This is good
/// enough for `DOC002-todo-fixme` (TODO/FIXME rarely appear inside string
/// payloads) and will be replaced with a token-stream-aware extractor when
/// other rules need accurate comment data.
fn extract_comments(source: &Arc<zuit_core::SourceFile>, index: &mut SemanticIndex) {
    let bytes = source.as_str().as_bytes();
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    let mut next_id = 1u32;
    let mut i: u32 = 0;

    while i < len {
        let b = bytes[i as usize];
        if b != b'/' || i + 1 >= len {
            i += 1;
            continue;
        }
        let next = bytes[i as usize + 1];
        match next {
            b'/' => {
                // `//` line comment. Skip doc-comment markers (`///`, `//!`).
                let third = bytes.get(i as usize + 2).copied();
                let is_doc = matches!(third, Some(b'/' | b'!'));
                let start = i;
                i += 2;
                while i < len && bytes[i as usize] != b'\n' {
                    i += 1;
                }
                if !is_doc {
                    let text = std::str::from_utf8(&bytes[(start + 2) as usize..i as usize])
                        .unwrap_or("")
                        .trim_start()
                        .to_string();
                    index.comments.push(Comment {
                        id: NodeId(next_id),
                        text,
                        span: Span::new(ByteOffset(start), ByteOffset(i)),
                    });
                    next_id += 1;
                }
            }
            b'*' => {
                // `/* */` block comment. Skip doc-comment markers (`/**`, `/*!`).
                let third = bytes.get(i as usize + 2).copied();
                let is_doc = matches!(third, Some(b'*' | b'!'));
                let start = i;
                i += 2;
                let mut closed = false;
                while i + 1 < len {
                    if bytes[i as usize] == b'*' && bytes[i as usize + 1] == b'/' {
                        i += 2;
                        closed = true;
                        break;
                    }
                    i += 1;
                }
                if !closed {
                    i = len;
                }
                if !is_doc {
                    let inner_end = if closed { i - 2 } else { i };
                    let text =
                        std::str::from_utf8(&bytes[(start + 2) as usize..inner_end as usize])
                            .unwrap_or("")
                            .trim()
                            .to_string();
                    index.comments.push(Comment {
                        id: NodeId(next_id),
                        text,
                        span: Span::new(ByteOffset(start), ByteOffset(i)),
                    });
                    next_id += 1;
                }
            }
            _ => {
                i += 1;
            }
        }
    }
}

// ── visitor ───────────────────────────────────────────────────────────────────

struct IndexVisitor {
    index: SemanticIndex,
    next_id: u32,
    source: Arc<zuit_core::SourceFile>,
}

impl IndexVisitor {
    fn new(source: Arc<zuit_core::SourceFile>) -> Self {
        Self {
            index: SemanticIndex::new(),
            next_id: 1,
            source,
        }
    }

    fn alloc_id(&mut self) -> NodeId {
        let id = NodeId(self.next_id);
        self.next_id += 1;
        id
    }

    /// Convert a `proc_macro2::Span` to our [`Span`] using real byte offsets.
    fn proc_span(&self, span: proc_macro2::Span) -> Span {
        span_util::proc_span_to_byte_span(span, &self.source)
    }

    /// Extract doc-comment text from a list of `syn::Attribute`s.
    /// Returns the concatenated text and the span of the first doc attr, if any.
    fn extract_doc(&mut self, attrs: &[syn::Attribute]) -> Option<NodeId> {
        let mut lines: Vec<String> = Vec::new();
        let mut first_span: Option<Span> = None;

        for attr in attrs {
            if attr.path().is_ident("doc") {
                let span = if let Some(ident) = attr.meta.path().get_ident() {
                    self.proc_span(ident.span())
                } else {
                    Span::new(ByteOffset(0), ByteOffset(0))
                };
                if first_span.is_none() {
                    first_span = Some(span);
                }
                // Extract the string value from #[doc = "..."]
                if let syn::Meta::NameValue(nv) = &attr.meta
                    && let syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(s),
                        ..
                    }) = &nv.value
                {
                    lines.push(s.value());
                }
            }
        }

        if lines.is_empty() {
            return None;
        }

        let text = lines.join("\n");
        let span = first_span.unwrap_or_else(|| Span::new(ByteOffset(0), ByteOffset(0)));
        let id = self.alloc_id();
        self.index.doc_comments.push(DocComment { id, text, span });
        Some(id)
    }

    /// Map `syn::Visibility` to our [`Visibility`].
    fn map_visibility(vis: &syn::Visibility) -> Visibility {
        match vis {
            syn::Visibility::Public(_) => Visibility::Public,
            syn::Visibility::Restricted(r) => {
                let path = &r.path;
                if path.is_ident("crate") {
                    Visibility::Crate
                } else {
                    Visibility::Module
                }
            }
            syn::Visibility::Inherited => Visibility::Private,
        }
    }

    /// Whether any attribute in the list is `#[test]`.
    fn is_test(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|a| a.path().is_ident("test"))
    }

    /// Register a free-standing `fn` item.
    fn register_fn_item(&mut self, item: &syn::ItemFn) {
        let doc = self.extract_doc(&item.attrs);
        let vis = Self::map_visibility(&item.vis);
        let is_test = Self::is_test(&item.attrs);
        let is_async = item.sig.asyncness.is_some();

        let param_count = item
            .sig
            .inputs
            .iter()
            .filter(|a| !matches!(a, syn::FnArg::Receiver(_)))
            .count();

        let span = self.proc_span(item.sig.fn_token.span);
        let body_span = self.proc_span(item.block.brace_token.span.join());
        let complexity = complexity::compute(&item.block);

        let id = self.alloc_id();
        self.index.functions.push(FunctionLike {
            id,
            kind: FunctionKind::Function,
            name: Some(item.sig.ident.to_string()),
            visibility: vis,
            span,
            body_span,
            #[allow(clippy::cast_possible_truncation)]
            param_count: param_count as u32,
            is_async,
            is_test,
            doc,
            complexity,
            parent_name: None,
        });

        // Still recurse to catch nested functions and string literals in the body.
        syn::visit::visit_item_fn(self, item);
    }

    /// Register a method from an `impl` block.
    fn register_impl_method(&mut self, method: &syn::ImplItemFn, parent_name: Option<String>) {
        let doc = self.extract_doc(&method.attrs);
        let vis = Self::map_visibility(&method.vis);
        let is_test = Self::is_test(&method.attrs);
        let is_async = method.sig.asyncness.is_some();

        let param_count = method
            .sig
            .inputs
            .iter()
            .filter(|a| !matches!(a, syn::FnArg::Receiver(_)))
            .count();

        let span = self.proc_span(method.sig.fn_token.span);
        let body_span = self.proc_span(method.block.brace_token.span.join());
        let complexity = complexity::compute(&method.block);

        let id = self.alloc_id();
        self.index.functions.push(FunctionLike {
            id,
            kind: FunctionKind::Method,
            name: Some(method.sig.ident.to_string()),
            visibility: vis,
            span,
            body_span,
            #[allow(clippy::cast_possible_truncation)]
            param_count: param_count as u32,
            is_async,
            is_test,
            doc,
            complexity,
            parent_name,
        });

        syn::visit::visit_impl_item_fn(self, method);
    }
}

impl<'ast> Visit<'ast> for IndexVisitor {
    // ── fn items ─────────────────────────────────────────────────────────

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.register_fn_item(node);
        // Do NOT call visit_item_fn again — register_fn_item does the recursion.
    }

    // ── impl blocks ───────────────────────────────────────────────────────

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        // Extract the self-type name for parent_name population.
        // For `impl Foo { … }` this is `"Foo"`; for `impl Trait for Foo { … }`
        // this is also `"Foo"` (the implementing type).
        let parent_name: Option<String> = match node.self_ty.as_ref() {
            syn::Type::Path(tp) => tp.path.segments.last().map(|s| s.ident.to_string()),
            _ => None,
        };
        for item in &node.items {
            if let syn::ImplItem::Fn(method) = item {
                self.register_impl_method(method, parent_name.clone());
            }
        }
        // Do NOT recurse further through visit_item_impl to avoid double-counting.
    }

    // ── trait blocks (register trait methods if they have bodies) ─────────

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        let doc = self.extract_doc(&node.attrs);
        let vis = Self::map_visibility(&node.vis);
        let span = self.proc_span(node.trait_token.span);

        let id = self.alloc_id();
        self.index.types.push(TypeDecl {
            id,
            name: node.ident.to_string(),
            visibility: vis,
            span,
            doc,
        });

        // Visit trait items for default methods
        for item in &node.items {
            if let syn::TraitItem::Fn(method) = item
                && let Some(block) = &method.default
            {
                let doc2 = self.extract_doc(&method.attrs);
                let is_async = method.sig.asyncness.is_some();
                let param_count = method
                    .sig
                    .inputs
                    .iter()
                    .filter(|a| !matches!(a, syn::FnArg::Receiver(_)))
                    .count();
                let span2 = self.proc_span(method.sig.fn_token.span);
                let body_span = self.proc_span(block.brace_token.span.join());
                let complexity = complexity::compute(block);
                let id2 = self.alloc_id();
                self.index.functions.push(FunctionLike {
                    id: id2,
                    kind: FunctionKind::Method,
                    name: Some(method.sig.ident.to_string()),
                    visibility: Visibility::Public,
                    span: span2,
                    body_span,
                    #[allow(clippy::cast_possible_truncation)]
                    param_count: param_count as u32,
                    is_async,
                    is_test: false,
                    doc: doc2,
                    complexity,
                    parent_name: Some(node.ident.to_string()),
                });
            }
        }
    }

    // ── struct / enum / type alias ────────────────────────────────────────

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        let doc = self.extract_doc(&node.attrs);
        let vis = Self::map_visibility(&node.vis);
        let span = self.proc_span(node.struct_token.span);
        let id = self.alloc_id();
        self.index.types.push(TypeDecl {
            id,
            name: node.ident.to_string(),
            visibility: vis,
            span,
            doc,
        });
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        let doc = self.extract_doc(&node.attrs);
        let vis = Self::map_visibility(&node.vis);
        let span = self.proc_span(node.enum_token.span);
        let id = self.alloc_id();
        self.index.types.push(TypeDecl {
            id,
            name: node.ident.to_string(),
            visibility: vis,
            span,
            doc,
        });
        syn::visit::visit_item_enum(self, node);
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        let doc = self.extract_doc(&node.attrs);
        let vis = Self::map_visibility(&node.vis);
        let span = self.proc_span(node.type_token.span);
        let id = self.alloc_id();
        self.index.types.push(TypeDecl {
            id,
            name: node.ident.to_string(),
            visibility: vis,
            span,
            doc,
        });
        syn::visit::visit_item_type(self, node);
    }

    // ── mod declarations ──────────────────────────────────────────────────

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let span = self.proc_span(node.mod_token.span);
        let id = self.alloc_id();
        self.index.modules.push(ModuleDecl {
            id,
            name: node.ident.to_string(),
            span,
        });
        syn::visit::visit_item_mod(self, node);
    }

    // ── use statements ────────────────────────────────────────────────────

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        let span = self.proc_span(node.use_token.span);
        let id = self.alloc_id();
        // Render the use tree as a simple string.
        let path = use_tree_to_string(&node.tree);
        self.index.imports.push(Import { id, path, span });
        // Do NOT recurse — we've captured the whole use item.
    }

    // ── string literals ───────────────────────────────────────────────────

    fn visit_lit_str(&mut self, node: &'ast syn::LitStr) {
        let span = self.proc_span(node.span());
        let id = self.alloc_id();
        self.index.string_literals.push(StringLit {
            id,
            value: node.value(),
            span,
        });
    }

    // ── regex literals (SEC014-redos-regex) ───────────────────────────────
    //
    // Detect `Regex::new(<str>)` / `RegexBuilder::new(<str>)` / etc.
    // The last path segment must be `new` and the preceding segment must end
    // with `Regex` or `RegexBuilder`.

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Some(pattern) = extract_regex_new_pattern(node) {
            let span = self.proc_span(node.span());
            let id = self.alloc_id();
            self.index.regex_literals.push(RegexLiteral {
                id,
                value: pattern,
                span,
            });
        }
        // Always continue visiting so nested calls / string literals are found.
        syn::visit::visit_expr_call(self, node);
    }
}

/// Extracts the regex pattern string from a `Regex::new(<str>)` /
/// `RegexBuilder::new(<str>)` / `regex::Regex::new(<str>)` call.
///
/// Returns `Some(pattern)` when:
/// - the callee is a path expression whose last segment is `new`;
/// - the preceding segment ends with `Regex` or `RegexBuilder`;
/// - the first argument is a string literal.
fn extract_regex_new_pattern(call: &syn::ExprCall) -> Option<String> {
    // The callee must be a path expression.
    let path = match call.func.as_ref() {
        syn::Expr::Path(p) => &p.path,
        _ => return None,
    };

    let segs: Vec<_> = path.segments.iter().collect();
    if segs.len() < 2 {
        return None;
    }

    // Last segment must be `new`.
    if segs.last()?.ident != "new" {
        return None;
    }

    // Second-to-last segment must end with `Regex` or `RegexBuilder`.
    let prev_ident = segs[segs.len() - 2].ident.to_string();
    if !prev_ident.ends_with("Regex") && !prev_ident.ends_with("RegexBuilder") {
        return None;
    }

    // First argument must be a string literal.
    let first_arg = call.args.first()?;
    if let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Str(s),
        ..
    }) = first_arg
    {
        return Some(s.value());
    }

    None
}

/// Render a `syn::UseTree` to a human-readable import path string.
fn use_tree_to_string(tree: &syn::UseTree) -> String {
    match tree {
        syn::UseTree::Path(p) => {
            format!("{}::{}", p.ident, use_tree_to_string(&p.tree))
        }
        syn::UseTree::Name(n) => n.ident.to_string(),
        syn::UseTree::Rename(r) => format!("{} as {}", r.ident, r.rename),
        syn::UseTree::Glob(_) => "*".to_string(),
        syn::UseTree::Group(g) => {
            let parts: Vec<_> = g.items.iter().map(use_tree_to_string).collect();
            format!("{{{}}}", parts.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::SourceFile;

    fn index_of(code: &str) -> SemanticIndex {
        let src = Arc::new(SourceFile::new("test.rs", code.as_bytes().to_vec()));
        let file: syn::File = syn::parse_str(code).unwrap();
        build_index(&file, &src)
    }

    #[test]
    fn single_pub_fn_indexed() {
        let idx = index_of("/// My function\npub fn hello() {}");
        assert_eq!(idx.functions.len(), 1);
        let f = &idx.functions[0];
        assert_eq!(f.name.as_deref(), Some("hello"));
        assert_eq!(f.visibility, Visibility::Public);
        assert!(f.doc.is_some(), "should have a doc comment");
    }

    #[test]
    fn private_fn_indexed() {
        let idx = index_of("fn private_fn(x: i32) {}");
        assert_eq!(idx.functions.len(), 1);
        let f = &idx.functions[0];
        assert_eq!(f.visibility, Visibility::Private);
        assert_eq!(f.param_count, 1);
    }

    #[test]
    fn struct_indexed() {
        let idx = index_of("pub struct Foo {}");
        assert_eq!(idx.types.len(), 1);
        assert_eq!(idx.types[0].name, "Foo");
        assert_eq!(idx.types[0].visibility, Visibility::Public);
    }

    #[test]
    fn enum_indexed() {
        let idx = index_of("pub enum Color { Red, Green, Blue }");
        assert_eq!(idx.types.len(), 1);
        assert_eq!(idx.types[0].name, "Color");
    }

    #[test]
    fn use_statement_indexed() {
        let idx = index_of("use std::collections::HashMap;");
        assert_eq!(idx.imports.len(), 1);
        assert!(idx.imports[0].path.contains("HashMap"));
    }

    #[test]
    fn mod_declaration_indexed() {
        let idx = index_of("mod my_module {}");
        assert_eq!(idx.modules.len(), 1);
        assert_eq!(idx.modules[0].name, "my_module");
    }

    #[test]
    fn string_literal_indexed() {
        let idx = index_of(r#"fn f() { let _ = "hello"; }"#);
        assert!(!idx.string_literals.is_empty());
        assert!(idx.string_literals.iter().any(|s| s.value == "hello"));
    }

    #[test]
    fn method_in_impl_indexed() {
        let code = "struct Foo; impl Foo { pub fn bar(&self) {} }";
        let idx = index_of(code);
        // Struct + method
        assert!(
            idx.functions
                .iter()
                .any(|f| f.name.as_deref() == Some("bar"))
        );
        let m = idx
            .functions
            .iter()
            .find(|f| f.name.as_deref() == Some("bar"))
            .unwrap();
        assert_eq!(m.kind, FunctionKind::Method);
    }

    #[test]
    fn test_fn_flagged() {
        let code = "#[test]\nfn my_test() {}";
        let idx = index_of(code);
        assert!(idx.functions[0].is_test);
    }

    #[test]
    fn async_fn_flagged() {
        let idx = index_of("async fn fetch() {}");
        assert!(idx.functions[0].is_async);
    }

    #[test]
    fn doc_comment_linked_to_function() {
        let idx = index_of("/// Says hello.\npub fn greet() {}");
        let f = &idx.functions[0];
        let doc_id = f.doc.expect("function should have doc");
        assert!(idx.doc_comments.iter().any(|d| d.id == doc_id));
        let doc = idx.doc_comments.iter().find(|d| d.id == doc_id).unwrap();
        assert!(doc.text.contains("Says hello"));
    }

    #[test]
    fn complexity_propagated() {
        let idx = index_of("fn f(a: bool) -> i32 { if a { 1 } else { 2 } }");
        assert_eq!(idx.functions[0].complexity.cyclomatic, 2);
    }

    // ── suppression extraction tests ──────────────────────────────────────────

    #[test]
    fn suppression_directive_extracted_from_line_comment() {
        // Line 1 has the suppression comment, so line should be 1.
        let idx = index_of("// zuit: ignore MAINT003\nfn foo() {}");
        assert_eq!(idx.suppressions.len(), 1);
        let s = &idx.suppressions[0];
        assert_eq!(s.rule_id, "MAINT003");
        assert_eq!(s.line, 1);
        assert!(!s.file_scoped);
    }

    #[test]
    fn suppression_directive_file_scoped() {
        let idx = index_of("// zuit: ignore-file SEC001\nfn foo() {}");
        assert_eq!(idx.suppressions.len(), 1);
        let s = &idx.suppressions[0];
        assert_eq!(s.rule_id, "SEC001");
        assert!(s.file_scoped);
    }

    #[test]
    fn suppression_comma_separated_produces_multiple_entries() {
        let idx = index_of("// zuit: ignore RULE1,RULE2\nfn foo() {}");
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
    fn regular_comment_does_not_produce_suppression() {
        let idx = index_of("// TODO: fix this\nfn foo() {}");
        assert!(idx.suppressions.is_empty());
    }

    // ── regex literal collection (SEC014-redos-regex) ─────────────────────────

    #[test]
    fn regex_new_call_produces_regex_literal() {
        let code = r#"fn f() { let r = Regex::new("(a+)+").unwrap(); }"#;
        let idx = index_of(code);
        assert!(
            !idx.regex_literals.is_empty(),
            "expected at least one regex literal, got none"
        );
        assert!(
            idx.regex_literals.iter().any(|r| r.value == "(a+)+"),
            "expected value '(a+)+', got {:?}",
            idx.regex_literals
                .iter()
                .map(|r| &r.value)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn regex_crate_path_new_call_produces_regex_literal() {
        let code = r#"fn f() { let r = regex::Regex::new("abc+").unwrap(); }"#;
        let idx = index_of(code);
        assert!(idx.regex_literals.iter().any(|r| r.value == "abc+"));
    }

    #[test]
    fn regex_builder_new_call_produces_regex_literal() {
        let code = r#"fn f() { let r = RegexBuilder::new("(a|b)+").build().unwrap(); }"#;
        let idx = index_of(code);
        assert!(
            !idx.regex_literals.is_empty(),
            "expected regex literal for RegexBuilder::new"
        );
        assert!(idx.regex_literals.iter().any(|r| r.value == "(a|b)+"));
    }
}
