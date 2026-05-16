//! [`SemanticIndex`]: the cross-language contract that language frontends fill in
//! and analyzers consume.
//!
//! All complexity metrics are computed by the frontend at parse time.
//! Analyzers **must not** re-walk native ASTs to compute these values.

use serde::{Deserialize, Serialize};

use crate::span::Span;

/// An opaque, frontend-scoped node identifier used to cross-reference entries
/// within the same [`SemanticIndex`] (e.g. linking a function to its doc comment).
///
/// The value is meaningful only within a single parsed file and must not be
/// compared across files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub u32);

/// The kind of callable represented by a [`FunctionLike`] entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FunctionKind {
    /// A free or associated function.
    Function,
    /// A method belonging to a type or trait.
    Method,
    /// A Rust closure or similar anonymous callable.
    Closure,
    /// A Python lambda or similar single-expression anonymous callable.
    Lambda,
    /// A JavaScript/TypeScript arrow function.
    ArrowFn,
}

/// The visibility of a declaration within its module hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Visibility {
    /// Visible to the whole world (e.g. Rust `pub`, Python non-prefixed top-level).
    Public,
    /// Visible within the current crate (Rust `pub(crate)`).
    Crate,
    /// Visible within the current module only (Rust `pub(super)` / `pub(in …)`).
    Module,
    /// Not visible outside the defining item (default in most languages).
    Private,
}

/// Pre-computed complexity counters for a single callable.
///
/// Frontends populate these at parse time. The specific counting rules
/// for each metric are documented per frontend in `docs/rules/MAINT001-cyclomatic.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct ComplexityMetrics {
    /// Cyclomatic complexity (V(G) / number of independent paths through the
    /// function body). Baseline is 1; each branching construct adds 1.
    pub cyclomatic: u32,
    /// Sonar-variant cognitive complexity. Measures how difficult the control
    /// flow is to understand, giving extra weight to nested structures.
    pub cognitive: u32,
    /// Maximum nesting depth reached anywhere in the function body.
    pub max_nesting: u32,
    /// Number of explicit `return` (or equivalent) statements.
    pub returns: u32,
}

/// A function, method, closure, lambda, or arrow-function entry.
///
/// Language frontends emit one `FunctionLike` per callable in the source,
/// fully populated at parse time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionLike {
    /// Frontend-assigned node identifier for cross-referencing.
    pub id: NodeId,
    /// Which kind of callable this entry represents.
    pub kind: FunctionKind,
    /// The declared name, if any (absent for anonymous closures / lambdas).
    pub name: Option<String>,
    /// Declared visibility of the callable.
    pub visibility: Visibility,
    /// Byte span covering the entire declaration (signature + body).
    pub span: Span,
    /// Byte span covering the body only (inside the braces / after `:`).
    pub body_span: Span,
    /// Number of parameters (excluding `self` / `this`).
    pub param_count: u32,
    /// Whether the callable is declared as `async`.
    pub is_async: bool,
    /// Whether the callable is a test function (e.g. `#[test]` in Rust).
    pub is_test: bool,
    /// `NodeId` of the associated doc comment entry, if one was found.
    pub doc: Option<NodeId>,
    /// Pre-computed complexity counters.
    pub complexity: ComplexityMetrics,
    /// Name of the enclosing type (impl block or class) for methods.
    ///
    /// `Some("MyStruct")` for a method in `impl MyStruct { … }` (Rust) or a
    /// method inside `class MyClass:` (Python). `None` for free functions,
    /// closures, lambdas, and arrow functions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_name: Option<String>,
}

/// A type declaration (struct, class, enum, interface, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeDecl {
    /// Frontend-assigned node identifier.
    pub id: NodeId,
    /// Declared name of the type.
    pub name: String,
    /// Declared visibility of the type.
    pub visibility: Visibility,
    /// Byte span of the entire declaration.
    pub span: Span,
    /// `NodeId` of the associated doc comment entry, if one was found.
    pub doc: Option<NodeId>,
}

/// A module or package declaration (Rust `mod`, Python package, JS module).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleDecl {
    /// Frontend-assigned node identifier.
    pub id: NodeId,
    /// Module name as it appears in the source.
    pub name: String,
    /// Byte span of the `mod` keyword or equivalent.
    pub span: Span,
}

/// An import or `use` statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Import {
    /// Frontend-assigned node identifier.
    pub id: NodeId,
    /// The imported path as a single string (e.g. `"std::collections::HashMap"`).
    pub path: String,
    /// Byte span of the entire import statement.
    pub span: Span,
}

/// A string literal found in the source.
///
/// Used by analyzers such as `SEC001-hardcoded-secret` to scan literal values
/// without re-visiting the native AST.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringLit {
    /// Frontend-assigned node identifier.
    pub id: NodeId,
    /// The decoded string value (escape sequences resolved).
    pub value: String,
    /// Byte span of the literal in the source, including delimiters.
    pub span: Span,
}

/// A regular (non-doc) comment in the source.
///
/// Used by `DOC002-todo-fixme` to inventory TODO and FIXME markers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comment {
    /// Frontend-assigned node identifier.
    pub id: NodeId,
    /// The raw text of the comment (without leading `//` or `/*` delimiters).
    pub text: String,
    /// Byte span of the comment token.
    pub span: Span,
}

/// A `zuit: ignore` directive extracted from a comment.
///
/// When a comment contains `zuit: ignore RULE_ID` or
/// `zuit: ignore-file RULE_ID`, the engine records it here and uses it
/// to suppress matching findings in [`crate::engine::Engine::analyze_path`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suppression {
    /// 1-indexed line where the directive was written. The directive
    /// suppresses findings on this line and on `line + 1`.
    pub line: u32,
    /// Rule the directive applies to.
    pub rule_id: String,
    /// If true the directive suppresses the rule across the entire file.
    pub file_scoped: bool,
}

/// A regex literal extracted from source for SEC014-redos-regex.
///
/// Each language frontend populates [`SemanticIndex::regex_literals`] by
/// detecting common regex construction patterns (`Regex::new`, `re.compile`,
/// `/pattern/flags`, etc.). The [`crate`]-level `RedosAnalyzer` then walks
/// the `regex_syntax` AST to check for catastrophic backtracking patterns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegexLiteral {
    /// Frontend-assigned node identifier.
    pub id: NodeId,
    /// The raw pattern source (without slashes/quotes).
    pub value: String,
    /// Byte span of the regex literal (or its enclosing call).
    pub span: Span,
}

/// A documentation comment (Rust `///` / `/** */`, Python docstring, etc.).
///
/// Stored separately from [`Comment`] because doc comments attach to items and
/// affect the `DOC001-public-api-undoc` finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocComment {
    /// Frontend-assigned node identifier; this value is what [`FunctionLike::doc`]
    /// and [`TypeDecl::doc`] reference.
    pub id: NodeId,
    /// The raw text of the doc comment (may span multiple lines).
    pub text: String,
    /// Byte span of the comment token(s).
    pub span: Span,
}

/// The full semantic summary of a parsed source file.
///
/// Language frontends populate this at parse time; cross-language analyzers
/// consume only this struct and never touch the native AST.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticIndex {
    /// All callable declarations found in the file.
    pub functions: Vec<FunctionLike>,
    /// All type declarations found in the file.
    pub types: Vec<TypeDecl>,
    /// All module declarations found in the file.
    pub modules: Vec<ModuleDecl>,
    /// All import or `use` statements found in the file.
    pub imports: Vec<Import>,
    /// All string literals found in the file.
    pub string_literals: Vec<StringLit>,
    /// All regular (non-doc) comments found in the file.
    pub comments: Vec<Comment>,
    /// All documentation comments found in the file.
    pub doc_comments: Vec<DocComment>,
    /// All suppression directives found in the file.
    pub suppressions: Vec<Suppression>,
    /// All regex literals found in the file, for SEC014-redos-regex.
    pub regex_literals: Vec<RegexLiteral>,
}

impl SemanticIndex {
    /// Creates an empty `SemanticIndex`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Parse a single comment body (without comment delimiters) for a
/// `zuit: ignore[-file] RULE_ID[,RULE_ID...]` directive.
///
/// Returns `(rule_ids, file_scoped)` if the comment is a directive, else `None`.
///
/// # Examples
///
/// ```
/// use zuit_core::index::parse_suppression_directive;
///
/// let (ids, scoped) = parse_suppression_directive("zuit: ignore RULE1").unwrap();
/// assert_eq!(ids, vec!["RULE1"]);
/// assert!(!scoped);
///
/// let (ids, scoped) = parse_suppression_directive("zuit: ignore-file RULE1,RULE2").unwrap();
/// assert_eq!(ids, vec!["RULE1", "RULE2"]);
/// assert!(scoped);
/// ```
#[must_use]
pub fn parse_suppression_directive(text: &str) -> Option<(Vec<String>, bool)> {
    const IGNORE_FILE: &str = "zuit: ignore-file ";
    const IGNORE: &str = "zuit: ignore ";

    let text = text.trim();

    let (rest, file_scoped) = if let Some(r) = text.strip_prefix(IGNORE_FILE) {
        (r, true)
    } else if let Some(r) = text.strip_prefix(IGNORE) {
        (r, false)
    } else {
        return None;
    };

    let rule_ids: Vec<String> = rest
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if rule_ids.is_empty() {
        return None;
    }

    Some((rule_ids, file_scoped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span::{ByteOffset, Span};

    fn dummy_span() -> Span {
        Span::new(ByteOffset(0), ByteOffset(10))
    }

    #[test]
    fn empty_index_has_all_vecs_empty() {
        let index = SemanticIndex::new();
        assert!(index.functions.is_empty());
        assert!(index.types.is_empty());
        assert!(index.modules.is_empty());
        assert!(index.imports.is_empty());
        assert!(index.string_literals.is_empty());
        assert!(index.comments.is_empty());
        assert!(index.doc_comments.is_empty());
        assert!(index.suppressions.is_empty());
        assert!(index.regex_literals.is_empty());
    }

    #[test]
    fn regex_literals_in_index() {
        let mut index = SemanticIndex::new();
        index.regex_literals.push(RegexLiteral {
            id: NodeId(99),
            value: "(a+)+".to_string(),
            span: dummy_span(),
        });
        assert_eq!(index.regex_literals.len(), 1);
        assert_eq!(index.regex_literals[0].value, "(a+)+");
    }

    // ── parse_suppression_directive tests ─────────────────────────────────────

    #[test]
    fn parses_simple_ignore() {
        let result = parse_suppression_directive("zuit: ignore RULE1");
        assert!(result.is_some(), "expected Some, got None");
        let (ids, scoped) = result.unwrap();
        assert_eq!(ids, vec!["RULE1"]);
        assert!(!scoped);
    }

    #[test]
    fn parses_multiple_rules_comma_separated() {
        let result = parse_suppression_directive("zuit: ignore RULE1,RULE2");
        assert!(result.is_some());
        let (ids, scoped) = result.unwrap();
        assert_eq!(ids, vec!["RULE1", "RULE2"]);
        assert!(!scoped);
    }

    #[test]
    fn parses_multiple_rules_with_spaces() {
        let result = parse_suppression_directive("zuit: ignore RULE1, RULE2");
        assert!(result.is_some());
        let (ids, scoped) = result.unwrap();
        assert_eq!(ids, vec!["RULE1", "RULE2"]);
        assert!(!scoped);
    }

    #[test]
    fn parses_ignore_file_directive() {
        let result = parse_suppression_directive("zuit: ignore-file RULE1");
        assert!(result.is_some());
        let (ids, scoped) = result.unwrap();
        assert_eq!(ids, vec!["RULE1"]);
        assert!(scoped);
    }

    #[test]
    fn returns_none_for_unrelated_comment() {
        assert!(parse_suppression_directive("TODO: fix this").is_none());
        assert!(parse_suppression_directive("just a comment").is_none());
        assert!(parse_suppression_directive("FIXME: broken").is_none());
    }

    #[test]
    fn returns_none_for_directive_without_rule_id() {
        // "zuit: ignore " with trailing space but no rule id
        assert!(parse_suppression_directive("zuit: ignore ").is_none());
        assert!(parse_suppression_directive("zuit: ignore-file ").is_none());
    }

    #[test]
    fn tolerates_leading_whitespace() {
        let result = parse_suppression_directive("  zuit: ignore RULE_X");
        assert!(result.is_some());
        let (ids, scoped) = result.unwrap();
        assert_eq!(ids, vec!["RULE_X"]);
        assert!(!scoped);
    }

    #[test]
    fn complexity_metrics_default_is_zeroed() {
        let m = ComplexityMetrics::default();
        assert_eq!(m.cyclomatic, 0);
        assert_eq!(m.cognitive, 0);
        assert_eq!(m.max_nesting, 0);
        assert_eq!(m.returns, 0);
    }

    #[test]
    fn function_like_roundtrip() {
        let f = FunctionLike {
            id: NodeId(1),
            kind: FunctionKind::Function,
            name: Some("my_fn".to_string()),
            visibility: Visibility::Public,
            span: dummy_span(),
            body_span: dummy_span(),
            param_count: 2,
            is_async: false,
            is_test: false,
            doc: None,
            complexity: ComplexityMetrics {
                cyclomatic: 3,
                cognitive: 2,
                max_nesting: 1,
                returns: 1,
            },
            parent_name: None,
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: FunctionLike = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn semantic_index_serde_empty() {
        let index = SemanticIndex::new();
        let json = serde_json::to_string(&index).unwrap();
        let back: SemanticIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(index, back);
    }

    #[test]
    fn string_lit_in_index() {
        let mut index = SemanticIndex::new();
        index.string_literals.push(StringLit {
            id: NodeId(42),
            value: "hello".to_string(),
            span: dummy_span(),
        });
        assert_eq!(index.string_literals.len(), 1);
        assert_eq!(index.string_literals[0].value, "hello");
    }
}
