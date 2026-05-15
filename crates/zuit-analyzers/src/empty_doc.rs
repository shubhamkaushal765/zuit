//! `DOC003-empty-doc` — flags documentation comments whose content is
//! empty, purely punctuation, or exactly the identifier name.
//!
//! ## Detection strategy
//!
//! Walk [`SemanticIndex::doc_comments`].  For each entry, normalise the text
//! by stripping leading/trailing whitespace and the doc-comment markers
//! (`///`, `//!`, `/**`, `*`, `#`).  The normalised text is flagged if it:
//!
//! 1. Is empty after stripping.
//! 2. Consists entirely of non-alphanumeric characters (e.g. `"."`, `"?"`,
//!    `"TODO"`-class punctuation).
//! 3. Equals (case-insensitively) the name of the function or type that
//!    the comment is attached to (i.e. [`FunctionLike::doc`] or
//!    [`TypeDecl::doc`] points at this comment).
//!
//! One finding per flagged doc-comment is emitted.
//!
//! [`SemanticIndex::doc_comments`]: zuit_core::SemanticIndex::doc_comments
//! [`FunctionLike::doc`]: zuit_core::FunctionLike::doc
//! [`TypeDecl::doc`]: zuit_core::TypeDecl::doc

use std::collections::HashMap;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, NodeId, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
    span::{Location, Span},
};

/// Rule ID for the empty-doc check.
pub const RULE_ID: &str = "DOC003-empty-doc";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Info,
    doc_path: "docs/rules/DOC003-empty-doc.md",
    cwe: &[],
    owasp: &[],
};

/// Strip doc-comment markers and whitespace from a raw doc-comment text,
/// returning the normalised content.
///
/// Handles:
/// - Rust `///` / `//!` line-doc markers
/// - `JSDoc` `/**`, `*/`, leading ` * ` per-line markers
/// - Python `"""` / `'''` docstring markers (if present)
fn normalise_doc(text: &str) -> String {
    let mut result = String::new();
    for line in text.lines() {
        // Strip common leading markers.
        let stripped = line
            .trim_start()
            .trim_start_matches("///")
            .trim_start_matches("//!")
            .trim_start_matches("/**")
            .trim_start_matches("*/")
            .trim_start_matches('*')
            .trim_start_matches("\"\"\"")
            .trim_start_matches("'''")
            .trim();
        if !stripped.is_empty() {
            if !result.is_empty() {
                result.push(' ');
            }
            result.push_str(stripped);
        }
    }
    result.trim().to_string()
}

/// Returns `true` if the normalised text is empty or consists entirely of
/// non-alphanumeric characters (e.g. single punctuation like `.`, `?`, `!`).
fn is_placeholder(normalised: &str) -> bool {
    if normalised.is_empty() {
        return true;
    }
    // If every char is non-alphanumeric and the text is very short, it's a
    // placeholder (e.g. ".", "?", "-").
    if normalised.chars().all(|c| !c.is_alphanumeric()) {
        return true;
    }
    false
}

/// Returns `true` if the normalised text exactly matches the given identifier
/// name (case-insensitive).
fn is_name_as_doc(normalised: &str, name: &str) -> bool {
    normalised.to_lowercase() == name.to_lowercase()
}

/// Analyzer that flags empty or placeholder documentation comments.
#[derive(Debug, Default)]
pub struct EmptyDocAnalyzer;

impl Analyzer for EmptyDocAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Documentation
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let source = file.source();
        let index = file.index();

        if index.doc_comments.is_empty() {
            return vec![];
        }

        // Build a map from NodeId → parent name (function or type name).
        let mut doc_to_name: HashMap<NodeId, &str> = HashMap::new();
        for func in &index.functions {
            if let (Some(doc_id), Some(name)) = (func.doc, func.name.as_deref()) {
                doc_to_name.insert(doc_id, name);
            }
        }
        for ty in &index.types {
            if let Some(doc_id) = ty.doc {
                doc_to_name.insert(doc_id, &ty.name);
            }
        }

        let mut findings = Vec::new();

        for doc in &index.doc_comments {
            let normalised = normalise_doc(&doc.text);

            let reason = if is_placeholder(&normalised) {
                "empty or punctuation-only doc comment"
            } else if let Some(&parent_name) = doc_to_name.get(&doc.id)
                && is_name_as_doc(&normalised, parent_name)
            {
                "doc comment text is just the identifier name"
            } else {
                continue;
            };

            let span = Span::new(doc.span.start, doc.span.start);
            let (start_lc, end_lc) = source.span_to_linecols(span);

            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Documentation,
                rule_id: RULE_ID.to_string(),
                severity: Severity::Info,
                message: reason.to_string(),
                location: Location {
                    file: source.path.clone(),
                    span,
                    start: start_lc,
                    end: end_lc,
                },
                suggestion: Some(
                    "Write a meaningful one-sentence summary or remove the placeholder comment."
                        .to_string(),
                ),
                references: vec![],
                cwe: META.cwe_vec(),
                owasp: META.owasp_vec(),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use zuit_core::{Config, Language, SourceFile};

    fn rust_parse(path: &str, source: &str) -> ParsedFile {
        let src = Arc::new(SourceFile::new(path, source.as_bytes().to_vec()));
        zuit_lang_rust::RustLanguage
            .parse(src)
            .expect("rust parse failed")
    }

    fn python_parse(path: &str, source: &str) -> ParsedFile {
        let src = Arc::new(SourceFile::new(path, source.as_bytes().to_vec()));
        zuit_lang_python::PythonLanguage
            .parse(src)
            .expect("python parse failed")
    }

    fn js_parse(path: &str, source: &str) -> ParsedFile {
        let src = Arc::new(SourceFile::new(path, source.as_bytes().to_vec()));
        zuit_lang_js::JsLanguage
            .parse(src)
            .expect("js parse failed")
    }

    fn make_ctx(config: &Config) -> AnalysisContext<'_> {
        AnalysisContext::new(config)
    }

    // ── normalise helpers ─────────────────────────────────────────────────────

    #[test]
    fn normalise_empty_rust_doc() {
        assert_eq!(normalise_doc(""), "");
        assert_eq!(normalise_doc("\n"), "");
    }

    #[test]
    fn normalise_strips_rust_markers() {
        assert_eq!(normalise_doc("/// Hello world"), "Hello world");
        assert_eq!(normalise_doc(" ///  Hello "), "Hello");
    }

    #[test]
    fn normalise_strips_jsdoc_star() {
        assert_eq!(normalise_doc("* Description"), "Description");
        assert_eq!(normalise_doc("/**\n * Hello\n */"), "Hello");
    }

    #[test]
    fn is_placeholder_detects_empty() {
        assert!(is_placeholder(""));
        assert!(is_placeholder("."));
        assert!(is_placeholder("?!"));
    }

    #[test]
    fn is_placeholder_rejects_real_text() {
        assert!(!is_placeholder("Returns the sum of a and b"));
        assert!(!is_placeholder("TODO: implement"));
    }

    // ── Rust positive ─────────────────────────────────────────────────────────

    #[test]
    fn rust_empty_doc_positive() {
        let source = include_str!("../../../fixtures/rust/empty_doc/lib.rs");
        let file = rust_parse("fixtures/rust/empty_doc/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = EmptyDocAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 DOC003 finding for empty_doc Rust fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings should have a suggestion"
        );
    }

    // ── Rust negative ─────────────────────────────────────────────────────────

    #[test]
    fn rust_good_doc_negative() {
        let source = include_str!("../../../fixtures/rust/good_doc/lib.rs");
        let file = rust_parse("fixtures/rust/good_doc/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = EmptyDocAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 DOC003 findings for good_doc Rust fixture, got {findings:#?}"
        );
    }

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_empty_doc_positive() {
        let source = include_str!("../../../fixtures/python/empty_doc/main.py");
        let file = python_parse("fixtures/python/empty_doc/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = EmptyDocAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 DOC003 finding for empty_doc Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Python negative ───────────────────────────────────────────────────────

    #[test]
    fn python_good_doc_negative() {
        let source = include_str!("../../../fixtures/python/good_doc/main.py");
        let file = python_parse("fixtures/python/good_doc/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = EmptyDocAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 DOC003 findings for good_doc Python fixture, got {findings:#?}"
        );
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_empty_doc_positive() {
        let source = include_str!("../../../fixtures/js/empty_doc/main.ts");
        let file = js_parse("fixtures/js/empty_doc/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = EmptyDocAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 DOC003 finding for empty_doc JS fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── JS negative ───────────────────────────────────────────────────────────

    #[test]
    fn js_good_doc_negative() {
        let source = include_str!("../../../fixtures/js/good_doc/main.ts");
        let file = js_parse("fixtures/js/good_doc/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = EmptyDocAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 DOC003 findings for good_doc JS fixture, got {findings:#?}"
        );
    }
}
