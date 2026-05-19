//! `MAINT015-deprecated-function` — flags JavaScript/TypeScript function and
//! class declarations preceded by a `JSDoc` block that contains `@deprecated`
//! (CWE-477).
//!
//! # Detection
//!
//! `oxc` does not attach `JSDoc` to AST nodes, so we scan the source text:
//!
//! 1. Find every `/** … */` block whose body contains the literal `@deprecated`.
//! 2. Skip whitespace/blank lines after the block's `*/`.
//! 3. The next non-whitespace fragment must begin with a recognised
//!    declaration keyword: `function`, `async function`, `class`,
//!    `export function`, `export async function`, `export class`,
//!    `export default function`, `export default class`.
//! 4. Emit one finding anchored at the declaration's start.
//!
//! # Languages
//!
//! JavaScript and TypeScript only.

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, ByteOffset, Dimension, Finding, LanguageId, Location, ParsedFile,
    RuleMeta, Severity, SourceFile, Span, SupportedLanguages,
};

/// The stable rule ID.
const RULE_ID: &str = "MAINT015-deprecated-function";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/MAINT015-deprecated-function.md",
    cwe: &["CWE-477"],
    owasp: &[],
};

/// Analyzer that emits `MAINT015-deprecated-function` for JS/TS declarations
/// preceded by a `JSDoc` block containing `@deprecated`.
pub struct JsDeprecatedFunctionAnalyzer;

impl zuit_core::Analyzer for JsDeprecatedFunctionAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Maintainability
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::Only(smallvec![LanguageId("javascript")])
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let source = file.source();
        let text = source.as_str();
        let file_path = source.path.clone();

        find_deprecated_sites(text)
            .into_iter()
            .map(|(start, end, kind)| {
                // Source offsets in `oxc` are also `u32`; sources larger than 4 GiB
                // are not supported by the parser, so the cast is safe.
                #[allow(clippy::cast_possible_truncation)]
                let span = Span::new(ByteOffset(start as u32), ByteOffset(end as u32));
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Maintainability,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "{kind} marked `@deprecated` in JSDoc — schedule it for removal"
                    ),
                    location: Location {
                        file: file_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Plan a removal milestone for this deprecated declaration and \
                         migrate callers to the supported replacement."
                            .to_string(),
                    ),
                    references: vec!["https://cwe.mitre.org/data/definitions/477.html".to_string()],
                    cwe: META.cwe_vec(),
                    owasp: META.owasp_vec(),
                }
            })
            .collect()
    }
}

// ── source-text scanner ──────────────────────────────────────────────────────

/// Returns `(decl_start, decl_end, kind)` for every declaration in `source`
/// preceded by a `JSDoc` block whose body contains `@deprecated`.
fn find_deprecated_sites(source: &str) -> Vec<(usize, usize, &'static str)> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel_open) = source[search_from..].find("/**") {
        let open = search_from + rel_open;
        let after_open = open + 3;
        let Some(rel_close) = source[after_open..].find("*/") else {
            break;
        };
        let close = after_open + rel_close;
        let body = &source[after_open..close];
        // Require @deprecated as a tag (preceded by whitespace or `*`).
        if jsdoc_has_deprecated_tag(body) {
            let after_close = close + 2;
            // Skip whitespace (incl. newlines) until the next non-space byte.
            let mut i = after_close;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if let Some(kind) = match_decl_keyword(&source[i..]) {
                let decl_end = i + kind.0;
                out.push((i, decl_end, kind.1));
            }
        }
        search_from = close + 2;
    }
    out
}

/// Returns `true` if `body` (a `JSDoc` block body) contains a `@deprecated` tag
/// at a tag position (preceded by whitespace, the start of the body, or `*`).
fn jsdoc_has_deprecated_tag(body: &str) -> bool {
    let needle = "@deprecated";
    let mut from = 0;
    while let Some(rel) = body[from..].find(needle) {
        let pos = from + rel;
        // Tag must be at the very start or preceded by whitespace / `*`.
        let preceded_ok = pos == 0
            || body.as_bytes()[pos - 1].is_ascii_whitespace()
            || body.as_bytes()[pos - 1] == b'*';
        // Tag must be followed by whitespace / end-of-block / newline.
        let after = pos + needle.len();
        let followed_ok = after >= body.len() || !body.as_bytes()[after].is_ascii_alphanumeric();
        if preceded_ok && followed_ok {
            return true;
        }
        from = pos + needle.len();
    }
    false
}

/// If `rest` starts with a recognised declaration keyword, returns
/// `(consumed_len, kind_label)`.  `consumed_len` is the number of bytes
/// covered by the declaration keyword(s) and identifier — used to span the
/// finding tightly.
fn match_decl_keyword(rest: &str) -> Option<(usize, &'static str)> {
    // Skip an optional leading `export` and `export default`.
    // After each keyword, also skip whitespace before looking for the next.
    let mut head = rest;
    if let Some(after) = strip_keyword(head, "export") {
        head = after.trim_start();
        if let Some(after_default) = strip_keyword(head, "default") {
            head = after_default.trim_start();
        }
    }
    // Compute the offset of `head` inside `rest`.
    let head_offset = rest.len() - head.len();

    // Match the actual declarator.
    let (advance, kind) = if let Some(after) = strip_keyword(head, "async") {
        let next = after.trim_start();
        if let Some(after_fn) = strip_keyword(next, "function") {
            (head.len() - after_fn.len(), "async function")
        } else {
            return None;
        }
    } else if let Some(after) = strip_keyword(head, "function") {
        (head.len() - after.len(), "function")
    } else if let Some(after) = strip_keyword(head, "class") {
        (head.len() - after.len(), "class")
    } else {
        return None;
    };
    Some((head_offset + advance, kind))
}

/// If `rest` starts with the bare word `keyword` (followed by ASCII
/// whitespace), returns `Some(remainder)` where `remainder` is the text
/// after the keyword (whitespace is **not** consumed).
fn strip_keyword<'a>(rest: &'a str, keyword: &str) -> Option<&'a str> {
    let bytes = rest.as_bytes();
    let kw = keyword.as_bytes();
    if bytes.len() < kw.len() {
        return None;
    }
    if &bytes[..kw.len()] != kw {
        return None;
    }
    // Must be followed by whitespace (or end of input).
    match bytes.get(kw.len()) {
        None => Some(""),
        Some(b) if b.is_ascii_whitespace() => Some(&rest[kw.len()..]),
        _ => None,
    }
}

// Re-export `SourceFile` so the analyzer body in this module compiles
// even though we use it only via `source.as_str()` above.
#[allow(dead_code)]
fn _ensure_source_file_in_scope(_: &SourceFile) {}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse as js_parse;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, LanguageId, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.ts", src.as_bytes().to_vec()));
        let parsed = js_parse::parse(source).expect("parse failed");
        let analyzer = JsDeprecatedFunctionAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    #[test]
    fn flags_function_with_deprecated_jsdoc() {
        let src = r"
            /**
             * @deprecated use newFn() instead
             */
            function oldFn() { return 1; }
        ";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("function"));
    }

    #[test]
    fn flags_async_function_with_deprecated_jsdoc() {
        let src = r"
            /**
             * @deprecated
             */
            async function oldFn() {}
        ";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].message.contains("async function"));
    }

    #[test]
    fn flags_class_with_deprecated_jsdoc() {
        let src = r"
            /**
             * @deprecated rewritten as NewClass
             */
            class OldClass {}
        ";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].message.contains("class"));
    }

    #[test]
    fn flags_export_function_with_deprecated_jsdoc() {
        let src = r"
            /**
             * @deprecated
             */
            export function oldExport() {}
        ";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
    }

    #[test]
    fn flags_export_default_class_with_deprecated_jsdoc() {
        let src = r"
            /**
             * @deprecated
             */
            export default class OldDefault {}
        ";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
    }

    #[test]
    fn flags_multiple_deprecated_declarations() {
        let src = r"
            /** @deprecated */
            function a() {}

            /** @deprecated */
            class B {}
        ";
        let findings = analyze(src);
        assert_eq!(findings.len(), 2, "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_plain_function() {
        assert!(analyze("function good() { return 1; }").is_empty());
    }

    #[test]
    fn does_not_flag_function_without_deprecated_tag() {
        let src = r"
            /**
             * A documented function.
             * @param x  the input
             */
            function fine(x) { return x + 1; }
        ";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn does_not_flag_word_deprecated_in_prose() {
        // `deprecated` without `@` is not a JSDoc tag.
        let src = r"
            /**
             * This function is not deprecated despite the word here.
             */
            function fine() {}
        ";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn does_not_flag_jsdoc_far_from_declaration() {
        // A JSDoc block followed by unrelated non-decl statements should
        // not falsely tag the next decl.
        let src = r"
            /** @deprecated */
            const x = 1;
            function unrelated() {}
        ";
        // Only `const` is being attached the tag, and `const` is not a
        // recognised declaration kind in v1 — must not flag `unrelated`.
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn does_not_flag_line_comment_with_deprecated() {
        // Line comments are not JSDoc blocks.
        let src = "// @deprecated\nfunction fine() {}\n";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn does_not_flag_block_comment_with_deprecated() {
        // Plain block comments (single `*`) are not JSDoc blocks.
        let src = "/* @deprecated */\nfunction fine() {}\n";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn supported_languages_is_javascript_only() {
        let analyzer = JsDeprecatedFunctionAnalyzer;
        assert!(
            analyzer
                .supported_languages()
                .supports(LanguageId("javascript"))
        );
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
    }
}
