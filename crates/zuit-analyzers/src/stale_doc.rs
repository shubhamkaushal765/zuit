//! `DOC004-stale-doc` — flags documentation comments that reference a
//! parameter name which no longer appears in the function's signature.
//!
//! ## Detection strategy
//!
//! For each [`FunctionLike`] whose `doc` is `Some(node_id)`:
//!
//! 1. Locate the matching [`DocComment`] by `id == node_id`.
//! 2. Extract documented parameter names from the doc text.  The following
//!    comment styles are supported:
//!    - **`JSDoc` / `TSDoc`**: `@param {type} name` or `@param name`
//!    - **Sphinx/reStructuredText**: `:param name:` or `:param type name:`
//!    - **Google-style Python**: `Args:` section with `name:` or `name (type):`
//!    - **Rustdoc**: `# Arguments` section with `` * `name` `` or `` - `name` ``
//! 3. Extract the signature region: source bytes
//!    `func.span.start .. func.body_span.start`.  Falls back to the whole span
//!    when the region is empty.
//! 4. For each documented name, check whether it appears as a whole word in the
//!    signature region.
//! 5. Emit one [`Finding`] per (function, missing-name) pair.
//!
//! Only [`FunctionKind::Function`] and [`FunctionKind::Method`] are checked;
//! closures, lambdas, and arrow functions are skipped.
//!
//! [`FunctionLike`]: zuit_core::FunctionLike
//! [`DocComment`]: zuit_core::index::DocComment
//! [`Finding`]: zuit_core::Finding

use std::sync::OnceLock;

use regex::Regex;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages,
    index::FunctionKind,
    span::{Location, Span},
};

/// Rule ID for the stale-doc check.
pub const RULE_ID: &str = "DOC004-stale-doc";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/DOC004-stale-doc.md",
    cwe: &[],
    owasp: &[],
};

// ── compiled regex patterns (OnceLock) ───────────────────────────────────────

/// `JSDoc` / `TSDoc`: `@param {optional_type} name` or `@param name`.
///
/// Examples:
/// - `@param foo`
/// - `@param {string} foo`
/// - `@param {T} foo - description`
fn jsdoc_param_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"@param\s+(?:\{[^}]*\}\s*)?([A-Za-z_][A-Za-z0-9_]*)")
            .expect("invariant: jsdoc param pattern is valid")
    })
}

/// Sphinx / RST: `:param name:` or `:param type name:`.
///
/// We capture the last identifier before the closing `:`.
fn sphinx_param_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r":param\s+(?:[A-Za-z_][A-Za-z0-9_]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:")
            .expect("invariant: sphinx param pattern is valid")
    })
}

/// Rustdoc `# Arguments` bullet: `` * `name` - desc `` or `` - `name`: desc ``.
fn rustdoc_arg_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"[*\-]\s+`([A-Za-z_][A-Za-z0-9_]*)`")
            .expect("invariant: rustdoc arg pattern is valid")
    })
}

// ── parameter-name extraction ─────────────────────────────────────────────────

/// Returns `true` if `text` appears to contain a rustdoc `# Arguments`
/// section.
fn has_rustdoc_arguments_section(text: &str) -> bool {
    text.contains("# Arguments") || text.contains("## Arguments")
}

/// Returns `true` if `text` appears to contain a Google-style `Args:` section.
fn has_google_args_section(text: &str) -> bool {
    // Match `Args:` at any indentation level.
    text.lines().any(|l| l.trim() == "Args:")
}

/// Extract documented parameter names from a Google-style `Args:` block.
///
/// Lines after `Args:` that are indented relative to the section header and
/// start with `name:` or `name (type):` contribute a name.  Extraction stops
/// at the first non-indented line that is not blank.
fn extract_google_params(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_args = false;
    // The indentation of the `Args:` header line (so we know what counts as
    // "indented" for the parameter lines that follow it).
    let mut header_indent = 0usize;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "Args:" {
            in_args = true;
            header_indent = line.len() - line.trim_start().len();
            continue;
        }
        if !in_args {
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        let this_indent = line.len() - line.trim_start().len();
        // A line that is NOT more indented than the header ends the block.
        if this_indent <= header_indent {
            in_args = false;
            continue;
        }
        // Capture the identifier at the start of the (trimmed) line.
        let ident: String = trimmed
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !ident.is_empty() {
            // The next non-identifier character should be `:` or ` ` or `(`.
            let after = &trimmed[ident.len()..];
            let next = after.chars().next().unwrap_or(' ');
            if matches!(next, ':' | ' ' | '(') {
                names.push(ident);
            }
        }
    }
    names
}

/// Extract all documented parameter names from `doc_text`.
///
/// We apply each heuristic in order and collect results from all of them so
/// that a mixed-format doc comment (unlikely but possible) is fully covered.
/// Returns names in encounter order, deduplicated.
fn extract_param_names(doc_text: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();

    // 1. JSDoc / TSDoc (@param)
    for cap in jsdoc_param_re().captures_iter(doc_text) {
        if let Some(m) = cap.get(1) {
            let name = m.as_str().to_string();
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }

    // 2. Sphinx / RST (:param name:)
    for cap in sphinx_param_re().captures_iter(doc_text) {
        if let Some(m) = cap.get(1) {
            let name = m.as_str().to_string();
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }

    // 3. Rustdoc `# Arguments` bullets
    if has_rustdoc_arguments_section(doc_text) {
        for cap in rustdoc_arg_re().captures_iter(doc_text) {
            if let Some(m) = cap.get(1) {
                let name = m.as_str().to_string();
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
    }

    // 4. Google-style `Args:` block
    if has_google_args_section(doc_text) {
        for name in extract_google_params(doc_text) {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }

    names
}

// ── whole-word check (no per-call regex) ─────────────────────────────────────

/// Returns `true` if `needle` appears as a whole word anywhere in `haystack`.
///
/// A "whole word" match means:
/// - The character immediately before the match (if any) is NOT
///   `[A-Za-z0-9_]`.
/// - The character immediately after the match (if any) is NOT
///   `[A-Za-z0-9_]`.
fn contains_whole_word(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let hay = haystack.as_bytes();
    let ndl = needle.as_bytes();
    let nlen = ndl.len();

    let mut i = 0usize;
    while i + nlen <= hay.len() {
        if hay[i..i + nlen] == *ndl {
            // Check left boundary.
            let left_ok = i == 0 || !is_word_byte(hay[i - 1]);
            // Check right boundary.
            let right_ok = i + nlen == hay.len() || !is_word_byte(hay[i + nlen]);
            if left_ok && right_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[inline]
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

// ── analyzer ─────────────────────────────────────────────────────────────────

/// Analyzer that flags documentation comments referencing parameter names
/// absent from the function signature.
#[derive(Debug, Default)]
pub struct StaleDocAnalyzer;

impl Analyzer for StaleDocAnalyzer {
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
        let src_str = source.as_str();
        let index = file.index();

        if index.doc_comments.is_empty() || index.functions.is_empty() {
            return vec![];
        }

        let mut findings = Vec::new();

        for func in &index.functions {
            // Only check named Function / Method kinds.
            match func.kind {
                FunctionKind::Function | FunctionKind::Method => {}
                _ => continue,
            }
            let Some(_name) = func.name.as_deref() else {
                continue;
            };
            let Some(doc_id) = func.doc else {
                continue;
            };

            // Find the matching DocComment.
            let Some(doc) = index.doc_comments.iter().find(|d| d.id == doc_id) else {
                continue;
            };

            // Extract documented param names; skip if none found.
            let param_names = extract_param_names(&doc.text);
            if param_names.is_empty() {
                continue;
            }

            // Compute the signature region: span.start..body_span.start.
            let sig_start = func.span.start.0 as usize;
            let sig_end_raw = func.body_span.start.0 as usize;

            // If body_span.start <= span.start, fall back to the whole span.
            let (sig_start, sig_end) = if sig_end_raw > sig_start {
                (sig_start, sig_end_raw.min(src_str.len()))
            } else {
                let end = (func.span.end.0 as usize).min(src_str.len());
                (sig_start.min(end), end)
            };

            // Safely extract the signature slice (handle UTF-8 boundaries).
            let Some(sig_region) = src_str.get(sig_start..sig_end) else {
                continue;
            };

            // Check each documented name against the signature region.
            for name in &param_names {
                if !contains_whole_word(sig_region, name) {
                    let span = Span::new(func.span.start, func.span.start);
                    let (start_lc, end_lc) = source.span_to_linecols(span);

                    findings.push(Finding {
                        analyzer: AnalyzerId::new(RULE_ID),
                        dimension: Dimension::Documentation,
                        rule_id: RULE_ID.to_string(),
                        severity: Severity::Low,
                        message: format!(
                            "doc references parameter `{name}` which is not in the function signature"
                        ),
                        location: Location {
                            file: source.path.clone(),
                            span,
                            start: start_lc,
                            end: end_lc,
                        },
                        suggestion: Some(format!(
                            "Doc references parameter `{name}` which is not in the function \
                             signature; remove or rename the doc entry."
                        )),
                        references: vec![],
                        cwe: META.cwe_vec(),
                        owasp: META.owasp_vec(),
                    });
                }
            }
        }

        findings
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Config, Language, SourceFile};
    use std::sync::Arc;

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

    // ── unit tests for helpers ────────────────────────────────────────────────

    #[test]
    fn whole_word_basic() {
        assert!(contains_whole_word("fn add(x: i32)", "x"));
        assert!(contains_whole_word("fn add(x: i32, y: i32)", "y"));
        assert!(!contains_whole_word("fn add(xy: i32)", "x"));
        assert!(!contains_whole_word("fn add(xy: i32)", "y"));
    }

    #[test]
    fn extract_jsdoc_params() {
        let doc = "/**\n * @param {number} foo - first\n * @param bar - second\n */";
        let names = extract_param_names(doc);
        assert!(
            names.contains(&"foo".to_string()),
            "expected foo in {names:?}"
        );
        assert!(
            names.contains(&"bar".to_string()),
            "expected bar in {names:?}"
        );
    }

    #[test]
    fn extract_sphinx_params() {
        let doc = ":param x: the first operand\n:param y: the second operand";
        let names = extract_param_names(doc);
        assert!(names.contains(&"x".to_string()), "expected x in {names:?}");
        assert!(names.contains(&"y".to_string()), "expected y in {names:?}");
    }

    #[test]
    fn extract_rustdoc_params() {
        let doc = "Compute something.\n\n# Arguments\n\n* `a` - first\n* `b` - second";
        let names = extract_param_names(doc);
        assert!(names.contains(&"a".to_string()), "expected a in {names:?}");
        assert!(names.contains(&"b".to_string()), "expected b in {names:?}");
    }

    #[test]
    fn no_param_markers_returns_empty() {
        let doc = "Returns the sum of two numbers.";
        let names = extract_param_names(doc);
        assert!(names.is_empty(), "expected empty, got {names:?}");
    }

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_stale_doc_positive() {
        let source = include_str!("../../../fixtures/python/stale_doc/main.py");
        let file = python_parse("fixtures/python/stale_doc/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = StaleDocAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 DOC004 finding for stale_doc Python fixture"
        );
        assert!(
            findings.iter().all(|f| f.rule_id == RULE_ID),
            "all findings must have rule_id == {RULE_ID}"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.dimension == Dimension::Documentation),
            "all findings must have Dimension::Documentation"
        );
        assert!(
            findings.iter().all(|f| f.severity == Severity::Low),
            "all findings must have Severity::Low"
        );
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings must have a suggestion"
        );
    }

    // ── Python negative ───────────────────────────────────────────────────────

    #[test]
    fn python_not_stale_doc_negative() {
        let source = include_str!("../../../fixtures/python/not_stale_doc/main.py");
        let file = python_parse("fixtures/python/not_stale_doc/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = StaleDocAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 DOC004 findings for not_stale_doc Python fixture, got {findings:#?}"
        );
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_stale_doc_positive() {
        let source = include_str!("../../../fixtures/js/stale_doc/main.ts");
        let file = js_parse("fixtures/js/stale_doc/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = StaleDocAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 DOC004 finding for stale_doc JS fixture"
        );
        assert!(
            findings.iter().all(|f| f.rule_id == RULE_ID),
            "all findings must have rule_id == {RULE_ID}"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.dimension == Dimension::Documentation),
            "all findings must have Dimension::Documentation"
        );
        assert!(
            findings.iter().all(|f| f.severity == Severity::Low),
            "all findings must have Severity::Low"
        );
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings must have a suggestion"
        );
    }

    // ── JS negative ───────────────────────────────────────────────────────────

    #[test]
    fn js_not_stale_doc_negative() {
        let source = include_str!("../../../fixtures/js/not_stale_doc/main.ts");
        let file = js_parse("fixtures/js/not_stale_doc/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = StaleDocAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 DOC004 findings for not_stale_doc JS fixture, got {findings:#?}"
        );
    }

    // ── Rust positive ─────────────────────────────────────────────────────────

    #[test]
    fn rust_stale_doc_positive() {
        let source = include_str!("../../../fixtures/rust/stale_doc/lib.rs");
        let file = rust_parse("fixtures/rust/stale_doc/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = StaleDocAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 DOC004 finding for stale_doc Rust fixture"
        );
        assert!(
            findings.iter().all(|f| f.rule_id == RULE_ID),
            "all findings must have rule_id == {RULE_ID}"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.dimension == Dimension::Documentation),
            "all findings must have Dimension::Documentation"
        );
        assert!(
            findings.iter().all(|f| f.severity == Severity::Low),
            "all findings must have Severity::Low"
        );
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings must have a suggestion"
        );
    }

    // ── Rust negative ─────────────────────────────────────────────────────────

    #[test]
    fn rust_not_stale_doc_negative() {
        let source = include_str!("../../../fixtures/rust/not_stale_doc/lib.rs");
        let file = rust_parse("fixtures/rust/not_stale_doc/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = StaleDocAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 DOC004 findings for not_stale_doc Rust fixture, got {findings:#?}"
        );
    }

    // ── No doc comment emits nothing ─────────────────────────────────────────

    #[test]
    fn function_without_doc_emits_nothing() {
        let source = r"
pub fn add(x: i32, y: i32) -> i32 {
    x + y
}
";
        let file = rust_parse("synthetic.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = StaleDocAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "function without doc must emit 0 DOC004 findings, got {findings:#?}"
        );
    }
}
