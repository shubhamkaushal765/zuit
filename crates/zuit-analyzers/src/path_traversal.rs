//! `SEC007-path-traversal` — heuristic detector for path-traversal
//! vulnerabilities (CWE-22).
//!
//! ## Detection strategy
//!
//! A finding is emitted for each source line that satisfies **both** of:
//!
//! 1. **File-operation call** — the line matches the regex:
//!    `(?i)\b(open|read_file|write_file|readFile\w*|writeFile\w*|fs\.read\w*|fs\.write\w*|fs\.open|std::fs::\w+|Path::new|PathBuf::from)\s*\(`
//!
//! 2. **Traversal signal** — the line contains EITHER:
//!    - A literal `..` substring (direct traversal indicator), OR
//!    - An interpolation marker (`${`, `f"…{`, `" + `, `' + `) **and** the file
//!      imports a web-framework module (`flask`, `fastapi`, `django`, `express`,
//!      `http`, `aiohttp`, `tornado`, `actix_web`, `axum`, `rocket`) — signalling
//!      that user-controlled input could reach this call.
//!
//! One finding is emitted per matching line. Severity: **High**.

use std::sync::OnceLock;

use regex::Regex;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages, span::Location,
};

/// Rule ID for the path-traversal check.
pub const RULE_ID: &str = "SEC007-path-traversal";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/SEC007-path-traversal.md",
    cwe: &["CWE-22"],
    owasp: &["A01:2021"],
};

/// Suggestion text for every finding emitted by this rule.
const SUGGESTION: &str = "Validate paths: canonicalize() / realpath() and assert the result \
    starts with an allowed base directory; reject inputs containing '..'.";

/// Returns the compiled regex that matches file-operation function calls.
///
/// Matches any of the following followed by optional whitespace and `(`:
/// - `open` / `read_file` / `write_file` — common language builtins
/// - `readFile*` / `writeFile*` — camelCase variants (including `readFileSync`)
/// - `fs.read*` / `fs.write*` / `fs.open` — Node.js `fs` module methods
/// - `std::fs::<fn>` — Rust `std::fs` calls (any function after the `::`)
/// - `Path::new` / `PathBuf::from` — Rust path construction
fn file_op_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(
            r"(?i)\b(open|read_file|write_file|readFile\w*|writeFile\w*|fs\.read\w*|fs\.write\w*|fs\.open|std::fs::\w+|Path::new|PathBuf::from)\s*\(",
        )
        .expect("invariant: file-op regex is valid")
    })
}

/// Web-framework import substrings (lowercase) that indicate user input could
/// reach file operations in the same file.
const WEB_FRAMEWORK_SUBSTRINGS: &[&str] = &[
    "flask",
    "fastapi",
    "django",
    "express",
    "http",
    "aiohttp",
    "tornado",
    "actix_web",
    "axum",
    "rocket",
];

/// Interpolation markers indicating dynamic path construction.
const INTERPOLATION_MARKERS: &[&str] = &[
    "${",    // JS/TS template literal
    "\" + ", // string concat (double-quoted)
    "' + ",  // string concat (single-quoted)
    "+ \"",  // reversed concat
    "+ '",   // reversed concat
];

/// Returns `true` if `line` contains an f-string interpolation marker.
fn has_fstring_interpolation(line: &str) -> bool {
    (line.contains("f\"") || line.contains("f'")) && line.contains('{')
}

/// Returns `true` if the file imports any web-framework module that could
/// expose user-controlled input to file operations.
fn imports_web_framework(file: &ParsedFile) -> bool {
    let index = file.index();
    index.imports.iter().any(|imp| {
        let lower = imp.path.to_lowercase();
        WEB_FRAMEWORK_SUBSTRINGS
            .iter()
            .any(|sub| lower.contains(sub))
    })
}

/// Returns `true` if `line` has any interpolation marker.
fn has_interpolation_marker(line: &str) -> bool {
    INTERPOLATION_MARKERS.iter().any(|m| line.contains(m)) || has_fstring_interpolation(line)
}

/// Analyzer that detects path-traversal vulnerabilities in file operations.
#[derive(Debug, Default)]
pub struct PathTraversalAnalyzer;

impl Analyzer for PathTraversalAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Security
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let source = file.source();
        let text = source.as_str();
        let file_op_re = file_op_pattern();
        let web_framework = imports_web_framework(file);
        let mut findings: Vec<Finding> = Vec::new();
        let mut byte_offset: usize = 0;

        for line in text.lines() {
            let line_start = byte_offset;
            byte_offset += line.len() + 1; // +1 for '\n'

            if !file_op_re.is_match(line) {
                continue;
            }

            let has_dotdot = line.contains("..");
            let has_interpolation = web_framework && has_interpolation_marker(line);

            if !has_dotdot && !has_interpolation {
                continue;
            }

            #[allow(clippy::cast_possible_truncation)]
            let start = zuit_core::span::ByteOffset(line_start as u32);
            #[allow(clippy::cast_possible_truncation)]
            let end = zuit_core::span::ByteOffset((line_start + line.len()) as u32);
            let span = zuit_core::span::Span::new(start, end);
            let (start_lc, end_lc) = source.span_to_linecols(span);

            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Security,
                rule_id: RULE_ID.to_string(),
                severity: Severity::High,
                message: format!(
                    "possible path traversal: file operation with unvalidated path on line {}",
                    start_lc.line,
                ),
                location: Location {
                    file: source.path.clone(),
                    span,
                    start: start_lc,
                    end: end_lc,
                },
                suggestion: Some(SUGGESTION.to_string()),
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

    // ── unit tests ────────────────────────────────────────────────────────────

    #[test]
    fn file_op_pattern_matches_open() {
        assert!(file_op_pattern().is_match("open(filename)"));
    }

    #[test]
    fn file_op_pattern_matches_path_new() {
        assert!(file_op_pattern().is_match("Path::new(user_path)"));
    }

    #[test]
    fn file_op_pattern_matches_fs_read_file() {
        assert!(file_op_pattern().is_match("fs.readFile(path, 'utf8', cb)"));
    }

    #[test]
    fn file_op_pattern_matches_std_fs() {
        assert!(file_op_pattern().is_match("std::fs::read(path)"));
    }

    #[test]
    fn file_op_pattern_does_not_match_random_word() {
        assert!(!file_op_pattern().is_match("let x = compute(a, b)"));
    }

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_path_traversal_positive() {
        let source = include_str!("../../../fixtures/python/path_traversal/main.py");
        let file = python_parse("fixtures/python/path_traversal/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = PathTraversalAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC007 finding for path_traversal Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings.iter().all(|f| f.cwe.iter().any(|c| c == "CWE-22")),
            "expected CWE-22 in finding.cwe"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.owasp.iter().any(|o| o == "A01:2021")),
            "expected A01:2021 in finding.owasp"
        );
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings should have a suggestion"
        );
    }

    // ── Python negative (healthy) ─────────────────────────────────────────────

    #[test]
    fn python_healthy_path_traversal_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = PathTraversalAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC007 findings for healthy Python fixture, got {findings:#?}"
        );
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_path_traversal_positive() {
        let source = include_str!("../../../fixtures/js/path_traversal/main.ts");
        let file = js_parse("fixtures/js/path_traversal/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = PathTraversalAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC007 finding for path_traversal JS fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── JS negative (healthy) ─────────────────────────────────────────────────

    #[test]
    fn js_healthy_path_traversal_negative() {
        let source = include_str!("../../../fixtures/js/healthy/main.ts");
        let file = js_parse("fixtures/js/healthy/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = PathTraversalAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC007 findings for healthy JS fixture, got {findings:#?}"
        );
    }

    // ── Rust positive ─────────────────────────────────────────────────────────

    #[test]
    fn rust_path_traversal_positive() {
        let source = include_str!("../../../fixtures/rust/path_traversal/lib.rs");
        let file = rust_parse("fixtures/rust/path_traversal/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = PathTraversalAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC007 finding for path_traversal Rust fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Rust negative (healthy) ───────────────────────────────────────────────

    #[test]
    fn rust_healthy_path_traversal_negative() {
        let source = include_str!("../../../fixtures/rust/healthy/lib.rs");
        let file = rust_parse("fixtures/rust/healthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = PathTraversalAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC007 findings for healthy Rust fixture, got {findings:#?}"
        );
    }
}
