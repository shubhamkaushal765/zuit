//! `MAINT014-commented-out-code` — flags comment blocks that look like
//! commented-out source code rather than English prose.
//!
//! The heuristic groups consecutive comment lines into blocks (a blank line
//! breaks a block), requires at least 3 lines, and fires when ≥50% of
//! non-blank lines contain at least one code-like token marker **and** at
//! least one line contains structural punctuation (`{`, `}`, or `;`) that
//! English prose almost never uses.

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    Span, SupportedLanguages, span::Location,
};

/// Rule ID for the commented-out-code check.
pub const RULE_ID: &str = "MAINT014-commented-out-code";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Info,
    doc_path: "docs/rules/MAINT014-commented-out-code.md",
    cwe: &["CWE-1085"],
    owasp: &[],
};

/// Tokens that indicate code-like content on a comment line.
///
/// The list is intentionally conservative to keep the false-positive rate low.
const CODE_TOKENS: &[&str] = &[
    "{",
    "}",
    ";",
    "=",
    "(",
    ")",
    "if ",
    "else",
    "for ",
    "while ",
    "return",
    "def ",
    "function ",
    "let ",
    "const ",
    "var ",
    "fn ",
    "pub ",
    "impl ",
    "class ",
];

/// Structural punctuation whose presence distinguishes code from English prose.
///
/// Includes `{`, `}`, `;` (common in C-family languages), and `(` / `)` for
/// function-call patterns.  Python block-openers use `:` at end-of-line — we
/// detect that separately via `has_structural_punct`.
const STRUCTURAL_PUNCT: &[char] = &['{', '}', ';', '(', ')'];

/// Returns `true` when the line text contains at least one code-like token.
fn has_code_token(text: &str) -> bool {
    CODE_TOKENS.iter().any(|t| text.contains(t))
}

/// Returns `true` when the line text contains structural punctuation.
fn has_structural_punct(text: &str) -> bool {
    text.chars().any(|c| STRUCTURAL_PUNCT.contains(&c))
}

/// Returns `true` when the line looks like a TODO/FIXME/NOTE-style annotation
/// that is already covered by `DOC002-todo-fixme`.
///
/// Pattern: optional whitespace then one or more uppercase ASCII letters
/// followed by `:`.
fn is_annotation_line(text: &str) -> bool {
    let trimmed = text.trim_start();
    // Count leading uppercase ASCII letters.
    let word_end = trimmed
        .char_indices()
        .take_while(|(_, c)| c.is_ascii_uppercase())
        .last()
        .map_or(0, |(i, c)| i + c.len_utf8());
    // Must have at least one uppercase letter and be followed by ':'.
    word_end > 0 && trimmed.get(word_end..word_end + 1) == Some(":")
}

/// Analyzer that detects contiguous comment blocks that look like commented-out
/// code rather than human-readable prose.
#[derive(Debug, Default)]
pub struct CommentedCodeAnalyzer;

impl Analyzer for CommentedCodeAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Maintainability
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
        let mut findings = Vec::new();

        // Collect (line_number, comment_text, span) for every comment.
        // `span_to_linecols` returns ((start_line, start_col), (end_line, end_col))
        // where lines are 1-indexed.
        let mut comment_lines: Vec<(u32, &str, Span)> = index
            .comments
            .iter()
            .map(|c| {
                let (start_lc, _end_lc) = source.span_to_linecols(c.span);
                (start_lc.line, c.text.as_str(), c.span)
            })
            .collect();

        // Sort by line number so we can group consecutive lines.
        comment_lines.sort_by_key(|(line, _, _)| *line);

        // Group into contiguous blocks (no blank line between them).
        // A "block" is a run where each comment is on line N+1 relative to the
        // previous comment.
        let mut i = 0;
        while i < comment_lines.len() {
            let block_start = i;
            // Extend the block as long as consecutive lines are adjacent.
            while i + 1 < comment_lines.len() && comment_lines[i + 1].0 == comment_lines[i].0 + 1 {
                i += 1;
            }
            let block_end = i; // inclusive index
            i += 1;

            let block = &comment_lines[block_start..=block_end];

            // Need at least 3 lines.
            if block.len() < 3 {
                continue;
            }

            // Skip if any line looks like a TODO/FIXME/NOTE annotation.
            if block.iter().any(|(_, text, _)| is_annotation_line(text)) {
                continue;
            }

            // Count non-blank lines and code-like lines.
            let non_blank: Vec<_> = block
                .iter()
                .filter(|(_, text, _)| !text.trim().is_empty())
                .collect();

            if non_blank.is_empty() {
                continue;
            }

            let code_like_count = non_blank
                .iter()
                .filter(|(_, text, _)| has_code_token(text))
                .count();

            let has_structural = non_blank
                .iter()
                .any(|(_, text, _)| has_structural_punct(text));

            // ≥50% of non-blank lines must look like code AND at least one
            // line must contain structural punctuation.
            if code_like_count * 2 < non_blank.len() || !has_structural {
                continue;
            }

            // Emit ONE finding per block, spanning from the first to the last
            // comment in the block.
            let first_span = block[0].2;
            let last_span = block[block.len() - 1].2;
            let block_span = Span::new(first_span.start, last_span.end);
            let (start_lc, _) = source.span_to_linecols(first_span);
            let (_, end_lc) = source.span_to_linecols(last_span);

            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Maintainability,
                rule_id: RULE_ID.to_string(),
                severity: Severity::Info,
                message: format!(
                    "Comment block of {} lines looks like commented-out code; \
                     remove or restore it.",
                    block.len()
                ),
                location: Location {
                    file: source.path.clone(),
                    span: block_span,
                    start: start_lc,
                    end: end_lc,
                },
                suggestion: Some(
                    "Delete dead code from comments rather than leaving it around. \
                     If this is intentional, add a prose explanation."
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

    fn python_parse(path: &str, source: &str) -> ParsedFile {
        let src = Arc::new(SourceFile::new(path, source.as_bytes().to_vec()));
        zuit_lang_python::PythonLanguage
            .parse(src)
            .expect("python parse failed")
    }

    fn rust_parse(path: &str, source: &str) -> ParsedFile {
        let src = Arc::new(SourceFile::new(path, source.as_bytes().to_vec()));
        zuit_lang_rust::RustLanguage
            .parse(src)
            .expect("rust parse failed")
    }

    fn make_ctx(config: &Config) -> AnalysisContext<'_> {
        AnalysisContext::new(config)
    }

    // ── Step 3.1 positive test ────────────────────────────────────────────────

    #[test]
    fn flags_commented_code_block_in_python() {
        // Three consecutive comment lines that look like Python code.
        let src = "x = 1\n# def foo(y):\n#     return y * 2\n# print(foo(x))\n";
        let file = python_parse("test.py", src);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CommentedCodeAnalyzer.analyze_file(&ctx, &file);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 MAINT014 finding, got {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── Step 3.3 negative tests ───────────────────────────────────────────────

    /// English prose that happens to contain the word "if" must NOT fire.
    #[test]
    fn does_not_flag_english_prose_with_if_token() {
        // Three prose comment lines with an "if" token but no structural
        // punctuation and not enough code-token density to fire.
        let src = "# This function takes a number. If you want to use it, read the docs.\n# Very helpful for understanding the API.\n# Also useful for other purposes.\n";
        let file = python_parse("test.py", src);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CommentedCodeAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "English prose must not fire MAINT014, got {findings:#?}"
        );
    }

    /// A single TODO annotation must NOT fire.
    #[test]
    fn does_not_flag_single_todo_annotation() {
        let src = "# TODO: rewrite this for clarity\n";
        let file = python_parse("test.py", src);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CommentedCodeAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "Single TODO must not fire MAINT014, got {findings:#?}"
        );
    }

    /// A two-line comment block (below the minimum threshold of 3) must NOT fire.
    #[test]
    fn does_not_flag_two_line_block() {
        let src = "# def foo(y):\n#     return y;\n";
        let file = python_parse("test.py", src);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CommentedCodeAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "Two-line block must not fire MAINT014, got {findings:#?}"
        );
    }

    /// ASCII art / section header separators must NOT fire (no code tokens).
    #[test]
    fn does_not_flag_ascii_separator_block() {
        let src = "# Section Header\n# ===========\n# More decoration\n";
        let file = python_parse("test.py", src);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CommentedCodeAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "ASCII separator block must not fire MAINT014, got {findings:#?}"
        );
    }

    /// Rust fixture: a commented-out function body should fire.
    #[test]
    fn flags_commented_code_block_in_rust() {
        let src = "fn main() {\n\
                   // let x = 1;\n\
                   // if x > 0 {\n\
                   //     return x;\n\
                   // }\n\
                   }\n";
        let file = rust_parse("test.rs", src);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CommentedCodeAnalyzer.analyze_file(&ctx, &file);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 MAINT014 finding in Rust, got {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    /// Positive fixture file for Python.
    #[test]
    fn python_commented_code_positive_fixture() {
        let source = include_str!("../../../fixtures/python/commented_code/positive.py");
        let file = python_parse("fixtures/python/commented_code/positive.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CommentedCodeAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 MAINT014 finding for python positive fixture, got 0"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    /// Negative fixture file for Python.
    #[test]
    fn python_commented_code_negative_fixture() {
        let source = include_str!("../../../fixtures/python/commented_code/negative.py");
        let file = python_parse("fixtures/python/commented_code/negative.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CommentedCodeAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT014 findings for python negative fixture, got {findings:#?}"
        );
    }
}
