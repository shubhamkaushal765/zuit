//! `SEC006-sql-injection` — heuristic detector for SQL injection via string
//! interpolation (CWE-89).
//!
//! ## Detection strategy
//!
//! A finding is emitted for each source line that satisfies **all three** of
//! the following criteria simultaneously:
//!
//! 1. **SQL keyword** — the line matches the regex
//!    `(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|FROM|JOIN|WHERE)\b`.
//!
//! 2. **Quote character** — the line contains at least one of `"`, `'`, or `` ` ``.
//!
//! 3. **Interpolation marker** — the line contains at least one of:
//!    - Python f-string brace: `{` (when the line also starts with `f"` or `f'`)
//!    - Python percent-format: `% (`
//!    - `.format(`
//!    - JS/TS template-literal: `${`
//!    - String concatenation: `" + `, `' + `, or `` ` + ``
//!
//! One finding is emitted per matching line, located at the start of the line.
//! Severity: **High**.

use std::sync::OnceLock;

use regex::Regex;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages, span::Location,
};

/// Rule ID for the SQL-injection check.
pub const RULE_ID: &str = "SEC006-sql-injection";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/SEC006-sql-injection.md",
    cwe: &["CWE-89"],
    owasp: &["A03:2021"],
};

/// Suggestion text for every finding emitted by this rule.
const SUGGESTION: &str = "Use parameterised queries / prepared statements \
    (e.g. cursor.execute(sql, params), Knex/Sequelize bind variables).";

/// Returns the compiled regex that matches SQL keywords.
fn sql_keyword_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|FROM|JOIN|WHERE)\b")
            .expect("invariant: sql-keyword regex is valid")
    })
}

/// Interpolation markers that indicate user-controlled data is being spliced
/// into a SQL string.
const INTERPOLATION_MARKERS: &[&str] = &[
    "${",  // JS/TS template literal
    "% (", // Python percent-format
    ".format(", "\" + ", // string concat (double-quoted)
    "' + ",  // string concat (single-quoted)
    "` + ",  // string concat (backtick)
];

/// Returns `true` if `line` contains an f-string interpolation marker.
///
/// Detects lines that open an f-string (`f"` or `f'`) and contain a `{`
/// brace (which introduces a format expression).
fn has_fstring_interpolation(line: &str) -> bool {
    let trimmed = line.trim_start();
    (trimmed.contains("f\"") || trimmed.contains("f'")) && trimmed.contains('{')
}

/// Returns `true` if `line` contains any known interpolation marker.
fn has_interpolation(line: &str) -> bool {
    INTERPOLATION_MARKERS
        .iter()
        .any(|marker| line.contains(marker))
        || has_fstring_interpolation(line)
}

/// Returns `true` if `line` contains at least one quote character.
fn has_quote(line: &str) -> bool {
    line.contains('"') || line.contains('\'') || line.contains('`')
}

/// Analyzer that detects SQL injection via string interpolation heuristics.
#[derive(Debug, Default)]
pub struct SqlInjectionAnalyzer;

impl Analyzer for SqlInjectionAnalyzer {
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
        let sql_re = sql_keyword_pattern();
        let mut findings: Vec<Finding> = Vec::new();
        let mut byte_offset: usize = 0;

        for line in text.lines() {
            let line_start = byte_offset;
            byte_offset += line.len() + 1; // +1 for '\n'

            if !sql_re.is_match(line) {
                continue;
            }
            if !has_quote(line) {
                continue;
            }
            if !has_interpolation(line) {
                continue;
            }

            #[allow(clippy::cast_possible_truncation)]
            let start = zuit_core::span::ByteOffset(line_start as u32);
            #[allow(clippy::cast_possible_truncation)]
            let end_off = (line_start + line.len()) as u32;
            let end = zuit_core::span::ByteOffset(end_off);
            let span = zuit_core::span::Span::new(start, end);
            let (start_lc, end_lc) = source.span_to_linecols(span);

            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Security,
                rule_id: RULE_ID.to_string(),
                severity: Severity::High,
                message: format!(
                    "possible SQL injection: SQL keyword with string interpolation on line {}",
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

    // ── unit tests for helper functions ──────────────────────────────────────

    #[test]
    fn sql_keyword_regex_matches_select() {
        assert!(sql_keyword_pattern().is_match("SELECT * FROM users"));
    }

    #[test]
    fn sql_keyword_regex_matches_delete() {
        assert!(sql_keyword_pattern().is_match("DELETE FROM table"));
    }

    #[test]
    fn sql_keyword_regex_is_case_insensitive() {
        assert!(sql_keyword_pattern().is_match("select * from t"));
    }

    #[test]
    fn has_interpolation_detects_fstring() {
        assert!(has_interpolation(
            r#"    query = f"SELECT * FROM users WHERE name = '{name}'"#
        ));
    }

    #[test]
    fn has_interpolation_detects_template_literal() {
        assert!(has_interpolation(
            "const q = `SELECT * FROM users WHERE id = ${userId}`;"
        ));
    }

    #[test]
    fn has_interpolation_detects_string_concat() {
        assert!(has_interpolation(
            r#"    sql = "SELECT * FROM " + table + " WHERE id = " + id"#
        ));
    }

    #[test]
    fn has_interpolation_rejects_plain_sql() {
        assert!(!has_interpolation(
            r#"    sql = "SELECT * FROM users WHERE id = 1""#
        ));
    }

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_sql_injection_positive() {
        let source = include_str!("../../../fixtures/python/sql_injection/main.py");
        let file = python_parse("fixtures/python/sql_injection/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SqlInjectionAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC006 finding for sql_injection Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings.iter().all(|f| f.cwe.iter().any(|c| c == "CWE-89")),
            "expected CWE-89 in finding.cwe"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.owasp.iter().any(|o| o == "A03:2021")),
            "expected A03:2021 in finding.owasp"
        );
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings should have a suggestion"
        );
    }

    // ── Python negative (healthy) ─────────────────────────────────────────────

    #[test]
    fn python_healthy_sql_injection_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SqlInjectionAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC006 findings for healthy Python fixture, got {findings:#?}"
        );
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_sql_injection_positive() {
        let source = include_str!("../../../fixtures/js/sql_injection/main.ts");
        let file = js_parse("fixtures/js/sql_injection/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SqlInjectionAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC006 finding for sql_injection JS fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── JS negative (healthy) ─────────────────────────────────────────────────

    #[test]
    fn js_healthy_sql_injection_negative() {
        let source = include_str!("../../../fixtures/js/healthy/main.ts");
        let file = js_parse("fixtures/js/healthy/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SqlInjectionAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC006 findings for healthy JS fixture, got {findings:#?}"
        );
    }

    // ── parameterised query is not flagged ────────────────────────────────────

    #[test]
    fn parameterised_query_not_flagged() {
        let source = r#"
import sqlite3
def get(conn, user_id):
    conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
"#;
        let file = python_parse("test.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SqlInjectionAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "parameterised query must not be flagged, got {findings:#?}"
        );
    }
}
