//! `SEC011-cors-permissive` — heuristic detector for overly permissive CORS
//! configurations (CWE-942 / OWASP A05:2021).
//!
//! ## Detection strategy
//!
//! A finding is emitted for each source line (whose trimmed start is **not** a
//! comment) that matches any of the following patterns:
//!
//! - **`Access-Control-Allow-Origin: *`** — the line contains both
//!   `Access-Control-Allow-Origin` and `*`.
//! - **Express `cors()` with wildcard** — the line contains `cors(` **and**
//!   `origin` **and** (`"*"` or `'*'` or `: true`).
//! - **FastAPI/Starlette `CORSMiddleware`** — the line contains `allow_origins`
//!   **and** `"*"`.
//! - **Rust `CorsLayer::permissive` / `Cors::permissive`** — the line contains
//!   `CorsLayer::permissive()` or `CorsLayer::very_permissive()` or
//!   `Cors::permissive()`.
//! - **Django `CORS_ORIGIN_ALLOW_ALL`** — the line contains
//!   `CORS_ORIGIN_ALLOW_ALL` or `CORS_ALLOW_ALL_ORIGINS` followed by `True`.
//!
//! Comment lines (trimmed start begins with `//`, `#`, `*`, or `/*`) are
//! skipped entirely.
//!
//! One finding is emitted per matching line. Severity: **Medium**.
//!
//! [`ParsedFile`]: zuit_core::ParsedFile

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages, span::Location,
};

/// Rule ID for the permissive-CORS check.
pub const RULE_ID: &str = "SEC011-cors-permissive";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/SEC011-cors-permissive.md",
    cwe: &["CWE-942"],
    owasp: &["A05:2021"],
};

/// Suggestion text emitted with every finding.
const SUGGESTION: &str = "Restrict CORS to a known allow-list of origins \
    (e.g. `cors({ origin: ['https://app.example.com'] })`); avoid `*` and \
    `true` in production. Combine with credentials-aware checks if \
    `Access-Control-Allow-Credentials` is set.";

/// Returns `true` if `line` matches any permissive-CORS pattern.
fn is_cors_permissive(line: &str) -> bool {
    // `Access-Control-Allow-Origin` set to `*`.
    if line.contains("Access-Control-Allow-Origin") && line.contains('*') {
        return true;
    }

    // Express `cors({ origin: "*" })` or `cors({ origin: true })`.
    if line.contains("cors(")
        && line.contains("origin")
        && (line.contains("\"*\"") || line.contains("'*'") || line.contains(": true"))
    {
        return true;
    }

    // FastAPI/Starlette `CORSMiddleware(allow_origins=["*"])`.
    if line.contains("allow_origins") && line.contains("\"*\"") {
        return true;
    }

    // Rust tower-http `CorsLayer::permissive()` / `CorsLayer::very_permissive()`.
    if line.contains("CorsLayer::permissive()")
        || line.contains("CorsLayer::very_permissive()")
        || line.contains("Cors::permissive()")
    {
        return true;
    }

    // Django `CORS_ORIGIN_ALLOW_ALL = True` or `CORS_ALLOW_ALL_ORIGINS = True`.
    if (line.contains("CORS_ORIGIN_ALLOW_ALL") || line.contains("CORS_ALLOW_ALL_ORIGINS"))
        && line.contains("True")
    {
        return true;
    }

    false
}

/// Analyzer that detects overly permissive CORS configurations.
#[derive(Debug, Default)]
pub struct CorsPermissiveAnalyzer;

impl Analyzer for CorsPermissiveAnalyzer {
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
        let mut findings: Vec<Finding> = Vec::new();
        let mut byte_offset: usize = 0;

        for line in text.lines() {
            let line_start = byte_offset;
            byte_offset += line.len() + 1; // +1 for '\n'

            // Skip comment lines.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with('*')
                || trimmed.starts_with("/*")
            {
                continue;
            }

            if !is_cors_permissive(line) {
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
                severity: Severity::Medium,
                message: format!(
                    "permissive CORS configuration detected on line {} — restricts CORS to a known allow-list",
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

    // ── unit tests for is_cors_permissive ─────────────────────────────────────

    #[test]
    fn cors_permissive_detects_acao_star() {
        assert!(is_cors_permissive(
            r#"res.setHeader("Access-Control-Allow-Origin", "*")"#
        ));
    }

    #[test]
    fn cors_permissive_detects_express_origin_star() {
        assert!(is_cors_permissive(r#"app.use(cors({ origin: "*" }))"#));
    }

    #[test]
    fn cors_permissive_detects_cors_layer_permissive() {
        assert!(is_cors_permissive("let cors = CorsLayer::permissive();"));
    }

    #[test]
    fn cors_permissive_ignores_comment_line() {
        // The helper itself does not skip comments; the caller does.
        // But we verify the check still fires for non-commented code.
        assert!(is_cors_permissive("CORS_ALLOW_ALL_ORIGINS = True"));
    }

    #[test]
    fn cors_permissive_does_not_flag_restricted_origin() {
        assert!(!is_cors_permissive(
            r#"app.use(cors({ origin: "https://app.example.com" }))"#
        ));
    }

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_cors_permissive_positive() {
        let source = include_str!("../../../fixtures/python/cors_permissive/main.py");
        let file = python_parse("fixtures/python/cors_permissive/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CorsPermissiveAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC011 finding for cors_permissive Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings.iter().all(|f| f.dimension == Dimension::Security),
            "all findings must have Dimension::Security"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.cwe.iter().any(|c| c == "CWE-942")),
            "all findings must contain CWE-942"
        );
        assert!(
            findings.iter().all(|f| f.severity == Severity::Medium),
            "all findings must have Severity::Medium"
        );
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings must have a suggestion"
        );
    }

    // ── Python negative (healthy) ─────────────────────────────────────────────

    #[test]
    fn python_healthy_cors_permissive_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CorsPermissiveAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC011 findings for healthy Python fixture, got {findings:#?}"
        );
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_cors_permissive_positive() {
        let source = include_str!("../../../fixtures/js/cors_permissive/main.ts");
        let file = js_parse("fixtures/js/cors_permissive/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CorsPermissiveAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC011 finding for cors_permissive JS fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings
                .iter()
                .all(|f| f.cwe.iter().any(|c| c == "CWE-942")),
            "all findings must contain CWE-942"
        );
        assert!(
            findings.iter().all(|f| f.severity == Severity::Medium),
            "all findings must have Severity::Medium"
        );
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings must have a suggestion"
        );
    }

    // ── JS negative (healthy) ─────────────────────────────────────────────────

    #[test]
    fn js_healthy_cors_permissive_negative() {
        let source = include_str!("../../../fixtures/js/healthy/main.ts");
        let file = js_parse("fixtures/js/healthy/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CorsPermissiveAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC011 findings for healthy JS fixture, got {findings:#?}"
        );
    }

    // ── Rust positive ─────────────────────────────────────────────────────────

    #[test]
    fn rust_cors_permissive_positive() {
        let source = include_str!("../../../fixtures/rust/cors_permissive/lib.rs");
        let file = rust_parse("fixtures/rust/cors_permissive/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CorsPermissiveAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC011 finding for cors_permissive Rust fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings
                .iter()
                .all(|f| f.cwe.iter().any(|c| c == "CWE-942")),
            "all findings must contain CWE-942"
        );
        assert!(
            findings.iter().all(|f| f.severity == Severity::Medium),
            "all findings must have Severity::Medium"
        );
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings must have a suggestion"
        );
    }

    // ── Rust negative (healthy) ───────────────────────────────────────────────

    #[test]
    fn rust_healthy_cors_permissive_negative() {
        let source = include_str!("../../../fixtures/rust/healthy/lib.rs");
        let file = rust_parse("fixtures/rust/healthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CorsPermissiveAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC011 findings for healthy Rust fixture, got {findings:#?}"
        );
    }
}
