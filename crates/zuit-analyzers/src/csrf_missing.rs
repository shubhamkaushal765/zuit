//! `SEC008-csrf-missing` — heuristic detector for state-changing HTTP handlers
//! that lack CSRF protection (CWE-352 / OWASP A01:2021).
//!
//! ## Detection strategy
//!
//! For each [`ParsedFile`], the analyzer:
//!
//! 1. **Detects the web framework** by scanning `index.imports` for known
//!    framework substrings (`express`, `koa`, `fastify`, `body-parser`,
//!    `flask`, `fastapi`, `django`, `axum`, `actix_web`, `rocket`, `warp`).
//!    If no recognized framework is found, no findings are emitted.
//!
//! 2. **Checks for CSRF protection** by scanning the entire source text for any
//!    of the following tokens (case-insensitive): `csrf`, `csurf`,
//!    `csrf_protect`, `CSRFProtect`, `flask_wtf`, `csrf_token`, `XSRF`,
//!    `xsrf`.  If any of these appear, the file is considered protected and no
//!    findings are emitted.
//!
//! 3. **Identifies state-changing handlers** — functions whose surrounding
//!    source region (from declaration start to body end) contains any of the
//!    POST/PUT/DELETE/PATCH handler markers:
//!    - **JS/TS:** `app.post(`, `app.put(`, `app.delete(`, `app.patch(`,
//!      `router.post(`, `router.put(`, `router.delete(`, `router.patch(`
//!    - **Python:** `@app.post(`, `@app.put(`, `@app.delete(`, `@app.patch(`,
//!      `@app.route(`, `@router.post(`, `@router.put(`, `@blueprint.route(`
//!    - **Rust:** `.route(`, `Router::new()`, `#[post`, `#[put`, `#[delete`,
//!      `#[patch`, `web::post()`, `web::put()`, `web::delete()`
//!
//! One finding is emitted per state-changing handler function that lacks CSRF
//! protection. Severity: **Medium**. CWE: `CWE-352`. OWASP: `A01:2021`.
//!
//! ## Conservatism
//!
//! False positives erode trust. The analyzer only emits findings when a
//! framework import is positively recognised AND no CSRF token appears anywhere
//! in the source. Unrecognised frameworks produce no findings.
//!
//! [`ParsedFile`]: zuit_core::ParsedFile

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages,
    span::{Location, Span},
};

/// Rule ID for the CSRF-missing check.
pub const RULE_ID: &str = "SEC008-csrf-missing";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/SEC008-csrf-missing.md",
    cwe: &["CWE-352"],
    owasp: &["A01:2021"],
};

/// Web framework import substrings (lowercase) that indicate this file sets up
/// HTTP routes and therefore requires CSRF protection on state-changing handlers.
const WEB_FRAMEWORK_IMPORTS: &[&str] = &[
    "express",
    "koa",
    "fastify",
    "body-parser",
    "flask",
    "fastapi",
    "django",
    "axum",
    "actix_web",
    "rocket",
    "warp",
];

/// Tokens that indicate state-changing HTTP handlers (POST/PUT/DELETE/PATCH).
///
/// Checked as plain substring matches against the source region covering a
/// function declaration plus its body.
const STATE_CHANGING_MARKERS: &[&str] = &[
    // JS/TS — Express / Koa / Fastify style
    "app.post(",
    "app.put(",
    "app.delete(",
    "app.patch(",
    "router.post(",
    "router.put(",
    "router.delete(",
    "router.patch(",
    // Python — Flask / FastAPI / Django style decorators
    "@app.post(",
    "@app.put(",
    "@app.delete(",
    "@app.patch(",
    "@app.route(",
    "@router.post(",
    "@router.put(",
    "@blueprint.route(",
    // Rust — Axum / Actix-web / Rocket / Warp handler markers
    "Router::new()",
    ".route(",
    "#[post",
    "#[put",
    "#[delete",
    "#[patch",
    "web::post()",
    "web::put()",
    "web::delete()",
];

/// CSRF protection tokens (case-insensitive substring matches over the full
/// source text).  If any of these appear, the file is considered protected.
const CSRF_PROTECTION_TOKENS: &[&str] = &[
    "csrf",
    "csurf",
    "csrf_protect",
    "CSRFProtect",
    "flask_wtf",
    "csrf_token",
    "XSRF",
    "xsrf",
];

/// Suggestion text emitted with every finding.
const SUGGESTION: &str = "Add CSRF protection middleware before state-changing handlers: \
    use `csurf` (Express/Node.js), `Flask-WTF CSRFProtect` (Flask/Python), \
    or `tower_csrf` / `axum-csrf` (Axum/Rust). \
    Ensure the CSRF token is validated on every POST, PUT, DELETE, and PATCH request.";

/// Returns `true` if the file imports a recognised web framework.
fn imports_web_framework(file: &ParsedFile) -> bool {
    let index = file.index();
    index.imports.iter().any(|imp| {
        let lower = imp.path.to_lowercase();
        WEB_FRAMEWORK_IMPORTS.iter().any(|sub| lower.contains(sub))
    })
}

/// Returns `true` if the file contains any known CSRF protection signal.
///
/// The check scans:
/// 1. Import paths (e.g. `tower_csrf`, `csurf`, `flask_wtf.csrf`) — most
///    reliable indicator of intentional CSRF protection.
/// 2. Non-comment, non-blank source lines for CSRF-usage tokens.  Comment lines
///    are skipped to avoid false negatives caused by documentation comments that
///    describe the *absence* of CSRF protection (e.g. `no CSRF protection`).
fn has_csrf_protection(file: &ParsedFile) -> bool {
    let index = file.index();

    // Check imports first — most reliable signal.
    if index.imports.iter().any(|imp| {
        let lower = imp.path.to_lowercase();
        CSRF_PROTECTION_TOKENS
            .iter()
            .any(|token| lower.contains(&token.to_lowercase()))
    }) {
        return true;
    }

    // Scan non-comment source lines for CSRF usage tokens.
    let src_str = file.source().as_str();
    for line in src_str.lines() {
        let trimmed = line.trim_start();
        // Skip comment lines in all three languages.
        if trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with('*')
            || trimmed.starts_with("/*")
            || trimmed.starts_with("\"\"\"")
            || trimmed.starts_with("'''")
        {
            continue;
        }
        let lower = trimmed.to_lowercase();
        if CSRF_PROTECTION_TOKENS
            .iter()
            .any(|token| lower.contains(&token.to_lowercase()))
        {
            return true;
        }
    }

    false
}

/// Returns `true` if the given source region contains a state-changing handler
/// marker.
fn is_state_changing_handler(region: &str) -> bool {
    STATE_CHANGING_MARKERS
        .iter()
        .any(|marker| region.contains(marker))
}

/// Analyzer that detects state-changing HTTP handlers lacking CSRF protection.
#[derive(Debug, Default)]
pub struct CsrfMissingAnalyzer;

impl Analyzer for CsrfMissingAnalyzer {
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
        // Gate 1: only proceed for recognised web framework files.
        if !imports_web_framework(file) {
            return Vec::new();
        }

        let source = file.source();
        let src_str = source.as_str();

        // Gate 2: if any CSRF protection token appears in imports or non-comment
        // source lines, suppress all findings.
        if has_csrf_protection(file) {
            return Vec::new();
        }

        let index = file.index();
        let mut findings = Vec::new();

        for func in &index.functions {
            let decl_start = func.span.start.0 as usize;
            let body_end = func.body_span.end.0 as usize;

            if decl_start >= src_str.len() {
                continue;
            }

            let region_end = body_end.min(src_str.len());
            if decl_start > region_end {
                continue;
            }

            // For Python decorators we also need to look just before the declaration.
            // We scan from a reasonable lookback (up to 256 bytes before the function
            // declaration) so that decorator lines are captured.
            // Walk back at most 256 bytes for decorator lines, then snap to a
            // char boundary so we never slice inside a multi-byte UTF-8 char.
            let mut lookback_start = decl_start.saturating_sub(256);
            while lookback_start > 0 && !src_str.is_char_boundary(lookback_start) {
                lookback_start -= 1;
            }
            let region = &src_str[lookback_start..region_end];

            if !is_state_changing_handler(region) {
                continue;
            }

            let name = func.name.as_deref().unwrap_or("<anonymous>");
            let span = Span::new(func.span.start, func.span.start);
            let (start_lc, end_lc) = source.span_to_linecols(span);

            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Security,
                rule_id: RULE_ID.to_string(),
                severity: Severity::Medium,
                message: format!(
                    "state-changing HTTP handler `{name}` has no CSRF protection (CWE-352)"
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

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_csrf_missing_positive() {
        let source = include_str!("../../../fixtures/python/csrf_missing/main.py");
        let file = python_parse("fixtures/python/csrf_missing/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CsrfMissingAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC008 finding for csrf_missing Python fixture"
        );
        assert!(
            findings.iter().all(|f| f.rule_id == RULE_ID),
            "all findings must have rule_id == {RULE_ID}"
        );
        assert!(
            findings.iter().all(|f| f.dimension == Dimension::Security),
            "all findings must have Dimension::Security"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.cwe.iter().any(|c| c == "CWE-352")),
            "all findings must contain CWE-352"
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

    // ── Python negative ───────────────────────────────────────────────────────

    #[test]
    fn python_not_csrf_missing_negative() {
        let source = include_str!("../../../fixtures/python/not_csrf_missing/main.py");
        let file = python_parse("fixtures/python/not_csrf_missing/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CsrfMissingAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC008 findings for not_csrf_missing Python fixture, got {findings:#?}"
        );
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_csrf_missing_positive() {
        let source = include_str!("../../../fixtures/js/csrf_missing/main.ts");
        let file = js_parse("fixtures/js/csrf_missing/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CsrfMissingAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC008 finding for csrf_missing JS fixture"
        );
        assert!(
            findings.iter().all(|f| f.rule_id == RULE_ID),
            "all findings must have rule_id == {RULE_ID}"
        );
        assert!(
            findings.iter().all(|f| f.dimension == Dimension::Security),
            "all findings must have Dimension::Security"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.cwe.iter().any(|c| c == "CWE-352")),
            "all findings must contain CWE-352"
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

    // ── JS negative ───────────────────────────────────────────────────────────

    #[test]
    fn js_not_csrf_missing_negative() {
        let source = include_str!("../../../fixtures/js/not_csrf_missing/main.ts");
        let file = js_parse("fixtures/js/not_csrf_missing/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CsrfMissingAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC008 findings for not_csrf_missing JS fixture, got {findings:#?}"
        );
    }

    // ── Rust positive ─────────────────────────────────────────────────────────

    #[test]
    fn rust_csrf_missing_positive() {
        let source = include_str!("../../../fixtures/rust/csrf_missing/lib.rs");
        let file = rust_parse("fixtures/rust/csrf_missing/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CsrfMissingAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC008 finding for csrf_missing Rust fixture"
        );
        assert!(
            findings.iter().all(|f| f.rule_id == RULE_ID),
            "all findings must have rule_id == {RULE_ID}"
        );
        assert!(
            findings.iter().all(|f| f.dimension == Dimension::Security),
            "all findings must have Dimension::Security"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.cwe.iter().any(|c| c == "CWE-352")),
            "all findings must contain CWE-352"
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

    // ── Rust negative ─────────────────────────────────────────────────────────

    #[test]
    fn rust_not_csrf_missing_negative() {
        let source = include_str!("../../../fixtures/rust/not_csrf_missing/lib.rs");
        let file = rust_parse("fixtures/rust/not_csrf_missing/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CsrfMissingAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC008 findings for not_csrf_missing Rust fixture, got {findings:#?}"
        );
    }

    // ── Non-web file produces no findings ────────────────────────────────────

    #[test]
    fn non_web_file_emits_nothing() {
        let source = r"
/// A simple addition function with no web framework imports.
pub fn add(x: i32, y: i32) -> i32 {
    x + y
}
";
        let file = rust_parse("test_add.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = CsrfMissingAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "non-web file must produce no SEC008 findings, got {findings:#?}"
        );
    }

    // ── Regression: UTF-8 char boundary in lookback slice ────────────────────
    //
    // `lookback_start = decl_start.saturating_sub(256)` is byte arithmetic
    // that can land inside a multi-byte UTF-8 character in a preceding doc
    // comment, causing `&src_str[lookback_start..region_end]` to panic.
    #[test]
    fn no_panic_on_multibyte_unicode_before_handler() {
        // Header import contains "Expression" -> matches "express" substring
        // -> imports_web_framework gate passes.
        // Comment line is filled with `─` (U+2500, 3 bytes UTF-8) so that
        // `decl_start - 256` lands inside one of them.
        // Layout (bytes):
        //   "use oxc_ast::ast::Expression;\n"  -> bytes 0..30
        //   "//"                               -> bytes 30..32
        //   "─" * 200                          -> bytes 32..632 (3 bytes each)
        //   "x\n"                              -> bytes 632..634
        //   "fn handler() {}\n"                -> bytes 634..650
        // decl_start = 634, lookback_start = 378.
        // 378 - 32 = 346; 346 % 3 = 1 -> inside the 2nd byte of a `─`.
        let bars = "─".repeat(200);
        let source = format!("use oxc_ast::ast::Expression;\n//{bars}x\nfn handler() {{}}\n");

        let file = rust_parse("regression_unicode.rs", &source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        // Must not panic. We don't care about the contents of `findings`,
        // only that `analyze_file` returns at all.
        let _ = CsrfMissingAnalyzer.analyze_file(&ctx, &file);
    }
}
