//! `SEC010-ssrf` — heuristic detector for Server-Side Request Forgery
//! vulnerabilities (CWE-918 / OWASP A10:2021).
//!
//! ## Detection strategy
//!
//! A finding is emitted for each source line that satisfies **both** of:
//!
//! 1. **HTTP-client call** — the line matches the HTTP-client regex covering:
//!    `requests.get(`, `requests.post(`, `requests.put(`, `requests.delete(`,
//!    `requests.request(`, `urllib.request.urlopen(`, `urlopen(`,
//!    `httpx.get(`, `httpx.post(`, `aiohttp.ClientSession`, `fetch(`,
//!    `axios.get(`, `axios.post(`, `axios.request(`, `axios(`,
//!    `http.get(`, `http.request(`, `node-fetch`, `reqwest::get(`,
//!    `reqwest::Client::new()`, `Client::new().get(`, `ureq::get(`,
//!    `ureq::post(`, `hyper::Client`.
//!
//! 2. **Untrusted-input signal** — the line contains either:
//!    - An interpolation marker (`${`, `f"…{`, `" + `, `' + `, `+ "`, `+ '`,
//!      `format!(`, `.format(`, `%s`), OR
//!    - A known untrusted-source token (`req.query`, `req.params`, `req.body`,
//!      `request.args`, `request.form`, `request.GET`, `request.POST`,
//!      `request.json`, `params[`, `query[`).
//!
//! One finding is emitted per matching line. Severity: **High**.
//!
//! [`ParsedFile`]: zuit_core::ParsedFile

use std::sync::OnceLock;

use regex::Regex;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages, span::Location,
};

/// Rule ID for the SSRF check.
pub const RULE_ID: &str = "SEC010-ssrf";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/SEC010-ssrf.md",
    cwe: &["CWE-918"],
    owasp: &["A10:2021"],
};

/// Suggestion text emitted with every finding.
const SUGGESTION: &str = "Validate the destination URL against an allow-list of hosts; \
    reject internal/loopback addresses (127.0.0.1, 169.254.169.254, ::1, RFC1918) \
    before issuing the request. Do not pass user input directly to HTTP client constructors.";

/// Returns the compiled regex that matches HTTP-client call sites.
fn http_client_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(
            r"(?x)
            (?:
                \brequests\.(?:get|post|put|delete|request)\s*\(
                | urllib\.request\.urlopen\s*\(
                | \burlopen\s*\(
                | \bhttpx\.(?:get|post)\s*\(
                | \baiohttp\.ClientSession\b
                | \bfetch\s*\(
                | \baxios\.(?:get|post|request)\s*\(
                | \baxios\s*\(
                | \bhttp\.(?:get|request)\s*\(
                | \bnode-fetch\b
                | \breqwest::get\s*\(
                | \breqwest::Client::new\s*\(\s*\)
                | \bClient::new\s*\(\s*\)\.get\s*\(
                | \bureq::(?:get|post)\s*\(
                | \bhyper::Client\b
            )",
        )
        .expect("invariant: HTTP-client regex is valid")
    })
}

/// Interpolation markers indicating dynamic string construction.
const INTERPOLATION_MARKERS: &[&str] = &[
    "${",       // JS/TS template literal
    "\" + ",    // string concat (double-quoted left)
    "' + ",     // string concat (single-quoted left)
    "+ \"",     // string concat (double-quoted right)
    "+ '",      // string concat (single-quoted right)
    "format!(", // Rust format macro
    ".format(", // Python str.format
    "%s",       // printf-style formatting
];

/// Untrusted-source tokens indicating user-controlled input.
const UNTRUSTED_SOURCE_TOKENS: &[&str] = &[
    "req.query",
    "req.params",
    "req.body",
    "request.args",
    "request.form",
    "request.GET",
    "request.POST",
    "request.json",
    "params[",
    "query[",
];

/// Returns `true` if `line` contains an f-string interpolation marker.
fn has_fstring_interpolation(line: &str) -> bool {
    (line.contains("f\"") || line.contains("f'")) && line.contains('{')
}

/// Returns `true` if `line` contains any interpolation marker or untrusted-source token.
fn has_untrusted_signal(line: &str) -> bool {
    if INTERPOLATION_MARKERS.iter().any(|m| line.contains(m)) {
        return true;
    }
    if has_fstring_interpolation(line) {
        return true;
    }
    UNTRUSTED_SOURCE_TOKENS.iter().any(|t| line.contains(t))
}

/// Analyzer that detects Server-Side Request Forgery vulnerabilities.
#[derive(Debug, Default)]
pub struct SsrfAnalyzer;

impl Analyzer for SsrfAnalyzer {
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
        let http_re = http_client_pattern();
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

            if !http_re.is_match(line) {
                continue;
            }

            if !has_untrusted_signal(line) {
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
                    "possible SSRF: HTTP request destination derived from user input on line {}",
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

    // ── regex unit tests ──────────────────────────────────────────────────────

    #[test]
    fn http_client_pattern_matches_requests_get() {
        assert!(http_client_pattern().is_match("requests.get(url)"));
    }

    #[test]
    fn http_client_pattern_matches_reqwest_get() {
        assert!(http_client_pattern().is_match("reqwest::get(url)"));
    }

    #[test]
    fn http_client_pattern_matches_fetch() {
        assert!(http_client_pattern().is_match("await fetch(url)"));
    }

    #[test]
    fn http_client_pattern_does_not_match_unrelated() {
        assert!(!http_client_pattern().is_match("let x = compute(a, b)"));
    }

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_ssrf_positive() {
        let source = include_str!("../../../fixtures/python/ssrf/main.py");
        let file = python_parse("fixtures/python/ssrf/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SsrfAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC010 finding for ssrf Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings.iter().all(|f| f.dimension == Dimension::Security),
            "all findings must have Dimension::Security"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.cwe.iter().any(|c| c == "CWE-918")),
            "all findings must contain CWE-918"
        );
        assert!(
            findings.iter().all(|f| f.severity == Severity::High),
            "all findings must have Severity::High"
        );
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings must have a suggestion"
        );
    }

    // ── Python negative (healthy) ─────────────────────────────────────────────

    #[test]
    fn python_healthy_ssrf_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SsrfAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC010 findings for healthy Python fixture, got {findings:#?}"
        );
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_ssrf_positive() {
        let source = include_str!("../../../fixtures/js/ssrf/main.ts");
        let file = js_parse("fixtures/js/ssrf/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SsrfAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC010 finding for ssrf JS fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings
                .iter()
                .all(|f| f.cwe.iter().any(|c| c == "CWE-918")),
            "all findings must contain CWE-918"
        );
        assert!(
            findings.iter().all(|f| f.severity == Severity::High),
            "all findings must have Severity::High"
        );
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings must have a suggestion"
        );
    }

    // ── JS negative (healthy) ─────────────────────────────────────────────────

    #[test]
    fn js_healthy_ssrf_negative() {
        let source = include_str!("../../../fixtures/js/healthy/main.ts");
        let file = js_parse("fixtures/js/healthy/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SsrfAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC010 findings for healthy JS fixture, got {findings:#?}"
        );
    }

    // ── Rust positive ─────────────────────────────────────────────────────────

    #[test]
    fn rust_ssrf_positive() {
        let source = include_str!("../../../fixtures/rust/ssrf/lib.rs");
        let file = rust_parse("fixtures/rust/ssrf/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SsrfAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC010 finding for ssrf Rust fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings
                .iter()
                .all(|f| f.cwe.iter().any(|c| c == "CWE-918")),
            "all findings must contain CWE-918"
        );
        assert!(
            findings.iter().all(|f| f.severity == Severity::High),
            "all findings must have Severity::High"
        );
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings must have a suggestion"
        );
    }

    // ── Rust negative (healthy) ───────────────────────────────────────────────

    #[test]
    fn rust_healthy_ssrf_negative() {
        let source = include_str!("../../../fixtures/rust/healthy/lib.rs");
        let file = rust_parse("fixtures/rust/healthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SsrfAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC010 findings for healthy Rust fixture, got {findings:#?}"
        );
    }
}
