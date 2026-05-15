//! `SEC015-log-injection` — flags logging calls that may concatenate untrusted
//! input without sanitization, enabling log injection (CWE-117).
//!
//! # Detection
//!
//! Reads the pre-extracted [`crate::native_ast::JsAst::log_calls`] populated
//! at parse time by the walker.  A finding fires when ALL of:
//!
//! 1. The call is a known logging function:
//!    `console.log/info/debug/warn/error/trace`,
//!    `logger.log/info/debug/warn/error/trace`,
//!    `log.log/info/debug/warn/error/trace`.
//!
//! 2. The first argument is a string literal containing a placeholder marker
//!    (`{}`, `%s`, `%d`, `%r`, `%v`), OR the first argument is a template
//!    literal with at least one expression substitution.
//!
//! 3. A subsequent argument identifier (or a template substitution expression
//!    identifier) is either in the `REQUEST_LIKE` allowlist or appears in the
//!    immediately enclosing function's parameter list.

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

/// The stable rule ID.
const RULE_ID: &str = "SEC015-log-injection";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/SEC015-log-injection.md",
    cwe: &["CWE-117"],
    owasp: &[],
};

/// Placeholder markers that indicate format-string interpolation.
const PLACEHOLDER_MARKERS: &[&str] = &["%s", "%d", "%r", "%v", "{}"];

/// Request-style identifier names (case-insensitive).
const REQUEST_LIKE: &[&str] = &[
    "req",
    "request",
    "params",
    "body",
    "query",
    "ctx",
    "context",
    "input",
    "user_input",
    "payload",
    "headers",
    "cookies",
    "args",
    "kwargs",
    "event",
    "data",
];

/// Returns `true` when `name` (lowercased) is request-like.
fn is_request_like(name: &str) -> bool {
    let lower = name.to_lowercase();
    REQUEST_LIKE.iter().any(|&r| r == lower)
}

/// Returns `true` when `s` contains a placeholder marker.
fn has_placeholder(s: &str) -> bool {
    PLACEHOLDER_MARKERS.iter().any(|&m| s.contains(m))
}

/// Analyzer that emits `SEC015-log-injection` for potential log injection
/// vulnerabilities in JavaScript/TypeScript source files.
pub struct JsLogInjectionAnalyzer;

impl zuit_core::Analyzer for JsLogInjectionAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Security
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::Only(smallvec![LanguageId("javascript")])
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let Some(ast) = crate::try_js_ast(file) else {
            return Vec::new();
        };

        let source = file.source();
        let file_path = source.path.clone();

        ast.log_calls
            .iter()
            .filter(|site| {
                // Condition 2: first arg has a placeholder OR is a template with substitution
                let first_ok = site
                    .first_arg_string
                    .as_deref()
                    .is_some_and(has_placeholder)
                    || site.first_arg_is_template_with_subst;
                if !first_ok {
                    return false;
                }
                // Condition 3: a subsequent/template ident is request-like or a fn param
                site.arg_idents.iter().any(|ident| {
                    is_request_like(ident)
                        || site.enclosing_fn_params.iter().any(|p| p.as_str() == ident)
                })
            })
            .map(|site| {
                let span = site.span;
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Security,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "`{}` passes unsanitized user-controlled input to a logging call; \
                         sanitize or escape the value before logging",
                        site.callee_name,
                    ),
                    location: Location {
                        file: file_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Sanitize input before logging: strip newlines and control characters, \
                         or use structured logging fields instead of format strings."
                            .to_string(),
                    ),
                    references: vec!["https://cwe.mitre.org/data/definitions/117.html".to_string()],
                    cwe: META.cwe_vec(),
                    owasp: META.owasp_vec(),
                }
            })
            .collect()
    }
}

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
        let analyzer = JsLogInjectionAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_logger_info_with_template_and_req_param() {
        // logger.info(`user: ${req.body}`) — template literal + param
        let src = "function view(req) { logger.info(`user: ${req.body}`); }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_console_log_printf_with_req_body() {
        // console.log("user: %s", req.body) — printf-style + req identifier
        let src = r#"function view(req) { console.log("user: %s", req.body); }"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_log_info_printf_with_request_param() {
        // log.info with printf-style + request-style param
        let src = r#"function process(request) { log.info("processing: %s", request); }"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_logger_with_payload_request_like_ident() {
        // `payload` is in REQUEST_LIKE
        let src = r#"function receive() { logger.warn("received: %s", payload); }"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_no_placeholder_no_user_arg() {
        let src = r#"function startup() { logger.info("startup complete"); }"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "no-placeholder should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_placeholder_with_non_user_literal_arg() {
        // 42 is not an identifier
        let src = r#"function report() { logger.info("user count", 42); }"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "no-placeholder + non-user arg should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_local_non_param_ident() {
        // greeting is a local const, not a param
        let src = r#"const greeting = "hello"; function log_greeting() { console.log("user said", greeting); }"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "local non-param ident should not be flagged, got: {findings:#?}"
        );
    }

    // ── CWE tag ───────────────────────────────────────────────────────────────

    #[test]
    fn cwe_tag_is_cwe_117() {
        let src = "function view(req) { logger.info(`user: ${req.body}`); }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].cwe.iter().any(|c| c == "CWE-117"),
            "expected CWE-117 in finding.cwe, got: {:?}",
            findings[0].cwe
        );
    }

    #[test]
    fn supported_languages_is_javascript_only() {
        let analyzer = JsLogInjectionAnalyzer;
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
