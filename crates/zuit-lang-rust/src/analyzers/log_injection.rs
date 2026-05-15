//! `SEC015-log-injection` — flags logging macro calls that may concatenate
//! untrusted input without sanitization, enabling log injection (CWE-117).
//!
//! # Detection
//!
//! Reads the pre-extracted [`crate::parse::RustAst::log_calls`] populated at
//! parse time by the `Extractor` visitor for `log::info!`, `log::warn!`,
//! `info!`, `debug!`, `tracing::debug!`, etc.
//!
//! A finding fires when ALL of:
//! 1. The macro is a known logging macro (last segment in
//!    `trace|debug|info|warn|error|log`).
//! 2. The first argument string contains a placeholder (`{}`, `%s`, `%d`,
//!    `%r`, `%v`).
//! 3. A subsequent identifier argument is either in the `REQUEST_LIKE` list
//!    or matches an enclosing function parameter name.
//!
//! **Note:** The macro body is parsed via regex over the token-string, not via
//! full syntactic AST. This is reflected in the `message` field with the phrase
//! "(macro-body regex parse)".

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
/// vulnerabilities in Rust source files.
pub struct LogInjectionAnalyzer;

impl zuit_core::Analyzer for LogInjectionAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Security
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::Only(smallvec![LanguageId("rust")])
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let Some(ast) = crate::try_rust_ast(file) else {
            return Vec::new();
        };

        let source = file.source();
        let file_path = source.path.clone();

        ast.log_calls
            .iter()
            .filter(|site| {
                // Condition 2: first arg has a placeholder
                if !site
                    .first_arg_string
                    .as_deref()
                    .is_some_and(has_placeholder)
                {
                    return false;
                }
                // Condition 3: a subsequent ident is request-like or a fn param
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
                        "`{}!` passes unsanitized user-controlled input to a log macro; \
                         sanitize or escape the value before logging \
                         (macro-body regex parse)",
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
    use crate::parse as rust_parse;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, LanguageId, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.rs", src.as_bytes().to_vec()));
        let parsed = rust_parse::parse(source).expect("parse failed");
        let analyzer = LogInjectionAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_log_info_with_placeholder_and_req_param() {
        let src = r#"struct Request; fn handler(req: Request) { log::info!("user: {}", req); }"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(
            findings[0].message.contains("(macro-body regex parse)"),
            "message must mention macro-body regex parse, got: {}",
            findings[0].message
        );
    }

    #[test]
    fn flags_bare_info_with_placeholder_and_req_param() {
        let src = r#"struct Request; fn view(req: Request) { info!("received: {}", req); }"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_request_like_ident_in_args() {
        // `request` is in REQUEST_LIKE list
        let src = r#"fn process() { log::warn!("data: {}", request); }"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_no_placeholder() {
        let src = r#"fn startup() { log::info!("startup complete"); }"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "no-placeholder should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_non_request_local_ident() {
        // `total` is not request-style and not a param
        let src = r#"fn report() { let total = 42; log::info!("count: {}", total); }"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "non-request local should not be flagged, got: {findings:#?}"
        );
    }

    // ── CWE tag ───────────────────────────────────────────────────────────────

    #[test]
    fn cwe_tag_is_cwe_117() {
        let src = r#"struct Request; fn handler(req: Request) { log::info!("user: {}", req); }"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].cwe.iter().any(|c| c == "CWE-117"),
            "expected CWE-117 in finding.cwe, got: {:?}",
            findings[0].cwe
        );
    }

    #[test]
    fn supported_languages_is_rust_only() {
        let analyzer = LogInjectionAnalyzer;
        assert!(analyzer.supported_languages().supports(LanguageId("rust")));
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
    }
}
