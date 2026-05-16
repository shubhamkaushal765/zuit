//! `SEC013-bind-all-interfaces` — flags server-bind calls that use
//! `"0.0.0.0"` or `"::"` as the bind address in JavaScript/TypeScript source
//! files.
//!
//! # Detection
//!
//! Reads the pre-extracted `JsAst::bind_call_sites`
//! populated at parse time by the walker.  Each call site whose
//! `first_arg_string_value` passes the is-bind-all-address check emits a
//! finding.
//!
//! # Bind-callee allowlist (JS/TS)
//!
//! The allowlist is hard-coded in the walker
//! (`crates/zuit-lang-js/src/parse.rs: BIND_CALLEE_NAMES`):
//! - `listen` — `app.listen`, `server.listen`, `httpServer.listen`
//! - `bind` — `server.bind`, Express/Hapi callbacks

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

/// The stable rule ID.
const RULE_ID: &str = "SEC013-bind-all-interfaces";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/SEC013-bind-all-interfaces.md",
    cwe: &["CWE-1327"],
    owasp: &[],
};

/// Analyzer that emits `SEC013-bind-all-interfaces` for wide-open server bind
/// addresses in JavaScript/TypeScript source files.
pub struct JsBindAllInterfacesAnalyzer;

impl zuit_core::Analyzer for JsBindAllInterfacesAnalyzer {
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

        ast.bind_call_sites
            .iter()
            .filter_map(|site| {
                let val = site.first_arg_string_value.as_deref()?;
                if !is_bind_all_address(val) {
                    return None;
                }
                let span = site.span;
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Some(Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Security,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "`{}` binds to `{val}` — accepts connections on all network \
                         interfaces; use `\"127.0.0.1\"` (or `\"::1\"`) to restrict \
                         to loopback only",
                        site.callee_name,
                    ),
                    location: Location {
                        file: file_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Restrict the bind address to `\"127.0.0.1\"` or `\"::1\"` in \
                         production, or use an environment variable so the address is \
                         configurable without a code change."
                            .to_string(),
                    ),
                    references: vec![
                        "https://cwe.mitre.org/data/definitions/1327.html".to_string(),
                    ],
                    cwe: META.cwe_vec(),
                    owasp: META.owasp_vec(),
                })
            })
            .collect()
    }
}

/// Returns `true` when `raw` is a bind-all-interfaces address:
/// - `"0.0.0.0"` or `"0.0.0.0:PORT"` (IPv4 any-address)
/// - `"::"` or `"[::]:PORT"` or `":::PORT"` (IPv6 any-address)
fn is_bind_all_address(raw: &str) -> bool {
    let host = if let Some(stripped) = raw.strip_prefix('[') {
        stripped.split(']').next().unwrap_or(raw)
    } else if raw == "::" || raw.starts_with(":::") {
        "::"
    } else {
        raw.split(':').next().unwrap_or(raw)
    };
    host == "0.0.0.0" || host == "::"
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
        let analyzer = JsBindAllInterfacesAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_app_listen_0000() {
        let src = r#"app.listen("0.0.0.0", 3000);"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_server_listen_0000_with_port() {
        let src = r#"server.listen("0.0.0.0:8080");"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_listen_ipv6_any() {
        let src = r#"server.listen("::");"#;
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for ::, got: {findings:#?}"
        );
    }

    #[test]
    fn flags_bind_0000() {
        let src = r#"socket.bind("0.0.0.0");"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_localhost_listen() {
        let src = r#"app.listen("127.0.0.1", 3000);"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "127.0.0.1 should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_unrelated_callee() {
        let src = r#"console.log("0.0.0.0");"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "console.log(\"0.0.0.0\") should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_listen_with_port_number_arg() {
        // `app.listen(3000)` — first arg is a number, not a string.
        let src = "app.listen(3000);";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "listen(3000) should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn supported_languages_is_javascript_only() {
        let analyzer = JsBindAllInterfacesAnalyzer;
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

    // ── helper unit tests ─────────────────────────────────────────────────────

    #[test]
    fn is_bind_all_ipv6_bracketed() {
        assert!(is_bind_all_address("[::]:8080"));
        assert!(is_bind_all_address("::"));
        assert!(!is_bind_all_address("::1"));
    }
}
