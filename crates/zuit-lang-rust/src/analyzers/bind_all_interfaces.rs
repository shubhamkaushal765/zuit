//! `SEC013-bind-all-interfaces` — flags server-bind calls that use
//! `"0.0.0.0"` or `"::"` as the bind address in Rust source files.
//!
//! # Detection
//!
//! Reads the pre-extracted [`crate::parse::RustAst::bind_call_sites`] populated
//! at parse time by the `Extractor` visitor.  Each call site whose first string
//! argument passes [`crate::parse::is_bind_all_address_rust`] emits a finding.
//!
//! # Bind-callee allowlist (Rust)
//!
//! The allowlist is hard-coded in the extractor
//! (`crates/zuit-lang-rust/src/parse.rs: RUST_BIND_CALLEE_NAMES`):
//! - `bind` — `TcpListener::bind`, Tokio's `bind`, `HttpServer::bind`,
//!   `Server::bind`, `actix_web::HttpServer::bind`
//! - `bind_addr` — `HttpServer::bind_addr`
//! - `new` — `Server::new` (Hyper) when the first arg is the address

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

use crate::parse::is_bind_all_address_rust;

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
/// addresses in Rust source files.
pub struct BindAllInterfacesAnalyzer;

impl zuit_core::Analyzer for BindAllInterfacesAnalyzer {
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

        ast.bind_call_sites
            .iter()
            .filter_map(|site| {
                let val = site.first_arg_string_value.as_deref()?;
                if !is_bind_all_address_rust(val) {
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
        let analyzer = BindAllInterfacesAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_tcp_listener_bind_0000() {
        let src = r#"
use std::net::TcpListener;
fn main() {
    let listener = TcpListener::bind("0.0.0.0:8080").unwrap();
}
"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_tcp_listener_bind_ipv6_any() {
        let src = r#"
use std::net::TcpListener;
fn main() {
    let listener = TcpListener::bind("::").unwrap();
}
"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_bare_bind_call_0000() {
        let src = r#"fn start() { bind("0.0.0.0:9000"); }"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_localhost_bind() {
        let src = r#"
use std::net::TcpListener;
fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
}
"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "127.0.0.1 should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_unrelated_callee_string() {
        // `println!` is not a bind callee — string "0.0.0.0" must not fire.
        let src = r#"fn f() { println!("0.0.0.0"); }"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "println!(\"0.0.0.0\") should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_bind_non_string_arg() {
        // bind(addr) where `addr` is a variable, not a string literal.
        let src = "fn f(addr: &str) { bind(addr); }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "bind(variable) should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn supported_languages_is_rust_only() {
        let analyzer = BindAllInterfacesAnalyzer;
        assert!(analyzer.supported_languages().supports(LanguageId("rust")));
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
    }
}
