//! `SEC012-hardcoded-security-constant` — flags assignments whose LHS
//! identifier is a security keyword and whose RHS is a literal value.
//!
//! # Detection
//!
//! Reads the pre-extracted [`crate::parse::RustAst::assignments`] populated
//! at parse time by the `Extractor` visitor. Each assignment site whose
//! `lhs_name` matches a security keyword AND whose `rhs_literal` is a
//! meaningful value emits a finding.
//!
//! Covered constructs:
//! - `let api_key = "test";`
//! - `let api_key: &str = "test";`
//! - `api_key = "test";` (expression assignment)
//! - `const API_KEY: &str = "test";` (module-level constant)
//! - `static API_KEY: &str = "test";` (module-level static)
//!
//! # Distinct from SEC001
//!
//! SEC001 uses entropy/pattern heuristics on the *value*. SEC012 uses the
//! *identifier name* — catching low-entropy values like `api_key = "test"`.
//! Both may fire on the same site; that is intentional (different `rule_id`).

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

use crate::parse::RustLiteralValue;

/// The stable rule ID.
const RULE_ID: &str = "SEC012-hardcoded-security-constant";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/SEC012-hardcoded-security-constant.md",
    cwe: &["CWE-547"],
    owasp: &[],
};

/// Security keyword substrings (case-insensitive, matched against lowercased `lhs_name`).
const SECURITY_KEYWORDS: &[&str] = &[
    "secret",
    "password",
    "passwd",
    "token",
    "api_key",
    "apikey",
    "auth",
    "salt",
    "private_key",
    "privatekey",
    "client_secret",
    "consumer_secret",
];

/// Suffix-guard exclusions — last `_`-separated segment of the identifier.
const EXCLUDED_SUFFIXES: &[&str] = &[
    "count", "field", "handler", "type", "name", "url", "path", "class", "dict", "list", "set",
    "map",
];

/// Returns `true` if the lowercased identifier name matches a security keyword
/// and does not end with an excluded suffix.
fn is_security_lhs(lhs_lower: &str) -> bool {
    // Suffix guard.
    let last_segment = lhs_lower.rsplit('_').next().unwrap_or(lhs_lower);
    if EXCLUDED_SUFFIXES.contains(&last_segment) {
        return false;
    }
    SECURITY_KEYWORDS.iter().any(|&kw| lhs_lower.contains(kw))
}

/// Returns `true` when the literal value is non-empty / non-trivial and
/// should trigger a finding.
fn is_meaningful_literal(val: &RustLiteralValue) -> bool {
    match val {
        RustLiteralValue::Str(s) => !s.is_empty(),
        RustLiteralValue::Bytes(b) => !b.is_empty(),
        RustLiteralValue::Int(_) => true,
        RustLiteralValue::Other => false,
    }
}

/// Analyzer that emits `SEC012-hardcoded-security-constant` for hardcoded
/// security constants in Rust source files.
pub struct HardcodedSecurityConstantAnalyzer;

impl zuit_core::Analyzer for HardcodedSecurityConstantAnalyzer {
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

        ast.assignments
            .iter()
            .filter(|site| {
                is_security_lhs(&site.lhs_name) && is_meaningful_literal(&site.rhs_literal)
            })
            .map(|site| {
                let span = site.span;
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Security,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::High,
                    message: format!(
                        "hardcoded security constant: `{}` is assigned a literal value; \
                         use `std::env::var(\"NAME\")` or a secret manager instead",
                        site.lhs_name,
                    ),
                    location: Location {
                        file: file_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "load via `std::env::var(\"NAME\")` or a secret manager \
                         (AWS Secrets Manager / HashiCorp Vault / sops); \
                         never commit secrets to source."
                            .to_string(),
                    ),
                    references: vec!["https://cwe.mitre.org/data/definitions/547.html".to_string()],
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
        let analyzer = HardcodedSecurityConstantAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_let_api_key_string() {
        let src = r#"fn f() { let api_key = "test"; }"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn flags_let_password_string() {
        let src = r#"fn f() { let password = "admin"; }"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_let_private_key_string() {
        let src = r#"fn f() { let private_key = "abc"; }"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_static_api_key() {
        // module-level `static` declaration
        let src = r#"static API_KEY: &str = "test";"#;
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for static, got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_const_secret() {
        let src = r#"const MY_SECRET: &str = "hardcoded";"#;
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for const, got: {findings:#?}"
        );
    }

    #[test]
    fn flags_let_token_integer() {
        let src = "fn f() { let session_token = 1234_i64; }";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for integer token, got: {findings:#?}"
        );
    }

    #[test]
    fn flags_uppercase_secret() {
        // MY_SECRET_KEY — case-insensitive substring on `secret`
        let src = r#"const MY_SECRET_KEY: &str = "value";"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_env_var_rhs() {
        // RHS is a function call, not a literal.
        let src = r#"fn f() { let api_key = std::env::var("API_KEY").unwrap(); }"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "env var call should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_suffix_count() {
        let src = "fn f() { let total_password_count = 0; }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "_count suffix should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_suffix_handler() {
        let src = "fn f() { let auth_handler = setup(); }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "_handler suffix should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_suffix_type() {
        let src = r#"fn f() { let token_type = "bearer"; }"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "_type suffix should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_empty_string() {
        let src = r#"fn f() { let password = ""; }"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "empty string should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_unrelated_name() {
        let src = r#"fn f() { let username = "admin"; }"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "username is not a security keyword, got: {findings:#?}"
        );
    }

    // ── CWE tag ───────────────────────────────────────────────────────────────

    #[test]
    fn cwe_tag_is_cwe_547() {
        let src = r#"fn f() { let password = "admin"; }"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].cwe.iter().any(|c| c == "CWE-547"),
            "expected CWE-547 in finding.cwe, got: {:?}",
            findings[0].cwe
        );
    }

    #[test]
    fn supported_languages_is_rust_only() {
        let analyzer = HardcodedSecurityConstantAnalyzer;
        assert!(analyzer.supported_languages().supports(LanguageId("rust")));
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
    }
}
