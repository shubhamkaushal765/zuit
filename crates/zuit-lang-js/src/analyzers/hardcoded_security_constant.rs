//! `SEC012-hardcoded-security-constant` — flags assignments whose LHS
//! identifier is a security keyword and whose RHS is a literal value.
//!
//! # Detection
//!
//! Reads the pre-extracted `JsAst::assignments` populated
//! at parse time by the JS walker. Each assignment site whose `lhs_name`
//! matches a security keyword AND whose `rhs_literal` is a meaningful value
//! emits a finding.
//!
//! Covered constructs:
//! - `const SECRET = "x";`
//! - `let api_key = "test";`
//! - `var password = "admin";`
//! - `token = 1234;` (assignment expression)
//!
//! # Distinct from SEC001
//!
//! SEC001 uses entropy/pattern heuristics on the *value*. SEC012 uses the
//! *identifier name* — catching low-entropy values like `const SECRET = "x"`.
//! Both may fire on the same site; that is intentional (different `rule_id`).

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

use crate::native_ast::JsLiteralValue;

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
    let last_segment = lhs_lower.rsplit('_').next().unwrap_or(lhs_lower);
    if EXCLUDED_SUFFIXES.contains(&last_segment) {
        return false;
    }
    SECURITY_KEYWORDS.iter().any(|&kw| lhs_lower.contains(kw))
}

/// Returns `true` when the literal value is non-empty / non-trivial.
fn is_meaningful_literal(val: &JsLiteralValue) -> bool {
    match val {
        JsLiteralValue::Str(s) => !s.is_empty(),
        JsLiteralValue::Int(_) => true,
        JsLiteralValue::Other => false,
    }
}

/// Analyzer that emits `SEC012-hardcoded-security-constant` for hardcoded
/// security constants in JavaScript/TypeScript source files.
pub struct JsHardcodedSecurityConstantAnalyzer;

impl zuit_core::Analyzer for JsHardcodedSecurityConstantAnalyzer {
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
                         use `process.env.NAME` or a secret manager instead",
                        site.lhs_name,
                    ),
                    location: Location {
                        file: file_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "load via `process.env.NAME` or a secret manager \
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
    use crate::parse as js_parse;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, LanguageId, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.ts", src.as_bytes().to_vec()));
        let parsed = js_parse::parse(source).expect("parse failed");
        let analyzer = JsHardcodedSecurityConstantAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_const_secret_string() {
        let src = r#"const SECRET = "x";"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn flags_let_api_key_string() {
        let src = r#"let api_key = "test";"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_var_password_string() {
        let src = r#"var password = "admin";"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_private_key_string() {
        let src = r#"const private_key = "abc";"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_client_secret_string() {
        let src = r#"const clientSecret = "mysecret";"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_process_env_rhs() {
        let src = "const api_key = process.env.API_KEY;";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "process.env should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_suffix_count() {
        let src = "const total_password_count = 0;";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "_count suffix should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_suffix_handler() {
        let src = "const secret_handler = new MyClass();";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "_handler suffix should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_suffix_type() {
        let src = r#"const token_type = "bearer";"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "_type suffix should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_empty_string() {
        let src = r#"const password = "";"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "empty string should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_unrelated_name() {
        let src = r#"const username = "admin";"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "username is not a security keyword, got: {findings:#?}"
        );
    }

    // ── CWE + language ────────────────────────────────────────────────────────

    #[test]
    fn cwe_tag_is_cwe_547() {
        let src = r#"const password = "admin";"#;
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].cwe.iter().any(|c| c == "CWE-547"),
            "expected CWE-547 in finding.cwe, got: {:?}",
            findings[0].cwe
        );
    }

    #[test]
    fn supported_languages_is_javascript_only() {
        let analyzer = JsHardcodedSecurityConstantAnalyzer;
        assert!(
            analyzer
                .supported_languages()
                .supports(LanguageId("javascript"))
        );
        assert!(!analyzer.supported_languages().supports(LanguageId("rust")));
    }
}
