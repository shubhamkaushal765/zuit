//! `SEC012-hardcoded-security-constant` — flags assignments whose LHS
//! identifier is a security keyword and whose RHS is a literal value.
//!
//! # Detection
//!
//! Walks the full `ModModule` AST looking for:
//! - `Stmt::Assign` (e.g. `password = "admin"`)
//! - `Stmt::AnnAssign` (e.g. `api_key: str = "test"`)
//!
//! A finding is emitted when:
//! 1. The LHS (or any target for multi-target assigns) is a bare `Name` node.
//! 2. The identifier contains a security keyword (case-insensitive substring):
//!    `secret`, `password`, `passwd`, `token`, `api_key`, `apikey`, `auth`,
//!    `salt`, `private_key`, `privatekey`, `client_secret`, `consumer_secret`.
//! 3. The RHS is a string, bytes, or integer literal.
//! 4. None of the suffix-guard exclusions apply (see below).
//!
//! # Negative-case guards (suffix check on last `_`-separated segment)
//!
//! Skip when the last segment of the identifier name is one of:
//! `count`, `field`, `handler`, `type`, `name`, `url`, `path`, `class`,
//! `dict`, `list`, `set`, `map`.
//!
//! # Distinct from SEC001
//!
//! SEC001 (`hardcoded-secret`) uses **entropy** and **known-pattern** heuristics
//! on the *value* of string literals, regardless of the variable name.
//! SEC012 uses the **identifier name** to catch low-entropy values like
//! `api_key = "test"` or `admin_password = "admin"` that SEC001 would miss.
//! Both rules may fire on the same site when the value is also high-entropy or
//! pattern-matched; this is intentional — different `rule_id` values let users
//! disable one independently.

use rustpython_parser::ast::{Constant, Expr, Ranged, Stmt};
use rustpython_parser::text_size::TextRange;
use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, Span},
};

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

/// Security keyword substrings (case-insensitive, applied to the full name).
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

/// Returns `true` if the identifier name matches a security keyword.
///
/// The check is a case-insensitive substring search over the lowercased name.
fn is_security_lhs(name: &str) -> bool {
    let lower = name.to_lowercase();

    // Suffix guard: skip when the last underscore-separated segment is excluded.
    let last_segment = lower.rsplit('_').next().unwrap_or(&lower);
    if EXCLUDED_SUFFIXES.contains(&last_segment) {
        return false;
    }

    // Must contain at least one security keyword.
    SECURITY_KEYWORDS.iter().any(|&kw| lower.contains(kw))
}

/// Returns `true` when the expression is a non-empty string / bytes / integer
/// literal that should trigger SEC012.
///
/// Excluded:
/// - Empty string `""`
/// - `None` / `True` / `False` constants
/// - Call expressions (e.g. `os.environ["X"]`, `os.getenv("X")`)
fn is_literal_rhs(expr: &Expr) -> bool {
    match expr {
        Expr::Constant(c) => match &c.value {
            Constant::Str(s) => !s.is_empty(),
            Constant::Bytes(b) => !b.is_empty(),
            Constant::Int(_) => true,
            _ => false,
        },
        _ => false,
    }
}

/// Analyzer that emits `SEC012-hardcoded-security-constant` for hardcoded
/// security constants in Python source files.
pub struct HardcodedSecurityConstantAnalyzer;

impl zuit_core::Analyzer for HardcodedSecurityConstantAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Security
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::Only(smallvec![LanguageId("python")])
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let Some(ast) = crate::try_python_ast(file) else {
            return Vec::new();
        };

        let source = file.source();
        let file_path = source.path.clone();
        let mut findings = Vec::new();

        check_stmts(&ast.body, source, &file_path, &mut findings);
        findings
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn emit(
    range: TextRange,
    lhs_name: &str,
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    let span = Span::new(
        ByteOffset(range.start().to_u32()),
        ByteOffset(range.end().to_u32()),
    );
    let (start_lc, end_lc) = source.span_to_linecols(span);
    findings.push(Finding {
        analyzer: AnalyzerId::new(RULE_ID),
        dimension: Dimension::Security,
        rule_id: RULE_ID.to_string(),
        severity: Severity::High,
        message: format!(
            "hardcoded security constant: `{lhs_name}` is assigned a literal value; \
             use an environment variable or a secret manager instead"
        ),
        location: Location {
            file: file_path.to_path_buf(),
            span,
            start: start_lc,
            end: end_lc,
        },
        suggestion: Some(
            "load via `os.environ.get(\"NAME\")` or a secret manager \
             (AWS Secrets Manager / HashiCorp Vault / sops); \
             never commit secrets to source."
                .to_string(),
        ),
        references: vec!["https://cwe.mitre.org/data/definitions/547.html".to_string()],
        cwe: META.cwe_vec(),
        owasp: META.owasp_vec(),
    });
}

fn check_stmts(
    stmts: &[Stmt],
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    for stmt in stmts {
        check_stmt(stmt, source, file_path, findings);
    }
}

fn check_stmt(
    stmt: &Stmt,
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    match stmt {
        // `name = <literal>` — only emit when RHS is a security-relevant literal.
        Stmt::Assign(a) => {
            if !is_literal_rhs(&a.value) {
                return;
            }
            for target in &a.targets {
                if let Expr::Name(n) = target {
                    let name = n.id.as_str();
                    if is_security_lhs(name) {
                        emit(a.range(), name, source, file_path, findings);
                    }
                }
            }
        }
        // `name: type = <literal>`
        Stmt::AnnAssign(a) => {
            if let Some(val) = &a.value
                && is_literal_rhs(val)
                && let Expr::Name(n) = &*a.target
            {
                let name = n.id.as_str();
                if is_security_lhs(name) {
                    emit(a.range(), name, source, file_path, findings);
                }
            }
        }
        // Recurse into nested scopes.
        Stmt::FunctionDef(f) => check_stmts(&f.body, source, file_path, findings),
        Stmt::AsyncFunctionDef(f) => check_stmts(&f.body, source, file_path, findings),
        Stmt::ClassDef(c) => check_stmts(&c.body, source, file_path, findings),
        Stmt::If(s) => {
            check_stmts(&s.body, source, file_path, findings);
            check_stmts(&s.orelse, source, file_path, findings);
        }
        Stmt::For(s) => {
            check_stmts(&s.body, source, file_path, findings);
            check_stmts(&s.orelse, source, file_path, findings);
        }
        Stmt::AsyncFor(s) => {
            check_stmts(&s.body, source, file_path, findings);
            check_stmts(&s.orelse, source, file_path, findings);
        }
        Stmt::While(s) => check_stmts(&s.body, source, file_path, findings),
        Stmt::With(s) => check_stmts(&s.body, source, file_path, findings),
        Stmt::AsyncWith(s) => check_stmts(&s.body, source, file_path, findings),
        Stmt::Try(s) => {
            check_stmts(&s.body, source, file_path, findings);
            for handler in &s.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                check_stmts(&h.body, source, file_path, findings);
            }
            check_stmts(&s.orelse, source, file_path, findings);
            check_stmts(&s.finalbody, source, file_path, findings);
        }
        Stmt::TryStar(s) => {
            check_stmts(&s.body, source, file_path, findings);
            for handler in &s.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                check_stmts(&h.body, source, file_path, findings);
            }
        }
        _ => {}
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::PythonLanguage;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, Language, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.py", src.as_bytes().to_vec()));
        let lang = PythonLanguage;
        let parsed = lang.parse(source).expect("parse failed");
        let analyzer = HardcodedSecurityConstantAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_password_string_literal() {
        let findings = analyze("password = \"admin\"\n");
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn flags_api_key_string_literal() {
        let findings = analyze("api_key = \"test\"\n");
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_private_key_string_literal() {
        let findings = analyze("private_key = \"abc\"\n");
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_secret_string_literal() {
        let findings = analyze("my_secret = \"xyz\"\n");
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_token_integer_literal() {
        let findings = analyze("session_token = 1234\n");
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_admin_password_literal() {
        let findings = analyze("admin_password = \"admin\"\n");
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_client_secret_literal() {
        let findings = analyze("client_secret = \"supersecret\"\n");
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_uppercase_secret_literal() {
        // Case-insensitive matching: MY_SECRET_KEY should match `secret`.
        let findings = analyze("MY_SECRET_KEY = \"value\"\n");
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_environ_rhs() {
        // RHS is a call expression, not a literal.
        let findings = analyze("password = os.environ[\"PASSWORD\"]\n");
        assert!(
            findings.is_empty(),
            "os.environ[...] should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_getenv_rhs() {
        let findings = analyze("api_key = os.getenv(\"API_KEY\")\n");
        assert!(
            findings.is_empty(),
            "os.getenv(...) should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_suffix_count() {
        let findings = analyze("total_password_count = 0\n");
        assert!(
            findings.is_empty(),
            "_count suffix should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_suffix_handler() {
        let findings = analyze("secret_handler = None\n");
        assert!(
            findings.is_empty(),
            "_handler suffix should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_suffix_field() {
        let findings = analyze("password_field = \"input\"\n");
        assert!(
            findings.is_empty(),
            "_field suffix should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_suffix_type() {
        let findings = analyze("token_type = \"bearer\"\n");
        assert!(
            findings.is_empty(),
            "_type suffix should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_empty_string() {
        let findings = analyze("password = \"\"\n");
        assert!(
            findings.is_empty(),
            "empty string should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_none_rhs() {
        let findings = analyze("password = None\n");
        assert!(
            findings.is_empty(),
            "None should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_unrelated_name() {
        let findings = analyze("username = \"admin\"\n");
        assert!(
            findings.is_empty(),
            "username is not a security keyword, got: {findings:#?}"
        );
    }

    // ── helper unit tests ─────────────────────────────────────────────────────

    #[test]
    fn security_lhs_matches_case_insensitive() {
        assert!(is_security_lhs("PASSWORD"));
        assert!(is_security_lhs("API_KEY"));
        assert!(is_security_lhs("MY_SECRET_TOKEN"));
        assert!(is_security_lhs("db_password"));
    }

    #[test]
    fn security_lhs_rejects_suffixes() {
        assert!(!is_security_lhs("password_count"));
        assert!(!is_security_lhs("secret_handler"));
        assert!(!is_security_lhs("token_type"));
        assert!(!is_security_lhs("auth_name"));
    }

    #[test]
    fn security_lhs_rejects_unrelated() {
        assert!(!is_security_lhs("username"));
        assert!(!is_security_lhs("host"));
        assert!(!is_security_lhs("port"));
    }

    #[test]
    fn supported_languages_is_python_only() {
        let analyzer = HardcodedSecurityConstantAnalyzer;
        assert!(
            analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
        assert!(!analyzer.supported_languages().supports(LanguageId("rust")));
    }

    #[test]
    fn cwe_tag_is_present() {
        let findings = analyze("password = \"admin\"\n");
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].cwe.iter().any(|c| c == "CWE-547"),
            "expected CWE-547 in finding.cwe, got: {:?}",
            findings[0].cwe
        );
    }
}
