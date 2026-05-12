//! `SEC004-weak-crypto` — detects use of deprecated hash algorithms (MD5 and
//! SHA-1) via two complementary heuristics.
//!
//! ## Heuristics
//!
//! 1. **String-literal scan** — each entry in `SemanticIndex::string_literals`
//!    is tested against a regex that matches the whole tokens `md5`, `sha1`, or
//!    `sha-1` (case-insensitive, word-boundary anchored).  This catches patterns
//!    such as `hashlib.new("md5", data)` and `crypto.createHash('sha1')`.
//!
//! 2. **Import scan** — each entry in `SemanticIndex::imports` is tested for
//!    known weak-crypto module paths (case-insensitive substring match).
//!    Recognised paths include:
//!    - Python: `hashlib.md5`, `hashlib.sha1`, `Crypto.Hash.MD5`, `Crypto.Hash.SHA1`
//!    - JS/TS: `crypto-js/md5`, `crypto-js/sha1`
//!    - Rust crates: `md-5`, `sha-1`, `sha1`
//!
//! Double-flagging between the two heuristics is acceptable: a
//! `hashlib.new("sha1", data)` call in Python may produce both a string-literal
//! finding (for `"sha1"`) and, if the user has `from hashlib import sha1`, an
//! import finding.
//!
//! ## Avoiding false positives
//!
//! The string-literal regex uses `\b` word boundaries so that `sha512`, `sha256`,
//! or `sha1sum` do **not** match as `sha1`.

use std::sync::OnceLock;

use regex::Regex;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages, span::Location,
};

/// Rule ID for the weak-crypto check.
pub const RULE_ID: &str = "SEC004-weak-crypto";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/SEC004-weak-crypto.md",
    cwe: &["CWE-327"],
    owasp: &["A02:2021"],
};

/// Suggestion text used for every finding emitted by this rule.
const SUGGESTION: &str = "Use SHA-256 or stronger; for password hashing prefer Argon2 / bcrypt.";

// ── compiled patterns ─────────────────────────────────────────────────────────

/// Returns the compiled regex for weak algorithm names in string literals.
///
/// Matches the whole tokens `md5`, `sha1`, or `sha-1` (case-insensitive),
/// using word boundaries to avoid matching inside `sha512`, `sha256`, etc.
fn weak_algo_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(r"(?i)\b(md5|sha-?1)\b").expect("invariant: weak-algo regex is valid")
    })
}

/// Known import path substrings (lowercase) that indicate weak-crypto usage.
///
/// Checked via case-insensitive substring match against each `Import.path`.
const WEAK_IMPORT_SUBSTRINGS: &[&str] = &[
    "hashlib.md5",
    "hashlib.sha1",
    "crypto.hash.md5",
    "crypto.hash.sha1",
    "crypto-js/md5",
    "crypto-js/sha1",
    "md-5",
    "sha-1",
    "sha1",
];

/// Returns `true` if the given import path (lowercased) contains any of the
/// known weak-crypto substrings.
fn is_weak_import(path: &str) -> bool {
    let lower = path.to_lowercase();
    WEAK_IMPORT_SUBSTRINGS.iter().any(|sub| lower.contains(sub))
}

// ── analyzer ──────────────────────────────────────────────────────────────────

/// Analyzer that detects use of weak cryptographic hash algorithms.
#[derive(Debug, Default)]
pub struct WeakCryptoAnalyzer;

impl Analyzer for WeakCryptoAnalyzer {
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
        let index = file.index();
        let mut findings: Vec<Finding> = Vec::new();

        // ── heuristic 1: string-literal scan ─────────────────────────────────
        for lit in &index.string_literals {
            if weak_algo_pattern().is_match(&lit.value) {
                let (start_lc, end_lc) = source.span_to_linecols(lit.span);
                findings.push(Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Security,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "string literal `{}` references a weak hash algorithm",
                        lit.value,
                    ),
                    location: Location {
                        file: source.path.clone(),
                        span: lit.span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(SUGGESTION.to_string()),
                    references: vec![],
                    cwe: META.cwe_vec(),
                    owasp: META.owasp_vec(),
                });
            }
        }

        // ── heuristic 2: import-path scan ─────────────────────────────────────
        for imp in &index.imports {
            if is_weak_import(&imp.path) {
                let (start_lc, end_lc) = source.span_to_linecols(imp.span);
                findings.push(Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Security,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "import of `{}` uses a weak cryptographic hash algorithm",
                        imp.path,
                    ),
                    location: Location {
                        file: source.path.clone(),
                        span: imp.span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(SUGGESTION.to_string()),
                    references: vec![],
                    cwe: META.cwe_vec(),
                    owasp: META.owasp_vec(),
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Config, Language, SourceFile};
    use std::sync::Arc;

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

    // ── unit tests for is_weak_import ─────────────────────────────────────────

    #[test]
    fn weak_import_hashlib_md5_matches() {
        assert!(is_weak_import("hashlib.md5"));
    }

    #[test]
    fn weak_import_sha1_crate_matches() {
        assert!(is_weak_import("sha1::Sha1"));
    }

    #[test]
    fn weak_import_sha256_does_not_match() {
        // "sha256" does not contain any of the weak substrings.
        assert!(!is_weak_import("hashlib.sha256"));
    }

    #[test]
    fn weak_import_sha512_does_not_match() {
        assert!(!is_weak_import("sha512"));
    }

    // ── unit tests for the string-literal regex ───────────────────────────────

    #[test]
    fn regex_matches_md5() {
        assert!(weak_algo_pattern().is_match("md5"));
    }

    #[test]
    fn regex_matches_sha1() {
        assert!(weak_algo_pattern().is_match("sha1"));
    }

    #[test]
    fn regex_matches_sha_dash_1() {
        assert!(weak_algo_pattern().is_match("sha-1"));
    }

    #[test]
    fn regex_does_not_match_sha256() {
        assert!(!weak_algo_pattern().is_match("sha256"));
    }

    #[test]
    fn regex_does_not_match_sha512() {
        // Ensure "sha1" word boundary prevents matching inside "sha512" (no
        // shared substring that starts with sha1 boundary).
        assert!(!weak_algo_pattern().is_match("sha512"));
    }

    #[test]
    fn regex_case_insensitive() {
        assert!(weak_algo_pattern().is_match("MD5"));
        assert!(weak_algo_pattern().is_match("SHA1"));
        assert!(weak_algo_pattern().is_match("SHA-1"));
    }

    // ── Rust positive ─────────────────────────────────────────────────────────

    #[test]
    fn rust_weak_crypto_positive() {
        let source = include_str!("../../../fixtures/rust/weak_crypto/lib.rs");
        let file = rust_parse("fixtures/rust/weak_crypto/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = WeakCryptoAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC004 finding for weak_crypto Rust fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings
                .iter()
                .any(|f| f.cwe.iter().any(|c| c == "CWE-327")),
            "expected CWE-327 in finding.cwe"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.owasp.iter().any(|o| o == "A02:2021")),
            "expected A02:2021 in finding.owasp"
        );
    }

    // ── Rust negative ─────────────────────────────────────────────────────────

    #[test]
    fn rust_healthy_weak_crypto_negative() {
        let source = include_str!("../../../fixtures/rust/healthy/lib.rs");
        let file = rust_parse("fixtures/rust/healthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = WeakCryptoAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC004 findings for healthy Rust fixture, got {findings:#?}"
        );
    }

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_weak_crypto_positive() {
        let source = include_str!("../../../fixtures/python/weak_crypto/main.py");
        let file = python_parse("fixtures/python/weak_crypto/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = WeakCryptoAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC004 finding for weak_crypto Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Python negative ───────────────────────────────────────────────────────

    #[test]
    fn python_healthy_weak_crypto_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = WeakCryptoAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC004 findings for healthy Python fixture, got {findings:#?}"
        );
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_weak_crypto_positive() {
        let source = include_str!("../../../fixtures/js/weak_crypto/main.ts");
        let file = js_parse("fixtures/js/weak_crypto/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = WeakCryptoAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC004 finding for weak_crypto JS fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── JS negative ───────────────────────────────────────────────────────────

    #[test]
    fn js_healthy_weak_crypto_negative() {
        let source = include_str!("../../../fixtures/js/healthy/main.ts");
        let file = js_parse("fixtures/js/healthy/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = WeakCryptoAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC004 findings for healthy JS fixture, got {findings:#?}"
        );
    }

    // ── suggestion field populated ────────────────────────────────────────────

    #[test]
    fn md5_suggestion_mentions_sha256() {
        // "md5" string literal → suggestion must mention SHA-256
        let source = r#"fn h() { let algo = "md5"; }"#;
        let file = rust_parse("src/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = WeakCryptoAnalyzer.analyze_file(&ctx, &file);
        assert!(!findings.is_empty(), "expected ≥1 finding for md5");
        let sugg = findings[0]
            .suggestion
            .as_deref()
            .expect("suggestion must be Some");
        assert!(
            sugg.contains("SHA-256"),
            "MD5 suggestion should mention SHA-256; got: {sugg}"
        );
    }

    #[test]
    fn sha1_suggestion_mentions_sha256() {
        // "sha1" string literal → suggestion must mention SHA-256
        let source = r#"fn h() { let algo = "sha1"; }"#;
        let file = rust_parse("src/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = WeakCryptoAnalyzer.analyze_file(&ctx, &file);
        assert!(!findings.is_empty(), "expected ≥1 finding for sha1");
        let sugg = findings[0]
            .suggestion
            .as_deref()
            .expect("suggestion must be Some");
        assert!(
            sugg.contains("SHA-256"),
            "SHA-1 suggestion should mention SHA-256; got: {sugg}"
        );
    }

    #[test]
    fn suggestion_is_some_for_import_finding() {
        // Import of sha1 crate → suggestion must be Some and mention SHA-256.
        // (The recognised Rust import substrings are `md-5`, `sha-1`, `sha1` —
        // see [`WEAK_IMPORT_SUBSTRINGS`].)
        let source = "use sha1::Sha1;";
        let file = rust_parse("src/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = WeakCryptoAnalyzer.analyze_file(&ctx, &file);
        assert!(!findings.is_empty(), "expected ≥1 finding for sha1 import");
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings should have a suggestion"
        );
        let sugg = findings[0]
            .suggestion
            .as_deref()
            .expect("suggestion must be Some");
        assert!(
            sugg.contains("SHA-256"),
            "import finding suggestion should mention SHA-256; got: {sugg}"
        );
    }
}
