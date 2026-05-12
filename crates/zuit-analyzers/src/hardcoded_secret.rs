//! `SEC001-hardcoded-secret` — detects credentials and high-entropy secrets
//! embedded in string literals.
//!
//! Two heuristics are applied in order for each string literal found in
//! `SemanticIndex::string_literals`:
//!
//! 1. **Pattern matching** against a catalogue of known secret shapes (AWS
//!    access keys, JWTs, Slack tokens, PEM private-key headers).
//! 2. **Shannon entropy** — a literal of length ≥ 24 with entropy ≥ 4.5
//!    bits/byte is flagged as a likely high-entropy secret.
//!
//! Doc-comment text is stored in `SemanticIndex::doc_comments` (not
//! `string_literals`) so it is automatically excluded from both heuristics.

use std::sync::OnceLock;

use regex::Regex;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages, span::Location,
};

/// Rule ID for the hardcoded-secret check.
pub const RULE_ID: &str = "SEC001-hardcoded-secret";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/SEC001-hardcoded-secret.md",
    cwe: &["CWE-798"],
    owasp: &["A07:2021"],
};

/// Minimum length (in bytes) before entropy is evaluated.
const ENTROPY_MIN_LEN: usize = 24;

/// Shannon entropy threshold (bits per byte) above which a long literal is
/// considered a high-entropy secret.
const ENTROPY_THRESHOLD: f64 = 4.5;

// ── compiled regex patterns ───────────────────────────────────────────────────

/// Returns the compiled regex for AWS access key IDs.
fn aws_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| Regex::new(r"AKIA[0-9A-Z]{16}").expect("invariant: AWS pattern is valid"))
}

/// Returns the compiled regex for JSON Web Tokens.
fn jwt_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
            .expect("invariant: JWT pattern is valid")
    })
}

/// Returns the compiled regex for Slack API tokens.
fn slack_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(r"xox[abp]-[A-Za-z0-9-]{10,}").expect("invariant: Slack pattern is valid")
    })
}

/// Returns the compiled regex for PEM private-key headers.
fn pem_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").expect("invariant: PEM pattern is valid")
    })
}

/// Returns the compiled regex for GitHub personal-access tokens.
fn github_pat_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(r"gh[opsur]_[A-Za-z0-9]{36}").expect("invariant: GitHub PAT pattern is valid")
    })
}

/// Returns the compiled regex for Stripe live API keys.
fn stripe_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(r"(?:sk|pk|rk)_live_[0-9A-Za-z]{24,}")
            .expect("invariant: Stripe pattern is valid")
    })
}

/// Returns the compiled regex for Google API keys.
fn google_api_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(r"AIza[0-9A-Za-z_\-]{35}").expect("invariant: Google API key pattern is valid")
    })
}

/// Returns the compiled regex for Twilio API keys (34-char, starting with `SK`).
fn twilio_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(r"SK[0-9a-fA-F]{32}").expect("invariant: Twilio pattern is valid")
    })
}

/// Returns the compiled regex for Mailgun API keys.
fn mailgun_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(r"key-[0-9a-zA-Z]{32}").expect("invariant: Mailgun pattern is valid")
    })
}

// ── entropy calculation ───────────────────────────────────────────────────────

/// Computes the Shannon entropy (bits per byte) over the byte frequencies of
/// `s`.
///
/// The formula is `H = −Σ p_i × log₂(p_i)` where the probability `p_i` of
/// each byte value is its frequency divided by the total length.  Returns 0.0
/// for empty strings.
#[allow(clippy::cast_precision_loss)] // files bounded by u32; precision loss is acceptable
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

// ── analyzer ─────────────────────────────────────────────────────────────────

/// Analyzer that detects hardcoded secrets in string literals.
#[derive(Debug, Default)]
pub struct HardcodedSecretAnalyzer;

/// Describes why a literal was flagged.
enum MatchKind<'a> {
    /// A known secret pattern matched with the given human-readable label.
    Pattern(&'a str),
    /// The literal exceeded the entropy threshold.
    Entropy(f64),
}

impl HardcodedSecretAnalyzer {
    /// Tests a single literal value against all heuristics.
    ///
    /// Returns `Some(MatchKind)` when the literal should be flagged, `None`
    /// otherwise.
    fn classify(value: &str) -> Option<MatchKind<'_>> {
        // Pattern catalogue — checked in order of specificity.
        if aws_pattern().is_match(value) {
            return Some(MatchKind::Pattern("AWS access key ID"));
        }
        if jwt_pattern().is_match(value) {
            return Some(MatchKind::Pattern("JSON Web Token"));
        }
        if slack_pattern().is_match(value) {
            return Some(MatchKind::Pattern("Slack API token"));
        }
        if pem_pattern().is_match(value) {
            return Some(MatchKind::Pattern("PEM private key"));
        }
        if github_pat_pattern().is_match(value) {
            return Some(MatchKind::Pattern("GitHub personal-access token"));
        }
        if stripe_pattern().is_match(value) {
            return Some(MatchKind::Pattern("Stripe live API key"));
        }
        if google_api_pattern().is_match(value) {
            return Some(MatchKind::Pattern("Google API key"));
        }
        if twilio_pattern().is_match(value) {
            return Some(MatchKind::Pattern("Twilio API key"));
        }
        if mailgun_pattern().is_match(value) {
            return Some(MatchKind::Pattern("Mailgun API key"));
        }

        // Entropy heuristic as a fallback for unrecognised secrets.
        if value.len() >= ENTROPY_MIN_LEN {
            let entropy = shannon_entropy(value);
            if entropy >= ENTROPY_THRESHOLD {
                return Some(MatchKind::Entropy(entropy));
            }
        }

        None
    }
}

/// Returns a language-tailored remediation hint for `SEC001` findings.
///
/// The suggestion references the canonical environment-variable accessor in each
/// language and advises rotation if the secret may already be exposed.
fn suggestion_for(language: zuit_core::LanguageId) -> &'static str {
    match language.as_str() {
        "rust" => {
            "load via std::env::var(\"NAME\") or use a secret manager \
             (AWS Secrets Manager / HashiCorp Vault / sops); \
             never commit secrets to source. \
             If this is already exposed, rotate it immediately."
        }
        "python" => {
            "load via os.environ.get(\"NAME\") or use a secret manager \
             (AWS Secrets Manager / HashiCorp Vault / sops); \
             never commit secrets to source. \
             If this is already exposed, rotate it immediately."
        }
        "javascript" => {
            "load via process.env.NAME or use a secret manager \
             (AWS Secrets Manager / HashiCorp Vault / sops); \
             never commit secrets to source. \
             If this is already exposed, rotate it immediately."
        }
        _ => {
            "load from an environment variable or a secret manager \
             (AWS Secrets Manager / HashiCorp Vault / sops); \
             never commit secrets to source. \
             If this is already exposed, rotate it immediately."
        }
    }
}

impl Analyzer for HardcodedSecretAnalyzer {
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
        let suggestion = suggestion_for(file.language());

        index
            .string_literals
            .iter()
            .filter_map(|lit| {
                let kind = Self::classify(&lit.value)?;
                let message = match kind {
                    MatchKind::Pattern(label) => format!("hardcoded secret: {label}"),
                    MatchKind::Entropy(e) => {
                        format!("high-entropy string literal (entropy={e:.1})")
                    }
                };
                let (start_lc, end_lc) = source.span_to_linecols(lit.span);
                Some(Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Security,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::High,
                    message,
                    location: Location {
                        file: source.path.clone(),
                        span: lit.span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(suggestion.to_string()),
                    references: vec![],
                    cwe: META.cwe_vec(),
                    owasp: META.owasp_vec(),
                })
            })
            .collect()
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

    // ── entropy unit tests ────────────────────────────────────────────────────

    #[test]
    fn entropy_empty_string_is_zero() {
        assert!(shannon_entropy("") < f64::EPSILON);
    }

    #[test]
    fn entropy_uniform_string_is_zero() {
        // "aaaa" has only one distinct byte → entropy 0.
        assert!(shannon_entropy("aaaa") < f64::EPSILON);
    }

    #[test]
    fn entropy_high_for_random_like_string() {
        // A Base64-like token should be well above 4.5 bits/byte.
        let token = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        assert!(
            shannon_entropy(token) > ENTROPY_THRESHOLD,
            "expected high entropy for {token}"
        );
    }

    // ── pattern unit tests ────────────────────────────────────────────────────

    #[test]
    fn aws_pattern_matches() {
        let key = "AKIAIOSFODNN7EXAMPLE";
        assert!(aws_pattern().is_match(key));
    }

    #[test]
    fn aws_pattern_does_not_match_short() {
        assert!(!aws_pattern().is_match("AKIASHORT"));
    }

    #[test]
    fn slack_pattern_matches() {
        let token = "xoxb-1234567890-1234567890";
        assert!(slack_pattern().is_match(token));
    }

    // ── new pattern unit tests ────────────────────────────────────────────────

    #[test]
    fn github_pat_pattern_matches() {
        let token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        assert!(github_pat_pattern().is_match(token));
    }

    #[test]
    fn github_pat_pattern_does_not_match_short() {
        assert!(!github_pat_pattern().is_match("ghp_tooshort"));
    }

    #[test]
    fn stripe_pattern_matches() {
        let key = "sk_live_ABCDEFGHIJKLMNOPQRSTUVWX";
        assert!(stripe_pattern().is_match(key));
    }

    #[test]
    fn stripe_pattern_does_not_match_test_key() {
        assert!(!stripe_pattern().is_match("sk_test_ABCDEFGHIJKLMNOPQRSTUVWX"));
    }

    #[test]
    fn google_api_pattern_matches() {
        let key = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890";
        assert!(google_api_pattern().is_match(key));
    }

    #[test]
    fn google_api_pattern_does_not_match_short() {
        assert!(!google_api_pattern().is_match("AIzaToShort"));
    }

    #[test]
    fn twilio_pattern_matches() {
        // 34 chars total: "SK" + 32 hex chars
        let key = "SK1234567890abcdef1234567890abcdef";
        assert!(twilio_pattern().is_match(key));
    }

    #[test]
    fn twilio_pattern_does_not_match_short() {
        assert!(!twilio_pattern().is_match("SK1234"));
    }

    #[test]
    fn mailgun_pattern_matches() {
        let key = "key-abcdefghijklmnopqrstuvwxyz012345";
        assert!(mailgun_pattern().is_match(key));
    }

    #[test]
    fn mailgun_pattern_does_not_match_without_prefix() {
        assert!(!mailgun_pattern().is_match("abcdefghijklmnopqrstuvwxyz01234567"));
    }

    // ── end-to-end tests for new patterns ────────────────────────────────────

    #[test]
    fn github_pat_end_to_end() {
        let source = r#"const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";"#;
        let file = js_parse("main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = HardcodedSecretAnalyzer.analyze_file(&ctx, &file);
        assert!(!findings.is_empty(), "expected ≥1 finding for GitHub PAT");
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("GitHub personal-access token")),
            "expected label in message; got: {findings:#?}"
        );
    }

    #[test]
    fn stripe_end_to_end() {
        let source = r#"key = "sk_live_ABCDEFGHIJKLMNOPQRSTUVWX""#;
        let file = python_parse("main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = HardcodedSecretAnalyzer.analyze_file(&ctx, &file);
        assert!(!findings.is_empty(), "expected ≥1 finding for Stripe key");
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("Stripe live API key")),
            "expected label in message; got: {findings:#?}"
        );
    }

    #[test]
    fn google_api_end_to_end() {
        let source = r#"API_KEY = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890""#;
        let file = python_parse("config.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = HardcodedSecretAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 finding for Google API key"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("Google API key")),
            "expected label in message; got: {findings:#?}"
        );
    }

    #[test]
    fn twilio_end_to_end() {
        // 34 chars: SK + 32 hex
        let source = r#"let sid = "SK1234567890abcdef1234567890abcdef";"#;
        let file = js_parse("config.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = HardcodedSecretAnalyzer.analyze_file(&ctx, &file);
        assert!(!findings.is_empty(), "expected ≥1 finding for Twilio key");
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("Twilio API key")),
            "expected label in message; got: {findings:#?}"
        );
    }

    #[test]
    fn mailgun_end_to_end() {
        let source = r#"let apiKey = "key-abcdefghijklmnopqrstuvwxyz012345";"#;
        let file = js_parse("config.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = HardcodedSecretAnalyzer.analyze_file(&ctx, &file);
        assert!(!findings.is_empty(), "expected ≥1 finding for Mailgun key");
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("Mailgun API key")),
            "expected label in message; got: {findings:#?}"
        );
    }

    // ── suggestion quality ────────────────────────────────────────────────────

    #[test]
    fn suggestion_mentions_rotate_or_secret_manager() {
        let source = r#"fn main() { let k = "AKIAIOSFODNN7EXAMPLEKEY"; }"#;
        let file = rust_parse("src/main.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = HardcodedSecretAnalyzer.analyze_file(&ctx, &file);
        assert!(!findings.is_empty(), "expected ≥1 finding");
        let sugg = findings[0]
            .suggestion
            .as_deref()
            .expect("suggestion must be Some");
        assert!(
            sugg.contains("rotate") || sugg.contains("secret manager"),
            "suggestion should mention rotation or secret manager; got: {sugg}"
        );
    }

    // ── Rust positive ─────────────────────────────────────────────────────────

    #[test]
    fn rust_unhealthy_secret_positive() {
        let source = include_str!("../../../fixtures/rust/unhealthy/lib.rs");
        let file = rust_parse("fixtures/rust/unhealthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = HardcodedSecretAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC001 finding for unhealthy Rust fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings
                .iter()
                .all(|f| f.cwe.iter().any(|c| c == "CWE-798")),
            "expected CWE-798 in finding.cwe"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.owasp.iter().any(|o| o == "A07:2021")),
            "expected A07:2021 in finding.owasp"
        );
    }

    // ── Rust negative ─────────────────────────────────────────────────────────

    #[test]
    fn rust_healthy_secret_negative() {
        let source = include_str!("../../../fixtures/rust/healthy/lib.rs");
        let file = rust_parse("fixtures/rust/healthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = HardcodedSecretAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC001 findings for healthy Rust fixture, got {findings:#?}"
        );
    }

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_unhealthy_secret_positive() {
        let source = include_str!("../../../fixtures/python/unhealthy/main.py");
        let file = python_parse("fixtures/python/unhealthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = HardcodedSecretAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC001 finding for unhealthy Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Python negative ───────────────────────────────────────────────────────

    #[test]
    fn python_healthy_secret_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = HardcodedSecretAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC001 findings for healthy Python fixture, got {findings:#?}"
        );
    }

    // ── JS / TS positive ──────────────────────────────────────────────────────

    #[test]
    fn js_unhealthy_secret_positive() {
        let source = include_str!("../../../fixtures/js/unhealthy/main.ts");
        let file = js_parse("fixtures/js/unhealthy/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = HardcodedSecretAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC001 finding for unhealthy JS fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings
                .iter()
                .any(|f| f.cwe.iter().any(|c| c == "CWE-798")),
            "expected CWE-798 mapping on JS finding"
        );
    }

    // ── JS / TS negative ──────────────────────────────────────────────────────

    #[test]
    fn js_healthy_secret_negative() {
        let source = include_str!("../../../fixtures/js/healthy/main.ts");
        let file = js_parse("fixtures/js/healthy/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = HardcodedSecretAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC001 findings for healthy JS fixture, got {findings:#?}"
        );
    }

    // ── suggestion field populated ────────────────────────────────────────────

    #[test]
    fn rust_suggestion_contains_env_var() {
        // AWS key in a Rust file → suggestion should reference std::env::var
        let source = r#"fn main() { let k = "AKIAIOSFODNN7EXAMPLEKEY"; }"#;
        let file = rust_parse("src/main.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = HardcodedSecretAnalyzer.analyze_file(&ctx, &file);
        assert!(!findings.is_empty(), "expected ≥1 finding");
        let sugg = findings[0]
            .suggestion
            .as_deref()
            .expect("suggestion must be Some");
        assert!(
            sugg.contains("std::env::var"),
            "Rust suggestion should reference std::env::var; got: {sugg}"
        );
        assert!(
            sugg.contains("env"),
            "Rust suggestion should mention env; got: {sugg}"
        );
    }

    #[test]
    fn python_suggestion_contains_os_environ() {
        // AWS key in a Python file → suggestion should reference os.environ
        let source = r#"k = "AKIAIOSFODNN7EXAMPLEKEY""#;
        let file = python_parse("main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = HardcodedSecretAnalyzer.analyze_file(&ctx, &file);
        assert!(!findings.is_empty(), "expected ≥1 finding");
        let sugg = findings[0]
            .suggestion
            .as_deref()
            .expect("suggestion must be Some");
        assert!(
            sugg.contains("os.environ"),
            "Python suggestion should reference os.environ; got: {sugg}"
        );
    }

    #[test]
    fn js_suggestion_contains_process_env() {
        // AWS key in a JS/TS file → suggestion should reference process.env
        let source = r#"const k = "AKIAIOSFODNN7EXAMPLEKEY";"#;
        let file = js_parse("main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = HardcodedSecretAnalyzer.analyze_file(&ctx, &file);
        assert!(!findings.is_empty(), "expected ≥1 finding");
        let sugg = findings[0]
            .suggestion
            .as_deref()
            .expect("suggestion must be Some");
        assert!(
            sugg.contains("process.env"),
            "JS suggestion should reference process.env; got: {sugg}"
        );
    }
}
