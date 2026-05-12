//! `SOUND002-unsafe-in-pub-api-signature` — fires when an `unsafe fn` is visible
//! at the module boundary (`pub`, `pub(crate)`, etc.).
//!
//! | Field | Value |
//! |---|---|
//! | Rule ID | `SOUND002-unsafe-in-pub-api-signature` |
//! | Dimension | `unsafe_soundness` |
//! | Default severity | High |
//! | Languages | Rust only |

use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};
use smallvec::smallvec;

use crate::try_rust_ast;

/// The stable rule ID emitted by this analyzer.
const RULE_ID: &str = "SOUND002-unsafe-in-pub-api-signature";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/SOUND002-unsafe-in-pub-api-signature.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that fires when a `pub unsafe fn` is visible at the module boundary.
pub struct Sound002UnsafeInPubApiSignature;

impl zuit_core::Analyzer for Sound002UnsafeInPubApiSignature {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("unsafe_soundness".to_string())
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::Only(smallvec![LanguageId("rust")])
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let Some(rust_ast) = try_rust_ast(file) else {
            return Vec::new();
        };

        let source_path = file.source().path.clone();
        let source = file.source();

        rust_ast
            .pub_unsafe_fns
            .iter()
            .map(|&span| {
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Custom("unsafe_soundness".to_string()),
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::High,
                    message: "public `unsafe fn` exposes unsafety at the module boundary; \
                              callers must uphold invariants that the type system cannot enforce"
                        .to_string(),
                    location: Location {
                        file: source_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Wrap the unsafe internals in a safe abstraction and document \
                         the required invariants with `# Safety` in the doc comment."
                            .to_string(),
                    ),
                    references: vec![
                        "https://doc.rust-lang.org/reference/unsafe-functions.html".to_string(),
                        "https://doc.rust-lang.org/nomicon/safe-unsafe-meaning.html".to_string(),
                    ],
                    cwe: META.cwe_vec(),
                    owasp: META.owasp_vec(),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Analyzer, Config, SourceFile};
    use std::sync::Arc;

    fn analyze(code: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.rs", code.as_bytes().to_vec()));
        let parsed = crate::parse::parse(source).unwrap();
        let analyzer = Sound002UnsafeInPubApiSignature;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    #[test]
    fn sound002_unsafe_fn_in_pub_api_emits_high() {
        let findings = analyze("pub unsafe fn dangerous() {}");
        assert_eq!(findings.len(), 1, "expected one SOUND002 finding");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn sound002_private_unsafe_fn_emits_zero() {
        let findings = analyze("unsafe fn internal() {}");
        assert!(
            findings.is_empty(),
            "expected 0 findings for private unsafe fn: {findings:#?}"
        );
    }

    #[test]
    fn sound002_pub_crate_unsafe_fn_emits_high() {
        let findings = analyze("pub(crate) unsafe fn pkg_internal() {}");
        assert_eq!(
            findings.len(),
            1,
            "expected one SOUND002 finding for pub(crate): {findings:#?}"
        );
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn sound002_safe_pub_fn_emits_zero() {
        let findings = analyze("pub fn safe() -> u32 { 42 }");
        assert!(
            findings.is_empty(),
            "expected 0 findings for safe pub fn: {findings:#?}"
        );
    }

    #[test]
    fn sound002_suppression_smoke() {
        // Confirm the analyzer emits a finding for the trigger code.
        let findings = analyze("pub unsafe fn dangerous() {}");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }
}
