//! `SOUND005-unsafe-and-parsing-combo` — fires when a function body contains
//! both an `unsafe` block AND a call to a known parser/decoder family.
//!
//! Known heuristic names: `from_bytes`, `from_raw`, `parse_unchecked`,
//! `from_utf8_unchecked`, `from_raw_parts`, `from_raw_parts_mut`, `from_ptr`.
//!
//! | Field | Value |
//! |---|---|
//! | Rule ID | `SOUND005-unsafe-and-parsing-combo` |
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
const RULE_ID: &str = "SOUND005-unsafe-and-parsing-combo";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/SOUND005-unsafe-and-parsing-combo.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that fires on functions mixing `unsafe` blocks with decoder calls.
pub struct Sound005UnsafeAndParsingCombo;

impl zuit_core::Analyzer for Sound005UnsafeAndParsingCombo {
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
            .unsafe_with_parser_calls
            .iter()
            .map(|&span| {
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Custom("unsafe_soundness".to_string()),
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::High,
                    message: "function body combines an `unsafe` block with a \
                              parser/decoder call (e.g. `from_utf8_unchecked`, \
                              `slice::from_raw_parts`); input validation may be \
                              bypassed in the unsafe path"
                        .to_string(),
                    location: Location {
                        file: source_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Separate parsing (safe, validated) from the unsafe operation. \
                         Ensure all invariants required by the unsafe call are proven \
                         before the unsafe block executes."
                            .to_string(),
                    ),
                    references: vec![
                        "https://doc.rust-lang.org/nomicon/working-with-unsafe.html".to_string(),
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
        let analyzer = Sound005UnsafeAndParsingCombo;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    #[test]
    fn sound005_unsafe_with_parser_call_emits_high() {
        let findings = analyze(
            "fn f(data: &[u8]) -> &str {\
             unsafe { std::str::from_utf8_unchecked(data) }\
             }",
        );
        assert_eq!(findings.len(), 1, "expected one SOUND005 finding");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn sound005_from_raw_parts_emits_high() {
        let findings = analyze(
            "fn f(p: *const u8, len: usize) -> &'static [u8] {\
             unsafe { std::slice::from_raw_parts(p, len) }\
             }",
        );
        assert_eq!(
            findings.len(),
            1,
            "expected one SOUND005 finding for from_raw_parts"
        );
    }

    #[test]
    fn sound005_safe_only_emits_zero() {
        let findings = analyze("fn f(x: u32) -> u64 { x as u64 }");
        assert!(
            findings.is_empty(),
            "expected 0 findings on safe code: {findings:#?}"
        );
    }

    #[test]
    fn sound005_unsafe_without_parser_emits_zero() {
        let findings = analyze("fn f() { unsafe { let _ = 1 + 1; } }");
        assert!(
            findings.is_empty(),
            "expected 0 findings for unsafe without parser call: {findings:#?}"
        );
    }

    #[test]
    fn sound005_suppression_smoke() {
        let findings = analyze(
            "fn f(data: &[u8]) -> &str {\
             unsafe { std::str::from_utf8_unchecked(data) }\
             }",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }
}
