//! `SOUND006-ffi-without-safety-doc` — fires when an `unsafe fn` inside an
//! `extern "…"` block has no `// SAFETY:` or `/// SAFETY:` comment on the
//! line(s) immediately above it.
//!
//! | Field | Value |
//! |---|---|
//! | Rule ID | `SOUND006-ffi-without-safety-doc` |
//! | Dimension | `unsafe_soundness` |
//! | Default severity | Medium |
//! | Languages | Rust only |

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

use crate::try_rust_ast;

/// The stable rule ID emitted by this analyzer.
const RULE_ID: &str = "SOUND006-ffi-without-safety-doc";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/SOUND006-ffi-without-safety-doc.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that fires when FFI `unsafe fn` declarations lack a safety comment.
pub struct Sound006FfiWithoutSafetyDoc;

impl zuit_core::Analyzer for Sound006FfiWithoutSafetyDoc {
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
            .extern_unsafe_fns_no_doc
            .iter()
            .map(|&span| {
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Custom("unsafe_soundness".to_string()),
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Medium,
                    message: "`unsafe fn` inside `extern` block has no `// SAFETY:` comment; \
                              document the invariants required by the foreign function"
                        .to_string(),
                    location: Location {
                        file: source_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Add `// SAFETY: <reason>` on the line above the `unsafe fn` \
                         declaration to explain the safety contract with the foreign library."
                            .to_string(),
                    ),
                    references: vec!["https://doc.rust-lang.org/nomicon/ffi.html".to_string()],
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
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, SourceFile};

    fn analyze(code: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.rs", code.as_bytes().to_vec()));
        let parsed = crate::parse::parse(source).unwrap();
        let analyzer = Sound006FfiWithoutSafetyDoc;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    #[test]
    fn sound006_extern_unsafe_fn_no_doc_emits_medium() {
        let findings = analyze("extern \"C\" {\n    unsafe fn foreign_call(x: i32) -> i32;\n}");
        assert_eq!(findings.len(), 1, "expected one SOUND006 finding");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn sound006_safety_comment_present_emits_zero() {
        let findings = analyze(
            "extern \"C\" {\n\
             // SAFETY: foreign_call is safe when x >= 0\n\
             unsafe fn foreign_call(x: i32) -> i32;\n\
             }",
        );
        assert!(
            findings.is_empty(),
            "expected 0 findings with SAFETY comment: {findings:#?}"
        );
    }

    #[test]
    fn sound006_safe_extern_fn_emits_zero() {
        // Non-unsafe fn in extern block should not fire.
        let findings = analyze("extern \"C\" {\n    fn safe_c_fn(x: i32) -> i32;\n}");
        assert!(
            findings.is_empty(),
            "expected 0 findings for non-unsafe extern fn: {findings:#?}"
        );
    }

    #[test]
    fn sound006_suppression_smoke() {
        let findings = analyze("extern \"C\" {\n    unsafe fn foreign_call(x: i32) -> i32;\n}");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }
}
