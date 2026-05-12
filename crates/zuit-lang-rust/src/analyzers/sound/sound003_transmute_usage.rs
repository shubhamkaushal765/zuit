//! `SOUND003-transmute-usage` — fires when source contains a call to
//! `mem::transmute`, `std::mem::transmute`, or bare `transmute`.
//!
//! | Field | Value |
//! |---|---|
//! | Rule ID | `SOUND003-transmute-usage` |
//! | Dimension | `unsafe_soundness` |
//! | Default severity | High |
//! | CWE | CWE-704 |
//! | Languages | Rust only |

use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};
use smallvec::smallvec;

use crate::try_rust_ast;

/// The stable rule ID emitted by this analyzer.
const RULE_ID: &str = "SOUND003-transmute-usage";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/SOUND003-transmute-usage.md",
    cwe: &["CWE-704"],
    owasp: &[],
};

/// Analyzer that fires on every `transmute` call expression.
pub struct Sound003TransmuteUsage;

impl zuit_core::Analyzer for Sound003TransmuteUsage {
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
            .transmute_calls
            .iter()
            .map(|&span| {
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Custom("unsafe_soundness".to_string()),
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::High,
                    message: "`mem::transmute` reinterprets bits between types without any \
                              safety guarantees; it can trigger undefined behaviour if the \
                              types are not layout-compatible"
                        .to_string(),
                    location: Location {
                        file: source_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Replace with a safer alternative such as `pointer::cast`, \
                         `From`/`Into`, or a well-audited `bytemuck::cast`. If transmute \
                         is unavoidable, add a `// SAFETY:` comment proving layout \
                         compatibility."
                            .to_string(),
                    ),
                    references: vec![
                        "https://doc.rust-lang.org/std/mem/fn.transmute.html".to_string(),
                        "https://cwe.mitre.org/data/definitions/704.html".to_string(),
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
        let analyzer = Sound003TransmuteUsage;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    #[test]
    fn sound003_transmute_usage_emits_high() {
        let findings =
            analyze("use std::mem; fn f() { let x: u32 = 0; let _: i32 = mem::transmute(x); }");
        assert_eq!(findings.len(), 1, "expected one SOUND003 finding");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn sound003_transmute_cwe_704() {
        let findings =
            analyze("use std::mem; fn f() { let x: u32 = 0; let _: i32 = mem::transmute(x); }");
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].cwe.contains(&"CWE-704".to_string()),
            "expected CWE-704: {:?}",
            findings[0].cwe
        );
    }

    #[test]
    fn sound003_no_transmute_emits_zero() {
        let findings = analyze("fn f() { let x: u32 = 1u32; let _: u64 = x as u64; }");
        assert!(
            findings.is_empty(),
            "expected 0 findings without transmute: {findings:#?}"
        );
    }

    #[test]
    fn sound003_std_mem_transmute_detected() {
        let findings = analyze(
            "fn f() { let x: u32 = 0; \
             let _: i32 = unsafe { std::mem::transmute(x) }; }",
        );
        assert_eq!(
            findings.len(),
            1,
            "expected one SOUND003 finding for std::mem::transmute"
        );
    }

    #[test]
    fn sound003_suppression_smoke() {
        let findings =
            analyze("use std::mem; fn f() { let x: u32 = 0; let _: i32 = mem::transmute(x); }");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }
}
