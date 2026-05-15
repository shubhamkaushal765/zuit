//! `MAINT013-empty-block` — flags `if`/`for`/`while` expressions whose body
//! block is empty in Rust source files.
//!
//! # Detection
//!
//! Reads the pre-extracted [`crate::parse::RustAst::empty_blocks`] spans
//! populated at parse time by the `Extractor` visitor.
//!
//! # Skips
//!
//! - Empty `loop {}` bodies (covered by MAINT010-infinite-loop-no-exit).
//! - Empty function bodies (often intentional stubs or trait implementations).

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

/// The stable rule ID.
const RULE_ID: &str = "MAINT013-empty-block";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/MAINT013-empty-block.md",
    cwe: &["CWE-1071"],
    owasp: &[],
};

/// Analyzer that emits `MAINT013-empty-block` for empty control-flow blocks
/// in Rust source files.
///
/// Severity: **Low**. Empty `if`/`for`/`while` blocks are almost always
/// leftover scaffolding or forgotten logic branches.
pub struct EmptyBlockAnalyzer;

impl zuit_core::Analyzer for EmptyBlockAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Maintainability
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

        ast.empty_blocks
            .iter()
            .map(|&span| {
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Maintainability,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Low,
                    message: "empty control-flow block — add implementation or a \
                              comment explaining the intent"
                        .to_string(),
                    location: Location {
                        file: file_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Fill in the block body, or add a comment if the empty body \
                         is intentional."
                            .to_string(),
                    ),
                    references: vec![
                        "https://cwe.mitre.org/data/definitions/1071.html".to_string(),
                    ],
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
        let analyzer = EmptyBlockAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_empty_if_block() {
        let src = "fn f(x: bool) { if x {} }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_empty_for_block() {
        let src = "fn f() { for _i in 0..10 {} }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_empty_while_block() {
        let src = "fn f(mut x: i32) { while x > 0 {} }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_nonempty_if() {
        let src = "fn f(x: bool) { if x { let _ = 1; } }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected no findings, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_empty_loop() {
        // empty loop {} is excluded — covered by MAINT010
        let src = "fn f() { loop {} }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "empty loop should not be flagged by MAINT013, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_empty_fn_body() {
        // empty function body is an intentional stub; not flagged
        let src = "fn stub() {}";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "empty function body should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn supported_languages_is_rust_only() {
        let analyzer = EmptyBlockAnalyzer;
        assert!(analyzer.supported_languages().supports(LanguageId("rust")));
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
    }
}
