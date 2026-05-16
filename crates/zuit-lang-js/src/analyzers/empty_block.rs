//! `MAINT013-empty-block` — flags `if`/`for`/`while` statements and `catch`
//! clauses whose body block is empty in JavaScript/TypeScript source files.
//!
//! # Detection
//!
//! Reads the pre-extracted `JsAst::empty_blocks` spans
//! populated at parse time by the walker.
//!
//! # Skips
//!
//! - `catch` clauses whose parameter is absent or named `_` (intentional
//!   swallow idiom).

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
/// in JavaScript/TypeScript source files.
///
/// Severity: **Low**. Empty `if`/`for`/`while`/`catch` blocks are almost
/// always leftover scaffolding or forgotten logic branches.
pub struct JsEmptyBlockAnalyzer;

impl zuit_core::Analyzer for JsEmptyBlockAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Maintainability
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
    use crate::parse as js_parse;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, LanguageId, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.ts", src.as_bytes().to_vec()));
        let parsed = js_parse::parse(source).expect("parse failed");
        let analyzer = JsEmptyBlockAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_empty_if_block() {
        let src = "const x = 1; if (x) {}";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_empty_while_block() {
        let src = "let x = 1; while (x > 0) {}";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_empty_for_block() {
        let src = "for (let i = 0; i < 10; i++) {}";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_empty_catch_with_named_param() {
        // catch (e) {} is flagged — not the intentional swallow idiom
        let src = "try { doSomething(); } catch (e) {}";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_nonempty_if() {
        let src = "const x = 1; if (x) { console.log(x); }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "expected no findings, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_empty_catch_underscore() {
        // catch (_) {} is the intentional swallow idiom — skip
        let src = "try { doSomething(); } catch (_) {}";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "catch (_) {{}} should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn supported_languages_is_javascript_only() {
        let analyzer = JsEmptyBlockAnalyzer;
        assert!(
            analyzer
                .supported_languages()
                .supports(LanguageId("javascript"))
        );
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
    }
}
