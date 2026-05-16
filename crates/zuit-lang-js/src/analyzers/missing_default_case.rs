//! `MAINT009-missing-default-case` — flags `switch` statements that lack a
//! `default:` clause in JavaScript/TypeScript source files.
//!
//! # Detection
//!
//! Reads the pre-extracted `JsAst::switch_sites`
//! populated at parse time by the walker.  A finding is emitted for every
//! `SwitchStatement` whose `cases` list contains no clause with `test: None`
//! (the AST representation of a `default:` clause in oxc).

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

/// The stable rule ID.
const RULE_ID: &str = "MAINT009-missing-default-case";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/MAINT009-missing-default-case.md",
    cwe: &["CWE-478"],
    owasp: &[],
};

/// Analyzer that emits `MAINT009-missing-default-case` for `switch` statements
/// without a `default:` clause in JavaScript/TypeScript source files.
pub struct JsMissingDefaultCaseAnalyzer;

impl zuit_core::Analyzer for JsMissingDefaultCaseAnalyzer {
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

        ast.switch_sites
            .iter()
            .filter(|site| !site.has_default)
            .map(|site| {
                let span = site.span;
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Maintainability,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Medium,
                    message: "switch statement is missing a `default:` clause; \
                              add `default: break;` or `default: throw new Error(…)` \
                              to handle unexpected values explicitly"
                        .to_string(),
                    location: Location {
                        file: file_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Add a `default:` clause as the last case of the switch statement. \
                         Use `default: throw new Error('Unhandled value: ' + value);` \
                         to fail loudly on unexpected input."
                            .to_string(),
                    ),
                    references: vec!["https://cwe.mitre.org/data/definitions/478.html".to_string()],
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
        let analyzer = JsMissingDefaultCaseAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_switch_without_default() {
        let src = "switch (x) { case 1: break; case 2: break; }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_switch_with_default() {
        let src = "switch (x) { case 1: break; default: break; }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "switch with default should not fire, got: {findings:#?}"
        );
    }

    // ── CWE tag check ─────────────────────────────────────────────────────────

    #[test]
    fn cwe_tag_is_cwe_478() {
        let src = "switch (x) { case 1: break; case 2: break; }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].cwe.iter().any(|c| c == "CWE-478"),
            "expected CWE-478 in finding.cwe, got: {:?}",
            findings[0].cwe
        );
    }

    #[test]
    fn supported_languages_is_javascript_only() {
        let analyzer = JsMissingDefaultCaseAnalyzer;
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
