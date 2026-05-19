//! `BUG002-switch-fallthrough` — flags `case` clauses in `switch` statements
//! that don't end with a terminating statement (`break`, `return`, `throw`,
//! `continue`) and silently fall through to the next case (CWE-484).
//!
//! # Detection
//!
//! Reads the pre-extracted `JsAst::case_fallthroughs` populated at parse
//! time by the walker.
//!
//! For each `SwitchStatement`, walk every case clause except the last:
//!
//! - If the case has **empty** consequent statements, treat it as an
//!   intentional grouping (`case 1: case 2: …`) — **not flagged**.
//! - If the case has at least one statement and the **last flat-level**
//!   statement is not a terminator, flag it.
//!
//! # Carve-out
//!
//! Following `ESLint` `no-fallthrough`, a line comment matching
//! `/falls?\s*through/i` on the preceding source line silences the finding.
//! Common phrasings: `// fallthrough`, `// falls through`, `// FALLTHROUGH`.
//!
//! # Languages
//!
//! JavaScript and TypeScript only (`LanguageId("javascript")`). Python's
//! `match` statement uses pattern matching, not fallthrough; Rust `match` arms
//! never fall through.

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

/// The stable rule ID.
const RULE_ID: &str = "BUG002-switch-fallthrough";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/BUG002-switch-fallthrough.md",
    cwe: &["CWE-484"],
    owasp: &[],
};

/// Analyzer that emits `BUG002-switch-fallthrough` for JS/TS `switch` cases
/// that silently fall through to the next case.
pub struct JsSwitchFallthroughAnalyzer;

impl zuit_core::Analyzer for JsSwitchFallthroughAnalyzer {
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

        ast.case_fallthroughs
            .iter()
            .map(|site| {
                let span = site.span;
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Maintainability,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Medium,
                    message: "switch case falls through to the next case — \
                              add a `break`, `return`, `throw`, or `continue`, \
                              or annotate with a `// falls through` comment if intentional"
                        .to_string(),
                    location: Location {
                        file: file_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "End the case body with `break;` (or `return`, `throw`, `continue`). \
                         If fallthrough is intentional, add `// falls through` on the line \
                         immediately before the next `case`."
                            .to_string(),
                    ),
                    references: vec!["https://cwe.mitre.org/data/definitions/484.html".to_string()],
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
        let analyzer = JsSwitchFallthroughAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_case_without_break() {
        let src = r"
            switch (x) {
                case 1:
                    doA();
                case 2:
                    doB();
                    break;
            }
        ";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_multiple_fallthroughs() {
        let src = r"
            switch (x) {
                case 1:
                    doA();
                case 2:
                    doB();
                case 3:
                    doC();
                    break;
            }
        ";
        let findings = analyze(src);
        assert_eq!(findings.len(), 2, "expected 2 findings, got: {findings:#?}");
    }

    #[test]
    fn flags_default_in_middle_falling_through() {
        let src = r"
            switch (x) {
                case 1:
                    doA();
                    break;
                default:
                    doDefault();
                case 2:
                    doB();
                    break;
            }
        ";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_empty_case_grouping() {
        // Empty consequents are the idiomatic `case 1: case 2: do…;` grouping.
        let src = r"
            switch (x) {
                case 1:
                case 2:
                case 3:
                    doMulti();
                    break;
            }
        ";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "empty case grouping should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_break_terminator() {
        let src = r"
            switch (x) {
                case 1:
                    doA();
                    break;
                case 2:
                    doB();
                    break;
            }
        ";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn does_not_flag_return_terminator() {
        let src = r"
            function f(x) {
                switch (x) {
                    case 1:
                        return doA();
                    case 2:
                        return doB();
                }
            }
        ";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn does_not_flag_throw_terminator() {
        let src = r"
            switch (x) {
                case 1:
                    throw new Error('a');
                case 2:
                    doB();
                    break;
            }
        ";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn does_not_flag_continue_terminator() {
        let src = r"
            for (const x of items) {
                switch (x) {
                    case 1:
                        continue;
                    case 2:
                        doB();
                        break;
                }
            }
        ";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn does_not_flag_last_case_without_break() {
        // The last case (or default at the end) can't fall through.
        let src = r"
            switch (x) {
                case 1:
                    doA();
                    break;
                case 2:
                    doB();
            }
        ";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn does_not_flag_last_default_without_break() {
        let src = r"
            switch (x) {
                case 1:
                    doA();
                    break;
                default:
                    doDefault();
            }
        ";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn does_not_flag_fallthrough_comment_carveout() {
        let src = r"
            switch (x) {
                case 1:
                    doA();
                    // falls through
                case 2:
                    doB();
                    break;
            }
        ";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "// falls through carve-out should suppress the finding, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_fallthrough_block_comment_carveout() {
        let src = r"
            switch (x) {
                case 1:
                    doA();
                    /* fallthrough */
                case 2:
                    doB();
                    break;
            }
        ";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "/* fallthrough */ carve-out should suppress the finding, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_block_terminator() {
        // Block statement whose last statement is a terminator.
        let src = r"
            switch (x) {
                case 1: {
                    doA();
                    break;
                }
                case 2:
                    doB();
                    break;
            }
        ";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn flags_block_without_terminator() {
        let src = r"
            switch (x) {
                case 1: {
                    doA();
                }
                case 2:
                    doB();
                    break;
            }
        ";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn supported_languages_is_javascript_only() {
        let analyzer = JsSwitchFallthroughAnalyzer;
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

    #[test]
    fn handles_empty_switch() {
        let src = "switch (x) {}";
        assert!(analyze(src).is_empty());
    }
}
