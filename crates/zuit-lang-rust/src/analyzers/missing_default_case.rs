//! `MAINT009-missing-default-case` — flags `match` expressions that lack a
//! fallback (`_`) arm when the scrutinee is a literal or a lowercase-path
//! expression.
//!
//! # Detection
//!
//! Reads the pre-extracted `RustAst::match_sites` populated at
//! parse time by the `Extractor` visitor.  A finding is emitted when:
//!
//! 1. `!has_wildcard` — no arm pattern is `_` or a `|`-pattern containing `_`.
//! 2. `scrutinee_kind` is `RustScrutineeKind::Literal` or
//!    `RustScrutineeKind::LowerPath`.
//!
//! Enum matches (scrutinee path ends with an uppercase letter, e.g.
//! `match Color::Red { … }`) are excluded to avoid false-positives on
//! exhaustive enum matches that the Rust compiler already checks.

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

use crate::parse::RustScrutineeKind;

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

/// Analyzer that emits `MAINT009-missing-default-case` for `match` expressions
/// without a wildcard arm in Rust source files.
pub struct MissingDefaultCaseAnalyzer;

impl zuit_core::Analyzer for MissingDefaultCaseAnalyzer {
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

        ast.match_sites
            .iter()
            .filter(|site| {
                !site.has_wildcard
                    && matches!(
                        site.scrutinee_kind,
                        RustScrutineeKind::Literal | RustScrutineeKind::LowerPath
                    )
            })
            .map(|site| {
                let span = site.span;
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Maintainability,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Medium,
                    message: "match expression is missing a default (`_`) arm; \
                              add `_ => {}` or `_ => unreachable!()` to handle \
                              unexpected values explicitly"
                        .to_string(),
                    location: Location {
                        file: file_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Add a `_ => { /* handle unexpected value */ }` arm as the last \
                         arm of the match expression, or use `_ => unreachable!()` if \
                         you are certain all cases are covered."
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
    use crate::parse as rust_parse;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, LanguageId, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.rs", src.as_bytes().to_vec()));
        let parsed = rust_parse::parse(source).expect("parse failed");
        let analyzer = MissingDefaultCaseAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_literal_scrutinee_no_wildcard() {
        let src = "fn f() { match 1 { 1 => {}, 2 => {} } }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_lowercase_path_scrutinee_no_wildcard() {
        // `status` is a lowercase local variable path — should fire.
        let src = "fn f(status: i32) { match status { 0 => {}, 1 => {} } }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_uppercase_enum_variant_scrutinee() {
        // CRITICAL: `Color::Red` as scrutinee — final segment "Red" starts with uppercase.
        // Must NOT fire (enum exhaustiveness is checked by the compiler).
        let src = "fn f() { match Color::Red { Color::Red => {}, Color::Blue => {} } }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "uppercase enum scrutinee should not fire, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_literal_with_wildcard() {
        let src = "fn f() { match 1 { _ => {} } }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "match with `_` arm should not fire, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_wildcard_with_other_arms() {
        let src = "fn f(x: i32) { match x { _ => {}, 1 => {} } }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "match with `_` arm should not fire, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_uppercase_path_self_field() {
        // `Self::Field` — final segment "Field" starts with uppercase.
        let src = "fn f() { match Self::Field { Self::Field => {} } }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "Self::Field (uppercase) should not fire, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_some_x_scrutinee() {
        // Scrutinee is a call expression (`Some(x)`) — `Other` kind, out of scope.
        let src = "fn f(x: Option<i32>) { match Some(x) { Some(y) => {}, None => {} } }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "call-expression scrutinee should not fire, got: {findings:#?}"
        );
    }

    // ── CWE tag check ─────────────────────────────────────────────────────────

    #[test]
    fn cwe_tag_is_cwe_478() {
        let src = "fn f() { match 1 { 1 => {}, 2 => {} } }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].cwe.iter().any(|c| c == "CWE-478"),
            "expected CWE-478 in finding.cwe, got: {:?}",
            findings[0].cwe
        );
    }

    #[test]
    fn supported_languages_is_rust_only() {
        let analyzer = MissingDefaultCaseAnalyzer;
        assert!(analyzer.supported_languages().supports(LanguageId("rust")));
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
    }
}
