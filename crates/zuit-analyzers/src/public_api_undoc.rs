//! `DOC001-public-api-undoc` — flags public functions and types that lack a
//! documentation comment.
//!
//! The analyzer consumes only the `SemanticIndex`: it checks
//! `functions[].visibility == Public && functions[].doc.is_none()` and the
//! equivalent for `types[]`.

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages, span::Location,
};

/// Rule ID for the public-API undocumented check.
pub const RULE_ID: &str = "DOC001-public-api-undoc";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/DOC001-public-api-undoc.md",
    cwe: &["CWE-1059"],
    owasp: &[],
};

/// Analyzer that emits a finding for every public function or type without a
/// documentation comment.
#[derive(Debug, Default)]
pub struct PublicApiUndocAnalyzer;

impl Analyzer for PublicApiUndocAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Documentation
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        use zuit_core::index::Visibility;

        let source = file.source();
        let index = file.index();
        let mut findings = Vec::new();

        // Check public functions.
        for func in &index.functions {
            if func.visibility != Visibility::Public || func.doc.is_some() {
                continue;
            }
            // Skip anonymous items (closures, lambdas with no name).
            let Some(name) = func.name.as_deref() else {
                continue;
            };

            let (start_lc, end_lc) = source.span_to_linecols(func.span);
            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Documentation,
                rule_id: RULE_ID.to_string(),
                severity: Severity::Medium,
                message: format!("public function `{name}` is missing a doc comment"),
                location: Location {
                    file: source.path.clone(),
                    span: func.span,
                    start: start_lc,
                    end: end_lc,
                },
                suggestion: Some(
                    "Add a doc comment (e.g. `/// …` in Rust or a docstring in Python) \
                     describing what this function does."
                        .to_string(),
                ),
                references: vec![],
                cwe: META.cwe_vec(),
                owasp: META.owasp_vec(),
            });
        }

        // Check public types.
        for ty in &index.types {
            if ty.visibility != Visibility::Public || ty.doc.is_some() {
                continue;
            }

            let (start_lc, end_lc) = source.span_to_linecols(ty.span);
            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Documentation,
                rule_id: RULE_ID.to_string(),
                severity: Severity::Medium,
                message: format!("public type `{}` is missing a doc comment", ty.name),
                location: Location {
                    file: source.path.clone(),
                    span: ty.span,
                    start: start_lc,
                    end: end_lc,
                },
                suggestion: Some(
                    "Add a doc comment describing this type's purpose and usage.".to_string(),
                ),
                references: vec![],
                cwe: META.cwe_vec(),
                owasp: META.owasp_vec(),
            });
        }

        findings
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

    fn make_ctx(config: &Config) -> AnalysisContext<'_> {
        AnalysisContext::new(config)
    }

    // ── Rust positive ─────────────────────────────────────────────────────────

    #[test]
    fn rust_unhealthy_undoc_positive() {
        // The unhealthy Rust fixture has `pub fn undocumented(...)` without a doc comment.
        let source = include_str!("../../../fixtures/rust/unhealthy/lib.rs");
        let file = rust_parse("fixtures/rust/unhealthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = PublicApiUndocAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 DOC001 finding for unhealthy Rust fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings.iter().any(|f| f.message.contains("undocumented")),
            "expected finding naming `undocumented`, got {findings:#?}"
        );
    }

    // ── Rust negative ─────────────────────────────────────────────────────────

    #[test]
    fn rust_healthy_undoc_negative() {
        let source = include_str!("../../../fixtures/rust/healthy/lib.rs");
        let file = rust_parse("fixtures/rust/healthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = PublicApiUndocAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 DOC001 findings for healthy Rust fixture, got {findings:#?}"
        );
    }

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_unhealthy_undoc_positive() {
        // The unhealthy Python fixture has `def undocumented_public_function(...)` without a docstring.
        let source = include_str!("../../../fixtures/python/unhealthy/main.py");
        let file = python_parse("fixtures/python/unhealthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = PublicApiUndocAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 DOC001 finding for unhealthy Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Python negative ───────────────────────────────────────────────────────

    #[test]
    fn python_healthy_undoc_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = PublicApiUndocAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 DOC001 findings for healthy Python fixture, got {findings:#?}"
        );
    }
}
