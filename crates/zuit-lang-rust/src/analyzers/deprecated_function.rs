//! `MAINT015-deprecated-function` — flags Rust items annotated with the
//! `#[deprecated]` attribute (CWE-477).
//!
//! # Detection
//!
//! Reads the pre-extracted `RustAst::deprecated_items` populated at parse
//! time inside `Extractor`'s `visit_item_*` methods.
//!
//! Item kinds covered: `fn`, `impl` method, trait method, `struct`, `enum`,
//! `const`, `static`, type alias.  Both the bare `#[deprecated]` form and the
//! parameterised forms `#[deprecated(since = "…", note = "…")]` are
//! recognised — `syn` parses them identically.
//!
//! # Languages
//!
//! Rust only.

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

/// The stable rule ID.
const RULE_ID: &str = "MAINT015-deprecated-function";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/MAINT015-deprecated-function.md",
    cwe: &["CWE-477"],
    owasp: &[],
};

/// Analyzer that emits `MAINT015-deprecated-function` for Rust items marked
/// `#[deprecated]`.
pub struct DeprecatedFunctionAnalyzer;

impl zuit_core::Analyzer for DeprecatedFunctionAnalyzer {
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

        ast.deprecated_items
            .iter()
            .map(|item| {
                let (start_lc, end_lc) = source.span_to_linecols(item.span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Maintainability,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "{} `{}` is marked `#[deprecated]` — schedule it for removal",
                        item.kind, item.name
                    ),
                    location: Location {
                        file: file_path.clone(),
                        span: item.span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Plan a removal milestone for this deprecated item and migrate \
                         callers to the supported replacement before deleting it."
                            .to_string(),
                    ),
                    references: vec!["https://cwe.mitre.org/data/definitions/477.html".to_string()],
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
    use crate::RustLanguage;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, Language, LanguageId, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.rs", src.as_bytes().to_vec()));
        let parsed = RustLanguage.parse(source).expect("parse failed");
        let analyzer = DeprecatedFunctionAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    #[test]
    fn flags_bare_deprecated_function() {
        let src = "#[deprecated]\nfn old() {}\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("old"));
        assert!(findings[0].message.contains("fn"));
    }

    #[test]
    fn flags_parameterized_deprecated_function() {
        let src = "#[deprecated(since = \"1.0.0\", note = \"use new()\")]\nfn old() {}\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
    }

    #[test]
    fn flags_deprecated_struct() {
        let src = "#[deprecated]\npub struct OldType;\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("struct"));
        assert!(findings[0].message.contains("OldType"));
    }

    #[test]
    fn flags_deprecated_enum() {
        let src = "#[deprecated]\nenum E { A, B }\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("enum"));
    }

    #[test]
    fn flags_deprecated_const() {
        let src = "#[deprecated]\nconst OLD: u32 = 1;\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("const"));
    }

    #[test]
    fn flags_deprecated_static() {
        let src = "#[deprecated]\nstatic OLD: u32 = 1;\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("static"));
    }

    #[test]
    fn flags_deprecated_type_alias() {
        let src = "#[deprecated]\ntype OldAlias = u32;\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("type"));
    }

    #[test]
    fn flags_deprecated_impl_method() {
        let src = "struct S;\nimpl S {\n    #[deprecated]\n    pub fn old(&self) {}\n}\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].message.contains("method"));
        assert!(findings[0].message.contains("old"));
    }

    #[test]
    fn flags_deprecated_trait_method() {
        let src = "trait T {\n    #[deprecated]\n    fn old(&self);\n}\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("trait method"));
    }

    #[test]
    fn flags_each_deprecated_item_once() {
        let src = "#[deprecated]\nfn a() {}\n\n#[deprecated]\nfn b() {}\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn does_not_flag_plain_function() {
        assert!(analyze("fn good() {}\n").is_empty());
    }

    #[test]
    fn does_not_flag_other_attributes() {
        let src = "#[inline]\n#[must_use]\nfn good() -> u32 { 1 }\n";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn does_not_flag_doc_comment_mentioning_deprecated() {
        let src = "/// This function was deprecated in v1.0 but we never bothered.\nfn keeps_going() {}\n";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn supported_languages_is_rust_only() {
        let analyzer = DeprecatedFunctionAnalyzer;
        assert!(analyzer.supported_languages().supports(LanguageId("rust")));
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
    }
}
