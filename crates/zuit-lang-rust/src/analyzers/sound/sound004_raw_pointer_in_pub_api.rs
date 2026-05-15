//! `SOUND004-raw-pointer-in-pub-api` — fires when a `pub fn` signature contains
//! `*const T` or `*mut T` in argument or return position.
//!
//! | Field | Value |
//! |---|---|
//! | Rule ID | `SOUND004-raw-pointer-in-pub-api` |
//! | Dimension | `unsafe_soundness` |
//! | Default severity | High |
//! | Languages | Rust only |

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

use crate::try_rust_ast;

/// The stable rule ID emitted by this analyzer.
const RULE_ID: &str = "SOUND004-raw-pointer-in-pub-api";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/SOUND004-raw-pointer-in-pub-api.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that fires when a `pub fn` signature contains raw pointer types.
pub struct Sound004RawPointerInPubApi;

impl zuit_core::Analyzer for Sound004RawPointerInPubApi {
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
            .raw_ptr_pub_apis
            .iter()
            .map(|&span| {
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Custom("unsafe_soundness".to_string()),
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::High,
                    message: "public function signature contains a raw pointer (`*const T` or \
                              `*mut T`); callers cannot use this API safely without consulting \
                              additional documentation"
                        .to_string(),
                    location: Location {
                        file: source_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Replace the raw pointer with a safe reference (`&T` / `&mut T`), a \
                         `NonNull<T>`, or a `Box<T>`. If raw pointers are unavoidable (e.g. \
                         FFI), mark the function `unsafe` and add a `# Safety` doc comment."
                            .to_string(),
                    ),
                    references: vec![
                        "https://doc.rust-lang.org/reference/types/pointer.html".to_string(),
                        "https://doc.rust-lang.org/nomicon/ffi.html".to_string(),
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
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, SourceFile};

    fn analyze(code: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.rs", code.as_bytes().to_vec()));
        let parsed = crate::parse::parse(source).unwrap();
        let analyzer = Sound004RawPointerInPubApi;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    #[test]
    fn sound004_raw_pointer_in_pub_api_emits_high() {
        let findings = analyze("pub fn f() -> *const u8 { std::ptr::null() }");
        assert_eq!(findings.len(), 1, "expected one SOUND004 finding");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn sound004_mut_raw_pointer_arg_emits_high() {
        let findings = analyze("pub fn write(dst: *mut u8, val: u8) {}");
        assert_eq!(
            findings.len(),
            1,
            "expected one SOUND004 finding for *mut arg"
        );
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn sound004_private_fn_with_raw_ptr_emits_zero() {
        let findings = analyze("fn internal(p: *const u8) -> *mut u8 { p as *mut u8 }");
        assert!(
            findings.is_empty(),
            "expected 0 findings for private fn: {findings:#?}"
        );
    }

    #[test]
    fn sound004_pub_fn_safe_signature_emits_zero() {
        let findings = analyze("pub fn safe(x: u32) -> u64 { x as u64 }");
        assert!(
            findings.is_empty(),
            "expected 0 findings for safe pub fn: {findings:#?}"
        );
    }

    #[test]
    fn sound004_suppression_smoke() {
        let findings = analyze("pub fn f() -> *const u8 { std::ptr::null() }");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }
}
