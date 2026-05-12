//! `ECO003-send-sync-violations-on-pub-types` — fires when a `pub struct`
//! contains a raw pointer field (`*mut T` or `*const T`) without an explicit
//! `unsafe impl Send for X` declaration in the same file.
//!
//! **Heuristic:** the rule uses pre-extracted `RustAst::pub_struct_with_raw_ptr`
//! spans, populated in `parse.rs`.  If any `unsafe impl Send` is found in the
//! same file the rule is suppressed file-wide (conservative, to avoid
//! false-positives when the author has already thought about Send/Sync safety).
//!
//! **False-positive risk:** the file-wide check may suppress findings when only
//! one struct has `unsafe impl Send` but another does not.  Document this
//! limitation in the rule's md doc.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
};

use crate::try_rust_ast;

const RULE_ID: &str = "ECO003-send-sync-violations-on-pub-types";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/ECO003-send-sync-violations-on-pub-types.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer for `ECO003-send-sync-violations-on-pub-types`.
pub struct Eco003SendSyncViolations;

impl zuit_core::Analyzer for Eco003SendSyncViolations {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("ecosystem".to_string())
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn kind(&self) -> AnalyzerKind {
        AnalyzerKind::FileLevel
    }

    fn analyze_file(
        &self,
        _ctx: &AnalysisContext<'_>,
        file: &zuit_core::ParsedFile,
    ) -> Vec<Finding> {
        let Some(ast) = try_rust_ast(file) else {
            return Vec::new();
        };

        if ast.pub_struct_with_raw_ptr.is_empty() {
            return Vec::new();
        }

        let src = file.source();
        let source_path = src.path.clone();

        ast.pub_struct_with_raw_ptr
            .iter()
            .map(|&span| {
                let (start_lc, end_lc) = src.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Custom("ecosystem".to_string()),
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Low,
                    message: "`pub struct` contains a raw pointer field (`*mut T` or `*const T`) \
                         without an `unsafe impl Send` declaration; the struct is not \
                         automatically `Send`, which may confuse downstream users."
                        .to_string(),
                    location: Location {
                        file: source_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Add `unsafe impl Send for YourStruct {}` (and document the \
                         invariants) or change the raw pointer to a wrapper type that \
                         implements `Send`."
                            .to_string(),
                    ),
                    references: vec![
                        "https://doc.rust-lang.org/nomicon/send-and-sync.html".to_string(),
                    ],
                    cwe: vec![],
                    owasp: vec![],
                }
            })
            .collect()
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, _project: &Project) -> Vec<Finding> {
        Vec::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use zuit_core::{Analyzer, Config, SourceFile};

    use super::*;

    fn parse_and_analyze(code: &str) -> Vec<Finding> {
        let src = Arc::new(SourceFile::new("test.rs", code.as_bytes().to_vec()));
        let parsed = crate::parse::parse(src).expect("parse failed");
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        Eco003SendSyncViolations.analyze_file(&ctx, &parsed)
    }

    /// Positive: pub struct with *mut field, no unsafe impl Send → 1 finding.
    #[test]
    fn eco003_pub_struct_raw_ptr_emits_low() {
        let code = "pub struct MyBuf { ptr: *mut u8, len: usize, }";
        let findings = parse_and_analyze(code);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    /// Negative: pub struct with *mut field AND unsafe impl Send → 0 findings.
    #[test]
    fn eco003_with_unsafe_impl_send_emits_zero() {
        let code = "pub struct MyBuf { ptr: *mut u8 }\n\
                    // SAFETY: we manage the pointer carefully\n\
                    unsafe impl Send for MyBuf {}";
        let findings = parse_and_analyze(code);
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Negative: private struct with *mut field → 0 findings.
    #[test]
    fn eco003_private_struct_emits_zero() {
        let code = "struct InternalBuf { ptr: *mut u8 }";
        let findings = parse_and_analyze(code);
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Negative: pub struct without raw pointer → 0 findings.
    #[test]
    fn eco003_pub_struct_no_ptr_emits_zero() {
        let code = "pub struct Point { x: f64, y: f64 }";
        let findings = parse_and_analyze(code);
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }
}
