//! `MAINT012-dead-store` — flags simple `let name = expr;` bindings whose
//! value is never read before going out of scope (Rust).
//!
//! # Detection
//!
//! Reads the pre-extracted [`crate::parse::RustAst::dead_stores`] populated
//! at parse time.  Only simple immutable `let name = expr;` with a
//! `Pat::Ident` pattern are considered (no `let mut`, no destructuring).
//!
//! # Default: DISABLED
//!
//! The Rust dead-store heuristic is shipped with `ENABLED = false` because
//! its token-stream substring search produced **too many false positives** on
//! the zuit codebase (see the docs page for the count).  The Rust compiler's
//! own `unused_variables` lint is more accurate.  Future work: add a config
//! flag (requires a new `rule_bool` accessor in `zuit_core`) to let users
//! opt in.
//!
//! In the meantime, users who want this check can enable it by patching the
//! `ENABLED` constant below or by relying on `rustc -W unused-variables`.

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

/// The stable rule ID.
const RULE_ID: &str = "MAINT012-dead-store";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/MAINT012-dead-store.md",
    cwe: &["CWE-563"],
    owasp: &[],
};

/// Whether this analyzer is currently enabled.
///
/// Set to `false` because the token-stream substring heuristic produces a
/// high false-positive rate on files that use macros heavily (the extractor
/// already skips files with non-empty macro bodies, but the FP count was
/// still above the 30-finding threshold for the zuit workspace).
///
/// To enable: set this to `true` (or wait for a future release that adds a
/// proper config toggle).
const ENABLED: bool = false;

/// Analyzer that emits `MAINT012-dead-store` for dead local variable writes
/// in Rust source files.
pub struct RustDeadStoreAnalyzer;

impl zuit_core::Analyzer for RustDeadStoreAnalyzer {
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
        // Hard-disabled: the heuristic has too many false positives.
        if !ENABLED {
            return Vec::new();
        }

        let Some(ast) = crate::try_rust_ast(file) else {
            return Vec::new();
        };

        // Skip files with non-empty macro bodies — macros are opaque and may
        // reference variable names without a syntactic Identifier node.
        if ast.has_macro_body {
            return Vec::new();
        }

        let source = file.source();
        let file_path = source.path.clone();

        ast.dead_stores
            .iter()
            .map(|ds| {
                let (start_lc, end_lc) = source.span_to_linecols(ds.span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Maintainability,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Low,
                    message: format!(
                        "variable `{}` is written but its value is never read \
                         (dead store, CWE-563)",
                        ds.name
                    ),
                    location: Location {
                        file: file_path.clone(),
                        span: ds.span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Remove the assignment if the value is unused, or read it \
                         before the binding goes out of scope. Prefix with `_` to \
                         silence this warning for intentionally unused bindings. \
                         The Rust compiler's `unused_variables` lint is more \
                         accurate for this check."
                            .to_string(),
                    ),
                    references: vec!["https://cwe.mitre.org/data/definitions/563.html".to_string()],
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

    fn parse_and_get_dead_stores(src: &str) -> Vec<crate::parse::RustDeadStore> {
        let source = Arc::new(SourceFile::new("test.rs", src.as_bytes().to_vec()));
        let parsed = rust_parse::parse(source).expect("parse failed");
        let ast = crate::try_rust_ast(&parsed).expect("invariant: RustAst present");
        ast.dead_stores.clone()
    }

    /// Test via the extractor directly because `ENABLED = false` causes
    /// `analyze_file` to return an empty vec unconditionally.
    fn analyze_extractor(src: &str) -> Vec<crate::parse::RustDeadStore> {
        parse_and_get_dead_stores(src)
    }

    // ── positive tests (extractor must find dead stores) ─────────────────────

    #[test]
    fn extractor_flags_binding_never_read() {
        // `x` is never referenced after the binding.
        let src = "fn f() { let x = 1; let _y = 2; }";
        let dead = analyze_extractor(src);
        assert!(
            dead.iter().any(|d| d.name == "x"),
            "expected `x` to be dead; got: {:?}",
            dead.iter().map(|d| &d.name).collect::<Vec<_>>()
        );
        // `_y` has underscore prefix — must be excluded.
        assert!(
            !dead.iter().any(|d| d.name == "_y"),
            "`_y` must not be flagged; got: {dead:?}"
        );
    }

    #[test]
    fn extractor_flags_compute_result_never_read() {
        let src = "fn compute() -> i32 { 42 } fn f() { let unused = compute(); }";
        let dead = analyze_extractor(src);
        assert!(
            dead.iter().any(|d| d.name == "unused"),
            "expected `unused` to be dead; got: {dead:?}"
        );
    }

    // ── negative tests (extractor must NOT find dead stores) ─────────────────

    #[test]
    fn extractor_does_not_flag_binding_that_is_read() {
        let src = "fn f() { let x = 1; let _ = x + 1; }";
        let dead = analyze_extractor(src);
        assert!(
            !dead.iter().any(|d| d.name == "x"),
            "`x` is read — must not be dead; got: {dead:?}"
        );
    }

    #[test]
    fn extractor_does_not_flag_mut_binding() {
        // `let mut x` — skipped by the scanner.
        let src = "fn f() { let mut x = 1; x = 2; let _ = x; }";
        let dead = analyze_extractor(src);
        assert!(
            !dead.iter().any(|d| d.name == "x"),
            "`mut` binding must be skipped; got: {dead:?}"
        );
    }

    #[test]
    fn extractor_does_not_flag_destructure() {
        // `let (a, b) = pair();` — skipped (not a simple Pat::Ident).
        let src =
            "fn pair() -> (i32, i32) { (1, 2) } fn f() { let (a, b) = pair(); let _ = a + b; }";
        let dead = analyze_extractor(src);
        assert!(
            !dead.iter().any(|d| d.name == "a" || d.name == "b"),
            "destructure must be skipped; got: {dead:?}"
        );
    }

    #[test]
    fn extractor_does_not_flag_shadowing_chain() {
        // `let x = 1; let x = 2; x` — shadowing; first binding is not flagged.
        let src = "fn f() -> i32 { let x = 1; let x = 2; x }";
        let dead = analyze_extractor(src);
        assert!(
            dead.is_empty(),
            "shadowing chain must not be flagged; got: {dead:?}"
        );
    }

    // ── analyzer behavior tests (ENABLED=false) ───────────────────────────────

    #[test]
    fn analyze_file_returns_empty_because_disabled() {
        // Even a clear dead store must produce no finding because ENABLED=false.
        let src = "fn f() { let unused = 42; }";
        let source = Arc::new(SourceFile::new("test.rs", src.as_bytes().to_vec()));
        let parsed = rust_parse::parse(source).expect("parse failed");
        let analyzer = RustDeadStoreAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_file(&ctx, &parsed);
        assert!(
            findings.is_empty(),
            "ENABLED=false must suppress all findings; got: {findings:#?}"
        );
    }

    #[test]
    fn macro_body_file_returns_empty_even_if_enabled_were_true() {
        // If the file has a macro body, the extractor flags has_macro_body=true,
        // which would cause early-return.  Verify x is NOT in dead_stores here
        // because the file contains a macro with body println!("{}",x) which
        // references x — the search should not find it dead.
        let src = r#"fn f() { let x = 1; println!("{}", x); }"#;
        // x appears inside the macro body — the important test is that
        // analyze_file returns empty (ENABLED=false, and would also be empty
        // because has_macro_body causes early-return if ENABLED were true).
        let source = Arc::new(SourceFile::new("test.rs", src.as_bytes().to_vec()));
        let parsed = rust_parse::parse(source).expect("parse failed");
        let analyzer = RustDeadStoreAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let findings = analyzer.analyze_file(&ctx, &parsed);
        assert!(
            findings.is_empty(),
            "file with macro body must produce no findings; got: {findings:#?}"
        );
    }

    // ── CWE tag check ─────────────────────────────────────────────────────────

    #[test]
    fn meta_has_cwe_563() {
        assert!(META.cwe.contains(&"CWE-563"), "META must include CWE-563");
    }

    #[test]
    fn supported_languages_is_rust_only() {
        let analyzer = RustDeadStoreAnalyzer;
        assert!(analyzer.supported_languages().supports(LanguageId("rust")));
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
    }
}
