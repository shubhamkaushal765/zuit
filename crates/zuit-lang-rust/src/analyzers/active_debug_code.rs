//! `MAINT011-active-debug-code` — flags active debug-code macro invocations in
//! Rust source files.
//!
//! # Detection
//!
//! Reads the pre-extracted `RustAst::debug_calls` populated at
//! parse time by the `Extractor` visitor.
//!
//! # Flagged macros
//!
//! - `dbg!(…)` → **`Severity::Medium`** (always flagged)
//! - `println!(…)` / `eprintln!(…)` → flagged only when the config option
//!   `MAINT011.flag_println` is `true` (default: `false`, because the zuit CLI
//!   itself legitimately uses `println!` in its output layer).
//!
//! # Skips
//!
//! Macros inside `#[cfg(test)]` or `#[cfg(debug_assertions)]` attribute scopes
//! are **not** separately excluded at the extractor level (syn's visitor does
//! not easily surface cfg context at macro granularity). The `flag_println`
//! default of `false` is the primary mitigation for noise in CLI crates.

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

use crate::parse::RustDebugKind;

/// The stable rule ID.
const RULE_ID: &str = "MAINT011-active-debug-code";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/MAINT011-active-debug-code.md",
    cwe: &["CWE-489"],
    owasp: &[],
};

/// Analyzer that emits `MAINT011-active-debug-code` for debug-code macro
/// invocations in Rust source files.
///
/// - `dbg!(…)` → `Severity::Medium` (always)
/// - `println!` / `eprintln!` → `Severity::Medium` (only when `flag_println` config is true)
pub struct ActiveDebugCodeAnalyzer;

impl zuit_core::Analyzer for ActiveDebugCodeAnalyzer {
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

        // `println!`/`eprintln!` are not flagged by default (too noisy for CLI
        // crates). There is no `Config::rule_bool` helper yet; the default
        // value of `false` is hard-coded here per plan note §2.2b.
        let flag_println = false;

        let source = file.source();
        let file_path = source.path.clone();

        ast.debug_calls
            .iter()
            .filter_map(|&(span, kind)| {
                let (macro_name, severity) = match kind {
                    RustDebugKind::Dbg => ("dbg!", Severity::Medium),
                    RustDebugKind::Println => {
                        if !flag_println {
                            return None;
                        }
                        ("println!", Severity::Medium)
                    }
                    RustDebugKind::Eprintln => {
                        if !flag_println {
                            return None;
                        }
                        ("eprintln!", Severity::Medium)
                    }
                };
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Some(Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Maintainability,
                    rule_id: RULE_ID.to_string(),
                    severity,
                    message: format!(
                        "debug macro `{macro_name}` should not be present in production code"
                    ),
                    location: Location {
                        file: file_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Remove this debug macro before shipping to production; \
                         use a proper logging crate (e.g. `tracing`, `log`) instead."
                            .to_string(),
                    ),
                    references: vec!["https://cwe.mitre.org/data/definitions/489.html".to_string()],
                    cwe: META.cwe_vec(),
                    owasp: META.owasp_vec(),
                })
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
        let analyzer = ActiveDebugCodeAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_dbg_macro() {
        let src = "fn f(x: i32) -> i32 { dbg!(x) }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_multiple_dbg_macros() {
        let src = "fn f() { dbg!(1); dbg!(2); }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 2, "expected 2 findings, got: {findings:#?}");
    }

    // ── negative tests (default config) ──────────────────────────────────────

    #[test]
    fn does_not_flag_println_by_default() {
        let src = r#"fn f() { println!("hello"); }"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "println! should not be flagged by default, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_eprintln_by_default() {
        let src = r#"fn f() { eprintln!("error: {}", x); }"#;
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "eprintln! should not be flagged by default, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_unrelated_macro() {
        let src = "fn f() { vec![1, 2, 3]; }";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "vec! should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn supported_languages_is_rust_only() {
        let analyzer = ActiveDebugCodeAnalyzer;
        assert!(analyzer.supported_languages().supports(LanguageId("rust")));
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
    }
}
