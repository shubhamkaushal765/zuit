//! `MAINT018-global-var-density` — fires when a file declares too many
//! file-scoped mutable public globals (`pub static mut NAME: T = …;`).
//!
//! # Detection
//!
//! Reads the pre-extracted `RustAst::pub_static_muts` field populated at
//! parse time by the `Extractor` visitor.  When the count of `pub static mut`
//! items in a file meets or exceeds the configured threshold, a single finding
//! is emitted pointing at the first such declaration.
//!
//! Only `pub static mut` items are counted.  Private (`static mut`) and
//! immutable (`pub static`) declarations are intentionally excluded.
//!
//! # Configuration
//!
//! ```toml
//! [rules."MAINT018-global-var-density"]
//! threshold = 3   # default; fire when count >= threshold
//! ```

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

/// The stable rule ID.
const RULE_ID: &str = "MAINT018-global-var-density";

/// Default threshold: fire when a file has this many or more `pub static mut` items.
const DEFAULT_THRESHOLD: u32 = 3;

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/MAINT018-global-var-density.md",
    cwe: &["CWE-1108"],
    owasp: &[],
};

/// Analyzer that emits `MAINT018-global-var-density` when a Rust source file
/// declares too many `pub static mut` globals.
///
/// Severity: **Low** / Dimension: **Maintainability** / CWE-1108.
pub struct GlobalVarDensityAnalyzer;

impl zuit_core::Analyzer for GlobalVarDensityAnalyzer {
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

    fn analyze_file(&self, ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let Some(ast) = crate::try_rust_ast(file) else {
            return Vec::new();
        };

        let threshold = ctx.config.rule_threshold(RULE_ID, DEFAULT_THRESHOLD);
        let count = u32::try_from(ast.pub_static_muts.len()).unwrap_or(u32::MAX);

        if count < threshold {
            return Vec::new();
        }

        let source = file.source();
        let file_path = source.path.clone();

        // Point at the first offender for the location.
        let span = ast.pub_static_muts[0];
        let (start_lc, end_lc) = source.span_to_linecols(span);

        vec![Finding {
            analyzer: AnalyzerId::new(RULE_ID),
            dimension: Dimension::Maintainability,
            rule_id: RULE_ID.to_string(),
            severity: Severity::Low,
            message: format!(
                "file declares {count} mutable globals — consider reducing global state"
            ),
            location: Location {
                file: file_path,
                span,
                start: start_lc,
                end: end_lc,
            },
            suggestion: Some(
                "Replace file-scoped `pub static mut` with thread-local storage (`thread_local!`), \
                 a `Mutex`/`RwLock`-wrapped static, or a dependency-injection pattern."
                    .to_string(),
            ),
            references: vec!["https://cwe.mitre.org/data/definitions/1108.html".to_string()],
            cwe: META.cwe_vec(),
            owasp: META.owasp_vec(),
        }]
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
        analyze_with_config(src, &Config::default())
    }

    fn analyze_with_config(src: &str, config: &Config) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.rs", src.as_bytes().to_vec()));
        let parsed = rust_parse::parse(source).expect("parse failed");
        let analyzer = GlobalVarDensityAnalyzer;
        let ctx = AnalysisContext::new(config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive: at/above threshold ─────────────────────────────────────────

    #[test]
    fn flags_when_count_equals_threshold() {
        // exactly 3 pub static mut — threshold is 3, so >= fires
        let src = "
pub static mut A: i32 = 1;
pub static mut B: i32 = 2;
pub static mut C: i32 = 3;
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn flags_when_count_above_threshold() {
        // 5 pub static mut items
        let src = "
pub static mut A: i32 = 1;
pub static mut B: i32 = 2;
pub static mut C: i32 = 3;
pub static mut D: i32 = 4;
pub static mut E: i32 = 5;
";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 finding, got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
        let msg = &findings[0].message;
        assert!(
            msg.contains("5 mutable globals"),
            "message should contain count, got: {msg}"
        );
    }

    // ── below threshold: no finding ───────────────────────────────────────────

    #[test]
    fn silent_when_count_below_threshold() {
        // 2 pub static mut — below default threshold of 3
        let src = "
pub static mut A: i32 = 1;
pub static mut B: i32 = 2;
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "should not fire below threshold, got: {findings:#?}"
        );
    }

    #[test]
    fn silent_when_no_pub_static_muts() {
        let src = "fn f() {}";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "empty file should not fire, got: {findings:#?}"
        );
    }

    // ── pub static (immutable) not counted ───────────────────────────────────

    #[test]
    fn pub_static_immutable_not_counted() {
        // pub static (not mut) — should NOT be counted
        let src = "
pub static A: i32 = 1;
pub static B: i32 = 2;
pub static C: i32 = 3;
pub static D: i32 = 4;
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "immutable pub static should not be counted, got: {findings:#?}"
        );
    }

    // ── private static mut not counted ───────────────────────────────────────

    #[test]
    fn private_static_mut_not_counted() {
        // private static mut — should NOT be counted (spec: pub-only)
        let src = "
static mut A: i32 = 1;
static mut B: i32 = 2;
static mut C: i32 = 3;
static mut D: i32 = 4;
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "private static mut should not be counted, got: {findings:#?}"
        );
    }

    // ── config-overridden threshold ───────────────────────────────────────────

    #[test]
    fn custom_threshold_5_does_not_fire_at_4() {
        let src = "
pub static mut A: i32 = 1;
pub static mut B: i32 = 2;
pub static mut C: i32 = 3;
pub static mut D: i32 = 4;
";
        let mut config = Config::default();
        config
            .rules
            .entry(RULE_ID.to_string())
            .or_default()
            .threshold = Some(5);
        let findings = analyze_with_config(src, &config);
        assert!(
            findings.is_empty(),
            "should not fire at 4 when threshold=5, got: {findings:#?}"
        );
    }

    #[test]
    fn custom_threshold_5_fires_at_5() {
        let src = "
pub static mut A: i32 = 1;
pub static mut B: i32 = 2;
pub static mut C: i32 = 3;
pub static mut D: i32 = 4;
pub static mut E: i32 = 5;
";
        let mut config = Config::default();
        config
            .rules
            .entry(RULE_ID.to_string())
            .or_default()
            .threshold = Some(5);
        let findings = analyze_with_config(src, &config);
        assert_eq!(
            findings.len(),
            1,
            "should fire at exactly 5 when threshold=5, got: {findings:#?}"
        );
    }

    // ── supported languages ───────────────────────────────────────────────────

    #[test]
    fn supported_languages_is_rust_only() {
        let analyzer = GlobalVarDensityAnalyzer;
        assert!(analyzer.supported_languages().supports(LanguageId("rust")));
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
        assert!(!analyzer.supported_languages().supports(LanguageId("js")));
    }
}
