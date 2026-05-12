//! `MAINT008-large-impl-block` — flags `impl` blocks (Rust) and classes (Python)
//! with more than a configurable number of methods.
//!
//! Large `impl` blocks / classes are a code-smell that often indicates a type
//! trying to do too many things (a violation of the Single Responsibility
//! Principle).  Splitting such types into smaller, focused units improves
//! readability and testability.
//!
//! ## Detection strategy
//!
//! The analyzer groups [`FunctionLike`] entries by `(file, parent_name)` pairs.
//! Entries with `kind == Method` and `parent_name == Some(_)` are counted per
//! group.  When a group's count exceeds the configured threshold, a single
//! finding is emitted at the span of the first method in the group (which is
//! the best available proxy for the impl block / class header).
//!
//! Languages without `parent_name` support (JS/TS) produce no findings from
//! this rule.
//!
//! ## Configuration
//!
//! ```toml
//! [rules."MAINT008-large-impl-block"]
//! threshold = 30   # default; methods strictly > threshold trigger the rule
//! ```
//!
//! [`FunctionLike`]: zuit_core::FunctionLike

use std::collections::BTreeMap;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, FunctionKind, ParsedFile, RuleMeta,
    Severity, SupportedLanguages, span::Location,
};

/// Rule ID for the large-impl-block check.
pub const RULE_ID: &str = "MAINT008-large-impl-block";

/// Default method-count threshold; impl blocks / classes at or below this
/// value are not flagged.
const DEFAULT_THRESHOLD: u32 = 30;

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/MAINT008-large-impl-block.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that flags `impl` blocks (Rust) and classes (Python) with more
/// methods than the configured threshold.
///
/// The threshold is read from `[rules."MAINT008-large-impl-block"] threshold`
/// in `zuit.toml`; the default is 30 methods.
#[derive(Debug, Default)]
pub struct LargeImplBlockAnalyzer;

impl Analyzer for LargeImplBlockAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Maintainability
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let threshold = ctx.config.rule_threshold(RULE_ID, DEFAULT_THRESHOLD);
        let source = file.source();
        let index = file.index();

        // Group methods by parent_name. Only count entries with a parent name
        // (i.e. methods belonging to a named impl block or class).
        //
        // BTreeMap<parent_name, Vec<method_index>> — sorted for determinism.
        let mut groups: BTreeMap<&str, Vec<usize>> = BTreeMap::new();

        for (i, func) in index.functions.iter().enumerate() {
            if func.kind != FunctionKind::Method {
                continue;
            }
            let Some(parent) = func.parent_name.as_deref() else {
                continue;
            };
            groups.entry(parent).or_default().push(i);
        }

        let mut findings = Vec::new();

        for (parent_name, method_indices) in &groups {
            #[allow(clippy::cast_possible_truncation)]
            let count = method_indices.len() as u32;
            if count <= threshold {
                continue;
            }

            // Emit one finding for the whole block, at the span of the first
            // method (best available proxy for the block header).
            let first_fn = &index.functions[method_indices[0]];
            let (start_lc, end_lc) = source.span_to_linecols(first_fn.span);

            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Maintainability,
                rule_id: RULE_ID.to_string(),
                severity: Severity::Low,
                message: format!(
                    "`{parent_name}` has {count} methods (threshold {threshold}); \
                     consider splitting into smaller types",
                ),
                location: Location {
                    file: source.path.clone(),
                    span: first_fn.span,
                    start: start_lc,
                    end: end_lc,
                },
                suggestion: Some(
                    "Extract a subset of methods into a focused helper type or trait.".to_string(),
                ),
                references: vec![],
                cwe: vec![],
                owasp: vec![],
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

    /// Generate N methods for a Rust impl block.
    fn rust_impl_with_n_methods(n: usize) -> String {
        use std::fmt::Write as _;
        let mut methods = String::new();
        for i in 0..n {
            writeln!(methods, "    pub fn method_{i}(&self) {{}}").unwrap();
        }
        format!("pub struct Foo;\nimpl Foo {{\n{methods}}}\n")
    }

    /// Generate N methods for a Python class.
    fn python_class_with_n_methods(n: usize) -> String {
        use std::fmt::Write as _;
        let mut methods = String::new();
        for i in 0..n {
            writeln!(methods, "    def method_{i}(self):").unwrap();
            writeln!(methods, "        pass").unwrap();
        }
        format!("class MyClass:\n{methods}\n")
    }

    // ── Rust positive: impl block with threshold+1 methods triggers ───────────

    #[test]
    fn rust_large_impl_positive() {
        let source = rust_impl_with_n_methods(31);
        let file = rust_parse("src/lib.rs", &source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = LargeImplBlockAnalyzer.analyze_file(&ctx, &file);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 MAINT008 finding for 31-method Rust impl block, got {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert!(
            findings[0].message.contains("Foo"),
            "message should mention type name 'Foo'; got: {}",
            findings[0].message
        );
        assert!(
            findings[0].message.contains("31"),
            "message should mention method count; got: {}",
            findings[0].message
        );
    }

    // ── Rust negative: impl block at threshold does NOT trigger ───────────────

    #[test]
    fn rust_at_threshold_negative() {
        let source = rust_impl_with_n_methods(30);
        let file = rust_parse("src/lib.rs", &source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = LargeImplBlockAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT008 findings for 30-method Rust impl block (at threshold), \
             got {findings:#?}"
        );
    }

    // ── Python positive: class with threshold+1 methods triggers ─────────────

    #[test]
    fn python_large_class_positive() {
        let source = python_class_with_n_methods(31);
        let file = python_parse("main.py", &source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = LargeImplBlockAnalyzer.analyze_file(&ctx, &file);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 MAINT008 finding for 31-method Python class, got {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert!(
            findings[0].message.contains("MyClass"),
            "message should mention class name 'MyClass'; got: {}",
            findings[0].message
        );
        assert!(
            findings[0].message.contains("31"),
            "message should mention method count; got: {}",
            findings[0].message
        );
    }

    // ── Python negative: class at threshold does NOT trigger ──────────────────

    #[test]
    fn python_at_threshold_negative() {
        let source = python_class_with_n_methods(30);
        let file = python_parse("main.py", &source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = LargeImplBlockAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 MAINT008 findings for 30-method Python class (at threshold), \
             got {findings:#?}"
        );
    }

    // ── Config override: threshold=5 triggers on 6-method impl block ──────────

    #[test]
    fn config_override_threshold() {
        let source = rust_impl_with_n_methods(6);
        let file = rust_parse("src/lib.rs", &source);
        let toml = r#"
[rules."MAINT008-large-impl-block"]
threshold = 5
"#;
        let config = Config::from_toml_str(toml).expect("toml parse failed");
        let ctx = make_ctx(&config);
        let findings = LargeImplBlockAnalyzer.analyze_file(&ctx, &file);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 MAINT008 finding with custom threshold=5 on 6-method impl block"
        );
        assert!(
            findings[0].message.contains("threshold 5"),
            "message should mention overridden threshold 5; got: {}",
            findings[0].message
        );
    }

    // ── Multiple impl blocks: each counted separately ─────────────────────────

    #[test]
    fn multiple_impl_blocks_counted_separately() {
        use std::fmt::Write as _;
        // Two impl blocks: Foo with 31 methods, Bar with 5 methods.
        let mut foo_methods = String::new();
        for i in 0..31 {
            writeln!(foo_methods, "    pub fn foo_{i}(&self) {{}}").unwrap();
        }
        let mut bar_methods = String::new();
        for i in 0..5 {
            writeln!(bar_methods, "    pub fn bar_{i}(&self) {{}}").unwrap();
        }
        let source = format!(
            "pub struct Foo;\npub struct Bar;\nimpl Foo {{\n{foo_methods}}}\nimpl Bar {{\n{bar_methods}}}\n"
        );
        let file = rust_parse("src/lib.rs", &source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = LargeImplBlockAnalyzer.analyze_file(&ctx, &file);
        // Only Foo should trigger (31 > 30); Bar has 5 <= 30.
        assert_eq!(
            findings.len(),
            1,
            "expected 1 MAINT008 finding (only Foo triggers), got {findings:#?}"
        );
        assert!(
            findings[0].message.contains("Foo"),
            "expected finding for Foo, not Bar"
        );
    }

    // ── Free functions do NOT contribute to method count ──────────────────────

    #[test]
    fn free_functions_not_counted() {
        use std::fmt::Write as _;
        // 31 free functions but 0 methods in any impl block.
        let mut fns = String::new();
        for i in 0..31 {
            writeln!(fns, "pub fn free_fn_{i}() {{}}").unwrap();
        }
        let file = rust_parse("src/lib.rs", &fns);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = LargeImplBlockAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "free functions must not be counted toward MAINT008, got {findings:#?}"
        );
    }
}
