//! `PERF002-clone-in-iter-chain` — detects `.clone()` calls inside iterator
//! chains, which are a common performance pitfall.
//!
//! **Heuristic:** this rule inspects pre-extracted `RustAst` data.  The
//! `parse.rs` visitor flags any `Block` that contains both an iter-start method
//! call (`.iter()`, `.into_iter()`, or `.iter_mut()`) **and** a `.clone()` call
//! anywhere within the same block.  False-positives are possible when the clone
//! is genuinely necessary (e.g. cloning a value before moving it into a
//! closure), but the hint is cheap to evaluate and useful for review.
//!
//! **Fix guidance:** replace `.clone()` with a borrow where possible, or use
//! `.cloned()` / `.copied()` adapters on iterators of references.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
};

use crate::try_rust_ast;

const RULE_ID: &str = "PERF002-clone-in-iter-chain";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/PERF002-clone-in-iter-chain.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer for `PERF002-clone-in-iter-chain`.
pub struct Perf002CloneInIterChain;

impl zuit_core::Analyzer for Perf002CloneInIterChain {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("performance".to_string())
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

        if ast.clone_in_iter_chains.is_empty() {
            return Vec::new();
        }

        let src = file.source();
        let source_path = src.path.clone();

        ast.clone_in_iter_chains
            .iter()
            .map(|&span| {
                let (start_lc, end_lc) = src.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Custom("performance".to_string()),
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Medium,
                    message:
                        "`.clone()` found inside an iterator chain block; consider `.cloned()` \
                         or `.copied()` adapters to avoid unnecessary heap allocations."
                            .to_string(),
                    location: Location {
                        file: source_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Use `.cloned()` on iterators of `&T` where `T: Clone`, or \
                         `.copied()` for `T: Copy` types."
                            .to_string(),
                    ),
                    references: vec![
                        "https://nnethercote.github.io/perf-book/".to_string(),
                        "https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.cloned"
                            .to_string(),
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
        Perf002CloneInIterChain.analyze_file(&ctx, &parsed)
    }

    /// Positive: `.iter().map(|x| x.clone())` in a function body → ≥1 finding.
    #[test]
    fn perf002_clone_in_iter_chain_emits_medium() {
        let code = "fn process(items: &[String]) -> Vec<String> \
                    { items.iter().map(|x| x.clone()).collect() }";
        let findings = parse_and_analyze(code);
        assert!(!findings.is_empty(), "expected PERF002 finding, got none");
        assert_eq!(findings[0].severity, zuit_core::Severity::Medium);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    /// Negative: clone without an iter chain → 0 findings.
    #[test]
    fn perf002_clone_without_iter_emits_zero() {
        let code = "fn duplicate(s: &String) -> String { s.clone() }";
        let findings = parse_and_analyze(code);
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Negative: iter chain without clone → 0 findings.
    #[test]
    fn perf002_iter_without_clone_emits_zero() {
        let code =
            "fn sum_lengths(items: &[String]) -> usize { items.iter().map(|x| x.len()).sum() }";
        let findings = parse_and_analyze(code);
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Boundary: separate function scopes don't cross-contaminate.
    #[test]
    fn perf002_separate_blocks_dont_cross_contaminate() {
        // iter in one fn, clone in another → 0 findings.
        let code = "fn a(items: &[String]) -> usize { items.iter().map(|x| x.len()).sum() }\n\
                    fn b(s: &String) -> String { s.clone() }";
        let findings = parse_and_analyze(code);
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }
}
