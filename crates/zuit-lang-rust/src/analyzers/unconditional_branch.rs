//! `MAINT019-unconditional-branch` — flags overly long dispatch constructs.
//!
//! Fires on `match` expressions with too many arms, or on `if`/`else if`
//! chains with too many branches.  The default threshold is 11; configure
//! via `[rules."MAINT019-unconditional-branch"] threshold = N`.
//!
//! # Counting rules
//!
//! - `match`: count is the number of arms (a wildcard `_ => …` arm counts).
//! - `if/else if`: count is the number of `if` plus `else if` rungs.  A
//!   trailing bare `else { … }` is NOT counted (it is fallthrough, not a
//!   branch).  `if let` rungs count like `if`.
//!
//! # Reporting
//!
//! At most one finding per construct (per chain, not per rung).  Nested
//! chains inside an outer chain's `then_branch` are reported independently.

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

const RULE_ID: &str = "MAINT019-unconditional-branch";

/// Default threshold: fire when an `if/else if` chain or `match` reaches this
/// many branches.
const DEFAULT_THRESHOLD: u32 = 11;

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/MAINT019-unconditional-branch.md",
    cwe: &["CWE-1119"],
    owasp: &[],
};

/// Analyzer that emits `MAINT019-unconditional-branch` when a Rust source file
/// contains an overly long `match` or `if`/`else if` dispatch chain.
///
/// Severity: **Low** / Dimension: **Maintainability** / CWE-1119.
pub struct UnconditionalBranchAnalyzer;

impl zuit_core::Analyzer for UnconditionalBranchAnalyzer {
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
        let source = file.source();
        let file_path = source.path.clone();

        ast.long_dispatch_sites
            .iter()
            .filter(|site| site.count >= threshold)
            .map(|site| {
                let (start_lc, end_lc) = source.span_to_linecols(site.span);
                let (message, suggestion) = match site.kind {
                    crate::parse::LongDispatchKind::Match => (
                        format!(
                            "`match` expression has {count} arms (threshold {threshold}); consider extracting branches or using a lookup table",
                            count = site.count,
                            threshold = threshold,
                        ),
                        "Split the match into smaller helpers, use a `HashMap`/`phf` lookup, or dispatch through a trait object.".to_string(),
                    ),
                    crate::parse::LongDispatchKind::IfChain => (
                        format!(
                            "`if`/`else if` chain has {count} branches (threshold {threshold}); consider rewriting as `match` or table dispatch",
                            count = site.count,
                            threshold = threshold,
                        ),
                        "Rewrite as a `match`, extract branches into named helpers, or replace the chain with a `HashMap`/`phf` lookup keyed on the discriminator.".to_string(),
                    ),
                };
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Maintainability,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Low,
                    message,
                    location: Location {
                        file: file_path.clone(),
                        span: site.span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(suggestion),
                    references: vec!["https://cwe.mitre.org/data/definitions/1119.html".to_string()],
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
    use crate::parse as rust_parse;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, LanguageId, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        analyze_with_config(src, &Config::default())
    }

    fn analyze_with_config(src: &str, config: &Config) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.rs", src.as_bytes().to_vec()));
        let parsed = rust_parse::parse(source).expect("parse failed");
        let analyzer = UnconditionalBranchAnalyzer;
        let ctx = AnalysisContext::new(config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    fn with_threshold(t: u32) -> Config {
        let mut c = Config::default();
        c.rules.entry(RULE_ID.to_string()).or_default().threshold = Some(t);
        c
    }

    // ── positive: long match ────────────────────────────────────────────────

    #[test]
    fn flags_match_with_11_arms() {
        // 11 arms: 0..=9 plus wildcard.  Default threshold is 11, so >= fires.
        let src = "
fn dispatch(x: i32) -> i32 {
    match x {
        0 => 0,
        1 => 0,
        2 => 0,
        3 => 0,
        4 => 0,
        5 => 0,
        6 => 0,
        7 => 0,
        8 => 0,
        9 => 0,
        _ => 0,
    }
}
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Low);
        let msg = &findings[0].message;
        assert!(
            msg.contains("11 arms"),
            "message should mention '11 arms', got: {msg}"
        );
    }

    #[test]
    fn flags_match_with_15_arms() {
        let src = "
fn dispatch(x: i32) -> i32 {
    match x {
        0 => 0,
        1 => 0,
        2 => 0,
        3 => 0,
        4 => 0,
        5 => 0,
        6 => 0,
        7 => 0,
        8 => 0,
        9 => 0,
        10 => 0,
        11 => 0,
        12 => 0,
        13 => 0,
        _ => 0,
    }
}
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        let msg = &findings[0].message;
        assert!(
            msg.contains("15 arms"),
            "message should mention '15 arms', got: {msg}"
        );
    }

    // ── positive: long if/else chain ─────────────────────────────────────────

    #[test]
    fn flags_if_chain_of_length_11_once() {
        // 11 rungs (one `if` + ten `else if`) and a trailing bare `else {}`
        // which must NOT contribute to the count.
        let src = "
fn dispatch(x: i32) -> i32 {
    if x == 0 { 0 }
    else if x == 1 { 0 }
    else if x == 2 { 0 }
    else if x == 3 { 0 }
    else if x == 4 { 0 }
    else if x == 5 { 0 }
    else if x == 6 { 0 }
    else if x == 7 { 0 }
    else if x == 8 { 0 }
    else if x == 9 { 0 }
    else if x == 10 { 0 }
    else { 0 }
}
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
            msg.contains("11 branches"),
            "message should mention '11 branches', got: {msg}"
        );
    }

    #[test]
    fn flags_long_if_chain_inside_function_body() {
        // Chain surrounded by extra statements; must still be detected exactly once.
        let src = "
fn dispatch(x: i32) -> i32 {
    let mut acc = 0;
    acc += 1;
    let _ = acc;
    let r = if x == 0 { 0 }
        else if x == 1 { 0 }
        else if x == 2 { 0 }
        else if x == 3 { 0 }
        else if x == 4 { 0 }
        else if x == 5 { 0 }
        else if x == 6 { 0 }
        else if x == 7 { 0 }
        else if x == 8 { 0 }
        else if x == 9 { 0 }
        else if x == 10 { 0 }
        else { 0 };
    let _ = acc + 1;
    r
}
";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 finding, got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn flags_two_sibling_long_matches() {
        // Two sibling 12-arm matches → 2 findings.
        let src = "
fn a(x: i32) -> i32 {
    match x {
        0 => 0,
        1 => 0,
        2 => 0,
        3 => 0,
        4 => 0,
        5 => 0,
        6 => 0,
        7 => 0,
        8 => 0,
        9 => 0,
        10 => 0,
        _ => 0,
    }
}

fn b(y: i32) -> i32 {
    match y {
        0 => 0,
        1 => 0,
        2 => 0,
        3 => 0,
        4 => 0,
        5 => 0,
        6 => 0,
        7 => 0,
        8 => 0,
        9 => 0,
        10 => 0,
        _ => 0,
    }
}
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 2, "expected 2 findings, got: {findings:#?}");
        for f in &findings {
            assert_eq!(f.rule_id, RULE_ID);
        }
    }

    // ── below threshold: silent ─────────────────────────────────────────────

    #[test]
    fn silent_when_match_has_exactly_10_arms() {
        // 10 arms (9 + wildcard) → below default 11 → silent.
        let src = "
fn dispatch(x: i32) -> i32 {
    match x {
        0 => 0,
        1 => 0,
        2 => 0,
        3 => 0,
        4 => 0,
        5 => 0,
        6 => 0,
        7 => 0,
        8 => 0,
        _ => 0,
    }
}
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "10 arms should not fire at default threshold 11, got: {findings:#?}"
        );
    }

    #[test]
    fn silent_when_match_has_3_arms() {
        let src = "
fn dispatch(x: i32) -> i32 {
    match x {
        0 => 0,
        1 => 1,
        _ => 2,
    }
}
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "3 arms should not fire, got: {findings:#?}"
        );
    }

    #[test]
    fn silent_when_if_chain_has_10_rungs() {
        // 10 rungs (1 if + 9 else-if) + bare else → below default 11.
        let src = "
fn dispatch(x: i32) -> i32 {
    if x == 0 { 0 }
    else if x == 1 { 0 }
    else if x == 2 { 0 }
    else if x == 3 { 0 }
    else if x == 4 { 0 }
    else if x == 5 { 0 }
    else if x == 6 { 0 }
    else if x == 7 { 0 }
    else if x == 8 { 0 }
    else if x == 9 { 0 }
    else { 0 }
}
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "10 rungs should not fire, got: {findings:#?}"
        );
    }

    #[test]
    fn silent_for_simple_if_else() {
        // Count = 1; never recorded.
        let src = "
fn f(x: i32) -> i32 {
    if x == 0 { 1 } else { 0 }
}
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "simple if/else should not fire, got: {findings:#?}"
        );
    }

    #[test]
    fn silent_for_sequence_of_standalone_ifs() {
        // Three independent if statements (no else-if).  Each chain has count=1.
        let src = "
fn f(x: i32) {
    if x == 0 { let _ = 1; }
    if x == 1 { let _ = 2; }
    if x == 2 { let _ = 3; }
}
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "standalone ifs should not fire, got: {findings:#?}"
        );
    }

    // ── boundary ─────────────────────────────────────────────────────────────

    #[test]
    fn fires_at_exact_threshold() {
        // Exactly 11 rungs at default threshold 11 → fires (>=).
        let src = "
fn dispatch(x: i32) -> i32 {
    if x == 0 { 0 }
    else if x == 1 { 0 }
    else if x == 2 { 0 }
    else if x == 3 { 0 }
    else if x == 4 { 0 }
    else if x == 5 { 0 }
    else if x == 6 { 0 }
    else if x == 7 { 0 }
    else if x == 8 { 0 }
    else if x == 9 { 0 }
    else if x == 10 { 0 }
    else { 0 }
}
";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 finding at boundary, got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── config-overridden threshold ─────────────────────────────────────────

    #[test]
    fn custom_threshold_6_fires_on_6_arm_match() {
        // 6 arms (5 + wildcard) with threshold=6 → fires.
        let src = "
fn f(x: i32) -> i32 {
    match x {
        0 => 0,
        1 => 0,
        2 => 0,
        3 => 0,
        4 => 0,
        _ => 0,
    }
}
";
        let cfg = with_threshold(6);
        let findings = analyze_with_config(src, &cfg);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding when threshold=6 and arms=6, got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn custom_threshold_100_silences_50_arm_match() {
        // 50-arm match with threshold=100 → silent.
        use std::fmt::Write as _;
        let arms: String = (1..=49).fold(String::new(), |mut acc, i| {
            let _ = writeln!(acc, "        {i} => 0,");
            acc
        });
        let src = format!(
            "
fn f(x: i32) -> i32 {{
    match x {{
        0 => 0,
{arms}        _ => 0,
    }}
}}
"
        );
        let cfg = with_threshold(100);
        let findings = analyze_with_config(&src, &cfg);
        assert!(
            findings.is_empty(),
            "should not fire when threshold=100 and arms=50, got: {findings:#?}"
        );
    }

    // ── if-let chain ─────────────────────────────────────────────────────────

    #[test]
    fn if_let_chain_counts_as_branches() {
        // 11 `if let` rungs.  Trailing bare `else {}` ignored.
        let src = "
fn f(o: Option<i32>) -> i32 {
    if let Some(1) = o { 1 }
    else if let Some(2) = o { 2 }
    else if let Some(3) = o { 3 }
    else if let Some(4) = o { 4 }
    else if let Some(5) = o { 5 }
    else if let Some(6) = o { 6 }
    else if let Some(7) = o { 7 }
    else if let Some(8) = o { 8 }
    else if let Some(9) = o { 9 }
    else if let Some(10) = o { 10 }
    else if let Some(11) = o { 11 }
    else { 0 }
}
";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for 11-rung if-let chain, got: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
        let msg = &findings[0].message;
        assert!(
            msg.contains("11 branches"),
            "message should mention '11 branches', got: {msg}"
        );
    }

    // ── dedup: one finding per chain ────────────────────────────────────────

    #[test]
    fn long_chain_produces_single_finding_not_one_per_rung() {
        // 12-rung chain — exactly 1 finding (regression for de-dup flag).
        let src = "
fn f(x: i32) -> i32 {
    if x == 0 { 0 }
    else if x == 1 { 0 }
    else if x == 2 { 0 }
    else if x == 3 { 0 }
    else if x == 4 { 0 }
    else if x == 5 { 0 }
    else if x == 6 { 0 }
    else if x == 7 { 0 }
    else if x == 8 { 0 }
    else if x == 9 { 0 }
    else if x == 10 { 0 }
    else if x == 11 { 0 }
    else { 0 }
}
";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "12-rung chain must produce a single finding, got: {findings:#?}"
        );
    }

    // ── nested chains: outer + inner counted independently ──────────────────

    #[test]
    fn chain_inside_then_branch_is_a_separate_chain() {
        // Outer 11-rung chain whose first then-branch body contains another
        // 11-rung chain.  Both chains qualify → 2 findings.
        let src = "
fn f(x: i32, y: i32) -> i32 {
    if x == 0 {
        if y == 0 { 0 }
        else if y == 1 { 0 }
        else if y == 2 { 0 }
        else if y == 3 { 0 }
        else if y == 4 { 0 }
        else if y == 5 { 0 }
        else if y == 6 { 0 }
        else if y == 7 { 0 }
        else if y == 8 { 0 }
        else if y == 9 { 0 }
        else if y == 10 { 0 }
        else { 0 }
    }
    else if x == 1 { 0 }
    else if x == 2 { 0 }
    else if x == 3 { 0 }
    else if x == 4 { 0 }
    else if x == 5 { 0 }
    else if x == 6 { 0 }
    else if x == 7 { 0 }
    else if x == 8 { 0 }
    else if x == 9 { 0 }
    else if x == 10 { 0 }
    else { 0 }
}
";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            2,
            "nested long chain should produce 2 findings (inner + outer), got: {findings:#?}"
        );
        for f in &findings {
            assert_eq!(f.rule_id, RULE_ID);
        }
    }

    // ── supported languages ─────────────────────────────────────────────────

    #[test]
    fn supported_languages_is_rust_only() {
        let analyzer = UnconditionalBranchAnalyzer;
        assert!(analyzer.supported_languages().supports(LanguageId("rust")));
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
        assert!(!analyzer.supported_languages().supports(LanguageId("js")));
    }
}

// ── adversarial / pinning tests ──────────────────────────────────────────────
//
// Targeted edge cases discovered during adversarial QA review. Each test either
// (a) pins a deliberate behavior so future refactors don't silently change it,
// or (b) covers a bug that was previously latent.
#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use crate::parse as rust_parse;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        analyze_with_config(src, &Config::default())
    }

    fn analyze_with_config(src: &str, config: &Config) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.rs", src.as_bytes().to_vec()));
        let parsed = rust_parse::parse(source).expect("parse failed");
        let analyzer = UnconditionalBranchAnalyzer;
        let ctx = AnalysisContext::new(config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    fn with_threshold(t: u32) -> Config {
        let mut c = Config::default();
        c.rules.entry(RULE_ID.to_string()).or_default().threshold = Some(t);
        c
    }

    // 1. Empty match (0 arms): does not panic and does not fire.
    #[test]
    fn empty_match_does_not_fire_or_panic() {
        let src = "
fn f(x: i32) {
    match x {}
    let _ = x;
}
";
        // Even with threshold = 0, an empty match must not produce a finding
        // (`count > 0` gate in the extractor skips zero-arm matches).
        let cfg = with_threshold(0);
        let findings = analyze_with_config(src, &cfg);
        assert!(
            findings.is_empty(),
            "empty match should not fire even at threshold 0, got: {findings:#?}"
        );
    }

    // 2. Very many arms: programmatically build a 4096-arm match and verify
    //    the analyzer fires exactly once with the correct arm count.
    #[test]
    fn very_large_match_fires_exactly_once_with_correct_count() {
        use std::fmt::Write as _;
        // 4095 numeric arms + 1 wildcard = 4096 arms total.
        let arms: String = (0..4095u32).fold(String::new(), |mut acc, i| {
            let _ = writeln!(acc, "        {i} => 0,");
            acc
        });
        let generated_src = format!(
            "
fn f(x: u32) -> i32 {{
    match x {{
{arms}        _ => 0,
    }}
}}
"
        );
        let findings = analyze(&generated_src);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 finding for 4096-arm match, got: {}",
            findings.len()
        );
        assert!(
            findings[0].message.contains("4096 arms"),
            "message should mention '4096 arms', got: {}",
            findings[0].message
        );
    }

    // 3. Or-pattern arms count as ONE arm each, not N.
    //    14 numeric arms each with two or-pattern alternatives (28 patterns
    //    total) — but only 14 arms + 1 wildcard = 15 arms.
    #[test]
    fn or_pattern_arms_count_as_one_each_pin() {
        let src = "
fn f(x: i32) -> i32 {
    match x {
        0 | 100 => 0,
        1 | 101 => 0,
        2 | 102 => 0,
        3 | 103 => 0,
        4 | 104 => 0,
        5 | 105 => 0,
        6 | 106 => 0,
        7 | 107 => 0,
        8 | 108 => 0,
        9 | 109 => 0,
        10 | 110 => 0,
        _ => 0,
    }
}
";
        let findings = analyze(src);
        // 12 arms ≥ default threshold 11 → fires.
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(
            findings[0].message.contains("12 arms"),
            "or-patterns count as single arms — expected '12 arms', got: {}",
            findings[0].message
        );
    }

    // 4. Guarded arms (`p if g => ...`) count as ONE arm each.
    #[test]
    fn guarded_arms_count_as_one_each_pin() {
        let src = "
fn f(x: i32, y: i32) -> i32 {
    match x {
        0 if y > 0 => 0,
        1 if y > 0 => 0,
        2 if y > 0 => 0,
        3 if y > 0 => 0,
        4 if y > 0 => 0,
        5 if y > 0 => 0,
        6 if y > 0 => 0,
        7 if y > 0 => 0,
        8 if y > 0 => 0,
        9 if y > 0 => 0,
        10 if y > 0 => 0,
        _ => 0,
    }
}
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(
            findings[0].message.contains("12 arms"),
            "guards do not multiply arm counts — expected '12 arms', got: {}",
            findings[0].message
        );
    }

    // 5. Match-inside-match-arm: inner long match nested inside one arm of an
    //    outer long match. Both should fire independently → 2 findings.
    #[test]
    fn long_match_nested_inside_long_match_arm_fires_twice() {
        let src = "
fn f(x: i32, y: i32) -> i32 {
    match x {
        0 => match y {
            0 => 0,
            1 => 0,
            2 => 0,
            3 => 0,
            4 => 0,
            5 => 0,
            6 => 0,
            7 => 0,
            8 => 0,
            9 => 0,
            10 => 0,
            _ => 0,
        },
        1 => 0,
        2 => 0,
        3 => 0,
        4 => 0,
        5 => 0,
        6 => 0,
        7 => 0,
        8 => 0,
        9 => 0,
        10 => 0,
        _ => 0,
    }
}
";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            2,
            "expected outer + inner match findings, got: {findings:#?}"
        );
        // Both should be Match-kind, both mention "12 arms".
        for f in &findings {
            assert!(
                f.message.contains("12 arms"),
                "expected '12 arms', got: {}",
                f.message
            );
        }
    }

    // 6. `if let` chain of length 2: counted as 2 rungs but below default
    //    threshold 11 → silent. Pin that the count is computed (no panic) and
    //    no finding emerges at default threshold.
    #[test]
    fn short_if_let_chain_silent_pin() {
        let src = "
fn f(o: Option<i32>) -> i32 {
    if let Some(x) = o { x }
    else if let None = o { 0 }
    else { 0 }
}
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "2-rung if-let chain should be silent at default threshold, got: {findings:#?}"
        );
        // But with threshold 2 it should fire.
        let cfg = with_threshold(2);
        let findings = analyze_with_config(src, &cfg);
        assert_eq!(
            findings.len(),
            1,
            "at threshold 2, 2-rung if-let chain should fire: {findings:#?}"
        );
        assert!(
            findings[0].message.contains("2 branches"),
            "expected '2 branches', got: {}",
            findings[0].message
        );
    }

    // 7. Mixed `if` / `if let` rungs in one chain — all rungs counted uniformly.
    #[test]
    fn mixed_if_and_if_let_rungs_all_count_pin() {
        let src = "
fn f(x: i32, o: Option<i32>) -> i32 {
    if x == 0 { 0 }
    else if let Some(1) = o { 1 }
    else if x == 2 { 2 }
    else if let Some(3) = o { 3 }
    else if x == 4 { 4 }
    else if let Some(5) = o { 5 }
    else if x == 6 { 6 }
    else if let Some(7) = o { 7 }
    else if x == 8 { 8 }
    else if let Some(9) = o { 9 }
    else if x == 10 { 10 }
    else { 0 }
}
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(
            findings[0].message.contains("11 branches"),
            "expected '11 branches' (all rung shapes count), got: {}",
            findings[0].message
        );
    }

    // 8. Block-wrapped inner if: `if a {} else { if b {} else if c {} ... }`
    //    Outer chain has count = 1 (else_branch is a Block, not If). Inner
    //    chain stands on its own. Pin that only the inner chain reaches the
    //    threshold and the outer does NOT contribute to it.
    #[test]
    fn block_wrapped_else_starts_fresh_chain_pin() {
        let src = "
fn f(x: i32) -> i32 {
    if x == 0 { 0 }
    else {
        if x == 1 { 0 }
        else if x == 2 { 0 }
        else if x == 3 { 0 }
        else if x == 4 { 0 }
        else if x == 5 { 0 }
        else if x == 6 { 0 }
        else if x == 7 { 0 }
        else if x == 8 { 0 }
        else if x == 9 { 0 }
        else if x == 10 { 0 }
        else if x == 11 { 0 }
        else { 0 }
    }
}
";
        let findings = analyze(src);
        // Inner has 11 rungs ≥ threshold 11 → fires once. Outer has count=1
        // (else is Block) → not even recorded.
        assert_eq!(
            findings.len(),
            1,
            "block-wrapped else should restart the chain at the inner if; \
             outer should contribute count=1 (not recorded). Got: {findings:#?}"
        );
        assert!(
            findings[0].message.contains("11 branches"),
            "expected '11 branches' for the inner chain, got: {}",
            findings[0].message
        );
    }

    // 9. Macros opaque to the visitor: a `vec![…]` body with what would lex
    //    as many "arms" inside it must NOT be parsed as a match. Pin.
    #[test]
    fn match_inside_macro_body_does_not_fire_pin() {
        // The `=>` tokens are inside `vec![...]`, which `syn` keeps as an
        // opaque TokenStream until macro expansion. The visitor must not
        // detect them as a match construct.
        let src = "
fn f() -> Vec<(i32, i32)> {
    vec![
        (0, 0),
        (1, 0),
        (2, 0),
        (3, 0),
        (4, 0),
        (5, 0),
        (6, 0),
        (7, 0),
        (8, 0),
        (9, 0),
        (10, 0),
        (11, 0),
    ]
}
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "macro body must be opaque — no match construct detected, got: {findings:#?}"
        );
    }

    // 10. Closures should be descended into: a long match inside a closure
    //     body fires. (Default `syn::visit` recurses into ExprClosure.body.)
    #[test]
    fn long_match_inside_closure_body_fires() {
        let src = "
fn f() -> impl Fn(i32) -> i32 {
    |x: i32| -> i32 {
        match x {
            0 => 0,
            1 => 0,
            2 => 0,
            3 => 0,
            4 => 0,
            5 => 0,
            6 => 0,
            7 => 0,
            8 => 0,
            9 => 0,
            10 => 0,
            _ => 0,
        }
    }
}
";
        let findings = analyze(src);
        assert_eq!(
            findings.len(),
            1,
            "closure body match should fire, got: {findings:#?}"
        );
        assert!(findings[0].message.contains("12 arms"));
    }

    // 11. `const fn` bodies: visitor descends.
    #[test]
    fn long_match_inside_const_fn_fires() {
        let src = "
const fn classify(x: u8) -> u8 {
    match x {
        0 => 0,
        1 => 0,
        2 => 0,
        3 => 0,
        4 => 0,
        5 => 0,
        6 => 0,
        7 => 0,
        8 => 0,
        9 => 0,
        10 => 0,
        _ => 0,
    }
}
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].message.contains("12 arms"));
    }

    // 12. Impl-trait methods: visitor descends into impl items.
    #[test]
    fn long_match_inside_trait_impl_method_fires_pin() {
        let src = "
trait T { fn classify(&self, x: i32) -> i32; }

struct S;

impl T for S {
    fn classify(&self, x: i32) -> i32 {
        match x {
            0 => 0,
            1 => 0,
            2 => 0,
            3 => 0,
            4 => 0,
            5 => 0,
            6 => 0,
            7 => 0,
            8 => 0,
            9 => 0,
            10 => 0,
            _ => 0,
        }
    }
}
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].message.contains("12 arms"));
    }

    // 13. async fn bodies.
    #[test]
    fn long_match_inside_async_fn_fires_pin() {
        let src = "
async fn classify(x: i32) -> i32 {
    match x {
        0 => 0,
        1 => 0,
        2 => 0,
        3 => 0,
        4 => 0,
        5 => 0,
        6 => 0,
        7 => 0,
        8 => 0,
        9 => 0,
        10 => 0,
        _ => 0,
    }
}
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].message.contains("12 arms"));
    }

    // 14. Nested modules — visitor descends.
    #[test]
    fn long_match_inside_nested_mod_fires_pin() {
        let src = "
mod inner {
    pub fn classify(x: i32) -> i32 {
        match x {
            0 => 0,
            1 => 0,
            2 => 0,
            3 => 0,
            4 => 0,
            5 => 0,
            6 => 0,
            7 => 0,
            8 => 0,
            9 => 0,
            10 => 0,
            _ => 0,
        }
    }
}
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].message.contains("12 arms"));
    }

    // 15. cfg-gated arms count toward arm total (syn keeps them in the AST).
    #[test]
    fn cfg_gated_arms_still_counted_pin() {
        // 11 plain numeric arms + 1 wildcard would be 12 ≥ threshold 11; we
        // remove one numeric arm and replace with a `#[cfg(...)]` arm. The
        // total is still 12 because syn parses attributes as arm metadata.
        let src = "
fn f(x: i32) -> i32 {
    match x {
        0 => 0,
        1 => 0,
        2 => 0,
        3 => 0,
        4 => 0,
        5 => 0,
        6 => 0,
        7 => 0,
        8 => 0,
        9 => 0,
        #[cfg(feature = \"never\")]
        10 => 0,
        _ => 0,
    }
}
";
        let findings = analyze(src);
        // 12 arms (incl. cfg-gated + wildcard) ≥ threshold 11 → fires.
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(
            findings[0].message.contains("12 arms"),
            "cfg-gated arm should be counted; expected '12 arms', got: {}",
            findings[0].message
        );
    }

    // 16. Attribute on the match expression itself does not break span
    //     anchoring or analysis.
    #[test]
    fn attribute_on_match_expression_does_not_break_analysis_pin() {
        let src = "
fn f(x: i32) -> i32 {
    #[allow(clippy::match_same_arms)]
    match x {
        0 => 0,
        1 => 0,
        2 => 0,
        3 => 0,
        4 => 0,
        5 => 0,
        6 => 0,
        7 => 0,
        8 => 0,
        9 => 0,
        10 => 0,
        _ => 0,
    }
}
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].message.contains("12 arms"));
        // Span should still be inside the file (non-empty, sane).
        assert!(findings[0].location.span.start.0 < findings[0].location.span.end.0);
    }

    // 17. Side-effect / assignment / block in if-chain conditions does not
    //     change the rung count (visitor must still descend into cond).
    #[test]
    fn block_expression_in_condition_does_not_perturb_chain_count_pin() {
        // Each rung's `cond` is `{ let v = x; v > N }` — a block expression.
        // The chain length is the # of rungs, regardless of how each cond is
        // shaped. This also exercises descent: any matches inside cond would
        // also be picked up (none here).
        let src = "
fn f(x: i32) -> i32 {
    if { let v = x; v > 0 } { 0 }
    else if { let v = x; v > 1 } { 0 }
    else if { let v = x; v > 2 } { 0 }
    else if { let v = x; v > 3 } { 0 }
    else if { let v = x; v > 4 } { 0 }
    else if { let v = x; v > 5 } { 0 }
    else if { let v = x; v > 6 } { 0 }
    else if { let v = x; v > 7 } { 0 }
    else if { let v = x; v > 8 } { 0 }
    else if { let v = x; v > 9 } { 0 }
    else if { let v = x; v > 10 } { 0 }
    else { 0 }
}
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].message.contains("11 branches"));
    }

    // 18. Empty arm/rung bodies don't affect counting (1 finding when chain
    //     length ≥ threshold, 0 otherwise).
    #[test]
    fn empty_rung_bodies_in_chain_count_normally_pin() {
        // 10 rungs total — below default threshold 11 → silent.
        let src = "
fn f(x: i32) {
    if x == 0 {}
    else if x == 1 {}
    else if x == 2 {}
    else if x == 3 {}
    else if x == 4 {}
    else if x == 5 {}
    else if x == 6 {}
    else if x == 7 {}
    else if x == 8 {}
    else if x == 9 {}
    else {}
}
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "10 empty-body rungs should not fire, got: {findings:#?}"
        );
    }

    // 19. Block-style arm body (`p => { stmts; expr }`) doesn't change arm
    //     counting.
    #[test]
    fn block_arm_bodies_do_not_change_arm_counting_pin() {
        let src = "
fn f(x: i32) -> i32 {
    match x {
        0 => { let v = 1; v + 1 }
        1 => { let v = 2; v + 1 }
        2 => { let v = 3; v + 1 }
        3 => { let v = 4; v + 1 }
        4 => { let v = 5; v + 1 }
        5 => { let v = 6; v + 1 }
        6 => { let v = 7; v + 1 }
        7 => { let v = 8; v + 1 }
        8 => { let v = 9; v + 1 }
        9 => { let v = 10; v + 1 }
        10 => { let v = 11; v + 1 }
        _ => 0,
    }
}
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].message.contains("12 arms"));
    }

    // 20. Multibyte UTF-8 chars in nearby comments and string literals must
    //     not cause panics or off-by-one spans. Pin no-panic behavior and a
    //     finding whose span lies within the file.
    #[test]
    fn utf8_chars_near_match_do_not_panic_and_produce_sane_span() {
        let src = "
fn f(x: i32) -> &'static str {
    // \u{300C}コメント\u{300D} — multibyte chars above the match keyword
    let s = \"日本語\";
    let _ = s;
    match x {
        0 => \"\u{3042}\",
        1 => \"\u{3044}\",
        2 => \"\u{3046}\",
        3 => \"\u{3048}\",
        4 => \"\u{304A}\",
        5 => \"\u{304B}\",
        6 => \"\u{304D}\",
        7 => \"\u{304F}\",
        8 => \"\u{3051}\",
        9 => \"\u{3053}\",
        10 => \"\u{3055}\",
        _ => \"\u{3057}\",
    }
}
";
        // Should not panic and should produce exactly one finding.
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        let span = findings[0].location.span;
        // Span must lie within the source byte length.
        let byte_len = u32::try_from(src.len()).unwrap();
        assert!(
            span.start.0 <= byte_len && span.end.0 <= byte_len,
            "span {span:?} should fit within source of {byte_len} bytes"
        );
        assert!(span.start.0 <= span.end.0, "span start must precede end");
    }

    // 21. Nested (NOT chained) ifs: three `if a { if b { if c { … } } }`
    //     levels. Each has count = 1 → never recorded → silent.
    #[test]
    fn deeply_nested_ifs_are_not_a_chain_pin() {
        let src = "
fn f(a: bool, b: bool, c: bool) -> i32 {
    if a {
        if b {
            if c {
                1
            } else {
                2
            }
        } else {
            3
        }
    } else {
        4
    }
}
";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "nested (non-chained) ifs must not fire, got: {findings:#?}"
        );
    }

    // 22. A trailing bare `else { … }` at the END of an else-if chain does
    //     NOT increment the chain count. Place the trailing else after the
    //     11th rung — count must stay 11, not 12.
    #[test]
    fn trailing_else_does_not_increment_chain_count_pin() {
        let src = "
fn f(x: i32) -> i32 {
    if x == 0 { 0 }
    else if x == 1 { 0 }
    else if x == 2 { 0 }
    else if x == 3 { 0 }
    else if x == 4 { 0 }
    else if x == 5 { 0 }
    else if x == 6 { 0 }
    else if x == 7 { 0 }
    else if x == 8 { 0 }
    else if x == 9 { 0 }
    else if x == 10 { 0 }
    else { 9999 }
}
";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        // Must say "11 branches" — NOT "12".
        let msg = &findings[0].message;
        assert!(
            msg.contains("11 branches"),
            "trailing else must NOT count — expected '11 branches', got: {msg}"
        );
        assert!(
            !msg.contains("12 branches"),
            "trailing else accidentally counted! got: {msg}"
        );
    }

    // Bonus: a match whose arm body contains an if-chain — both should fire
    //   if both qualify (cross-construct independence).
    #[test]
    fn if_chain_inside_match_arm_fires_independently_pin() {
        let src = "
fn f(x: i32, y: i32) -> i32 {
    match x {
        0 => {
            if y == 0 { 0 }
            else if y == 1 { 0 }
            else if y == 2 { 0 }
            else if y == 3 { 0 }
            else if y == 4 { 0 }
            else if y == 5 { 0 }
            else if y == 6 { 0 }
            else if y == 7 { 0 }
            else if y == 8 { 0 }
            else if y == 9 { 0 }
            else if y == 10 { 0 }
            else { 0 }
        }
        1 => 0,
        2 => 0,
        3 => 0,
        4 => 0,
        5 => 0,
        6 => 0,
        7 => 0,
        8 => 0,
        9 => 0,
        10 => 0,
        _ => 0,
    }
}
";
        let findings = analyze(src);
        // Outer match has 12 arms ≥ 11 → fires.
        // Inner if-chain has 11 rungs ≥ 11 → fires.
        assert_eq!(
            findings.len(),
            2,
            "expected outer match + inner if-chain findings, got: {findings:#?}"
        );
        let match_count = findings
            .iter()
            .filter(|f| f.message.starts_with("`match`"))
            .count();
        let chain_count = findings
            .iter()
            .filter(|f| f.message.starts_with("`if`/`else if`"))
            .count();
        assert_eq!(match_count, 1, "should have 1 match finding");
        assert_eq!(chain_count, 1, "should have 1 chain finding");
    }
}
