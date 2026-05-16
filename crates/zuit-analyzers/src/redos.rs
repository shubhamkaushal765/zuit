//! `SEC014-redos-regex` — detects regular expressions that are vulnerable to
//! `ReDoS` (Regular-Expression Denial of Service) via catastrophic backtracking.
//!
//! The analyzer walks every [`RegexLiteral`] in the [`SemanticIndex`], parses
//! the pattern with `regex_syntax`, and checks for two classic catastrophic
//! patterns:
//!
//! 1. **Nested repetition** — a `Repetition` whose body contains another
//!    `Repetition` (e.g. `(a+)+`, `(.*)*`). This causes exponential
//!    backtracking on certain inputs.
//! 2. **Alternation with duplicate branches** — an `Alternation` where two or
//!    more branches stringify identically (e.g. `(a|a)+`, `(foo|foo)`).
//!    Combined with an outer repetition this can cause polynomial/exponential
//!    backtracking.
//!
//! Patterns that fail to parse are silently skipped (they are not valid regexes
//! as far as `regex_syntax` is concerned — flagging them would be a false
//! positive).
//!
//! [`RegexLiteral`]: zuit_core::RegexLiteral

use regex_syntax::ast::{Alternation, Ast, GroupKind};

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    span::Location,
};

/// Rule ID for the redos-regex check.
pub const RULE_ID: &str = "SEC014-redos-regex";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/SEC014-redos-regex.md",
    cwe: &["CWE-1333"],
    owasp: &[],
};

/// Cross-language analyzer that detects ReDoS-vulnerable regex patterns.
#[derive(Debug, Default)]
pub struct RedosAnalyzer;

impl Analyzer for RedosAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Security
    }

    fn supported_languages(&self) -> zuit_core::SupportedLanguages {
        zuit_core::SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let source = file.source();
        let index = file.index();
        let mut findings = Vec::new();

        for lit in &index.regex_literals {
            // Parse the regex source. If parsing fails, skip — not a valid
            // regex per regex_syntax, so flagging it would be a false positive.
            let Ok(ast) = regex_syntax::ast::parse::Parser::new().parse(&lit.value) else {
                continue;
            };

            if has_catastrophic_pattern(&ast) {
                let (start_lc, end_lc) = source.span_to_linecols(lit.span);
                findings.push(Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Security,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Regex `{}` contains a potentially catastrophic backtracking pattern \
                         (nested repetition or duplicate alternation branches) — verify with \
                         input testing before deploying.",
                        lit.value
                    ),
                    location: Location {
                        file: source.path.clone(),
                        span: lit.span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Rewrite the regex to avoid nested quantifiers or overlapping \
                         alternatives. Consider using possessive quantifiers or atomic groups \
                         if your engine supports them, or limit input length at the call site."
                            .to_string(),
                    ),
                    references: vec![
                        "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS".to_string(),
                        "https://cwe.mitre.org/data/definitions/1333.html".to_string(),
                    ],
                    cwe: META.cwe_vec(),
                    owasp: META.owasp_vec(),
                });
            }
        }

        findings
    }
}

// ── catastrophic pattern detection ───────────────────────────────────────────

/// Returns `true` when the `ast` subtree contains a catastrophic backtracking
/// pattern.
///
/// Two patterns are detected:
/// - **Nested repetition**: a `Repetition` whose body (ignoring `Group`
///   wrappers) contains another `Repetition`.
/// - **Duplicate alternation branches**: an `Alternation` with two or more
///   branches that stringify identically.
fn has_catastrophic_pattern(ast: &Ast) -> bool {
    match ast {
        Ast::Repetition(rep) => {
            // Check if the body of this repetition contains another repetition.
            if inner_has_repetition(&rep.ast) {
                return true;
            }
            // Recurse into the body.
            has_catastrophic_pattern(&rep.ast)
        }
        Ast::Alternation(alt) => {
            if alternation_has_duplicate_branches(alt) {
                return true;
            }
            alt.asts.iter().any(has_catastrophic_pattern)
        }
        Ast::Group(g) => has_catastrophic_pattern(&g.ast),
        Ast::Concat(c) => c.asts.iter().any(has_catastrophic_pattern),
        // Leaves (literals, character classes, anchors, etc.) cannot be
        // catastrophic on their own.
        _ => false,
    }
}

/// Returns `true` when `ast` (ignoring `Group` wrappers) is or contains a
/// `Repetition` node — used to detect the inner half of a nested repetition.
fn inner_has_repetition(ast: &Ast) -> bool {
    match ast {
        Ast::Repetition(_) => true,
        // Transparent wrappers — look through all group kinds.
        Ast::Group(g) => match &g.kind {
            GroupKind::NonCapturing(_)
            | GroupKind::CaptureIndex(_)
            | GroupKind::CaptureName { .. } => inner_has_repetition(&g.ast),
        },
        Ast::Concat(c) => c.asts.iter().any(inner_has_repetition),
        Ast::Alternation(a) => a.asts.iter().any(inner_has_repetition),
        _ => false,
    }
}

/// Returns `true` when the alternation has two or more branches with identical
/// string representations.
fn alternation_has_duplicate_branches(alt: &Alternation) -> bool {
    let strs: Vec<String> = alt.asts.iter().map(|a| format!("{a}")).collect();
    for i in 0..strs.len() {
        for j in (i + 1)..strs.len() {
            if strs[i] == strs[j] {
                return true;
            }
        }
    }
    false
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use zuit_core::{Config, Language, SourceFile};

    fn make_ctx(config: &Config) -> AnalysisContext<'_> {
        AnalysisContext::new(config)
    }

    /// Build a [`zuit_core::ParsedFile`] from Python source embedding `pattern`
    /// as a `re.compile` call so the Python frontend picks it up automatically.
    fn parsed_with_regex(pattern: &str) -> zuit_core::ParsedFile {
        // We need a ParsedFile whose index has the regex literal.
        // Easiest path: parse a trivial Python file, then the index will be
        // empty — but we can't mutate ParsedFile after construction.
        //
        // Instead, build a Python source that embeds the pattern as a re.compile
        // call so the Python frontend picks it up automatically.
        let src_text = format!("import re\nre.compile(r\"{pattern}\")\n");
        let src = Arc::new(SourceFile::new("test.py", src_text.as_bytes().to_vec()));
        zuit_lang_python::PythonLanguage
            .parse(src)
            .expect("python parse failed")
    }

    fn analyze(pattern: &str) -> Vec<Finding> {
        let file = parsed_with_regex(pattern);
        let config = Config::default();
        let ctx = make_ctx(&config);
        RedosAnalyzer.analyze_file(&ctx, &file)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn detects_nested_repetition_plus_plus() {
        let findings = analyze("(a+)+");
        assert!(!findings.is_empty(), "expected finding for (a+)+, got none");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert!(
            findings[0].cwe.iter().any(|c| c == "CWE-1333"),
            "expected CWE-1333, got {:?}",
            findings[0].cwe
        );
    }

    #[test]
    fn detects_nested_repetition_star_star() {
        let findings = analyze("(.*)* ");
        assert!(
            !findings.is_empty(),
            "expected finding for (.*)*,  got none"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn detects_duplicate_alternation_branches() {
        let findings = analyze("(a|a)+");
        assert!(
            !findings.is_empty(),
            "expected finding for (a|a)+, got none"
        );
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn no_finding_for_simple_character_class_repetition() {
        let findings = analyze("[a-z]+");
        assert!(
            findings.is_empty(),
            "expected no finding for [a-z]+, got {findings:#?}"
        );
    }

    #[test]
    fn no_finding_for_bounded_repetition() {
        let findings = analyze(r"\d{1,5}");
        assert!(
            findings.is_empty(),
            r"expected no finding for \d{{1,5}}, got {findings:#?}"
        );
    }

    #[test]
    fn no_finding_for_anchored_literal() {
        let findings = analyze("^abc$");
        assert!(
            findings.is_empty(),
            "expected no finding for ^abc$, got {findings:#?}"
        );
    }

    #[test]
    fn no_panic_and_no_finding_for_unparseable_regex() {
        // `(invalid` is not a valid regex — the parser will fail. We must not
        // panic and must not emit a finding.
        let findings = analyze("(invalid");
        assert!(
            findings.is_empty(),
            "expected no finding for unparseable regex, got {findings:#?}"
        );
    }

    // ── unit tests for the catastrophic pattern detector ──────────────────────

    fn parse_ast(pattern: &str) -> Ast {
        regex_syntax::ast::parse::Parser::new()
            .parse(pattern)
            .unwrap()
    }

    #[test]
    fn catastrophic_pattern_nested_rep() {
        let ast = parse_ast("(a+)+");
        assert!(has_catastrophic_pattern(&ast));
    }

    #[test]
    fn catastrophic_pattern_dup_alt() {
        let ast = parse_ast("(a|a)");
        assert!(has_catastrophic_pattern(&ast));
    }

    #[test]
    fn no_catastrophic_pattern_simple() {
        let ast = parse_ast("[a-z]+");
        assert!(!has_catastrophic_pattern(&ast));
    }

    // ── fixture tests ─────────────────────────────────────────────────────────

    fn python_parse(path: &str, source: &str) -> zuit_core::ParsedFile {
        let src = Arc::new(SourceFile::new(path, source.as_bytes().to_vec()));
        zuit_lang_python::PythonLanguage
            .parse(src)
            .expect("python parse failed")
    }

    #[test]
    fn python_redos_positive_fixture() {
        let source = include_str!("../../../fixtures/python/redos_regex/positive.py");
        let file = python_parse("fixtures/python/redos_regex/positive.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = RedosAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC014 finding for python positive fixture, got 0"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    #[test]
    fn python_redos_negative_fixture() {
        let source = include_str!("../../../fixtures/python/redos_regex/negative.py");
        let file = python_parse("fixtures/python/redos_regex/negative.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = RedosAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC014 findings for python negative fixture, got {findings:#?}"
        );
    }
}
