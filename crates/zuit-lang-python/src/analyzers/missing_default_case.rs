//! `MAINT009-missing-default-case` — flags Python `match` statements that lack
//! a wildcard (`case _:` or `case <name>:`) arm.
//!
//! # Detection
//!
//! Walks the full `ModModule` AST recursively (mirroring the `check_stmts` /
//! `check_stmt` pattern from `SEC012`).  For each `Stmt::Match`, checks
//! whether any `MatchCase` has a pattern that is irrefutable.
//!
//! An irrefutable pattern is `Pattern::MatchAs(PatternMatchAs { pattern: None,
//! .. })`, which covers:
//! - `case _:`  — `pattern: None, name: None`
//! - `case x:`  — `pattern: None, name: Some("x")`
//!
//! Both forms catch all remaining values, so both are treated as a wildcard.
//!
//! # Note
//!
//! This analyzer walks the AST directly — no changes to `parse.rs` are needed
//! because the `PythonAst` wrapper already exposes the full `ModModule`.

use rustpython_parser::ast::{Pattern, Ranged, Stmt};
use rustpython_parser::text_size::TextRange;
use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, Span},
};

/// The stable rule ID.
const RULE_ID: &str = "MAINT009-missing-default-case";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/MAINT009-missing-default-case.md",
    cwe: &["CWE-478"],
    owasp: &[],
};

/// Analyzer that emits `MAINT009-missing-default-case` for Python `match`
/// statements without a wildcard arm.
pub struct MissingDefaultCaseAnalyzer;

impl zuit_core::Analyzer for MissingDefaultCaseAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Maintainability
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::Only(smallvec![LanguageId("python")])
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let Some(ast) = crate::try_python_ast(file) else {
            return Vec::new();
        };

        let source = file.source();
        let file_path = source.path.clone();
        let mut findings = Vec::new();

        check_stmts(&ast.body, source, &file_path, &mut findings);
        findings
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Returns `true` if the `MatchCase` pattern is irrefutable (i.e. catches all
/// remaining values).
///
/// Both `case _:` (`MatchAs { pattern: None, name: None }`) and `case x:`
/// (`MatchAs { pattern: None, name: Some("x") }`) are irrefutable.
fn is_wildcard_case(pattern: &Pattern) -> bool {
    if let Pattern::MatchAs(ma) = pattern {
        // `pattern == None` means this is not a more-specific sub-pattern;
        // it's a bare `_` or bare name binding — both are irrefutable.
        return ma.pattern.is_none();
    }
    false
}

fn emit(
    range: TextRange,
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    let span = Span::new(
        ByteOffset(range.start().to_u32()),
        ByteOffset(range.end().to_u32()),
    );
    let (start_lc, end_lc) = source.span_to_linecols(span);
    findings.push(Finding {
        analyzer: AnalyzerId::new(RULE_ID),
        dimension: Dimension::Maintainability,
        rule_id: RULE_ID.to_string(),
        severity: Severity::Medium,
        message: "match statement is missing a wildcard (`case _:`) arm; \
                  add `case _:` or `case other:` to handle unexpected values explicitly"
            .to_string(),
        location: Location {
            file: file_path.to_path_buf(),
            span,
            start: start_lc,
            end: end_lc,
        },
        suggestion: Some(
            "Add a `case _: ...` (or `case other: ...`) arm as the last case of the \
             match statement to ensure all possible values are handled."
                .to_string(),
        ),
        references: vec!["https://cwe.mitre.org/data/definitions/478.html".to_string()],
        cwe: META.cwe_vec(),
        owasp: META.owasp_vec(),
    });
}

fn check_stmts(
    stmts: &[Stmt],
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    for stmt in stmts {
        check_stmt(stmt, source, file_path, findings);
    }
}

fn check_stmt(
    stmt: &Stmt,
    source: &zuit_core::SourceFile,
    file_path: &std::path::Path,
    findings: &mut Vec<Finding>,
) {
    match stmt {
        Stmt::Match(m) => {
            // Check if any case arm is irrefutable (wildcard).
            let has_wildcard = m.cases.iter().any(|c| is_wildcard_case(&c.pattern));
            if !has_wildcard {
                emit(m.range(), source, file_path, findings);
            }
            // Recurse into case bodies.
            for case in &m.cases {
                check_stmts(&case.body, source, file_path, findings);
            }
        }
        // Recurse into nested scopes (mirroring SEC012 pattern).
        Stmt::FunctionDef(f) => check_stmts(&f.body, source, file_path, findings),
        Stmt::AsyncFunctionDef(f) => check_stmts(&f.body, source, file_path, findings),
        Stmt::ClassDef(c) => check_stmts(&c.body, source, file_path, findings),
        Stmt::If(s) => {
            check_stmts(&s.body, source, file_path, findings);
            check_stmts(&s.orelse, source, file_path, findings);
        }
        Stmt::For(s) => {
            check_stmts(&s.body, source, file_path, findings);
            check_stmts(&s.orelse, source, file_path, findings);
        }
        Stmt::AsyncFor(s) => {
            check_stmts(&s.body, source, file_path, findings);
            check_stmts(&s.orelse, source, file_path, findings);
        }
        Stmt::While(s) => check_stmts(&s.body, source, file_path, findings),
        Stmt::With(s) => check_stmts(&s.body, source, file_path, findings),
        Stmt::AsyncWith(s) => check_stmts(&s.body, source, file_path, findings),
        Stmt::Try(s) => {
            check_stmts(&s.body, source, file_path, findings);
            for handler in &s.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                check_stmts(&h.body, source, file_path, findings);
            }
            check_stmts(&s.orelse, source, file_path, findings);
            check_stmts(&s.finalbody, source, file_path, findings);
        }
        Stmt::TryStar(s) => {
            check_stmts(&s.body, source, file_path, findings);
            for handler in &s.handlers {
                let rustpython_parser::ast::ExceptHandler::ExceptHandler(h) = handler;
                check_stmts(&h.body, source, file_path, findings);
            }
        }
        _ => {}
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::PythonLanguage;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, Language, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.py", src.as_bytes().to_vec()));
        let lang = PythonLanguage;
        let parsed = lang.parse(source).expect("parse failed");
        let analyzer = MissingDefaultCaseAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_match_without_wildcard() {
        let src = "match x:\n    case 1:\n        pass\n    case 2:\n        pass\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_match_with_underscore_wildcard() {
        let src = "match x:\n    case 1:\n        pass\n    case _:\n        pass\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "match with `case _:` should not fire, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_match_with_capture_wildcard() {
        // `case other:` is MatchAs { pattern: None, name: Some("other") } —
        // irrefutable, so treated as a wildcard. Must NOT fire.
        let src = "match x:\n    case 1:\n        pass\n    case other:\n        pass\n";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "match with `case other:` (irrefutable capture) should not fire, got: {findings:#?}"
        );
    }

    // ── CWE tag check ─────────────────────────────────────────────────────────

    #[test]
    fn cwe_tag_is_cwe_478() {
        let src = "match x:\n    case 1:\n        pass\n    case 2:\n        pass\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].cwe.iter().any(|c| c == "CWE-478"),
            "expected CWE-478 in finding.cwe, got: {:?}",
            findings[0].cwe
        );
    }

    #[test]
    fn supported_languages_is_python_only() {
        let analyzer = MissingDefaultCaseAnalyzer;
        assert!(
            analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
        assert!(!analyzer.supported_languages().supports(LanguageId("rust")));
    }
}
