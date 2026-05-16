//! `MAINT011-active-debug-code` — flags active debug-code constructs in
//! JavaScript/TypeScript source files.
//!
//! # Detection
//!
//! Reads the pre-extracted `JsAst::debug_calls` populated
//! at parse time by the walker.
//!
//! # Flagged constructs
//!
//! - `debugger;` statement → **`Severity::Medium`**
//! - `console.log(…)` call → **`Severity::Low`**
//! - `console.debug(…)` call → **`Severity::Low`**
//! - `console.trace(…)` call → **`Severity::Low`**
//!
//! # Skips
//!
//! - `console.error`, `console.warn`, and `console.info` are intentionally
//!   excluded (legitimate in production error-reporting and health-check paths).

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

use crate::native_ast::JsDebugKind;

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

/// Analyzer that emits `MAINT011-active-debug-code` for debug-code constructs
/// in JavaScript/TypeScript source files.
///
/// - `debugger;` → `Severity::Medium`
/// - `console.log/debug/trace` → `Severity::Low`
pub struct JsActiveDebugCodeAnalyzer;

impl zuit_core::Analyzer for JsActiveDebugCodeAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Maintainability
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::Only(smallvec![LanguageId("javascript")])
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let Some(ast) = crate::try_js_ast(file) else {
            return Vec::new();
        };

        let source = file.source();
        let file_path = source.path.clone();

        ast.debug_calls
            .iter()
            .map(|&(span, kind)| {
                let (construct_name, severity) = match kind {
                    JsDebugKind::DebuggerStmt => ("debugger", Severity::Medium),
                    JsDebugKind::ConsoleLog => ("console.log", Severity::Low),
                    JsDebugKind::ConsoleDebug => ("console.debug", Severity::Low),
                    JsDebugKind::ConsoleTrace => ("console.trace", Severity::Low),
                };
                let (start_lc, end_lc) = source.span_to_linecols(span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Maintainability,
                    rule_id: RULE_ID.to_string(),
                    severity,
                    message: format!(
                        "debug construct `{construct_name}` should not be present in \
                         production code"
                    ),
                    location: Location {
                        file: file_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Remove this debug construct before shipping to production; \
                         use a proper logging library instead."
                            .to_string(),
                    ),
                    references: vec!["https://cwe.mitre.org/data/definitions/489.html".to_string()],
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
    use crate::parse as js_parse;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, LanguageId, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.ts", src.as_bytes().to_vec()));
        let parsed = js_parse::parse(source).expect("parse failed");
        let analyzer = JsActiveDebugCodeAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn flags_debugger_statement() {
        let src = "function f() { debugger; }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_console_log() {
        let src = "const x = 1; console.log(x);";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn flags_console_debug() {
        let src = "console.debug('verbose info');";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn flags_console_trace() {
        let src = "console.trace('stack');";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn does_not_flag_console_error() {
        let src = "console.error('something went wrong');";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "console.error should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_console_warn() {
        let src = "console.warn('deprecated feature');";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "console.warn should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_console_info() {
        let src = "console.info('server started');";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "console.info should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_other_member_calls() {
        let src = "const arr = [1, 2, 3]; arr.forEach(x => x + 1);";
        let findings = analyze(src);
        assert!(
            findings.is_empty(),
            "forEach should not be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn supported_languages_is_javascript_only() {
        let analyzer = JsActiveDebugCodeAnalyzer;
        assert!(
            analyzer
                .supported_languages()
                .supports(LanguageId("javascript"))
        );
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
    }
}
