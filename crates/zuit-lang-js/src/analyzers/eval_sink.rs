//! `SEC002-eval-sink` — detects code-injection and DOM-based XSS sinks in
//! JavaScript/TypeScript source files.
//!
//! # Detected patterns
//!
//! | Pattern | Example |
//! |---------|---------|
//! | Bare `eval(...)` call | `eval(userInput)` |
//! | `new Function(...)` | `new Function("return 1")` |
//! | Bare `Function(...)` call | `Function("return 1")()` |
//! | `setTimeout` with string literal first arg | `setTimeout("alert(1)", 0)` |
//! | `setInterval` with string literal first arg | `setInterval("code()", 500)` |
//! | Assignment to `.innerHTML` | `el.innerHTML = userInput` |
//! | Assignment to `.outerHTML` | `el.outerHTML = userInput` |
//! | Call to `document.write(...)` | `document.write(html)` |
//! | Call to `document.writeln(...)` | `document.writeln(html)` |
//! | Call to `.insertAdjacentHTML(...)` | `el.insertAdjacentHTML("beforeend", html)` |
//! | JSX `dangerouslySetInnerHTML` | `<Comp dangerouslySetInnerHTML={{__html: x}} />` |
//!
//! Template literals with no substitution expressions (`` `static text` ``) are
//! treated as string literals for `setTimeout`/`setInterval` detection.
//!
//! # Suppression of trivial `.innerHTML`/`.outerHTML` assignments
//!
//! Assignments to `.innerHTML` or `.outerHTML` whose right-hand side is a plain
//! string literal (no template substitutions) are **skipped** to reduce noise
//! from patterns like `el.innerHTML = "<b>Hello</b>"`. Only dynamic values
//! (identifiers, calls, template literals with substitutions, etc.) are flagged.
//!
//! # Heuristic note
//!
//! This analyzer matches **bare name** calls only for the eval-family sinks, and
//! specific member-call forms for the DOM XSS sinks. It does **not** detect:
//!
//! - Member-access forms of eval: `window.eval(x)`, `globalThis.eval(x)` — out
//!   of scope for v1; consistent with the Python sibling's bare-name-only
//!   behaviour.
//! - Identifier shadowing: `const eval = () => 1; eval()` — tracking aliases
//!   would require dataflow analysis, which is out of scope for v1.
//! - `setTimeout(() => doThing(), 100)` — function-expression arguments are
//!   explicitly excluded; only string/template literals trigger the rule.
//! - `arr.map(eval)` — passing `eval` as a *reference* (not calling it) is not
//!   flagged. Tracking references is out of scope for v1.

use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};
use smallvec::smallvec;

/// The stable rule ID for this analyzer.
const RULE_ID: &str = "SEC002-eval-sink";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/SEC002-eval-sink.md",
    cwe: &["CWE-95", "CWE-79"],
    owasp: &["A03:2021"],
};

/// Analyzer that emits `SEC002-eval-sink` for code-injection sinks in
/// JavaScript and TypeScript source files.
///
/// Severity: **High**. These APIs execute arbitrary code at runtime and are a
/// common vector for code-injection attacks when fed user-controlled input.
pub struct JsEvalSinkAnalyzer;

impl zuit_core::Analyzer for JsEvalSinkAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Security
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::Only(smallvec![LanguageId("javascript")])
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    #[allow(clippy::too_many_lines)]
    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let Some(ast) = crate::try_js_ast(file) else {
            return Vec::new();
        };

        let source = file.source();
        let file_path = source.path.clone();
        let mut findings = Vec::new();

        // ── eval-family call sinks ────────────────────────────────────────────
        for site in &ast.call_sites {
            let callee_name = match &site.callee {
                crate::native_ast::JsCallee::Name(n) | crate::native_ast::JsCallee::New(n) => {
                    n.as_str()
                }
            };

            // Determine whether this site should produce a finding.
            let message = match &site.callee {
                crate::native_ast::JsCallee::Name(n) if n == "eval" => Some(
                    "call to `eval` is a code-injection sink; never pass untrusted input"
                        .to_string(),
                ),
                crate::native_ast::JsCallee::Name(n) if n == "Function" => Some(
                    "call to `new Function` is a code-injection sink; never pass untrusted input"
                        .to_string(),
                ),
                crate::native_ast::JsCallee::New(n) if n == "Function" => Some(
                    "call to `new Function` is a code-injection sink; never pass untrusted input"
                        .to_string(),
                ),
                crate::native_ast::JsCallee::Name(n)
                    if (n == "setTimeout" || n == "setInterval")
                        && site.first_arg_is_string_literal =>
                {
                    Some(format!(
                        "call to `{n}` with string argument is a code-injection sink"
                    ))
                }
                _ => None,
            };

            let Some(msg) = message else { continue };

            let (start_lc, end_lc) = source.span_to_linecols(site.span);
            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Security,
                rule_id: RULE_ID.to_string(),
                severity: Severity::High,
                message: msg,
                location: Location {
                    file: file_path.clone(),
                    span: site.span,
                    start: start_lc,
                    end: end_lc,
                },
                suggestion: Some(suggestion_for(callee_name)),
                references: vec!["https://cwe.mitre.org/data/definitions/95.html".to_string()],
                cwe: META.cwe_vec(),
                owasp: META.owasp_vec(),
            });
        }

        // ── DOM-based XSS sinks ───────────────────────────────────────────────
        for sink in &ast.dom_sinks {
            use crate::native_ast::DomSinkKind;

            let message = match sink.kind {
                DomSinkKind::InnerHtml => "assignment to .innerHTML can introduce DOM-based XSS; \
                     use textContent or sanitize the value"
                    .to_string(),
                DomSinkKind::OuterHtml => "assignment to .outerHTML can introduce DOM-based XSS; \
                     use a safe DOM API or sanitize the value"
                    .to_string(),
                DomSinkKind::DocumentWrite => "call to document.write is a DOM-based XSS sink; \
                     never pass untrusted input"
                    .to_string(),
                DomSinkKind::DocumentWriteln => {
                    "call to document.writeln is a DOM-based XSS sink; \
                     never pass untrusted input"
                        .to_string()
                }
                DomSinkKind::InsertAdjacentHtml => {
                    "call to insertAdjacentHTML can introduce DOM-based XSS; \
                     use textContent or sanitize the value"
                        .to_string()
                }
                DomSinkKind::DangerouslySetInnerHtml => {
                    "JSX dangerouslySetInnerHTML can introduce DOM-based XSS; \
                     sanitize before rendering"
                        .to_string()
                }
            };

            let (start_lc, end_lc) = source.span_to_linecols(sink.span);
            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Security,
                rule_id: RULE_ID.to_string(),
                severity: Severity::High,
                message,
                location: Location {
                    file: file_path.clone(),
                    span: sink.span,
                    start: start_lc,
                    end: end_lc,
                },
                suggestion: Some(suggestion_for_dom_sink(&sink.kind)),
                references: vec![
                    "https://cwe.mitre.org/data/definitions/79.html".to_string(),
                    "https://cwe.mitre.org/data/definitions/95.html".to_string(),
                ],
                cwe: META.cwe_vec(),
                owasp: META.owasp_vec(),
            });
        }

        findings
    }
}

fn suggestion_for(callee: &str) -> String {
    match callee {
        "eval" => "Replace `eval` with a safe parser (e.g. `JSON.parse` for data) or \
                   redesign to avoid dynamic code execution entirely."
            .to_string(),
        "Function" => "Avoid constructing functions from strings; use named function declarations \
                       or arrow functions instead."
            .to_string(),
        "setTimeout" | "setInterval" => {
            "Pass a function reference or arrow function instead of a string: \
             `setTimeout(() => doThing(), delay)`."
                .to_string()
        }
        _ => "Avoid passing untrusted input to code-execution APIs.".to_string(),
    }
}

fn suggestion_for_dom_sink(kind: &crate::native_ast::DomSinkKind) -> String {
    use crate::native_ast::DomSinkKind;
    match kind {
        DomSinkKind::InnerHtml | DomSinkKind::OuterHtml => {
            "Use `textContent` to set plain text, or sanitize HTML with a trusted library \
             (e.g. DOMPurify) before assigning to innerHTML/outerHTML."
                .to_string()
        }
        DomSinkKind::DocumentWrite | DomSinkKind::DocumentWriteln => {
            "Avoid `document.write`/`document.writeln`; build DOM nodes with \
             `document.createElement` and `appendChild` instead."
                .to_string()
        }
        DomSinkKind::InsertAdjacentHtml => {
            "Use `insertAdjacentText` for plain text, or sanitize HTML with a trusted library \
             (e.g. DOMPurify) before calling insertAdjacentHTML."
                .to_string()
        }
        DomSinkKind::DangerouslySetInnerHtml => {
            "Sanitize the HTML string with a trusted library (e.g. DOMPurify) before passing it \
             to dangerouslySetInnerHTML."
                .to_string()
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse as js_parse;
    use zuit_core::{Analyzer, Config, LanguageId, SourceFile, span::ByteOffset};
    use std::sync::Arc;

    fn analyze(path: &str, src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new(path, src.as_bytes().to_vec()));
        let parsed = js_parse(source).expect("parse failed");
        let analyzer = JsEvalSinkAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    fn analyze_js(src: &str) -> Vec<Finding> {
        analyze("test.js", src)
    }

    // ── negative tests ────────────────────────────────────────────────────────

    #[test]
    fn zero_findings_on_healthy_fixture() {
        let src = include_str!("../../../../fixtures/js/healthy/main.ts");
        let findings = analyze("main.ts", src);
        assert!(
            findings.is_empty(),
            "expected no findings on healthy fixture, got: {findings:#?}"
        );
    }

    #[test]
    fn zero_findings_on_eval_sink_negative_fixture() {
        let src = include_str!("../../../../fixtures/js/eval_sink/negative/healthy.js");
        let findings = analyze("healthy.js", src);
        assert!(
            findings.is_empty(),
            "expected no findings on negative fixture, got: {findings:#?}"
        );
    }

    // ── positive tests ────────────────────────────────────────────────────────

    #[test]
    fn detects_eval_call() {
        let findings = analyze_js("eval(userInput);");
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].message.contains("`eval`"));
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn detects_new_function() {
        let findings = analyze_js("const f = new Function('return 1');");
        let func_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("`new Function`"))
            .collect();
        assert!(
            !func_findings.is_empty(),
            "expected a `new Function` finding, got: {findings:#?}"
        );
    }

    #[test]
    fn detects_bare_function_constructor() {
        // `Function('return 1')()` — bare call without `new`
        let findings = analyze_js("Function('return 1')();");
        let func_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("`new Function`"))
            .collect();
        assert!(
            !func_findings.is_empty(),
            "expected a `new Function` finding for bare Function() call, got: {findings:#?}"
        );
    }

    #[test]
    fn detects_settimeout_with_string() {
        let findings = analyze_js(r#"setTimeout("alert(1)", 0);"#);
        let st_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("`setTimeout`"))
            .collect();
        assert!(
            !st_findings.is_empty(),
            "expected a setTimeout finding, got: {findings:#?}"
        );
    }

    #[test]
    fn detects_settimeout_with_template_literal() {
        let findings = analyze_js("setTimeout(`alert(1)`, 0);");
        let st_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("`setTimeout`"))
            .collect();
        assert!(
            !st_findings.is_empty(),
            "expected a setTimeout finding for template literal, got: {findings:#?}"
        );
    }

    #[test]
    fn detects_setinterval_with_string() {
        let findings = analyze_js(r#"setInterval("doThing()", 500);"#);
        let si_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("`setInterval`"))
            .collect();
        assert!(
            !si_findings.is_empty(),
            "expected a setInterval finding, got: {findings:#?}"
        );
    }

    // ── negative / non-flagged cases ──────────────────────────────────────────

    #[test]
    fn does_not_flag_settimeout_with_function_arg() {
        let findings = analyze_js("setTimeout(() => 1, 0);");
        assert!(
            findings.is_empty(),
            "expected no findings for setTimeout with arrow fn, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_settimeout_with_function_ref() {
        let findings = analyze_js("function handler() {} setTimeout(handler, 200);");
        assert!(
            findings.is_empty(),
            "expected no findings for setTimeout with function ref, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_safe_calls() {
        // `console.log('eval')` — member call whose name contains "eval" as a string arg
        // `arr.map(eval)` — passing eval as a reference (not a bare call)
        let findings = analyze_js(
            "console.log('eval');\nconst arr = [1,2,3];\nconst mapped = arr.map(eval);\n",
        );
        // arr.map(eval) — `eval` here is an identifier expression used as a callback
        // reference, not a bare CallExpression. It should NOT be flagged.
        // console.log('eval') — member call, not a bare `eval(...)`. Not flagged.
        assert!(
            findings.is_empty(),
            "expected no findings for safe calls, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_member_eval() {
        // Member access eval — out of scope for v1
        let findings = analyze_js("window.eval('x');");
        assert!(
            findings.is_empty(),
            "expected no findings for window.eval(), got: {findings:#?}"
        );
    }

    // ── metadata tests ────────────────────────────────────────────────────────

    #[test]
    fn supported_languages_is_javascript_only() {
        let analyzer = JsEvalSinkAnalyzer;
        let sl = analyzer.supported_languages();
        assert!(sl.supports(LanguageId("javascript")));
        assert!(!sl.supports(LanguageId("python")));
        assert!(!sl.supports(LanguageId("rust")));
    }

    #[test]
    fn rule_meta_has_correct_cwe_and_owasp() {
        let analyzer = JsEvalSinkAnalyzer;
        let rules = analyzer.rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, RULE_ID);
        assert!(rules[0].cwe.contains(&"CWE-95"));
        assert!(rules[0].owasp.contains(&"A03:2021"));
        assert_eq!(rules[0].default_severity, Severity::High);
    }

    // ── location accuracy ─────────────────────────────────────────────────────

    #[test]
    fn finding_has_correct_location() {
        // "eval(userInput);" — eval call starts at byte 0
        let src = "eval(userInput);";
        let findings = analyze_js(src);
        assert_eq!(findings.len(), 1, "expected exactly 1 finding");
        let f = &findings[0];
        assert_eq!(f.rule_id, RULE_ID);
        assert_eq!(f.severity, Severity::High);
        // The span covers the full call expression `eval(userInput)`.
        assert_eq!(
            f.location.span.start,
            ByteOffset(0),
            "call should start at byte 0"
        );
        assert_eq!(f.location.start.line, 1);
        // column is 1-indexed; eval starts at the first column on line 1
        assert_eq!(f.location.start.column, 1);
    }

    #[test]
    fn finding_location_offset_when_not_at_start() {
        // "const x = eval('dangerous');\n"
        //  0         1
        //  0123456789012
        //                ^-- eval starts at byte 10
        let src = "const x = eval('dangerous');\n";
        let findings = analyze_js(src);
        assert_eq!(findings.len(), 1, "expected exactly 1 finding");
        let f = &findings[0];
        assert_eq!(
            f.location.span.start,
            ByteOffset(10),
            "eval call should start at byte 10"
        );
        assert_eq!(f.location.start.line, 1);
    }

    // ── TypeScript support ────────────────────────────────────────────────────

    #[test]
    fn works_on_typescript() {
        // `let x: number = eval('1')` — TypeScript with type annotation
        let findings = analyze("test.ts", "let x: number = eval('1');");
        assert_eq!(findings.len(), 1, "expected 1 finding in TS file");
        assert!(findings[0].message.contains("`eval`"));
    }

    #[test]
    fn works_on_tsx() {
        let findings = analyze(
            "comp.tsx",
            r#"function Comp() { return <div>{eval("1")}</div>; }"#,
        );
        assert_eq!(findings.len(), 1, "expected 1 finding in TSX file");
    }

    // ── positive fixture integration ──────────────────────────────────────────

    #[test]
    fn detects_findings_in_positive_fixture_js() {
        let src = include_str!("../../../../fixtures/js/eval_sink/positive/unhealthy.js");
        let findings = analyze("unhealthy.js", src);
        assert!(
            findings.len() >= 5,
            "expected >=5 findings in positive fixture, got {}: {findings:#?}",
            findings.len()
        );
    }

    #[test]
    fn detects_findings_in_positive_fixture_ts() {
        let src = include_str!("../../../../fixtures/js/eval_sink/positive/unhealthy.ts");
        let findings = analyze("unhealthy.ts", src);
        assert!(
            findings.len() >= 2,
            "expected >=2 findings in positive fixture (TS), got {}: {findings:#?}",
            findings.len()
        );
    }

    // ── DOM-based XSS sinks ───────────────────────────────────────────────────

    #[test]
    fn detects_inner_html_assignment() {
        let findings = analyze_js("el.innerHTML = userInput;");
        assert!(
            findings.iter().any(|f| f.message.contains(".innerHTML")),
            "expected an innerHTML finding, got: {findings:#?}"
        );
    }

    #[test]
    fn detects_outer_html_assignment() {
        let findings = analyze_js("document.body.outerHTML = userInput;");
        assert!(
            findings.iter().any(|f| f.message.contains(".outerHTML")),
            "expected an outerHTML finding, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_inner_html_read() {
        // Reading `.innerHTML` is fine — only assignment is a sink.
        let findings = analyze_js("const x = el.innerHTML;");
        assert!(
            findings.is_empty(),
            "reading .innerHTML must not flag, got: {findings:#?}"
        );
    }

    #[test]
    fn detects_document_write_call() {
        let findings = analyze_js("document.write(userInput);");
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("document.write")),
            "expected a document.write finding, got: {findings:#?}"
        );
    }

    #[test]
    fn detects_document_writeln_call() {
        let findings = analyze_js("document.writeln(userInput);");
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("document.writeln")),
            "expected a document.writeln finding, got: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_other_object_write() {
        // `obj.write(...)` where obj is not `document` should NOT flag.
        let findings = analyze_js("logger.write(line);");
        assert!(
            findings.is_empty(),
            "non-document .write must not flag, got: {findings:#?}"
        );
    }

    #[test]
    fn detects_insert_adjacent_html_call() {
        let findings = analyze_js("el.insertAdjacentHTML('beforeend', userInput);");
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("insertAdjacentHTML")),
            "expected an insertAdjacentHTML finding, got: {findings:#?}"
        );
    }

    #[test]
    fn detects_dangerously_set_inner_html_jsx() {
        let src = r"
            function Comp() {
                return <div dangerouslySetInnerHTML={{ __html: userInput }} />;
            }
        ";
        let findings = analyze("comp.tsx", src);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("dangerouslySetInnerHTML")),
            "expected a dangerouslySetInnerHTML finding, got: {findings:#?}"
        );
    }

    #[test]
    fn dom_sink_findings_have_cwe_79() {
        let findings = analyze_js("el.innerHTML = x;");
        let f = findings
            .iter()
            .find(|f| f.message.contains("innerHTML"))
            .expect("innerHTML finding");
        assert!(
            f.cwe.iter().any(|c| c == "CWE-79"),
            "expected CWE-79 in finding.cwe, got: {:?}",
            f.cwe
        );
    }

    #[test]
    fn eval_finding_has_suggestion() {
        let findings = analyze_js("eval('dangerous code');");
        assert!(!findings.is_empty(), "expected at least one finding");
        assert!(
            findings[0].suggestion.is_some(),
            "eval finding should have a suggestion"
        );
    }
}
