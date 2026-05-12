//! `SEC003-shell-injection` — heuristic detector for shell-command construction sinks.
//!
//! Two complementary signals must both be present in the same file before any
//! finding is emitted, which keeps the false-positive rate low:
//!
//! 1. **Shell-exec import**: at least one `Import.path` in the
//!    [`zuit_core::SemanticIndex`] contains (case-insensitively) one of the
//!    well-known shell-execution module names:
//!    `subprocess`, `os.system`, `os.popen`, `commands.getoutput`,
//!    `child_process`, `std::process::Command`, `std.process`, `shelljs`, `execa`.
//!
//! 2. **Shell-prefix string literal**: at least one string literal value matches
//!    the regex `(?i)^(sh|bash|zsh|cmd|cmd\.exe|powershell|/bin/sh|/bin/bash|pwsh)\s+(-c|/c|/k)\b`.
//!    These prefixes indicate that a shell is being invoked with a constructed
//!    command argument — the canonical injection sink.
//!
//! One finding is emitted per matching string literal (located at the literal's
//! span). If signal 1 is absent the file is skipped entirely.

use std::sync::OnceLock;

use regex::Regex;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages, span::Location,
};

/// Rule ID for the shell-injection check.
pub const RULE_ID: &str = "SEC003-shell-injection";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/SEC003-shell-injection.md",
    cwe: &["CWE-78"],
    owasp: &["A03:2021"],
};

/// Substrings that, when found (case-insensitively) in an import path, indicate
/// that the file is capable of spawning shell processes.
const SHELL_EXEC_MODULES: &[&str] = &[
    "subprocess",
    "os.system",
    "os.popen",
    "commands.getoutput",
    "child_process",
    "std::process::command",
    "std.process",
    "shelljs",
    "execa",
];

/// Returns the compiled regex that matches string literals whose prefix
/// indicates a shell invocation with a constructed argument.
///
/// Pattern: the value starts with a shell name followed by whitespace and then
/// `-c`, `/c`, or `/k` (the flags that cause the shell to execute a string).
fn shell_prefix_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(
            r"(?i)^(sh|bash|zsh|cmd|cmd\.exe|powershell|/bin/sh|/bin/bash|pwsh)\s+(-c|/c|/k)\b",
        )
        .expect("invariant: shell-prefix pattern is valid")
    })
}

/// Returns `true` if the file's import list contains at least one shell-exec
/// module reference.
fn has_shell_exec_import(file: &ParsedFile) -> bool {
    let index = file.index();
    index.imports.iter().any(|imp| {
        let path_lower = imp.path.to_lowercase();
        SHELL_EXEC_MODULES
            .iter()
            .any(|module| path_lower.contains(module))
    })
}

/// Analyzer that detects likely shell-command construction sinks.
///
/// Both signals (shell-exec import *and* shell-prefix string literal) must be
/// present in the same file for a finding to be emitted.
#[derive(Debug, Default)]
pub struct ShellInjectionAnalyzer;

impl Analyzer for ShellInjectionAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Security
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        // Signal 1: the file must import a shell-exec module.
        if !has_shell_exec_import(file) {
            return vec![];
        }

        let source = file.source();
        let index = file.index();
        let regex = shell_prefix_pattern();

        // Signal 2: emit one finding per string literal that looks like a
        // shell-prefix invocation.
        index
            .string_literals
            .iter()
            .filter(|lit| regex.is_match(&lit.value))
            .map(|lit| {
                let (start_lc, end_lc) = source.span_to_linecols(lit.span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Security,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::High,
                    message: format!(
                        "shell-command string literal with shell-prefix pattern: {:?}",
                        &lit.value
                    ),
                    location: Location {
                        file: source.path.clone(),
                        span: lit.span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Pass arguments as a list (avoid shell=True / shell wrappers); \
                         validate or quote untrusted input with `shlex.quote` (Py) / \
                         a safe escaping helper (JS)."
                            .to_string(),
                    ),
                    references: vec![],
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

    fn js_parse(path: &str, source: &str) -> ParsedFile {
        let src = Arc::new(SourceFile::new(path, source.as_bytes().to_vec()));
        zuit_lang_js::JsLanguage
            .parse(src)
            .expect("js parse failed")
    }

    fn make_ctx(config: &Config) -> AnalysisContext<'_> {
        AnalysisContext::new(config)
    }

    // ── regex unit tests ──────────────────────────────────────────────────────

    #[test]
    fn regex_sh_minus_c_matches() {
        assert!(
            shell_prefix_pattern().is_match("sh -c"),
            "expected 'sh -c' to match shell-prefix pattern"
        );
    }

    #[test]
    fn regex_bash_minus_c_matches() {
        assert!(
            shell_prefix_pattern().is_match("bash -c echo hello"),
            "expected 'bash -c echo hello' to match shell-prefix pattern"
        );
    }

    #[test]
    fn regex_bash_login_does_not_match() {
        assert!(
            !shell_prefix_pattern().is_match("bash --login"),
            "'bash --login' must NOT match — no -c / /c / /k"
        );
    }

    #[test]
    fn regex_sshd_config_does_not_match() {
        // The word 'sh' at start followed by 'd' is not a shell binary.
        // However since the regex requires \s+ after the shell name this
        // particular string would fail at that step; the word boundary on the
        // shell token is enforced by the `^` anchor and `\s+` requirement.
        assert!(
            !shell_prefix_pattern().is_match("sshd-config"),
            "'sshd-config' must NOT match — not a shell invocation"
        );
    }

    #[test]
    fn regex_cmd_slash_c_matches() {
        assert!(
            shell_prefix_pattern().is_match("cmd /c dir"),
            "expected 'cmd /c dir' to match shell-prefix pattern"
        );
    }

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_shell_injection_positive() {
        let source = include_str!("../../../fixtures/python/shell_injection/main.py");
        let file = python_parse("fixtures/python/shell_injection/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = ShellInjectionAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC003 finding for shell_injection Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings.iter().all(|f| f.cwe.iter().any(|c| c == "CWE-78")),
            "expected CWE-78 in finding.cwe"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.owasp.iter().any(|o| o == "A03:2021")),
            "expected A03:2021 in finding.owasp"
        );
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings should have a suggestion"
        );
    }

    // ── Python negative (healthy) ─────────────────────────────────────────────

    #[test]
    fn python_healthy_shell_injection_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = ShellInjectionAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC003 findings for healthy Python fixture, got {findings:#?}"
        );
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_shell_injection_positive() {
        let source = include_str!("../../../fixtures/js/shell_injection/main.ts");
        let file = js_parse("fixtures/js/shell_injection/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = ShellInjectionAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC003 finding for shell_injection JS fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── JS negative (healthy) ─────────────────────────────────────────────────

    #[test]
    fn js_healthy_shell_injection_negative() {
        let source = include_str!("../../../fixtures/js/healthy/main.ts");
        let file = js_parse("fixtures/js/healthy/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = ShellInjectionAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC003 findings for healthy JS fixture, got {findings:#?}"
        );
    }

    // ── Rust positive ─────────────────────────────────────────────────────────

    #[test]
    fn rust_shell_injection_positive() {
        let source = include_str!("../../../fixtures/rust/shell_injection/lib.rs");
        let file = rust_parse("fixtures/rust/shell_injection/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = ShellInjectionAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC003 finding for shell_injection Rust fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Rust negative (healthy) ───────────────────────────────────────────────

    #[test]
    fn rust_healthy_shell_injection_negative() {
        let source = include_str!("../../../fixtures/rust/healthy/lib.rs");
        let file = rust_parse("fixtures/rust/healthy/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = ShellInjectionAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC003 findings for healthy Rust fixture, got {findings:#?}"
        );
    }
}
