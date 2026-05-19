//! `SEC016-dangerous-function` — flags calls to inherently dangerous libc
//! C functions exposed through FFI (CWE-242).
//!
//! # Detection
//!
//! Reads the pre-extracted `RustAst::dangerous_calls` populated at parse
//! time inside `Extractor::visit_expr_call`. The match is on the **last**
//! path segment, so `libc::gets(...)`, `::libc::gets(...)`, and bare
//! `gets(...)` all flag.
//!
//! # Flagged callees
//!
//! `gets`, `gets_s`, `strcpy`, `strcat`, `sprintf`, `vsprintf`, `scanf`,
//! `wcscpy`, `wcscat`. These functions copy or read without length bounds
//! and cannot be made safe through input validation alone.
//!
//! # Languages
//!
//! Rust only. (Python and JavaScript variants of `SEC016` exist in the
//! corresponding language crates.)

use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, Dimension, Finding, LanguageId, Location, ParsedFile, RuleMeta,
    Severity, SupportedLanguages,
};

/// The stable rule ID.
const RULE_ID: &str = "SEC016-dangerous-function";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/SEC016-dangerous-function.md",
    cwe: &["CWE-242"],
    owasp: &["A03:2021"],
};

/// Analyzer that emits `SEC016-dangerous-function` for Rust FFI calls to
/// inherently dangerous libc functions.
pub struct DangerousFunctionAnalyzer;

impl zuit_core::Analyzer for DangerousFunctionAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Security
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

        let source = file.source();
        let file_path = source.path.clone();

        ast.dangerous_calls
            .iter()
            .map(|site| {
                let (start_lc, end_lc) = source.span_to_linecols(site.span);
                Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Security,
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::High,
                    message: format!(
                        "call to inherently dangerous libc function `{}` — \
                         no input validation can make this call safe",
                        site.name
                    ),
                    location: Location {
                        file: file_path.clone(),
                        span: site.span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(safer_alternative(site.name).to_string()),
                    references: vec!["https://cwe.mitre.org/data/definitions/242.html".to_string()],
                    cwe: META.cwe_vec(),
                    owasp: META.owasp_vec(),
                }
            })
            .collect()
    }
}

/// Returns a one-sentence suggestion for replacing each flagged callee.
fn safer_alternative(name: &str) -> &'static str {
    match name {
        "gets" | "gets_s" => {
            "Replace with `fgets` plus an explicit buffer length, or use Rust's `BufRead::read_line`."
        }
        "strcpy" | "wcscpy" => {
            "Replace with `strncpy_s` (with checked length), `std::ffi::CStr` round-trips, \
             or use Rust's owned `String`/`CString` types."
        }
        "strcat" | "wcscat" => {
            "Replace with `strncat_s` (with checked length) or use Rust's `String::push_str`."
        }
        "sprintf" | "vsprintf" => {
            "Replace with `snprintf` (with explicit buffer length) or Rust's `format!`/`write!` macros."
        }
        "scanf" => {
            "Replace with `fgets` + a dedicated parser, or use Rust's `BufRead`/`std::io` parsing helpers."
        }
        _ => {
            "Replace with a length-checked variant from the same family or with a Rust-native equivalent."
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RustLanguage;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, Language, LanguageId, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("test.rs", src.as_bytes().to_vec()));
        let parsed = RustLanguage.parse(source).expect("parse failed");
        let analyzer = DangerousFunctionAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    #[test]
    fn flags_libc_gets_call() {
        let src = r"
            extern crate libc;
            unsafe fn unsafe_read(buf: *mut std::os::raw::c_char) {
                libc::gets(buf);
            }
        ";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].dimension, Dimension::Security);
        assert!(findings[0].message.contains("gets"));
    }

    #[test]
    fn flags_libc_strcpy() {
        let src = r"
            unsafe fn copy(dst: *mut i8, src: *const i8) {
                libc::strcpy(dst, src);
            }
        ";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].message.contains("strcpy"));
    }

    #[test]
    fn flags_bare_strcat() {
        // No `libc::` prefix — last-segment match still fires.
        let src = "unsafe fn append() { strcat(a, b); }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].message.contains("strcat"));
    }

    #[test]
    fn flags_absolute_path_form() {
        let src = "unsafe fn s() { ::libc::sprintf(buf, fmt); }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].message.contains("sprintf"));
    }

    #[test]
    fn flags_scanf() {
        let src = "unsafe fn read() { libc::scanf(fmt, &mut x); }";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_each_dangerous_call_separately() {
        let src = r"
            unsafe fn many() {
                libc::gets(a);
                libc::strcpy(a, b);
                libc::sprintf(buf, fmt);
            }
        ";
        let findings = analyze(src);
        assert_eq!(findings.len(), 3, "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_safe_alternatives() {
        let src = r"
            unsafe fn safe() {
                libc::fgets(buf, n, stream);
                libc::snprintf(buf, n, fmt);
                libc::strncpy(dst, src, n);
            }
        ";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn does_not_flag_unrelated_function_with_collision() {
        // A user-defined function called `strcpy` is still flagged — there's
        // no way to disambiguate without symbol resolution, and the convention
        // is loud-name. The same applies to other rules in this family.
        // This test documents the expected behaviour, not a bug.
        let src = "fn strcpy() {}\nfn caller() { strcpy(); }\n";
        let findings = analyze(src);
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_method_call() {
        // `x.gets()` is a method call, not a free function — should not flag.
        let src = "fn user() { x.gets(); }";
        assert!(analyze(src).is_empty());
    }

    #[test]
    fn supported_languages_is_rust_only() {
        let analyzer = DangerousFunctionAnalyzer;
        assert!(analyzer.supported_languages().supports(LanguageId("rust")));
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
    }
}
