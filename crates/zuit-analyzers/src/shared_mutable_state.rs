//! `TEST006-shared-mutable-state` — detects test functions that mutate
//! module-level state without a `setUp`/`tearDown` (or equivalent) fixture
//! providing cleanup. (CWE-820)
//!
//! ## Detection strategy
//!
//! For every [`FunctionLike`] in the [`SemanticIndex`] with `is_test == true`:
//!
//! 1. **Fixture guard** — scan all function names in `index.functions` and the
//!    entire source for any setUp/tearDown/fixture pattern.  If any lifecycle
//!    hook is found, **suppress all findings for that file** (conservative).
//!
//! 2. **Module-level mutable names** — collect names of module-scope mutable
//!    declarations for the language:
//!    - **Python:** lines at column 0 matching `^[A-Za-z_]\w*\s*=` (excluding
//!      `def`/`class`/`import`/`from`); also honour explicit `global` keyword.
//!    - **JS/TS:** `let` or `var` declarations at column 0
//!      (`^(?:let|var)\s+([A-Za-z_$]\w*)`).
//!    - **Rust:** `static\s+mut\s+([A-Z_][A-Z_0-9]*)` at column 0.
//!
//! 3. **Mutation check** — scan the test function body for mutation operators
//!    referencing any of the collected names, or (for Rust) for `unsafe {`
//!    which typically wraps `static mut` writes.  If found, emit one finding
//!    per test function (first matching name wins for the message).
//!
//! ## CWE
//!
//! CWE-820: Missing Synchronization / Shared Mutable State
//!
//! [`FunctionLike`]: zuit_core::FunctionLike
//! [`SemanticIndex`]: zuit_core::SemanticIndex

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages,
    span::{Location, Span},
};

/// Rule ID for the shared-mutable-state check.
pub const RULE_ID: &str = "TEST006-shared-mutable-state";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/TEST006-shared-mutable-state.md",
    cwe: &["CWE-820"],
    owasp: &[],
};

/// Suggestion text emitted with every finding.
const SUGGESTION: &str = "Isolate test state with setUp/tearDown (Python), beforeEach/afterEach (JS/TS), \
     or a Drop-based fixture (Rust). Prefer dependency injection and fresh-per-test \
     state over module-level mutable globals.";

/// Function names that indicate lifecycle teardown/setup is present in the file.
const FIXTURE_NAMES: &[&str] = &[
    "setUp",
    "tearDown",
    "setup",
    "teardown",
    "before",
    "after",
    "beforeEach",
    "afterEach",
    "before_each",
    "after_each",
    "setup_method",
    "teardown_method",
];

/// Source-level tokens that also indicate fixture/lifecycle presence.
const FIXTURE_SOURCE_TOKENS: &[&str] = &[
    "beforeEach(",
    "afterEach(",
    "before(",
    "after(",
    "pytest.fixture",
    "@fixture",
];

/// Returns `true` if the file contains any setUp/tearDown/fixture signal,
/// which causes all findings for the file to be suppressed.
fn has_fixture(file: &ParsedFile) -> bool {
    let index = file.index();

    // Check function names in the SemanticIndex.
    for func in &index.functions {
        if let Some(name) = &func.name
            && FIXTURE_NAMES.contains(&name.as_str())
        {
            return true;
        }
    }

    // Also scan source text for call-site tokens (e.g. `beforeEach(`, `@fixture`).
    let src = file.source().as_str();
    for &token in FIXTURE_SOURCE_TOKENS {
        if src.contains(token) {
            return true;
        }
    }

    false
}

/// Collect Python module-level mutable names.
///
/// Heuristic: lines at column 0 that look like `NAME =` where the name is not
/// a keyword (`def`, `class`, `import`, `from`, `if`, `for`, `while`, `try`,
/// `with`, `else`, `elif`, `except`, `finally`, `return`, `async`, `await`).
fn python_module_level_names(src: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in src.lines() {
        // Must start at column 0 — no leading whitespace.
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        // Skip obvious non-assignment lines.
        let first_word: &str = line.split_whitespace().next().unwrap_or("");
        if matches!(
            first_word,
            "def"
                | "class"
                | "import"
                | "from"
                | "if"
                | "for"
                | "while"
                | "try"
                | "with"
                | "else"
                | "elif"
                | "except"
                | "finally"
                | "return"
                | "async"
                | "await"
                | "#"
                | "@"
        ) {
            continue;
        }
        // Look for IDENTIFIER followed by optional whitespace then `=`
        // but not `==`.
        let trimmed = line.trim_end();
        if let Some(eq_pos) = trimmed.find('=') {
            // Exclude `==`.
            if trimmed.as_bytes().get(eq_pos + 1) == Some(&b'=') {
                continue;
            }
            // The part before `=` should be a valid identifier (possibly with
            // trailing whitespace).
            let before = trimmed[..eq_pos].trim_end();
            if is_identifier(before) {
                names.push(before.to_string());
            }
        }
    }
    names
}

/// Collect JS/TS module-level mutable variable names.
///
/// Heuristic: `let` or `var` declarations at column 0.
fn js_module_level_names(src: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in src.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        // Match `let NAME` or `var NAME` at start of line.
        let rest = if let Some(r) = line.strip_prefix("let ") {
            r
        } else if let Some(r) = line.strip_prefix("var ") {
            r
        } else {
            continue;
        };
        // Extract the identifier before any `=`, `:`, `;`, or whitespace.
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
            .collect();
        if !name.is_empty() {
            names.push(name);
        }
    }
    names
}

/// Collect Rust module-level `static mut` names.
///
/// Heuristic: `static mut NAME` at column 0.
fn rust_module_level_names(src: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in src.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        // Match `static mut NAME` or `pub static mut NAME`.
        let rest = if let Some(r) = line.strip_prefix("static mut ") {
            r
        } else if let Some(r) = line.strip_prefix("pub static mut ") {
            r
        } else if let Some(r) = line.strip_prefix("pub(crate) static mut ") {
            r
        } else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            names.push(name);
        }
    }
    names
}

/// Returns `true` if `s` is a non-empty valid identifier (ASCII subset).
fn is_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap_or('\0');
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|c| c.is_alphanumeric() || c == '_')
}

/// Returns `true` if the Python test body mutates `name` via:
/// - explicit `global name`
/// - `name = …`, `name += …`, etc.
/// - `name.append(`, `name.pop(`, `name.clear(`, `name.remove(`, `name.extend(`
/// - `name[` (subscript mutation)
fn python_body_mutates(body: &str, name: &str) -> bool {
    // Explicit global keyword.
    let global_kw = format!("global {name}");
    if body.contains(&global_kw) {
        return true;
    }
    // Assignment / augmented assignment patterns.
    let patterns: &[&str] = &[
        &format!("{name} ="),
        &format!("{name} +="),
        &format!("{name} -="),
        &format!("{name} *="),
        &format!("{name}.append("),
        &format!("{name}.pop("),
        &format!("{name}.clear("),
        &format!("{name}.remove("),
        &format!("{name}.extend("),
        &format!("{name}["),
    ];
    patterns.iter().any(|pat| body.contains(*pat))
}

/// Returns `true` if the JS/TS test body mutates `name`.
fn js_body_mutates(body: &str, name: &str) -> bool {
    let patterns: &[&str] = &[
        &format!("{name} ="),
        &format!("{name} +="),
        &format!("{name} -="),
        &format!("{name}++"),
        &format!("{name}--"),
        &format!("{name}.push("),
        &format!("{name}.pop("),
        &format!("{name}.shift("),
        &format!("{name}.unshift("),
        &format!("{name}.length ="),
        &format!("{name}["),
    ];
    patterns.iter().any(|pat| body.contains(*pat))
}

/// Returns `true` if the Rust test body likely mutates a `static mut`.
///
/// Signals: `unsafe {` block anywhere in the body (almost always wraps
/// `static mut` writes in Rust), or an assignment to any of the known names.
fn rust_body_mutates(body: &str, names: &[String]) -> bool {
    // `unsafe {` is the canonical guard for `static mut` writes.
    if body.contains("unsafe {") || body.contains("unsafe{") {
        return true;
    }
    // Direct assignment patterns for the known names.
    for name in names {
        let patterns: &[&str] = &[
            &format!("{name} ="),
            &format!("{name} +="),
            &format!("{name} -="),
        ];
        if patterns.iter().any(|pat| body.contains(*pat)) {
            return true;
        }
    }
    // Also catch `.write()` or `.lock()` mutation patterns on OnceLock/lazy_static.
    body.contains(".write()") || body.contains(".lock()")
}

/// Detect which language the file is based on its extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileLang {
    Python,
    Js,
    Rust,
    Other,
}

fn detect_lang(path: &str) -> FileLang {
    let p = std::path::Path::new(path);
    let ext = p
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("py") => FileLang::Python,
        Some("ts" | "tsx" | "js" | "jsx" | "mjs") => FileLang::Js,
        Some("rs") => FileLang::Rust,
        _ => FileLang::Other,
    }
}

/// Analyzer that detects test functions mutating module-level state without
/// a setUp/tearDown fixture providing isolation.
#[derive(Debug, Default)]
pub struct SharedMutableStateAnalyzer;

impl Analyzer for SharedMutableStateAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::TestSmell
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let source = file.source();
        let path_str = source.path.to_string_lossy();
        let lang = detect_lang(&path_str);

        // Only handle the three target languages; skip everything else.
        if lang == FileLang::Other {
            return Vec::new();
        }

        // Gate: if any fixture / lifecycle hook is present, suppress all findings.
        if has_fixture(file) {
            return Vec::new();
        }

        let src_str = source.as_str();
        let index = file.index();

        // Collect module-level mutable names for the language.
        let module_names: Vec<String> = match lang {
            FileLang::Python => python_module_level_names(src_str),
            FileLang::Js => js_module_level_names(src_str),
            FileLang::Rust => rust_module_level_names(src_str),
            FileLang::Other => Vec::new(),
        };

        // For Rust, if there are no static mut names and no unsafe usage
        // expected, there's nothing to flag.  We still run the check because
        // the body scanner (rust_body_mutates) also covers `unsafe {` broadly.
        // If no module names and we're Rust, only fire on `unsafe {`.
        let has_module_names = !module_names.is_empty();
        if lang == FileLang::Rust && !has_module_names {
            // Nothing to flag without `static mut` declarations.
            return Vec::new();
        }
        if lang != FileLang::Rust && !has_module_names {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for func in &index.functions {
            if !func.is_test {
                continue;
            }

            let body_start = func.body_span.start.0 as usize;
            let body_end = func.body_span.end.0 as usize;
            let body_end = body_end.min(src_str.len());

            if body_start >= src_str.len() || body_start > body_end {
                continue;
            }

            let body = &src_str[body_start..body_end];
            let name = func.name.as_deref().unwrap_or("<anonymous>");

            // Find the first mutated name (for the message).
            let first_mutated: Option<&str> = match lang {
                FileLang::Python => module_names
                    .iter()
                    .find(|n| python_body_mutates(body, n))
                    .map(String::as_str),
                FileLang::Js => module_names
                    .iter()
                    .find(|n| js_body_mutates(body, n))
                    .map(String::as_str),
                FileLang::Rust => {
                    if rust_body_mutates(body, &module_names) {
                        // Report the first declared static mut name.
                        module_names.first().map(String::as_str)
                    } else {
                        None
                    }
                }
                FileLang::Other => None,
            };

            let Some(mutated) = first_mutated else {
                continue;
            };

            let span = Span::new(func.span.start, func.span.start);
            let (start_lc, end_lc) = source.span_to_linecols(span);

            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::TestSmell,
                rule_id: RULE_ID.to_string(),
                severity: Severity::Medium,
                message: format!(
                    "test function `{name}` mutates module-level state `{mutated}` \
                     without setUp/tearDown isolation (CWE-820)"
                ),
                location: Location {
                    file: source.path.clone(),
                    span,
                    start: start_lc,
                    end: end_lc,
                },
                suggestion: Some(SUGGESTION.to_string()),
                references: vec![],
                cwe: META.cwe_vec(),
                owasp: META.owasp_vec(),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use zuit_core::{Config, Language, SourceFile};

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

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_shared_mutable_state_positive() {
        let source = include_str!("../../../fixtures/python/shared_mutable_state/main.py");
        let file = python_parse("fixtures/python/shared_mutable_state/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SharedMutableStateAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 TEST006 finding for shared_mutable_state Python fixture"
        );
        assert!(
            findings.iter().all(|f| f.rule_id == RULE_ID),
            "all findings must have rule_id == {RULE_ID}"
        );
        assert!(
            findings.iter().all(|f| f.dimension == Dimension::TestSmell),
            "all findings must have Dimension::TestSmell"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.cwe.iter().any(|c| c == "CWE-820")),
            "all findings must contain CWE-820"
        );
        assert!(
            findings.iter().all(|f| f.severity == Severity::Medium),
            "all findings must have Severity::Medium"
        );
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings must have a suggestion"
        );
    }

    // ── Python negative ───────────────────────────────────────────────────────

    #[test]
    fn python_not_shared_mutable_state_negative() {
        let source = include_str!("../../../fixtures/python/not_shared_mutable_state/main.py");
        let file = python_parse("fixtures/python/not_shared_mutable_state/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SharedMutableStateAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST006 findings for not_shared_mutable_state Python fixture, \
             got {findings:#?}"
        );
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_shared_mutable_state_positive() {
        let source = include_str!("../../../fixtures/js/shared_mutable_state/main.ts");
        let file = js_parse("fixtures/js/shared_mutable_state/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SharedMutableStateAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 TEST006 finding for shared_mutable_state JS fixture"
        );
        assert!(
            findings.iter().all(|f| f.rule_id == RULE_ID),
            "all findings must have rule_id == {RULE_ID}"
        );
        assert!(
            findings.iter().all(|f| f.dimension == Dimension::TestSmell),
            "all findings must have Dimension::TestSmell"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.cwe.iter().any(|c| c == "CWE-820")),
            "all findings must contain CWE-820"
        );
        assert!(
            findings.iter().all(|f| f.severity == Severity::Medium),
            "all findings must have Severity::Medium"
        );
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings must have a suggestion"
        );
    }

    // ── JS negative ───────────────────────────────────────────────────────────

    #[test]
    fn js_not_shared_mutable_state_negative() {
        let source = include_str!("../../../fixtures/js/not_shared_mutable_state/main.ts");
        let file = js_parse("fixtures/js/not_shared_mutable_state/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SharedMutableStateAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST006 findings for not_shared_mutable_state JS fixture, \
             got {findings:#?}"
        );
    }

    // ── Rust positive ─────────────────────────────────────────────────────────

    #[test]
    fn rust_shared_mutable_state_positive() {
        let source = include_str!("../../../fixtures/rust/shared_mutable_state/lib.rs");
        let file = rust_parse("fixtures/rust/shared_mutable_state/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SharedMutableStateAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 TEST006 finding for shared_mutable_state Rust fixture"
        );
        assert!(
            findings.iter().all(|f| f.rule_id == RULE_ID),
            "all findings must have rule_id == {RULE_ID}"
        );
        assert!(
            findings.iter().all(|f| f.dimension == Dimension::TestSmell),
            "all findings must have Dimension::TestSmell"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.cwe.iter().any(|c| c == "CWE-820")),
            "all findings must contain CWE-820"
        );
        assert!(
            findings.iter().all(|f| f.severity == Severity::Medium),
            "all findings must have Severity::Medium"
        );
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings must have a suggestion"
        );
    }

    // ── Rust negative ─────────────────────────────────────────────────────────

    #[test]
    fn rust_not_shared_mutable_state_negative() {
        let source = include_str!("../../../fixtures/rust/not_shared_mutable_state/lib.rs");
        let file = rust_parse("fixtures/rust/not_shared_mutable_state/lib.rs", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SharedMutableStateAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 TEST006 findings for not_shared_mutable_state Rust fixture, \
             got {findings:#?}"
        );
    }

    // ── Non-test function emits nothing ───────────────────────────────────────

    #[test]
    fn non_test_function_emits_nothing() {
        // A Python file with module-level `X = 0` and a non-test function
        // that mutates it — must emit 0 findings because `is_test == false`.
        let source = r"
X = 0

def use_x():
    global X
    X += 1
";
        let file = python_parse("synthetic.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = SharedMutableStateAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "non-test function must emit 0 TEST006 findings, got {findings:#?}"
        );
    }
}
