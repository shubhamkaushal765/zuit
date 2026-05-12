//! `SEC005-insecure-deser` — detects use of insecure deserialization functions
//! that can execute arbitrary code when fed untrusted input.
//!
//! ## Heuristics
//!
//! Two complementary signals are combined per file:
//!
//! 1. **Import scan** — at least one `Import.path` contains (case-insensitively)
//!    a known insecure deserializer module:
//!    - Python: `pickle`, `cpickle`, `marshal`, `yaml`
//!    - JS/TS: `node-serialize`, `serialize-javascript`
//!
//! 2. **Source scan** — the raw file text is scanned line-by-line for call-site
//!    patterns such as `pickle.loads(`, `marshal.load(`, `yaml.load(` (without a
//!    safe Loader argument), `yaml.unsafe_load(`, and `unserialize(` (when a
//!    `node-serialize` import is present).
//!
//! If signal 1 is absent, the file is skipped immediately (no source scan).
//! When signal 1 is present, every matching call site in signal 2 becomes a
//! finding.  One finding is emitted per matching source-text occurrence.
//!
//! For `yaml.load(`, the finding is **suppressed** when `Loader=yaml.SafeLoader`,
//! `Loader=SafeLoader`, or `Loader=yaml.CSafeLoader` appears within 120 bytes
//! after the opening parenthesis.

use std::sync::OnceLock;

use regex::Regex;

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, Dimension, Finding, ParsedFile, RuleMeta, Severity,
    SupportedLanguages, span::Location,
};

/// Rule ID for the insecure-deserialization check.
pub const RULE_ID: &str = "SEC005-insecure-deser";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/SEC005-insecure-deser.md",
    cwe: &["CWE-502"],
    owasp: &["A08:2021"],
};

/// Suggestion text for every finding emitted by this rule.
const SUGGESTION: &str = "Avoid pickle/marshal/yaml.load on untrusted data; use json.loads or \
    yaml.safe_load. For node-serialize, use JSON.parse on validated input.";

/// Import-path substrings (lower-cased) that indicate the file can deserialize
/// untrusted data with a dangerous library.
const INSECURE_DESER_IMPORTS: &[&str] = &[
    "pickle",
    "cpickle",
    "marshal",
    "yaml",
    "node-serialize",
    "serialize-javascript",
];

/// Returns the compiled regex that matches insecure deserialization call sites
/// in raw source text.
///
/// The pattern covers:
/// - `pickle.load(` / `pickle.loads(`
/// - `cPickle.load(` / `cPickle.loads(`
/// - `marshal.load(` / `marshal.loads(`
/// - `yaml.load(` (safe-loader suppression is applied separately)
/// - `yaml.unsafe_load(`
/// - `unserialize(` (gated on import presence in the caller)
fn insecure_call_pattern() -> &'static Regex {
    static PAT: OnceLock<Regex> = OnceLock::new();
    PAT.get_or_init(|| {
        Regex::new(
            r"(?i)(pickle\.loads?\(|cPickle\.loads?\(|marshal\.loads?\(|yaml\.load\(|yaml\.unsafe_load\(|unserialize\()",
        )
        .expect("invariant: insecure-deser call pattern is valid")
    })
}

/// Safe-loader strings that, when appearing within 120 bytes after `yaml.load(`,
/// indicate safe usage and should suppress the finding.
const YAML_SAFE_LOADERS: &[&str] = &[
    "Loader=yaml.SafeLoader",
    "Loader=SafeLoader",
    "Loader=yaml.CSafeLoader",
];

/// Returns `true` if the file imports at least one insecure deserializer module.
fn has_insecure_deser_import(file: &ParsedFile) -> bool {
    let index = file.index();
    index.imports.iter().any(|imp| {
        let lower = imp.path.to_lowercase();
        INSECURE_DESER_IMPORTS.iter().any(|sub| lower.contains(sub))
    })
}

/// Returns `true` if the file imports `node-serialize` (used to gate
/// `unserialize(` findings).
fn has_node_serialize_import(file: &ParsedFile) -> bool {
    file.index()
        .imports
        .iter()
        .any(|imp| imp.path.to_lowercase().contains("node-serialize"))
}

/// Returns `true` if the `yaml.load(` match at `match_end` (index of the char
/// immediately after `(`) has a safe-Loader argument within 120 bytes of `source`.
fn yaml_load_is_safe(source: &str, match_end: usize) -> bool {
    let window_end = (match_end + 120).min(source.len());
    let window = &source[match_end..window_end];
    YAML_SAFE_LOADERS.iter().any(|safe| window.contains(safe))
}

/// Analyzer that detects use of insecure deserialization APIs.
#[derive(Debug, Default)]
pub struct InsecureDeserAnalyzer;

impl Analyzer for InsecureDeserAnalyzer {
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
        if !has_insecure_deser_import(file) {
            return vec![];
        }

        let source = file.source();
        let text = source.as_str();
        let regex = insecure_call_pattern();
        let node_serialize = has_node_serialize_import(file);
        let mut findings = Vec::new();

        for mat in regex.find_iter(text) {
            let matched = mat.as_str();
            let byte_start = mat.start();
            let byte_end = mat.end();

            // Gate `unserialize(` on a node-serialize import.
            if matched.to_lowercase().starts_with("unserialize") && !node_serialize {
                continue;
            }

            // Suppress safe yaml.load calls.
            if matched.to_lowercase().starts_with("yaml.load(") && yaml_load_is_safe(text, byte_end)
            {
                continue;
            }

            #[allow(clippy::cast_possible_truncation)]
            let span = zuit_core::span::Span::new(
                zuit_core::span::ByteOffset(byte_start as u32),
                zuit_core::span::ByteOffset(byte_end as u32),
            );
            let (start_lc, end_lc) = source.span_to_linecols(span);
            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Security,
                rule_id: RULE_ID.to_string(),
                severity: Severity::High,
                message: format!(
                    "insecure deserialization call `{}` may execute arbitrary code on untrusted input",
                    matched.trim_end_matches('('),
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
    use zuit_core::{Config, Language, SourceFile};
    use std::sync::Arc;

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

    // ── regex / helper unit tests ─────────────────────────────────────────────

    #[test]
    fn regex_matches_pickle_loads() {
        assert!(insecure_call_pattern().is_match("pickle.loads(data)"));
    }

    #[test]
    fn regex_matches_pickle_load() {
        assert!(insecure_call_pattern().is_match("pickle.load(f)"));
    }

    #[test]
    fn regex_matches_yaml_load() {
        assert!(insecure_call_pattern().is_match("yaml.load(stream)"));
    }

    #[test]
    fn regex_matches_yaml_unsafe_load() {
        assert!(insecure_call_pattern().is_match("yaml.unsafe_load(stream)"));
    }

    #[test]
    fn regex_matches_marshal_loads() {
        assert!(insecure_call_pattern().is_match("marshal.loads(b)"));
    }

    #[test]
    fn regex_does_not_match_json_loads() {
        assert!(!insecure_call_pattern().is_match("json.loads(s)"));
    }

    #[test]
    fn yaml_load_suppressed_by_safeloader() {
        let source = "yaml.load(stream, Loader=yaml.SafeLoader)";
        let mat = insecure_call_pattern().find(source).expect("should match");
        assert!(yaml_load_is_safe(source, mat.end()));
    }

    #[test]
    fn yaml_load_not_suppressed_without_safeloader() {
        let source = "yaml.load(stream)";
        let mat = insecure_call_pattern().find(source).expect("should match");
        assert!(!yaml_load_is_safe(source, mat.end()));
    }

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_insecure_deser_positive() {
        let source = include_str!("../../../fixtures/python/insecure_deser/main.py");
        let file = python_parse("fixtures/python/insecure_deser/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = InsecureDeserAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC005 finding for insecure_deser Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings
                .iter()
                .all(|f| f.cwe.iter().any(|c| c == "CWE-502")),
            "expected CWE-502 in finding.cwe"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.owasp.iter().any(|o| o == "A08:2021")),
            "expected A08:2021 in finding.owasp"
        );
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings should have a suggestion"
        );
    }

    // ── Python negative (healthy) ─────────────────────────────────────────────

    #[test]
    fn python_healthy_insecure_deser_negative() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let file = python_parse("fixtures/python/healthy/main.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = InsecureDeserAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC005 findings for healthy Python fixture, got {findings:#?}"
        );
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_insecure_deser_positive() {
        let source = include_str!("../../../fixtures/js/insecure_deser/main.ts");
        let file = js_parse("fixtures/js/insecure_deser/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = InsecureDeserAnalyzer.analyze_file(&ctx, &file);
        assert!(
            !findings.is_empty(),
            "expected ≥1 SEC005 finding for insecure_deser JS fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── JS negative (healthy) ─────────────────────────────────────────────────

    #[test]
    fn js_healthy_insecure_deser_negative() {
        let source = include_str!("../../../fixtures/js/healthy/main.ts");
        let file = js_parse("fixtures/js/healthy/main.ts", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = InsecureDeserAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "expected 0 SEC005 findings for healthy JS fixture, got {findings:#?}"
        );
    }

    // ── yaml.load with safe loader is not flagged ─────────────────────────────

    #[test]
    fn python_yaml_safe_load_not_flagged() {
        let source = "
import yaml
def load(s):
    return yaml.load(s, Loader=yaml.SafeLoader)
";
        let file = python_parse("test.py", source);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = InsecureDeserAnalyzer.analyze_file(&ctx, &file);
        assert!(
            findings.is_empty(),
            "yaml.load with SafeLoader must not be flagged, got {findings:#?}"
        );
    }
}
