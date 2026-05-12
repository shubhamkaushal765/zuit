//! `CPLX003-duplicate-code` — cross-file sliding-window hash duplicate
//! detection.
//!
//! ## Algorithm
//!
//! 1. For each parsed file, extract its normalised non-blank, non-comment
//!    lines from the raw source text.  A line is considered a comment if it
//!    starts (after trimming) with `//`, `#`, or `*`.
//!
//! 2. Slide a window of `threshold` lines over each file's line list.  For
//!    each window, compute a 64-bit hash of the concatenated normalised lines.
//!
//! 3. The first time a hash is seen, record its location (file path + first
//!    line number).  Every subsequent occurrence is a duplicate: emit one
//!    finding at the duplicate site referencing the original location.
//!
//! ## Configuration
//!
//! ```toml
//! [rules."CPLX003-duplicate-code"]
//! threshold = 6   # default window size in lines
//! ```
//!
//! ## Notes
//!
//! * `analyze_file` always returns an empty vec; all work happens in
//!   `analyze_project`.
//! * Hash collisions are astronomically unlikely for realistic source files
//!   but are not impossible.  The implementation uses `FxHasher` (from
//!   `rustc_hash`) for speed; a false positive would require a collision
//!   on a 64-bit hash.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, AnalyzerKind, Dimension, Finding, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Location, Span},
};

/// Rule ID for the duplicate-code check.
pub const RULE_ID: &str = "CPLX003-duplicate-code";

/// Default sliding-window size in lines.
const DEFAULT_THRESHOLD: u32 = 6;

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/CPLX003-duplicate-code.md",
    cwe: &[],
    owasp: &[],
};

/// A location for the first occurrence of a window hash: (file path, 1-based start line).
#[derive(Clone)]
struct Origin {
    path: std::path::PathBuf,
    line: u32,
}

/// Normalises a single source line for duplicate detection.
///
/// Strips leading/trailing whitespace.  Returns `None` if the line is blank
/// or looks like a comment (starts with `//`, `#`, `*`, or `--`).
fn normalise_line(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Skip comment lines.
    if trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with('*')
        || trimmed.starts_with("--")
    {
        return None;
    }
    Some(trimmed)
}

/// Collects the normalised non-blank, non-comment lines from `source` together
/// with their 1-based original line numbers.
fn collect_lines(source: &str) -> Vec<(u32, &str)> {
    source
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            normalise_line(line).map(|l| {
                #[allow(clippy::cast_possible_truncation)]
                let line_no = (i + 1) as u32;
                (line_no, l)
            })
        })
        .collect()
}

/// Hashes a slice of normalised line strings using the standard hasher.
///
/// Using [`std::collections::hash_map::DefaultHasher`] is sufficient for
/// correctness; we only need collision-free hashing of source text, not
/// cryptographic strength.
fn hash_window(lines: &[&str]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for line in lines {
        line.hash(&mut hasher);
    }
    hasher.finish()
}

/// Analyzer that detects duplicate code blocks across all project files.
#[derive(Debug, Default)]
pub struct DuplicateCodeAnalyzer;

impl Analyzer for DuplicateCodeAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Complexity
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn kind(&self) -> AnalyzerKind {
        AnalyzerKind::ProjectLevel
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, _file: &ParsedFile) -> Vec<Finding> {
        // All work is done in analyze_project.
        vec![]
    }

    fn analyze_project(&self, ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        if project.files.is_empty() {
            return vec![];
        }

        let threshold = ctx.config.rule_threshold(RULE_ID, DEFAULT_THRESHOLD);
        let window = threshold as usize;
        if window == 0 {
            return vec![];
        }

        // Sort files by path for determinism.
        let mut files: Vec<&ParsedFile> = project.files.iter().collect();
        files.sort_by_key(|f| &f.source().path);

        // Map from window hash → first occurrence.
        let mut seen: HashMap<u64, Origin> = HashMap::new();
        let mut findings: Vec<Finding> = Vec::new();

        for file in &files {
            let source = file.source();
            let src_str = source.as_str();
            let lines = collect_lines(src_str);

            if lines.len() < window {
                continue;
            }

            for i in 0..=(lines.len() - window) {
                let window_lines: Vec<&str> =
                    lines[i..i + window].iter().map(|(_, l)| *l).collect();

                let h = hash_window(&window_lines);
                let start_line = lines[i].0;

                if let Some(origin) = seen.get(&h) {
                    // Duplicate found; emit a finding at this site.
                    let origin_path = origin.path.display().to_string();
                    let span = Span::new(ByteOffset(0), ByteOffset(0));
                    let lc = LineCol::new(start_line, 1);

                    findings.push(Finding {
                        analyzer: AnalyzerId::new(RULE_ID),
                        dimension: Dimension::Complexity,
                        rule_id: RULE_ID.to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "duplicate code block ({window} lines) first seen at \
                             {origin_path}:{orig_line}",
                            orig_line = origin.line,
                        ),
                        location: Location {
                            file: source.path.clone(),
                            span,
                            start: lc,
                            end: lc,
                        },
                        suggestion: Some(
                            "Extract the duplicated block into a shared function or module."
                                .to_string(),
                        ),
                        references: vec![],
                        cwe: META.cwe_vec(),
                        owasp: META.owasp_vec(),
                    });
                } else {
                    seen.insert(
                        h,
                        Origin {
                            path: source.path.clone(),
                            line: start_line,
                        },
                    );
                }
            }
        }

        findings.sort();
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Config, Language, SourceFile};
    use std::path::PathBuf;
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

    // ── helper tests ──────────────────────────────────────────────────────────

    #[test]
    fn normalise_line_strips_blank() {
        assert_eq!(normalise_line(""), None);
        assert_eq!(normalise_line("   "), None);
    }

    #[test]
    fn normalise_line_strips_comments() {
        assert_eq!(normalise_line("// comment"), None);
        assert_eq!(normalise_line("# comment"), None);
        assert_eq!(normalise_line("* doc"), None);
    }

    #[test]
    fn normalise_line_keeps_code() {
        assert_eq!(normalise_line("  let x = 1;"), Some("let x = 1;"));
    }

    #[test]
    fn same_content_same_hash() {
        let a = hash_window(&["a", "b", "c"]);
        let b = hash_window(&["a", "b", "c"]);
        assert_eq!(a, b);
    }

    #[test]
    fn different_content_different_hash() {
        let a = hash_window(&["a", "b", "c"]);
        let b = hash_window(&["a", "b", "d"]);
        assert_ne!(a, b);
    }

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_duplicate_code_positive() {
        let a = include_str!("../../../fixtures/python/duplicate_code/a.py");
        let b = include_str!("../../../fixtures/python/duplicate_code/b.py");
        let files = vec![
            python_parse("fixtures/python/duplicate_code/a.py", a),
            python_parse("fixtures/python/duplicate_code/b.py", b),
        ];
        let root = PathBuf::from("fixtures/python/duplicate_code");
        let project = Project::new(root, files);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = DuplicateCodeAnalyzer.analyze_project(&ctx, &project);
        assert!(
            !findings.is_empty(),
            "expected ≥1 CPLX003 finding for duplicate_code Python fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
        assert!(
            findings.iter().all(|f| f.suggestion.is_some()),
            "all findings should have a suggestion"
        );
    }

    // ── Python negative (healthy single file) ─────────────────────────────────

    #[test]
    fn python_healthy_no_duplicates() {
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let files = vec![python_parse("fixtures/python/healthy/main.py", source)];
        let root = PathBuf::from("fixtures/python/healthy");
        let project = Project::new(root, files);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = DuplicateCodeAnalyzer.analyze_project(&ctx, &project);
        assert!(
            findings.is_empty(),
            "expected 0 CPLX003 findings for single healthy file, got {findings:#?}"
        );
    }

    // ── Rust positive ─────────────────────────────────────────────────────────

    #[test]
    fn rust_duplicate_code_positive() {
        let a = include_str!("../../../fixtures/rust/duplicate_code/a.rs");
        let b = include_str!("../../../fixtures/rust/duplicate_code/b.rs");
        let files = vec![
            rust_parse("fixtures/rust/duplicate_code/a.rs", a),
            rust_parse("fixtures/rust/duplicate_code/b.rs", b),
        ];
        let root = PathBuf::from("fixtures/rust/duplicate_code");
        let project = Project::new(root, files);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = DuplicateCodeAnalyzer.analyze_project(&ctx, &project);
        assert!(
            !findings.is_empty(),
            "expected ≥1 CPLX003 finding for duplicate_code Rust fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_duplicate_code_positive() {
        let a = include_str!("../../../fixtures/js/duplicate_code/a.ts");
        let b = include_str!("../../../fixtures/js/duplicate_code/b.ts");
        let files = vec![
            js_parse("fixtures/js/duplicate_code/a.ts", a),
            js_parse("fixtures/js/duplicate_code/b.ts", b),
        ];
        let root = PathBuf::from("fixtures/js/duplicate_code");
        let project = Project::new(root, files);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = DuplicateCodeAnalyzer.analyze_project(&ctx, &project);
        assert!(
            !findings.is_empty(),
            "expected ≥1 CPLX003 finding for duplicate_code JS fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── threshold config ──────────────────────────────────────────────────────

    #[test]
    fn high_threshold_suppresses_findings() {
        // With a very high threshold, no window will match.
        let a = include_str!("../../../fixtures/python/duplicate_code/a.py");
        let b = include_str!("../../../fixtures/python/duplicate_code/b.py");
        let files = vec![
            python_parse("fixtures/python/duplicate_code/a.py", a),
            python_parse("fixtures/python/duplicate_code/b.py", b),
        ];
        let root = PathBuf::from("fixtures/python/duplicate_code");
        let project = Project::new(root, files);
        let config = Config::from_toml_str("[rules.\"CPLX003-duplicate-code\"]\nthreshold = 9999")
            .expect("valid toml");
        let ctx = make_ctx(&config);
        let findings = DuplicateCodeAnalyzer.analyze_project(&ctx, &project);
        assert!(
            findings.is_empty(),
            "threshold=9999 should suppress findings, got {findings:#?}"
        );
    }
}
