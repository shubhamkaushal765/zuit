//! `TEST001-test-ratio` — flags directories where the ratio of test files to
//! source files is below a configurable threshold.
//!
//! # Algorithm
//!
//! 1. **Classification.** Each parsed file is classified as either `Test` or
//!    `Source`.  A file is classified as `Test` when **any** of the following
//!    hold:
//!    - A path component (directory name) is `tests`, `__tests__`, `spec`, or
//!      matches `test_*`.
//!    - The filename stem (without extension) matches: starts with `test_`,
//!      ends with `_test`, or the full filename contains `.test.` or `.spec.`.
//!    - The file's `SemanticIndex` contains at least one function with
//!      `is_test = true`.
//!
//! 2. **Grouping.** Files are grouped by their immediate parent directory
//!    (the `PathBuf` of `file_path.parent()`).
//!
//! 3. **Threshold check.** For each directory that contains at least
//!    `MIN_SOURCE_FILES` source files (default 3, constant — not configurable in
//!    v1 to avoid noise from single-file utility modules) and whose test-to-source
//!    ratio is strictly below `threshold` percent, one finding is emitted,
//!    anchored at byte 0 of the lexicographically-first source file.
//!
//! # Configuration
//!
//! The threshold is read from `[rules.TEST001-test-ratio] threshold` (a
//! percentage integer; default 10, meaning 10%).  The minimum source-file count
//! (`MIN_SOURCE_FILES = 3`) is intentionally hard-coded for v1 to prevent noise
//! in small directories.
//!
//! # Limitations
//!
//! The `is_test` flag on `FunctionLike` is currently set by the language
//! frontends according to naming conventions (`test_*` in Python/JS, `#[test]`
//! attribute in Rust).  A file full of `jest`-style `it(…)` / `describe(…)`
//! calls will not be flagged as a test file by the function heuristic alone —
//! only by the filename/directory heuristics.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, AnalyzerKind, Dimension, Finding, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Location, Span},
};

/// Rule ID for the test-ratio check.
pub const RULE_ID: &str = "TEST001-test-ratio";

/// Default threshold percentage (10 = 10% = 0.1 ratio).
const DEFAULT_THRESHOLD: u32 = 10;

/// Minimum number of source files in a directory before the ratio is evaluated.
///
/// Directories with fewer than this many source files are skipped to avoid
/// noisy findings in small utility modules.
const MIN_SOURCE_FILES: usize = 3;

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/TEST001-test-ratio.md",
    cwe: &[],
    owasp: &[],
};

// ── file classification ───────────────────────────────────────────────────────

/// Classification of a parsed file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileClass {
    /// The file is (or contains) test code.
    Test,
    /// The file is production source code.
    Source,
}

/// Classifies a single file as `Test` or `Source`.
///
/// The heuristics are applied in order:
/// 1. Directory-name heuristic (path components).
/// 2. Filename heuristic (stem / full filename).
/// 3. `SemanticIndex` `is_test` flag on any function.
#[must_use]
pub fn classify_file(file: &ParsedFile) -> FileClass {
    let path = &file.source().path;

    // 1. Directory-name heuristic.
    if path_has_test_component(path) {
        return FileClass::Test;
    }

    // 2. Filename heuristic.
    if filename_is_test(path) {
        return FileClass::Test;
    }

    // 3. SemanticIndex heuristic.
    if file.index().functions.iter().any(|f| f.is_test) {
        return FileClass::Test;
    }

    FileClass::Source
}

/// Returns `true` if any path component signals a test directory.
fn path_has_test_component(path: &Path) -> bool {
    path.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        matches!(s.as_ref(), "tests" | "__tests__" | "spec") || s.starts_with("test_")
    })
}

/// Returns `true` if the filename (stem or full name) signals a test file.
fn filename_is_test(path: &Path) -> bool {
    let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };

    // Stem-based: `test_foo.py`, `foo_test.rs`
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    if stem.starts_with("test_") || stem.ends_with("_test") {
        return true;
    }

    // Full-filename-based: `foo.test.ts`, `foo.spec.ts`
    filename.contains(".test.") || filename.contains(".spec.")
}

// ── analyzer ──────────────────────────────────────────────────────────────────

/// Analyzer that flags directories with a low test-to-source ratio.
#[derive(Debug, Default)]
pub struct TestRatioAnalyzer;

impl Analyzer for TestRatioAnalyzer {
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

    fn kind(&self) -> AnalyzerKind {
        AnalyzerKind::ProjectLevel
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, _file: &ParsedFile) -> Vec<Finding> {
        // All logic lives in `analyze_project`.
        vec![]
    }

    fn analyze_project(&self, ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        let threshold = ctx.config.rule_threshold(RULE_ID, DEFAULT_THRESHOLD);

        // Group files by parent directory.
        // Each entry: (directory, (source_files, test_count))
        let mut dir_map: HashMap<PathBuf, (Vec<PathBuf>, u32)> = HashMap::new();

        for file in &project.files {
            let path = &file.source().path;
            let dir = path
                .parent()
                .map_or_else(|| PathBuf::from("."), Path::to_path_buf);

            let entry = dir_map.entry(dir).or_insert_with(|| (Vec::new(), 0));

            match classify_file(file) {
                FileClass::Source => entry.0.push(path.clone()),
                FileClass::Test => entry.1 += 1,
            }
        }

        let mut findings: Vec<Finding> = Vec::new();

        // Sort directories for determinism.
        let mut dirs: Vec<PathBuf> = dir_map.keys().cloned().collect();
        dirs.sort();

        for dir in dirs {
            let (mut source_paths, test_count) = dir_map
                .remove(&dir)
                .expect("invariant: dir was just inserted");

            let source_count = source_paths.len();

            // Skip directories with fewer source files than the minimum.
            if source_count < MIN_SOURCE_FILES {
                continue;
            }

            // Compute ratio as integer percentage; avoid division by zero.
            let ratio_pct = (test_count * 100) / u32::try_from(source_count).unwrap_or(u32::MAX);

            if ratio_pct >= threshold {
                continue;
            }

            // Anchor the finding at the lex-first source file in this directory.
            source_paths.sort();
            let anchor_path = source_paths
                .into_iter()
                .next()
                .expect("invariant: source_count >= MIN_SOURCE_FILES > 0");

            let span = Span::new(ByteOffset(0), ByteOffset(0));
            let lc = LineCol::new(1, 1);

            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::TestSmell,
                rule_id: RULE_ID.to_string(),
                severity: Severity::Low,
                message: format!(
                    "directory '{}' has a low test:source ratio ({ratio_pct}%, target ≥{threshold}%)",
                    dir.display()
                ),
                location: Location {
                    file: anchor_path,
                    span,
                    start: lc,
                    end: lc,
                },
                suggestion: Some(format!(
                    "Add tests for code in this directory: current test:source ratio is \
                     {ratio_pct}%, target ≥{threshold}%."
                )),
                references: vec![],
                cwe: META.cwe_vec(),
                owasp: META.owasp_vec(),
            });
        }

        findings.sort();
        findings
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use zuit_core::{Config, Language, SourceFile};

    // ── parse helpers ─────────────────────────────────────────────────────────

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

    fn rust_parse(path: &str, source: &str) -> ParsedFile {
        let src = Arc::new(SourceFile::new(path, source.as_bytes().to_vec()));
        zuit_lang_rust::RustLanguage
            .parse(src)
            .expect("rust parse failed")
    }

    fn make_ctx(config: &Config) -> AnalysisContext<'_> {
        AnalysisContext::new(config)
    }

    // ── classifier unit tests ─────────────────────────────────────────────────

    #[test]
    fn classify_test_directory_component() {
        let f = python_parse("myproject/tests/test_foo.py", "def test_foo(): pass\n");
        assert_eq!(classify_file(&f), FileClass::Test);
    }

    #[test]
    fn classify_test_prefix_filename() {
        let f = python_parse("src/test_utils.py", "x = 1\n");
        assert_eq!(classify_file(&f), FileClass::Test);
    }

    #[test]
    fn classify_test_suffix_filename() {
        let f = rust_parse("src/foo_test.rs", "fn foo() {}\n");
        assert_eq!(classify_file(&f), FileClass::Test);
    }

    #[test]
    fn classify_dottest_filename() {
        let f = js_parse("src/foo.test.ts", "export function x() {}");
        assert_eq!(classify_file(&f), FileClass::Test);
    }

    #[test]
    fn classify_dotspec_filename() {
        let f = js_parse("src/foo.spec.ts", "export function x() {}");
        assert_eq!(classify_file(&f), FileClass::Test);
    }

    #[test]
    fn classify_source_file() {
        let f = python_parse("src/utils.py", "def helper(): pass\n");
        assert_eq!(classify_file(&f), FileClass::Source);
    }

    #[test]
    fn classify_is_test_flag_in_index() {
        // Python function starting with `test_` sets is_test = true in the index.
        let f = python_parse("src/utils.py", "def test_something(): pass\n");
        assert_eq!(classify_file(&f), FileClass::Test);
    }

    #[test]
    fn classify_teststar_directory() {
        let f = python_parse("myproject/__tests__/helpers.py", "x = 1\n");
        assert_eq!(classify_file(&f), FileClass::Test);
    }

    // ── min source files guard ────────────────────────────────────────────────

    #[test]
    fn fewer_than_min_source_files_not_flagged() {
        // Two source files — below MIN_SOURCE_FILES — should not trigger.
        let files = vec![
            python_parse("src/a.py", "def a(): pass\n"),
            python_parse("src/b.py", "def b(): pass\n"),
        ];
        let project = Project::new(PathBuf::from("src"), files);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = TestRatioAnalyzer.analyze_project(&ctx, &project);
        assert!(
            findings.is_empty(),
            "directories with < {MIN_SOURCE_FILES} source files should not be flagged, got {findings:#?}",
        );
    }

    // ── Python positive ───────────────────────────────────────────────────────

    #[test]
    fn python_no_tests_positive() {
        let alpha = include_str!("../../../fixtures/python/no_tests/alpha.py");
        let beta = include_str!("../../../fixtures/python/no_tests/beta.py");
        let gamma = include_str!("../../../fixtures/python/no_tests/gamma.py");
        let delta = include_str!("../../../fixtures/python/no_tests/delta.py");
        let epsilon = include_str!("../../../fixtures/python/no_tests/epsilon.py");

        let files = vec![
            python_parse("fixtures/python/no_tests/alpha.py", alpha),
            python_parse("fixtures/python/no_tests/beta.py", beta),
            python_parse("fixtures/python/no_tests/gamma.py", gamma),
            python_parse("fixtures/python/no_tests/delta.py", delta),
            python_parse("fixtures/python/no_tests/epsilon.py", epsilon),
        ];

        let project = Project::new(PathBuf::from("fixtures/python/no_tests"), files);
        let config = Config::default();
        let ctx = make_ctx(&config);

        let findings = TestRatioAnalyzer.analyze_project(&ctx, &project);
        assert!(
            !findings.is_empty(),
            "expected ≥1 TEST001 finding for Python no_tests fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── JS positive ───────────────────────────────────────────────────────────

    #[test]
    fn js_no_tests_positive() {
        let alpha = include_str!("../../../fixtures/js/no_tests/alpha.ts");
        let beta = include_str!("../../../fixtures/js/no_tests/beta.ts");
        let gamma = include_str!("../../../fixtures/js/no_tests/gamma.ts");
        let delta = include_str!("../../../fixtures/js/no_tests/delta.ts");
        let epsilon = include_str!("../../../fixtures/js/no_tests/epsilon.ts");

        let files = vec![
            js_parse("fixtures/js/no_tests/alpha.ts", alpha),
            js_parse("fixtures/js/no_tests/beta.ts", beta),
            js_parse("fixtures/js/no_tests/gamma.ts", gamma),
            js_parse("fixtures/js/no_tests/delta.ts", delta),
            js_parse("fixtures/js/no_tests/epsilon.ts", epsilon),
        ];

        let project = Project::new(PathBuf::from("fixtures/js/no_tests"), files);
        let config = Config::default();
        let ctx = make_ctx(&config);

        let findings = TestRatioAnalyzer.analyze_project(&ctx, &project);
        assert!(
            !findings.is_empty(),
            "expected ≥1 TEST001 finding for JS no_tests fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Rust positive ─────────────────────────────────────────────────────────

    #[test]
    fn rust_no_tests_positive() {
        // Use only the leaf source files (alpha, beta, gamma, delta, epsilon)
        // — lib.rs is in the parent, so each leaf lives in no_tests/ and
        // forms a directory with 5 source, 0 test files.
        let alpha = include_str!("../../../fixtures/rust/no_tests/alpha.rs");
        let beta = include_str!("../../../fixtures/rust/no_tests/beta.rs");
        let gamma = include_str!("../../../fixtures/rust/no_tests/gamma.rs");
        let delta = include_str!("../../../fixtures/rust/no_tests/delta.rs");
        let epsilon = include_str!("../../../fixtures/rust/no_tests/epsilon.rs");

        let files = vec![
            rust_parse("fixtures/rust/no_tests/alpha.rs", alpha),
            rust_parse("fixtures/rust/no_tests/beta.rs", beta),
            rust_parse("fixtures/rust/no_tests/gamma.rs", gamma),
            rust_parse("fixtures/rust/no_tests/delta.rs", delta),
            rust_parse("fixtures/rust/no_tests/epsilon.rs", epsilon),
        ];

        let project = Project::new(PathBuf::from("fixtures/rust/no_tests"), files);
        let config = Config::default();
        let ctx = make_ctx(&config);

        let findings = TestRatioAnalyzer.analyze_project(&ctx, &project);
        assert!(
            !findings.is_empty(),
            "expected ≥1 TEST001 finding for Rust no_tests fixture"
        );
        assert!(findings.iter().all(|f| f.rule_id == RULE_ID));
    }

    // ── Python negative ───────────────────────────────────────────────────────

    #[test]
    fn python_healthy_below_min_files_no_finding() {
        // The healthy fixture has only one file — below MIN_SOURCE_FILES.
        // No finding should be emitted regardless of tests present.
        let source = include_str!("../../../fixtures/python/healthy/main.py");
        let files = vec![python_parse("fixtures/python/healthy/main.py", source)];

        let project = Project::new(PathBuf::from("fixtures/python/healthy"), files);
        let config = Config::default();
        let ctx = make_ctx(&config);

        let findings = TestRatioAnalyzer.analyze_project(&ctx, &project);
        assert!(
            findings.is_empty(),
            "single-file healthy fixture should not trigger TEST001, got {findings:#?}"
        );
    }

    // ── ratio above threshold is not flagged ──────────────────────────────────

    #[test]
    fn above_threshold_not_flagged() {
        // 3 source + 1 test = 33% — above the default 10% threshold.
        let files = vec![
            python_parse("src/a.py", "def a(): pass\n"),
            python_parse("src/b.py", "def b(): pass\n"),
            python_parse("src/c.py", "def c(): pass\n"),
            python_parse("src/test_d.py", "def test_d(): pass\n"),
        ];
        let project = Project::new(PathBuf::from("src"), files);
        let config = Config::default();
        let ctx = make_ctx(&config);
        let findings = TestRatioAnalyzer.analyze_project(&ctx, &project);
        assert!(
            findings.is_empty(),
            "33% ratio is above threshold, should not be flagged, got {findings:#?}"
        );
    }

    // ── configurable threshold ────────────────────────────────────────────────

    #[test]
    fn high_threshold_flags_directory_that_would_otherwise_pass() {
        // 3 source + 1 test = 33%.  With threshold=50 this should be flagged.
        let toml = "[rules.\"TEST001-test-ratio\"]\nthreshold = 50\n";
        let config = Config::from_toml_str(toml).expect("valid toml");
        let ctx = make_ctx(&config);

        let files = vec![
            python_parse("src/a.py", "def a(): pass\n"),
            python_parse("src/b.py", "def b(): pass\n"),
            python_parse("src/c.py", "def c(): pass\n"),
            python_parse("src/test_d.py", "def test_d(): pass\n"),
        ];
        let project = Project::new(PathBuf::from("src"), files);
        let findings = TestRatioAnalyzer.analyze_project(&ctx, &project);
        assert!(
            !findings.is_empty(),
            "33% ratio should be flagged with threshold=50"
        );
    }
}
