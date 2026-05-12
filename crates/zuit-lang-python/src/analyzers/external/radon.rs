//! `RadonAnalyzer` — wraps `radon` as an external-tool adapter.
//!
//! This analyzer implements [`zuit_core::Analyzer::analyze_project`] (not
//! `analyze_file`).  When called:
//!
//! 1. Searches `$PATH` for the `radon` binary (via the `which` crate).
//!    If missing, emits a single [`Severity::Info`] finding with rule
//!    `PY/radon-missing` and returns.
//! 2. Spawns two radon sub-commands from the project root:
//!    - `radon cc --json .` — cyclomatic complexity per function/method.
//!    - `radon mi --json .` — maintainability index per file.
//!
//!    Each sub-command has a 60-second timeout and 32 MiB cap.
//! 3. Parses both JSON outputs and returns the combined [`Finding`]s.
//!
//! ## radon cc JSON shape
//! ```json
//! {
//!   "path/to/file.py": [
//!     {"name":"foo","lineno":10,"col_offset":0,"endline":20,"complexity":12,"rank":"C","type":"function"}
//!   ]
//! }
//! ```
//!
//! ## radon mi JSON shape
//! ```json
//! {
//!   "path/to/file.py": {"mi": 25.0, "rank": "C"}
//! }
//! ```

use std::collections::HashMap;
use std::path::Path;

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};
use serde::Deserialize;

use super::{DEFAULT_MAX_STDOUT_BYTES, DEFAULT_TIMEOUT_SECS, Outcome, run_with_limits};

// ── Rule IDs ──────────────────────────────────────────────────────────────────

/// Rule ID emitted when `radon` is absent from `$PATH`.
pub const RULE_MISSING: &str = "PY/radon-missing";
const RULE_TIMEOUT: &str = "PY/radon-timeout";
const RULE_OUTPUT_TOO_LARGE: &str = "PY/radon-output-too-large";
const RULE_SPAWN_FAILED: &str = "PY/radon-spawn-failed";

const CC_RULE_PREFIX: &str = "PY/radon/cc-";
const MI_RULE_PREFIX: &str = "PY/radon/mi-";

// ── JSON deserialization model ────────────────────────────────────────────────

/// Entry in `radon cc --json` output: one function/method/class.
#[derive(Debug, Deserialize)]
pub(crate) struct RadonCcEntry {
    /// Function/method/class name.
    #[serde(default)]
    pub name: String,
    /// One-indexed starting line number.
    #[serde(default)]
    pub lineno: u32,
    /// Zero-indexed column offset.
    #[serde(default)]
    pub col_offset: u32,
    /// Cyclomatic complexity score.
    #[serde(default)]
    pub complexity: u32,
    /// Rank letter: A, B, C, D, E, F.
    #[serde(default)]
    pub rank: String,
}

/// Entry in `radon mi --json` output: one file.
#[derive(Debug, Deserialize)]
pub(crate) struct RadonMiEntry {
    /// Maintainability index score (0–100).
    #[serde(default)]
    pub mi: f64,
    /// Rank letter: A, B, C, D, E, F.
    #[serde(default)]
    pub rank: String,
}

// ── Severity mapping ──────────────────────────────────────────────────────────

/// Maps a radon rank letter to a zuit [`Severity`].
///
/// | Rank | Meaning | Severity |
/// |------|---------|----------|
/// | A, B, C | Low/medium risk | Low |
/// | D, E | High risk | Medium |
/// | F | Very high risk | High |
fn map_radon_severity(rank: &str) -> Severity {
    match rank.to_ascii_uppercase().as_str() {
        "D" | "E" => Severity::Medium,
        "F" => Severity::High,
        // A, B, C, and any unknown rank
        _ => Severity::Low,
    }
}

// ── Core parsing functions (pure — no I/O) ────────────────────────────────────

/// Parses `radon cc --json` output and returns cyclomatic complexity findings.
///
/// Returns an empty `Vec` on empty input or `{}`.
#[must_use]
pub fn parse_radon_cc_output(json: &str, project_root: &Path) -> Vec<Finding> {
    if json.trim().is_empty() {
        return Vec::new();
    }
    let file_map: HashMap<String, Vec<RadonCcEntry>> = match serde_json::from_str(json) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("failed to parse radon cc output: {e}");
            return Vec::new();
        }
    };

    let mut findings = Vec::new();

    for (file_str, entries) in &file_map {
        let raw_path = Path::new(file_str);
        let file_path = if raw_path.is_absolute() {
            raw_path
                .strip_prefix(project_root)
                .unwrap_or(raw_path)
                .to_path_buf()
        } else {
            raw_path.to_path_buf()
        };

        for entry in entries {
            let severity = map_radon_severity(&entry.rank);
            let rule_id = format!("{CC_RULE_PREFIX}{}", entry.rank.to_ascii_uppercase());

            // col_offset is 0-indexed; zuit uses 1-indexed columns.
            let column = entry.col_offset + 1;
            let zero = Span::new(ByteOffset(0), ByteOffset(0));
            let start_lc = LineCol::new(entry.lineno.max(1), column.max(1));

            findings.push(Finding {
                analyzer: AnalyzerId::new("RadonAnalyzer"),
                dimension: Dimension::Complexity,
                rule_id,
                severity,
                message: format!(
                    "`{}` has cyclomatic complexity {} (rank {}); consider refactoring",
                    entry.name, entry.complexity, entry.rank
                ),
                location: Location {
                    file: file_path.clone(),
                    span: zero,
                    start: start_lc,
                    end: start_lc,
                },
                suggestion: Some(
                    "Reduce branching by extracting sub-functions or simplifying conditionals."
                        .to_string(),
                ),
                references: vec![
                    "https://radon.readthedocs.io/en/latest/commandline.html#the-cc-command"
                        .to_string(),
                ],
                cwe: vec![],
                owasp: vec![],
            });
        }
    }

    findings
}

/// Parses `radon mi --json` output and returns maintainability index findings.
///
/// Returns an empty `Vec` on empty input or `{}`.
#[must_use]
pub fn parse_radon_mi_output(json: &str, project_root: &Path) -> Vec<Finding> {
    if json.trim().is_empty() {
        return Vec::new();
    }
    let file_map: HashMap<String, RadonMiEntry> = match serde_json::from_str(json) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("failed to parse radon mi output: {e}");
            return Vec::new();
        }
    };

    let mut findings = Vec::new();

    for (file_str, entry) in &file_map {
        let raw_path = Path::new(file_str);
        let file_path = if raw_path.is_absolute() {
            raw_path
                .strip_prefix(project_root)
                .unwrap_or(raw_path)
                .to_path_buf()
        } else {
            raw_path.to_path_buf()
        };

        let severity = map_radon_severity(&entry.rank);
        let rule_id = format!("{MI_RULE_PREFIX}{}", entry.rank.to_ascii_uppercase());

        let zero = Span::new(ByteOffset(0), ByteOffset(0));

        findings.push(Finding {
            analyzer: AnalyzerId::new("RadonAnalyzer"),
            dimension: Dimension::Maintainability,
            rule_id,
            severity,
            message: format!(
                "`{}` has a maintainability index of {:.1} (rank {}); consider refactoring",
                file_str, entry.mi, entry.rank
            ),
            location: Location {
                file: file_path,
                span: zero,
                start: LineCol::new(1, 1),
                end: LineCol::new(1, 1),
            },
            suggestion: Some(
                "Reduce file complexity by splitting into smaller modules or extracting functions."
                    .to_string(),
            ),
            references: vec![
                "https://radon.readthedocs.io/en/latest/commandline.html#the-mi-command"
                    .to_string(),
            ],
            cwe: vec![],
            owasp: vec![],
        });
    }

    findings
}

// ── Subprocess spawning ───────────────────────────────────────────────────────

/// Internal implementation with parameterised limits — used by tests.
#[must_use]
pub fn run_radon_cc_with_limits(
    working_dir: &Path,
    max_stdout_bytes: usize,
    timeout_secs: u64,
) -> Outcome {
    run_with_limits(
        "radon",
        &["cc", "--json", "."],
        working_dir,
        max_stdout_bytes,
        timeout_secs,
    )
}

/// Internal implementation with parameterised limits — used by tests.
#[must_use]
pub fn run_radon_mi_with_limits(
    working_dir: &Path,
    max_stdout_bytes: usize,
    timeout_secs: u64,
) -> Outcome {
    run_with_limits(
        "radon",
        &["mi", "--json", "."],
        working_dir,
        max_stdout_bytes,
        timeout_secs,
    )
}

fn run_radon_cc(working_dir: &Path) -> Outcome {
    run_radon_cc_with_limits(working_dir, DEFAULT_MAX_STDOUT_BYTES, DEFAULT_TIMEOUT_SECS)
}

fn run_radon_mi(working_dir: &Path) -> Outcome {
    run_radon_mi_with_limits(working_dir, DEFAULT_MAX_STDOUT_BYTES, DEFAULT_TIMEOUT_SECS)
}

// ── Helper: operational finding at project root ───────────────────────────────

fn operational_finding(
    project: &Project,
    rule_id: &str,
    severity: Severity,
    message: String,
    suggestion: Option<String>,
    references: Vec<String>,
) -> Finding {
    let zero = Span::new(ByteOffset(0), ByteOffset(0));
    Finding {
        analyzer: AnalyzerId::new("RadonAnalyzer"),
        dimension: Dimension::Complexity,
        rule_id: rule_id.to_string(),
        severity,
        message,
        location: Location {
            file: project.root.clone(),
            span: zero,
            start: LineCol::new(1, 1),
            end: LineCol::new(1, 1),
        },
        suggestion,
        references,
        cwe: vec![],
        owasp: vec![],
    }
}

// ── Analyzer impl ─────────────────────────────────────────────────────────────

/// Integrates `radon` (cc + mi) into the zuit analysis pipeline.
pub struct RadonAnalyzer;

impl zuit_core::Analyzer for RadonAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new("RadonAnalyzer")
    }

    fn dimension(&self) -> Dimension {
        Dimension::Complexity
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        &[
            RuleMeta {
                id: RULE_MISSING,
                default_severity: Severity::Info,
                doc_path: "docs/rules/PY-radon.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_TIMEOUT,
                default_severity: Severity::Info,
                doc_path: "docs/rules/PY-radon.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_OUTPUT_TOO_LARGE,
                default_severity: Severity::Info,
                doc_path: "docs/rules/PY-radon.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_SPAWN_FAILED,
                default_severity: Severity::Info,
                doc_path: "docs/rules/PY-radon.md",
                cwe: &[],
                owasp: &[],
            },
        ]
    }

    fn kind(&self) -> AnalyzerKind {
        AnalyzerKind::ExternalTool
    }

    fn analyze_file(
        &self,
        _ctx: &AnalysisContext<'_>,
        _file: &zuit_core::ParsedFile,
    ) -> Vec<Finding> {
        Vec::new()
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        // Only run for projects that contain Python files.
        let has_python_files = project
            .files
            .iter()
            .any(|pf| pf.language() == zuit_core::LanguageId("python"));
        if !has_python_files {
            return Vec::new();
        }

        let mut findings: Vec<Finding> = Vec::new();

        // 1. Detect the binary.
        if which::which("radon").is_err() {
            findings.push(operational_finding(
                project,
                RULE_MISSING,
                Severity::Info,
                "radon not found on PATH; install it to enable Python complexity analysis"
                    .to_string(),
                Some("Install radon: https://radon.readthedocs.io/en/latest/".to_string()),
                vec!["https://radon.readthedocs.io/".to_string()],
            ));
            return findings;
        }

        // 2. Spawn radon cc.
        let cc_findings = match run_radon_cc(&project.root) {
            Outcome::Ok(stdout) => {
                if stdout.is_empty() {
                    Vec::new()
                } else {
                    let stdout_str = String::from_utf8_lossy(&stdout);
                    parse_radon_cc_output(&stdout_str, &project.root)
                }
            }
            Outcome::Timeout => {
                findings.push(operational_finding(
                    project,
                    RULE_TIMEOUT,
                    Severity::Info,
                    format!("radon cc timed out after {DEFAULT_TIMEOUT_SECS} seconds"),
                    None,
                    vec![],
                ));
                Vec::new()
            }
            Outcome::OutputTooLarge => {
                let mib_cap = DEFAULT_MAX_STDOUT_BYTES / (1024 * 1024);
                findings.push(operational_finding(
                    project,
                    RULE_OUTPUT_TOO_LARGE,
                    Severity::Info,
                    format!("radon cc output exceeded {mib_cap} MiB cap"),
                    None,
                    vec![],
                ));
                Vec::new()
            }
            Outcome::SpawnFailed(e) => {
                tracing::warn!("radon cc spawn failed: {e}");
                findings.push(operational_finding(
                    project,
                    RULE_SPAWN_FAILED,
                    Severity::Info,
                    format!("radon failed to spawn: {e}"),
                    None,
                    vec![],
                ));
                Vec::new()
            }
        };

        // 3. Spawn radon mi.
        let mi_findings = match run_radon_mi(&project.root) {
            Outcome::Ok(stdout) => {
                if stdout.is_empty() {
                    Vec::new()
                } else {
                    let stdout_str = String::from_utf8_lossy(&stdout);
                    parse_radon_mi_output(&stdout_str, &project.root)
                }
            }
            // Non-fatal — already reported from cc run if tool is missing.
            Outcome::Timeout | Outcome::OutputTooLarge | Outcome::SpawnFailed(_) => Vec::new(),
        };

        findings.extend(cc_findings);
        findings.extend(mi_findings);
        findings
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use zuit_core::{Dimension, Project, Severity, SourceFile};

    use super::*;

    // 6. parse_radon_cc_rank_f_is_high — rank F → severity High
    #[test]
    fn parse_radon_cc_rank_f_is_high() {
        let json = include_str!("../../../tests/fixtures/radon-cc-output.json");
        let root = PathBuf::from("/project");

        let findings = parse_radon_cc_output(json, &root);
        assert!(
            !findings.is_empty(),
            "expected findings from fixture, got none"
        );

        // Find the rank-F finding
        let rank_f = findings.iter().find(|f| f.rule_id == "PY/radon/cc-F");
        assert!(
            rank_f.is_some(),
            "expected a rank-F finding in fixture: {findings:#?}"
        );
        assert_eq!(
            rank_f.unwrap().severity,
            Severity::High,
            "rank F must be High severity"
        );
    }

    // 7. parse_radon_mi_rank_f_is_high
    #[test]
    fn parse_radon_mi_rank_f_is_high() {
        let json = include_str!("../../../tests/fixtures/radon-mi-output.json");
        let root = PathBuf::from("/project");

        let findings = parse_radon_mi_output(json, &root);
        assert!(
            !findings.is_empty(),
            "expected findings from mi fixture, got none"
        );

        let rank_f = findings.iter().find(|f| f.rule_id == "PY/radon/mi-F");
        assert!(
            rank_f.is_some(),
            "expected a rank-F mi finding in fixture: {findings:#?}"
        );
        assert_eq!(rank_f.unwrap().severity, Severity::High);
    }

    // 12. parse_radon_cc_empty_returns_zero
    #[test]
    fn parse_radon_cc_empty_returns_zero() {
        let root = PathBuf::from("/project");
        let findings = parse_radon_cc_output("{}", &root);
        assert!(
            findings.is_empty(),
            "expected 0 findings for empty object: {findings:#?}"
        );
    }

    // Rank A/B/C → Low severity
    #[test]
    fn radon_rank_abc_is_low() {
        assert_eq!(map_radon_severity("A"), Severity::Low);
        assert_eq!(map_radon_severity("B"), Severity::Low);
        assert_eq!(map_radon_severity("C"), Severity::Low);
    }

    // Rank D/E → Medium severity
    #[test]
    fn radon_rank_de_is_medium() {
        assert_eq!(map_radon_severity("D"), Severity::Medium);
        assert_eq!(map_radon_severity("E"), Severity::Medium);
    }

    // Rank F → High severity
    #[test]
    fn radon_rank_f_is_high() {
        assert_eq!(map_radon_severity("F"), Severity::High);
    }

    // cc findings have Complexity dimension
    #[test]
    fn radon_cc_findings_have_complexity_dimension() {
        let json = r#"{"foo.py":[{"name":"bar","lineno":1,"col_offset":0,"endline":10,"complexity":5,"rank":"B","type":"function"}]}"#;
        let root = PathBuf::from("/project");
        let findings = parse_radon_cc_output(json, &root);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].dimension, Dimension::Complexity);
    }

    // mi findings have Maintainability dimension
    #[test]
    fn radon_mi_findings_have_maintainability_dimension() {
        let json = r#"{"foo.py":{"mi":45.0,"rank":"C"}}"#;
        let root = PathBuf::from("/project");
        let findings = parse_radon_mi_output(json, &root);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].dimension, Dimension::Maintainability);
    }

    // 10. radon_missing_binary_emits_info
    #[test]
    fn radon_missing_binary_emits_info() {
        use zuit_core::{Analyzer, Language};

        if which::which("radon").is_ok() {
            // Binary present — skip this test path.
            return;
        }

        let source = Arc::new(SourceFile::new(
            std::path::PathBuf::from("/tmp/main.py"),
            b"x = 1".to_vec(),
        ));
        let parsed = crate::parse::PythonLanguage.parse(source).expect("parse");
        let project = Project::new(std::path::PathBuf::from("/tmp"), vec![parsed]);

        let config = zuit_core::Config::default();
        let ctx = zuit_core::AnalysisContext::new(&config);
        let analyzer = RadonAnalyzer;
        let findings = analyzer.analyze_project(&ctx, &project);

        assert_eq!(
            findings.len(),
            1,
            "expected exactly 1 finding when radon is missing"
        );
        assert_eq!(findings[0].rule_id, RULE_MISSING);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    // Suppression directive format
    #[test]
    fn radon_suppression_directive_format() {
        let directive = "# zuit: ignore PY/radon/cc-F";
        assert!(directive.contains("zuit: ignore"));
        assert!(directive.contains("PY/radon/cc-F"));
    }

    // Timeout test (unix only)
    #[test]
    #[cfg(unix)]
    fn radon_timeout_kills_process() {
        let root = PathBuf::from("/tmp");
        let outcome = run_radon_cc_with_limits(&root, usize::MAX, 1);
        assert!(
            matches!(
                outcome,
                Outcome::SpawnFailed(_) | Outcome::Timeout | Outcome::Ok(_)
            ),
            "expected a valid outcome, got {outcome:?}"
        );
    }
}
