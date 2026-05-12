//! `CargoClippyAnalyzer` — wraps `cargo clippy` as an external-tool adapter.
//!
//! This analyzer implements [`zuit_core::Analyzer::analyze_project`] (not
//! `analyze_file`).  When called:
//!
//! 1. Searches `$PATH` for the `cargo` binary (via the `which` crate).
//!    If missing, emits a single [`Severity::Info`] finding with rule
//!    `RS/cargo-clippy-missing` and returns.
//! 2. Spawns `cargo clippy --message-format=json --quiet` from the project root.
//!    Captures stdout with a 60-second timeout and 32 MiB cap.  A non-zero
//!    exit code is normal when warnings exist; only a spawn failure is treated
//!    as an error.
//! 3. Parses the NDJSON output with [`parse_cargo_clippy_output`].
//! 4. Returns the resulting [`Finding`]s.
//!
//! # Operational rule IDs
//!
//! - `RS/cargo-clippy-missing` — `cargo` not found on `$PATH`
//! - `RS/cargo-clippy-timeout` — process exceeded 60-second timeout
//! - `RS/cargo-clippy-output-too-large` — stdout exceeded 32 MiB cap
//! - `RS/cargo-clippy-spawn-failed` — OS-level spawn failure or missing workspace
//!
//! # Finding rule ID format
//!
//! `RS/clippy/<lint_short_name>` (with `clippy::` prefix stripped), e.g.
//! `RS/clippy/integer_arithmetic`.

use std::path::Path;

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};
use serde::Deserialize;

use zuit_core::external::{DEFAULT_MAX_STDOUT_BYTES, DEFAULT_TIMEOUT_SECS, Outcome, run_with_limits};

// ── Rule IDs ──────────────────────────────────────────────────────────────────

/// Rule ID emitted when `cargo` is absent from `$PATH`.
pub const RULE_MISSING: &str = "RS/cargo-clippy-missing";
/// Rule ID emitted when `cargo clippy` exceeds the timeout.
const RULE_TIMEOUT: &str = "RS/cargo-clippy-timeout";
/// Rule ID emitted when `cargo clippy` stdout exceeds the cap.
const RULE_OUTPUT_TOO_LARGE: &str = "RS/cargo-clippy-output-too-large";
/// Rule ID emitted when the OS cannot spawn `cargo clippy` or no workspace exists.
const RULE_SPAWN_FAILED: &str = "RS/cargo-clippy-spawn-failed";

/// Prefix for lint-specific rule IDs.
const CLIPPY_RULE_PREFIX: &str = "RS/clippy/";

// ── JSON wire types (NDJSON — one object per line) ────────────────────────────

/// A single JSON object emitted on one line by `cargo clippy --message-format=json`.
///
/// Cargo emits several `reason` kinds; this adapter only processes
/// `"compiler-message"`.
#[derive(Debug, Deserialize)]
struct CompilerMsg {
    /// Reason tag. We only care about `"compiler-message"`.
    #[serde(default)]
    reason: String,
    /// The inner compiler message (present when `reason == "compiler-message"`).
    #[serde(default)]
    message: Option<ClippyMessage>,
}

/// Inner compiler diagnostic message.
#[derive(Debug, Deserialize)]
struct ClippyMessage {
    /// Diagnostic code (contains the lint name for clippy lints).
    #[serde(default)]
    code: Option<ClippyCode>,
    /// Severity level: `"error"`, `"warning"`, `"note"`, `"help"`.
    #[serde(default)]
    level: String,
    /// Human-readable description.
    #[serde(default)]
    message: String,
    /// Source spans associated with this diagnostic.
    #[serde(default)]
    spans: Vec<ClippySpan>,
}

/// Lint code information.
#[derive(Debug, Deserialize)]
struct ClippyCode {
    /// The lint identifier, e.g. `"clippy::integer_arithmetic"`.
    #[serde(default)]
    code: String,
}

/// A single source span within a diagnostic.
#[derive(Debug, Deserialize)]
struct ClippySpan {
    /// Relative or absolute file path.
    #[serde(default)]
    file_name: String,
    /// One-indexed start line.
    #[serde(default)]
    line_start: u32,
    /// One-indexed start column.
    #[serde(default)]
    column_start: u32,
    /// Whether this is the primary span for the diagnostic.
    #[serde(default)]
    is_primary: bool,
}

// ── Severity mapping ──────────────────────────────────────────────────────────

/// Maps a clippy diagnostic level string to a zuit [`Severity`].
///
/// | Level | Severity |
/// |---|---|
/// | `"error"` | High |
/// | `"warning"` | Medium |
/// | `"note"` | Low |
/// | `"help"` | Low |
/// | anything else | Medium |
#[must_use]
fn map_clippy_severity(level: &str) -> Severity {
    match level {
        "error" => Severity::High,
        "note" | "help" => Severity::Low,
        // "warning" and unknown values default to Medium.
        _ => Severity::Medium,
    }
}

// ── Dimension mapping ─────────────────────────────────────────────────────────

/// Maps a clippy lint short name (without `clippy::` prefix) to a zuit [`Dimension`].
///
/// | Pattern | Dimension |
/// |---|---|
/// | contains `arithmetic` / `integer` / `overflow` / `panic` / `unwrap` | Security |
/// | contains `complexity` / `cognitive` / `cyclomatic` | Complexity |
/// | contains `doc` / `missing_doc` | Documentation |
/// | else | Maintainability |
#[must_use]
pub fn map_clippy_dimension(lint: &str) -> Dimension {
    if lint.contains("arithmetic")
        || lint.contains("integer")
        || lint.contains("overflow")
        || lint.contains("panic")
        || lint.contains("unwrap")
    {
        return Dimension::Security;
    }
    if lint.contains("complexity") || lint.contains("cognitive") || lint.contains("cyclomatic") {
        return Dimension::Complexity;
    }
    if lint.contains("doc") || lint.contains("missing_doc") {
        return Dimension::Documentation;
    }
    Dimension::Maintainability
}

// ── CWE mapping ───────────────────────────────────────────────────────────────

/// Maps a clippy lint short name to zero or more CWE identifiers.
///
/// | Lint pattern | CWE |
/// |---|---|
/// | `integer_arithmetic` / `arithmetic_side_effects` | CWE-190 |
/// | `unwrap_used` / `panic` / `expect_used` | CWE-248 |
/// | `unsafe_*` | CWE-758 |
/// | else | (empty) |
#[must_use]
pub fn map_clippy_cwe(lint: &str) -> &'static [&'static str] {
    if lint == "integer_arithmetic" || lint == "arithmetic_side_effects" {
        return &["CWE-190"];
    }
    if lint == "unwrap_used" || lint == "panic" || lint == "expect_used" {
        return &["CWE-248"];
    }
    if lint.starts_with("unsafe_") {
        return &["CWE-758"];
    }
    &[]
}

// ── Helper: operational finding at project root ───────────────────────────────

/// Builds an operational [`Finding`] pointing at the project root.
#[must_use]
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
        analyzer: AnalyzerId::new("CargoClippyAnalyzer"),
        dimension: Dimension::Maintainability,
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

// ── Core parsing function (pure — no I/O) ────────────────────────────────────

/// Parses `cargo clippy --message-format=json` NDJSON output and returns a
/// [`Vec<Finding>`].
///
/// This function is **pure** — it does not touch the filesystem or spawn any
/// processes.  It is the primary unit-test target for this module.
///
/// The output is NDJSON (newline-delimited JSON): one JSON object per line.
/// Lines that don't parse as a valid `CompilerMsg` are silently skipped, as
/// cargo emits other JSON kinds (`compiler-artifact`, `build-finished`, etc.).
///
/// Only `reason == "compiler-message"` objects with a `code.code` starting with
/// `"clippy::"` are converted to findings.
///
/// # Errors
///
/// Returns `Ok(vec![])` for fully empty or non-JSON input (NDJSON tolerates
/// partial failures per line). Returns `Err` only when the overall approach
/// is fundamentally broken — in practice this function always returns `Ok`.
pub fn parse_cargo_clippy_output(
    stdout: &str,
    project_root: &Path,
    project: &Project,
) -> Result<Vec<Finding>, crate::error::RustError> {
    let mut findings = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Silently skip lines that don't parse as CompilerMsg.
        let msg: CompilerMsg = match serde_json::from_str(line) {
            Ok(m) => m,
            Err(_) => continue,
        };

        // Only process compiler-message entries.
        if msg.reason != "compiler-message" {
            continue;
        }

        let Some(inner) = msg.message else {
            continue;
        };

        // Only clippy lints.
        let Some(code_obj) = inner.code else {
            continue;
        };
        if !code_obj.code.starts_with("clippy::") {
            continue;
        }

        // Strip "clippy::" prefix to get the short lint name.
        let lint_short = code_obj
            .code
            .strip_prefix("clippy::")
            .unwrap_or(&code_obj.code);

        let rule_id = format!("{CLIPPY_RULE_PREFIX}{lint_short}");

        // Find the primary span (first primary, fallback to first).
        let span_obj = inner
            .spans
            .iter()
            .find(|s| s.is_primary)
            .or_else(|| inner.spans.first());

        let Some(span_obj) = span_obj else {
            // No span — skip.
            continue;
        };

        let raw_path = Path::new(&span_obj.file_name);
        let file_path = if raw_path.is_absolute() {
            raw_path
                .strip_prefix(project_root)
                .unwrap_or(raw_path)
                .to_path_buf()
        } else {
            raw_path.to_path_buf()
        };

        let severity = map_clippy_severity(&inner.level);
        let dimension = map_clippy_dimension(lint_short);
        let cwe: Vec<String> = map_clippy_cwe(lint_short)
            .iter()
            .map(|s| (*s).to_string())
            .collect();

        // Compute span using shared helper.
        let (byte_span, start_lc, end_lc) = zuit_core::external::compute_span(
            project,
            project_root,
            &file_path,
            &span_obj.file_name,
            span_obj.line_start,
            span_obj.column_start,
        );

        findings.push(Finding {
            analyzer: AnalyzerId::new("CargoClippyAnalyzer"),
            dimension,
            rule_id,
            severity,
            message: format!("{} (clippy::{})", inner.message, lint_short),
            location: Location {
                file: file_path,
                span: byte_span,
                start: start_lc,
                end: end_lc,
            },
            suggestion: None,
            references: vec![format!(
                "https://rust-lang.github.io/rust-clippy/master/index.html#{lint_short}"
            )],
            cwe,
            owasp: vec![],
        });
    }

    Ok(findings)
}

// ── Analyzer impl ─────────────────────────────────────────────────────────────

/// Integrates `cargo clippy` into the zuit analysis pipeline.
///
/// Overrides [`zuit_core::Analyzer::analyze_project`] rather than
/// `analyze_file`, because `cargo clippy` operates on the whole workspace.
///
/// # Binary detection
///
/// If `cargo` is not found on `$PATH`, a single [`Severity::Info`] finding
/// with rule `RS/cargo-clippy-missing` is returned.
///
/// # Workspace requirement
///
/// `cargo clippy` requires a `Cargo.toml` in the project root.  If absent, a
/// `RS/cargo-clippy-spawn-failed` Info finding is emitted and the tool is not
/// spawned.
///
/// # Non-zero exit codes
///
/// `cargo clippy` exits non-zero when warnings exist.  This is normal.
pub struct CargoClippyAnalyzer;

impl zuit_core::Analyzer for CargoClippyAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new("CargoClippyAnalyzer")
    }

    fn dimension(&self) -> Dimension {
        Dimension::Maintainability
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        &[
            RuleMeta {
                id: RULE_MISSING,
                default_severity: Severity::Info,
                doc_path: "docs/rules/RS-cargo-clippy.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_TIMEOUT,
                default_severity: Severity::Info,
                doc_path: "docs/rules/RS-cargo-clippy.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_OUTPUT_TOO_LARGE,
                default_severity: Severity::Info,
                doc_path: "docs/rules/RS-cargo-clippy.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_SPAWN_FAILED,
                default_severity: Severity::Info,
                doc_path: "docs/rules/RS-cargo-clippy.md",
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
        // All work is done at project level.
        Vec::new()
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        // 1. Early-exit if no Rust files and no Cargo.toml.
        let has_rust_files = project
            .files
            .iter()
            .any(|pf| pf.language() == zuit_core::LanguageId("rust"));
        let has_cargo_toml = project.root.join("Cargo.toml").exists();
        if !has_rust_files && !has_cargo_toml {
            return Vec::new();
        }

        let mut findings: Vec<Finding> = Vec::new();

        // 2. Check for `cargo` on PATH.
        if which::which("cargo").is_err() {
            findings.push(operational_finding(
                project,
                RULE_MISSING,
                Severity::Info,
                "cargo not found on PATH; install Rust to enable cargo clippy".to_string(),
                Some("Install Rust: https://www.rust-lang.org/tools/install".to_string()),
                vec!["https://doc.rust-lang.org/clippy/".to_string()],
            ));
            return findings;
        }

        // 3. Require a Cargo.toml (workspace root).
        if !project.root.join("Cargo.toml").exists() {
            findings.push(operational_finding(
                project,
                RULE_SPAWN_FAILED,
                Severity::Info,
                "cargo clippy requires a Cargo workspace; no Cargo.toml found at project root"
                    .to_string(),
                None,
                vec![],
            ));
            return findings;
        }

        // 4. Spawn `cargo clippy --message-format=json --quiet`.
        let mut clippy_findings = match run_with_limits(
            "cargo",
            &["clippy", "--message-format=json", "--quiet"],
            &project.root,
            DEFAULT_MAX_STDOUT_BYTES,
            DEFAULT_TIMEOUT_SECS,
        ) {
            Outcome::Ok(stdout) => {
                if stdout.is_empty() {
                    Vec::new()
                } else {
                    let stdout_str = String::from_utf8_lossy(&stdout);
                    match parse_cargo_clippy_output(&stdout_str, &project.root, project) {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            tracing::warn!("failed to parse cargo clippy output: {e}; skipping");
                            Vec::new()
                        }
                    }
                }
            }
            Outcome::Timeout => {
                findings.push(operational_finding(
                    project,
                    RULE_TIMEOUT,
                    Severity::Info,
                    format!("cargo clippy timed out after {DEFAULT_TIMEOUT_SECS} seconds"),
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
                    format!("cargo clippy output exceeded {mib_cap} MiB cap"),
                    None,
                    vec![],
                ));
                Vec::new()
            }
            Outcome::SpawnFailed(e) => {
                tracing::warn!("cargo clippy spawn failed: {e}");
                findings.push(operational_finding(
                    project,
                    RULE_SPAWN_FAILED,
                    Severity::Info,
                    format!("cargo clippy failed to spawn: {e}"),
                    None,
                    vec![],
                ));
                Vec::new()
            }
        };

        findings.append(&mut clippy_findings);
        findings
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use zuit_core::{Dimension, Project, Severity};

    use super::*;

    fn empty_project(root: impl Into<PathBuf>) -> Project {
        Project::new(root.into(), vec![])
    }

    // ── NDJSON fixtures ───────────────────────────────────────────────────────

    fn three_clippy_msgs() -> String {
        let m1 = r#"{"reason":"compiler-message","message":{"code":{"code":"clippy::integer_arithmetic"},"level":"warning","message":"integer arithmetic","spans":[{"file_name":"src/lib.rs","line_start":10,"column_start":5,"is_primary":true}]}}"#;
        let m2 = r#"{"reason":"compiler-message","message":{"code":{"code":"clippy::unwrap_used"},"level":"warning","message":"called unwrap","spans":[{"file_name":"src/lib.rs","line_start":20,"column_start":9,"is_primary":true}]}}"#;
        let m3 = r#"{"reason":"compiler-message","message":{"code":{"code":"clippy::cognitive_complexity"},"level":"warning","message":"cognitive complexity","spans":[{"file_name":"src/lib.rs","line_start":30,"column_start":1,"is_primary":true}]}}"#;
        format!("{m1}\n{m2}\n{m3}")
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// 1. Three clippy messages produce three findings with RS/clippy/ prefix.
    #[test]
    fn parse_cargo_clippy_happy_three_findings() {
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_cargo_clippy_output(&three_clippy_msgs(), &root, &project)
            .expect("parse must succeed");
        assert_eq!(findings.len(), 3, "expected 3 findings");
        for f in &findings {
            assert!(
                f.rule_id.starts_with("RS/clippy/"),
                "rule_id must start with RS/clippy/, got: {}",
                f.rule_id
            );
        }
    }

    /// 2. A non-clippy code (`dead_code`) produces no findings.
    #[test]
    fn parse_cargo_clippy_skips_non_clippy_codes() {
        let line = r#"{"reason":"compiler-message","message":{"code":{"code":"dead_code"},"level":"warning","message":"unused","spans":[{"file_name":"src/lib.rs","line_start":1,"column_start":1,"is_primary":true}]}}"#;
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings =
            parse_cargo_clippy_output(line, &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 0, "non-clippy code must be skipped");
    }

    /// 3. Lines with `reason` other than `compiler-message` are silently skipped.
    #[test]
    fn parse_cargo_clippy_skips_non_compiler_message_lines() {
        let line = r#"{"reason":"build-finished","success":true}"#;
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings =
            parse_cargo_clippy_output(line, &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 0, "non-compiler-message must be skipped");
    }

    /// 4. `clippy::integer_arithmetic` maps to CWE-190.
    #[test]
    fn cargo_clippy_integer_arithmetic_maps_to_cwe_190() {
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_cargo_clippy_output(&three_clippy_msgs(), &root, &project)
            .expect("parse must succeed");
        let f = findings
            .iter()
            .find(|f| f.rule_id == "RS/clippy/integer_arithmetic")
            .expect("integer_arithmetic finding must be present");
        assert_eq!(f.cwe, vec!["CWE-190".to_string()]);
    }

    /// 5. `integer_arithmetic` has `Dimension::Security`.
    #[test]
    fn parse_cargo_clippy_dimension_security_for_arithmetic() {
        assert_eq!(
            map_clippy_dimension("integer_arithmetic"),
            Dimension::Security
        );
    }

    /// 6. `cognitive_complexity` has `Dimension::Complexity`.
    #[test]
    fn parse_cargo_clippy_dimension_complexity_for_cognitive() {
        assert_eq!(
            map_clippy_dimension("cognitive_complexity"),
            Dimension::Complexity
        );
    }

    /// 7. Completely empty stdout returns Ok([]).
    #[test]
    fn parse_cargo_clippy_empty_stdout_returns_ok_empty() {
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_cargo_clippy_output("", &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 0, "empty stdout must produce 0 findings");
    }

    /// Severity: error → High.
    #[test]
    fn map_clippy_severity_error_is_high() {
        assert_eq!(map_clippy_severity("error"), Severity::High);
    }

    /// Severity: warning → Medium.
    #[test]
    fn map_clippy_severity_warning_is_medium() {
        assert_eq!(map_clippy_severity("warning"), Severity::Medium);
    }

    /// Severity: note → Low.
    #[test]
    fn map_clippy_severity_note_is_low() {
        assert_eq!(map_clippy_severity("note"), Severity::Low);
    }

    /// Severity: help → Low.
    #[test]
    fn map_clippy_severity_help_is_low() {
        assert_eq!(map_clippy_severity("help"), Severity::Low);
    }

    /// CWE: `unwrap_used` → CWE-248.
    #[test]
    fn map_clippy_cwe_unwrap_used_is_cwe_248() {
        assert_eq!(map_clippy_cwe("unwrap_used"), &["CWE-248"]);
    }

    /// CWE: `unsafe_removed_from_name` (starts with `unsafe_`) → CWE-758.
    #[test]
    fn map_clippy_cwe_unsafe_prefix_is_cwe_758() {
        assert_eq!(map_clippy_cwe("unsafe_removed_from_name"), &["CWE-758"]);
    }

    /// CWE: unknown lint → empty.
    #[test]
    fn map_clippy_cwe_unknown_is_empty() {
        assert!(map_clippy_cwe("some_other_lint").is_empty());
    }

    /// Dimension: doc-related lint → Documentation.
    #[test]
    fn map_clippy_dimension_doc_is_documentation() {
        assert_eq!(
            map_clippy_dimension("missing_docs_in_private_items"),
            Dimension::Documentation
        );
    }

    /// Bonus: missing-binary finding is well-formed.
    #[test]
    fn missing_binary_finding_is_well_formed() {
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let f = operational_finding(
            &project,
            RULE_MISSING,
            Severity::Info,
            "cargo not found".to_string(),
            None,
            vec![],
        );
        assert_eq!(f.rule_id, RULE_MISSING);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.dimension, Dimension::Maintainability);
    }
}
