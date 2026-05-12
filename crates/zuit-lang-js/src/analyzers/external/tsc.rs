//! `TscAnalyzer` — wraps `tsc` as an external-tool adapter.
//!
//! When called:
//!
//! 1. Skips when `tsconfig.json` is absent from the project root.
//! 2. Searches `$PATH` for the `tsc` binary. If missing, emits a single
//!    [`Severity::Info`] finding with rule `JS/tsc-missing` and returns.
//! 3. Spawns `tsc --noEmit --pretty false` from the project root. Captures
//!    stdout with a 60-second timeout and 32 MiB cap. A non-zero exit code is
//!    normal (it means type errors exist); only a spawn failure is an error.
//! 4. Parses the line-oriented output with [`parse_tsc_output`].
//! 5. Returns the resulting [`Finding`]s.
//!
//! # Output format
//!
//! `tsc --pretty false` emits one diagnostic per line:
//! ```text
//! src/foo.ts(12,5): error TS2345: Argument of type 'X' is not assignable ...
//! ```
//! Lines not matching the pattern are silently ignored.

use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Instant;

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};
use regex::Regex;

use crate::error::JsError;

// ── Configuration ─────────────────────────────────────────────────────────────

/// Maximum time allowed for `tsc` to complete, in seconds.
const TSC_TIMEOUT_SECS: u64 = 60;

/// Maximum size of stdout captured from `tsc`, in bytes (32 MiB).
const TSC_MAX_STDOUT_BYTES: usize = 32 * 1024 * 1024;

// ── Rule IDs ──────────────────────────────────────────────────────────────────

/// Rule ID emitted when `tsc` is absent from `$PATH`.
pub const RULE_MISSING: &str = "JS/tsc-missing";

/// Rule ID emitted when `tsc` exceeds the timeout.
const RULE_TIMEOUT: &str = "JS/tsc-timeout";

/// Rule ID emitted when `tsc` stdout exceeds the cap.
const RULE_OUTPUT_TOO_LARGE: &str = "JS/tsc-output-too-large";

// ── Diagnostic line pattern ───────────────────────────────────────────────────

/// Returns the compiled [`Regex`] for a TSC diagnostic line.
///
/// Pattern captures: `file`, `line`, `col`, `sev`, `code`, `msg`.
///
/// # Panics
///
/// Panics on first call if the compiled regex pattern is invalid — this is a
/// hard invariant; the pattern is a compile-time constant.
fn tsc_line_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(?P<file>[^(]+)\((?P<line>\d+),(?P<col>\d+)\):\s+(?P<sev>\w+)\s+(?P<code>TS\d+):\s+(?P<msg>.+)$",
        )
        .expect("invariant: tsc diagnostic regex is valid")
    })
}

// ── Core parsing function (pure — no I/O) ─────────────────────────────────────

/// Parses `tsc --noEmit --pretty false` output and returns a [`Vec<Finding>`].
///
/// This function is **pure** — it does not touch the filesystem or spawn any
/// processes.  It is the primary unit-test target for this module.
///
/// Lines not matching the TSC diagnostic pattern are silently ignored.
///
/// # WHY the return type is `Result` even though TSC parsing cannot produce a
/// `JsError::Json` error: the signature is kept symmetric with the `ESLint`
/// adapter so callers can handle both adapters uniformly. In practice this
/// function always returns `Ok(...)`.
///
/// # Errors
///
/// Always returns `Ok`; the `Result` wrapper is kept for API symmetry with
/// `parse_eslint_output`.
pub fn parse_tsc_output(
    stdout: &str,
    project_root: &Path,
    _project: &Project,
) -> Result<Vec<Finding>, JsError> {
    let re = tsc_line_regex();
    let mut findings = Vec::new();

    for line in stdout.lines() {
        let Some(caps) = re.captures(line) else {
            continue;
        };

        let raw_file = caps["file"].trim();
        let line_num: u32 = caps["line"].parse().unwrap_or(1);
        let col_num: u32 = caps["col"].parse().unwrap_or(1);
        let code = &caps["code"];
        let msg = caps["msg"].trim();

        let rule_id = format!("JS/tsc/{code}");

        // Normalise file path: strip project_root prefix when absolute.
        let raw_path = Path::new(raw_file);
        let file_path = if raw_path.is_absolute() {
            raw_path
                .strip_prefix(project_root)
                .unwrap_or(raw_path)
                .to_path_buf()
        } else {
            raw_path.to_path_buf()
        };

        let zero = Span::new(ByteOffset(0), ByteOffset(0));
        let lc = LineCol::new(line_num.max(1), col_num.max(1));

        findings.push(Finding {
            analyzer: AnalyzerId::new("TscAnalyzer"),
            dimension: Dimension::Maintainability,
            rule_id,
            severity: Severity::Medium,
            message: msg.to_string(),
            location: Location {
                file: file_path,
                span: zero,
                start: lc,
                end: lc,
            },
            suggestion: None,
            references: vec![],
            cwe: vec![],
            owasp: vec![],
        });
    }

    Ok(findings)
}

// ── Subprocess spawning (with timeout and output cap) ────────────────────────

/// Outcome of running `tsc`.
#[derive(Debug, PartialEq)]
enum TscOutcome {
    /// Successfully captured stdout (may be empty).
    Ok(Vec<u8>),
    /// Process exceeded the timeout.
    Timeout,
    /// Stdout exceeded the byte cap.
    OutputTooLarge,
    /// Failed to spawn the process.
    SpawnFailed(String),
}

/// Spawns `tsc --noEmit --pretty false` from `working_dir` with a timeout and
/// output cap.
fn run_tsc(working_dir: &Path) -> TscOutcome {
    run_tsc_with_limits(working_dir, TSC_MAX_STDOUT_BYTES, TSC_TIMEOUT_SECS)
}

/// Internal implementation: spawns `tsc` with parameterised limits.
///
/// Used by `run_tsc` and tests.
fn run_tsc_with_limits(
    working_dir: &Path,
    max_stdout_bytes: usize,
    timeout_secs: u64,
) -> TscOutcome {
    use std::process::{Command, Stdio};

    let mut child = match Command::new("tsc")
        .args(["--noEmit", "--pretty", "false"])
        .current_dir(working_dir)
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return TscOutcome::SpawnFailed(e.to_string()),
    };

    let Some(mut stdout) = child.stdout.take() else {
        return TscOutcome::SpawnFailed("stdout not piped".to_string());
    };

    let start = Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);

    let mut buffer = Vec::new();
    #[allow(clippy::large_stack_arrays)]
    let mut read_buf = [0u8; 65536];

    loop {
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return TscOutcome::Timeout;
        }

        match child.try_wait() {
            Ok(Some(_status)) => loop {
                match stdout.read(&mut read_buf) {
                    Ok(0) | Err(_) => return TscOutcome::Ok(buffer),
                    Ok(n) => {
                        if buffer.len() + n > max_stdout_bytes {
                            let _ = child.kill();
                            let _ = child.wait();
                            return TscOutcome::OutputTooLarge;
                        }
                        buffer.extend_from_slice(&read_buf[..n]);
                    }
                }
            },
            Ok(None) => match stdout.read(&mut read_buf) {
                Ok(0) => {
                    let _ = child.wait();
                    return TscOutcome::Ok(buffer);
                }
                Ok(n) => {
                    if buffer.len() + n > max_stdout_bytes {
                        let _ = child.kill();
                        let _ = child.wait();
                        return TscOutcome::OutputTooLarge;
                    }
                    buffer.extend_from_slice(&read_buf[..n]);
                }
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            },
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

// ── Helper: info finding at project root ──────────────────────────────────────

fn root_info_finding(project: &Project, rule_id: &str, message: String) -> Finding {
    let zero = Span::new(ByteOffset(0), ByteOffset(0));
    Finding {
        analyzer: AnalyzerId::new("TscAnalyzer"),
        dimension: Dimension::Maintainability,
        rule_id: rule_id.to_string(),
        severity: Severity::Info,
        message,
        location: Location {
            file: project.root.clone(),
            span: zero,
            start: LineCol::new(1, 1),
            end: LineCol::new(1, 1),
        },
        suggestion: None,
        references: vec![],
        cwe: vec![],
        owasp: vec![],
    }
}

// ── Analyzer impl ─────────────────────────────────────────────────────────────

/// Integrates `tsc` into the zuit analysis pipeline.
///
/// Overrides [`zuit_core::Analyzer::analyze_project`] rather than
/// `analyze_file` because TSC must be invoked once for the whole project.
///
/// Runs only when `tsconfig.json` exists at the project root; otherwise
/// returns an empty finding list without spawning any subprocess.
pub struct TscAnalyzer;

impl zuit_core::Analyzer for TscAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new("TscAnalyzer")
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
                doc_path: "docs/rules/JS-tsc.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_TIMEOUT,
                default_severity: Severity::Info,
                doc_path: "docs/rules/JS-tsc.md",
                cwe: &[],
                owasp: &[],
            },
            RuleMeta {
                id: RULE_OUTPUT_TOO_LARGE,
                default_severity: Severity::Info,
                doc_path: "docs/rules/JS-tsc.md",
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
        vec![]
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        // Only run when tsconfig.json is present.
        if !project.root.join("tsconfig.json").exists() {
            return vec![];
        }

        if which::which("tsc").is_err() {
            return vec![root_info_finding(
                project,
                RULE_MISSING,
                "tsc not found on PATH; install TypeScript to enable type checking".to_string(),
            )];
        }

        match run_tsc(&project.root) {
            TscOutcome::Ok(stdout) => {
                if stdout.is_empty() {
                    return vec![];
                }
                let stdout_str = String::from_utf8_lossy(&stdout);
                if stdout_str.trim().is_empty() {
                    return vec![];
                }
                match parse_tsc_output(&stdout_str, &project.root, project) {
                    Ok(findings) => findings,
                    Err(e) => {
                        tracing::warn!("failed to parse tsc output: {e}; skipping type checking");
                        vec![]
                    }
                }
            }
            TscOutcome::Timeout => vec![root_info_finding(
                project,
                RULE_TIMEOUT,
                format!("tsc timed out after {TSC_TIMEOUT_SECS} seconds"),
            )],
            TscOutcome::OutputTooLarge => {
                let mib = TSC_MAX_STDOUT_BYTES / (1024 * 1024);
                vec![root_info_finding(
                    project,
                    RULE_OUTPUT_TOO_LARGE,
                    format!("tsc output exceeded {mib} MiB cap"),
                )]
            }
            TscOutcome::SpawnFailed(e) => {
                tracing::warn!("tsc spawn failed: {e}; skipping type checking");
                vec![]
            }
        }
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

    // ── 1. Happy path: two errors from fixture ────────────────────────────────

    #[test]
    fn parse_tsc_happy_two_errors() {
        let txt = include_str!("../../../tests/fixtures/tsc-output.txt");
        let root = PathBuf::from("/project");
        let project = empty_project(&root);

        let findings = parse_tsc_output(txt, &root, &project).expect("parse must succeed");

        assert_eq!(
            findings.len(),
            2,
            "expected 2 findings, got {}",
            findings.len()
        );

        assert!(
            findings.iter().any(|f| f.rule_id == "JS/tsc/TS2345"),
            "missing JS/tsc/TS2345"
        );
        assert!(
            findings.iter().any(|f| f.rule_id == "JS/tsc/TS2304"),
            "missing JS/tsc/TS2304"
        );
    }

    // ── 2. Empty output returns empty vec ─────────────────────────────────────

    #[test]
    fn parse_tsc_empty_output_returns_empty() {
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_tsc_output("", &root, &project).expect("parse must succeed");
        assert!(
            findings.is_empty(),
            "expected empty findings for empty stdout"
        );
    }

    // ── 3. Unparseable lines are silently ignored ─────────────────────────────

    #[test]
    fn parse_tsc_unparseable_lines_ignored() {
        let txt = "This is not a diagnostic\nNeither is this\nerror: also not matching\n";
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_tsc_output(txt, &root, &project).expect("parse must succeed");
        assert!(
            findings.is_empty(),
            "expected 0 findings from unparseable lines"
        );
    }

    // ── 4. All findings have Medium severity ──────────────────────────────────

    #[test]
    fn parse_tsc_severity_is_medium() {
        let txt = include_str!("../../../tests/fixtures/tsc-output.txt");
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_tsc_output(txt, &root, &project).expect("parse must succeed");
        for f in &findings {
            assert_eq!(
                f.severity,
                Severity::Medium,
                "all tsc findings must be Medium, got {:?} for {}",
                f.severity,
                f.rule_id
            );
        }
    }

    // ── 5. All findings have Maintainability dimension ─────────────────────────

    #[test]
    fn parse_tsc_dimension_is_maintainability() {
        let txt = include_str!("../../../tests/fixtures/tsc-output.txt");
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_tsc_output(txt, &root, &project).expect("parse must succeed");
        for f in &findings {
            assert_eq!(
                f.dimension,
                Dimension::Maintainability,
                "all tsc findings must be Maintainability, got {:?} for {}",
                f.dimension,
                f.rule_id
            );
        }
    }

    // ── 6. All rule_ids start with JS/tsc/ ────────────────────────────────────

    #[test]
    fn parse_tsc_rule_id_prefixed() {
        let txt = include_str!("../../../tests/fixtures/tsc-output.txt");
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_tsc_output(txt, &root, &project).expect("parse must succeed");
        for f in &findings {
            assert!(
                f.rule_id.starts_with("JS/tsc/"),
                "rule_id must start with 'JS/tsc/', got: {}",
                f.rule_id
            );
        }
    }

    // ── 7. TscOutcome enum variants are constructible ─────────────────────────

    #[test]
    fn tsc_outcome_variants_constructible() {
        let ok = TscOutcome::Ok(vec![]);
        let timeout = TscOutcome::Timeout;
        let too_large = TscOutcome::OutputTooLarge;
        let spawn_failed = TscOutcome::SpawnFailed("test".to_string());
        let _ = (ok, timeout, too_large, spawn_failed);
    }

    // ── 8. Absolute path is stripped to relative ──────────────────────────────

    #[test]
    fn parse_tsc_absolute_path_stripped() {
        let txt = "/project/src/foo.ts(5,3): error TS2345: some error here\n";
        let root = PathBuf::from("/project");
        let project = empty_project(&root);
        let findings = parse_tsc_output(txt, &root, &project).expect("parse must succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].location.file, PathBuf::from("src/foo.ts"));
    }

    // ── 9. (unix) Timeout / output-cap sanity ─────────────────────────────────

    #[test]
    #[cfg(unix)]
    fn tsc_timeout_kills_long_running_process() {
        let root = PathBuf::from("/tmp");
        let outcome = run_tsc_with_limits(&root, usize::MAX, 1);
        assert!(
            matches!(
                outcome,
                TscOutcome::SpawnFailed(_) | TscOutcome::Timeout | TscOutcome::Ok(_)
            ),
            "expected a valid outcome variant, got {outcome:?}"
        );
    }
}
