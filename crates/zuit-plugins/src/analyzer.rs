//! [`PluginAnalyzer`] — drives a third-party plugin subprocess and returns [`Finding`]s.
//!
//! # Overview
//!
//! [`PluginAnalyzer`] implements the [`zuit_core::Analyzer`] trait. When the
//! engine calls [`PluginAnalyzer::analyze_project`] it:
//!
//! 1. Resolves the plugin's executable: checks `plugin_dir/command[0]` first,
//!    then falls back to `which::which(command[0])` for PATH resolution.
//! 2. Spawns the subprocess via [`zuit_core::external::run_with_limits`].
//! 3. Dispatches stdout to the appropriate parser
//!    ([`crate::parse_ndjson`] or [`crate::parse_sarif`]).
//! 4. Returns the resulting findings.
//!
//! # Operational rule IDs
//!
//! These rule IDs are emitted directly by [`PluginAnalyzer`] (not by the output
//! parsers) when the subprocess cannot be run or misbehaves. They are **not**
//! registered in [`zuit_core::Analyzer::rules`] (which returns `&[]`), so they
//! will not appear in `zuit list analyzers --explain`. This mirrors how
//! `cargo_clippy` handles its own operational rule IDs.
//!
//! | Rule ID | Severity | Meaning |
//! |---|---|---|
//! | `PLUGIN/<name>-binary-missing` | Info | Executable not found in plugin dir or PATH |
//! | `PLUGIN/<name>-timeout` | Medium | Subprocess exceeded the timeout |
//! | `PLUGIN/<name>-output-too-large` | Medium | Stdout exceeded the byte cap |
//! | `PLUGIN/<name>-spawn-failed` | High | OS-level spawn failure |

use std::path::PathBuf;

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
    external::{DEFAULT_MAX_STDOUT_BYTES, DEFAULT_TIMEOUT_SECS, Outcome, run_with_limits},
    span::{ByteOffset, LineCol, Span},
};

use crate::manifest::{OutputFormat, PluginManifest};
use crate::{parse_ndjson, parse_sarif};

// ── PluginAnalyzer ────────────────────────────────────────────────────────────

/// An [`zuit_core::Analyzer`] that drives a third-party plugin subprocess.
///
/// Construct one via [`PluginAnalyzer::new`]. The analyzer reads the plugin's
/// manifest to determine the command to run, the output format to expect, and
/// the resource limits to enforce.
///
/// # Operational findings
///
/// If the binary cannot be found, times out, produces too much output, or fails
/// to spawn, a single operational finding is emitted in its place. Operational
/// rule IDs (`PLUGIN/<name>-binary-missing`, etc.) are **not** registered in
/// [`rules()`][Self::rules] — they appear in output but not in `list analyzers`.
///
/// # `dimension()` vs per-finding dimension
///
/// [`PluginAnalyzer::dimension`] returns `Dimension::Custom("plugin".into())` as
/// a fallback metadata value only. The actual `Dimension` of each emitted
/// [`Finding`] comes from the per-finding `dimension` field in the plugin's stdout,
/// resolved by the parser (see [`crate::parse_ndjson`] / [`crate::parse_sarif`]).
pub struct PluginAnalyzer {
    /// Validated plugin manifest describing the command, format, and limits.
    manifest: PluginManifest,
    /// Directory where the plugin is installed. Used for local binary resolution.
    plugin_dir: PathBuf,
}

impl PluginAnalyzer {
    /// Creates a new `PluginAnalyzer` from a validated manifest and the directory
    /// that contains the plugin (typically its install directory).
    #[must_use]
    pub fn new(manifest: PluginManifest, plugin_dir: PathBuf) -> Self {
        Self {
            manifest,
            plugin_dir,
        }
    }

    /// Builds the operational finding location used for subprocess errors.
    ///
    /// All fields are set to sentinel values: `file` is a literal `"<plugin>"`
    /// placeholder, `span` is zero-length at offset 0, `start`/`end` are line 1 col 1.
    fn operational_location(plugin_name: &str) -> Location {
        Location {
            file: PathBuf::from(format!("<{plugin_name}>")),
            span: Span::new(ByteOffset(0), ByteOffset(0)),
            start: LineCol::new(1, 1),
            end: LineCol::new(1, 1),
        }
    }

    /// Builds an operational [`Finding`] for subprocess-level errors.
    fn make_operational(
        plugin_name: &str,
        rule_id: String,
        severity: Severity,
        message: String,
    ) -> Finding {
        Finding {
            analyzer: AnalyzerId::new(format!("plugin/{plugin_name}")),
            dimension: Dimension::Custom("plugin".into()),
            rule_id,
            severity,
            message,
            location: Self::operational_location(plugin_name),
            suggestion: None,
            references: vec![],
            cwe: vec![],
            owasp: vec![],
        }
    }
}

impl zuit_core::Analyzer for PluginAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(format!("plugin/{}", self.manifest.name))
    }

    /// Returns `Dimension::Custom("plugin")` as a metadata-level fallback.
    ///
    /// The actual dimension of each emitted finding is set by the output parser
    /// from the per-finding `dimension` field in the plugin's stdout.
    fn dimension(&self) -> Dimension {
        Dimension::Custom("plugin".into())
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    /// Returns an empty slice.
    ///
    /// Operational rule IDs (`PLUGIN/<name>-binary-missing`, etc.) are emitted
    /// but unregistered — they cannot be queried via `zuit list analyzers --explain`.
    /// This matches the pattern used by `CargoClippyAnalyzer`.
    fn rules(&self) -> &[RuleMeta] {
        &[]
    }

    fn kind(&self) -> AnalyzerKind {
        AnalyzerKind::ExternalTool
    }

    /// No-op: all work happens in [`Self::analyze_project`].
    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, _file: &ParsedFile) -> Vec<Finding> {
        Vec::new()
    }

    /// Resolves, spawns, and parses the plugin subprocess.
    ///
    /// Steps:
    /// 1. Resolves `command[0]` — checks `plugin_dir/command[0]` first, then PATH.
    ///    If not found, emits `PLUGIN/<name>-binary-missing` (Info) and returns.
    /// 2. Builds full argv: `[<resolved>, ...command[1..], "--project-root", <root>, "--output-format", <fmt>]`.
    /// 3. Calls [`run_with_limits`] with the manifest's timeout and byte cap.
    /// 4. Dispatches the `Outcome` to the appropriate parser or emits an operational finding.
    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        let name = &self.manifest.name;
        let command = &self.manifest.command;

        // Step 1: Resolve the executable.
        let argv0 = &command[0];
        let candidate = self.plugin_dir.join(argv0);
        let resolved = if candidate.exists() && candidate.is_file() {
            candidate
        } else {
            match which::which(argv0) {
                Ok(p) => p,
                Err(_) => {
                    return vec![Self::make_operational(
                        name,
                        format!("PLUGIN/{name}-binary-missing"),
                        Severity::Info,
                        format!(
                            "plugin binary {argv0:?} not found in plugin directory or PATH"
                        ),
                    )];
                }
            }
        };

        // Ensure the resolved path is absolute (run_with_limits changes cwd).
        let resolved = if resolved.is_absolute() {
            resolved
        } else {
            match resolved.canonicalize() {
                Ok(p) => p,
                Err(_) => resolved,
            }
        };

        // Step 2: Build full argv.
        let output_format_str = match self.manifest.output {
            OutputFormat::ZuitJson => "zuit-json",
            OutputFormat::Sarif => "sarif",
        };
        let root_str = project.root.to_string_lossy();
        let cmd_str = resolved.to_string_lossy().into_owned();

        // Extra args: command[1..] + --project-root <root> + --output-format <fmt>
        let mut extra: Vec<String> = command[1..].to_vec();
        extra.push("--project-root".to_string());
        extra.push(root_str.into_owned());
        extra.push("--output-format".to_string());
        extra.push(output_format_str.to_string());

        let args_refs: Vec<&str> = extra.iter().map(String::as_str).collect();

        // Step 3: Spawn with resource limits.
        let timeout_secs = if self.manifest.timeout_seconds == 0 {
            DEFAULT_TIMEOUT_SECS
        } else {
            self.manifest.timeout_seconds
        };
        let max_bytes = if self.manifest.max_output_bytes == 0 {
            DEFAULT_MAX_STDOUT_BYTES as u64
        } else {
            self.manifest.max_output_bytes
        };

        #[allow(clippy::cast_possible_truncation)]
        let max_bytes_usize = max_bytes as usize;

        let outcome = run_with_limits(
            &cmd_str,
            &args_refs,
            &project.root,
            max_bytes_usize,
            timeout_secs,
        );

        // Step 4: Dispatch on outcome.
        match outcome {
            Outcome::Ok(stdout) => match self.manifest.output {
                OutputFormat::ZuitJson => parse_ndjson(
                    &stdout,
                    project,
                    &project.root,
                    name,
                    &self.manifest.rule_id_prefix,
                ),
                OutputFormat::Sarif => parse_sarif(
                    &stdout,
                    project,
                    &project.root,
                    name,
                    &self.manifest.rule_id_prefix,
                ),
            },
            Outcome::Timeout => vec![Self::make_operational(
                name,
                format!("PLUGIN/{name}-timeout"),
                Severity::Medium,
                format!("plugin {name:?} timed out after {timeout_secs} seconds"),
            )],
            Outcome::OutputTooLarge => vec![Self::make_operational(
                name,
                format!("PLUGIN/{name}-output-too-large"),
                Severity::Medium,
                format!(
                    "plugin {name:?} stdout exceeded the {max_bytes}-byte cap"
                ),
            )],
            Outcome::SpawnFailed(msg) => vec![Self::make_operational(
                name,
                format!("PLUGIN/{name}-spawn-failed"),
                Severity::High,
                format!("plugin {name:?} failed to spawn: {msg}"),
            )],
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use zuit_core::Analyzer as _;

    use crate::manifest::{OutputFormat, PluginManifest};

    /// Returns the path to the echo-plugin fixture directory.
    fn echo_fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/echo-plugin")
    }

    /// Returns the [`PluginManifest`] parsed from the echo-plugin fixture.
    fn echo_manifest() -> PluginManifest {
        let toml = std::fs::read_to_string(echo_fixture_dir().join("zuit-plugin.toml"))
            .expect("echo-plugin manifest must exist");
        PluginManifest::load_from_str(&toml, None).expect("echo-plugin manifest must be valid")
    }

    /// Builds an empty [`Project`] with the given root.
    fn empty_project(root: impl Into<PathBuf>) -> Project {
        Project::new(root.into(), vec![])
    }

    /// The echo-plugin fixture should run and emit one finding with the expected `rule_id`.
    #[test]
    fn runs_fixture_emits_finding() {
        let manifest = echo_manifest();
        let plugin_dir = echo_fixture_dir();
        let analyzer = PluginAnalyzer::new(manifest, plugin_dir.clone());

        let project = empty_project(plugin_dir);
        let cfg = zuit_core::Config::default();
        let ctx = zuit_core::AnalysisContext::new(&cfg);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert_eq!(
            findings.len(),
            1,
            "expected exactly one finding, got: {findings:#?}"
        );
        let f = &findings[0];
        // The rule_id emitted by run.sh already carries the "echo/" prefix, so
        // parse_ndjson must keep it unchanged (prefix already present).
        assert_eq!(f.rule_id, "echo/test-rule");
        assert_eq!(f.analyzer, AnalyzerId::new("plugin/echo"));
    }

    /// When `command[0]` names a binary that does not exist, the analyzer must
    /// emit a single Info finding with rule `PLUGIN/echo-binary-missing`.
    #[test]
    fn binary_missing_emits_info_finding() {
        let manifest = PluginManifest {
            name: "echo".to_string(),
            version: "0.1.0".to_string(),
            output: OutputFormat::ZuitJson,
            command: vec!["./does-not-exist".to_string()],
            description: None,
            rule_id_prefix: "echo/".to_string(),
            extensions: vec![],
            timeout_seconds: 60,
            max_output_bytes: 32 * 1024 * 1024,
            license: None,
            homepage: None,
        };

        let plugin_dir = echo_fixture_dir();
        let analyzer = PluginAnalyzer::new(manifest, plugin_dir.clone());

        let project = empty_project(plugin_dir);
        let cfg = zuit_core::Config::default();
        let ctx = zuit_core::AnalysisContext::new(&cfg);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert_eq!(findings.len(), 1, "expected exactly one operational finding");
        let f = &findings[0];
        assert_eq!(f.rule_id, "PLUGIN/echo-binary-missing");
        assert_eq!(f.severity, Severity::Info);
    }

    /// When the subprocess takes too long, the analyzer must emit a single
    /// Medium finding with rule `PLUGIN/<name>-timeout`.
    ///
    /// Approach: write a temporary `sleep 5` script via `tempfile::NamedTempFile`,
    /// make it executable, and construct a `PluginManifest` directly (bypassing
    /// `load_from_str` validation) with `timeout_seconds = 1`. We construct the
    /// struct directly because `load_from_str` rejects `timeout_seconds = 0`.
    #[test]
    fn timeout_emits_warning() {
        // Write a temporary sleep script.
        // The script writes data in a tight loop so run_with_limits can observe
        // the timeout check at the top of its read loop. A simple `sleep` does
        // not work because the blocking stdout read never returns control to the
        // timeout check. The shell loop is slow enough (~1 MB/s) that the 32 MiB
        // cap is not reached before the 1-second timeout fires.
        let mut script = tempfile::NamedTempFile::new().expect("tempfile creation must succeed");
        script
            .write_all(b"#!/usr/bin/env sh\nwhile true; do printf 'x'; done\n")
            .expect("write must succeed");
        let script_path = script.path().to_path_buf();

        // Make it executable.
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod must succeed");

        let script_name = script_path
            .file_name()
            .expect("tempfile has a name")
            .to_string_lossy()
            .into_owned();
        let plugin_dir = script_path
            .parent()
            .expect("tempfile has a parent")
            .to_path_buf();

        // Construct the manifest directly so we can set timeout_seconds = 1
        // without triggering the `load_from_str` validator (which rejects 0,
        // but does allow 1). We use 1 second against a 5-second sleep.
        let manifest = PluginManifest {
            name: "timeout-test".to_string(),
            version: "0.1.0".to_string(),
            output: OutputFormat::ZuitJson,
            command: vec![format!("./{script_name}")],
            description: None,
            rule_id_prefix: "timeout-test/".to_string(),
            extensions: vec![],
            timeout_seconds: 1,
            max_output_bytes: 32 * 1024 * 1024,
            license: None,
            homepage: None,
        };

        let analyzer = PluginAnalyzer::new(manifest, plugin_dir.clone());
        let project = empty_project(plugin_dir);
        let cfg = zuit_core::Config::default();
        let ctx = zuit_core::AnalysisContext::new(&cfg);
        let findings = analyzer.analyze_project(&ctx, &project);

        assert_eq!(
            findings.len(),
            1,
            "expected exactly one timeout finding, got: {findings:#?}"
        );
        let f = &findings[0];
        assert_eq!(f.rule_id, "PLUGIN/timeout-test-timeout");
        assert_eq!(f.severity, Severity::Medium);

        // Keep `script` alive until here so the file is not deleted early.
        drop(script);
    }
}
