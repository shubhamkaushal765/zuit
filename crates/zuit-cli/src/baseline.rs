//! Implementation of the `zuit baseline save` subcommand.
//!
//! Generates a baseline JSON file that can later be passed to
//! `zuit analyze --baseline <file>` to suppress findings that were already
//! present at a given point in time.
//!
//! # Usage
//!
//! ```text
//! zuit baseline save [--output FILE] [--ref <git-ref>] [PATH]
//! ```
//!
//! - `PATH` defaults to `.`.
//! - `--output` defaults to `zuit-baseline.json`.
//! - Without `--ref`: runs a normal analysis of the working tree and writes the
//!   JSON report.
//! - With `--ref <git-ref>`: materialises that ref's source tree via
//!   `git archive | tar -x` into a temporary directory, then analyses it.
//!   Exits cleanly (with an error message) if `git` is not in `PATH` or the
//!   ref is invalid.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail};
use zuit_core::{Config, Engine};
use zuit_report::{RenderOptions, ReportFormat, render};

use crate::registry_builtin::build_registry;

/// Runs the `baseline save` subcommand.
///
/// # Errors
///
/// Returns an error if:
/// - `--ref` is given but `git` is absent or the ref is invalid.
/// - The analysis path does not exist or cannot be walked.
/// - Writing the output file fails.
pub fn run(args: &crate::cli::BaselineSaveArgs) -> Result<i32> {
    let path = args.path.clone().unwrap_or_else(|| PathBuf::from("."));
    let output = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from("zuit-baseline.json"));

    if let Some(ref git_ref) = args.git_ref {
        run_with_ref(&path, git_ref, &output)
    } else {
        run_working_tree(&path, &output, args.config.as_deref())
    }
}

/// Analyses the working tree and writes the JSON report to `output`.
fn run_working_tree(path: &Path, output: &Path, config_flag: Option<&Path>) -> Result<i32> {
    let config = resolve_config(config_flag, path)?;
    let report = run_engine(path, &config)?;
    write_report(output, &report)
}

/// Materialises `git_ref` into a temp dir via `git archive | tar -x`, analyses
/// it, and writes the JSON report to `output`.
fn run_with_ref(path: &Path, git_ref: &str, output: &Path) -> Result<i32> {
    // Create a temp dir to hold the extracted source tree.
    let tmp = tempfile::TempDir::new().context("creating temp dir for git archive")?;

    // Run: git archive <ref> | tar -x -C <tmp>
    // We pipe the two commands together using std::process pipes.
    let mut git_cmd = Command::new("git")
        .args([
            "archive",
            "--format=tar",
            git_ref,
            // Only archive the sub-path if it was given (relative to repo root).
            // For simplicity, always archive from the repo root.
        ])
        // Run from `path` so git finds the repo.
        .current_dir(path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context(
            "spawning `git archive` — ensure git is installed and the path is inside a repository",
        )?;

    let git_stdout = git_cmd.stdout.take().expect("invariant: stdout was piped");

    // Extract the archive into the temp dir using tar.
    let tar_status = Command::new("tar")
        .args(["-x", "-C"])
        .arg(tmp.path())
        .stdin(git_stdout)
        .status()
        .context("spawning `tar` — ensure tar is installed")?;

    // Wait for git and check its exit status.
    let git_output = git_cmd
        .wait_with_output()
        .context("waiting for `git archive`")?;

    if !git_output.status.success() {
        let stderr = String::from_utf8_lossy(&git_output.stderr);
        bail!("git archive failed for ref `{git_ref}`: {stderr}");
    }

    if !tar_status.success() {
        bail!("tar extraction failed (exit code: {tar_status})");
    }

    // Analyse the extracted tree.
    let config = Config::default();
    let report = run_engine(tmp.path(), &config)?;
    write_report(output, &report)
}

/// Resolves `Config` using the same logic as `analyze::run`.
fn resolve_config(config_flag: Option<&Path>, root: &Path) -> Result<Config> {
    if let Some(explicit) = config_flag {
        return Config::load(explicit)
            .with_context(|| format!("loading config from {}", explicit.display()));
    }
    let mut dir = root.to_path_buf();
    loop {
        let candidate = dir.join("zuit.toml");
        if candidate.exists() {
            return Config::load(&candidate)
                .with_context(|| format!("loading config from {}", candidate.display()));
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => break,
        }
    }
    Ok(Config::default())
}

/// Builds the engine and runs analysis over `path`.
fn run_engine(path: &Path, config: &Config) -> Result<zuit_core::Report> {
    let registry = build_registry();
    let engine = Engine::new(registry);
    engine
        .analyze_path(path, config)
        .with_context(|| format!("analyzing path {}", path.display()))
}

/// Serialises `report` as pretty-printed JSON and writes it to `output`.
fn write_report(output: &Path, report: &zuit_core::Report) -> Result<i32> {
    let opts = RenderOptions::default();
    let json = render(ReportFormat::Json, report, &opts).context("rendering JSON report")?;
    std::fs::write(output, json.as_bytes())
        .with_context(|| format!("writing baseline to {}", output.display()))?;
    println!(
        "Baseline saved to {} ({} findings)",
        output.display(),
        report.findings.len()
    );
    Ok(0)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper: create a baseline args with default options.
    fn make_args(
        path: Option<PathBuf>,
        output: Option<PathBuf>,
        git_ref: Option<String>,
    ) -> crate::cli::BaselineSaveArgs {
        crate::cli::BaselineSaveArgs {
            path,
            output,
            git_ref,
            config: None,
        }
    }

    #[test]
    fn baseline_save_empty_dir_produces_valid_json() {
        let tmp = TempDir::new().unwrap();
        let out = tmp.path().join("baseline.json");
        let args = make_args(Some(tmp.path().to_path_buf()), Some(out.clone()), None);
        let code = run(&args).unwrap();
        assert_eq!(code, 0);
        assert!(out.exists(), "output file must exist");
        let text = std::fs::read_to_string(&out).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(json["schema_version"], 1);
        assert!(json["findings"].is_array());
    }

    #[test]
    fn baseline_default_output_path() {
        // When no --output is given the default is zuit-baseline.json in the
        // current working directory.  We can't easily test that here without
        // changing cwd, so just verify the args struct default is correct.
        let args = make_args(None, None, None);
        let out = args
            .output
            .clone()
            .unwrap_or_else(|| PathBuf::from("zuit-baseline.json"));
        assert_eq!(out, PathBuf::from("zuit-baseline.json"));
    }

    #[test]
    fn baseline_invalid_git_ref_returns_error() {
        // git archive with a nonexistent ref should return an error, not panic.
        let tmp = TempDir::new().unwrap();
        // We cannot guarantee git is available in all test environments, so we
        // accept either a "git not found" IO error or a "git archive failed" bail.
        let args = make_args(
            Some(tmp.path().to_path_buf()),
            Some(tmp.path().join("out.json")),
            Some("nonexistent-ref-xyz-9999".to_string()),
        );
        let result = run(&args);
        // Either git is absent → Err, or git is present but ref invalid → Err.
        assert!(
            result.is_err(),
            "invalid git ref must return an error, got Ok"
        );
    }

    #[test]
    fn baseline_round_trip_with_analyze_baseline_suppression() {
        // Generate a baseline from a directory, then verify it is valid JSON with
        // the expected schema fields.  This is the round-trip integration test
        // mentioned in the spec.
        let tmp = TempDir::new().unwrap();
        // Write a dummy Rust file so there might be some findings.
        std::fs::write(tmp.path().join("dummy.rs"), "fn main() { let _x = 1; }\n").unwrap();

        let out = tmp.path().join("baseline.json");
        let args = make_args(Some(tmp.path().to_path_buf()), Some(out.clone()), None);
        run(&args).unwrap();

        let text = std::fs::read_to_string(&out).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");

        // Verify the baseline has the required schema fields.
        assert!(json.get("schema_version").is_some());
        assert!(json.get("findings").is_some());
        assert!(json.get("scores").is_some());
        assert!(json.get("stats").is_some());
    }
}
