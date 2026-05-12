//! Implementation of the `zuit diff <FROM> <TO>` subcommand.
//!
//! Computes a finding-level diff between two JSON report files and emits the
//! result as JSON (default) or a human-readable terminal summary.

use std::path::Path;

use anyhow::{Context as _, Result};
use zuit_show::analytics::{ScanDiff, compute_scan_diff};

/// Output format for `zuit diff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffFormat {
    /// Pretty-printed JSON (default).
    Json,
    /// Human-readable terminal summary with ANSI colour.
    Terminal,
}

/// ANSI escape codes used in terminal output.
const RESET: &str = "\x1b[0m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";

/// Loads and normalises a report file into an envelope-shaped `serde_json::Value`.
///
/// If the file contains a top-level `report` key that is an object, it is treated
/// as a scan envelope and returned as-is.  Otherwise the value is wrapped:
/// `{"report": <value>}`.
fn load_as_envelope(path: &Path) -> Result<serde_json::Value> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("parsing JSON from {}", path.display()))?;

    if value.get("report").and_then(|v| v.as_object()).is_some() {
        Ok(value)
    } else {
        Ok(serde_json::json!({"report": value}))
    }
}

/// Formats a single finding for terminal display.
fn format_finding_line(finding: &serde_json::Value) -> String {
    let file = finding["location"]["file"].as_str().unwrap_or("?");
    let line = finding["location"]["start"]["line"].as_u64().unwrap_or(0);
    let rule_id = finding["rule_id"].as_str().unwrap_or("?");
    let message = finding["message"].as_str().unwrap_or("?");
    format!("  {file}:{line}  {rule_id}  {message}")
}

/// Renders a `ScanDiff` as a human-readable terminal string.
fn render_terminal(diff: &ScanDiff) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    writeln!(out, "Diff: {} → {}", diff.from_scan_id, diff.to_scan_id)
        .expect("writing to String is infallible");
    writeln!(
        out,
        "  New: {}  Resolved: {}  Persisting: {}\n",
        diff.new.len(),
        diff.resolved.len(),
        diff.persisting.len()
    )
    .expect("writing to String is infallible");

    if !diff.new.is_empty() {
        writeln!(out, "{RED}+ New findings ({}):{RESET}", diff.new.len())
            .expect("writing to String is infallible");
        for f in &diff.new {
            writeln!(out, "{RED}{}{RESET}", format_finding_line(f))
                .expect("writing to String is infallible");
        }
        out.push('\n');
    }

    if !diff.resolved.is_empty() {
        writeln!(
            out,
            "{GREEN}- Resolved findings ({}):{RESET}",
            diff.resolved.len()
        )
        .expect("writing to String is infallible");
        for f in &diff.resolved {
            writeln!(out, "{GREEN}{}{RESET}", format_finding_line(f))
                .expect("writing to String is infallible");
        }
        out.push('\n');
    }

    if !diff.persisting.is_empty() {
        writeln!(
            out,
            "{YELLOW}= Persisting findings ({}):{RESET}",
            diff.persisting.len()
        )
        .expect("writing to String is infallible");
        for f in &diff.persisting {
            writeln!(out, "{YELLOW}{}{RESET}", format_finding_line(f))
                .expect("writing to String is infallible");
        }
    }

    out
}

/// Runs the `diff` subcommand.
///
/// Loads `from_path` and `to_path`, computes the diff, and prints the result
/// to stdout in the requested format.
///
/// # Exit codes
///
/// - `0` if `new` is empty (no regressions).
/// - `1` if `new` is non-empty (new findings introduced).
///
/// # Errors
///
/// Returns an error (which the caller maps to exit code 2) on I/O or parse
/// failures.
pub fn run(from_path: &Path, to_path: &Path, format: DiffFormat) -> Result<i32> {
    let from = load_as_envelope(from_path)?;
    let to = load_as_envelope(to_path)?;

    let diff = compute_scan_diff(&from, &to);

    match format {
        DiffFormat::Json => {
            let json = serde_json::to_string_pretty(&diff).context("serializing diff to JSON")?;
            println!("{json}");
        }
        DiffFormat::Terminal => {
            print!("{}", render_terminal(&diff));
        }
    }

    if diff.new.is_empty() { Ok(0) } else { Ok(1) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn make_finding(file: &str, line: u64, rule_id: &str, message: &str) -> serde_json::Value {
        serde_json::json!({
            "rule_id": rule_id,
            "message": message,
            "location": {
                "file": file,
                "start": { "line": line, "col": 1 }
            }
        })
    }

    fn make_envelope(findings: &[serde_json::Value]) -> serde_json::Value {
        serde_json::json!({
            "scan_id": "test-scan",
            "report": {
                "findings": findings,
                "scores": {}
            }
        })
    }

    fn write_json(
        dir: &tempfile::TempDir,
        name: &str,
        value: &serde_json::Value,
    ) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, serde_json::to_string(value).unwrap()).unwrap();
        path
    }

    #[test]
    fn load_bare_report_wraps_as_envelope() {
        let tmp = tempfile::TempDir::new().unwrap();
        let report = serde_json::json!({
            "findings": [],
            "scores": {}
        });
        let path = write_json(&tmp, "report.json", &report);
        let envelope = load_as_envelope(&path).unwrap();
        assert!(
            envelope.get("report").is_some(),
            "should have wrapped in envelope"
        );
    }

    #[test]
    fn load_envelope_passthrough() {
        let tmp = tempfile::TempDir::new().unwrap();
        let envelope = make_envelope(&[]);
        let path = write_json(&tmp, "envelope.json", &envelope);
        let loaded = load_as_envelope(&path).unwrap();
        assert!(loaded.get("report").is_some());
    }
}
