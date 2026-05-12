//! Implementation of the `zuit report` subcommand.
//!
//! Reads an existing JSON [`zuit_core::Report`] and re-renders it in
//! another format. This is purely a transformation — no analysis runs and the
//! command always returns exit code 0 on success.

use std::io::{Read as _, Write as _};
use std::path::Path;

use anyhow::{Context as _, Result};
use zuit_core::Report;
use zuit_report::{RenderOptions, ReportFormat, render};

use crate::cli::{Format, ReportArgs};

/// Reads `path` (or stdin if `path == "-"`) and returns the contents as a
/// `String`. Validating UTF-8 here gives a clearer error than letting `serde`
/// fail later.
fn read_input(path: &str) -> Result<String> {
    if path == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .with_context(|| "reading report JSON from stdin")?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path).with_context(|| format!("reading report JSON from {path}"))
    }
}

/// Converts a CLI [`Format`] into a [`ReportFormat`]. Kept private so the
/// mapping doesn't drift between `analyze` and `report`.
fn to_report_format(fmt: Format) -> ReportFormat {
    match fmt {
        Format::Json => ReportFormat::Json,
        Format::Terminal => ReportFormat::Terminal,
        Format::Markdown => ReportFormat::Markdown,
        Format::Sarif => ReportFormat::Sarif,
        Format::Checkstyle => ReportFormat::Checkstyle,
        Format::Junit => ReportFormat::Junit,
    }
}

/// Runs the `report` subcommand and returns the desired process exit code (0).
///
/// # Errors
///
/// Returns an error if the input cannot be read, is not valid JSON for a
/// [`Report`], the requested format cannot be rendered, or the output file
/// cannot be written.
pub fn run(args: &ReportArgs) -> Result<i32> {
    let text = read_input(&args.input)?;
    let report: Report = serde_json::from_str(&text).with_context(|| "parsing report JSON")?;

    let opts = RenderOptions {
        use_color: !args.no_color,
        use_hyperlinks: args.hyperlinks,
    };
    let rendered = render(to_report_format(args.format), &report, &opts)
        .with_context(|| "rendering report")?;

    write_output(args.output.as_deref(), &rendered)?;
    Ok(0)
}

fn write_output(path: Option<&Path>, rendered: &str) -> Result<()> {
    match path {
        Some(out_path) => {
            let mut file = std::fs::File::create(out_path)
                .with_context(|| format!("creating output file {}", out_path.display()))?;
            file.write_all(rendered.as_bytes())
                .with_context(|| format!("writing to output file {}", out_path.display()))?;
        }
        None => {
            print!("{rendered}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Format;

    /// Minimal `Report` JSON the renderer can consume — no findings, all five
    /// dimensions present at perfect scores. The shape mirrors what
    /// `zuit analyze --format json` would emit for an empty project.
    const EMPTY_REPORT_JSON: &str = r#"{
        "schema_version": 1,
        "findings": [],
        "scores": {
            "maintainability": 100.0,
            "security": 100.0,
            "documentation": 100.0,
            "complexity": 100.0,
            "test_smell": 100.0
        },
        "stats": {
            "files_scanned": 0,
            "parse_failures": 0,
            "elapsed_ms": 0,
            "suppressed": 0
        }
    }"#;

    fn write_tmp_json(text: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("invariant: tempfile");
        f.write_all(text.as_bytes()).expect("invariant: write");
        f
    }

    fn args_for(input: &str, format: Format) -> ReportArgs {
        ReportArgs {
            input: input.to_string(),
            format,
            output: None,
            no_color: true,
            hyperlinks: false,
        }
    }

    #[test]
    fn report_run_succeeds_for_empty_report_terminal() {
        let f = write_tmp_json(EMPTY_REPORT_JSON);
        let args = args_for(
            f.path().to_str().expect("invariant: tmp path utf8"),
            Format::Terminal,
        );
        // Always returns exit code 0 — this is a transformation, not analysis.
        let code = run(&args).expect("run failed");
        assert_eq!(code, 0);
    }

    #[test]
    fn report_run_writes_markdown_to_output_file() {
        let input = write_tmp_json(EMPTY_REPORT_JSON);
        let out = tempfile::NamedTempFile::new().expect("invariant: tempfile");
        let args = ReportArgs {
            input: input.path().to_string_lossy().into_owned(),
            format: Format::Markdown,
            output: Some(out.path().to_path_buf()),
            no_color: true,
            hyperlinks: false,
        };
        run(&args).expect("run failed");
        let body = std::fs::read_to_string(out.path()).expect("read output");
        assert!(
            !body.is_empty(),
            "markdown report should be non-empty even for an empty input"
        );
        // Markdown renderers conventionally start with a heading.
        assert!(
            body.contains('#'),
            "markdown output should contain a heading marker; got:\n{body}"
        );
    }

    #[test]
    fn report_run_round_trips_json_format() {
        let input = write_tmp_json(EMPTY_REPORT_JSON);
        let out = tempfile::NamedTempFile::new().expect("invariant: tempfile");
        let args = ReportArgs {
            input: input.path().to_string_lossy().into_owned(),
            format: Format::Json,
            output: Some(out.path().to_path_buf()),
            no_color: true,
            hyperlinks: false,
        };
        run(&args).expect("run failed");
        // Round-trip: re-parse the output and assert it matches the input shape.
        let body = std::fs::read_to_string(out.path()).expect("read output");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("output is JSON");
        assert_eq!(
            parsed
                .get("schema_version")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn report_run_returns_error_for_invalid_json() {
        let f = write_tmp_json("not json at all");
        let args = args_for(
            f.path().to_str().expect("invariant: tmp path utf8"),
            Format::Terminal,
        );
        let err = run(&args).expect_err("expected parse error");
        let s = format!("{err:#}");
        assert!(s.contains("parsing report JSON"), "error chain: {s}");
    }
}
