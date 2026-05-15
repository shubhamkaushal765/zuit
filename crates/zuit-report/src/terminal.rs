//! Terminal formatter for zuit reports.
//!
//! Groups findings by [`Dimension`] then by [`Severity`] (highest first), and
//! closes with a scoreboard table showing each dimension's score.
//!
//! Colour is emitted via ANSI escape codes only when [`RenderOptions::use_color`]
//! is `true`.  OSC-8 hyperlinks for file paths are emitted only when
//! [`RenderOptions::use_hyperlinks`] is `true`.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as FmtWrite;

use zuit_core::analyzer::{Dimension, Severity};
use zuit_core::engine::Report;
use zuit_core::finding::Finding;
use zuit_core::score::Score;

use crate::{RenderOptions, ReportError};

// ANSI escape code constants.
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[31m";
const RED_BOLD: &str = "\x1b[1;31m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const WHITE: &str = "\x1b[37m";
const GREEN: &str = "\x1b[32m";

/// Severity display order (highest to lowest).
const SEVERITY_ORDER: &[Severity] = &[
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
];

/// Fixed dimension display order.
const DIMENSION_ORDER: &[Dimension] = &[
    Dimension::Security,
    Dimension::Maintainability,
    Dimension::Complexity,
    Dimension::Documentation,
    Dimension::TestSmell,
];

/// Writes the findings for a single dimension (header + severity groups + individual findings).
///
/// The dimension header, severity buckets, and per-finding lines (location, `rule_id`, message,
/// optional suggestion) are appended to `out`.
fn write_dimension_findings(
    out: &mut String,
    dim: &Dimension,
    findings: &[&Finding],
    opts: &RenderOptions,
) -> Result<(), ReportError> {
    // Dimension header.
    let header = format!("\n=== {} ===", dim_label(dim));
    writeln!(out, "{}", with_bold(&header, opts.use_color))?;

    // Group by severity in descending order.
    let mut by_sev: HashMap<Severity, Vec<&&Finding>> = HashMap::new();
    for f in findings {
        by_sev.entry(f.severity).or_default().push(f);
    }

    for sev in SEVERITY_ORDER {
        let Some(sev_findings) = by_sev.get(sev) else {
            continue;
        };

        let sev_label = format!("  [{}]", severity_label(*sev));
        writeln!(
            out,
            "{}",
            with_severity_color(&sev_label, *sev, opts.use_color)
        )?;

        for f in sev_findings {
            write_finding(out, f, opts)?;
        }
    }
    Ok(())
}

/// Writes a single finding's location, `rule_id`, message, and optional suggestion line.
fn write_finding(out: &mut String, f: &Finding, opts: &RenderOptions) -> Result<(), ReportError> {
    let file_str = f.location.file.display().to_string();
    let line = f.location.start.line;
    let col = f.location.start.column;
    let loc_str = format!("{file_str}:{line}:{col}");

    let location_display = if opts.use_hyperlinks {
        // OSC-8: \e]8;;URI\e\\TEXT\e]8;;\e\\
        // We use a file:// URI. Relative paths are accepted by most terminals.
        let uri = format!("file://{file_str}");
        format!("\x1b]8;;{uri}\x1b\\{loc_str}\x1b]8;;\x1b\\")
    } else {
        loc_str
    };

    let taxonomy = format_taxonomy(&f.cwe, &f.owasp);
    writeln!(out, "    {} {}{taxonomy}", location_display, f.rule_id)?;
    writeln!(out, "      {}", f.message)?;
    if let Some(suggestion) = &f.suggestion {
        writeln!(out, "      Suggestion: {suggestion}")?;
    }
    Ok(())
}

/// Returns `(dim, score)` pairs in canonical v1 order, with any custom dimensions appended.
fn ordered_score_dims(scores: &BTreeMap<Dimension, Score>) -> Vec<(&Dimension, &Score)> {
    let mut out: Vec<(&Dimension, &Score)> = Vec::new();
    for dim in DIMENSION_ORDER {
        if let Some(score) = scores.get(dim) {
            out.push((dim, score));
        }
    }
    for (dim, score) in scores {
        if !DIMENSION_ORDER.contains(dim) {
            out.push((dim, score));
        }
    }
    out
}

/// Maps a 0–100 score to a letter grade.
///
/// - ≥ 90 → `"A"`
/// - ≥ 80 → `"B"`
/// - ≥ 70 → `"C"`
/// - ≥ 60 → `"D"`
/// - < 60 → `"F"`
fn score_to_grade(score: f32) -> &'static str {
    if score >= 90.0 {
        "A"
    } else if score >= 80.0 {
        "B"
    } else if score >= 70.0 {
        "C"
    } else if score >= 60.0 {
        "D"
    } else {
        "F"
    }
}

/// Writes the SCORES scoreboard section (separator, header, per-dimension rows, closing separator).
fn write_scoreboard(
    out: &mut String,
    scores: &BTreeMap<Dimension, Score>,
    opts: &RenderOptions,
) -> Result<(), ReportError> {
    writeln!(out)?;
    let sep = "─".repeat(54);
    writeln!(out, "{}", with_bold(&sep, opts.use_color))?;
    writeln!(out, "{}", with_bold("SCORES", opts.use_color))?;
    writeln!(out, "{}", with_bold(&sep, opts.use_color))?;

    for (dim, score) in ordered_score_dims(scores) {
        let bar = score_bar(score.value(), opts.use_color);
        let grade = score_to_grade(score.value());
        writeln!(
            out,
            "  {:<20} {:>5.1}  {}  {}",
            dim_label(dim),
            score.value(),
            bar,
            grade
        )?;
    }

    writeln!(out, "{sep}")?;
    Ok(())
}

/// Renders `report` as a terminal string.
///
/// Findings are grouped by dimension, then by severity (critical first).
/// A scoreboard table is appended at the end.
///
/// When `opts.use_color` is `false` the output is plain ASCII with no ANSI
/// escape codes (suitable for CI logs and snapshot tests).
///
/// When `opts.use_hyperlinks` is `true` file paths are wrapped in OSC-8
/// hyperlink sequences so that terminals supporting the protocol can render
/// them as clickable links.
///
/// # Errors
///
/// Returns [`ReportError::Fmt`] on a formatting error (essentially infallible
/// when writing to a `String`).
pub fn render_terminal(report: &Report, opts: &RenderOptions) -> Result<String, ReportError> {
    let mut out = String::new();

    // Group findings by dimension.
    let mut by_dim: HashMap<&Dimension, Vec<&Finding>> = HashMap::new();
    for f in &report.findings {
        by_dim.entry(&f.dimension).or_default().push(f);
    }

    // Render v1 dimensions in canonical order, then any custom dimensions.
    let mut dims_to_render: Vec<&Dimension> = Vec::new();
    for dim in DIMENSION_ORDER {
        if by_dim.contains_key(dim) {
            dims_to_render.push(dim);
        }
    }
    // Custom dimensions not in the v1 order.
    for dim in by_dim.keys() {
        if !DIMENSION_ORDER.contains(dim) {
            dims_to_render.push(dim);
        }
    }

    for dim in &dims_to_render {
        write_dimension_findings(&mut out, dim, &by_dim[dim], opts)?;
    }

    write_scoreboard(&mut out, &report.scores, opts)?;

    // Stats line.
    if report.stats.suppressed > 0 {
        writeln!(
            out,
            "  {} files scanned, {} parse failures, {}ms ({} suppressed)",
            report.stats.files_scanned,
            report.stats.parse_failures,
            report.stats.elapsed_ms,
            report.stats.suppressed,
        )?;
    } else {
        writeln!(
            out,
            "  {} files scanned, {} parse failures, {}ms",
            report.stats.files_scanned, report.stats.parse_failures, report.stats.elapsed_ms
        )?;
    }

    Ok(out)
}

/// Formats a `[CWE-…, A0…:2021]` suffix from a finding's taxonomy fields.
///
/// Returns an empty string when both lists are empty so existing rules without
/// a mapping render exactly as before.
fn format_taxonomy(cwe: &[String], owasp: &[String]) -> String {
    if cwe.is_empty() && owasp.is_empty() {
        return String::new();
    }
    let joined: Vec<&str> = cwe.iter().chain(owasp.iter()).map(String::as_str).collect();
    format!(" [{}]", joined.join(", "))
}

/// Returns a human-readable label for a dimension.
fn dim_label(dim: &Dimension) -> &str {
    match dim {
        Dimension::Maintainability => "Maintainability",
        Dimension::Security => "Security",
        Dimension::Complexity => "Complexity",
        Dimension::Documentation => "Documentation",
        Dimension::TestSmell => "TestSmell",
        Dimension::Custom(s) => s,
    }
}

/// Returns a human-readable label for a severity level.
fn severity_label(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

/// Wraps text in ANSI bold codes when `use_color` is true.
fn with_bold(s: impl AsRef<str>, use_color: bool) -> String {
    let s = s.as_ref();
    if use_color {
        format!("{BOLD}{s}{RESET}")
    } else {
        s.to_string()
    }
}

/// Wraps text in the appropriate severity ANSI colour when `use_color` is true.
fn with_severity_color(s: &str, sev: Severity, use_color: bool) -> String {
    if !use_color {
        return s.to_string();
    }
    let code = match sev {
        Severity::Critical => RED_BOLD,
        Severity::High => RED,
        Severity::Medium => YELLOW,
        Severity::Low => CYAN,
        Severity::Info => WHITE,
    };
    format!("{code}{s}{RESET}")
}

/// Renders a simple ASCII bar chart segment for a score value.
///
/// The bar is 20 characters wide; each character represents 5 points.
fn score_bar(value: f32, use_color: bool) -> String {
    // value is in [0.0, 100.0], so (value / 5.0).round() is in [0.0, 20.0]:
    // the cast to usize is safe since the value is non-negative and at most 20.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let filled = ((value / 5.0).round() as usize).min(20);
    let hashes = "#".repeat(filled);
    let dots = ".".repeat(20 - filled);
    let bar = format!("{hashes}{dots}");
    if !use_color {
        return bar;
    }
    let code = if value >= 80.0 {
        GREEN
    } else if value >= 50.0 {
        YELLOW
    } else {
        RED
    };
    format!("{code}{bar}{RESET}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use zuit_core::analyzer::{Dimension, Severity};
    use zuit_core::engine::{Report, RunStats};
    use zuit_core::finding::Finding;
    use zuit_core::id::AnalyzerId;
    use zuit_core::score::Score;
    use zuit_core::span::{ByteOffset, LineCol, Location, Span};

    fn make_report() -> Report {
        let mut scores = BTreeMap::new();
        scores.insert(Dimension::Security, Score(72.0));
        scores.insert(Dimension::Maintainability, Score(88.5));
        scores.insert(Dimension::Complexity, Score(100.0));
        scores.insert(Dimension::Documentation, Score(55.0));
        scores.insert(Dimension::TestSmell, Score(100.0));

        let findings = vec![Finding {
            analyzer: AnalyzerId::new("test"),
            dimension: Dimension::Security,
            rule_id: "SEC001".to_string(),
            severity: Severity::High,
            message: "Hardcoded secret detected".to_string(),
            location: Location {
                file: PathBuf::from("src/config.rs"),
                span: Span::new(ByteOffset(0), ByteOffset(10)),
                start: LineCol::new(3, 1),
                end: LineCol::new(3, 11),
            },
            suggestion: Some("Move to environment variable".to_string()),
            references: vec![],
            cwe: vec!["CWE-798".to_string()],
            owasp: vec!["A07:2021".to_string()],
        }];

        Report {
            schema_version: 1,
            findings,
            scores,
            stats: RunStats {
                files_scanned: 5,
                parse_failures: 0,
                elapsed_ms: 42,
                suppressed: 0,
                cache_hits: 0,
            },
        }
    }

    #[test]
    fn no_color_output_contains_no_ansi_escapes() {
        let report = make_report();
        let opts = RenderOptions {
            use_color: false,
            use_hyperlinks: false,
        };
        let output = render_terminal(&report, &opts).unwrap();
        assert!(
            !output.contains('\x1b'),
            "unexpected ANSI escape in no-color output"
        );
    }

    #[test]
    fn output_contains_rule_id() {
        let report = make_report();
        let opts = RenderOptions {
            use_color: false,
            use_hyperlinks: false,
        };
        let output = render_terminal(&report, &opts).unwrap();
        assert!(output.contains("SEC001"), "rule_id missing from output");
    }

    #[test]
    fn output_contains_scoreboard() {
        let report = make_report();
        let opts = RenderOptions {
            use_color: false,
            use_hyperlinks: false,
        };
        let output = render_terminal(&report, &opts).unwrap();
        assert!(output.contains("SCORES"), "scoreboard header missing");
        assert!(
            output.contains("Security"),
            "dimension missing from scoreboard"
        );
    }

    #[test]
    fn with_color_output_contains_ansi_escapes() {
        let report = make_report();
        let opts = RenderOptions {
            use_color: true,
            use_hyperlinks: false,
        };
        let output = render_terminal(&report, &opts).unwrap();
        assert!(
            output.contains('\x1b'),
            "expected ANSI escapes in color output"
        );
    }

    #[test]
    fn with_hyperlinks_output_contains_osc8() {
        let report = make_report();
        let opts = RenderOptions {
            use_color: false,
            use_hyperlinks: true,
        };
        let output = render_terminal(&report, &opts).unwrap();
        // OSC-8 sequences start with \x1b]8;
        assert!(
            output.contains("\x1b]8;"),
            "expected OSC-8 hyperlink in output"
        );
    }

    #[test]
    fn stats_line_present() {
        let report = make_report();
        let opts = RenderOptions {
            use_color: false,
            use_hyperlinks: false,
        };
        let output = render_terminal(&report, &opts).unwrap();
        assert!(output.contains("5 files scanned"), "stats line missing");
        assert!(output.contains("42ms"), "elapsed_ms missing from stats");
    }

    #[test]
    fn stats_line_includes_suppressed_when_nonzero() {
        let mut report = make_report();
        report.stats.suppressed = 3;
        let opts = RenderOptions {
            use_color: false,
            use_hyperlinks: false,
        };
        let output = render_terminal(&report, &opts).unwrap();
        assert!(
            output.contains("3 suppressed"),
            "expected '3 suppressed' in stats line: {output}"
        );
    }

    #[test]
    fn stats_line_omits_suppressed_when_zero() {
        let report = make_report(); // suppressed = 0
        let opts = RenderOptions {
            use_color: false,
            use_hyperlinks: false,
        };
        let output = render_terminal(&report, &opts).unwrap();
        assert!(
            !output.contains("suppressed"),
            "expected no 'suppressed' in stats line when zero: {output}"
        );
    }

    #[test]
    fn scoreboard_contains_letter_grade() {
        let report = make_report();
        let opts = RenderOptions {
            use_color: false,
            use_hyperlinks: false,
        };
        let output = render_terminal(&report, &opts).unwrap();
        // make_report sets Security=72.0 (C), Maintainability=88.5 (B),
        // Complexity=100.0 (A), Documentation=55.0 (F), TestSmell=100.0 (A).
        let has_grade = output.contains("  A")
            || output.contains("  B")
            || output.contains("  C")
            || output.contains("  D")
            || output.contains("  F");
        assert!(
            has_grade,
            "scoreboard must contain a letter grade (A/B/C/D/F): {output}"
        );
    }

    #[test]
    fn grade_boundaries() {
        assert_eq!(score_to_grade(100.0), "A");
        assert_eq!(score_to_grade(90.0), "A");
        assert_eq!(score_to_grade(89.99), "B");
        assert_eq!(score_to_grade(80.0), "B");
        assert_eq!(score_to_grade(70.0), "C");
        assert_eq!(score_to_grade(60.0), "D");
        assert_eq!(score_to_grade(0.0), "F");
    }
}
