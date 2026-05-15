//! Markdown formatter for zuit reports.
//!
//! Produces output suitable for GitHub PR comments or any Markdown renderer that
//! supports `<details>` / `<summary>` HTML elements.
//!
//! ## Structure
//!
//! 1. A top-level scoreboard table with one row per dimension.
//! 2. Run statistics (files scanned, parse failures, elapsed time).
//! 3. One `<details>` block per dimension that has findings.

use std::fmt::Write as FmtWrite;

use zuit_core::analyzer::{Dimension, Severity};
use zuit_core::engine::Report;
use zuit_core::finding::Finding;
use zuit_core::score::Score;

use crate::ReportError;

/// Canonical dimension render order.
const DIMENSION_ORDER: &[Dimension] = &[
    Dimension::Security,
    Dimension::Maintainability,
    Dimension::Complexity,
    Dimension::Documentation,
    Dimension::TestSmell,
];

/// Writes the scoreboard table header and one row per dimension. Canonical v1
/// dimensions appear first in fixed order; any custom dimensions follow in
/// alphabetical order for deterministic output.
///
/// # Errors
///
/// Returns [`ReportError::Fmt`] on a formatting error.
fn write_scoreboard_table(out: &mut String, report: &Report) -> Result<(), ReportError> {
    writeln!(out, "| Dimension | Score | Rating |")?;
    writeln!(out, "|-----------|------:|--------|")?;

    for dim in DIMENSION_ORDER {
        if let Some(score) = report.scores.get(dim) {
            writeln!(
                out,
                "| {} | {:.1} | {} |",
                dim_label(dim),
                score.value(),
                rating_emoji(*score)
            )?;
        }
    }

    let mut custom_dims: Vec<(&Dimension, &Score)> = report
        .scores
        .iter()
        .filter(|(dim, _)| !DIMENSION_ORDER.contains(dim))
        .collect();
    custom_dims.sort_by_key(|(dim, _)| (*dim).to_string());
    for (dim, score) in custom_dims {
        writeln!(
            out,
            "| {} | {:.1} | {} |",
            dim_label(dim),
            score.value(),
            rating_emoji(*score)
        )?;
    }

    Ok(())
}

/// Groups `findings` by dimension.
fn group_findings_by_dimension(
    findings: &[Finding],
) -> std::collections::HashMap<&Dimension, Vec<&Finding>> {
    let mut by_dim: std::collections::HashMap<&Dimension, Vec<&Finding>> =
        std::collections::HashMap::new();
    for f in findings {
        by_dim.entry(&f.dimension).or_default().push(f);
    }
    by_dim
}

/// Returns dimensions that have findings in canonical order followed by sorted custom dimensions.
fn ordered_dims_with_findings<'a>(
    by_dim: &std::collections::HashMap<&'a Dimension, Vec<&Finding>>,
) -> Vec<&'a Dimension> {
    let mut dims: Vec<&Dimension> = DIMENSION_ORDER
        .iter()
        .filter(|d| by_dim.contains_key(d))
        .collect();

    let mut custom: Vec<&Dimension> = by_dim
        .keys()
        .filter(|d| !DIMENSION_ORDER.contains(d))
        .copied()
        .collect();
    custom.sort_by_key(std::string::ToString::to_string);
    dims.extend(custom);
    dims
}

/// Writes a single `<details>` block for `dim` containing a findings table.
///
/// # Errors
///
/// Returns [`ReportError::Fmt`] on a formatting error.
fn write_details_block(
    out: &mut String,
    dim: &Dimension,
    findings: &[&Finding],
    score: Option<&Score>,
) -> Result<(), ReportError> {
    let count = findings.len();
    let score_text = score.map_or_else(|| "N/A".to_string(), |s| format!("{:.1}", s.value()));

    writeln!(out)?;
    writeln!(
        out,
        "<details><summary><strong>{}</strong> &mdash; score: {} ({} finding{})</summary>",
        dim_label(dim),
        score_text,
        count,
        if count == 1 { "" } else { "s" }
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "| File | Line | Rule | Severity | Taxonomy | Message |"
    )?;
    writeln!(
        out,
        "|------|------|------|----------|----------|---------|"
    )?;

    for f in findings {
        let file = f.location.file.display();
        let line = f.location.start.line;
        let sev = severity_label(f.severity);
        let msg = f.message.replace('|', r"\|");
        let taxonomy = format_taxonomy(&f.cwe, &f.owasp);
        writeln!(
            out,
            "| `{}` | {} | `{}` | {} | {} | {} |",
            file, line, f.rule_id, sev, taxonomy, msg
        )?;
    }

    writeln!(out)?;
    writeln!(out, "</details>")?;
    Ok(())
}

/// Writes the collapsible `<details>` blocks for all dimensions that have findings,
/// preceded by a horizontal rule separator when there are any findings to show.
///
/// # Errors
///
/// Returns [`ReportError::Fmt`] on a formatting error.
fn write_findings_section(out: &mut String, report: &Report) -> Result<(), ReportError> {
    let by_dim = group_findings_by_dimension(&report.findings);

    if !report.findings.is_empty() {
        writeln!(out)?;
        writeln!(out, "---")?;
    }

    for dim in ordered_dims_with_findings(&by_dim) {
        write_details_block(out, dim, &by_dim[dim], report.scores.get(dim))?;
    }

    Ok(())
}

/// Renders `report` as GitHub-flavoured Markdown.
///
/// # Errors
///
/// Returns [`ReportError::Fmt`] on a formatting error (essentially infallible
/// when writing to a `String`).
pub fn render_markdown(report: &Report) -> Result<String, ReportError> {
    let mut out = String::new();

    writeln!(out, "## zuit report")?;
    writeln!(out)?;

    write_scoreboard_table(&mut out, report)?;

    writeln!(out)?;
    if report.stats.suppressed > 0 {
        writeln!(
            out,
            "_Scanned {} file(s) &mdash; {} parse failure(s) &mdash; {}ms &mdash; {} suppressed_",
            report.stats.files_scanned,
            report.stats.parse_failures,
            report.stats.elapsed_ms,
            report.stats.suppressed,
        )?;
    } else {
        writeln!(
            out,
            "_Scanned {} file(s) &mdash; {} parse failure(s) &mdash; {}ms_",
            report.stats.files_scanned, report.stats.parse_failures, report.stats.elapsed_ms
        )?;
    }

    write_findings_section(&mut out, report)?;

    Ok(out)
}

/// Formats a finding's CWE/OWASP mapping as a comma-separated cell value.
///
/// Returns an empty string for findings with no mapping so the column is
/// blank rather than `(none)` for non-security rules.
fn format_taxonomy(cwe: &[String], owasp: &[String]) -> String {
    if cwe.is_empty() && owasp.is_empty() {
        return String::new();
    }
    cwe.iter()
        .chain(owasp.iter())
        .map(|s| format!("`{s}`"))
        .collect::<Vec<_>>()
        .join(", ")
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

/// Returns a rating text based on the score value.
fn rating_emoji(score: Score) -> &'static str {
    if score.value() >= 90.0 {
        "Excellent"
    } else if score.value() >= 75.0 {
        "Good"
    } else if score.value() >= 50.0 {
        "Fair"
    } else {
        "Poor"
    }
}

/// Returns a human-readable label for a severity level.
fn severity_label(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
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
            message: "Hardcoded secret".to_string(),
            location: Location {
                file: PathBuf::from("src/config.rs"),
                span: Span::new(ByteOffset(0), ByteOffset(10)),
                start: LineCol::new(3, 1),
                end: LineCol::new(3, 11),
            },
            suggestion: None,
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
    fn output_contains_scoreboard_table() {
        let report = make_report();
        let md = render_markdown(&report).unwrap();
        assert!(
            md.contains("| Dimension | Score | Rating |"),
            "scoreboard header missing"
        );
        assert!(md.contains("Security"), "dimension missing");
    }

    #[test]
    fn output_contains_details_block() {
        let report = make_report();
        let md = render_markdown(&report).unwrap();
        assert!(md.contains("<details>"), "<details> block missing");
        assert!(md.contains("</details>"), "</details> missing");
    }

    #[test]
    fn output_contains_finding_rule_id() {
        let report = make_report();
        let md = render_markdown(&report).unwrap();
        assert!(md.contains("SEC001"), "rule_id missing");
    }

    #[test]
    fn stats_line_present() {
        let report = make_report();
        let md = render_markdown(&report).unwrap();
        assert!(md.contains("5 file(s)"), "files_scanned missing");
        assert!(md.contains("42ms"), "elapsed_ms missing");
    }

    #[test]
    fn stats_line_includes_suppressed_when_nonzero() {
        let mut report = make_report();
        report.stats.suppressed = 7;
        let md = render_markdown(&report).unwrap();
        assert!(
            md.contains("7 suppressed"),
            "expected '7 suppressed' in stats: {md}"
        );
    }

    #[test]
    fn stats_line_omits_suppressed_when_zero() {
        let report = make_report(); // suppressed = 0
        let md = render_markdown(&report).unwrap();
        assert!(
            !md.contains("suppressed"),
            "expected no 'suppressed' in stats when zero: {md}"
        );
    }
}
