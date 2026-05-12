//! Checkstyle XML formatter for zuit reports.
//!
//! Produces Checkstyle v8 XML that is consumed by `IntelliJ` (via the Checkstyle
//! plugin) and `SonarQube` (via `sonar.externalReportPaths.checkstyle`).
//!
//! ## Output structure
//!
//! ```xml
//! <?xml version="1.0" encoding="UTF-8"?>
//! <checkstyle version="10.0">
//!   <file name="path/to/file.rs">
//!     <error line="42" column="5" severity="error" message="..." source="zuit.SEC001"/>
//!   </file>
//! </checkstyle>
//! ```
//!
//! ## Severity mapping
//!
//! | zuit Severity | Checkstyle severity |
//! |-------------------|---------------------|
//! | Critical          | `"error"`           |
//! | High              | `"error"`           |
//! | Medium            | `"warning"`         |
//! | Low               | `"info"`            |
//! | Info              | `"info"`            |

use zuit_core::analyzer::Severity;
use zuit_core::engine::Report;
use zuit_core::finding::Finding;
use quick_xml::Writer;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, Event};

use crate::ReportError;

/// Maps a zuit [`Severity`] to a Checkstyle severity string.
fn severity_to_checkstyle(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "info",
    }
}

/// Returns the sort key for a finding: `(file, line, column, rule_id)`.
fn sort_key(f: &Finding) -> (String, u32, u32, &str) {
    (
        f.location.file.to_string_lossy().into_owned(),
        f.location.start.line,
        f.location.start.column,
        f.rule_id.as_str(),
    )
}

/// Renders `report` as a Checkstyle v8 XML string.
///
/// Findings are sorted deterministically by `(file, line, column, rule_id)`
/// and grouped by file. XML attribute values are escaped automatically by
/// `quick_xml`.
///
/// # Errors
///
/// Returns [`ReportError::Xml`] if `quick_xml` encounters an I/O or encoding
/// error (practically infallible for in-memory writes, but propagated for
/// correctness).
pub fn render_checkstyle(report: &Report) -> Result<String, ReportError> {
    // Sort findings defensively (engine may already sort, but we must guarantee
    // deterministic output regardless of input order).
    let mut sorted: Vec<&Finding> = report.findings.iter().collect();
    sorted.sort_by_key(|f| sort_key(f));

    // Group by file path string (same key used in sort, so ordering is preserved).
    let mut groups: Vec<(String, Vec<&Finding>)> = Vec::new();
    for finding in &sorted {
        let file = finding.location.file.to_string_lossy().into_owned();
        let same_file = groups.last().is_some_and(|(k, _)| k == &file);
        if same_file {
            if let Some(last) = groups.last_mut() {
                last.1.push(finding);
            }
        } else {
            groups.push((file, vec![finding]));
        }
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut writer = Writer::new(&mut buf);

    // <?xml version="1.0" encoding="UTF-8"?>
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .map_err(ReportError::Xml)?;

    // <checkstyle version="10.0">
    let mut checkstyle_elem = BytesStart::new("checkstyle");
    checkstyle_elem.push_attribute(("version", "10.0"));
    writer
        .write_event(Event::Start(checkstyle_elem))
        .map_err(ReportError::Xml)?;

    for (file_name, findings) in &groups {
        // <file name="...">
        let mut file_elem = BytesStart::new("file");
        file_elem.push_attribute(("name", file_name.as_str()));
        writer
            .write_event(Event::Start(file_elem))
            .map_err(ReportError::Xml)?;

        for finding in findings {
            let line = finding.location.start.line.to_string();
            let column = finding.location.start.column.to_string();
            let severity = severity_to_checkstyle(finding.severity);
            let source = format!("zuit.{}", finding.rule_id);

            // <error line="…" column="…" severity="…" message="…" source="…"/>
            let mut error_elem = BytesStart::new("error");
            error_elem.push_attribute(("line", line.as_str()));
            error_elem.push_attribute(("column", column.as_str()));
            error_elem.push_attribute(("severity", severity));
            error_elem.push_attribute(("message", finding.message.as_str()));
            error_elem.push_attribute(("source", source.as_str()));
            writer
                .write_event(Event::Empty(error_elem))
                .map_err(ReportError::Xml)?;
        }

        // </file>
        writer
            .write_event(Event::End(BytesEnd::new("file")))
            .map_err(ReportError::Xml)?;
    }

    // </checkstyle>
    writer
        .write_event(Event::End(BytesEnd::new("checkstyle")))
        .map_err(ReportError::Xml)?;

    String::from_utf8(buf).map_err(|e| ReportError::Xml(quick_xml::Error::from(e)))
}
