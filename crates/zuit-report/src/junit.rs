//! `JUnit` XML formatter for zuit reports.
//!
//! Produces `JUnit` XML in the Surefire/Maven flavour that is consumed by
//! GitHub Actions (`junit-test-summary` and similar actions), Jenkins, and
//! GitLab CI.
//!
//! ## Output structure
//!
//! ```xml
//! <?xml version="1.0" encoding="UTF-8"?>
//! <testsuites name="zuit" tests="N" failures="F" errors="E" time="0">
//!   <testsuite name="security" tests="N" failures="F" errors="E" time="0">
//!     <testcase name="SEC001 at src/main.rs:42" classname="src/main.rs" time="0">
//!       <failure message="hardcoded secret" type="SEC001">
//! File: src/main.rs
//! Line: 42
//! Severity: high
//! CWE: CWE-798
//! </failure>
//!     </testcase>
//!   </testsuite>
//! </testsuites>
//! ```
//!
//! ## Severity mapping
//!
//! | zuit Severity | JUnit element |
//! |-------------------|---------------|
//! | Critical          | `<error>`     |
//! | High              | `<error>`     |
//! | Medium            | `<failure>`   |
//! | Low               | `<failure>`   |
//! | Info              | (none — bare `<testcase>`) |

use std::fmt::Write as _;

use zuit_core::analyzer::{Dimension, Severity};
use zuit_core::engine::Report;
use zuit_core::finding::Finding;
use quick_xml::Writer;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};

use crate::ReportError;

/// Returns the display name for a dimension as used in the `<testsuite name>`
/// attribute.
fn dimension_name(dim: &Dimension) -> String {
    match dim {
        Dimension::Maintainability => "maintainability".to_string(),
        Dimension::Security => "security".to_string(),
        Dimension::Complexity => "complexity".to_string(),
        Dimension::Documentation => "documentation".to_string(),
        Dimension::TestSmell => "test_smell".to_string(),
        Dimension::Custom(s) => s.clone(),
    }
}

/// Returns the sort key for a finding: `(dimension, file, line, column, rule_id)`.
fn sort_key(f: &Finding) -> (Dimension, String, u32, u32, &str) {
    (
        f.dimension.clone(),
        f.location.file.to_string_lossy().into_owned(),
        f.location.start.line,
        f.location.start.column,
        f.rule_id.as_str(),
    )
}

/// The `JUnit` child element type for a finding based on its severity.
enum JunitOutcome {
    /// `<error>` element — Critical or High severity.
    Error,
    /// `<failure>` element — Medium or Low severity.
    Failure,
    /// No child element — Info severity.
    Pass,
}

/// Maps a [`Severity`] to the `JUnit` outcome type.
fn severity_to_outcome(severity: Severity) -> JunitOutcome {
    match severity {
        Severity::Critical | Severity::High => JunitOutcome::Error,
        Severity::Medium | Severity::Low => JunitOutcome::Failure,
        Severity::Info => JunitOutcome::Pass,
    }
}

/// Builds the text content of a `<failure>` or `<error>` element for `finding`.
fn element_body(finding: &Finding) -> String {
    let mut body = String::new();
    let file = finding.location.file.to_string_lossy();
    // String's Write impl is infallible — the `let _ =` silences the unused-result warning.
    let _ = writeln!(body, "File: {file}");
    let _ = writeln!(body, "Line: {}", finding.location.start.line);
    let sev_str = match finding.severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    };
    let _ = writeln!(body, "Severity: {sev_str}");
    if !finding.cwe.is_empty() {
        let _ = writeln!(body, "CWE: {}", finding.cwe.join(", "));
    }
    if !finding.owasp.is_empty() {
        let _ = writeln!(body, "OWASP: {}", finding.owasp.join(", "));
    }
    if let Some(ref suggestion) = finding.suggestion {
        let _ = writeln!(body, "Suggestion: {suggestion}");
    }
    body
}

/// Renders `report` as a `JUnit` XML string (Surefire/Maven flavour).
///
/// Findings are grouped by [`Dimension`] into separate `<testsuite>` elements
/// and sorted deterministically by `(dimension, file, line, column, rule_id)`.
/// XML attribute values are escaped automatically by `quick_xml`.
///
/// # Errors
///
/// Returns [`ReportError::Xml`] if `quick_xml` encounters an I/O or encoding
/// error (practically infallible for in-memory writes, but propagated for
/// correctness).
#[allow(clippy::too_many_lines)] // XML writer is inherently sequential; extraction adds no clarity
pub fn render_junit(report: &Report) -> Result<String, ReportError> {
    // Sort findings defensively (engine may already sort, but we must guarantee
    // deterministic output regardless of input order).
    let mut sorted: Vec<&Finding> = report.findings.iter().collect();
    sorted.sort_by_key(|f| sort_key(f));

    // Group by dimension, preserving sort order within each group.
    let mut groups: Vec<(Dimension, Vec<&Finding>)> = Vec::new();
    for finding in &sorted {
        let dim = &finding.dimension;
        let same_dim = groups.last().is_some_and(|(k, _)| k == dim);
        if same_dim {
            if let Some(last) = groups.last_mut() {
                last.1.push(finding);
            }
        } else {
            groups.push((dim.clone(), vec![finding]));
        }
    }

    // Compute top-level counts.
    let total_tests: usize = sorted.len();
    let total_failures: usize = sorted
        .iter()
        .filter(|f| matches!(severity_to_outcome(f.severity), JunitOutcome::Failure))
        .count();
    let total_errors: usize = sorted
        .iter()
        .filter(|f| matches!(severity_to_outcome(f.severity), JunitOutcome::Error))
        .count();

    let mut buf: Vec<u8> = Vec::new();
    let mut writer = Writer::new(&mut buf);

    // <?xml version="1.0" encoding="UTF-8"?>
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .map_err(ReportError::Xml)?;

    // <testsuites name="zuit" tests="N" failures="F" errors="E" time="0">
    let mut root = BytesStart::new("testsuites");
    root.push_attribute(("name", "zuit"));
    root.push_attribute(("tests", total_tests.to_string().as_str()));
    root.push_attribute(("failures", total_failures.to_string().as_str()));
    root.push_attribute(("errors", total_errors.to_string().as_str()));
    root.push_attribute(("time", "0"));
    writer
        .write_event(Event::Start(root))
        .map_err(ReportError::Xml)?;

    for (dim, findings) in &groups {
        let suite_tests = findings.len();
        let suite_failures = findings
            .iter()
            .filter(|f| matches!(severity_to_outcome(f.severity), JunitOutcome::Failure))
            .count();
        let suite_errors = findings
            .iter()
            .filter(|f| matches!(severity_to_outcome(f.severity), JunitOutcome::Error))
            .count();

        // <testsuite name="<dim>" tests="N" failures="F" errors="E" time="0">
        let mut suite = BytesStart::new("testsuite");
        suite.push_attribute(("name", dimension_name(dim).as_str()));
        suite.push_attribute(("tests", suite_tests.to_string().as_str()));
        suite.push_attribute(("failures", suite_failures.to_string().as_str()));
        suite.push_attribute(("errors", suite_errors.to_string().as_str()));
        suite.push_attribute(("time", "0"));
        writer
            .write_event(Event::Start(suite))
            .map_err(ReportError::Xml)?;

        for finding in findings {
            let file = finding.location.file.to_string_lossy();
            let line = finding.location.start.line;
            let tc_name = format!("{} at {}:{}", finding.rule_id, file, line);

            // <testcase name="…" classname="…" time="0">
            let mut tc = BytesStart::new("testcase");
            tc.push_attribute(("name", tc_name.as_str()));
            tc.push_attribute(("classname", file.as_ref()));
            tc.push_attribute(("time", "0"));
            writer
                .write_event(Event::Start(tc))
                .map_err(ReportError::Xml)?;

            match severity_to_outcome(finding.severity) {
                JunitOutcome::Pass => {
                    // No child element — bare testcase (informational pass).
                }
                JunitOutcome::Failure => {
                    // <failure message="…" type="…">…</failure>
                    let mut fail_elem = BytesStart::new("failure");
                    fail_elem.push_attribute(("message", finding.message.as_str()));
                    fail_elem.push_attribute(("type", finding.rule_id.as_str()));
                    writer
                        .write_event(Event::Start(fail_elem))
                        .map_err(ReportError::Xml)?;
                    let body = element_body(finding);
                    writer
                        .write_event(Event::Text(BytesText::new(&body)))
                        .map_err(ReportError::Xml)?;
                    writer
                        .write_event(Event::End(BytesEnd::new("failure")))
                        .map_err(ReportError::Xml)?;
                }
                JunitOutcome::Error => {
                    // <error message="…" type="…">…</error>
                    let mut err_elem = BytesStart::new("error");
                    err_elem.push_attribute(("message", finding.message.as_str()));
                    err_elem.push_attribute(("type", finding.rule_id.as_str()));
                    writer
                        .write_event(Event::Start(err_elem))
                        .map_err(ReportError::Xml)?;
                    let body = element_body(finding);
                    writer
                        .write_event(Event::Text(BytesText::new(&body)))
                        .map_err(ReportError::Xml)?;
                    writer
                        .write_event(Event::End(BytesEnd::new("error")))
                        .map_err(ReportError::Xml)?;
                }
            }

            // </testcase>
            writer
                .write_event(Event::End(BytesEnd::new("testcase")))
                .map_err(ReportError::Xml)?;
        }

        // </testsuite>
        writer
            .write_event(Event::End(BytesEnd::new("testsuite")))
            .map_err(ReportError::Xml)?;
    }

    // </testsuites>
    writer
        .write_event(Event::End(BytesEnd::new("testsuites")))
        .map_err(ReportError::Xml)?;

    String::from_utf8(buf).map_err(|e| ReportError::Xml(quick_xml::Error::from(e)))
}

// ── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use zuit_core::Finding;
    use zuit_core::analyzer::{Dimension, Severity};
    use zuit_core::engine::{Report, RunStats};
    use zuit_core::id::AnalyzerId;
    use zuit_core::span::{ByteOffset, LineCol, Location, Span};
    use quick_xml::Reader;
    use quick_xml::events::Event as XmlEvent;

    use super::*;

    /// Builds a minimal [`Report`] with no findings.
    fn empty_report() -> Report {
        Report {
            schema_version: 1,
            findings: vec![],
            scores: BTreeMap::new(),
            stats: RunStats {
                files_scanned: 0,
                parse_failures: 0,
                elapsed_ms: 0,
                suppressed: 0,
                cache_hits: 0,
            },
        }
    }

    /// Wraps a vec of findings in a minimal [`Report`].
    fn report_with(findings: Vec<Finding>) -> Report {
        let mut r = empty_report();
        r.findings = findings;
        r
    }

    /// Constructs a [`Finding`] with the given parameters.
    #[allow(clippy::too_many_arguments)]
    fn make_finding(
        rule: &str,
        sev: Severity,
        dim: Dimension,
        file: &str,
        line: u32,
        message: &str,
        cwe: Vec<&str>,
        owasp: Vec<&str>,
        suggestion: Option<&str>,
    ) -> Finding {
        Finding {
            analyzer: AnalyzerId::new("test"),
            dimension: dim,
            rule_id: rule.to_string(),
            severity: sev,
            message: message.to_string(),
            location: Location {
                file: PathBuf::from(file),
                span: Span::new(ByteOffset(0), ByteOffset(1)),
                start: LineCol::new(line, 1),
                end: LineCol::new(line, 2),
            },
            suggestion: suggestion.map(String::from),
            references: vec![],
            cwe: cwe.into_iter().map(String::from).collect(),
            owasp: owasp.into_iter().map(String::from).collect(),
        }
    }

    /// Parses an XML string with `quick_xml` and returns all start-element names
    /// encountered, in order.
    fn element_names(xml: &str) -> Vec<String> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(false);
        let mut names = Vec::new();
        loop {
            match reader.read_event() {
                Ok(XmlEvent::Start(e) | XmlEvent::Empty(e)) => {
                    names.push(String::from_utf8_lossy(e.name().as_ref()).into_owned());
                }
                Ok(XmlEvent::Eof) => break,
                Err(e) => panic!("XML parse error: {e}"),
                _ => {}
            }
        }
        names
    }

    /// Returns the value of `attr` on the root element of `xml`.
    fn root_attr(xml: &str, attr: &str) -> Option<String> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(false);
        loop {
            match reader.read_event() {
                Ok(XmlEvent::Start(e) | XmlEvent::Empty(e)) => {
                    for a in e.attributes().flatten() {
                        if a.key.as_ref() == attr.as_bytes() {
                            return Some(String::from_utf8_lossy(&a.value).into_owned());
                        }
                    }
                    return None; // first element only
                }
                Ok(XmlEvent::Eof) => return None,
                Err(e) => panic!("XML parse error: {e}"),
                _ => {}
            }
        }
    }

    /// Counts how many `<testsuite>` start elements appear in `xml`.
    fn count_testsuites(xml: &str) -> usize {
        element_names(xml)
            .into_iter()
            .filter(|n| n == "testsuite")
            .count()
    }

    /// Collects all attribute values for `attr` across all `<testsuite>` elements.
    fn testsuite_attr_values(xml: &str, attr: &str) -> Vec<String> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(false);
        let mut values = Vec::new();
        loop {
            match reader.read_event() {
                Ok(XmlEvent::Start(e)) if e.name().as_ref() == b"testsuite" => {
                    for a in e.attributes().flatten() {
                        if a.key.as_ref() == attr.as_bytes() {
                            values.push(String::from_utf8_lossy(&a.value).into_owned());
                        }
                    }
                }
                Ok(XmlEvent::Eof) => break,
                Err(e) => panic!("XML parse error: {e}"),
                _ => {}
            }
        }
        values
    }

    // ── 1. Smoke / well-formed XML round-trip ────────────────────────────────

    /// Renders a report with one finding per severity tier to a string and
    /// re-parses it with `quick_xml` to verify it is well-formed XML.  Also
    /// checks that the root element is `testsuites` and carries the expected
    /// aggregate counts.
    #[test]
    fn junit_round_trip_smoke() {
        let findings = vec![
            make_finding(
                "RULE-CRITICAL",
                Severity::Critical,
                Dimension::Security,
                "src/a.rs",
                1,
                "critical finding",
                vec!["CWE-798"],
                vec![],
                None,
            ),
            make_finding(
                "RULE-HIGH",
                Severity::High,
                Dimension::Security,
                "src/b.rs",
                2,
                "high finding",
                vec![],
                vec![],
                None,
            ),
            make_finding(
                "RULE-MEDIUM",
                Severity::Medium,
                Dimension::Maintainability,
                "src/c.rs",
                3,
                "medium finding",
                vec![],
                vec![],
                None,
            ),
            make_finding(
                "RULE-LOW",
                Severity::Low,
                Dimension::Maintainability,
                "src/d.rs",
                4,
                "low finding",
                vec![],
                vec![],
                None,
            ),
            make_finding(
                "RULE-INFO",
                Severity::Info,
                Dimension::Documentation,
                "src/e.rs",
                5,
                "info finding",
                vec![],
                vec![],
                None,
            ),
        ];
        let report = report_with(findings);
        let xml = render_junit(&report).expect("render must succeed");

        // Must start with an XML declaration.
        assert!(
            xml.starts_with("<?xml"),
            "must start with <?xml, got: {xml}"
        );

        // Re-parse to confirm well-formedness.
        let names = element_names(&xml);
        assert_eq!(names[0], "testsuites", "root element must be testsuites");

        // counts: 5 tests, 2 failures (medium+low), 2 errors (critical+high)
        let tests = root_attr(&xml, "tests").expect("tests attr");
        let failures = root_attr(&xml, "failures").expect("failures attr");
        let errors = root_attr(&xml, "errors").expect("errors attr");

        assert_eq!(tests, "5", "tests count mismatch");
        assert_eq!(failures, "2", "failures count mismatch");
        assert_eq!(errors, "2", "errors count mismatch");
    }

    // ── 2. Severity → JUnit element mapping ─────────────────────────────────

    /// Verifies that High/Critical map to `<error>`, Medium/Low map to
    /// `<failure>`, and Info produces a bare `<testcase>` with no child.
    #[test]
    fn junit_severity_mapping() {
        let xml_for = |sev: Severity| {
            let f = make_finding(
                "RULE",
                sev,
                Dimension::Security,
                "f.rs",
                1,
                "msg",
                vec![],
                vec![],
                None,
            );
            render_junit(&report_with(vec![f])).expect("render")
        };

        // High → <error>
        let xml = xml_for(Severity::High);
        assert!(
            xml.contains("<error "),
            "High must produce <error>, xml: {xml}"
        );

        // Critical → <error>
        let xml = xml_for(Severity::Critical);
        assert!(
            xml.contains("<error "),
            "Critical must produce <error>, xml: {xml}"
        );

        // Medium → <failure>
        let xml = xml_for(Severity::Medium);
        assert!(
            xml.contains("<failure "),
            "Medium must produce <failure>, xml: {xml}"
        );

        // Low → <failure>
        let xml = xml_for(Severity::Low);
        assert!(
            xml.contains("<failure "),
            "Low must produce <failure>, xml: {xml}"
        );

        // Info → no <failure> or <error> child
        let xml = xml_for(Severity::Info);
        assert!(
            !xml.contains("<failure") && !xml.contains("<error"),
            "Info must produce bare <testcase>, xml: {xml}"
        );
        assert!(
            xml.contains("<testcase "),
            "Info must still produce <testcase>, xml: {xml}"
        );
    }

    // ── 3. XML attribute escaping ────────────────────────────────────────────

    /// A finding whose message contains `&`, `<`, `"`, and `'` must produce
    /// well-formed XML — `quick_xml` escapes these characters automatically.
    #[test]
    fn junit_xml_attribute_escaping() {
        let f = make_finding(
            "RULE-ESC",
            Severity::Medium,
            Dimension::Security,
            "src/a.rs",
            1,
            r#"found: a & b < c > "d" 'e'"#,
            vec![],
            vec![],
            None,
        );
        let xml = render_junit(&report_with(vec![f])).expect("render");

        // Must be re-parseable (i.e. well-formed).
        let _names = element_names(&xml); // panics if malformed
        assert!(xml.starts_with("<?xml"), "must start with <?xml");
    }

    // ── 4. Deterministic ordering ────────────────────────────────────────────

    /// Findings inserted in reverse order must produce byte-identical output
    /// compared to the sorted order.
    #[test]
    fn junit_deterministic_ordering() {
        let mut findings = vec![
            make_finding(
                "RULE-C",
                Severity::Medium,
                Dimension::Security,
                "c.rs",
                10,
                "msg",
                vec![],
                vec![],
                None,
            ),
            make_finding(
                "RULE-A",
                Severity::Medium,
                Dimension::Security,
                "a.rs",
                1,
                "msg",
                vec![],
                vec![],
                None,
            ),
            make_finding(
                "RULE-B",
                Severity::Medium,
                Dimension::Security,
                "b.rs",
                5,
                "msg",
                vec![],
                vec![],
                None,
            ),
        ];

        let xml1 = render_junit(&report_with(findings.clone())).expect("render1");

        findings.reverse();
        let xml2 = render_junit(&report_with(findings)).expect("render2");

        assert_eq!(
            xml1, xml2,
            "output must be byte-identical regardless of input order"
        );
    }

    // ── 5. Grouping by dimension ─────────────────────────────────────────────

    /// Findings spanning two dimensions must produce two `<testsuite>` elements
    /// in canonical Dimension order (Maintainability < Security per derived Ord).
    #[test]
    fn junit_grouping_by_dimension() {
        let findings = vec![
            make_finding(
                "SEC001",
                Severity::High,
                Dimension::Security,
                "s.rs",
                1,
                "sec",
                vec![],
                vec![],
                None,
            ),
            make_finding(
                "MAINT001",
                Severity::Medium,
                Dimension::Maintainability,
                "m.rs",
                1,
                "maint",
                vec![],
                vec![],
                None,
            ),
        ];
        let xml = render_junit(&report_with(findings)).expect("render");

        assert_eq!(
            count_testsuites(&xml),
            2,
            "expected exactly 2 testsuite elements"
        );

        // Suites must appear in canonical order: Maintainability before Security.
        let names = testsuite_attr_values(&xml, "name");
        assert_eq!(
            names,
            vec!["maintainability", "security"],
            "suites must be in canonical Dimension order"
        );
    }

    // ── 6. Counter accuracy ──────────────────────────────────────────────────

    /// The `tests`, `failures`, and `errors` attributes on both
    /// `<testsuites>` and `<testsuite>` must match the actual child counts.
    #[test]
    fn junit_counts_match() {
        let findings = vec![
            make_finding(
                "R1",
                Severity::Critical,
                Dimension::Security,
                "a.rs",
                1,
                "m",
                vec![],
                vec![],
                None,
            ),
            make_finding(
                "R2",
                Severity::High,
                Dimension::Security,
                "b.rs",
                2,
                "m",
                vec![],
                vec![],
                None,
            ),
            make_finding(
                "R3",
                Severity::Medium,
                Dimension::Security,
                "c.rs",
                3,
                "m",
                vec![],
                vec![],
                None,
            ),
            make_finding(
                "R4",
                Severity::Low,
                Dimension::Security,
                "d.rs",
                4,
                "m",
                vec![],
                vec![],
                None,
            ),
            make_finding(
                "R5",
                Severity::Info,
                Dimension::Security,
                "e.rs",
                5,
                "m",
                vec![],
                vec![],
                None,
            ),
        ];
        let xml = render_junit(&report_with(findings)).expect("render");

        // Root <testsuites> counts.
        let tests = root_attr(&xml, "tests").expect("tests");
        let failures = root_attr(&xml, "failures").expect("failures");
        let errors = root_attr(&xml, "errors").expect("errors");
        assert_eq!(tests, "5", "total tests");
        assert_eq!(failures, "2", "total failures (Medium + Low)");
        assert_eq!(errors, "2", "total errors (Critical + High)");

        // There's one testsuite; verify its counts match.
        let suite_tests = testsuite_attr_values(&xml, "tests");
        let suite_failures = testsuite_attr_values(&xml, "failures");
        let suite_errors = testsuite_attr_values(&xml, "errors");

        assert_eq!(suite_tests, vec!["5"], "suite tests");
        assert_eq!(suite_failures, vec!["2"], "suite failures");
        assert_eq!(suite_errors, vec!["2"], "suite errors");
    }

    // ── 7. Empty report ──────────────────────────────────────────────────────

    /// A report with zero findings must produce a well-formed `<testsuites>`
    /// with zero counts and no child `<testsuite>` elements.
    #[test]
    fn junit_empty_report() {
        let xml = render_junit(&empty_report()).expect("render");

        assert!(xml.starts_with("<?xml"), "must start with <?xml");

        let names = element_names(&xml);
        assert_eq!(names, vec!["testsuites"], "only the root element");

        let tests = root_attr(&xml, "tests").expect("tests");
        let failures = root_attr(&xml, "failures").expect("failures");
        let errors = root_attr(&xml, "errors").expect("errors");
        assert_eq!(tests, "0", "tests must be 0");
        assert_eq!(failures, "0", "failures must be 0");
        assert_eq!(errors, "0", "errors must be 0");
    }
}
