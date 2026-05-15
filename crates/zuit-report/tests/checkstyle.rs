//! Unit tests for the Checkstyle XML formatter.
//!
//! Tests are written first (TDD) and must fail before the implementation exists.

use std::collections::BTreeMap;
use std::path::PathBuf;
use zuit_core::analyzer::{Dimension, Severity};
use zuit_core::engine::{Report, RunStats};
use zuit_core::finding::Finding;
use zuit_core::id::AnalyzerId;
use zuit_core::span::{ByteOffset, LineCol, Location, Span};
use zuit_report::checkstyle::render_checkstyle;

fn make_finding(
    file: &str,
    rule: &str,
    severity: Severity,
    line: u32,
    column: u32,
    message: &str,
) -> Finding {
    Finding {
        analyzer: AnalyzerId::new(rule),
        dimension: Dimension::Security,
        rule_id: rule.to_string(),
        severity,
        message: message.to_string(),
        location: Location {
            file: PathBuf::from(file),
            span: Span::new(ByteOffset(0), ByteOffset(1)),
            start: LineCol::new(line, column),
            end: LineCol::new(line, column + 1),
        },
        suggestion: None,
        references: vec![],
        cwe: vec![],
        owasp: vec![],
    }
}

fn make_report(findings: Vec<Finding>) -> Report {
    Report {
        schema_version: 1,
        findings,
        scores: BTreeMap::new(),
        stats: RunStats {
            files_scanned: 1,
            parse_failures: 0,
            elapsed_ms: 0,
            suppressed: 0,
            cache_hits: 0,
        },
    }
}

// ── Test 1: round-trip — parse XML and assert all 3 findings are present ──────

#[test]
fn render_checkstyle_round_trip_three_findings_across_two_files() {
    let report = make_report(vec![
        make_finding(
            "src/auth.rs",
            "SEC001",
            Severity::Critical,
            42,
            5,
            "secret found",
        ),
        make_finding(
            "src/auth.rs",
            "SEC002",
            Severity::High,
            10,
            1,
            "another issue",
        ),
        make_finding(
            "src/lib.rs",
            "MAINT001",
            Severity::Medium,
            12,
            3,
            "complexity too high",
        ),
    ]);

    let xml = render_checkstyle(&report).expect("render_checkstyle must not fail");

    // Parse with quick_xml::Reader to verify structure
    let mut reader = quick_xml::Reader::from_str(&xml);
    reader.config_mut().trim_text(true);

    let mut error_count = 0;
    let mut file_count = 0;
    let mut found_line_42 = false;
    let mut found_line_10 = false;
    let mut found_line_12 = false;

    loop {
        match reader.read_event().expect("xml parse error") {
            quick_xml::events::Event::Start(e) | quick_xml::events::Event::Empty(e) => {
                match e.name().as_ref() {
                    b"file" => file_count += 1,
                    b"error" => {
                        error_count += 1;
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"line" {
                                match attr.value.as_ref() {
                                    b"42" => found_line_42 = true,
                                    b"10" => found_line_10 = true,
                                    b"12" => found_line_12 = true,
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            quick_xml::events::Event::Eof => break,
            _ => {}
        }
    }

    assert_eq!(error_count, 3, "expected 3 error elements");
    assert_eq!(
        file_count, 2,
        "expected 2 file elements (src/auth.rs and src/lib.rs)"
    );
    assert!(found_line_42, "finding at line 42 not found");
    assert!(found_line_10, "finding at line 10 not found");
    assert!(found_line_12, "finding at line 12 not found");
}

// ── Test 2: severity mapping ───────────────────────────────────────────────────

#[test]
fn render_checkstyle_severity_mapping() {
    let report = make_report(vec![
        make_finding("a.rs", "R1", Severity::Critical, 1, 1, "critical"),
        make_finding("b.rs", "R2", Severity::High, 1, 1, "high"),
        make_finding("c.rs", "R3", Severity::Medium, 1, 1, "medium"),
        make_finding("d.rs", "R4", Severity::Low, 1, 1, "low"),
        make_finding("e.rs", "R5", Severity::Info, 1, 1, "info"),
    ]);

    let xml = render_checkstyle(&report).expect("render_checkstyle must not fail");

    let mut reader = quick_xml::Reader::from_str(&xml);
    reader.config_mut().trim_text(true);

    // Collect (source, severity) pairs from error elements
    let mut severities: Vec<(String, String)> = Vec::new();

    loop {
        match reader.read_event().expect("xml parse error") {
            quick_xml::events::Event::Start(e) | quick_xml::events::Event::Empty(e) => {
                if e.name().as_ref() == b"error" {
                    let mut source = String::new();
                    let mut sev = String::new();
                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"source" => source = String::from_utf8_lossy(&attr.value).into_owned(),
                            b"severity" => sev = String::from_utf8_lossy(&attr.value).into_owned(),
                            _ => {}
                        }
                    }
                    severities.push((source, sev));
                }
            }
            quick_xml::events::Event::Eof => break,
            _ => {}
        }
    }

    // Sort by source to get deterministic order
    severities.sort_by(|a, b| a.0.cmp(&b.0));

    // R1 (Critical) → error, R2 (High) → error, R3 (Medium) → warning, R4 (Low) → info, R5 (Info) → info
    let expected = vec![
        ("zuit.R1".to_string(), "error".to_string()),
        ("zuit.R2".to_string(), "error".to_string()),
        ("zuit.R3".to_string(), "warning".to_string()),
        ("zuit.R4".to_string(), "info".to_string()),
        ("zuit.R5".to_string(), "info".to_string()),
    ];

    assert_eq!(severities, expected, "severity mapping mismatch");
}

// ── Test 3: XML escaping ───────────────────────────────────────────────────────

#[test]
fn render_checkstyle_xml_escaping() {
    let report = make_report(vec![make_finding(
        "src/main.rs",
        "SEC001",
        Severity::High,
        1,
        1,
        "<script>alert(1)</script>",
    )]);

    let xml = render_checkstyle(&report).expect("render_checkstyle must not fail");

    // The raw XML must NOT contain the unescaped characters inside attributes
    assert!(!xml.contains("<script>"), "unescaped < found in XML output");
    // Must contain the escaped form
    assert!(
        xml.contains("&lt;script&gt;"),
        "escaped form &lt;script&gt; not found in:\n{xml}"
    );
}

// ── Test 4: deterministic ordering ────────────────────────────────────────────

#[test]
fn render_checkstyle_deterministic_ordering() {
    // Findings in an intentionally unsorted order
    let findings = vec![
        make_finding("z.rs", "Z_RULE", Severity::Info, 100, 1, "z finding"),
        make_finding("a.rs", "A_RULE", Severity::High, 5, 3, "a finding"),
        make_finding(
            "a.rs",
            "A_RULE",
            Severity::High,
            2,
            1,
            "a finding earlier line",
        ),
    ];
    let report = make_report(findings);

    let xml1 = render_checkstyle(&report).expect("first call must not fail");
    let xml2 = render_checkstyle(&report).expect("second call must not fail");

    assert_eq!(
        xml1, xml2,
        "two calls on the same report must produce identical bytes"
    );

    // Also assert that a.rs appears before z.rs in the output
    let pos_a = xml1.find("a.rs").expect("a.rs not found");
    let pos_z = xml1.find("z.rs").expect("z.rs not found");
    assert!(
        pos_a < pos_z,
        "a.rs should appear before z.rs (sorted by file)"
    );

    // And line 2 appears before line 100 within a.rs
    let pos_line2 = xml1.find("line=\"2\"").expect("line 2 not found");
    let pos_line5 = xml1.find("line=\"5\"").expect("line 5 not found");
    assert!(
        pos_line2 < pos_line5,
        "line 2 should appear before line 5 within same file"
    );
}
