//! Shared test helper for zuit-report snapshot tests.

use std::collections::BTreeMap;
use std::path::PathBuf;

use zuit_core::analyzer::{Dimension, Severity};
use zuit_core::engine::{Report, RunStats};
use zuit_core::finding::Finding;
use zuit_core::id::AnalyzerId;
use zuit_core::score::Score;
use zuit_core::span::{ByteOffset, LineCol, Location, Span};

/// Builds a hand-crafted `Report` that covers:
///
/// - 5 findings across 3 dimensions (Security, Maintainability, Documentation)
/// - 2 files (`src/auth.rs`, `src/lib.rs`)
/// - Multiple severity levels (Critical, High, Medium, Low)
/// - Scores for all 5 v1 dimensions
/// - Non-zero `RunStats`
#[allow(clippy::too_many_lines)]
pub fn fake_report() -> Report {
    let findings = vec![
        Finding {
            analyzer: AnalyzerId::new("SEC001-hardcoded-secret"),
            dimension: Dimension::Security,
            rule_id: "SEC001-hardcoded-secret".to_string(),
            severity: Severity::Critical,
            message: "High-entropy string resembles a secret: 'AKIAIOSFODNN7EXAMPLE...'"
                .to_string(),
            location: Location {
                file: PathBuf::from("src/auth.rs"),
                span: Span::new(ByteOffset(42), ByteOffset(80)),
                start: LineCol::new(3, 15),
                end: LineCol::new(3, 53),
            },
            suggestion: Some(
                "Move credentials to environment variables or a secrets manager.".to_string(),
            ),
            references: vec!["https://docs.zuit.dev/rules/SEC001-hardcoded-secret".to_string()],
            cwe: vec!["CWE-798".to_string()],
            owasp: vec!["A07:2021".to_string()],
        },
        Finding {
            analyzer: AnalyzerId::new("SEC001-hardcoded-secret"),
            dimension: Dimension::Security,
            rule_id: "SEC001-hardcoded-secret".to_string(),
            severity: Severity::High,
            message: "JWT-like token found in source: 'eyJhbGciOiJIUzI1NiJ9...'".to_string(),
            location: Location {
                file: PathBuf::from("src/auth.rs"),
                span: Span::new(ByteOffset(120), ByteOffset(185)),
                start: LineCol::new(7, 20),
                end: LineCol::new(7, 85),
            },
            suggestion: None,
            references: vec![],
            cwe: vec!["CWE-798".to_string()],
            owasp: vec!["A07:2021".to_string()],
        },
        Finding {
            analyzer: AnalyzerId::new("MAINT001-cyclomatic"),
            dimension: Dimension::Maintainability,
            rule_id: "MAINT001-cyclomatic".to_string(),
            severity: Severity::Medium,
            message: "Function 'parse_request' has cyclomatic complexity 14 (threshold: 10)."
                .to_string(),
            location: Location {
                file: PathBuf::from("src/lib.rs"),
                span: Span::new(ByteOffset(200), ByteOffset(900)),
                start: LineCol::new(12, 1),
                end: LineCol::new(45, 2),
            },
            suggestion: Some("Extract sub-routines to reduce branching.".to_string()),
            references: vec!["https://docs.zuit.dev/rules/MAINT001-cyclomatic".to_string()],
            cwe: vec!["CWE-1121".to_string()],
            owasp: vec![],
        },
        Finding {
            analyzer: AnalyzerId::new("MAINT001-cyclomatic"),
            dimension: Dimension::Maintainability,
            rule_id: "MAINT001-cyclomatic".to_string(),
            severity: Severity::Low,
            message: "Function 'build_response' has cyclomatic complexity 11 (threshold: 10)."
                .to_string(),
            location: Location {
                file: PathBuf::from("src/lib.rs"),
                span: Span::new(ByteOffset(950), ByteOffset(1300)),
                start: LineCol::new(48, 1),
                end: LineCol::new(72, 2),
            },
            suggestion: None,
            references: vec![],
            cwe: vec!["CWE-1121".to_string()],
            owasp: vec![],
        },
        Finding {
            analyzer: AnalyzerId::new("DOC001-public-api-undoc"),
            dimension: Dimension::Documentation,
            rule_id: "DOC001-public-api-undoc".to_string(),
            severity: Severity::Medium,
            message: "Public function 'verify_token' lacks a documentation comment.".to_string(),
            location: Location {
                file: PathBuf::from("src/auth.rs"),
                span: Span::new(ByteOffset(300), ByteOffset(320)),
                start: LineCol::new(20, 1),
                end: LineCol::new(20, 21),
            },
            suggestion: Some(
                "Add a `///` doc comment explaining purpose, parameters, and return value."
                    .to_string(),
            ),
            references: vec![],
            cwe: vec!["CWE-1059".to_string()],
            owasp: vec![],
        },
    ];

    let mut scores = BTreeMap::new();
    scores.insert(Dimension::Security, Score(62.0));
    scores.insert(Dimension::Maintainability, Score(84.5));
    scores.insert(Dimension::Complexity, Score(100.0));
    scores.insert(Dimension::Documentation, Score(78.0));
    scores.insert(Dimension::TestSmell, Score(95.0));

    Report {
        schema_version: 1,
        findings,
        scores,
        stats: RunStats {
            files_scanned: 12,
            parse_failures: 1,
            elapsed_ms: 237,
            suppressed: 0,
            cache_hits: 0,
        },
    }
}
