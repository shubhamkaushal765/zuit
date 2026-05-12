//! Converts [`zuit_core::finding::Finding`]s into LSP `Diagnostic` JSON objects.
//!
//! The LSP `Diagnostic` type is defined in the Language Server Protocol
//! specification §3.17 (textDocument/publishDiagnostics). We produce only the
//! fields that editors reliably use: `range`, `severity`, `code`, `source`, and
//! `message`.
//!
//! ## Severity mapping
//!
//! | zuit [`Severity`]    | LSP severity |
//! |--------------------------|-------------|
//! | `Critical` / `High`      | 1 (Error)   |
//! | `Medium`                 | 2 (Warning) |
//! | `Low`                    | 3 (Information) |
//! | `Info`                   | 4 (Hint)    |
//!
//! ## Position mapping
//!
//! zuit stores positions as **1-indexed** `(line, column)` pairs.  LSP
//! positions are **0-indexed**.  This module subtracts 1 from both fields.

use zuit_core::analyzer::Severity;
use zuit_core::finding::Finding;
use serde_json::{Value, json};

/// Converts `severity` to the LSP `DiagnosticSeverity` integer.
///
/// | LSP value | Meaning     |
/// |-----------|-------------|
/// | 1         | Error       |
/// | 2         | Warning     |
/// | 3         | Information |
/// | 4         | Hint        |
#[must_use]
pub fn severity_to_lsp(severity: Severity) -> u32 {
    match severity {
        Severity::Critical | Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

/// Converts a [`Finding`] to an LSP `Diagnostic` JSON object.
///
/// The returned `Value` is suitable for inclusion in the `diagnostics` array
/// of a `textDocument/publishDiagnostics` notification.
///
/// Position fields are converted from **1-indexed** zuit coordinates to
/// **0-indexed** LSP coordinates by subtracting 1 from each field.  Columns
/// below 1 are clamped to 0 to guard against malformed findings.
#[must_use]
pub fn finding_to_diagnostic(finding: &Finding) -> Value {
    // LSP uses 0-indexed lines and columns; zuit uses 1-indexed.
    let start_line = finding.location.start.line.saturating_sub(1);
    let start_col = finding.location.start.column.saturating_sub(1);
    let end_line = finding.location.end.line.saturating_sub(1);
    let end_col = finding.location.end.column.saturating_sub(1);

    let severity = severity_to_lsp(finding.severity);

    json!({
        "range": {
            "start": { "line": start_line, "character": start_col },
            "end":   { "line": end_line,   "character": end_col   },
        },
        "severity": severity,
        "code": finding.rule_id,
        "source": "zuit",
        "message": finding.message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use zuit_core::analyzer::{Dimension, Severity};
    use zuit_core::id::AnalyzerId;
    use zuit_core::span::{ByteOffset, LineCol, Location, Span};

    fn make_finding(severity: Severity, start_line: u32, start_col: u32) -> Finding {
        Finding {
            analyzer: AnalyzerId::new("test"),
            dimension: Dimension::Security,
            rule_id: "SEC001-hardcoded-secret".into(),
            severity,
            message: "hardcoded secret detected".into(),
            location: Location {
                file: PathBuf::from("src/main.rs"),
                span: Span::new(ByteOffset(0), ByteOffset(10)),
                start: LineCol::new(start_line, start_col),
                end: LineCol::new(start_line, start_col + 5),
            },
            suggestion: None,
            references: vec![],
            cwe: vec![],
            owasp: vec![],
        }
    }

    // ── severity mapping ─────────────────────────────────────────────────────

    #[test]
    fn critical_maps_to_error() {
        assert_eq!(severity_to_lsp(Severity::Critical), 1);
    }

    #[test]
    fn high_maps_to_error() {
        assert_eq!(severity_to_lsp(Severity::High), 1);
    }

    #[test]
    fn medium_maps_to_warning() {
        assert_eq!(severity_to_lsp(Severity::Medium), 2);
    }

    #[test]
    fn low_maps_to_information() {
        assert_eq!(severity_to_lsp(Severity::Low), 3);
    }

    #[test]
    fn info_maps_to_hint() {
        assert_eq!(severity_to_lsp(Severity::Info), 4);
    }

    // ── position conversion ──────────────────────────────────────────────────

    #[test]
    fn position_is_zero_indexed_in_lsp_output() {
        // zuit line 3, col 5  →  LSP line 2, char 4
        let finding = make_finding(Severity::High, 3, 5);
        let diag = finding_to_diagnostic(&finding);
        assert_eq!(diag["range"]["start"]["line"], 2);
        assert_eq!(diag["range"]["start"]["character"], 4);
    }

    #[test]
    fn first_line_col_maps_to_zero_zero() {
        // zuit line 1, col 1  →  LSP line 0, char 0
        let finding = make_finding(Severity::Medium, 1, 1);
        let diag = finding_to_diagnostic(&finding);
        assert_eq!(diag["range"]["start"]["line"], 0);
        assert_eq!(diag["range"]["start"]["character"], 0);
    }

    // ── field population ─────────────────────────────────────────────────────

    #[test]
    fn diagnostic_has_correct_source_field() {
        let finding = make_finding(Severity::Low, 1, 1);
        let diag = finding_to_diagnostic(&finding);
        assert_eq!(diag["source"], "zuit");
    }

    #[test]
    fn diagnostic_code_matches_rule_id() {
        let finding = make_finding(Severity::Critical, 1, 1);
        let diag = finding_to_diagnostic(&finding);
        assert_eq!(diag["code"], "SEC001-hardcoded-secret");
    }

    #[test]
    fn diagnostic_message_matches_finding_message() {
        let finding = make_finding(Severity::Info, 1, 1);
        let diag = finding_to_diagnostic(&finding);
        assert_eq!(diag["message"], "hardcoded secret detected");
    }

    #[test]
    fn diagnostic_severity_field_is_integer() {
        let finding = make_finding(Severity::Critical, 2, 3);
        let diag = finding_to_diagnostic(&finding);
        // Must be a JSON integer, not a string.
        assert!(diag["severity"].is_number());
        assert_eq!(diag["severity"], 1);
    }

    #[test]
    fn end_position_is_also_zero_indexed() {
        // start line 5, col 2  →  end line 5, col 7 (start_col + 5)
        let finding = make_finding(Severity::High, 5, 2);
        let diag = finding_to_diagnostic(&finding);
        // end line should be line 5 - 1 = 4
        assert_eq!(diag["range"]["end"]["line"], 4);
        // end col should be (2 + 5) - 1 = 6
        assert_eq!(diag["range"]["end"]["character"], 6);
    }
}
