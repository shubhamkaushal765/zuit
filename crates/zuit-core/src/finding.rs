//! [`Finding`]: a single diagnostic emitted by an [`crate::analyzer::Analyzer`].
//!
//! The deterministic sort order for findings is `(file, span.start, rule_id)`,
//! as required by `ARCH_SPEC` §10.

use serde::{Deserialize, Serialize};

use crate::analyzer::{Dimension, Severity};
use crate::id::AnalyzerId;
use crate::span::Location;

/// A single diagnostic produced by an analyzer for one location in one file.
///
/// Findings are sorted by `(location.file, location.span.start, rule_id)` before
/// any output is produced. This ensures deterministic reports regardless of the
/// order in which parallel workers return results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Identifier of the analyzer that produced this finding.
    pub analyzer: AnalyzerId,
    /// Quality dimension this finding addresses.
    pub dimension: Dimension,
    /// Stable rule identifier (e.g. `"MAINT001-cyclomatic"`).
    pub rule_id: String,
    /// How severe the finding is.
    pub severity: Severity,
    /// Human-readable explanation of what was found.
    pub message: String,
    /// Precise location in the source file.
    pub location: Location,
    /// Optional suggestion for how to fix the issue.
    pub suggestion: Option<String>,
    /// Free-form links to external documentation (rule pages, vendor advisories).
    ///
    /// Use [`Self::cwe`] / [`Self::owasp`] for structured taxonomy IDs; this
    /// field is for arbitrary URLs that don't fit a known scheme.
    pub references: Vec<String>,
    /// CWE identifiers this finding maps to (e.g. `["CWE-798"]`).
    ///
    /// Populated from the analyzer's [`crate::analyzer::RuleMeta::cwe`].
    /// Omitted from JSON when empty so existing consumers see no extra field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    /// OWASP categories this finding maps to (e.g. `["A07:2021"]`).
    ///
    /// Populated from the analyzer's [`crate::analyzer::RuleMeta::owasp`].
    /// Omitted from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owasp: Vec<String>,
}

impl Finding {
    /// Returns the sort key used for deterministic output ordering.
    ///
    /// The key is `(&file_path, span.start_byte, &rule_id)`, matching `ARCH_SPEC` §10.
    fn sort_key(&self) -> (&std::path::Path, u32, &str) {
        (
            &self.location.file,
            self.location.span.start.0,
            &self.rule_id,
        )
    }
}

impl PartialOrd for Finding {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Finding {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sort_key().cmp(&other.sort_key())
    }
}

/// Sorts a slice of [`Finding`]s in-place using the canonical order
/// `(file, span.start, rule_id)`.
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::analyzer::{Dimension, Severity};
    use crate::id::AnalyzerId;
    use crate::span::{ByteOffset, LineCol, Location, Span};

    fn make_finding(file: &str, start: u32, rule: &str) -> Finding {
        Finding {
            analyzer: AnalyzerId::new("test"),
            dimension: Dimension::Maintainability,
            rule_id: rule.to_string(),
            severity: Severity::Medium,
            message: "test".to_string(),
            location: Location {
                file: PathBuf::from(file),
                span: Span::new(ByteOffset(start), ByteOffset(start + 1)),
                start: LineCol::new(1, 1),
                end: LineCol::new(1, 2),
            },
            suggestion: None,
            references: vec![],
            cwe: vec![],
            owasp: vec![],
        }
    }

    #[test]
    fn sort_by_file_then_offset_then_rule_id() {
        let mut findings = vec![
            make_finding("b.rs", 0, "RULE-Z"),
            make_finding("a.rs", 10, "RULE-A"),
            make_finding("a.rs", 5, "RULE-B"),
            make_finding("a.rs", 5, "RULE-A"),
        ];
        sort_findings(&mut findings);
        assert_eq!(findings[0].location.file, PathBuf::from("a.rs"));
        assert_eq!(findings[0].location.span.start, ByteOffset(5));
        assert_eq!(findings[0].rule_id, "RULE-A");

        assert_eq!(findings[1].rule_id, "RULE-B");
        assert_eq!(findings[2].location.span.start, ByteOffset(10));
        assert_eq!(findings[3].location.file, PathBuf::from("b.rs"));
    }

    #[test]
    fn finding_serde_round_trip() {
        let f = make_finding("src/lib.rs", 42, "MAINT001-cyclomatic");
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }
}
