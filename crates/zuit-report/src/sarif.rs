//! SARIF 2.1.0 formatter for zuit reports.
//!
//! Produces a single *merged run* — all findings from all analyzers are
//! combined into one `runs[0]` entry.  This is a deliberate v1 choice: the
//! `ARCH_SPEC` §7.2 notes that per-analyzer runs are *configurable*, but v1
//! ships with the simpler merged variant.  A future version can make the
//! strategy selectable via [`crate::RenderOptions`].
//!
//! ## Output structure
//!
//! ```json
//! {
//!   "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
//!   "version": "2.1.0",
//!   "runs": [
//!     {
//!       "tool": {
//!         "driver": {
//!           "name": "zuit",
//!           "version": "0.1.0",
//!           "informationUri": "https://github.com/shubhamkaushal/zuit",
//!           "rules": [ /* deduplicated, sorted by id */ ]
//!         }
//!       },
//!       "results": [ /* one per finding, sorted by (uri, line, col, ruleId) */ ]
//!     }
//!   ]
//! }
//! ```
//!
//! ## Severity → level mapping
//!
//! | zuit Severity | SARIF level  |
//! |-------------------|--------------|
//! | Critical          | `"error"`    |
//! | High              | `"error"`    |
//! | Medium            | `"warning"`  |
//! | Low               | `"note"`     |
//! | Info              | `"note"`     |
//!
//! ## Taxonomy references
//!
//! CWE and OWASP identifiers carried in findings are emitted as `taxa`
//! references on each result.  Each `taxa` entry uses the `toolComponent`
//! reference `{ "name": "CWE" }` or `{ "name": "OWASP" }` so that SARIF
//! consumers can correlate entries without requiring a full taxonomy
//! `toolComponentReference` to be registered in the run.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use zuit_core::analyzer::Severity;
use zuit_core::engine::Report;
use zuit_core::finding::Finding;

use crate::ReportError;

/// URL of the SARIF 2.1.0 JSON schema, used in the `$schema` field.
const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// SARIF version string.
const SARIF_VERSION: &str = "2.1.0";

/// The tool's canonical name.
const TOOL_NAME: &str = "zuit";

/// Public URL for the tool, used in `tool.driver.informationUri`.
const TOOL_INFORMATION_URI: &str = "https://github.com/shubhamkaushal/zuit";

/// Maps a zuit [`Severity`] to a SARIF `level` string.
///
/// | Severity         | SARIF level  |
/// |------------------|--------------|
/// | `Critical`       | `"error"`    |
/// | `High`           | `"error"`    |
/// | `Medium`         | `"warning"`  |
/// | `Low`            | `"note"`     |
/// | `Info`           | `"note"`     |
fn severity_to_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Converts a file-system path (any platform) to a POSIX-style URI string.
///
/// On Windows paths use `\` as a separator; SARIF `artifactLocation.uri`
/// must use `/`.  This function replaces every `\` with `/`.
fn path_to_uri(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Builds a deduplicated, sorted list of SARIF rule descriptors from findings.
///
/// Each unique `rule_id` across all findings becomes one entry.  When multiple
/// findings share the same rule, the *highest* severity among them is used for
/// `defaultConfiguration.level` so that the rule descriptor reflects its most
/// impactful occurrence.
///
/// Rules are sorted by `id` for deterministic output.
fn build_rules(findings: &[Finding]) -> Vec<Value> {
    // Map rule_id → highest severity seen.
    let mut rule_map: BTreeMap<&str, Severity> = BTreeMap::new();
    for f in findings {
        let entry = rule_map.entry(f.rule_id.as_str()).or_insert(f.severity);
        if f.severity > *entry {
            *entry = f.severity;
        }
    }

    rule_map
        .into_iter()
        .map(|(id, severity)| {
            json!({
                "id": id,
                "name": id,
                "shortDescription": {
                    "text": id
                },
                "defaultConfiguration": {
                    "level": severity_to_level(severity)
                }
            })
        })
        .collect()
}

/// Builds the `taxa` array for a single result from its CWE and OWASP entries.
///
/// Returns `None` when both `cwe` and `owasp` are empty, so the field can be
/// omitted from the result object entirely.
fn build_taxa(cwe: &[String], owasp: &[String]) -> Option<Value> {
    if cwe.is_empty() && owasp.is_empty() {
        return None;
    }

    let mut taxa: Vec<Value> = Vec::with_capacity(cwe.len() + owasp.len());

    for id in cwe {
        taxa.push(json!({
            "toolComponent": { "name": "CWE" },
            "id": id
        }));
    }

    for id in owasp {
        taxa.push(json!({
            "toolComponent": { "name": "OWASP" },
            "id": id
        }));
    }

    Some(Value::Array(taxa))
}

/// Converts a single [`Finding`] into a SARIF result object.
fn finding_to_result(finding: &Finding) -> Value {
    let uri = path_to_uri(&finding.location.file);
    let region = json!({
        "startLine":   finding.location.start.line,
        "startColumn": finding.location.start.column,
        "endLine":     finding.location.end.line,
        "endColumn":   finding.location.end.column,
    });

    let mut result = json!({
        "ruleId": finding.rule_id,
        "level":  severity_to_level(finding.severity),
        "message": { "text": finding.message },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": uri },
                "region": region
            }
        }]
    });

    // Emit `suggestion` under `properties` (SARIF propertyBag, §3.8) when present.
    //
    // SARIF 2.1.0 §3.55 requires every `fix` object to carry a non-empty
    // `artifactChanges` array of structured replacements (deletedRegion +
    // insertedContent). zuit's suggestions are free-form prose, not
    // machine-applicable edits, so emitting them under `fixes` made the SARIF
    // fail GitHub code-scanning's schema validator on upload. Prose remediation
    // belongs in the propertyBag — consumers that want to render it can pull
    // `result.properties.suggestion`.
    if let Some(suggestion) = &finding.suggestion {
        result["properties"] = json!({ "suggestion": suggestion });
    }

    // Emit `taxa` only when CWE or OWASP entries are present.
    if let Some(taxa) = build_taxa(&finding.cwe, &finding.owasp) {
        result["taxa"] = taxa;
    }

    result
}

/// Sort key for SARIF results: `(uri, startLine, startColumn, ruleId)`.
///
/// This matches the `ARCH_SPEC` determinism requirement while being meaningful
/// for SARIF consumers that process results in document order.
fn result_sort_key(result: &Value) -> (String, u64, u64, String) {
    let uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let line = result["locations"][0]["physicalLocation"]["region"]["startLine"]
        .as_u64()
        .unwrap_or(0);
    let col = result["locations"][0]["physicalLocation"]["region"]["startColumn"]
        .as_u64()
        .unwrap_or(0);
    let rule = result["ruleId"].as_str().unwrap_or("").to_string();
    (uri, line, col, rule)
}

/// Renders `report` as a SARIF 2.1.0 JSON string.
///
/// The output is a single merged run containing all findings from all
/// analyzers.  This is the v1 strategy; see the module-level documentation
/// for the full rationale.
///
/// ## Output determinism
///
/// - `tool.driver.rules` is sorted by rule `id`.
/// - `results` is sorted by `(artifactLocation.uri, startLine, startColumn, ruleId)`.
///
/// ## Empty reports
///
/// An empty `Report` (no findings) produces valid SARIF with empty `rules`
/// and `results` arrays.
///
/// # Errors
///
/// Returns [`ReportError::Serialize`] if `serde_json` serialization fails
/// (practically infallible for well-formed data, but propagated for
/// correctness).
pub fn render_sarif(report: &Report) -> Result<String, ReportError> {
    let rules = build_rules(&report.findings);

    let mut results: Vec<Value> = report.findings.iter().map(finding_to_result).collect();
    results.sort_by_key(result_sort_key);

    let sarif = json!({
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": TOOL_INFORMATION_URI,
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    Ok(serde_json::to_string_pretty(&sarif)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use zuit_core::analyzer::{Dimension, Severity};
    use zuit_core::engine::{Report, RunStats};
    use zuit_core::id::AnalyzerId;
    use zuit_core::score::aggregate_dimension_score;
    use zuit_core::span::{ByteOffset, LineCol, Location, Span};

    fn empty_report() -> Report {
        let mut scores = BTreeMap::new();
        for dim in [
            Dimension::Maintainability,
            Dimension::Security,
            Dimension::Complexity,
            Dimension::Documentation,
            Dimension::TestSmell,
        ] {
            scores.insert(dim, aggregate_dimension_score(&[], 1.0));
        }
        Report {
            schema_version: 1,
            findings: vec![],
            scores,
            stats: RunStats {
                files_scanned: 0,
                parse_failures: 0,
                elapsed_ms: 0,
                suppressed: 0,
                cache_hits: 0,
            },
        }
    }

    // ------------------------------------------------------------------
    // Unit tests: severity → level mapping
    // ------------------------------------------------------------------

    #[test]
    fn severity_critical_maps_to_error() {
        assert_eq!(severity_to_level(Severity::Critical), "error");
    }

    #[test]
    fn severity_high_maps_to_error() {
        assert_eq!(severity_to_level(Severity::High), "error");
    }

    #[test]
    fn severity_medium_maps_to_warning() {
        assert_eq!(severity_to_level(Severity::Medium), "warning");
    }

    #[test]
    fn severity_low_maps_to_note() {
        assert_eq!(severity_to_level(Severity::Low), "note");
    }

    #[test]
    fn severity_info_maps_to_note() {
        assert_eq!(severity_to_level(Severity::Info), "note");
    }

    // ------------------------------------------------------------------
    // Unit tests: path → URI conversion
    // ------------------------------------------------------------------

    #[test]
    fn posix_path_unchanged() {
        let p = std::path::Path::new("src/auth.rs");
        assert_eq!(path_to_uri(p), "src/auth.rs");
    }

    #[cfg(windows)]
    #[test]
    fn windows_path_converted_to_forward_slash() {
        let p = std::path::Path::new("src\\auth.rs");
        assert_eq!(path_to_uri(p), "src/auth.rs");
    }

    // ------------------------------------------------------------------
    // Unit tests: empty report edge case
    // ------------------------------------------------------------------

    #[test]
    fn empty_report_produces_valid_sarif() {
        let report = empty_report();
        let output = render_sarif(&report).expect("empty report must not fail");
        let v: serde_json::Value = serde_json::from_str(&output).expect("must be valid JSON");
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["$schema"], SARIF_SCHEMA);
        let runs = v["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        assert!(runs[0]["results"].as_array().unwrap().is_empty());
        assert!(
            runs[0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    // ------------------------------------------------------------------
    // Unit tests: taxa helpers
    // ------------------------------------------------------------------

    #[test]
    fn build_taxa_returns_none_when_empty() {
        assert!(build_taxa(&[], &[]).is_none());
    }

    #[test]
    fn build_taxa_includes_cwe_and_owasp() {
        let taxa = build_taxa(&["CWE-798".to_string()], &["A07:2021".to_string()])
            .expect("taxa must be Some");
        let arr = taxa.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["toolComponent"]["name"], "CWE");
        assert_eq!(arr[0]["id"], "CWE-798");
        assert_eq!(arr[1]["toolComponent"]["name"], "OWASP");
        assert_eq!(arr[1]["id"], "A07:2021");
    }

    // ------------------------------------------------------------------
    // Unit test: finding with suggestion emits properties.suggestion
    // ------------------------------------------------------------------

    #[test]
    fn finding_with_suggestion_emits_property() {
        let finding = zuit_core::finding::Finding {
            analyzer: AnalyzerId::new("test"),
            dimension: Dimension::Security,
            rule_id: "SEC001".to_string(),
            severity: Severity::High,
            message: "secret found".to_string(),
            location: Location {
                file: PathBuf::from("src/lib.rs"),
                span: Span::new(ByteOffset(0), ByteOffset(10)),
                start: LineCol::new(1, 1),
                end: LineCol::new(1, 11),
            },
            suggestion: Some("use env vars".to_string()),
            references: vec![],
            cwe: vec![],
            owasp: vec![],
        };
        let result = finding_to_result(&finding);
        assert_eq!(result["properties"]["suggestion"], "use env vars");
        assert!(
            result.get("fixes").is_none(),
            "fixes must never be emitted — suggestions are prose, not artifactChanges"
        );
    }

    #[test]
    fn finding_without_suggestion_omits_properties() {
        let finding = zuit_core::finding::Finding {
            analyzer: AnalyzerId::new("test"),
            dimension: Dimension::Security,
            rule_id: "SEC001".to_string(),
            severity: Severity::High,
            message: "secret found".to_string(),
            location: Location {
                file: PathBuf::from("src/lib.rs"),
                span: Span::new(ByteOffset(0), ByteOffset(10)),
                start: LineCol::new(1, 1),
                end: LineCol::new(1, 11),
            },
            suggestion: None,
            references: vec![],
            cwe: vec![],
            owasp: vec![],
        };
        let result = finding_to_result(&finding);
        assert!(
            result.get("properties").is_none(),
            "properties must be absent when suggestion is None"
        );
        assert!(result.get("fixes").is_none(), "fixes must never be emitted");
    }
}
