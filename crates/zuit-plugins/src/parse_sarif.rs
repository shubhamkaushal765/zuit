//! Parser for SARIF 2.1.0 plugin output (minimal subset).
//!
//! Plugins that emit `output = "sarif"` write a single SARIF JSON document to
//! stdout.  This module converts the `runs[0].results[]` array into [`Finding`]s
//! that the rest of the zuit engine can consume.
//!
//! # SARIF subset supported
//!
//! Only the minimal shape is parsed:
//!
//! ```json
//! {
//!   "runs": [{
//!     "results": [{
//!       "ruleId": "ZIG/leak",
//!       "level": "error",
//!       "message": {"text": "Possible memory leak"},
//!       "locations": [{
//!         "physicalLocation": {
//!           "artifactLocation": {"uri": "src/a.zig"},
//!           "region": {"startLine": 42, "startColumn": 3, "endLine": 42, "endColumn": 8}
//!         }
//!       }]
//!     }]
//!   }]
//! }
//! ```
//!
//! Richer SARIF fields (tool runs beyond `runs[0]`, thread flows, taxonomies,
//! etc.) are silently ignored.  The parser is intentionally tolerant: all
//! SARIF fields are treated as optional except for the top-level `runs` key —
//! a missing `runs` array is treated as a malformed document.
//!
//! # Level mapping
//!
//! | SARIF `level` | zuit [`Severity`] |
//! |---------------|----------------------|
//! | `"error"`     | [`Severity::High`]   |
//! | `"warning"`   | [`Severity::Medium`] |
//! | `"note"`      | [`Severity::Low`]    |
//! | `"none"`      | [`Severity::Info`]   |
//! | missing       | [`Severity::Info`]   |
//!
//! # Dimension
//!
//! SARIF carries no concept of quality dimension.  Every SARIF-sourced finding
//! is assigned `Dimension::Custom("plugin")` to indicate its provenance.
//!
//! # `rule_id` prefix rewriting
//!
//! If `ruleId` does not already start with `rule_id_prefix`, the prefix is
//! prepended.  Results whose `ruleId` is absent are silently skipped (the SARIF
//! spec allows omitting it for informational results).
//!
//! # Parse errors
//!
//! If the top-level `runs` field is absent (malformed SARIF), a single
//! Warning-level finding with `rule_id = "PLUGIN/<name>-output-parse-error"` is
//! returned.  [`Severity::Medium`] is used because `zuit-core` has no
//! `Warning` variant.

use std::path::{Path, PathBuf};

use zuit_core::analyzer::{Dimension, Project, Severity};
use zuit_core::external::compute_span;
use zuit_core::finding::Finding;
use zuit_core::id::AnalyzerId;
use zuit_core::span::{ByteOffset, LineCol, Location, Span};

// ── Wire shape ────────────────────────────────────────────────────────────────

/// Top-level SARIF 2.1.0 document.
///
/// Only `runs` is extracted; all other top-level SARIF fields are ignored.
#[derive(Debug, serde::Deserialize)]
struct Sarif {
    /// The array of tool runs.  Present in well-formed SARIF; absent indicates
    /// a malformed document and triggers a parse-error finding.
    runs: Option<Vec<Run>>,
}

/// One tool run within a SARIF document.
///
/// Only `results` is extracted; `tool`, `artifacts`, etc. are ignored.
#[derive(Debug, serde::Deserialize, Default)]
#[serde(default)]
struct Run {
    /// The list of results produced by the tool run.
    results: Vec<SarifResult>,
}

/// One result (finding) within a SARIF run.
///
/// All fields are optional at the deserialisation level to handle inconsistent
/// SARIF emitters.
#[derive(Debug, serde::Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct SarifResult {
    /// Stable rule identifier (e.g. `"ZIG/leak"`).  May be absent for
    /// informational results; such results are silently skipped.
    rule_id: Option<String>,
    /// Severity level string (`"error"`, `"warning"`, `"note"`, `"none"`).
    level: Option<String>,
    /// Human-readable message text.
    message: SarifMessage,
    /// Physical locations reported for this result.  Only the first element is
    /// used.
    locations: Vec<SarifLocation>,
}

/// SARIF message object.
#[derive(Debug, serde::Deserialize, Default)]
#[serde(default)]
struct SarifMessage {
    /// Plain-text message content.
    text: String,
}

/// SARIF location object.
#[derive(Debug, serde::Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct SarifLocation {
    /// Physical (file) location.
    physical_location: SarifPhysicalLocation,
}

/// SARIF physical location: maps to a file path and optional region.
#[derive(Debug, serde::Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct SarifPhysicalLocation {
    /// URI of the artifact (source file).
    artifact_location: SarifArtifactLocation,
    /// Text region within the file.
    region: SarifRegion,
}

/// SARIF artifact location: the file URI.
#[derive(Debug, serde::Deserialize, Default)]
#[serde(default)]
struct SarifArtifactLocation {
    /// Relative or absolute URI of the artifact.
    uri: String,
}

/// SARIF region: start/end line and column (all one-indexed, all optional).
#[derive(Debug, serde::Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct SarifRegion {
    /// One-indexed start line.
    start_line: Option<u32>,
    /// One-indexed start column.
    start_column: Option<u32>,
    /// One-indexed end line.
    end_line: Option<u32>,
    /// One-indexed end column.
    end_column: Option<u32>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse the raw bytes of SARIF 2.1.0 plugin stdout into a list of [`Finding`]s.
///
/// Only the `runs[0].results[]` array is processed.  All SARIF fields are
/// treated as optional at the deserialisation level to handle inconsistent
/// emitters gracefully.
///
/// A result whose `ruleId` is absent is silently skipped (SARIF spec allows
/// this for informational results).  If the top-level `runs` field is missing
/// entirely, a single parse-error finding is returned instead of panicking.
///
/// # Arguments
///
/// - `stdout` — raw bytes captured from the plugin subprocess (must be valid
///   UTF-8; invalid sequences are replaced by the JSON parser with an error).
/// - `project` — the project view used for source-based span resolution.
/// - `project_root` — absolute path to the project root; used to canonicalise
///   file paths reported in SARIF `artifactLocation.uri`.
/// - `plugin_name` — the plugin's install name; used to form [`AnalyzerId`] and
///   the parse-error rule ID.
/// - `rule_id_prefix` — prefix prepended to any `ruleId` that does not already
///   start with it (e.g. `"ZIG/"`).
#[must_use]
pub fn parse_sarif(
    stdout: &[u8],
    project: &Project,
    project_root: &Path,
    plugin_name: &str,
    rule_id_prefix: &str,
) -> Vec<Finding> {
    let analyzer_id = AnalyzerId::new(format!("plugin/{plugin_name}"));

    // Top-level parse: the whole document must be valid JSON.
    let sarif = match serde_json::from_slice::<Sarif>(stdout) {
        Ok(s) => s,
        Err(err) => {
            return vec![make_sarif_parse_error_finding(
                &analyzer_id,
                plugin_name,
                &err.to_string(),
            )];
        }
    };

    // `runs` is required.  Its absence means the document is malformed.
    let Some(runs) = sarif.runs else {
        return vec![make_sarif_parse_error_finding(
            &analyzer_id,
            plugin_name,
            "missing required field `runs`",
        )];
    };

    // Only process runs[0].
    let Some(run) = runs.into_iter().next() else {
        // An empty runs array is unusual but not an error — just no findings.
        return vec![];
    };

    let mut findings = Vec::new();

    for result in run.results {
        // ruleId is absent → skip silently per SARIF spec.
        let Some(raw_rule_id) = result.rule_id else {
            continue;
        };

        let rule_id = apply_rule_id_prefix(&raw_rule_id, rule_id_prefix);
        let severity = map_level(result.level.as_deref());

        // Extract physical location (first location entry only).
        let (file_str, start_line, start_col, end_line, end_col) =
            extract_location(result.locations);

        let file_path = canonicalise_path(&file_str, project_root);

        let (span, start_lc, _) = if file_str.is_empty() {
            // No location info — zero-length span at line 1 col 1.
            let lc = LineCol::new(1, 1);
            (Span::new(ByteOffset(0), ByteOffset(0)), lc, lc)
        } else {
            compute_span(
                project,
                project_root,
                &file_path,
                &file_str,
                start_line,
                start_col,
            )
        };

        let end_lc = LineCol::new(end_line.max(1), end_col.max(1));

        findings.push(Finding {
            analyzer: analyzer_id.clone(),
            dimension: Dimension::Custom("plugin".to_string()),
            rule_id,
            severity,
            message: result.message.text,
            location: Location {
                file: file_path,
                span,
                start: start_lc,
                end: end_lc,
            },
            suggestion: None,
            references: vec![],
            cwe: vec![],
            owasp: vec![],
        });
    }

    findings
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Map a SARIF `level` string to a zuit [`Severity`].
///
/// | SARIF `level` | [`Severity`]         |
/// |---------------|----------------------|
/// | `"error"`     | [`Severity::High`]   |
/// | `"warning"`   | [`Severity::Medium`] |
/// | `"note"`      | [`Severity::Low`]    |
/// | `"none"`      | [`Severity::Info`]   |
/// | missing/other | [`Severity::Info`]   |
fn map_level(level: Option<&str>) -> Severity {
    match level {
        Some("error") => Severity::High,
        Some("warning") => Severity::Medium,
        Some("note") => Severity::Low,
        _ => Severity::Info,
    }
}

/// Apply `rule_id_prefix` to a rule ID that does not already carry it.
fn apply_rule_id_prefix(rule_id: &str, prefix: &str) -> String {
    if rule_id.starts_with(prefix) {
        rule_id.to_string()
    } else {
        format!("{prefix}{rule_id}")
    }
}

/// Canonicalise a URI / file path from SARIF `artifactLocation.uri`.
///
/// If the raw string parses as an absolute path inside `project_root`, the
/// returned path is root-relative.  Otherwise the raw string is used as-is.
fn canonicalise_path(raw: &str, project_root: &Path) -> PathBuf {
    let p = Path::new(raw);
    if p.is_absolute()
        && let Ok(rel) = p.strip_prefix(project_root)
    {
        return rel.to_path_buf();
    }
    PathBuf::from(raw)
}

/// Extract `(file_uri, start_line, start_col, end_line, end_col)` from the
/// first SARIF location, falling back to sensible defaults when absent.
///
/// When `locations` is empty or `physicalLocation` is absent:
/// - `file_uri` → `""`
/// - `start_line` / `end_line` → `1`
/// - `start_col` / `end_col` → `1`
fn extract_location(locations: Vec<SarifLocation>) -> (String, u32, u32, u32, u32) {
    let Some(loc) = locations.into_iter().next() else {
        return (String::new(), 1, 1, 1, 1);
    };

    let phys = loc.physical_location;
    let uri = phys.artifact_location.uri;
    let region = phys.region;

    let start_line = region.start_line.unwrap_or(1).max(1);
    let start_col = region.start_column.unwrap_or(1).max(1);
    let end_line = region.end_line.unwrap_or(start_line).max(1);
    let end_col = region.end_column.unwrap_or(start_col).max(1);

    (uri, start_line, start_col, end_line, end_col)
}

/// Build the parse-error sentinel finding for malformed SARIF input.
///
/// Uses [`Severity::Medium`] as the operational "Warning" severity because
/// `zuit-core` has no `Warning` variant.  The location is a zero-length
/// span at line 1 col 1 in the synthetic path `"<plugin-output>"`.
fn make_sarif_parse_error_finding(
    analyzer_id: &AnalyzerId,
    plugin_name: &str,
    reason: &str,
) -> Finding {
    Finding {
        analyzer: analyzer_id.clone(),
        dimension: Dimension::Custom("plugin".to_string()),
        rule_id: format!("PLUGIN/{plugin_name}-output-parse-error"),
        severity: Severity::Medium,
        message: format!("failed to parse SARIF output: {reason}"),
        location: Location {
            file: PathBuf::from("<plugin-output>"),
            span: Span::new(ByteOffset(0), ByteOffset(0)),
            start: LineCol::new(1, 1),
            end: LineCol::new(1, 1),
        },
        suggestion: None,
        references: vec![],
        cwe: vec![],
        owasp: vec![],
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Build a minimal [`Project`] with no files (sufficient for parse-only tests).
    fn empty_project(root: &Path) -> Project {
        Project::new(root.to_path_buf(), vec![])
    }

    /// Call [`parse_sarif`] with sensible defaults for tests.
    fn parse(stdout: &[u8]) -> Vec<Finding> {
        let root = PathBuf::from("/proj");
        let project = empty_project(&root);
        parse_sarif(stdout, &project, &root, "acme-zig", "ZIG/")
    }

    // ── parse_minimal_run_ok ──────────────────────────────────────────────────

    #[test]
    fn parse_minimal_run_ok() {
        let sarif = br#"{
            "runs": [{
                "tool": {"driver": {"name": "my-rules"}},
                "results": [{
                    "ruleId": "ZIG/leak",
                    "level": "error",
                    "message": {"text": "Possible memory leak"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/a.zig"},
                            "region": {"startLine": 42, "startColumn": 3, "endLine": 42, "endColumn": 8}
                        }
                    }]
                }]
            }]
        }"#;

        let findings = parse(sarif);
        assert_eq!(findings.len(), 1, "expected exactly one finding");
        let f = &findings[0];
        assert_eq!(f.rule_id, "ZIG/leak");
        assert_eq!(f.severity, Severity::High, "error → High");
        assert_eq!(f.message, "Possible memory leak");
        assert_eq!(f.dimension, Dimension::Custom("plugin".to_string()));
        assert_eq!(f.location.file, PathBuf::from("src/a.zig"));
        assert_eq!(f.location.start, LineCol::new(42, 3));
        assert_eq!(f.location.end, LineCol::new(42, 8));
        assert_eq!(f.analyzer, AnalyzerId::new("plugin/acme-zig"));
    }

    // ── level_mapping ─────────────────────────────────────────────────────────

    #[test]
    fn level_mapping() {
        let make = |level: &str| -> Vec<u8> {
            format!(
                r#"{{"runs":[{{"results":[{{"ruleId":"ZIG/x","level":"{level}","message":{{"text":"m"}},"locations":[{{"physicalLocation":{{"artifactLocation":{{"uri":"a.zig"}},"region":{{"startLine":1}}}}}}]}}]}}]}}"#
            )
            .into_bytes()
        };
        let make_no_level = || -> Vec<u8> {
            br#"{"runs":[{"results":[{"ruleId":"ZIG/x","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.zig"},"region":{"startLine":1}}}]}]}]}"#.to_vec()
        };

        assert_eq!(parse(&make("error"))[0].severity, Severity::High);
        assert_eq!(parse(&make("warning"))[0].severity, Severity::Medium);
        assert_eq!(parse(&make("note"))[0].severity, Severity::Low);
        assert_eq!(parse(&make("none"))[0].severity, Severity::Info);
        assert_eq!(
            parse(&make_no_level())[0].severity,
            Severity::Info,
            "missing level → Info"
        );
    }

    // ── multiple_results_ok ───────────────────────────────────────────────────

    #[test]
    fn multiple_results_ok() {
        let sarif = br#"{
            "runs": [{
                "results": [
                    {"ruleId":"ZIG/leak","level":"error","message":{"text":"leak"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/a.zig"},"region":{"startLine":1}}}]},
                    {"ruleId":"ZIG/null","level":"warning","message":{"text":"null deref"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/b.zig"},"region":{"startLine":2}}}]},
                    {"ruleId":"ZIG/style","level":"note","message":{"text":"style issue"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/c.zig"},"region":{"startLine":3}}}]}
                ]
            }]
        }"#;

        let findings = parse(sarif);
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].rule_id, "ZIG/leak");
        assert_eq!(findings[1].rule_id, "ZIG/null");
        assert_eq!(findings[2].rule_id, "ZIG/style");
    }

    // ── tolerates_missing_locations ───────────────────────────────────────────

    #[test]
    fn tolerates_missing_locations() {
        let sarif = br#"{"runs":[{"results":[{"ruleId":"ZIG/x","level":"note","message":{"text":"no loc"}}]}]}"#;
        let findings = parse(sarif);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(
            f.location.file,
            PathBuf::from(""),
            "no location → empty file path"
        );
        assert_eq!(
            f.location.start,
            LineCol::new(1, 1),
            "no location → line 1 col 1"
        );
        assert_eq!(f.location.span, Span::new(ByteOffset(0), ByteOffset(0)));
    }

    // ── rule_id_prefix_applied ────────────────────────────────────────────────

    #[test]
    fn rule_id_prefix_applied() {
        // Already-prefixed: must stay unchanged.
        let already = br#"{"runs":[{"results":[{"ruleId":"ZIG/leak","level":"error","message":{"text":"m"}}]}]}"#;
        // Bare (no prefix): must get prefix prepended.
        let bare = br#"{"runs":[{"results":[{"ruleId":"leak","level":"error","message":{"text":"m"}}]}]}"#;

        let root = PathBuf::from("/proj");
        let project = empty_project(&root);

        let f_already = parse_sarif(already, &project, &root, "acme-zig", "ZIG/");
        let f_bare = parse_sarif(bare, &project, &root, "acme-zig", "ZIG/");

        assert_eq!(
            f_already[0].rule_id,
            "ZIG/leak",
            "pre-prefixed rule_id must stay unchanged"
        );
        assert_eq!(
            f_bare[0].rule_id,
            "ZIG/leak",
            "bare rule_id must get prefix prepended"
        );
    }

    // ── rejects_missing_runs ──────────────────────────────────────────────────

    #[test]
    fn rejects_missing_runs() {
        // Valid JSON but `runs` field is absent → parse-error finding, no panic.
        let sarif = br#"{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0"}"#;
        let findings = parse(sarif);
        assert_eq!(
            findings.len(),
            1,
            "missing `runs` must produce exactly one parse-error finding"
        );
        let f = &findings[0];
        assert_eq!(f.rule_id, "PLUGIN/acme-zig-output-parse-error");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.dimension, Dimension::Custom("plugin".to_string()));
        assert!(
            f.message.contains("missing required field `runs`"),
            "expected runs-missing message, got: {}",
            f.message
        );
    }
}
