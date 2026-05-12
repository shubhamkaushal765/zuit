//! Parser for zuit-native NDJSON plugin output.
//!
//! Plugins that emit `output = "zuit-json"` write one JSON object per line
//! to stdout.  This module converts that raw byte stream into [`Finding`]s that
//! the rest of the zuit engine can consume.
//!
//! # Wire format
//!
//! Each non-blank line must be a JSON object with at minimum:
//!
//! ```json
//! {"rule_id":"ACME/leak","severity":"high","file":"src/a.zig","line":42,"message":"…","dimension":"security"}
//! ```
//!
//! Required keys: `rule_id`, `severity`, `file`, `line`, `message`, `dimension`.
//! Optional keys: `col`, `end_line`, `end_col`, `byte_offset_start`,
//! `byte_offset_end`, `cwe`, `owasp`, `details`.
//!
//! # Span resolution
//!
//! When both `byte_offset_start` and `byte_offset_end` are present they are
//! **authoritative** and the resulting [`Span`] is built from them directly.
//! Otherwise [`zuit_core::external::compute_span`] is called with the
//! reported `line`/`col` to derive byte offsets from the cached source file.
//!
//! # `rule_id` prefix rewriting
//!
//! If `rule_id` does not already start with `rule_id_prefix`, the prefix is
//! prepended.  Plugin authors may therefore choose either convention:
//! - emit `"leak"` → stored as `"ZIG/leak"`
//! - emit `"ZIG/leak"` → stored as-is.
//!
//! # Parse errors
//!
//! A line that fails JSON deserialization does **not** cause a panic or return
//! an error.  Instead a single Warning-level finding with
//! `rule_id = "PLUGIN/<name>-output-parse-error"` is appended to the output.
//! "Warning" maps to [`Severity::Medium`] because `zuit-core` has no
//! `Warning` variant.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use zuit_core::analyzer::{Dimension, Project, Severity};
use zuit_core::external::compute_span;
use zuit_core::finding::Finding;
use zuit_core::id::AnalyzerId;
use zuit_core::span::{ByteOffset, LineCol, Location, Span};

// ── Wire shape ────────────────────────────────────────────────────────────────

/// Internal deserialization target for one line of NDJSON plugin output.
///
/// Using a separate struct (rather than deserializing directly into [`Finding`])
/// keeps the parsing layer decoupled from the public `Finding` shape and lets
/// us apply strict field checking via `deny_unknown_fields`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFinding {
    /// Stable rule identifier emitted by the plugin (may or may not carry the prefix).
    rule_id: String,
    /// Severity level as a lowercase string (`info|low|medium|high|critical`).
    severity: Severity,
    /// Path to the file containing the finding (relative or absolute).
    file: String,
    /// One-indexed line number of the finding.
    line: u32,
    /// One-indexed column number of the finding (optional).
    #[serde(default)]
    col: Option<u32>,
    /// One-indexed end line number (optional).
    #[serde(default)]
    end_line: Option<u32>,
    /// One-indexed end column number (optional).
    #[serde(default)]
    end_col: Option<u32>,
    /// Authoritative byte offset of the start of the finding (optional).
    #[serde(default)]
    byte_offset_start: Option<u32>,
    /// Authoritative byte offset of the end of the finding (optional).
    #[serde(default)]
    byte_offset_end: Option<u32>,
    /// Human-readable message emitted by the plugin.
    message: String,
    /// Quality dimension string; unknown values become [`Dimension::Custom`].
    dimension: String,
    /// Optional remediation hint.
    #[serde(default)]
    details: Option<String>,
    /// CWE identifiers (e.g. `["CWE-401"]`).
    #[serde(default)]
    cwe: Vec<String>,
    /// OWASP categories (e.g. `["A05:2021"]`).
    #[serde(default)]
    owasp: Vec<String>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse the raw bytes of plugin stdout into a list of [`Finding`]s.
///
/// Each non-blank line of `stdout` is expected to be a JSON object matching the
/// zuit plugin wire format (see module docs).  Lines that fail to parse
/// produce a single `PLUGIN/<plugin_name>-output-parse-error` finding at
/// severity [`Severity::Medium`] (the operational "Warning" level for this
/// codebase) rather than panicking or propagating an error.
///
/// # Arguments
///
/// - `stdout` — raw bytes captured from the plugin subprocess.
/// - `project` — the project view used for source-based span resolution.
/// - `project_root` — absolute path to the project root; used to canonicalise
///   absolute file paths reported by the plugin.
/// - `plugin_name` — the plugin's install name; used to form `AnalyzerId` and
///   the parse-error rule ID.
/// - `rule_id_prefix` — prefix prepended to any `rule_id` that does not
///   already start with it (e.g. `"ZIG/"`).
#[must_use]
pub fn parse_ndjson(
    stdout: &[u8],
    project: &Project,
    project_root: &Path,
    plugin_name: &str,
    rule_id_prefix: &str,
) -> Vec<Finding> {
    let analyzer_id = AnalyzerId::new(format!("plugin/{plugin_name}"));
    let mut findings = Vec::new();

    for (line_no_zero, raw_line) in stdout.split(|&b| b == b'\n').enumerate() {
        // line_no is 1-indexed for error messages
        let line_no = line_no_zero + 1;

        // Strip optional trailing \r (handles \r\n line endings).
        let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);

        // Skip blank or whitespace-only lines.
        if raw_line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }

        match serde_json::from_slice::<RawFinding>(raw_line) {
            Ok(raw) => {
                let finding = convert_raw(
                    raw,
                    &analyzer_id,
                    project,
                    project_root,
                    rule_id_prefix,
                );
                findings.push(finding);
            }
            Err(err) => {
                findings.push(make_parse_error_finding(
                    &analyzer_id,
                    plugin_name,
                    line_no,
                    &err,
                ));
            }
        }
    }

    findings
}

// ── Conversion helpers ────────────────────────────────────────────────────────

/// Convert a successfully-parsed [`RawFinding`] into a zuit [`Finding`].
fn convert_raw(
    raw: RawFinding,
    analyzer_id: &AnalyzerId,
    project: &Project,
    project_root: &Path,
    rule_id_prefix: &str,
) -> Finding {
    // ── rule_id prefix rewriting ──────────────────────────────────────────
    let rule_id = if raw.rule_id.starts_with(rule_id_prefix) {
        raw.rule_id.clone()
    } else {
        format!("{rule_id_prefix}{}", raw.rule_id)
    };

    // ── dimension: unknown strings → Custom ──────────────────────────────
    let dimension = match raw.dimension.as_str() {
        "maintainability" => Dimension::Maintainability,
        "security" => Dimension::Security,
        "complexity" => Dimension::Complexity,
        "documentation" => Dimension::Documentation,
        "test_smell" => Dimension::TestSmell,
        other => Dimension::Custom(other.to_string()),
    };

    // ── file path canonicalisation ────────────────────────────────────────
    let file_path = canonicalise_path(&raw.file, project_root);

    // ── span resolution ───────────────────────────────────────────────────
    let col = raw.col.unwrap_or(1);
    let (span, start_lc, end_lc) =
        resolve_span(&raw, &file_path, col, project, project_root);

    Finding {
        analyzer: analyzer_id.clone(),
        dimension,
        rule_id,
        severity: raw.severity,
        message: raw.message,
        location: Location {
            file: file_path,
            span,
            start: start_lc,
            end: end_lc,
        },
        suggestion: raw.details,
        references: vec![],
        cwe: raw.cwe,
        owasp: raw.owasp,
    }
}

/// Resolve the [`Span`] and [`LineCol`] endpoints for a raw finding.
///
/// When both `byte_offset_start` and `byte_offset_end` are present, they are
/// used directly as the authoritative [`Span`].  In that case `LineCol` is
/// derived from the plugin-reported `line`/`col` values (or their defaults)
/// since we do not need to index the source file just to recover line/col.
///
/// Otherwise [`compute_span`] is called with `line`/`col` from the plugin.
fn resolve_span(
    raw: &RawFinding,
    file_path: &Path,
    col: u32,
    project: &Project,
    project_root: &Path,
) -> (Span, LineCol, LineCol) {
    if let (Some(start_off), Some(end_off)) =
        (raw.byte_offset_start, raw.byte_offset_end)
    {
        // Byte offsets are authoritative.
        let span = Span::new(ByteOffset(start_off), ByteOffset(end_off));
        let start_lc = LineCol::new(raw.line.max(1), col.max(1));
        let end_line = raw.end_line.unwrap_or(raw.line).max(1);
        let end_col = raw.end_col.unwrap_or(col).max(1);
        let end_lc = LineCol::new(end_line, end_col);
        (span, start_lc, end_lc)
    } else {
        // Derive byte offsets from source via compute_span.
        compute_span(
            project,
            project_root,
            file_path,
            &raw.file,
            raw.line,
            col,
        )
    }
}

/// Canonicalise a file path reported by a plugin.
///
/// If the raw string parses as an absolute path **and** resolving it relative
/// to `project_root` shows it lives inside the root, the returned path is the
/// relative-to-root form.  Otherwise the raw string is used as-is.
fn canonicalise_path(raw: &str, project_root: &Path) -> PathBuf {
    let p = Path::new(raw);
    if p.is_absolute() && let Ok(rel) = p.strip_prefix(project_root) {
        return rel.to_path_buf();
    }
    PathBuf::from(raw)
}

/// Build the parse-error sentinel finding appended when a line fails to parse.
///
/// Uses [`Severity::Medium`] as the operational "Warning" severity because
/// `zuit-core` has no `Warning` variant.  The location is a zero-length
/// span at line 1 col 1 in a synthetic path `"<plugin-output>"`.
fn make_parse_error_finding(
    analyzer_id: &AnalyzerId,
    plugin_name: &str,
    line_no: usize,
    err: &serde_json::Error,
) -> Finding {
    Finding {
        analyzer: analyzer_id.clone(),
        dimension: Dimension::Custom("plugin".to_string()),
        rule_id: format!("PLUGIN/{plugin_name}-output-parse-error"),
        severity: Severity::Medium,
        message: format!("failed to parse line {line_no}: {err}"),
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

    /// Helper: call [`parse_ndjson`] with sensible defaults for tests.
    fn parse(stdout: &[u8]) -> Vec<Finding> {
        let root = PathBuf::from("/proj");
        let project = empty_project(&root);
        parse_ndjson(stdout, &project, &root, "acme-zig", "ZIG/")
    }

    // ── parse_one_finding_ok ──────────────────────────────────────────────────

    #[test]
    fn parse_one_finding_ok() {
        let line = br#"{"rule_id":"ZIG/leak","severity":"high","file":"src/a.zig","line":42,"col":3,"message":"Possible memory leak","dimension":"security"}"#;
        let findings = parse(line);
        assert_eq!(findings.len(), 1, "expected exactly one finding");
        let f = &findings[0];
        assert_eq!(f.rule_id, "ZIG/leak");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.message, "Possible memory leak");
        assert_eq!(f.dimension, Dimension::Security);
        assert_eq!(f.location.file, PathBuf::from("src/a.zig"));
        assert_eq!(f.location.start, LineCol::new(42, 3));
        assert_eq!(f.analyzer, AnalyzerId::new("plugin/acme-zig"));
    }

    // ── parse_multiple_lines_ok ───────────────────────────────────────────────

    #[test]
    fn parse_multiple_lines_ok() {
        let stdout = b"\
{\"rule_id\":\"ZIG/leak\",\"severity\":\"high\",\"file\":\"src/a.zig\",\"line\":1,\"message\":\"leak\",\"dimension\":\"security\"}\n\
{\"rule_id\":\"ZIG/null\",\"severity\":\"low\",\"file\":\"src/b.zig\",\"line\":2,\"message\":\"null deref\",\"dimension\":\"security\"}\n";
        let findings = parse(stdout);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule_id, "ZIG/leak");
        assert_eq!(findings[1].rule_id, "ZIG/null");
    }

    // ── tolerates_blank_lines ─────────────────────────────────────────────────

    #[test]
    fn tolerates_blank_lines() {
        let stdout = b"\n\
{\"rule_id\":\"ZIG/leak\",\"severity\":\"medium\",\"file\":\"a.zig\",\"line\":1,\"message\":\"m\",\"dimension\":\"security\"}\n\
\n\
   \n";
        let findings = parse(stdout);
        assert_eq!(findings.len(), 1, "blank lines must be skipped");
    }

    // ── rejects_missing_required_field ────────────────────────────────────────

    #[test]
    fn rejects_missing_required_field() {
        // Missing "rule_id" — must produce a parse-error finding.
        let line = br#"{"severity":"high","file":"src/a.zig","line":1,"message":"oops","dimension":"security"}"#;
        let findings = parse(line);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.rule_id, "PLUGIN/acme-zig-output-parse-error");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.dimension, Dimension::Custom("plugin".to_string()));
        assert!(
            f.message.contains("failed to parse line"),
            "expected parse-error message, got: {}",
            f.message
        );
    }

    // ── byte_offsets_authoritative_when_present ───────────────────────────────

    #[test]
    fn byte_offsets_authoritative_when_present() {
        // Provide byte offsets that differ from what compute_span would produce.
        // Even though line=1/col=1, the span must use the explicit byte offsets.
        let line = br#"{"rule_id":"ZIG/leak","severity":"high","file":"src/a.zig","line":1,"col":1,"byte_offset_start":100,"byte_offset_end":200,"message":"leak","dimension":"security"}"#;
        let findings = parse(line);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(
            f.location.span,
            Span::new(ByteOffset(100), ByteOffset(200)),
            "byte offsets must be authoritative"
        );
    }

    // ── unknown_dimension_becomes_custom ──────────────────────────────────────

    #[test]
    fn unknown_dimension_becomes_custom() {
        let line = br#"{"rule_id":"ZIG/q","severity":"info","file":"a.zig","line":1,"message":"m","dimension":"performance"}"#;
        let findings = parse(line);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].dimension,
            Dimension::Custom("performance".to_string())
        );
    }

    // ── rule_id_prefix_applied ────────────────────────────────────────────────

    #[test]
    fn rule_id_prefix_applied() {
        // "ZIG/leak" already has the prefix → unchanged.
        let already_prefixed = br#"{"rule_id":"ZIG/leak","severity":"low","file":"a.zig","line":1,"message":"m","dimension":"security"}"#;
        // "leak" lacks the prefix → must become "ZIG/leak".
        let bare = br#"{"rule_id":"leak","severity":"low","file":"a.zig","line":1,"message":"m","dimension":"security"}"#;

        let root = PathBuf::from("/proj");
        let project = empty_project(&root);

        let f_already = parse_ndjson(already_prefixed, &project, &root, "acme-zig", "ZIG/");
        let f_bare = parse_ndjson(bare, &project, &root, "acme-zig", "ZIG/");

        assert_eq!(f_already[0].rule_id, "ZIG/leak", "pre-prefixed rule_id must stay unchanged");
        assert_eq!(f_bare[0].rule_id, "ZIG/leak", "bare rule_id must get the prefix prepended");
    }
}
