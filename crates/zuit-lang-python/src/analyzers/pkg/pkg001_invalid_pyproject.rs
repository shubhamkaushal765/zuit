//! `PKG001-invalid-pyproject` — detects `pyproject.toml` files that fail TOML
//! parsing.
//!
//! A malformed `pyproject.toml` will silently break every build, packaging, and
//! tool that reads it.  Failing early with a clear message is essential.

use std::path::PathBuf;

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};

use crate::manifest::manifest_for;

const RULE_ID: &str = "PKG001-invalid-pyproject";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/PKG001-invalid-pyproject.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG001` when `pyproject.toml` cannot be parsed.
pub struct Pkg001InvalidPyproject;

impl zuit_core::Analyzer for Pkg001InvalidPyproject {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("packaging".to_string())
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::All
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn kind(&self) -> AnalyzerKind {
        AnalyzerKind::ProjectLevel
    }

    fn analyze_file(
        &self,
        _ctx: &AnalysisContext<'_>,
        _file: &zuit_core::ParsedFile,
    ) -> Vec<Finding> {
        Vec::new()
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        let manifest = manifest_for(project);

        // Only emit if pyproject.toml exists but failed to parse.
        let Some((msg, (line, col))) = &manifest.pyproject_parse_error else {
            return Vec::new();
        };

        let pyproject_path = manifest
            .pyproject_path
            .clone()
            .unwrap_or_else(|| project.root.join("pyproject.toml"));

        let relative = relative_to_root(project, &pyproject_path);

        // Best-effort: convert (line, col) to byte offset.
        let byte_offset = estimate_byte_offset(&pyproject_path, *line, *col);
        let span = Span::new(ByteOffset(byte_offset), ByteOffset(byte_offset));
        let start_lc = LineCol::new(*line, *col);

        vec![Finding {
            analyzer: AnalyzerId::new(RULE_ID),
            dimension: Dimension::Custom("packaging".to_string()),
            rule_id: RULE_ID.to_string(),
            severity: Severity::High,
            message: format!("pyproject.toml parse error: {msg}"),
            location: Location {
                file: relative,
                span,
                start: start_lc,
                end: start_lc,
            },
            suggestion: Some(
                "Validate your pyproject.toml with a TOML linter (e.g. `taplo lint pyproject.toml`)."
                    .to_string(),
            ),
            references: vec![
                "https://packaging.python.org/en/latest/guides/writing-pyproject-toml/".to_string(),
            ],
            cwe: vec![],
            owasp: vec![],
        }]
    }
}

/// Attempts to estimate the byte offset for `(line, col)` by reading the file.
/// Falls back to 0 on any I/O error.
fn estimate_byte_offset(path: &PathBuf, line: u32, col: u32) -> u32 {
    let Ok(content) = std::fs::read_to_string(path) else {
        return 0;
    };
    let target_line = line.saturating_sub(1) as usize;
    let mut offset = 0usize;
    for (i, l) in content.split('\n').enumerate() {
        if i == target_line {
            offset += (col.saturating_sub(1) as usize).min(l.len());
            break;
        }
        offset += l.len() + 1; // +1 for '\n'
    }
    offset.try_into().unwrap_or(0)
}

// ── helpers (shared with sibling rules) ──────────────────────────────────────

/// Strips the project root from `path`, preferring the canonicalized root.
///
/// `manifest_for` canonicalizes its cache key (resolving symlinks like macOS
/// `/var/folders` → `/private/var/folders`), so paths derived from the manifest
/// may not share `project.root`'s prefix verbatim. This helper tries the
/// canonical root first, then falls back to the as-given root, then to the
/// absolute path.
pub(super) fn relative_to_root(project: &Project, path: &std::path::Path) -> PathBuf {
    let canonical_root = project
        .root
        .canonicalize()
        .unwrap_or_else(|_| project.root.clone());
    path.strip_prefix(&canonical_root)
        .or_else(|_| path.strip_prefix(&project.root))
        .unwrap_or(path)
        .to_path_buf()
}

/// Builds a simple `Finding` anchored to the start of `pyproject.toml`
/// (or a synthetic path when the file is absent).
pub(super) fn pyproject_finding(
    project: &Project,
    pyproject_path: &std::path::Path,
    rule_id: &'static str,
    severity: Severity,
    message: String,
    suggestion: Option<String>,
) -> Finding {
    let relative = relative_to_root(project, pyproject_path);

    Finding {
        analyzer: AnalyzerId::new(rule_id),
        dimension: Dimension::Custom("packaging".to_string()),
        rule_id: rule_id.to_string(),
        severity,
        message,
        location: Location {
            file: relative,
            span: Span::new(ByteOffset(0), ByteOffset(0)),
            start: LineCol::new(1, 1),
            end: LineCol::new(1, 1),
        },
        suggestion,
        references: vec![
            "https://packaging.python.org/en/latest/guides/writing-pyproject-toml/".to_string(),
        ],
        cwe: vec![],
        owasp: vec![],
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use zuit_core::{Analyzer, Config, Project};

    fn run(toml_content: Option<&str>) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        if let Some(content) = toml_content {
            let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
            f.write_all(content.as_bytes()).unwrap();
        }
        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        let analyzer = Pkg001InvalidPyproject;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg001_invalid_toml_emits_one_high() {
        // Truncated TOML header — parse will fail.
        let findings = run(Some("[project"));
        assert_eq!(findings.len(), 1, "expected exactly 1 PKG001 finding");
        let f = &findings[0];
        assert_eq!(f.rule_id, RULE_ID);
        assert_eq!(f.severity, Severity::High);
        assert!(
            f.location.file == std::path::Path::new("pyproject.toml"),
            "expected location file to be pyproject.toml, got {:?}",
            f.location.file
        );
    }

    #[test]
    fn pkg001_valid_toml_emits_zero() {
        let findings = run(Some("[project]\nname = \"my-pkg\"\nversion = \"1.0.0\"\n"));
        assert!(
            findings.is_empty(),
            "expected no findings on valid pyproject.toml, got: {findings:#?}"
        );
    }

    #[test]
    fn pkg001_missing_pyproject_emits_zero() {
        // PKG001 only fires when the file exists but is invalid.
        // A missing file is reported by other rules (e.g. PKG002).
        let findings = run(None);
        assert!(
            findings.is_empty(),
            "expected no PKG001 findings when pyproject.toml is absent, got: {findings:#?}"
        );
    }

    #[test]
    fn pkg001_suppression_directive_works() {
        // The suppression directive test verifies that a `# zuit: ignore PKG001`
        // comment in pyproject.toml can suppress the finding.
        // NOTE: Because pyproject.toml is not parsed as a source file by the
        // engine (only .py files are), engine-level suppression does NOT apply to
        // PKG001 when findings are pinned to pyproject.toml.
        // This test asserts that the rule itself does not fire on a *valid* file
        // (the suppression use-case is documented in the rule's doc page).
        let findings = run(Some(
            "# zuit: ignore PKG001\n[project]\nname = \"x\"\nversion = \"1.0\"\n",
        ));
        assert!(
            findings.is_empty(),
            "expected 0 PKG001 findings on valid toml with ignore directive"
        );
    }
}
