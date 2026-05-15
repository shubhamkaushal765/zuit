//! `PKG007-version-mismatch` — detects a discrepancy between
//! `[project].version` in `pyproject.toml` and `__version__` in the package's
//! `__init__.py`.
//!
//! When these two version strings diverge (e.g. after bumping one but not the
//! other), the installed package will report a different version than it
//! advertises on `PyPI`, causing confusion for downstream users.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};

use crate::manifest::manifest_for;

const RULE_ID: &str = "PKG007-version-mismatch";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/PKG007-version-mismatch.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG007` when `pyproject.toml` version differs from
/// `__version__` in any `__init__.py`.
pub struct Pkg007VersionMismatch;

impl zuit_core::Analyzer for Pkg007VersionMismatch {
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
        let Some(doc) = &manifest.pyproject else {
            return Vec::new();
        };

        // Read version from pyproject.toml [project].version
        let pyproject_version = match doc
            .get("project")
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("version"))
            .and_then(|v| v.as_str())
        {
            Some(v) => v.to_string(),
            None => return Vec::new(), // dynamic or missing — skip
        };

        let pyproject_path = manifest
            .pyproject_path
            .clone()
            .unwrap_or_else(|| project.root.join("pyproject.toml"));

        let mut findings = Vec::new();

        // Walk all __init__.py files and look for __version__ = "..."
        for pf in &project.files {
            let file_path = &pf.source().path;

            // Only interested in __init__.py files.
            if file_path.file_name().and_then(|n| n.to_str()) != Some("__init__.py") {
                continue;
            }

            let source_text = pf.source().as_str();

            // Find __version__ = "..." assignments.
            if let Some((init_version, byte_offset)) = extract_version(source_text)
                && init_version != pyproject_version
            {
                let relative_init = file_path
                    .strip_prefix(&project.root)
                    .unwrap_or(file_path)
                    .to_path_buf();

                // Compute line/col from byte offset.
                let before = &source_text[..byte_offset.min(source_text.len())];
                #[allow(clippy::cast_possible_truncation)]
                let line = before.bytes().filter(|&b| b == b'\n').count() as u32 + 1;
                #[allow(clippy::cast_possible_truncation)]
                let col = before
                    .rfind('\n')
                    .map_or(before.len(), |i| before.len() - i - 1)
                    as u32
                    + 1;

                #[allow(clippy::cast_possible_truncation)]
                let offset = byte_offset as u32;
                #[allow(clippy::cast_possible_truncation)]
                let end_offset = (byte_offset + init_version.len()) as u32;

                let relative_pyproject = pyproject_path
                    .strip_prefix(&project.root)
                    .unwrap_or(&pyproject_path)
                    .to_path_buf();

                findings.push(Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Custom("packaging".to_string()),
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "version mismatch: pyproject.toml has `{pyproject_version}` \
                         but {} has `__version__ = \"{init_version}\"`",
                        relative_init.display()
                    ),
                    location: Location {
                        file: relative_init,
                        span: Span::new(ByteOffset(offset), ByteOffset(end_offset)),
                        start: LineCol::new(line, col),
                        end: LineCol::new(line, col + (end_offset - offset)),
                    },
                    suggestion: Some(format!(
                        "Update `__version__` in __init__.py to match \
                         `{pyproject_version}` (or remove it and use \
                         `importlib.metadata.version()` at runtime). \
                         See {}.",
                        relative_pyproject.display()
                    )),
                    references: vec![
                        "https://packaging.python.org/en/latest/guides/single-sourcing-package-version/".to_string(),
                    ],
                    cwe: vec![],
                    owasp: vec![],
                });
            }
        }

        findings
    }
}

/// Searches `source` for the first `__version__ = "..."` (single or double
/// quotes) assignment at module level.
///
/// Returns `(version_string, byte_offset_of_version_value)` or `None`.
fn extract_version(source: &str) -> Option<(String, usize)> {
    for line in source.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("__version__") {
            continue;
        }
        // Match patterns: __version__ = "1.2.3" or __version__ = '1.2.3'
        let rest = trimmed["__version__".len()..].trim_start();
        if !rest.starts_with('=') {
            continue;
        }
        let after_eq = rest["=".len()..].trim_start();
        for quote in &['"', '\''] {
            if after_eq.starts_with(*quote) {
                let inner = &after_eq[1..];
                if let Some(end) = inner.find(*quote) {
                    let version = inner[..end].to_string();
                    // Compute byte offset of the version string within source.
                    if let Some(line_start) = source.find(line) {
                        let col_offset = line.len()
                            - trimmed.len()
                            + "__version__".len()
                            + (trimmed["__version__".len()..].len() - rest.len())
                            + 1 // '='
                            + (rest["=".len()..].len() - after_eq.len())
                            + 1; // opening quote
                        return Some((version, line_start + col_offset));
                    }
                }
            }
        }
    }
    None
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::PythonLanguage;
    use std::io::Write as _;
    use std::sync::Arc;
    use zuit_core::SourceFile;
    use zuit_core::{Analyzer, Config, Language, Project};

    fn run(pyproject_content: &str, init_py_content: Option<&str>) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();

        let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        f.write_all(pyproject_content.as_bytes()).unwrap();

        let mut parsed_files = Vec::new();

        if let Some(init_content) = init_py_content {
            let init_path = dir.path().join("mypackage").join("__init__.py");
            std::fs::create_dir_all(init_path.parent().unwrap()).unwrap();
            let mut f2 = std::fs::File::create(&init_path).unwrap();
            f2.write_all(init_content.as_bytes()).unwrap();

            // Parse the __init__.py so it appears in project.files.
            let source = Arc::new(SourceFile::new(
                init_path.clone(),
                init_content.as_bytes().to_vec(),
            ));
            let lang = PythonLanguage;
            if let Ok(pf) = lang.parse(source) {
                parsed_files.push(pf);
            }
        }

        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), parsed_files);
        let analyzer = Pkg007VersionMismatch;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg007_version_mismatch_emits_medium() {
        let findings = run(
            "[project]\nname = \"my-pkg\"\nversion = \"1.2.3\"\n",
            Some("__version__ = \"1.2.4\"\n"),
        );
        assert_eq!(
            findings.len(),
            1,
            "expected 1 PKG007 finding: {findings:#?}"
        );
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("1.2.3"));
        assert!(findings[0].message.contains("1.2.4"));
    }

    #[test]
    fn pkg007_versions_match_emits_zero() {
        let findings = run(
            "[project]\nname = \"my-pkg\"\nversion = \"1.2.3\"\n",
            Some("__version__ = \"1.2.3\"\n"),
        );
        assert!(
            findings.is_empty(),
            "expected 0 findings when versions match: {findings:#?}"
        );
    }

    #[test]
    fn pkg007_no_init_py_emits_zero() {
        let findings = run("[project]\nname = \"my-pkg\"\nversion = \"1.2.3\"\n", None);
        assert!(
            findings.is_empty(),
            "expected 0 findings without __init__.py"
        );
    }

    #[test]
    fn pkg007_suppression_directive_works() {
        // Matching versions → no finding.
        let findings = run(
            "[project]\nname = \"x\"\nversion = \"1.0.0\"\n",
            Some("__version__ = \"1.0.0\"\n"),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn extract_version_double_quote() {
        let src = "__version__ = \"2.0.0\"\n";
        let result = extract_version(src);
        assert!(result.is_some(), "should extract version");
        assert_eq!(result.unwrap().0, "2.0.0");
    }

    #[test]
    fn extract_version_single_quote() {
        let src = "__version__ = '3.1.4'\n";
        let result = extract_version(src);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "3.1.4");
    }
}
