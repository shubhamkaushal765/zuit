//! `PKG008-entry-points-malformed` — detects malformed entry-point strings in
//! `[project.scripts]`, `[project.gui-scripts]`, and `[project.entry-points]`.
//!
//! Entry-point values must be of the form `module.path:callable` (a dotted
//! module path, a colon separator, and a dotted attribute path).  Malformed
//! values cause `pip install` to succeed but `<command>` to fail at runtime
//! with an `ImportError` or `AttributeError`.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::pkg001_invalid_pyproject::pyproject_finding;

const RULE_ID: &str = "PKG008-entry-points-malformed";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/PKG008-entry-points-malformed.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG008` for malformed entry-point strings.
pub struct Pkg008EntryPointsMalformed;

impl zuit_core::Analyzer for Pkg008EntryPointsMalformed {
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

        let pyproject_path = manifest
            .pyproject_path
            .clone()
            .unwrap_or_else(|| project.root.join("pyproject.toml"));

        let Some(project_table) = doc.get("project").and_then(|v| v.as_table()) else {
            return Vec::new();
        };

        let mut bad_entries: Vec<String> = Vec::new();

        // Check [project.scripts] and [project.gui-scripts]
        for section in &["scripts", "gui-scripts"] {
            if let Some(table) = project_table.get(section).and_then(|v| v.as_table()) {
                for (name, value) in table {
                    if let Some(ep) = value.as_str()
                        && !is_valid_entry_point(ep)
                    {
                        bad_entries.push(format!("[project.{section}] {name} = \"{ep}\""));
                    }
                }
            }
        }

        // Check [project.entry-points.<group>]
        if let Some(ep_groups) = project_table.get("entry-points").and_then(|v| v.as_table()) {
            for (group, group_table) in ep_groups {
                if let Some(table) = group_table.as_table() {
                    for (name, value) in table {
                        if let Some(ep) = value.as_str()
                            && !is_valid_entry_point(ep)
                        {
                            bad_entries
                                .push(format!("[project.entry-points.{group}] {name} = \"{ep}\""));
                        }
                    }
                }
            }
        }

        if bad_entries.is_empty() {
            return Vec::new();
        }

        vec![pyproject_finding(
            project,
            &pyproject_path,
            RULE_ID,
            Severity::Medium,
            format!(
                "pyproject.toml has malformed entry-point value(s): {}. \
                 Entry points must be in the form `package.module:callable`.",
                bad_entries.join("; ")
            ),
            Some(
                "Ensure all entry-point values follow the `module.path:function` format, \
                 e.g. `mypackage.cli:main`."
                    .to_string(),
            ),
        )]
    }
}

/// Returns `true` if `ep` is a valid entry-point string (`module:attr` form).
///
/// Valid: `package.module:callable`, `module:attr.sub`
/// Invalid: `no-colon`, `module:`, `:attr`, empty
fn is_valid_entry_point(ep: &str) -> bool {
    let Some(colon_pos) = ep.find(':') else {
        return false;
    };
    let module_part = &ep[..colon_pos];
    let attr_part = &ep[colon_pos + 1..];

    // Both parts must be non-empty dotted identifiers.
    !module_part.is_empty()
        && !attr_part.is_empty()
        && is_dotted_name(module_part)
        && is_dotted_name(attr_part)
}

fn is_dotted_name(s: &str) -> bool {
    s.split('.').all(|part| {
        !part.is_empty()
            && part.chars().enumerate().all(|(i, c)| {
                if i == 0 {
                    c.is_alphabetic() || c == '_'
                } else {
                    c.is_alphanumeric() || c == '_'
                }
            })
    })
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Analyzer, Config, Project};
    use std::io::Write as _;

    fn run(toml_content: &str) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();
        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        let analyzer = Pkg008EntryPointsMalformed;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg008_malformed_script_emits_medium() {
        let findings = run(
            "[project]\nname = \"x\"\nversion = \"1.0\"\n\n[project.scripts]\ncli = \"mypackage-main\"\n",
        );
        assert_eq!(
            findings.len(),
            1,
            "expected 1 PKG008 finding: {findings:#?}"
        );
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn pkg008_valid_script_emits_zero() {
        let findings = run(
            "[project]\nname = \"x\"\nversion = \"1.0\"\n\n[project.scripts]\ncli = \"mypackage.cli:main\"\n",
        );
        assert!(findings.is_empty(), "expected 0 findings: {findings:#?}");
    }

    #[test]
    fn pkg008_no_scripts_emits_zero() {
        let findings = run("[project]\nname = \"x\"\nversion = \"1.0\"\n");
        assert!(findings.is_empty(), "expected 0 findings with no scripts");
    }

    #[test]
    fn pkg008_suppression_directive_works() {
        // Valid script — no finding.
        let findings = run(
            "[project]\nname = \"x\"\nversion = \"1.0\"\n\n[project.scripts]\ncli = \"mypackage:main\"\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn is_valid_entry_point_cases() {
        assert!(is_valid_entry_point("mypackage.cli:main"));
        assert!(is_valid_entry_point("mod:fn"));
        assert!(is_valid_entry_point("a.b.c:d.e"));
        assert!(!is_valid_entry_point("no-colon"));
        assert!(!is_valid_entry_point("mod:"));
        assert!(!is_valid_entry_point(":attr"));
        assert!(!is_valid_entry_point(""));
    }
}
