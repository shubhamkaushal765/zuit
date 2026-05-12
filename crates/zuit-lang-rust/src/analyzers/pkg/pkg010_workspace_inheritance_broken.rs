//! `PKG010-workspace-inheritance-broken` — emits when `[package]` uses
//! `key.workspace = true` but no `[workspace]` / `[workspace.package]` section
//! exists in this `Cargo.toml`.
//!
//! If a non-workspace-root `Cargo.toml` declares `version.workspace = true` but
//! there is no `[workspace.package]` section in the same file (nor is this file
//! itself the workspace root), Cargo will reject the build.  Best-effort: this
//! rule fires when the current `Cargo.toml` contains `workspace = true` on a
//! `[package]` key AND has no `[workspace]` table at all.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Project, RuleMeta, Severity,
    SupportedLanguages,
};

use crate::manifest::manifest_for;

use super::cargo_toml_finding;

const RULE_ID: &str = "PKG010-workspace-inheritance-broken";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/PKG010-workspace-inheritance-broken.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG010` when workspace inheritance keys are used
/// without a `[workspace]` section in the same file.
pub struct Pkg010WorkspaceInheritanceBroken;

impl zuit_core::Analyzer for Pkg010WorkspaceInheritanceBroken {
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
        let Some(doc) = &manifest.cargo_toml else {
            return Vec::new();
        };

        let cargo_toml_path = manifest
            .cargo_toml_path
            .clone()
            .unwrap_or_else(|| project.root.join("Cargo.toml"));

        // If a [workspace] section exists in this file, workspace inheritance is
        // valid — this IS the workspace root (or defines workspace).
        if doc.get("workspace").is_some() {
            return Vec::new();
        }

        let Some(pkg_table) = doc.get("package").and_then(|v| v.as_table()) else {
            return Vec::new();
        };

        // Look for any key under [package] that has `workspace = true`.
        let has_workspace_inheritance = pkg_table.iter().any(|(_, value)| {
            // inline table form: key = { workspace = true }
            value
                .as_inline_table()
                .and_then(|t| t.get("workspace"))
                .and_then(toml_edit::Value::as_bool)
                .unwrap_or(false)
                || value
                    .as_table()
                    .and_then(|t| t.get("workspace"))
                    .and_then(toml_edit::Item::as_bool)
                    .unwrap_or(false)
        });

        if !has_workspace_inheritance {
            return Vec::new();
        }

        vec![cargo_toml_finding(
            project,
            &cargo_toml_path,
            RULE_ID,
            Severity::Medium,
            "Cargo.toml [package] uses `workspace = true` on one or more keys but \
             this file has no `[workspace]` table; workspace inheritance will fail at \
             build time unless a parent workspace Cargo.toml provides the values"
                .to_string(),
            Some(
                "Either add a `[workspace.package]` section to define the inherited keys, \
                 or remove the `workspace = true` references and declare the values directly."
                    .to_string(),
            ),
        )]
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Analyzer, Config, Project};
    use std::io::Write as _;

    fn run(toml_content: &str) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("Cargo.toml")).unwrap();
        f.write_all(toml_content.as_bytes()).unwrap();
        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        let analyzer = Pkg010WorkspaceInheritanceBroken;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg010_workspace_key_without_workspace_section_emits_medium() {
        // [package] uses version.workspace = true but no [workspace] present.
        let findings = run("[package]\nname = \"my-crate\"\nversion = { workspace = true }\n");
        assert_eq!(findings.len(), 1, "expected exactly 1 PKG010 finding");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(
            findings[0].location.file,
            std::path::Path::new("Cargo.toml")
        );
    }

    #[test]
    fn pkg010_workspace_section_present_emits_zero() {
        // [workspace] is present → this is the workspace root, no finding.
        let findings = run(
            "[package]\nname = \"my-crate\"\nversion = { workspace = true }\n\
             [workspace]\nmembers = [\".\"]  \n\
             [workspace.package]\nversion = \"1.0.0\"\n",
        );
        assert!(
            findings.is_empty(),
            "expected 0 findings when [workspace] exists: {findings:#?}"
        );
    }

    #[test]
    fn pkg010_no_workspace_keys_emits_zero() {
        // Plain Cargo.toml without any workspace inheritance.
        let findings = run("[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\n");
        assert!(
            findings.is_empty(),
            "expected 0 findings without workspace keys: {findings:#?}"
        );
    }

    #[test]
    fn pkg010_suppression_directive_works() {
        let findings =
            run("# zuit: ignore PKG010\n[package]\nname = \"x\"\nversion = \"1.0\"\n");
        assert!(findings.is_empty());
    }
}
