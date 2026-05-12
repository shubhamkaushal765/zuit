//! `PKG001-invalid-cargo-toml` — detects `Cargo.toml` files that fail TOML
//! parsing.
//!
//! A malformed `Cargo.toml` will prevent Cargo from reading the project at all.
//! Failing early with a clear message is essential for CI triage.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};

use crate::manifest::manifest_for;

const RULE_ID: &str = "PKG001-invalid-cargo-toml";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::High,
    doc_path: "docs/rules/PKG001-invalid-cargo-toml.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PKG001` when `Cargo.toml` cannot be parsed.
pub struct Pkg001InvalidCargoToml;

impl zuit_core::Analyzer for Pkg001InvalidCargoToml {
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

        // Only emit if Cargo.toml exists but failed to parse.
        let Some((msg, (line, col))) = &manifest.cargo_toml_parse_error else {
            return Vec::new();
        };

        let cargo_toml_path = manifest
            .cargo_toml_path
            .clone()
            .unwrap_or_else(|| project.root.join("Cargo.toml"));

        let relative = super::relative_to_root(project, &cargo_toml_path);

        // Best-effort: convert (line, col) to byte offset.
        let byte_offset = estimate_byte_offset(&cargo_toml_path, *line, *col);
        let span = Span::new(ByteOffset(byte_offset), ByteOffset(byte_offset));
        let start_lc = LineCol::new(*line, *col);

        vec![Finding {
            analyzer: AnalyzerId::new(RULE_ID),
            dimension: Dimension::Custom("packaging".to_string()),
            rule_id: RULE_ID.to_string(),
            severity: Severity::High,
            message: format!("Cargo.toml parse error: {msg}"),
            location: Location {
                file: relative,
                span,
                start: start_lc,
                end: start_lc,
            },
            suggestion: Some(
                "Validate your Cargo.toml with a TOML linter (e.g. `taplo lint Cargo.toml`)."
                    .to_string(),
            ),
            references: vec!["https://doc.rust-lang.org/cargo/reference/manifest.html".to_string()],
            cwe: vec![],
            owasp: vec![],
        }]
    }
}

/// Attempts to estimate the byte offset for `(line, col)` by reading the file.
/// Falls back to 0 on any I/O error.
fn estimate_byte_offset(path: &std::path::Path, line: u32, col: u32) -> u32 {
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

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Analyzer, Config, Project};
    use std::io::Write as _;

    fn run(toml_content: Option<&str>) -> Vec<Finding> {
        let dir = tempfile::TempDir::new().unwrap();
        if let Some(content) = toml_content {
            let mut f = std::fs::File::create(dir.path().join("Cargo.toml")).unwrap();
            f.write_all(content.as_bytes()).unwrap();
        }
        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        let analyzer = Pkg001InvalidCargoToml;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn pkg001_invalid_toml_emits_one_high() {
        // Truncated TOML header — parse will fail.
        let findings = run(Some("[package"));
        assert_eq!(findings.len(), 1, "expected exactly 1 PKG001 finding");
        let f = &findings[0];
        assert_eq!(f.rule_id, RULE_ID);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(
            f.location.file,
            std::path::Path::new("Cargo.toml"),
            "expected location file to be Cargo.toml, got {:?}",
            f.location.file
        );
    }

    #[test]
    fn pkg001_valid_toml_emits_zero() {
        let findings = run(Some(
            "[package]\nname = \"my-crate\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
        ));
        assert!(
            findings.is_empty(),
            "expected no findings on valid Cargo.toml, got: {findings:#?}"
        );
    }

    #[test]
    fn pkg001_missing_cargo_toml_emits_zero() {
        // PKG001 only fires when the file exists but is invalid.
        let findings = run(None);
        assert!(
            findings.is_empty(),
            "expected no PKG001 findings when Cargo.toml is absent, got: {findings:#?}"
        );
    }

    #[test]
    fn pkg001_suppression_directive_works() {
        // A valid Cargo.toml with the suppression directive should not fire.
        let findings = run(Some(
            "# zuit: ignore PKG001\n[package]\nname = \"x\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
        ));
        assert!(
            findings.is_empty(),
            "expected 0 PKG001 findings on valid toml with ignore directive"
        );
    }
}
