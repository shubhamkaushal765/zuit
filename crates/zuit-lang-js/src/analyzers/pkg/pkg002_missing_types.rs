//! `PKG002-missing-types` — flags packages that declare no TypeScript type
//! declarations.
//!
//! A package with no `types`/`typings` field and no `*.d.ts` file adjacent to
//! the entry point provides no type information to TypeScript consumers, hurting
//! DX and causing `noImplicitAny` errors in strict codebases.
//!
//! Entry point heuristic: use the `main` field, or fall back to `index.js`.
//! The companion `.d.ts` is checked by swapping the extension.

use zuit_core::span::{ByteOffset, LineCol, Location, Span};
use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, AnalyzerKind, Dimension, Finding, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
};

/// Rule ID for the missing-types check.
const RULE_ID: &str = "PKG002-missing-types";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/PKG002-missing-types.md",
    cwe: &[],
    owasp: &[],
};

/// Zero-width location anchored at `package.json` line 1, column 1.
fn pkg_json_location(root: &std::path::Path) -> Location {
    let zero = Span::new(ByteOffset(0), ByteOffset(0));
    Location {
        file: root.join("package.json"),
        span: zero,
        start: LineCol::new(1, 1),
        end: LineCol::new(1, 1),
    }
}

/// Returns `true` if a `.d.ts` sibling exists next to the entry-point file.
fn has_dts_sibling(root: &std::path::Path, entry: &str) -> bool {
    let entry_path = root.join(entry);
    let dts = entry_path.with_extension("d.ts");
    dts.exists()
}

/// Analyzer that emits `PKG002-missing-types` when a package provides no type
/// declarations.
pub struct Pkg002MissingTypesAnalyzer;

impl Analyzer for Pkg002MissingTypesAnalyzer {
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

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, _file: &ParsedFile) -> Vec<Finding> {
        vec![]
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        let manifest = crate::manifest::get_or_load(&project.root);
        let Some(pkg) = manifest.package_json.as_ref() else {
            return vec![];
        };

        // A declared `types` or `typings` field satisfies the check.
        if pkg.get("types").is_some() || pkg.get("typings").is_some() {
            return vec![];
        }

        // Fall back to a `.d.ts` file adjacent to the entry point.
        let entry = pkg
            .get("main")
            .and_then(|v| v.as_str())
            .unwrap_or("index.js");

        if has_dts_sibling(&project.root, entry) {
            return vec![];
        }

        vec![Finding {
            analyzer: AnalyzerId::new(RULE_ID),
            dimension: Dimension::Custom("packaging".to_string()),
            rule_id: RULE_ID.to_string(),
            severity: Severity::Low,
            message: "package declares no TypeScript type declarations (`types`/`typings` field \
                      missing and no `.d.ts` adjacent to entry point)"
                .to_string(),
            location: pkg_json_location(&project.root),
            suggestion: Some(
                "Add a `types` field pointing to your `.d.ts` entry file, or generate \
                 declarations with `tsc --declaration`."
                    .to_string(),
            ),
            references: vec![],
            cwe: META.cwe_vec(),
            owasp: META.owasp_vec(),
        }]
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use zuit_core::{Config, Project};

    fn write(dir: &std::path::Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).expect("invariant: temp dir is writable");
    }

    fn run(dir: &std::path::Path) -> Vec<Finding> {
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let project = Project::new(dir.to_path_buf(), vec![]);
        Pkg002MissingTypesAnalyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn missing_types_emits_one_low() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"name":"foo","main":"index.js"}"#,
        );
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn types_field_present_emits_zero() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"name":"foo","main":"index.js","types":"index.d.ts"}"#,
        );
        let findings = run(dir.path());
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn typings_field_present_emits_zero() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"name":"foo","main":"index.js","typings":"index.d.ts"}"#,
        );
        let findings = run(dir.path());
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn dts_sibling_present_emits_zero() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"name":"foo","main":"index.js"}"#,
        );
        // Create the sibling .d.ts file
        write(
            dir.path(),
            "index.d.ts",
            "export declare function foo(): void;",
        );
        let findings = run(dir.path());
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn no_package_json_emits_zero() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        let findings = run(dir.path());
        assert!(findings.is_empty(), "got: {findings:#?}");
    }
}
