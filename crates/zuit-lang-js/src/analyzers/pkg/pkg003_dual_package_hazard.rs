//! `PKG003-dual-package-hazard` — detects packages that expose both `CommonJS`
//! and ESM entry points without a proper conditional exports map.
//!
//! Dual CJS+ESM packages can cause two copies of the package to be loaded in
//! the same process (one by `require`, one by `import`), breaking singleton
//! assumptions, `WeakMap` keys, and `instanceof` checks. The hazard exists when:
//!
//! 1. Both `main` (CJS) and `module`/`exports` (ESM) are declared, but no
//!    `exports` map covers at least both `import` and `require` conditions; or
//! 2. `type: "module"` is declared alongside `.cjs` files at the project root
//!    (a common mis-configuration where the CJS build was not isolated).

use zuit_core::span::{ByteOffset, LineCol, Location, Span};
use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, AnalyzerKind, Dimension, Finding, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
};

/// Rule ID for the dual-package-hazard check.
const RULE_ID: &str = "PKG003-dual-package-hazard";

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/PKG003-dual-package-hazard.md",
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

/// Returns `true` when the `exports` object contains both `import` and
/// `require` conditions at any depth, indicating a clean dual-mode setup.
fn exports_has_import_and_require(exports: &serde_json::Value) -> bool {
    let has_import = json_contains_key(exports, "import");
    let has_require = json_contains_key(exports, "require");
    has_import && has_require
}

/// Recursively searches a JSON value for a given key.
fn json_contains_key(v: &serde_json::Value, key: &str) -> bool {
    match v {
        serde_json::Value::Object(map) => {
            map.contains_key(key) || map.values().any(|child| json_contains_key(child, key))
        }
        serde_json::Value::Array(arr) => arr.iter().any(|child| json_contains_key(child, key)),
        _ => false,
    }
}

/// Returns `true` if any `*.cjs` file exists directly inside `root`.
fn has_cjs_file_at_root(root: &std::path::Path) -> bool {
    std::fs::read_dir(root).is_ok_and(|entries| {
        entries.filter_map(Result::ok).any(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("cjs"))
        })
    })
}

/// Analyzer that emits `PKG003-dual-package-hazard` when a package exposes
/// both CJS and ESM without a proper exports map.
pub struct Pkg003DualPackageHazardAnalyzer;

impl Analyzer for Pkg003DualPackageHazardAnalyzer {
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

        let has_main = pkg.get("main").is_some();
        let has_module = pkg.get("module").is_some();
        let has_exports = pkg.get("exports").is_some();
        let is_esm_type = pkg.get("type").and_then(|v| v.as_str()) == Some("module");

        // Pattern 1: main + module/exports but no clean conditional exports.
        if has_main && (has_module || has_exports) {
            let clean = pkg
                .get("exports")
                .is_some_and(exports_has_import_and_require);
            if !clean {
                return vec![make_finding(&project.root)];
            }
        }

        // Pattern 2: type: "module" with .cjs siblings at root.
        if is_esm_type && has_cjs_file_at_root(&project.root) {
            return vec![make_finding(&project.root)];
        }

        vec![]
    }
}

fn make_finding(root: &std::path::Path) -> Finding {
    Finding {
        analyzer: AnalyzerId::new(RULE_ID),
        dimension: Dimension::Custom("packaging".to_string()),
        rule_id: RULE_ID.to_string(),
        severity: Severity::Medium,
        message: "dual-package hazard: package exposes both CJS and ESM without a proper \
                  conditional `exports` map covering `import` and `require`"
            .to_string(),
        location: pkg_json_location(root),
        suggestion: Some(
            "Add a conditional `exports` map with `import` and `require` conditions, \
             or use the `exports` field exclusively (drop the bare `main`/`module` fields)."
                .to_string(),
        ),
        references: vec![
            "https://nodejs.org/api/packages.html#dual-commonjses-module-packages".to_string(),
        ],
        cwe: META.cwe_vec(),
        owasp: META.owasp_vec(),
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
        Pkg003DualPackageHazardAnalyzer.analyze_project(&ctx, &project)
    }

    #[test]
    fn dual_package_no_exports_map_emits_medium() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"name":"foo","main":"index.cjs","module":"index.mjs"}"#,
        );
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].rule_id, RULE_ID);
    }

    #[test]
    fn dual_package_with_clean_exports_emits_zero() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{
                "name": "foo",
                "main": "index.cjs",
                "module": "index.mjs",
                "exports": {
                    ".": {
                        "import": "./index.mjs",
                        "require": "./index.cjs"
                    }
                }
            }"#,
        );
        let findings = run(dir.path());
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn esm_type_with_cjs_sibling_emits_medium() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"name":"foo","type":"module"}"#,
        );
        write(dir.path(), "index.cjs", "module.exports = {};");
        let findings = run(dir.path());
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn cjs_only_package_emits_zero() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"name":"foo","main":"index.js"}"#,
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
