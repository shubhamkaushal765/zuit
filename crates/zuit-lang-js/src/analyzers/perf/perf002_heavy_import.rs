//! `PERF002-heavy-import` — flags top-level imports of known-heavy npm packages.
//!
//! # Rationale
//!
//! Packages like `lodash`, `moment`, `underscore`, and `jquery` are large
//! monolithic libraries. Importing the entire package at the top level of a
//! module prevents bundlers from tree-shaking unused code, resulting in
//! unnecessarily large bundles. Consumers should prefer deep imports
//! (e.g. `import cloneDeep from "lodash/cloneDeep"`) or lighter alternatives.
//!
//! # Detection
//!
//! For each `JsImport` in `JsAst::imports`, the rule checks whether the
//! import source is one of the hardcoded heavy packages. Both ES module
//! `import` declarations and `CommonJS` `require()` calls at module scope are
//! detected (the AST walker in `parse.rs` populates `imports` for both forms).
//!
//! # Deviations from the plan
//!
//! - **Bin carve-out skipped.** The plan specifies skipping emission when
//!   `package.json` declares a `bin` field. Loading `package.json` from a
//!   `FileLevel` analyzer is architecturally awkward (the path from file to
//!   project root is not part of the `ParsedFile` API). This is intentionally
//!   deferred to v2 when `Config` gains a `[javascript]` section. The rule is
//!   still useful for library files.
//! - **Configurable heavy-import list.** The plan mentions a configurable list;
//!   `Config` has no `[javascript.perf]` section yet. The list is hardcoded.
//!   Document the hardcoded list here: `lodash`, `moment`, `underscore`,
//!   `jquery`.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, LanguageId, Location,
    ParsedFile, RuleMeta, Severity, SupportedLanguages,
};
use smallvec::smallvec;

/// Rule ID for this analyzer.
const RULE_ID: &str = "PERF002-heavy-import";

/// Static rule metadata.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/PERF002-heavy-import.md",
    cwe: &[],
    owasp: &[],
};

/// Packages whose top-level import triggers this rule.
///
/// This list is intentionally conservative. Prefer deep imports
/// (e.g. `"lodash/cloneDeep"`) or per-method packages (`"lodash.clonedeep"`).
const HEAVY_PACKAGES: &[&str] = &["lodash", "moment", "underscore", "jquery"];

/// Returns `true` when `source` is an exact match for one of the heavy packages.
///
/// Only bare package names are matched — `"lodash/cloneDeep"` is **not**
/// flagged because it is a sub-path import and allows tree-shaking.
fn is_heavy(source: &str) -> bool {
    HEAVY_PACKAGES.contains(&source)
}

/// Analyzer that emits `PERF002-heavy-import` for top-level imports of
/// known-heavy packages in JavaScript/TypeScript files.
pub struct Perf002HeavyImportAnalyzer;

impl zuit_core::Analyzer for Perf002HeavyImportAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("performance".to_string())
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::Only(smallvec![LanguageId("javascript")])
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn kind(&self) -> AnalyzerKind {
        AnalyzerKind::FileLevel
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let Some(ast) = crate::try_js_ast(file) else {
            return vec![];
        };

        let source = file.source();
        let file_path = source.path.clone();
        let mut findings = Vec::new();

        for import in &ast.imports {
            if !is_heavy(&import.source) {
                continue;
            }
            let (start_lc, end_lc) = source.span_to_linecols(import.span);
            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Custom("performance".to_string()),
                rule_id: RULE_ID.to_string(),
                severity: Severity::Medium,
                message: format!(
                    "top-level import of '{}' imports the entire package; \
                     use a deep import (e.g. \"{}/method\") or a lighter alternative \
                     to enable tree-shaking",
                    import.source, import.source
                ),
                location: Location {
                    file: file_path.clone(),
                    span: import.span,
                    start: start_lc,
                    end: end_lc,
                },
                suggestion: Some(format!(
                    "Replace `import {} from \"{}\"` with a deep import such as \
                     `import cloneDeep from \"{}/cloneDeep\"`, or use a lighter \
                     per-method package.",
                    import.source, import.source, import.source
                )),
                references: vec![],
                cwe: vec![],
                owasp: vec![],
            });
        }

        findings
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse as js_parse;
    use zuit_core::{Analyzer, Config, LanguageId, SourceFile};
    use std::sync::Arc;

    fn analyze(path: &str, src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new(path, src.as_bytes().to_vec()));
        let parsed = js_parse(source).expect("parse failed");
        let analyzer = Perf002HeavyImportAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // 1. ES module import of lodash → 1 Medium finding
    #[test]
    fn perf002_heavy_import_lodash_emits_medium() {
        let findings = analyze("lib.js", r#"import _ from "lodash";"#);
        assert_eq!(findings.len(), 1, "got {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert!(findings[0].message.contains("lodash"));
    }

    // 2. ES module import of moment → 1 finding
    #[test]
    fn perf002_heavy_import_moment_emits_finding() {
        let findings = analyze("lib.js", r#"import moment from "moment";"#);
        assert_eq!(findings.len(), 1, "got {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    // 3. ES module import of underscore → 1 finding
    #[test]
    fn perf002_heavy_import_underscore_emits_finding() {
        let findings = analyze("lib.js", r#"import _ from "underscore";"#);
        assert_eq!(findings.len(), 1, "got {findings:#?}");
    }

    // 4. ES module import of jquery → 1 finding
    #[test]
    fn perf002_heavy_import_jquery_emits_finding() {
        let findings = analyze("lib.js", r#"import $ from "jquery";"#);
        assert_eq!(findings.len(), 1, "got {findings:#?}");
    }

    // 5. CommonJS require of lodash at module scope → 1 finding
    #[test]
    fn perf002_require_lodash_emits_finding() {
        let findings = analyze("lib.js", r#"const _ = require("lodash");"#);
        assert_eq!(
            findings.len(),
            1,
            "require lodash should flag; got {findings:#?}"
        );
    }

    // 6. Local import → 0 findings
    #[test]
    fn perf002_no_heavy_import_clean() {
        let findings = analyze("lib.js", r#"import x from "./local";"#);
        assert!(
            findings.is_empty(),
            "local import must not flag; got {findings:#?}"
        );
    }

    // 7. Deep subpath import of lodash → 0 findings (tree-shakeable)
    #[test]
    fn perf002_deep_import_lodash_clean() {
        let findings = analyze("lib.js", r#"import cloneDeep from "lodash/cloneDeep";"#);
        assert!(
            findings.is_empty(),
            "deep import must not flag; got {findings:#?}"
        );
    }

    // 8. require inside a function is not at module scope → 0 findings
    #[test]
    fn perf002_require_inside_function_clean() {
        let findings = analyze(
            "lib.js",
            r#"function getLodash() { return require("lodash"); }"#,
        );
        assert!(
            findings.is_empty(),
            "require inside function must not flag; got {findings:#?}"
        );
    }

    // 9. supported_languages is javascript only
    #[test]
    fn perf002_supported_languages_javascript_only() {
        let analyzer = Perf002HeavyImportAnalyzer;
        assert!(
            analyzer
                .supported_languages()
                .supports(LanguageId("javascript"))
        );
        assert!(
            !analyzer
                .supported_languages()
                .supports(LanguageId("python"))
        );
    }

    // 10. Multiple heavy imports → multiple findings
    #[test]
    fn perf002_multiple_heavy_imports_each_flagged() {
        let src = "import _ from \"lodash\";\nimport moment from \"moment\";\n";
        let findings = analyze("lib.js", src);
        assert_eq!(findings.len(), 2, "expected 2 findings; got {findings:#?}");
    }
}
