//! `PERF001-heavy-import` — detects top-level `import` of heavyweight packages
//! (numpy, pandas, tensorflow, torch, scipy, matplotlib, cv2, sklearn) in library
//! files.
//!
//! Top-level imports of these packages execute at `import` time of the hosting
//! library, imposing a load-time cost (hundreds of milliseconds to seconds) on
//! every consumer even when the feature that needs the heavyweight dependency is
//! never called.  The fix is to move the import inside the function or method
//! that actually uses it (a "lazy import" pattern).
//!
//! **Scope:** `AnalyzerKind::FileLevel`.
//! **Dimension:** `Custom("performance")`.
//! **Severity:** Medium.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, LanguageId, Location,
    ParsedFile, RuleMeta, Severity, SupportedLanguages,
    span::{ByteOffset, Span},
};
use rustpython_parser::ast::{Ranged, Stmt};
use smallvec::smallvec;

const RULE_ID: &str = "PERF001-heavy-import";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/PERF001-heavy-import.md",
    cwe: &[],
    owasp: &[],
};

/// Heavyweight packages whose top-level import triggers PERF001.
const HEAVY_PACKAGES: &[&str] = &[
    "numpy",
    "pandas",
    "tensorflow",
    "torch",
    "scipy",
    "matplotlib",
    "cv2",
    "sklearn",
];

/// Analyzer that emits `PERF001-heavy-import` for top-level imports of
/// heavyweight packages in Python library files.
pub struct Perf001HeavyImport;

impl zuit_core::Analyzer for Perf001HeavyImport {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("performance".to_string())
    }

    fn supported_languages(&self) -> SupportedLanguages {
        SupportedLanguages::Only(smallvec![LanguageId("python")])
    }

    fn rules(&self) -> &[RuleMeta] {
        std::slice::from_ref(&META)
    }

    fn kind(&self) -> AnalyzerKind {
        AnalyzerKind::FileLevel
    }

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
        let Some(ast) = crate::try_python_ast(file) else {
            return Vec::new();
        };

        let source = file.source();
        let file_path = source.path.clone();
        let mut findings = Vec::new();

        // Only check top-level statements (ast.body).
        for stmt in &ast.body {
            match stmt {
                Stmt::Import(import_stmt) => {
                    for alias in &import_stmt.names {
                        let top_name = alias.name.as_str().split('.').next().unwrap_or("");
                        if HEAVY_PACKAGES.contains(&top_name) {
                            let range = import_stmt.range();
                            let start_off = ByteOffset(range.start().to_u32());
                            let end_off = ByteOffset(range.end().to_u32());
                            let span = Span::new(start_off, end_off);
                            let (start_lc, end_lc) = source.span_to_linecols(span);
                            findings.push(Finding {
                                analyzer: AnalyzerId::new(RULE_ID),
                                dimension: Dimension::Custom("performance".to_string()),
                                rule_id: RULE_ID.to_string(),
                                severity: Severity::Medium,
                                message: format!(
                                    "top-level `import {top_name}` imposes significant load-time \
                                     cost on all consumers of this library; consider moving the \
                                     import inside the function that uses it"
                                ),
                                location: Location {
                                    file: file_path.clone(),
                                    span,
                                    start: start_lc,
                                    end: end_lc,
                                },
                                suggestion: Some(format!(
                                    "Move `import {top_name}` inside the function(s) that use it \
                                     to defer the cost until needed (lazy-import pattern)."
                                )),
                                references: vec![],
                                cwe: vec![],
                                owasp: vec![],
                            });
                        }
                    }
                }
                Stmt::ImportFrom(import_from) => {
                    if let Some(module) = &import_from.module {
                        let top_name = module.as_str().split('.').next().unwrap_or("");
                        if HEAVY_PACKAGES.contains(&top_name) {
                            let range = import_from.range();
                            let start_off = ByteOffset(range.start().to_u32());
                            let end_off = ByteOffset(range.end().to_u32());
                            let span = Span::new(start_off, end_off);
                            let (start_lc, end_lc) = source.span_to_linecols(span);
                            findings.push(Finding {
                                analyzer: AnalyzerId::new(RULE_ID),
                                dimension: Dimension::Custom("performance".to_string()),
                                rule_id: RULE_ID.to_string(),
                                severity: Severity::Medium,
                                message: format!(
                                    "top-level `from {top_name} import ...` imposes significant \
                                     load-time cost on all consumers of this library; consider \
                                     moving the import inside the function that uses it"
                                ),
                                location: Location {
                                    file: file_path.clone(),
                                    span,
                                    start: start_lc,
                                    end: end_lc,
                                },
                                suggestion: Some(format!(
                                    "Move `from {top_name} import ...` inside the function(s) \
                                     that use it to defer the cost until needed (lazy-import \
                                     pattern)."
                                )),
                                references: vec![],
                                cwe: vec![],
                                owasp: vec![],
                            });
                        }
                    }
                }
                // Only top-level: skip everything inside functions/classes.
                _ => {}
            }
        }

        findings
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::PythonLanguage;
    use zuit_core::{Analyzer, Config, Language, SourceFile};
    use std::sync::Arc;

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("lib.py", src.as_bytes().to_vec()));
        let parsed = PythonLanguage.parse(source).expect("parse failed");
        let analyzer = Perf001HeavyImport;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // 1. top-level pandas import in lib → one PERF001 Medium
    #[test]
    fn perf001_heavy_import_pandas_at_module_top() {
        let findings = analyze("import pandas\n\ndef foo():\n    pass\n");
        assert_eq!(findings.len(), 1, "expected 1 finding: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    // 2. import inside function → 0 findings
    #[test]
    fn perf001_heavy_import_inside_function_clean() {
        let findings = analyze("def foo():\n    import pandas\n    return pandas.DataFrame()\n");
        assert!(
            findings.is_empty(),
            "expected 0 findings for import inside function: {findings:#?}"
        );
    }

    // Positive: numpy, torch, sklearn, cv2 all fire
    #[test]
    fn perf001_all_heavy_packages_fire() {
        for pkg in HEAVY_PACKAGES {
            let src = format!("import {pkg}\n");
            let findings = analyze(&src);
            assert_eq!(
                findings.len(),
                1,
                "expected 1 finding for `import {pkg}`: {findings:#?}"
            );
        }
    }

    // Negative: standard library / unknown packages do not fire
    #[test]
    fn perf001_light_import_no_finding() {
        let findings = analyze("import os\nimport sys\nimport json\n");
        assert!(
            findings.is_empty(),
            "expected 0 findings for standard imports: {findings:#?}"
        );
    }

    // from pandas import DataFrame also fires
    #[test]
    fn perf001_from_import_fires() {
        let findings = analyze("from pandas import DataFrame\n");
        assert_eq!(findings.len(), 1, "expected 1 finding: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    // Suppression directive format is well-formed
    #[test]
    fn perf001_suppression_directive_format() {
        let directive = "# zuit: ignore PERF001-heavy-import";
        assert!(directive.contains("zuit: ignore"));
        assert!(directive.contains("PERF001-heavy-import"));
    }
}
