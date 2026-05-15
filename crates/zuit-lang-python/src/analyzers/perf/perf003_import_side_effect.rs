//! `PERF003-import-side-effect` — detects top-level statements that execute
//! side-effectful code at import time.
//!
//! Importing a Python module executes all top-level statements.  Non-declarative
//! statements (function calls, loops, I/O) at module level impose hidden costs on
//! every consumer, even when the triggered feature is never used.
//!
//! **Allowed top-level statements** (do NOT trigger PERF003):
//! - `import …` / `from … import …`
//! - `def` / `async def` / `class`
//! - `if __name__ == "__main__":` guard blocks
//! - Simple constant assignment: `NAME = <constant literal>` (no complex expression)
//! - `__all__ = [...]`
//! - Decorator-only function/class defs (still `def`/`class` at the Stmt level)
//!
//! **Carve-out:** the rule is **suppressed entirely** for any file belonging to a
//! project whose `pyproject.toml` declares at least one `[project.scripts]` entry.
//! Entry-point scripts are *expected* to run side-effectful top-level code.
//!
//! **Scope:** `AnalyzerKind::FileLevel`.
//! **Dimension:** `Custom("performance")`.
//! **Severity:** Medium.

use rustpython_parser::ast::{Constant, Expr, Ranged, Stmt};
use smallvec::smallvec;
use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, LanguageId, Location,
    ParsedFile, Project, RuleMeta, Severity, SupportedLanguages,
    span::{ByteOffset, Span},
};

const RULE_ID: &str = "PERF003-import-side-effect";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/PERF003-import-side-effect.md",
    cwe: &[],
    owasp: &[],
};

/// Analyzer that emits `PERF003-import-side-effect` for top-level side-effectful
/// statements in Python library files.
pub struct Perf003ImportSideEffect;

impl zuit_core::Analyzer for Perf003ImportSideEffect {
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

        for stmt in &ast.body {
            if !is_allowed_top_level(stmt) {
                let range = stmt.range();
                let start_off = ByteOffset(range.start().to_u32());
                let end_off = ByteOffset(range.end().to_u32());
                let span = Span::new(start_off, end_off);
                let (start_lc, end_lc) = source.span_to_linecols(span);
                findings.push(Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Custom("performance".to_string()),
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Medium,
                    message: "top-level statement executes side-effectful code at import time; \
                         move it inside a function or guard it with \
                         `if __name__ == \"__main__\":'"
                        .to_string(),
                    location: Location {
                        file: file_path.clone(),
                        span,
                        start: start_lc,
                        end: end_lc,
                    },
                    suggestion: Some(
                        "Wrap the statement in a function or place it under \
                         `if __name__ == \"__main__\":` to prevent execution at import time."
                            .to_string(),
                    ),
                    references: vec![],
                    cwe: vec![],
                    owasp: vec![],
                });
            }
        }

        findings
    }
}

/// Project-level wrapper that applies the entry-point carve-out.
///
/// Returns `true` if the project has `[project.scripts]` entries in pyproject.toml,
/// meaning PERF003 should be suppressed for all files in the project.
#[allow(dead_code)]
pub(crate) fn project_has_entry_point_scripts(project: &Project) -> bool {
    let manifest = crate::manifest::manifest_for(project);
    let Some(doc) = &manifest.pyproject else {
        return false;
    };
    doc.get("project")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("scripts"))
        .and_then(|v| v.as_table())
        .is_some_and(|t| !t.is_empty())
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Returns `true` if `stmt` is one of the allowed top-level forms that do NOT
/// constitute an import side-effect.
fn is_allowed_top_level(stmt: &Stmt) -> bool {
    match stmt {
        // import / from … import … / def / async def / class (including decorated variants)
        Stmt::Import(_)
        | Stmt::ImportFrom(_)
        | Stmt::FunctionDef(_)
        | Stmt::AsyncFunctionDef(_)
        | Stmt::ClassDef(_) => true,

        // if __name__ == "__main__": guard
        Stmt::If(if_stmt) => is_main_guard(&if_stmt.test),

        // Simple constant assignment: NAME = <constant>  or  __all__ = [...]
        Stmt::Assign(assign) => {
            // Must be a single target that's a bare Name.
            if assign.targets.len() != 1 {
                return false;
            }
            match &assign.targets[0] {
                Expr::Name(name) => {
                    // __all__ = anything is always allowed.
                    if name.id.as_str() == "__all__" {
                        return true;
                    }
                    // Otherwise the RHS must be a simple constant literal.
                    is_simple_constant(&assign.value)
                }
                // Tuple/starred assignments or subscripts on LHS → side-effectful.
                _ => false,
            }
        }

        // Annotated assignment with a constant or no value: X: int = 0
        Stmt::AnnAssign(ann) => {
            if let Some(value) = &ann.value {
                is_simple_constant(value)
            } else {
                // Bare annotation with no value: `x: int` — allowed (no side effect).
                true
            }
        }

        // Everything else (Expr/call, for, while, with, try, …) is a side effect.
        _ => false,
    }
}

/// Returns `true` if `expr` is an `if __name__ == "__main__":` comparison.
fn is_main_guard(expr: &Expr) -> bool {
    match expr {
        Expr::Compare(cmp) => {
            // Check: __name__ == "__main__"
            if let Expr::Name(name) = cmp.left.as_ref()
                && name.id.as_str() == "__name__"
                && cmp.ops.len() == 1
                && matches!(cmp.ops[0], rustpython_parser::ast::CmpOp::Eq)
                && cmp.comparators.len() == 1
                && let Expr::Constant(c) = &cmp.comparators[0]
                && let Constant::Str(s) = &c.value
            {
                return s.as_str() == "__main__";
            }
            false
        }
        _ => false,
    }
}

/// Returns `true` if `expr` is a simple constant literal (string, int, float,
/// bool, bytes, None, ellipsis).  Does NOT recurse into containers or calls.
fn is_simple_constant(expr: &Expr) -> bool {
    matches!(expr, Expr::Constant(_))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::PythonLanguage;
    use std::sync::Arc;
    use zuit_core::{Analyzer, Config, Language, SourceFile};

    fn analyze(src: &str) -> Vec<Finding> {
        let source = Arc::new(SourceFile::new("lib.py", src.as_bytes().to_vec()));
        let parsed = PythonLanguage.parse(source).expect("parse failed");
        let analyzer = Perf003ImportSideEffect;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_file(&ctx, &parsed)
    }

    // 4a. print at module top → one PERF003 Medium
    #[test]
    fn perf003_top_level_print_emits_finding() {
        let findings = analyze("print(\"loaded!\")\n");
        assert_eq!(findings.len(), 1, "expected 1 finding: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    // 4b. print inside if __name__ == "__main__": → 0 findings
    #[test]
    fn perf003_print_under_main_guard_no_finding() {
        let findings = analyze("if __name__ == \"__main__\":\n    print(\"loaded!\")\n");
        assert!(
            findings.is_empty(),
            "expected 0 findings under main guard: {findings:#?}"
        );
    }

    // Imports are always allowed
    #[test]
    fn perf003_import_no_finding() {
        let findings = analyze("import os\nfrom sys import argv\n");
        assert!(
            findings.is_empty(),
            "expected 0 findings for imports: {findings:#?}"
        );
    }

    // def / class are allowed
    #[test]
    fn perf003_def_class_no_finding() {
        let findings = analyze("def foo():\n    pass\n\nclass Bar:\n    pass\n");
        assert!(
            findings.is_empty(),
            "expected 0 findings for def/class: {findings:#?}"
        );
    }

    // Simple constant assignment is allowed
    #[test]
    fn perf003_simple_constant_assignment_no_finding() {
        let findings = analyze("VERSION = \"1.0\"\nDEBUG = False\n");
        assert!(
            findings.is_empty(),
            "expected 0 findings for constant assignments: {findings:#?}"
        );
    }

    // __all__ assignment is always allowed
    #[test]
    fn perf003_all_assignment_no_finding() {
        let findings = analyze("__all__ = [\"foo\", \"bar\"]\n");
        assert!(
            findings.is_empty(),
            "expected 0 findings for __all__ assignment: {findings:#?}"
        );
    }

    // Complex top-level call → fires
    #[test]
    fn perf003_top_level_function_call_fires() {
        let findings = analyze("setup_logging()\n");
        assert_eq!(findings.len(), 1, "expected 1 finding: {findings:#?}");
    }

    // Suppression directive format
    #[test]
    fn perf003_suppression_directive_format() {
        let directive = "# zuit: ignore PERF003-import-side-effect";
        assert!(directive.contains("zuit: ignore"));
        assert!(directive.contains("PERF003-import-side-effect"));
    }

    // 5. Carve-out test: project_has_entry_point_scripts returns true when scripts present
    #[test]
    fn perf003_carveout_when_entry_point_present() {
        use std::io::Write as _;
        use zuit_core::Project;

        let dir = tempfile::TempDir::new().unwrap();
        let toml = "[project]\nname = \"app\"\nversion = \"1.0\"\n\n[project.scripts]\nmycli = \"myapp.cli:main\"\n";
        let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        f.write_all(toml.as_bytes()).unwrap();

        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        assert!(
            project_has_entry_point_scripts(&project),
            "expected entry-point carve-out to be active"
        );
    }

    // Negative carve-out: no scripts in pyproject → returns false
    #[test]
    fn perf003_no_entry_points_carveout_inactive() {
        use std::io::Write as _;
        use zuit_core::Project;

        let dir = tempfile::TempDir::new().unwrap();
        let toml = "[project]\nname = \"lib\"\nversion = \"1.0\"\n";
        let mut f = std::fs::File::create(dir.path().join("pyproject.toml")).unwrap();
        f.write_all(toml.as_bytes()).unwrap();

        crate::manifest::clear_cache();
        let project = Project::new(dir.path(), vec![]);
        assert!(
            !project_has_entry_point_scripts(&project),
            "expected carve-out inactive when no scripts defined"
        );
    }
}
