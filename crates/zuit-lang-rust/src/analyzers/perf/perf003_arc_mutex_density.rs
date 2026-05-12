//! `PERF003-arc-mutex-density` — detects files with a high density of
//! `Arc<Mutex<…>>` usage, which may indicate over-reliance on shared
//! mutable state and unnecessary synchronisation overhead.
//!
//! **Algorithm:** scans the raw source text of each Rust file using the regex
//! `\bArc\s*<\s*Mutex\b`.  If any file exceeds the threshold (default 5
//! occurrences) one finding is emitted pinned to that file.
//!
//! **Threshold:** currently hardcoded at 5 per file; future configuration via
//! `[rust.perf] arc_mutex_density_threshold` is noted in the plan.

use regex::Regex;
use std::sync::OnceLock;

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};

const RULE_ID: &str = "PERF003-arc-mutex-density";

/// Default number of `Arc<Mutex<…>>` occurrences per file that triggers the rule.
const DEFAULT_THRESHOLD: usize = 5;

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/PERF003-arc-mutex-density.md",
    cwe: &[],
    owasp: &[],
};

/// Returns a compiled regex matching `Arc<Mutex<…>` usage.
fn arc_mutex_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bArc\s*<\s*Mutex\b").expect("PERF003 regex is valid"))
}

/// Analyzer for `PERF003-arc-mutex-density`.
pub struct Perf003ArcMutexDensity;

impl zuit_core::Analyzer for Perf003ArcMutexDensity {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("performance".to_string())
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
        let re = arc_mutex_regex();
        let rust_id = zuit_core::LanguageId("rust");

        // Count occurrences per file; track the file with the highest density.
        let mut max_count = 0usize;
        let mut max_file = None::<std::path::PathBuf>;

        for pf in &project.files {
            if pf.language() != rust_id {
                continue;
            }
            let src = pf.source();
            let count = re.find_iter(src.as_str()).count();
            if count > max_count {
                max_count = count;
                max_file = Some(src.path.clone());
            }
        }

        if max_count <= DEFAULT_THRESHOLD {
            return Vec::new();
        }

        let file_path = max_file.unwrap_or_else(|| project.root.clone());
        let relative = file_path
            .strip_prefix(&project.root)
            .unwrap_or(&file_path)
            .to_path_buf();

        vec![Finding {
            analyzer: AnalyzerId::new(RULE_ID),
            dimension: Dimension::Custom("performance".to_string()),
            rule_id: RULE_ID.to_string(),
            severity: Severity::Low,
            message: format!(
                "File contains {max_count} occurrences of `Arc<Mutex<…>>` (threshold: \
                 {DEFAULT_THRESHOLD}); excessive shared mutable state may cause lock contention \
                 and reduce parallelism."
            ),
            location: Location {
                file: relative,
                span: Span::new(ByteOffset(0), ByteOffset(0)),
                start: LineCol::new(1, 1),
                end: LineCol::new(1, 1),
            },
            suggestion: Some(
                "Consider actor-pattern designs, channels (`std::sync::mpsc`, `tokio::sync`), \
                 or per-item locks to reduce contention."
                    .to_string(),
            ),
            references: vec!["https://nnethercote.github.io/perf-book/".to_string()],
            cwe: vec![],
            owasp: vec![],
        }]
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::sync::Arc;

    use zuit_core::{Analyzer, Config, Project, SourceFile};

    use super::*;

    fn make_project_with_rust_file(content: &str) -> (tempfile::TempDir, Project) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("lib.rs");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();

        let src = Arc::new(SourceFile::new(
            path.to_str().unwrap(),
            content.as_bytes().to_vec(),
        ));
        let parsed = crate::parse::parse(src).unwrap();
        let project = Project::new(dir.path().to_path_buf(), vec![parsed]);
        (dir, project)
    }

    fn analyze(content: &str) -> Vec<Finding> {
        let (_dir, project) = make_project_with_rust_file(content);
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        Perf003ArcMutexDensity.analyze_project(&ctx, &project)
    }

    /// Positive: 6 occurrences → 1 finding.
    #[test]
    fn perf003_six_occurrences_fires() {
        let code =
            "use std::sync::{Arc, Mutex};\n".to_string() + &"type S = Arc<Mutex<u32>>;\n".repeat(6);
        let findings = analyze(&code);
        assert_eq!(findings.len(), 1, "expected 1 finding, got: {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert!(findings[0].message.contains('6'));
    }

    /// Negative: 4 occurrences → 0 findings.
    #[test]
    fn perf003_four_occurrences_silent() {
        let code =
            "use std::sync::{Arc, Mutex};\n".to_string() + &"type S = Arc<Mutex<u32>>;\n".repeat(4);
        let findings = analyze(&code);
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    /// Boundary: exactly threshold (5) → 0 findings; threshold + 1 (6) → 1 finding.
    #[test]
    fn perf003_boundary_at_threshold() {
        let at_threshold = "use std::sync::{Arc, Mutex};\n".to_string()
            + &"type S = Arc<Mutex<u32>>;\n".repeat(DEFAULT_THRESHOLD);
        assert!(
            analyze(&at_threshold).is_empty(),
            "at threshold should be silent"
        );

        let over_threshold = "use std::sync::{Arc, Mutex};\n".to_string()
            + &"type S = Arc<Mutex<u32>>;\n".repeat(DEFAULT_THRESHOLD + 1);
        assert_eq!(
            analyze(&over_threshold).len(),
            1,
            "over threshold should fire"
        );
    }
}
