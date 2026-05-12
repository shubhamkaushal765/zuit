//! `PERF002-wheel-size` — detects oversized distribution artifacts.
//!
//! Large wheels and source distributions inflate install time, CI cache
//! pressure, and end-user download time.  Thresholds:
//! - `dist/*.whl` over **50 MiB** → Low severity finding.
//! - `dist/*.tar.gz` over **100 MiB** → Low severity finding.
//!
//! **Scope:** `AnalyzerKind::ProjectLevel`.
//! **Dimension:** `Custom("performance")`.
//! **Severity:** Low.

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};

const RULE_ID: &str = "PERF002-wheel-size";

const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/PERF002-wheel-size.md",
    cwe: &[],
    owasp: &[],
};

const WHL_LIMIT_BYTES: u64 = 50 * 1024 * 1024; // 50 MiB
const TARGZ_LIMIT_BYTES: u64 = 100 * 1024 * 1024; // 100 MiB

fn zero_span() -> Span {
    Span::new(ByteOffset(0), ByteOffset(0))
}

/// Analyzer that emits `PERF002-wheel-size` for oversized distribution files
/// under the `dist/` directory.
pub struct Perf002WheelSize;

impl zuit_core::Analyzer for Perf002WheelSize {
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
        let dist_dir = project.root.join("dist");
        if !dist_dir.is_dir() {
            return Vec::new();
        }

        let Ok(entries) = std::fs::read_dir(&dist_dir) else {
            return Vec::new();
        };

        let mut findings = Vec::new();

        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            let is_whl = std::path::Path::new(file_name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("whl"));
            let is_targz = file_name.ends_with(".tar.gz");

            if !is_whl && !is_targz {
                continue;
            }

            let size_bytes = match entry.metadata() {
                Ok(m) => m.len(),
                Err(_) => continue,
            };

            let limit = if is_whl {
                WHL_LIMIT_BYTES
            } else {
                TARGZ_LIMIT_BYTES
            };
            let limit_mib = limit / (1024 * 1024);

            if size_bytes > limit {
                #[allow(clippy::cast_precision_loss)]
                let size_mib = size_bytes as f64 / (1024.0 * 1024.0);
                let rel_path = path
                    .strip_prefix(&project.root)
                    .unwrap_or(&path)
                    .to_path_buf();

                findings.push(Finding {
                    analyzer: AnalyzerId::new(RULE_ID),
                    dimension: Dimension::Custom("performance".to_string()),
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Low,
                    message: format!(
                        "`{file_name}` is {size_mib:.1} MiB, exceeding the {limit_mib} MiB \
                         threshold; large distributions inflate install time and bandwidth"
                    ),
                    location: Location {
                        file: rel_path,
                        span: zero_span(),
                        start: LineCol::new(1, 1),
                        end: LineCol::new(1, 1),
                    },
                    suggestion: Some(
                        "Audit the package contents (`unzip -l dist/*.whl`), exclude large \
                         test/fixture data or vendored binaries, and rebuild."
                            .to_string(),
                    ),
                    references: vec![
                        "https://packaging.python.org/en/latest/guides/distributing-packages-using-setuptools/#wheels".to_string(),
                    ],
                    cwe: vec![],
                    owasp: vec![],
                });
            }
        }

        findings
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Analyzer, Config, Project};

    fn run_on_dir(dir: &std::path::Path) -> Vec<Finding> {
        let project = Project::new(dir, vec![]);
        let analyzer = Perf002WheelSize;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    // 3. fake 60 MiB .whl → one PERF002 Low
    #[test]
    fn perf002_wheel_too_large() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("dist")).unwrap();
        let whl_path = dir.path().join("dist").join("foo-1.0-py3-none-any.whl");
        let file = std::fs::File::create(&whl_path).unwrap();
        file.set_len(60 * 1024 * 1024).unwrap(); // sparse 60 MiB

        let findings = run_on_dir(dir.path());
        assert_eq!(findings.len(), 1, "expected 1 finding: {findings:#?}");
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    // Negative: .whl exactly at or below 50 MiB → 0 findings
    #[test]
    fn perf002_wheel_exactly_at_limit_no_finding() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("dist")).unwrap();
        let whl_path = dir.path().join("dist").join("bar-1.0-py3-none-any.whl");
        let file = std::fs::File::create(&whl_path).unwrap();
        file.set_len(50 * 1024 * 1024).unwrap();

        let findings = run_on_dir(dir.path());
        assert!(
            findings.is_empty(),
            "expected 0 findings at exactly the limit: {findings:#?}"
        );
    }

    // tar.gz over 100 MiB → 1 finding
    #[test]
    fn perf002_targz_too_large() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("dist")).unwrap();
        let targz_path = dir.path().join("dist").join("mylib-1.0.tar.gz");
        let file = std::fs::File::create(&targz_path).unwrap();
        file.set_len(110 * 1024 * 1024).unwrap();

        let findings = run_on_dir(dir.path());
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for .tar.gz: {findings:#?}"
        );
        assert_eq!(findings[0].severity, Severity::Low);
    }

    // No dist/ directory → 0 findings
    #[test]
    fn perf002_no_dist_dir_no_finding() {
        let dir = tempfile::TempDir::new().unwrap();
        let findings = run_on_dir(dir.path());
        assert!(
            findings.is_empty(),
            "expected 0 findings with no dist/: {findings:#?}"
        );
    }

    // Suppression directive format
    #[test]
    fn perf002_suppression_directive_format() {
        let directive = "# zuit: ignore PERF002-wheel-size";
        assert!(directive.contains("zuit: ignore"));
        assert!(directive.contains("PERF002-wheel-size"));
    }
}
