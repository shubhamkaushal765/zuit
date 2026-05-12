//! `PERF001-bundle-size` — flags projects whose `dist/` directory exceeds 1 MiB.
//!
//! # Rationale
//!
//! A large unminified bundle suggests the package has not been tree-shaken or
//! split into smaller chunks. Consumers who install the package will download
//! and parse all of it, increasing page-load and startup latency.
//!
//! # Detection algorithm
//!
//! Recursively sums the byte sizes of every regular file directly under
//! `<project_root>/dist/`.  If the total exceeds `BUNDLE_SIZE_THRESHOLD`
//! bytes (1 MiB), one `PERF001-bundle-size` Low finding is emitted pointing at
//! the `dist/` directory.  If `dist/` does not exist the rule is skipped
//! silently.
//!
//! # Deviations from the plan
//!
//! The plan mentioned `walkdir` as a workspace dependency, but `walkdir` is not
//! listed in the workspace `Cargo.toml`.  A small recursive helper using
//! `std::fs::read_dir` is used instead to avoid adding a new dependency.

use std::fs;
use std::path::{Path, PathBuf};

use zuit_core::{
    AnalysisContext, AnalyzerId, AnalyzerKind, Dimension, Finding, Location, Project, RuleMeta,
    Severity, SupportedLanguages,
    span::{ByteOffset, LineCol, Span},
};

/// Rule ID for this analyzer.
const RULE_ID: &str = "PERF001-bundle-size";

/// Bundle-size threshold: 1 MiB.
const BUNDLE_SIZE_THRESHOLD: u64 = 1024 * 1024;

/// Static rule metadata.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Low,
    doc_path: "docs/rules/PERF001-bundle-size.md",
    cwe: &[],
    owasp: &[],
};

/// Recursively sums the byte sizes of all regular files under `dir`.
///
/// Silently skips entries that cannot be read (permission errors, broken
/// symlinks, etc.).  Returns `0` if `dir` is not a directory or cannot be
/// opened.
fn dir_bytes(dir: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut total: u64 = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            total = total.saturating_add(dir_bytes(&path));
        } else if path.is_file()
            && let Ok(meta) = fs::metadata(&path)
        {
            total = total.saturating_add(meta.len());
        }
    }
    total
}

/// Analyzer that emits `PERF001-bundle-size` when `dist/` exceeds 1 MiB.
pub struct Perf001BundleSizeAnalyzer;

impl zuit_core::Analyzer for Perf001BundleSizeAnalyzer {
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
        vec![]
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        let dist_dir = project.root.join("dist");
        if !dist_dir.is_dir() {
            return vec![];
        }

        let total_bytes = dir_bytes(&dist_dir);
        if total_bytes <= BUNDLE_SIZE_THRESHOLD {
            return vec![];
        }

        #[allow(clippy::cast_precision_loss)]
        let mib = total_bytes as f64 / (1024.0 * 1024.0);
        let zero = Span::new(ByteOffset(0), ByteOffset(0));
        vec![Finding {
            analyzer: AnalyzerId::new(RULE_ID),
            dimension: Dimension::Custom("performance".to_string()),
            rule_id: RULE_ID.to_string(),
            severity: Severity::Low,
            message: format!(
                "dist/ directory is {mib:.2} MiB unminified (threshold: 1 MiB); \
                 consider tree-shaking or code-splitting to reduce bundle size"
            ),
            location: Location {
                file: PathBuf::from("dist"),
                span: zero,
                start: LineCol::new(1, 1),
                end: LineCol::new(1, 1),
            },
            suggestion: Some(
                "Run your bundler with minification and tree-shaking enabled, \
                 or split the bundle into smaller chunks."
                    .to_string(),
            ),
            references: vec![],
            cwe: vec![],
            owasp: vec![],
        }]
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Analyzer, Config, Project, Severity};
    use std::io::Write;
    use tempfile::TempDir;

    fn run(root: &Path) -> Vec<Finding> {
        let project = Project::new(root.to_path_buf(), vec![]);
        let analyzer = Perf001BundleSizeAnalyzer;
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        analyzer.analyze_project(&ctx, &project)
    }

    // 1. dist/ over 1 MiB emits one Low finding
    #[test]
    fn perf001_dist_over_1mib_emits_low() {
        let tmp = TempDir::new().unwrap();
        let dist = tmp.path().join("dist");
        fs::create_dir(&dist).unwrap();

        // Write a 2 MiB file.
        let mut f = fs::File::create(dist.join("index.js")).unwrap();
        let chunk = vec![b'x'; 1024];
        for _ in 0..(2 * 1024) {
            f.write_all(&chunk).unwrap();
        }
        drop(f);

        let findings = run(tmp.path());
        assert_eq!(findings.len(), 1, "expected 1 finding, got {findings:#?}");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert_eq!(findings[0].location.file, PathBuf::from("dist"));
    }

    // 2. No dist/ → 0 findings
    #[test]
    fn perf001_no_dist_folder_clean() {
        let tmp = TempDir::new().unwrap();
        let findings = run(tmp.path());
        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:#?}"
        );
    }

    // 3. dist/ under 1 MiB → 0 findings
    #[test]
    fn perf001_dist_under_1mib_clean() {
        let tmp = TempDir::new().unwrap();
        let dist = tmp.path().join("dist");
        fs::create_dir(&dist).unwrap();
        let mut f = fs::File::create(dist.join("index.js")).unwrap();
        f.write_all(b"console.log('tiny');").unwrap();
        drop(f);

        let findings = run(tmp.path());
        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:#?}"
        );
    }

    // 4. dist/ exactly at threshold → 0 findings (boundary)
    #[test]
    fn perf001_dist_exactly_1mib_clean() {
        let tmp = TempDir::new().unwrap();
        let dist = tmp.path().join("dist");
        fs::create_dir(&dist).unwrap();
        let mut f = fs::File::create(dist.join("index.js")).unwrap();
        let data = vec![b'x'; 1024 * 1024]; // exactly 1 MiB
        f.write_all(&data).unwrap();
        drop(f);

        let findings = run(tmp.path());
        assert!(
            findings.is_empty(),
            "exactly 1 MiB must not trigger, got {findings:#?}"
        );
    }

    // 5. Recursive subdirs are included in the sum
    #[test]
    fn perf001_recursive_subdirs_counted() {
        let tmp = TempDir::new().unwrap();
        let dist = tmp.path().join("dist");
        let sub = dist.join("chunks");
        fs::create_dir_all(&sub).unwrap();

        // Write 0.6 MiB in root + 0.6 MiB in subdir = 1.2 MiB total → should flag
        let chunk = vec![b'x'; 1024];
        for (path, count) in [
            (dist.join("main.js"), 600_usize),
            (sub.join("chunk.js"), 600_usize),
        ] {
            let mut f = fs::File::create(path).unwrap();
            for _ in 0..count {
                f.write_all(&chunk).unwrap();
            }
        }

        let findings = run(tmp.path());
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding from recursive sum, got {findings:#?}"
        );
    }
}
