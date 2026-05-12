//! [`Engine`]: orchestrates file walking, parallel parsing, analysis dispatch,
//! and finding aggregation into a [`Report`].
//!
//! The determinism contract (`ARCH_SPEC` §10) is enforced here:
//! 1. Files are walked in lexicographic order before being dispatched.
//! 2. Findings from all analyzers are sorted by `(file, span.start, rule_id)`
//!    once, after all workers have returned.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing;

use crate::analyzer::{AnalysisContext, AnalyzerKind, Dimension, Project};
use crate::cache::{AnalysisCache, CacheEntry, hash_config};
use crate::config::{Config, parse_override_severity};
use crate::error::EngineError;
use crate::finding::{Finding, sort_findings};
use crate::index::Suppression;
use crate::parsed::ParsedFile;
use crate::registry::Registry;
use crate::score::{Score, aggregate_dimension_score};
use crate::source::SourceFile;
use crate::walk::walk_files;

/// Statistics collected during a single [`Engine::analyze_path`] run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunStats {
    /// Total number of files successfully scanned.
    pub files_scanned: u32,
    /// Number of files that failed to parse.
    pub parse_failures: u32,
    /// Wall-clock time for the full analysis in milliseconds.
    pub elapsed_ms: u64,
    /// Number of findings suppressed via `zuit: ignore` directives.
    #[serde(default)]
    pub suppressed: u32,
    /// Number of files whose results were served from the incremental cache
    /// (i.e., content hash matched and re-parse was skipped).
    ///
    /// Always 0 when [`Engine::analyze_path`] is used; populated by
    /// [`Engine::analyze_path_cached`].
    #[serde(default)]
    pub cache_hits: u32,
}

/// The complete output of an [`Engine::analyze_path`] call.
///
/// Findings are sorted by `(file, span.start, rule_id)` before this struct
/// is returned.  Scores are keyed by [`Dimension`].
///
/// `scores` uses [`BTreeMap`] so that the JSON representation is
/// deterministic: dimensions always appear in the canonical derived-`Ord` order
/// (`Maintainability`, `Security`, `Complexity`, `Documentation`, `TestSmell`,
/// then any `Custom` dimensions in lexicographic order).
#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    /// JSON schema version.  Starts at 1; bumped on any breaking change.
    pub schema_version: u32,
    /// All findings in deterministic order.
    pub findings: Vec<Finding>,
    /// Per-dimension aggregate scores in deterministic (`BTreeMap`) order.
    pub scores: BTreeMap<Dimension, Score>,
    /// Summary statistics for this run.
    pub stats: RunStats,
}

/// The static analysis engine.
///
/// Holds a [`Registry`] and drives the full analysis pipeline: walk -> parse ->
/// analyse per-file -> analyse project -> aggregate scores -> sort findings.
pub struct Engine {
    registry: Registry,
}

impl Engine {
    /// Creates an `Engine` backed by the given registry.
    #[must_use]
    pub fn new(registry: Registry) -> Self {
        Self { registry }
    }

    /// Returns a reference to the underlying registry.
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Analyses all source files under `path` and returns a [`Report`].
    ///
    /// # Pipeline
    ///
    /// 1. Collect all file extensions claimed by registered languages.
    /// 2. Walk `path` for files with those extensions (lexicographic order).
    /// 3. Parse each file with its language frontend (in parallel via `rayon`).
    /// 4. Run each applicable analyzer against each successfully-parsed file
    ///    (also in parallel).
    /// 5. Run project-level analysis for each analyzer.
    /// 6. Sort all findings.
    /// 7. Compute per-dimension scores.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Io`] if the root path cannot be walked, or
    /// [`EngineError::Config`] if the config is invalid.  Individual file parse
    /// failures are counted in [`RunStats::parse_failures`] but do not abort
    /// the run.
    pub fn analyze_path(&self, path: &Path, config: &Config) -> Result<Report, EngineError> {
        let start = Instant::now();

        // 1. Collect all extensions known to the registry.
        let extensions = self.collect_extensions();

        // 2. Walk and sort.
        let paths = walk_files(path, &extensions, config)?;

        // 3. Parse in parallel.
        let (parsed_files, parse_failures_count) = self.parse_files_parallel(&paths);

        let files_scanned = u32::try_from(parsed_files.len()).unwrap_or(u32::MAX);

        // 4. Run per-file analysis in parallel.
        let ctx = AnalysisContext::new(config);
        let analyzers: Vec<&dyn crate::analyzer::Analyzer> = self.registry.analyzers().collect();

        let per_file_findings: Vec<Finding> = parsed_files
            .par_iter()
            .flat_map(|pf| {
                let lang_id = pf.language();
                analyzers
                    .iter()
                    .filter(|a| {
                        a.kind() == AnalyzerKind::FileLevel
                            && a.supported_languages().supports(lang_id)
                    })
                    .flat_map(|a| a.analyze_file(&ctx, pf))
                    .collect::<Vec<_>>()
            })
            .collect();

        // 5. Run project-level analysis (parallel via rayon).
        let project = Project::new(path, parsed_files);
        let mut all_findings: Vec<Finding> = per_file_findings;

        let project_findings: Vec<Finding> = analyzers
            .par_iter()
            .filter(|a| a.kind() != AnalyzerKind::FileLevel)
            .flat_map_iter(|a| a.analyze_project(&ctx, &project))
            .collect();
        all_findings.extend(project_findings);

        // 5b–6. Suppress, apply overrides, sort deterministically.
        let suppressed_count = finalize_findings(&mut all_findings, &project, config, path);

        // 7. Compute per-dimension scores.
        let kloc = compute_kloc(&project.files);
        let scores = compute_scores(&all_findings, kloc);

        // Duration::as_millis returns u128; u64 can hold ~580 million years of ms.
        #[allow(clippy::cast_possible_truncation)]
        let elapsed_ms = start.elapsed().as_millis() as u64;

        Ok(Report {
            schema_version: 1,
            findings: all_findings,
            scores,
            stats: RunStats {
                files_scanned,
                parse_failures: parse_failures_count,
                elapsed_ms,
                suppressed: suppressed_count,
                cache_hits: 0,
            },
        })
    }

    /// Returns all file extensions registered across known languages.
    fn collect_extensions(&self) -> Vec<&'static str> {
        self.registry
            .languages()
            .flat_map(|l| l.extensions().iter().copied())
            .collect()
    }

    /// Parses `paths` in parallel and returns `(parsed_files, parse_failures_count)`.
    fn parse_files_parallel(&self, paths: &[std::path::PathBuf]) -> (Vec<ParsedFile>, u32) {
        let parse_failures = Arc::new(AtomicU32::new(0));

        let parsed_files: Vec<_> = paths
            .par_iter()
            .filter_map(|file_path| {
                let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                let lang = self.registry.language_for_extension(ext)?;

                let Ok(bytes) = std::fs::read(file_path) else {
                    parse_failures.fetch_add(1, Ordering::Relaxed);
                    return None;
                };
                let source = Arc::new(SourceFile::new(file_path.clone(), bytes));
                if let Ok(pf) = lang.parse(Arc::clone(&source)) {
                    Some(pf)
                } else {
                    parse_failures.fetch_add(1, Ordering::Relaxed);
                    None
                }
            })
            .collect();

        let count = parse_failures.load(Ordering::Relaxed);
        (parsed_files, count)
    }

    /// Analyses all source files under `path`, reusing the incremental cache for
    /// files whose content hash **and** config hash are unchanged.
    ///
    /// # Cache contract (v2 -- content-hash + config-hash)
    ///
    /// Each file's content is hashed with BLAKE3.  If the content hash AND the
    /// config hash both match the stored entry, the cached [`Finding`]s are
    /// reused and re-parsing is skipped.  If the config changes, all cache
    /// entries that were written with the old config are treated as misses and
    /// `tracing::warn!("zuit cache invalidated: config changed")` is emitted
    /// once per run.
    ///
    /// Project-level analyzers (`analyze_project`) always re-run on every call
    /// because they depend on the cross-file set of `ParsedFile`s which is not
    /// stored in the cache.
    ///
    /// Files that no longer exist on disk are pruned from the cache before the
    /// caller saves it.
    ///
    /// # Errors
    ///
    /// Same error conditions as [`Engine::analyze_path`].
    #[allow(clippy::too_many_lines)] // inherently complex: cache check + parse + update + project analysis
    pub fn analyze_path_cached(
        &self,
        path: &Path,
        config: &Config,
        cache: &mut AnalysisCache,
    ) -> Result<Report, EngineError> {
        use crate::cache::hash_bytes;

        let start = Instant::now();

        // 1. Collect all extensions known to the registry.
        let extensions = self.collect_extensions();

        // 2. Walk and sort.
        let paths = walk_files(path, &extensions, config)?;

        // 3. Reset per-run hit counter.
        cache.reset_hits();

        // Compute the config hash once -- used to validate cache entries.
        let current_config_hash = hash_config(config);

        // AtomicU32 counters -- lock-free increment-only counters for the
        // parallel pass.  Relaxed ordering is sufficient: we only read the
        // final values after the parallel iterator has joined.
        let parse_failures = Arc::new(AtomicU32::new(0));
        let hit_count = Arc::new(AtomicU32::new(0));
        // Track whether any miss was due to config-hash mismatch (for warning).
        let config_miss_count = Arc::new(AtomicU32::new(0));

        // 4. Single parallel pass: for each file, either return cached findings
        //    (hit) or run the analyzers now (miss).  This eliminates the ss4.1
        //    double-execution bug where the parallel pass built ParsedFiles and
        //    a separate sequential pass re-ran the same analyzers to populate
        //    the cache.
        //
        // Each element: (ParsedFile, Vec<Finding>, is_hit: bool, content_hash)
        let ctx = AnalysisContext::new(config);
        let analyzers: Vec<&dyn crate::analyzer::Analyzer> = self.registry.analyzers().collect();
        let cfg_hash_ref = &current_config_hash;

        let file_results: Vec<(ParsedFile, Vec<Finding>, bool, String)> = paths
            .par_iter()
            .filter_map(|file_path| {
                let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                let lang = self.registry.language_for_extension(ext)?;

                let Ok(bytes) = std::fs::read(file_path) else {
                    parse_failures.fetch_add(1, Ordering::Relaxed);
                    return None;
                };

                let current_hash = hash_bytes(&bytes);

                // Check cache: path must exist, content hash AND config hash must match.
                if let Some(entry) = cache.get(file_path)
                    && entry.content_hash == current_hash
                {
                    if entry.config_hash == *cfg_hash_ref {
                        // Full cache hit -- parse is still needed for project analysis.
                        let findings = entry.findings.clone();
                        let source = Arc::new(SourceFile::new(file_path.clone(), bytes));
                        if let Ok(pf) = lang.parse(Arc::clone(&source)) {
                            hit_count.fetch_add(1, Ordering::Relaxed);
                            return Some((pf, findings, true, current_hash));
                        }
                        // Parse failed even though file is cached -- treat as miss.
                        parse_failures.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                    // Content matches but config changed -> config-hash miss.
                    config_miss_count.fetch_add(1, Ordering::Relaxed);
                }

                // Cache miss: parse + run analyzers.
                let source = Arc::new(SourceFile::new(file_path.clone(), bytes));
                let Ok(pf) = lang.parse(Arc::clone(&source)) else {
                    parse_failures.fetch_add(1, Ordering::Relaxed);
                    return None;
                };
                let lang_id = pf.language();
                let findings: Vec<Finding> = analyzers
                    .iter()
                    .filter(|a| {
                        a.kind() == AnalyzerKind::FileLevel
                            && a.supported_languages().supports(lang_id)
                    })
                    .flat_map(|a| a.analyze_file(&ctx, &pf))
                    .collect();
                Some((pf, findings, false, current_hash))
            })
            .collect();

        let files_scanned = u32::try_from(file_results.len()).unwrap_or(u32::MAX);
        let parse_failures_count = parse_failures.load(Ordering::Relaxed);
        let raw_hits = hit_count.load(Ordering::Relaxed);
        let config_misses = config_miss_count.load(Ordering::Relaxed);

        // Warn once if any entry was invalidated solely due to a config change.
        if config_misses > 0 {
            tracing::warn!("zuit cache invalidated: config changed");
        }

        // 5. Collect per-file findings and update cache for misses (sequential
        //    to avoid aliased-mut borrow of `cache`).
        let mut per_file_findings: Vec<Finding> = Vec::new();
        let mut parsed_files: Vec<ParsedFile> = Vec::with_capacity(file_results.len());

        for (pf, findings, is_hit, content_hash) in file_results {
            per_file_findings.extend(findings.iter().cloned());
            if !is_hit {
                // Populate the cache for this miss.
                let file_path = pf.source().path.clone();
                cache.insert(
                    file_path,
                    CacheEntry {
                        content_hash,
                        config_hash: current_config_hash.clone(),
                        findings,
                        parse_failed: false,
                    },
                );
            }
            parsed_files.push(pf);
        }

        // Batch-update hit counter -- avoids the old loop of raw_hits x record_hit().
        cache.record_hit_n(raw_hits);

        // 6. Prune deleted files from the cache.
        cache.prune(&paths);

        // 7. Run project-level analysis (parallel via rayon; always runs; not cached).
        let project = Project::new(path, parsed_files);
        let mut all_findings: Vec<Finding> = per_file_findings;

        let project_findings: Vec<Finding> = analyzers
            .par_iter()
            .filter(|a| a.kind() != AnalyzerKind::FileLevel)
            .flat_map_iter(|a| a.analyze_project(&ctx, &project))
            .collect();
        all_findings.extend(project_findings);

        // 8–9. Suppress, apply overrides, sort deterministically.
        let suppressed_count = finalize_findings(&mut all_findings, &project, config, path);

        // 10. Compute scores.
        let kloc = compute_kloc(&project.files);
        let scores = compute_scores(&all_findings, kloc);

        #[allow(clippy::cast_possible_truncation)]
        let elapsed_ms = start.elapsed().as_millis() as u64;

        Ok(Report {
            schema_version: 1,
            findings: all_findings,
            scores,
            stats: RunStats {
                files_scanned,
                parse_failures: parse_failures_count,
                elapsed_ms,
                suppressed: suppressed_count,
                cache_hits: raw_hits,
            },
        })
    }
}

/// Suppresses findings, applies severity overrides, and sorts deterministically; returns suppressed count.
fn finalize_findings(
    findings: &mut Vec<Finding>,
    project: &Project,
    config: &Config,
    root: &Path,
) -> u32 {
    let suppression_map = build_suppression_map(&project.files);
    let suppressed_count = filter_suppressed(findings, &suppression_map);
    apply_per_glob_overrides(findings, config, root);
    apply_rule_severity_overrides(findings, config);
    sort_findings(findings);
    suppressed_count
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("registry", &self.registry)
            .finish()
    }
}

/// Builds a map from canonical file path to the suppressions recorded for
/// that file.
fn build_suppression_map(files: &[ParsedFile]) -> HashMap<std::path::PathBuf, Vec<Suppression>> {
    let mut map: HashMap<std::path::PathBuf, Vec<Suppression>> = HashMap::new();
    for pf in files {
        let path = pf.source().path.clone();
        let suppressions = pf.index().suppressions.clone();
        if !suppressions.is_empty() {
            map.insert(path, suppressions);
        }
    }
    map
}

/// Removes findings that are covered by a suppression directive and returns
/// the count of removed findings.
///
/// A finding is suppressed when:
/// - A file-scoped `Suppression { file_scoped: true, rule_id }` exists for
///   the finding's file and rule.
/// - A line-scoped `Suppression { file_scoped: false, line, rule_id }` exists
///   where `rule_id` matches and `line == finding.start.line` or
///   `line + 1 == finding.start.line` (directive on the line above).
pub(crate) fn filter_suppressed(
    findings: &mut Vec<Finding>,
    suppression_map: &HashMap<std::path::PathBuf, Vec<Suppression>>,
) -> u32 {
    if suppression_map.is_empty() {
        return 0;
    }
    let before = findings.len();
    findings.retain(|f| {
        let Some(suppressions) = suppression_map.get(&f.location.file) else {
            return true; // no suppressions for this file -> keep
        };
        let finding_line = f.location.start.line;
        let rule = &f.rule_id;
        !suppressions.iter().any(|s| {
            if s.rule_id != *rule {
                return false;
            }
            if s.file_scoped {
                return true;
            }
            // Inline (same line) or directive on the line above.
            s.line == finding_line || s.line + 1 == finding_line
        })
    });
    let after = findings.len();
    // before >= after because retain only removes.
    #[allow(clippy::cast_possible_truncation)]
    {
        (before - after) as u32
    }
}

/// Applies per-glob and global rule severity overrides from the config.
///
/// The precedence order is:
/// 1. Per-glob overrides (highest priority): if a path matches a glob in
///    `rules.<id>.overrides`, that value is used.
/// 2. Global rule severity (`rules.<id>.severity`): applied only when no
///    per-glob match was found.
///
/// For each finding the function:
/// - Looks up `config.rule_overrides(&finding.rule_id)`.
/// - Builds a `GlobSet` from the override keys and matches against the finding's
///   path relative to `root`.
/// - If a glob matches: `"ignore"` → remove; otherwise rewrite severity.
/// - If no glob matches: fall through to global `rules.<id>.severity`.
///
/// Invalid severity strings emit `tracing::warn!` and are treated as no-ops.
fn apply_per_glob_overrides(findings: &mut Vec<Finding>, config: &Config, root: &Path) {
    use globset::{GlobBuilder, GlobSetBuilder};

    findings.retain_mut(|finding| {
        let rule_id = &finding.rule_id;

        // --- Step 1: per-glob overrides (highest precedence) -----------------
        if let Some(overrides) = config.rule_overrides(rule_id)
            && !overrides.is_empty()
        {
            // Build a GlobSet from the BTreeMap keys (deterministic order).
            let mut builder = GlobSetBuilder::new();
            for glob_str in overrides.keys() {
                match GlobBuilder::new(glob_str).literal_separator(true).build() {
                    Ok(g) => {
                        builder.add(g);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "invalid glob pattern '{}' in rules.{}.overrides: {}",
                            glob_str,
                            rule_id,
                            e
                        );
                    }
                }
            }
            if let Ok(glob_set) = builder.build() {
                // Path relative to root; fall back to absolute on error.
                let rel_path = finding
                    .location
                    .file
                    .strip_prefix(root)
                    .unwrap_or(&finding.location.file);

                let matches = glob_set.matches(rel_path);
                if !matches.is_empty() {
                    // First match wins (BTreeMap insertion order = alphabetical).
                    let matched_idx = matches[0];
                    let sev_str = overrides
                        .values()
                        .nth(matched_idx)
                        .map_or("", String::as_str);

                    return match parse_override_severity(sev_str) {
                        Ok(None) => false, // "ignore" → drop
                        Ok(Some(sev)) => {
                            finding.severity = sev;
                            true
                        }
                        Err(e) => {
                            tracing::warn!(
                                "invalid severity '{}' in rules.{}.overrides: {}",
                                sev_str,
                                rule_id,
                                e
                            );
                            true // no-op
                        }
                    };
                    // ↑ early return: per-glob matched, skip global override
                }
            }
        }

        // --- Step 2: global rule severity (lower precedence) -----------------
        if let Some(sev_str) = config.rule_severity(rule_id) {
            return match parse_override_severity(sev_str) {
                Ok(None) => false, // "ignore" → drop
                Ok(Some(sev)) => {
                    finding.severity = sev;
                    true
                }
                Err(_) => true, // defensive no-op; already caught by Config::validate
            };
        }

        true // no override → keep unchanged
    });
}

/// Applies the global per-rule severity override from the config.
///
/// This is a separate post-pass kept for the pipeline wiring comments, but the
/// actual logic has been merged into [`apply_per_glob_overrides`] so that
/// per-glob takes precedence over global severity. This function is a no-op
/// placeholder so pipeline call sites remain readable.
#[inline]
fn apply_rule_severity_overrides(_findings: &mut Vec<Finding>, _config: &Config) {
    // Logic merged into apply_per_glob_overrides to respect precedence.
}

/// Estimates the project's effective KLOC from parsed files.
///
/// Uses the raw byte length divided by an average-line-length heuristic (80
/// bytes per line) as a cheap approximation that avoids a second file scan.
fn compute_kloc(files: &[crate::parsed::ParsedFile]) -> f32 {
    const AVG_LINE_BYTES: f32 = 80.0;
    let total_bytes: usize = files.iter().map(|f| f.source().len()).sum();
    #[allow(clippy::cast_precision_loss)]
    let kloc = (total_bytes as f32 / AVG_LINE_BYTES) / 1000.0;
    kloc
}

/// Aggregates per-dimension scores from a sorted list of findings.
///
/// Returns a [`BTreeMap`] so the result is in deterministic order: v1
/// dimensions first (in their derived-`Ord` order), then any `Custom`
/// dimensions in lexicographic order.
fn compute_scores(findings: &[Finding], kloc: f32) -> BTreeMap<Dimension, Score> {
    use crate::analyzer::Severity;
    let mut dim_sevs: HashMap<&Dimension, Vec<Severity>> = HashMap::new();

    for f in findings {
        dim_sevs.entry(&f.dimension).or_default().push(f.severity);
    }

    // Always include at least the five v1 dimensions so the report is complete
    // even when a dimension has no findings.
    let v1_dims = [
        Dimension::Maintainability,
        Dimension::Security,
        Dimension::Complexity,
        Dimension::Documentation,
        Dimension::TestSmell,
    ];

    let mut scores = BTreeMap::new();
    for dim in &v1_dims {
        let sevs = dim_sevs
            .get(dim)
            .map_or(&[] as &[Severity], |v| v.as_slice());
        scores.insert(dim.clone(), aggregate_dimension_score(sevs, kloc));
    }

    // Also include any Custom dimensions that appear in findings.
    for (dim, sevs) in &dim_sevs {
        if !scores.contains_key(*dim) {
            scores.insert((*dim).clone(), aggregate_dimension_score(sevs, kloc));
        }
    }

    scores
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    use crate::analyzer::{
        AnalysisContext, Analyzer, Dimension, RuleMeta, Severity, SupportedLanguages,
    };
    use crate::config::Config;
    use crate::finding::Finding;
    use crate::id::{AnalyzerId, LanguageId};
    use crate::language::tests::MockLanguage;
    use crate::parsed::ParsedFile;
    use crate::span::{ByteOffset, LineCol, Location, Span};

    struct CountingAnalyzer {
        pub findings_per_file: Vec<Finding>,
    }

    impl Analyzer for CountingAnalyzer {
        fn id(&self) -> AnalyzerId {
            AnalyzerId::new("counting")
        }
        fn dimension(&self) -> Dimension {
            Dimension::Maintainability
        }
        fn supported_languages(&self) -> SupportedLanguages {
            SupportedLanguages::All
        }
        fn rules(&self) -> &[RuleMeta] {
            &[]
        }
        fn analyze_file(&self, _ctx: &AnalysisContext<'_>, _file: &ParsedFile) -> Vec<Finding> {
            self.findings_per_file.clone()
        }
    }

    /// An analyzer whose findings embed the actual file path in their message.
    ///
    /// Used as a regression test for ss4.7: catches any divergence between
    /// cold-run and warm-run findings caused by the cache returning findings
    /// produced for the wrong file path.
    struct PathEmbeddingAnalyzer;

    impl Analyzer for PathEmbeddingAnalyzer {
        fn id(&self) -> AnalyzerId {
            AnalyzerId::new("path-embedding")
        }
        fn dimension(&self) -> Dimension {
            Dimension::Maintainability
        }
        fn supported_languages(&self) -> SupportedLanguages {
            SupportedLanguages::All
        }
        fn rules(&self) -> &[RuleMeta] {
            &[]
        }
        fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
            // Message embeds the real file path so cold vs warm runs can be
            // compared byte-for-byte.
            vec![Finding {
                analyzer: AnalyzerId::new("path-embedding"),
                dimension: Dimension::Maintainability,
                rule_id: "PATH001".to_string(),
                severity: Severity::Low,
                message: format!("found in {}", file.source().path.display()),
                location: Location {
                    file: file.source().path.clone(),
                    span: Span::new(ByteOffset(0), ByteOffset(1)),
                    start: LineCol::new(1, 1),
                    end: LineCol::new(1, 2),
                },
                suggestion: None,
                references: vec![],
                cwe: vec![],
                owasp: vec![],
            }]
        }
    }

    fn make_finding(file: &str, start: u32, rule: &str) -> Finding {
        Finding {
            analyzer: AnalyzerId::new("test"),
            dimension: Dimension::Maintainability,
            rule_id: rule.to_string(),
            severity: Severity::Medium,
            message: "test".to_string(),
            location: Location {
                file: std::path::PathBuf::from(file),
                span: Span::new(ByteOffset(start), ByteOffset(start + 1)),
                start: LineCol::new(1, 1),
                end: LineCol::new(1, 2),
            },
            suggestion: None,
            references: vec![],
            cwe: vec![],
            owasp: vec![],
        }
    }

    fn build_registry() -> Registry {
        let mut r = Registry::new();
        r.add_language(Box::new(MockLanguage {
            id: LanguageId("mock"),
            exts: &["mock"],
        }));
        r
    }

    #[test]
    fn empty_directory_returns_empty_report() {
        let tmp = TempDir::new().unwrap();
        let engine = Engine::new(build_registry());
        let config = Config::default();
        let report = engine.analyze_path(tmp.path(), &config).unwrap();
        assert!(report.findings.is_empty());
        assert_eq!(report.stats.files_scanned, 0);
        assert_eq!(report.schema_version, 1);
    }

    #[test]
    fn dispatches_to_analyzer_and_returns_findings() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.mock"), "content").unwrap();

        let finding = make_finding("a.mock", 0, "RULE-A");

        let mut r = Registry::new();
        r.add_language(Box::new(MockLanguage {
            id: LanguageId("mock"),
            exts: &["mock"],
        }));
        r.add_analyzer(Box::new(CountingAnalyzer {
            findings_per_file: vec![finding],
        }));

        let engine = Engine::new(r);
        let config = Config::default();
        let report = engine.analyze_path(tmp.path(), &config).unwrap();
        assert_eq!(report.stats.files_scanned, 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "RULE-A");
    }

    #[test]
    fn findings_are_sorted_deterministically() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("b.mock"), "").unwrap();
        fs::write(tmp.path().join("a.mock"), "").unwrap();

        let findings = vec![
            make_finding("b.mock", 5, "RULE-Z"),
            make_finding("a.mock", 10, "RULE-B"),
            make_finding("a.mock", 5, "RULE-A"),
        ];

        let mut r = Registry::new();
        r.add_language(Box::new(MockLanguage {
            id: LanguageId("mock"),
            exts: &["mock"],
        }));
        r.add_analyzer(Box::new(CountingAnalyzer {
            findings_per_file: findings,
        }));

        let engine = Engine::new(r);
        let config = Config::default();
        let report = engine.analyze_path(tmp.path(), &config).unwrap();

        let is_sorted = report.findings.windows(2).all(|w| w[0] <= w[1]);
        assert!(
            is_sorted,
            "findings are not in sorted order: {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.location.file, f.location.span.start, &f.rule_id))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn scores_contain_all_v1_dimensions() {
        let tmp = TempDir::new().unwrap();
        let engine = Engine::new(build_registry());
        let config = Config::default();
        let report = engine.analyze_path(tmp.path(), &config).unwrap();

        assert!(report.scores.contains_key(&Dimension::Maintainability));
        assert!(report.scores.contains_key(&Dimension::Security));
        assert!(report.scores.contains_key(&Dimension::Complexity));
        assert!(report.scores.contains_key(&Dimension::Documentation));
        assert!(report.scores.contains_key(&Dimension::TestSmell));
    }

    #[test]
    fn parse_failures_are_counted_not_fatal() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("x.unknown_ext"), "").unwrap();

        let engine = Engine::new(build_registry());
        let config = Config::default();
        let report = engine.analyze_path(tmp.path(), &config).unwrap();
        assert_eq!(report.stats.files_scanned, 0);
        assert_eq!(report.stats.parse_failures, 0);
    }

    // -- Task 1: Report.scores JSON is deterministic ---------------------------

    #[test]
    fn report_scores_json_is_deterministic() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.mock"), "content").unwrap();

        let mut r = Registry::new();
        r.add_language(Box::new(MockLanguage {
            id: LanguageId("mock"),
            exts: &["mock"],
        }));
        r.add_analyzer(Box::new(CountingAnalyzer {
            findings_per_file: vec![make_finding("a.mock", 0, "RULE-A")],
        }));

        let engine = Engine::new(r);
        let config = Config::default();
        let report1 = engine.analyze_path(tmp.path(), &config).unwrap();
        let report2 = engine.analyze_path(tmp.path(), &config).unwrap();

        let json1 = serde_json::to_string(&report1.scores).unwrap();
        let json2 = serde_json::to_string(&report2.scores).unwrap();
        assert_eq!(json1, json2, "scores JSON must be byte-for-byte identical");
    }

    #[test]
    fn report_scores_dimensions_appear_in_canonical_order() {
        let tmp = TempDir::new().unwrap();
        let engine = Engine::new(build_registry());
        let config = Config::default();
        let report = engine.analyze_path(tmp.path(), &config).unwrap();

        let keys: Vec<&Dimension> = report.scores.keys().collect();
        // Derived Ord order: Maintainability < Security < Complexity < Documentation < TestSmell
        assert_eq!(
            keys,
            vec![
                &Dimension::Maintainability,
                &Dimension::Security,
                &Dimension::Complexity,
                &Dimension::Documentation,
                &Dimension::TestSmell,
            ],
            "dimensions must appear in canonical (derived-Ord) order"
        );
    }

    // -- filter_suppressed unit tests ------------------------------------------

    use crate::index::Suppression;

    fn make_finding_at_line(file: &str, line: u32, rule: &str) -> Finding {
        Finding {
            analyzer: AnalyzerId::new("test"),
            dimension: Dimension::Maintainability,
            rule_id: rule.to_string(),
            severity: crate::analyzer::Severity::Medium,
            message: "test".to_string(),
            location: Location {
                file: std::path::PathBuf::from(file),
                span: Span::new(ByteOffset(0), ByteOffset(1)),
                start: LineCol::new(line, 1),
                end: LineCol::new(line, 2),
            },
            suggestion: None,
            references: vec![],
            cwe: vec![],
            owasp: vec![],
        }
    }

    fn suppression(line: u32, rule: &str, file_scoped: bool) -> Suppression {
        Suppression {
            line,
            rule_id: rule.to_string(),
            file_scoped,
        }
    }

    #[test]
    fn inline_same_line_suppression_removes_finding() {
        let mut findings = vec![make_finding_at_line("a.rs", 5, "RULE1")];
        let mut map = HashMap::new();
        map.insert(
            std::path::PathBuf::from("a.rs"),
            vec![suppression(5, "RULE1", false)],
        );
        let count = filter_suppressed(&mut findings, &map);
        assert_eq!(count, 1);
        assert!(findings.is_empty());
    }

    #[test]
    fn line_above_suppression_removes_finding() {
        let mut findings = vec![make_finding_at_line("a.rs", 5, "RULE1")];
        let mut map = HashMap::new();
        map.insert(
            std::path::PathBuf::from("a.rs"),
            vec![suppression(4, "RULE1", false)],
        );
        let count = filter_suppressed(&mut findings, &map);
        assert_eq!(count, 1);
        assert!(findings.is_empty());
    }

    #[test]
    fn file_scoped_suppression_removes_findings_anywhere_in_file() {
        let mut findings = vec![
            make_finding_at_line("a.rs", 1, "RULE1"),
            make_finding_at_line("a.rs", 100, "RULE1"),
            make_finding_at_line("a.rs", 200, "RULE1"),
        ];
        let mut map = HashMap::new();
        map.insert(
            std::path::PathBuf::from("a.rs"),
            vec![suppression(1, "RULE1", true)],
        );
        let count = filter_suppressed(&mut findings, &map);
        assert_eq!(count, 3);
        assert!(findings.is_empty());
    }

    #[test]
    fn non_matching_rule_id_leaves_finding() {
        let mut findings = vec![make_finding_at_line("a.rs", 5, "RULE1")];
        let mut map = HashMap::new();
        map.insert(
            std::path::PathBuf::from("a.rs"),
            vec![suppression(5, "RULE2", false)],
        );
        let count = filter_suppressed(&mut findings, &map);
        assert_eq!(count, 0);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn different_file_leaves_finding() {
        let mut findings = vec![make_finding_at_line("b.rs", 5, "RULE1")];
        let mut map = HashMap::new();
        map.insert(
            std::path::PathBuf::from("a.rs"),
            vec![suppression(5, "RULE1", false)],
        );
        let count = filter_suppressed(&mut findings, &map);
        assert_eq!(count, 0);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn returned_count_is_correct() {
        let mut findings = vec![
            make_finding_at_line("a.rs", 5, "RULE1"),
            make_finding_at_line("a.rs", 10, "RULE2"),
            make_finding_at_line("a.rs", 15, "RULE3"),
        ];
        let mut map = HashMap::new();
        map.insert(
            std::path::PathBuf::from("a.rs"),
            vec![
                suppression(5, "RULE1", false),
                suppression(15, "RULE3", false),
            ],
        );
        let count = filter_suppressed(&mut findings, &map);
        assert_eq!(count, 2);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "RULE2");
    }

    #[test]
    fn empty_suppression_map_returns_zero() {
        let mut findings = vec![make_finding_at_line("a.rs", 5, "RULE1")];
        let map = HashMap::new();
        let count = filter_suppressed(&mut findings, &map);
        assert_eq!(count, 0);
        assert_eq!(findings.len(), 1);
    }

    // ── Item 5 regression: suppression works for ExternalTool-style findings ──
    //
    // ExternalTool findings (e.g. from plugin analyzers (zuit-plugins)) are
    // produced by `analyze_project` and returned directly to the engine.  The
    // engine calls `filter_suppressed` on ALL findings after every project-level
    // phase, regardless of `AnalyzerKind`.  This test verifies that a finding
    // whose `location.file` and `rule_id` match a suppression entry in the map
    // is removed — exactly as it would be for file-level findings.

    #[test]
    fn external_tool_finding_is_suppressed_by_file_rule() {
        // Simulate a plugin analyzer finding: file "main.txt", rule "plugin/example".
        let mut findings = vec![make_finding_at_line("main.txt", 10, "plugin/example")];
        let mut map = HashMap::new();
        // Line-scoped suppression at line 9 (directive on the line above the finding).
        map.insert(
            std::path::PathBuf::from("main.txt"),
            vec![suppression(9, "plugin/example", false)],
        );
        let count = filter_suppressed(&mut findings, &map);
        assert_eq!(count, 1, "ExternalTool finding must be suppressed");
        assert!(findings.is_empty(), "suppressed finding must be removed");
    }

    #[test]
    fn external_tool_finding_not_suppressed_for_different_rule() {
        // Finding for plugin/other is NOT suppressed by a plugin/example directive.
        let mut findings = vec![make_finding_at_line("main.txt", 10, "plugin/other")];
        let mut map = HashMap::new();
        map.insert(
            std::path::PathBuf::from("main.txt"),
            vec![suppression(9, "plugin/example", false)],
        );
        let count = filter_suppressed(&mut findings, &map);
        assert_eq!(count, 0, "different rule_id must not suppress the finding");
        assert_eq!(findings.len(), 1, "finding must remain in the list");
    }

    #[test]
    fn external_tool_file_scoped_suppression_removes_all_findings_in_file() {
        // A file-scoped directive removes every finding in that file regardless of line.
        let mut findings = vec![
            make_finding_at_line("main.txt", 5, "plugin/example"),
            make_finding_at_line("main.txt", 42, "plugin/example"),
            make_finding_at_line("other.txt", 1, "plugin/example"), // different file → not suppressed
        ];
        let mut map = HashMap::new();
        map.insert(
            std::path::PathBuf::from("main.txt"),
            vec![suppression(1, "plugin/example", true)], // file_scoped = true
        );
        let count = filter_suppressed(&mut findings, &map);
        assert_eq!(count, 2, "both findings in main.txt must be suppressed");
        assert_eq!(findings.len(), 1, "only other.txt finding must remain");
        assert_eq!(
            findings[0].location.file,
            std::path::PathBuf::from("other.txt")
        );
    }

    // -- analyze_path_cached ---------------------------------------------------

    fn build_registry_with_analyzer() -> Registry {
        let finding = make_finding("placeholder.mock", 0, "RULE-CACHE");
        let mut r = Registry::new();
        r.add_language(Box::new(MockLanguage {
            id: LanguageId("mock"),
            exts: &["mock"],
        }));
        r.add_analyzer(Box::new(CountingAnalyzer {
            findings_per_file: vec![finding],
        }));
        r
    }

    #[test]
    fn cold_run_populates_cache() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.mock"), "content").unwrap();

        let engine = Engine::new(build_registry_with_analyzer());
        let config = Config::default();
        let mut cache = crate::cache::AnalysisCache::new();

        let report = engine
            .analyze_path_cached(tmp.path(), &config, &mut cache)
            .unwrap();
        assert_eq!(report.stats.files_scanned, 1);
        assert_eq!(report.stats.cache_hits, 0, "cold run has no cache hits");
        assert_eq!(cache.len(), 1, "cold run should populate cache");
    }

    #[test]
    fn warm_run_reuses_cache_and_reports_hit() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.mock"), "content").unwrap();

        let engine = Engine::new(build_registry_with_analyzer());
        let config = Config::default();
        let mut cache = crate::cache::AnalysisCache::new();

        let _ = engine
            .analyze_path_cached(tmp.path(), &config, &mut cache)
            .unwrap();

        let report = engine
            .analyze_path_cached(tmp.path(), &config, &mut cache)
            .unwrap();
        assert_eq!(
            report.stats.cache_hits, 1,
            "warm run should report 1 cache hit"
        );
    }

    #[test]
    fn single_file_edit_invalidates_only_that_file() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.mock"), "content_a").unwrap();
        fs::write(tmp.path().join("b.mock"), "content_b").unwrap();

        let engine = Engine::new(build_registry_with_analyzer());
        let config = Config::default();
        let mut cache = crate::cache::AnalysisCache::new();

        let _ = engine
            .analyze_path_cached(tmp.path(), &config, &mut cache)
            .unwrap();
        assert_eq!(cache.len(), 2);

        fs::write(tmp.path().join("b.mock"), "changed_content").unwrap();

        let report = engine
            .analyze_path_cached(tmp.path(), &config, &mut cache)
            .unwrap();
        assert_eq!(
            report.stats.cache_hits, 1,
            "only a.mock should be a cache hit"
        );
    }

    #[test]
    fn deleting_file_prunes_cache_entry() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.mock"), "content_a").unwrap();
        fs::write(tmp.path().join("b.mock"), "content_b").unwrap();

        let engine = Engine::new(build_registry_with_analyzer());
        let config = Config::default();
        let mut cache = crate::cache::AnalysisCache::new();

        let _ = engine
            .analyze_path_cached(tmp.path(), &config, &mut cache)
            .unwrap();
        assert_eq!(cache.len(), 2);

        fs::remove_file(tmp.path().join("b.mock")).unwrap();

        let _ = engine
            .analyze_path_cached(tmp.path(), &config, &mut cache)
            .unwrap();
        assert_eq!(cache.len(), 1, "deleted file should be pruned from cache");
    }

    // -- Task 5: config_change_invalidates_cache --------------------------------

    #[test]
    fn config_change_invalidates_cache() {
        // ss2.3: a config change must invalidate cache entries so that new config
        // settings affect per-file analysis results.
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.mock"), "content").unwrap();

        let engine = Engine::new(build_registry_with_analyzer());
        let config1 = Config::default();
        let mut config2 = Config::default();
        config2.general.follow_symlinks = true; // different config -> different hash

        let mut cache = crate::cache::AnalysisCache::new();

        let _ = engine
            .analyze_path_cached(tmp.path(), &config1, &mut cache)
            .unwrap();

        // Warm run with config2 -- must be a cache MISS because the config changed.
        let report = engine
            .analyze_path_cached(tmp.path(), &config2, &mut cache)
            .unwrap();
        assert_eq!(
            report.stats.cache_hits, 0,
            "cache must be invalidated when config changes"
        );
    }

    // -- Task 4: ss4.7 regression -- warm-run findings == cold-run findings ----

    // -- AnalyzerKind dispatch tests -------------------------------------------

    /// A stub analyzer whose `kind()` returns `ProjectLevel` and whose
    /// `analyze_file` panics.  Without the `AnalyzerKind` dispatch fix the engine
    /// would call `analyze_file` for every file and the test would panic.
    struct ProjectLevelPanicAnalyzer;

    impl Analyzer for ProjectLevelPanicAnalyzer {
        fn id(&self) -> AnalyzerId {
            AnalyzerId::new("project-level-panic")
        }
        fn dimension(&self) -> Dimension {
            Dimension::Maintainability
        }
        fn supported_languages(&self) -> SupportedLanguages {
            SupportedLanguages::All
        }
        fn rules(&self) -> &[RuleMeta] {
            &[]
        }
        fn kind(&self) -> crate::analyzer::AnalyzerKind {
            crate::analyzer::AnalyzerKind::ProjectLevel
        }
        fn analyze_file(&self, _ctx: &AnalysisContext<'_>, _file: &ParsedFile) -> Vec<Finding> {
            panic!("analyze_file must not be called for ProjectLevel analyzers");
        }
    }

    /// Same as `ProjectLevelPanicAnalyzer` but with `kind()` = `ExternalTool`.
    struct ExternalToolPanicAnalyzer;

    impl Analyzer for ExternalToolPanicAnalyzer {
        fn id(&self) -> AnalyzerId {
            AnalyzerId::new("external-tool-panic")
        }
        fn dimension(&self) -> Dimension {
            Dimension::Maintainability
        }
        fn supported_languages(&self) -> SupportedLanguages {
            SupportedLanguages::All
        }
        fn rules(&self) -> &[RuleMeta] {
            &[]
        }
        fn kind(&self) -> crate::analyzer::AnalyzerKind {
            crate::analyzer::AnalyzerKind::ExternalTool
        }
        fn analyze_file(&self, _ctx: &AnalysisContext<'_>, _file: &ParsedFile) -> Vec<Finding> {
            panic!("analyze_file must not be called for ExternalTool analyzers");
        }
    }

    /// A `FileLevel` analyzer that increments an `AtomicU32` each time
    /// `analyze_file` is invoked.  Used to prove the file-level path is still
    /// exercised after the `AnalyzerKind` filter was introduced.
    struct FileLevelCountingAnalyzer {
        counter: Arc<AtomicU32>,
    }

    impl Analyzer for FileLevelCountingAnalyzer {
        fn id(&self) -> AnalyzerId {
            AnalyzerId::new("file-level-counting")
        }
        fn dimension(&self) -> Dimension {
            Dimension::Maintainability
        }
        fn supported_languages(&self) -> SupportedLanguages {
            SupportedLanguages::All
        }
        fn rules(&self) -> &[RuleMeta] {
            &[]
        }
        // `kind()` intentionally omitted — defaults to `FileLevel`.
        fn analyze_file(&self, _ctx: &AnalysisContext<'_>, _file: &ParsedFile) -> Vec<Finding> {
            self.counter.fetch_add(1, Ordering::Relaxed);
            vec![]
        }
    }

    #[test]
    fn project_level_analyzer_analyze_file_not_called() {
        // `ProjectLevelPanicAnalyzer::analyze_file` panics.  The test succeeds
        // only if the engine never calls it — which requires the AnalyzerKind
        // filter to be in place.
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.mock"), "content").unwrap();
        fs::write(tmp.path().join("b.mock"), "content").unwrap();

        let mut r = Registry::new();
        r.add_language(Box::new(MockLanguage {
            id: LanguageId("mock"),
            exts: &["mock"],
        }));
        r.add_analyzer(Box::new(ProjectLevelPanicAnalyzer));

        let engine = Engine::new(r);
        let config = Config::default();
        // Must not panic.
        let report = engine.analyze_path(tmp.path(), &config).unwrap();
        assert_eq!(report.stats.files_scanned, 2);
    }

    #[test]
    fn external_tool_analyzer_analyze_file_not_called() {
        // `ExternalToolPanicAnalyzer::analyze_file` panics.  The test succeeds
        // only if the engine never calls it.
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.mock"), "content").unwrap();

        let mut r = Registry::new();
        r.add_language(Box::new(MockLanguage {
            id: LanguageId("mock"),
            exts: &["mock"],
        }));
        r.add_analyzer(Box::new(ExternalToolPanicAnalyzer));

        let engine = Engine::new(r);
        let config = Config::default();
        // Must not panic.
        let report = engine.analyze_path(tmp.path(), &config).unwrap();
        assert_eq!(report.stats.files_scanned, 1);
    }

    #[test]
    fn file_level_analyzer_still_called() {
        // Verifies that introducing the AnalyzerKind filter does not accidentally
        // skip `FileLevel` analyzers.  The counter must equal the number of files.
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.mock"), "content").unwrap();
        fs::write(tmp.path().join("b.mock"), "content").unwrap();
        fs::write(tmp.path().join("c.mock"), "content").unwrap();

        let counter = Arc::new(AtomicU32::new(0));
        let mut r = Registry::new();
        r.add_language(Box::new(MockLanguage {
            id: LanguageId("mock"),
            exts: &["mock"],
        }));
        r.add_analyzer(Box::new(FileLevelCountingAnalyzer {
            counter: Arc::clone(&counter),
        }));

        let engine = Engine::new(r);
        let config = Config::default();
        let report = engine.analyze_path(tmp.path(), &config).unwrap();
        assert_eq!(report.stats.files_scanned, 3);
        assert_eq!(
            counter.load(Ordering::Relaxed),
            3,
            "FileLevel analyzer must be called once per file"
        );
    }

    #[test]
    fn project_level_analyzer_analyze_file_not_called_cached() {
        // Same as `project_level_analyzer_analyze_file_not_called` but via
        // `analyze_path_cached`.
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.mock"), "content").unwrap();

        let mut r = Registry::new();
        r.add_language(Box::new(MockLanguage {
            id: LanguageId("mock"),
            exts: &["mock"],
        }));
        r.add_analyzer(Box::new(ProjectLevelPanicAnalyzer));

        let engine = Engine::new(r);
        let config = Config::default();
        let mut cache = crate::cache::AnalysisCache::new();
        // Cold run — must not panic.
        let _ = engine
            .analyze_path_cached(tmp.path(), &config, &mut cache)
            .unwrap();
        // Warm run — also must not panic (cache hit path still skips analyze_file).
        let report = engine
            .analyze_path_cached(tmp.path(), &config, &mut cache)
            .unwrap();
        assert_eq!(report.stats.cache_hits, 1);
    }

    #[test]
    fn external_tool_analyzer_analyze_file_not_called_cached() {
        // Same as `external_tool_analyzer_analyze_file_not_called` but via
        // `analyze_path_cached`.
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.mock"), "content").unwrap();

        let mut r = Registry::new();
        r.add_language(Box::new(MockLanguage {
            id: LanguageId("mock"),
            exts: &["mock"],
        }));
        r.add_analyzer(Box::new(ExternalToolPanicAnalyzer));

        let engine = Engine::new(r);
        let config = Config::default();
        let mut cache = crate::cache::AnalysisCache::new();
        // Cold run — must not panic.
        let _ = engine
            .analyze_path_cached(tmp.path(), &config, &mut cache)
            .unwrap();
        // Warm run — also must not panic.
        let report = engine
            .analyze_path_cached(tmp.path(), &config, &mut cache)
            .unwrap();
        assert_eq!(report.stats.cache_hits, 1);
    }

    // ---- Feature 1: per-glob severity overrides ----------------------------

    /// A stub `FileLevel` analyzer that always emits one finding per file.
    struct StubAnalyzer {
        rule_id: &'static str,
        severity: Severity,
    }

    impl Analyzer for StubAnalyzer {
        fn id(&self) -> AnalyzerId {
            AnalyzerId::new("stub")
        }
        fn dimension(&self) -> Dimension {
            Dimension::Security
        }
        fn supported_languages(&self) -> SupportedLanguages {
            SupportedLanguages::All
        }
        fn rules(&self) -> &[RuleMeta] {
            &[]
        }
        fn analyze_file(&self, _ctx: &AnalysisContext<'_>, file: &ParsedFile) -> Vec<Finding> {
            vec![Finding {
                analyzer: AnalyzerId::new("stub"),
                dimension: Dimension::Security,
                rule_id: self.rule_id.to_string(),
                severity: self.severity,
                message: "stub finding".to_string(),
                location: Location {
                    file: file.source().path.clone(),
                    span: Span::new(ByteOffset(0), ByteOffset(1)),
                    start: LineCol::new(1, 1),
                    end: LineCol::new(1, 2),
                },
                suggestion: None,
                references: vec![],
                cwe: vec![],
                owasp: vec![],
            }]
        }
    }

    fn build_registry_with_stub(rule_id: &'static str, severity: Severity) -> Registry {
        let mut r = Registry::new();
        r.add_language(Box::new(MockLanguage {
            id: LanguageId("mock"),
            exts: &["mock"],
        }));
        r.add_analyzer(Box::new(StubAnalyzer { rule_id, severity }));
        r
    }

    #[test]
    fn per_glob_override_drops_finding() {
        // Stub emits in tests/foo.mock. Config ignores "tests/**" for STUB rule.
        let tmp = TempDir::new().unwrap();
        let tests_dir = tmp.path().join("tests");
        fs::create_dir_all(&tests_dir).unwrap();
        fs::write(tests_dir.join("foo.mock"), "content").unwrap();

        let toml = r#"[rules.STUB]
overrides = { "tests/**" = "ignore" }
"#;
        let config = Config::from_toml_str(toml).unwrap();
        let engine = Engine::new(build_registry_with_stub("STUB", Severity::High));
        let report = engine.analyze_path(tmp.path(), &config).unwrap();
        assert_eq!(
            report.findings.len(),
            0,
            "per-glob ignore should drop the finding"
        );
    }

    #[test]
    fn per_glob_override_rewrites_severity() {
        // Stub emits High in src/foo.mock. Config overrides src/** to "low".
        let tmp = TempDir::new().unwrap();
        let src_dir = tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("foo.mock"), "content").unwrap();

        let toml = r#"[rules.STUB]
overrides = { "src/**" = "low" }
"#;
        let config = Config::from_toml_str(toml).unwrap();
        let engine = Engine::new(build_registry_with_stub("STUB", Severity::High));
        let report = engine.analyze_path(tmp.path(), &config).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].severity,
            Severity::Low,
            "per-glob should rewrite severity to Low"
        );
    }

    #[test]
    fn per_glob_override_no_match_passes_through() {
        // Stub emits in lib/foo.mock. Config only ignores tests/**; lib/** is unaffected.
        let tmp = TempDir::new().unwrap();
        let lib_dir = tmp.path().join("lib");
        fs::create_dir_all(&lib_dir).unwrap();
        fs::write(lib_dir.join("foo.mock"), "content").unwrap();

        let toml = r#"[rules.STUB]
overrides = { "tests/**" = "ignore" }
"#;
        let config = Config::from_toml_str(toml).unwrap();
        let engine = Engine::new(build_registry_with_stub("STUB", Severity::Medium));
        let report = engine.analyze_path(tmp.path(), &config).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].severity,
            Severity::Medium,
            "no-match glob should leave severity unchanged"
        );
    }

    // ---- Feature 3: parallel project-level analyzers ------------------------

    /// A `ProjectLevel` analyzer that sleeps 50ms per call and returns one finding.
    struct SlowProjectAnalyzer {
        rule_id: &'static str,
    }

    impl Analyzer for SlowProjectAnalyzer {
        fn id(&self) -> AnalyzerId {
            AnalyzerId::new(self.rule_id)
        }
        fn dimension(&self) -> Dimension {
            Dimension::Maintainability
        }
        fn supported_languages(&self) -> SupportedLanguages {
            SupportedLanguages::All
        }
        fn rules(&self) -> &[RuleMeta] {
            &[]
        }
        fn kind(&self) -> crate::analyzer::AnalyzerKind {
            crate::analyzer::AnalyzerKind::ProjectLevel
        }
        fn analyze_file(&self, _ctx: &AnalysisContext<'_>, _file: &ParsedFile) -> Vec<Finding> {
            panic!("analyze_file must not be called for ProjectLevel analyzers");
        }
        fn analyze_project(
            &self,
            _ctx: &AnalysisContext<'_>,
            project: &crate::analyzer::Project,
        ) -> Vec<Finding> {
            std::thread::sleep(std::time::Duration::from_millis(50));
            vec![Finding {
                analyzer: AnalyzerId::new(self.rule_id),
                dimension: Dimension::Maintainability,
                rule_id: self.rule_id.to_string(),
                severity: Severity::Low,
                message: "project finding".to_string(),
                location: Location {
                    file: project.root.join("fake.mock"),
                    span: Span::new(ByteOffset(0), ByteOffset(1)),
                    start: LineCol::new(1, 1),
                    end: LineCol::new(1, 2),
                },
                suggestion: None,
                references: vec![],
                cwe: vec![],
                owasp: vec![],
            }]
        }
    }

    #[test]
    fn project_level_analyzers_run_in_parallel() {
        let tmp = TempDir::new().unwrap();

        let mut r = Registry::new();
        r.add_language(Box::new(MockLanguage {
            id: LanguageId("mock"),
            exts: &["mock"],
        }));
        r.add_analyzer(Box::new(SlowProjectAnalyzer { rule_id: "PROJ001" }));
        r.add_analyzer(Box::new(SlowProjectAnalyzer { rule_id: "PROJ002" }));

        let engine = Engine::new(r);
        let config = Config::default();

        let t0 = std::time::Instant::now();
        let report = engine.analyze_path(tmp.path(), &config).unwrap();
        let elapsed = t0.elapsed();

        // Always: both analyzers must have returned their findings.
        assert_eq!(report.findings.len(), 2, "both project analyzers must emit");

        // Wall-time: only gate when rayon has multiple threads.
        if rayon::current_num_threads() > 1 {
            assert!(
                elapsed < std::time::Duration::from_millis(90),
                "parallel project analyzers should finish in <90ms, took {elapsed:?}"
            );
        }
    }

    // ---- Feature 4: global rule severity override ---------------------------

    #[test]
    fn rule_severity_override_rewrites() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.mock"), "content").unwrap();

        let toml = r#"[rules.STUB]
severity = "low"
"#;
        let config = Config::from_toml_str(toml).unwrap();
        let engine = Engine::new(build_registry_with_stub("STUB", Severity::High));
        let report = engine.analyze_path(tmp.path(), &config).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].severity,
            Severity::Low,
            "global severity override should rewrite High to Low"
        );
    }

    #[test]
    fn rule_severity_override_ignore_drops() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.mock"), "content").unwrap();

        let toml = r#"[rules.STUB]
severity = "ignore"
"#;
        let config = Config::from_toml_str(toml).unwrap();
        let engine = Engine::new(build_registry_with_stub("STUB", Severity::High));
        let report = engine.analyze_path(tmp.path(), &config).unwrap();
        assert_eq!(
            report.findings.len(),
            0,
            "global severity = ignore should drop the finding"
        );
    }

    #[test]
    fn rule_severity_override_works_for_external_rule_ids() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("a.mock"), "content").unwrap();

        let toml = r#"
[rules."GO/gosec"]
severity = "critical"
"#;
        let config = Config::from_toml_str(toml).unwrap();
        let engine = Engine::new(build_registry_with_stub("GO/gosec", Severity::Low));
        let report = engine.analyze_path(tmp.path(), &config).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].severity,
            Severity::Critical,
            "external rule id severity override should work"
        );
    }

    #[test]
    fn per_glob_takes_precedence_over_global_severity() {
        // File in tests/ → Critical (per-glob wins over global "low").
        // File in src/   → Low (global rule severity).
        let tmp = TempDir::new().unwrap();
        let tests_dir = tmp.path().join("tests");
        let src_dir = tmp.path().join("src");
        fs::create_dir_all(&tests_dir).unwrap();
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(tests_dir.join("a.mock"), "content").unwrap();
        fs::write(src_dir.join("b.mock"), "content").unwrap();

        let toml = r#"[rules.STUB]
severity = "low"
overrides = { "tests/**" = "critical" }
"#;
        let config = Config::from_toml_str(toml).unwrap();
        let engine = Engine::new(build_registry_with_stub("STUB", Severity::High));
        let report = engine.analyze_path(tmp.path(), &config).unwrap();
        assert_eq!(report.findings.len(), 2);

        // Sort by file path for deterministic comparison.
        let mut findings = report.findings.clone();
        findings.sort_by(|a, b| a.location.file.cmp(&b.location.file));

        // src/b.mock → global override → Low
        assert_eq!(
            findings[0].severity,
            Severity::Low,
            "src file: global override → Low"
        );
        // tests/a.mock → per-glob override → Critical
        assert_eq!(
            findings[1].severity,
            Severity::Critical,
            "tests file: per-glob → Critical"
        );
    }

    #[test]
    fn warm_run_findings_equal_cold_run_findings_with_path_embedding_analyzer() {
        // This test catches the ss4.7 double-execution bug: if the cache stored
        // findings from one execution context and returned them for a different
        // file path on a warm run, the path-embedded messages would diverge.
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("alpha.mock"), "hello").unwrap();
        fs::write(tmp.path().join("beta.mock"), "world").unwrap();

        let mut r = Registry::new();
        r.add_language(Box::new(MockLanguage {
            id: LanguageId("mock"),
            exts: &["mock"],
        }));
        r.add_analyzer(Box::new(PathEmbeddingAnalyzer));

        let engine = Engine::new(r);
        let config = Config::default();
        let mut cache = crate::cache::AnalysisCache::new();

        let cold_report = engine
            .analyze_path_cached(tmp.path(), &config, &mut cache)
            .unwrap();
        assert_eq!(
            cold_report.stats.cache_hits, 0,
            "cold run must have no hits"
        );

        let warm_report = engine
            .analyze_path_cached(tmp.path(), &config, &mut cache)
            .unwrap();
        assert_eq!(
            warm_report.stats.cache_hits, 2,
            "warm run must serve both files from cache"
        );

        // Sort both finding lists and compare byte-for-byte via JSON.
        let mut cold_findings = cold_report.findings.clone();
        let mut warm_findings = warm_report.findings.clone();
        cold_findings.sort();
        warm_findings.sort();

        let cold_json = serde_json::to_string(&cold_findings).unwrap();
        let warm_json = serde_json::to_string(&warm_findings).unwrap();
        assert_eq!(
            cold_json, warm_json,
            "warm-run findings must be byte-for-byte equal to cold-run findings"
        );
    }
}
