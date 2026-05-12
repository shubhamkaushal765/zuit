//! Pure-function analytics derived from stored scan envelopes.
//!
//! All functions are deterministic: the same envelope(s) always produce the
//! same output. No I/O is performed here; callers pass pre-loaded
//! `serde_json::Value` envelopes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::history::ProjectMeta;

/// Version stamp for the `.analytics.json` sidecar format.
///
/// Increment this whenever a structural change to [`ScanAnalytics`] requires
/// on-disk sidecars to be regenerated (e.g. a new required computed field).
///
/// | Version | Change |
/// |---------|--------|
/// | 1       | Initial format (implicit; sidecars without a `version` field) |
/// | 2       | Added `all_file_weighted` (severity-weighted per-file counts) |
pub const ANALYTICS_VERSION: u32 = 2;

/// Returns the default version for old sidecars that predate the `version` field.
fn default_analytics_version() -> u32 {
    1
}

/// Maps a severity string to a numeric weight for heatmap ranking.
///
/// | Severity | Weight |
/// |----------|--------|
/// | info     | 1      |
/// | low      | 2      |
/// | medium   | 5      |
/// | high     | 10     |
/// | critical | 20     |
///
/// Unknown or empty severity strings map to 1 (info-level, lowest weight).
#[must_use]
pub fn severity_weight(severity: &str) -> u32 {
    match severity {
        "critical" => 20,
        "high" => 10,
        "medium" => 5,
        "low" => 2,
        _ => 1, // "info" and unknown values
    }
}

/// Internal tally type for per-rule severity and dimension counts.
///
/// Maps `rule_id → (total_count, severity_tally, dimension_tally)`.
type RuleTally = BTreeMap<String, (u32, BTreeMap<String, u32>, BTreeMap<String, u32>)>;

// ── public types ─────────────────────────────────────────────────────────────

/// A single rule aggregated over all findings in one scan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleCount {
    /// The rule identifier (e.g. `"MAINT001-cyclomatic"`).
    pub rule_id: String,
    /// Number of findings that fired this rule in the scan.
    pub count: u32,
    /// The most-common severity for this rule (tie-break: alphabetical).
    pub severity: String,
    /// The most-common dimension for this rule (tie-break: alphabetical).
    pub dimension: String,
}

/// A single file aggregated over all findings in one scan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileCount {
    /// The file path string.
    pub file: String,
    /// Number of findings in this file.
    pub count: u32,
}

/// Derived analytics for one scan envelope.
///
/// This struct is serialised to a `.analytics.json` sidecar file alongside each
/// scan envelope so the HTTP API can serve analytics in O(1) file reads.
/// All fields use explicit Rust types; no `serde_json::Value` traversal at read
/// time. Adding new fields is additive: old sidecars without the field
/// deserialise with the `#[serde(default)]` fallback, triggering a lazy
/// regeneration on the next request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanAnalytics {
    /// Sidecar format version. Defaults to 1 for old sidecars.
    ///
    /// Bump [`ANALYTICS_VERSION`] and this field whenever a structural change
    /// requires regeneration of on-disk sidecars.
    #[serde(default = "default_analytics_version")]
    pub version: u32,
    /// The scan identifier.
    pub scan_id: String,
    /// RFC-3339 timestamp of when the scan was captured.
    pub captured_at: String,
    /// Total number of findings across all severities.
    pub total_findings: u32,
    /// Count of findings per severity level (lowercase keys).
    pub severity_counts: BTreeMap<String, u32>,
    /// Count of findings per dimension (lowercase keys).
    pub dimension_counts: BTreeMap<String, u32>,
    /// Top 10 rules by finding count (count desc, `rule_id` asc on tie).
    pub top_rules: Vec<RuleCount>,
    /// Top 10 files by finding count (count desc, file asc on tie).
    pub top_files: Vec<FileCount>,
    /// Count of CWE identifiers across all findings.
    pub cwe_counts: BTreeMap<String, u32>,
    /// Count of OWASP categories across all findings.
    pub owasp_counts: BTreeMap<String, u32>,
    /// Per-dimension grade letter (A–F), keyed by lowercase dimension name.
    pub grades: BTreeMap<String, String>,
    /// Raw `report.scores` object copied from the envelope.
    pub scores: serde_json::Value,
    /// Number of source files scanned.
    ///
    /// Sourced from `report.stats.files_scanned`; used by the trends endpoint
    /// to avoid reloading the full envelope.
    #[serde(default)]
    pub files_scanned: u64,
    /// Number of parse failures in this scan.
    ///
    /// Sourced from `report.stats.parse_failures`; used by the summary and
    /// trends endpoints.
    #[serde(default)]
    pub parse_failures: u64,
    /// Elapsed scan time in milliseconds.
    ///
    /// Sourced from `report.stats.elapsed_ms`; used by the trends endpoint.
    #[serde(default)]
    pub elapsed_ms: u64,
    /// Per-file finding counts across ALL files (not just top 10).
    ///
    /// This field powers the heatmap endpoint.  Old sidecars written before
    /// this field was added will deserialise with an empty map and trigger the
    /// lazy-regeneration path on the next request.
    #[serde(default)]
    pub all_file_counts: BTreeMap<String, u32>,
    /// Per-file severity-weighted sums across ALL files (not just top 10).
    ///
    /// Each finding is counted with its severity weight (info=1, low=2,
    /// medium=5, high=10, critical=20) rather than as a flat count.
    /// Old sidecars without this field deserialise with an empty map and
    /// trigger lazy regeneration.
    #[serde(default)]
    pub all_file_weighted: BTreeMap<String, u32>,
}

/// Finding-level diff between two scan envelopes.
#[derive(Debug, Clone, Serialize)]
pub struct ScanDiff {
    /// The source scan identifier.
    pub from_scan_id: String,
    /// The destination scan identifier.
    pub to_scan_id: String,
    /// Findings present in `to` but not in `from`.
    pub new: Vec<serde_json::Value>,
    /// Findings present in `from` but not in `to`.
    pub resolved: Vec<serde_json::Value>,
    /// Findings present in both `from` and `to`.
    pub persisting: Vec<serde_json::Value>,
}

/// Score and finding-count deltas versus the previous scan.
#[derive(Debug, Clone, Serialize)]
pub struct DeltaVsPrevious {
    /// The scan identifier of the previous scan.
    pub previous_scan_id: String,
    /// Captured-at timestamp of the previous scan.
    pub previous_captured_at: String,
    /// Per-dimension score delta (latest minus previous).
    pub score_deltas: BTreeMap<String, f32>,
    /// Total finding count delta (latest minus previous).
    pub finding_count_delta: i64,
    /// Per-severity finding count deltas (latest minus previous).
    pub severity_count_deltas: BTreeMap<String, i64>,
}

/// Project-level summary: latest analytics plus optional delta vs previous scan.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectSummary {
    /// Project metadata (`hash`, `name`, `root`, `first_seen`, `scan_count`).
    pub project: serde_json::Value,
    /// Analytics for the most recent scan, or `None` if no scans exist.
    pub latest: Option<ScanAnalytics>,
    /// Delta vs the previous scan, or `None` if fewer than two scans exist.
    pub delta_vs_previous: Option<DeltaVsPrevious>,
    /// Total parse failures summed across all stored scans.
    pub parse_failure_total: u64,
}

/// One chronological data point for time-series plotting.
#[derive(Debug, Clone, Serialize)]
pub struct TrendPoint {
    /// The scan identifier.
    pub scan_id: String,
    /// RFC-3339 timestamp of when the scan was captured.
    pub captured_at: String,
    /// Per-dimension scores at this point in time.
    pub scores: serde_json::Value,
    /// Count of findings per severity level at this point in time.
    pub severity_counts: BTreeMap<String, u32>,
    /// Total number of findings at this point in time.
    pub total_findings: u32,
    /// Number of files scanned.
    pub files_scanned: u64,
    /// Number of parse failures.
    pub parse_failures: u64,
    /// Elapsed time in milliseconds.
    pub elapsed_ms: u64,
}

/// Per-file rollup across a series of scans, used for the hot-files heatmap.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HeatmapEntry {
    /// File path.
    pub path: String,
    /// Sum of findings in this file across all scans.
    pub total_findings_all_time: u32,
    /// Sum of severity weights in this file across all scans.
    ///
    /// Uses the same weight table as [`severity_weight`]:
    /// info=1, low=2, medium=5, high=10, critical=20.
    pub total_weight_all_time: u32,
    /// Finding count for each scan (aligned with the input envelope slice).
    pub findings_per_scan: Vec<u32>,
    /// Highest finding count observed in a single scan.
    pub peak_count: u32,
    /// Scan identifier of the scan that last contained at least one finding.
    pub last_seen_scan_id: String,
}

// ── public functions ──────────────────────────────────────────────────────────

/// Maps a 0–100 score to a letter grade.
///
/// - ≥ 90 → `"A"`
/// - ≥ 80 → `"B"`
/// - ≥ 70 → `"C"`
/// - ≥ 60 → `"D"`
/// - < 60 → `"F"`
#[must_use]
pub fn score_to_grade(score: f32) -> &'static str {
    if score >= 90.0 {
        "A"
    } else if score >= 80.0 {
        "B"
    } else if score >= 70.0 {
        "C"
    } else if score >= 60.0 {
        "D"
    } else {
        "F"
    }
}

/// Computes derived analytics from one scan envelope (the full saved JSON).
///
/// Fields that are absent or malformed in the envelope are treated as zero /
/// empty rather than propagating errors.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn compute_scan_analytics(envelope: &serde_json::Value) -> ScanAnalytics {
    let scan_id = envelope["scan_id"].as_str().unwrap_or_default().to_owned();
    let captured_at = envelope["captured_at"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let scores = envelope["report"]["scores"].clone();

    let empty_arr: Vec<serde_json::Value> = Vec::new();
    let findings = envelope["report"]["findings"]
        .as_array()
        .unwrap_or(&empty_arr);

    let total_findings = u32::try_from(findings.len()).unwrap_or(u32::MAX);

    // Severity, dimension, cwe, owasp counts.
    let mut severity_counts: BTreeMap<String, u32> = BTreeMap::new();
    let mut dimension_counts: BTreeMap<String, u32> = BTreeMap::new();
    let mut cwe_counts: BTreeMap<String, u32> = BTreeMap::new();
    let mut owasp_counts: BTreeMap<String, u32> = BTreeMap::new();

    // Rule → (count, severity_tally, dimension_tally)
    let mut rule_tally: RuleTally = BTreeMap::new();

    // File → count
    let mut file_counts: BTreeMap<String, u32> = BTreeMap::new();
    // File → severity-weighted sum
    let mut file_weighted: BTreeMap<String, u32> = BTreeMap::new();

    for finding in findings {
        let sev = finding["severity"].as_str().unwrap_or_default().to_owned();
        let dim = finding["dimension"].as_str().unwrap_or_default().to_owned();
        let rule = finding["rule_id"].as_str().unwrap_or_default().to_owned();
        let file = finding["location"]["file"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        if !sev.is_empty() {
            *severity_counts.entry(sev.clone()).or_insert(0) += 1;
        }
        if !dim.is_empty() {
            *dimension_counts.entry(dim.clone()).or_insert(0) += 1;
        }

        // CWE / OWASP arrays.
        if let Some(cwes) = finding["cwe"].as_array() {
            for c in cwes {
                if let Some(s) = c.as_str() {
                    *cwe_counts.entry(s.to_owned()).or_insert(0) += 1;
                }
            }
        }
        if let Some(owasps) = finding["owasp"].as_array() {
            for o in owasps {
                if let Some(s) = o.as_str() {
                    *owasp_counts.entry(s.to_owned()).or_insert(0) += 1;
                }
            }
        }

        // Rule tally.
        if !rule.is_empty() {
            let entry = rule_tally
                .entry(rule)
                .or_insert_with(|| (0, BTreeMap::new(), BTreeMap::new()));
            entry.0 += 1;
            if !sev.is_empty() {
                *entry.1.entry(sev.clone()).or_insert(0) += 1;
            }
            if !dim.is_empty() {
                *entry.2.entry(dim).or_insert(0) += 1;
            }
        }

        // File tally: both flat count and severity-weighted sum.
        if !file.is_empty() {
            *file_counts.entry(file.clone()).or_insert(0) += 1;
            *file_weighted.entry(file).or_insert(0) += severity_weight(&sev);
        }
    }

    // Build top_rules: top 10 by count desc, rule_id asc on tie.
    let mut top_rules: Vec<RuleCount> = rule_tally
        .into_iter()
        .map(|(rule_id, (count, sev_tally, dim_tally))| {
            let severity = most_common_key(&sev_tally);
            let dimension = most_common_key(&dim_tally);
            RuleCount {
                rule_id,
                count,
                severity,
                dimension,
            }
        })
        .collect();
    // Sort: count desc, rule_id asc.
    top_rules.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    top_rules.truncate(10);

    // Build top_files: top 10 by count desc, file asc on tie.
    // Keep full clones before truncation for `all_file_counts` and `all_file_weighted`.
    let all_file_counts = file_counts.clone();
    let all_file_weighted = file_weighted;
    let mut top_files: Vec<FileCount> = file_counts
        .into_iter()
        .map(|(file, count)| FileCount { file, count })
        .collect();
    top_files.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.file.cmp(&b.file)));
    top_files.truncate(10);

    // Build grades from scores object.
    // Iterate over all keys present in the scores JSON object so that newer
    // dimensions (ci_release, performance, unsafe_soundness, etc.) are included
    // alongside the original v1 set. Non-numeric values are skipped defensively.
    let mut grades: BTreeMap<String, String> = BTreeMap::new();
    if let Some(obj) = scores.as_object() {
        for (key, v) in obj {
            if let Some(f) = v.as_f64() {
                // JSON stores f64; score_to_grade takes f32 — precision loss is
                // acceptable for the 0-100 domain.
                #[allow(clippy::cast_possible_truncation)]
                let s = f as f32;
                grades.insert(key.clone(), score_to_grade(s).to_owned());
            }
        }
    }

    // Stats for trends / summary sidecar-driven paths.
    let stats = &envelope["report"]["stats"];
    let files_scanned = stats["files_scanned"].as_u64().unwrap_or(0);
    let parse_failures = stats["parse_failures"].as_u64().unwrap_or(0);
    let elapsed_ms = stats["elapsed_ms"].as_u64().unwrap_or(0);

    ScanAnalytics {
        version: ANALYTICS_VERSION,
        scan_id,
        captured_at,
        total_findings,
        severity_counts,
        dimension_counts,
        top_rules,
        top_files,
        cwe_counts,
        owasp_counts,
        grades,
        scores,
        files_scanned,
        parse_failures,
        elapsed_ms,
        all_file_counts,
        all_file_weighted,
    }
}

/// Computes finding-level diff between two scan envelopes.
///
/// Fingerprint = `(file, start_line, rule_id, message)`. Output is sorted
/// deterministically by fingerprint.
#[must_use]
pub fn compute_scan_diff(from: &serde_json::Value, to: &serde_json::Value) -> ScanDiff {
    let from_scan_id = from["scan_id"].as_str().unwrap_or_default().to_owned();
    let to_scan_id = to["scan_id"].as_str().unwrap_or_default().to_owned();

    let empty_arr: Vec<serde_json::Value> = Vec::new();
    let from_findings = from["report"]["findings"].as_array().unwrap_or(&empty_arr);
    let to_findings = to["report"]["findings"].as_array().unwrap_or(&empty_arr);

    let from_fps: BTreeMap<String, &serde_json::Value> =
        from_findings.iter().map(|f| (fingerprint(f), f)).collect();
    let to_fps: BTreeMap<String, &serde_json::Value> =
        to_findings.iter().map(|f| (fingerprint(f), f)).collect();

    let mut new: Vec<serde_json::Value> = to_fps
        .iter()
        .filter(|(fp, _)| !from_fps.contains_key(*fp))
        .map(|(_, v)| (*v).clone())
        .collect();
    let mut resolved: Vec<serde_json::Value> = from_fps
        .iter()
        .filter(|(fp, _)| !to_fps.contains_key(*fp))
        .map(|(_, v)| (*v).clone())
        .collect();
    let mut persisting: Vec<serde_json::Value> = to_fps
        .iter()
        .filter(|(fp, _)| from_fps.contains_key(*fp))
        .map(|(_, v)| (*v).clone())
        .collect();

    // Sort each list by fingerprint for determinism.
    new.sort_by_key(fingerprint);
    resolved.sort_by_key(fingerprint);
    persisting.sort_by_key(fingerprint);

    ScanDiff {
        from_scan_id,
        to_scan_id,
        new,
        resolved,
        persisting,
    }
}

/// Builds a project summary: latest analytics plus delta vs previous scan.
///
/// `envelopes_oldest_first` must be in chronological order (oldest first).
///
/// # Panics
///
/// Panics if `envelopes_oldest_first.len() >= 2` but `last()` returns `None`,
/// which cannot happen (invariant maintained by slice semantics).
#[must_use]
pub fn compute_project_summary(
    meta: &ProjectMeta,
    envelopes_oldest_first: &[serde_json::Value],
) -> ProjectSummary {
    let scan_count = envelopes_oldest_first.len();

    // Sum parse failures across all scans.
    let parse_failure_total: u64 = envelopes_oldest_first
        .iter()
        .map(|e| e["report"]["stats"]["parse_failures"].as_u64().unwrap_or(0))
        .sum();

    let project = serde_json::json!({
        "name": meta.name,
        "root": meta.root,
        "first_seen": meta.first_seen,
        "scan_count": scan_count,
    });

    let latest = envelopes_oldest_first.last().map(compute_scan_analytics);

    let delta_vs_previous = if envelopes_oldest_first.len() >= 2 {
        let prev_envelope = &envelopes_oldest_first[envelopes_oldest_first.len() - 2];
        let latest_envelope = envelopes_oldest_first.last().expect("invariant: len >= 2");

        let prev_id = prev_envelope["scan_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let prev_captured_at = prev_envelope["captured_at"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let prev_scores = &prev_envelope["report"]["scores"];
        let latest_scores = &latest_envelope["report"]["scores"];

        let dimension_keys = [
            "maintainability",
            "security",
            "complexity",
            "documentation",
            "test_smell",
        ];

        let mut score_deltas: BTreeMap<String, f32> = BTreeMap::new();
        for key in dimension_keys {
            // JSON stores scores as f64; delta type is f32 per the public API.
            // Precision loss is acceptable in the 0-100 domain.
            #[allow(clippy::cast_possible_truncation)]
            let prev_s = prev_scores[key].as_f64().unwrap_or(0.0) as f32;
            #[allow(clippy::cast_possible_truncation)]
            let latest_s = latest_scores[key].as_f64().unwrap_or(0.0) as f32;
            score_deltas.insert(key.to_owned(), latest_s - prev_s);
        }

        let prev_analytics = compute_scan_analytics(prev_envelope);
        let latest_analytics = latest
            .as_ref()
            .expect("invariant: latest is Some when len >= 2");

        let finding_count_delta =
            i64::from(latest_analytics.total_findings) - i64::from(prev_analytics.total_findings);

        // Collect all severity keys from both scans.
        let mut all_severities: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        for k in prev_analytics.severity_counts.keys() {
            all_severities.insert(k.clone());
        }
        for k in latest_analytics.severity_counts.keys() {
            all_severities.insert(k.clone());
        }
        let mut severity_count_deltas: BTreeMap<String, i64> = BTreeMap::new();
        for sev in all_severities {
            let prev_c = i64::from(*prev_analytics.severity_counts.get(&sev).unwrap_or(&0));
            let latest_c = i64::from(*latest_analytics.severity_counts.get(&sev).unwrap_or(&0));
            severity_count_deltas.insert(sev, latest_c - prev_c);
        }

        Some(DeltaVsPrevious {
            previous_scan_id: prev_id,
            previous_captured_at: prev_captured_at,
            score_deltas,
            finding_count_delta,
            severity_count_deltas,
        })
    } else {
        None
    };

    ProjectSummary {
        project,
        latest,
        delta_vs_previous,
        parse_failure_total,
    }
}

/// Builds time-series data (one entry per scan, chronologically) for plotting.
///
/// `envelopes_oldest_first` must be in chronological order (oldest first).
#[must_use]
pub fn compute_trends(envelopes_oldest_first: &[serde_json::Value]) -> Vec<TrendPoint> {
    envelopes_oldest_first
        .iter()
        .map(|envelope| {
            let scan_id = envelope["scan_id"].as_str().unwrap_or_default().to_owned();
            let captured_at = envelope["captured_at"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let scores = envelope["report"]["scores"].clone();

            let empty_arr: Vec<serde_json::Value> = Vec::new();
            let findings = envelope["report"]["findings"]
                .as_array()
                .unwrap_or(&empty_arr);

            let total_findings = u32::try_from(findings.len()).unwrap_or(u32::MAX);

            let mut severity_counts: BTreeMap<String, u32> = BTreeMap::new();
            for f in findings {
                let sev = f["severity"].as_str().unwrap_or_default();
                if !sev.is_empty() {
                    *severity_counts.entry(sev.to_owned()).or_insert(0) += 1;
                }
            }

            let stats = &envelope["report"]["stats"];
            let files_scanned = stats["files_scanned"].as_u64().unwrap_or(0);
            let parse_failures = stats["parse_failures"].as_u64().unwrap_or(0);
            let elapsed_ms = stats["elapsed_ms"].as_u64().unwrap_or(0);

            TrendPoint {
                scan_id,
                captured_at,
                scores,
                severity_counts,
                total_findings,
                files_scanned,
                parse_failures,
                elapsed_ms,
            }
        })
        .collect()
}

/// Builds a hot-files heatmap: per-file finding counts rolled up across all
/// provided scan envelopes.
///
/// `envelopes_oldest_first` must be in chronological order (oldest first).
/// `top_n` controls the maximum number of returned entries (default 25 when
/// `top_n` is `None`). Results are sorted by `total_findings_all_time` desc,
/// then by `path` asc on ties.
///
/// Returns an empty `Vec` when `envelopes_oldest_first` is empty.
#[must_use]
pub fn compute_heatmap(
    envelopes_oldest_first: &[serde_json::Value],
    top_n: Option<usize>,
) -> Vec<HeatmapEntry> {
    let n_scans = envelopes_oldest_first.len();
    if n_scans == 0 {
        return Vec::new();
    }

    // Map: path → (total_count, total_weight, per_scan_counts, peak, last_seen_scan_id)
    let mut tally: BTreeMap<String, (u32, u32, Vec<u32>, u32, String)> = BTreeMap::new();

    for (scan_idx, envelope) in envelopes_oldest_first.iter().enumerate() {
        let scan_id = envelope["scan_id"].as_str().unwrap_or_default().to_owned();

        let empty: Vec<serde_json::Value> = Vec::new();
        let findings = envelope["report"]["findings"].as_array().unwrap_or(&empty);

        // Per-file count and weight for this scan.
        let mut file_count: BTreeMap<String, u32> = BTreeMap::new();
        let mut file_weight: BTreeMap<String, u32> = BTreeMap::new();
        for finding in findings {
            let file = finding["location"]["file"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            if !file.is_empty() {
                let sev = finding["severity"].as_str().unwrap_or_default();
                *file_count.entry(file.clone()).or_insert(0) += 1;
                *file_weight.entry(file).or_insert(0) += severity_weight(sev);
            }
        }

        for (path, count) in &file_count {
            let weight = file_weight.get(path).copied().unwrap_or(0);
            let entry = tally
                .entry(path.clone())
                .or_insert_with(|| (0_u32, 0_u32, vec![0_u32; n_scans], 0_u32, String::new()));
            entry.0 += count;
            entry.1 += weight;
            entry.2[scan_idx] = *count;
            if *count > entry.3 {
                entry.3 = *count;
            }
            if !scan_id.is_empty() {
                entry.4.clone_from(&scan_id);
            }
        }
    }

    let limit = top_n.unwrap_or(25);

    let mut result: Vec<HeatmapEntry> = tally
        .into_iter()
        .map(
            |(path, (total, weight, per_scan, peak, last_seen))| HeatmapEntry {
                path,
                total_findings_all_time: total,
                total_weight_all_time: weight,
                findings_per_scan: per_scan,
                peak_count: peak,
                last_seen_scan_id: last_seen,
            },
        )
        .collect();

    // Sort: weight desc, path asc on tie.
    result.sort_by(|a, b| {
        b.total_weight_all_time
            .cmp(&a.total_weight_all_time)
            .then_with(|| a.path.cmp(&b.path))
    });
    result.truncate(limit);
    result
}

/// Builds a project summary from pre-computed per-scan analytics sidecars.
///
/// This is the fast path: avoids loading any finding arrays from disk.
/// `analytics_oldest_first` must be sorted oldest-first (matching `list_scans`
/// sort order). `meta` is the project metadata as loaded from `meta.json`.
///
/// # Panics
///
/// Panics if `analytics_oldest_first.len() >= 2` but `last()` returns `None`,
/// which cannot happen (invariant maintained by slice semantics).
#[must_use]
pub fn compute_project_summary_from_analytics(
    meta: &ProjectMeta,
    analytics_oldest_first: &[ScanAnalytics],
) -> ProjectSummary {
    let scan_count = analytics_oldest_first.len();

    let parse_failure_total: u64 = analytics_oldest_first
        .iter()
        .map(|a| a.parse_failures)
        .sum();

    let project = serde_json::json!({
        "name": meta.name,
        "root": meta.root,
        "first_seen": meta.first_seen,
        "scan_count": scan_count,
    });

    let latest = analytics_oldest_first.last().cloned();

    let delta_vs_previous = if analytics_oldest_first.len() >= 2 {
        let prev = &analytics_oldest_first[analytics_oldest_first.len() - 2];
        let latest_a = analytics_oldest_first.last().expect("invariant: len >= 2");

        let dimension_keys = [
            "maintainability",
            "security",
            "complexity",
            "documentation",
            "test_smell",
        ];

        let mut score_deltas: BTreeMap<String, f32> = BTreeMap::new();
        for key in dimension_keys {
            // JSON stores scores as f64; delta type is f32 per the public API.
            // Precision loss is acceptable in the 0-100 domain.
            #[allow(clippy::cast_possible_truncation)]
            let prev_s = prev.scores[key].as_f64().unwrap_or(0.0) as f32;
            #[allow(clippy::cast_possible_truncation)]
            let latest_s = latest_a.scores[key].as_f64().unwrap_or(0.0) as f32;
            score_deltas.insert(key.to_owned(), latest_s - prev_s);
        }

        let finding_count_delta =
            i64::from(latest_a.total_findings) - i64::from(prev.total_findings);

        let mut all_severities: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        for k in prev.severity_counts.keys() {
            all_severities.insert(k.clone());
        }
        for k in latest_a.severity_counts.keys() {
            all_severities.insert(k.clone());
        }
        let mut severity_count_deltas: BTreeMap<String, i64> = BTreeMap::new();
        for sev in all_severities {
            let prev_c = i64::from(*prev.severity_counts.get(&sev).unwrap_or(&0));
            let latest_c = i64::from(*latest_a.severity_counts.get(&sev).unwrap_or(&0));
            severity_count_deltas.insert(sev, latest_c - prev_c);
        }

        Some(DeltaVsPrevious {
            previous_scan_id: prev.scan_id.clone(),
            previous_captured_at: prev.captured_at.clone(),
            score_deltas,
            finding_count_delta,
            severity_count_deltas,
        })
    } else {
        None
    };

    ProjectSummary {
        project,
        latest,
        delta_vs_previous,
        parse_failure_total,
    }
}

/// Builds time-series trend data from pre-computed per-scan analytics sidecars.
///
/// `analytics_oldest_first` must be sorted oldest-first.
#[must_use]
pub fn compute_trends_from_analytics(analytics_oldest_first: &[ScanAnalytics]) -> Vec<TrendPoint> {
    analytics_oldest_first
        .iter()
        .map(|a| TrendPoint {
            scan_id: a.scan_id.clone(),
            captured_at: a.captured_at.clone(),
            scores: a.scores.clone(),
            severity_counts: a.severity_counts.clone(),
            total_findings: a.total_findings,
            files_scanned: a.files_scanned,
            parse_failures: a.parse_failures,
            elapsed_ms: a.elapsed_ms,
        })
        .collect()
}

/// Builds a hot-files heatmap from pre-computed per-scan analytics sidecars.
///
/// Uses `ScanAnalytics::all_file_counts` (all files, not just the top-10).
/// `analytics_oldest_first` must be sorted oldest-first.
/// `top_n` controls the maximum number of returned entries (default 25).
///
/// Returns an empty `Vec` when `analytics_oldest_first` is empty.
#[must_use]
pub fn compute_heatmap_from_analytics(
    analytics_oldest_first: &[ScanAnalytics],
    top_n: Option<usize>,
) -> Vec<HeatmapEntry> {
    let n_scans = analytics_oldest_first.len();
    if n_scans == 0 {
        return Vec::new();
    }

    // Map: path → (total_count, total_weight, per_scan_counts, peak, last_seen_scan_id)
    let mut tally: BTreeMap<String, (u32, u32, Vec<u32>, u32, String)> = BTreeMap::new();

    for (scan_idx, a) in analytics_oldest_first.iter().enumerate() {
        for (path, &count) in &a.all_file_counts {
            let weight = a.all_file_weighted.get(path).copied().unwrap_or(0);
            let entry = tally
                .entry(path.clone())
                .or_insert_with(|| (0_u32, 0_u32, vec![0_u32; n_scans], 0_u32, String::new()));
            entry.0 += count;
            entry.1 += weight;
            entry.2[scan_idx] = count;
            if count > entry.3 {
                entry.3 = count;
            }
            if !a.scan_id.is_empty() {
                entry.4.clone_from(&a.scan_id);
            }
        }
    }

    let limit = top_n.unwrap_or(25);

    let mut result: Vec<HeatmapEntry> = tally
        .into_iter()
        .map(
            |(path, (total, weight, per_scan, peak, last_seen))| HeatmapEntry {
                path,
                total_findings_all_time: total,
                total_weight_all_time: weight,
                findings_per_scan: per_scan,
                peak_count: peak,
                last_seen_scan_id: last_seen,
            },
        )
        .collect();

    // Sort: weight desc, path asc on tie.
    result.sort_by(|a, b| {
        b.total_weight_all_time
            .cmp(&a.total_weight_all_time)
            .then_with(|| a.path.cmp(&b.path))
    });
    result.truncate(limit);
    result
}

// ── private helpers ───────────────────────────────────────────────────────────

/// Returns the key with the highest count in `tally`, breaking ties alphabetically.
///
/// Returns an empty string if `tally` is empty.
fn most_common_key(tally: &BTreeMap<String, u32>) -> String {
    tally
        .iter()
        .max_by(|(ka, va), (kb, vb)| va.cmp(vb).then_with(|| kb.cmp(ka)))
        .map(|(k, _)| k.clone())
        .unwrap_or_default()
}

/// Computes the fingerprint of a finding: `(file, start_line, rule_id, message)`.
fn fingerprint(finding: &serde_json::Value) -> String {
    let file = finding["location"]["file"].as_str().unwrap_or_default();
    let start_line = finding["location"]["start"]["line"].as_u64().unwrap_or(0);
    let rule_id = finding["rule_id"].as_str().unwrap_or_default();
    let message = finding["message"].as_str().unwrap_or_default();
    format!("{file}\x00{start_line}\x00{rule_id}\x00{message}")
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── fixture helpers ──────────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn make_finding(
        file: &str,
        line: u64,
        rule_id: &str,
        severity: &str,
        dimension: &str,
        message: &str,
        cwe: &[&str],
        owasp: &[&str],
    ) -> serde_json::Value {
        let mut f = json!({
            "analyzer": "test",
            "rule_id": rule_id,
            "severity": severity,
            "dimension": dimension,
            "message": message,
            "location": {
                "file": file,
                "span": {"start": 0, "end": 1},
                "start": {"line": line, "col": 1},
                "end":   {"line": line, "col": 2}
            }
        });
        if !cwe.is_empty() {
            f["cwe"] = json!(cwe);
        }
        if !owasp.is_empty() {
            f["owasp"] = json!(owasp);
        }
        f
    }

    #[allow(clippy::needless_pass_by_value)]
    fn make_envelope(
        scan_id: &str,
        captured_at: &str,
        findings: Vec<serde_json::Value>,
        scores: serde_json::Value,
        stats: serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "scan_id": scan_id,
            "captured_at": captured_at,
            "config_hash": "abc123",
            "report": {
                "schema_version": 1,
                "tool": {"name": "zuit", "version": "0.1.0"},
                "scores": scores,
                "findings": findings,
                "stats": stats,
            }
        })
    }

    fn default_scores() -> serde_json::Value {
        json!({
            "maintainability": 85.0,
            "security": 92.0,
            "complexity": 75.0,
            "documentation": 60.0,
            "test_smell": 55.0,
        })
    }

    fn default_stats() -> serde_json::Value {
        json!({"files_scanned": 10, "parse_failures": 0, "elapsed_ms": 123})
    }

    // ── score_to_grade_boundaries ────────────────────────────────────────────

    #[test]
    fn score_to_grade_boundaries() {
        assert_eq!(score_to_grade(100.0), "A");
        assert_eq!(score_to_grade(90.0), "A");
        assert_eq!(score_to_grade(89.99), "B");
        assert_eq!(score_to_grade(80.0), "B");
        assert_eq!(score_to_grade(79.99), "C");
        assert_eq!(score_to_grade(70.0), "C");
        assert_eq!(score_to_grade(69.99), "D");
        assert_eq!(score_to_grade(60.0), "D");
        assert_eq!(score_to_grade(59.99), "F");
        assert_eq!(score_to_grade(0.0), "F");
    }

    // ── analytics_empty_findings ─────────────────────────────────────────────

    #[test]
    fn analytics_empty_findings() {
        let envelope = make_envelope(
            "2026-01-01T00:00:00Z-aabbcc",
            "2026-01-01T00:00:00Z",
            vec![],
            default_scores(),
            default_stats(),
        );
        let a = compute_scan_analytics(&envelope);
        assert_eq!(a.total_findings, 0);
        assert!(a.severity_counts.is_empty());
        assert!(a.dimension_counts.is_empty());
        assert!(a.top_rules.is_empty());
        assert!(a.top_files.is_empty());
        assert!(a.cwe_counts.is_empty());
        assert!(a.owasp_counts.is_empty());
        // Grades must be populated from scores.
        assert_eq!(
            a.grades.get("maintainability").map(String::as_str),
            Some("B")
        ); // 85
        assert_eq!(a.grades.get("security").map(String::as_str), Some("A")); // 92
        assert_eq!(a.grades.get("complexity").map(String::as_str), Some("C")); // 75
        assert_eq!(a.grades.get("documentation").map(String::as_str), Some("D")); // 60
        assert_eq!(a.grades.get("test_smell").map(String::as_str), Some("F")); // 55
    }

    // ── analytics_counts_severities_and_dimensions ───────────────────────────

    #[test]
    fn analytics_counts_severities_and_dimensions() {
        let findings = vec![
            make_finding("a.rs", 1, "SEC001", "high", "security", "msg", &[], &[]),
            make_finding("a.rs", 2, "SEC001", "high", "security", "msg2", &[], &[]),
            make_finding("a.rs", 3, "SEC001", "high", "security", "msg3", &[], &[]),
            make_finding(
                "b.rs",
                1,
                "MAINT001",
                "medium",
                "maintainability",
                "m1",
                &[],
                &[],
            ),
            make_finding(
                "b.rs",
                2,
                "MAINT001",
                "medium",
                "maintainability",
                "m2",
                &[],
                &[],
            ),
        ];
        let envelope = make_envelope(
            "2026-01-01T00:00:00Z-aabbcc",
            "2026-01-01T00:00:00Z",
            findings,
            default_scores(),
            default_stats(),
        );
        let a = compute_scan_analytics(&envelope);
        assert_eq!(a.total_findings, 5);
        assert_eq!(a.severity_counts.get("high"), Some(&3));
        assert_eq!(a.severity_counts.get("medium"), Some(&2));
        assert_eq!(a.dimension_counts.get("security"), Some(&3));
        assert_eq!(a.dimension_counts.get("maintainability"), Some(&2));
    }

    // ── analytics_top_rules_sorted ───────────────────────────────────────────

    #[test]
    fn analytics_top_rules_sorted() {
        // SEC001 and SEC002 both have count 2 → tie-break by rule_id asc.
        let findings = vec![
            make_finding("a.rs", 1, "SEC002", "high", "security", "x", &[], &[]),
            make_finding("a.rs", 2, "SEC002", "high", "security", "y", &[], &[]),
            make_finding("b.rs", 1, "SEC001", "high", "security", "z", &[], &[]),
            make_finding("b.rs", 2, "SEC001", "high", "security", "w", &[], &[]),
            make_finding(
                "c.rs",
                1,
                "MAINT001",
                "medium",
                "maintainability",
                "v",
                &[],
                &[],
            ),
            make_finding(
                "c.rs",
                2,
                "MAINT001",
                "medium",
                "maintainability",
                "u",
                &[],
                &[],
            ),
            make_finding(
                "c.rs",
                3,
                "MAINT001",
                "medium",
                "maintainability",
                "t",
                &[],
                &[],
            ),
        ];
        let envelope = make_envelope(
            "2026-01-01T00:00:00Z-aabbcc",
            "2026-01-01T00:00:00Z",
            findings,
            default_scores(),
            default_stats(),
        );
        let a = compute_scan_analytics(&envelope);
        // MAINT001 has 3, then SEC001 and SEC002 are tied at 2.
        assert_eq!(a.top_rules[0].rule_id, "MAINT001");
        assert_eq!(a.top_rules[0].count, 3);
        // Tie-break: SEC001 < SEC002 alphabetically.
        assert_eq!(a.top_rules[1].rule_id, "SEC001");
        assert_eq!(a.top_rules[2].rule_id, "SEC002");
    }

    // ── analytics_taxonomy_rollup ────────────────────────────────────────────

    #[test]
    fn analytics_taxonomy_rollup() {
        let findings = vec![
            make_finding(
                "a.rs",
                1,
                "SEC001",
                "high",
                "security",
                "msg",
                &["CWE-79", "CWE-80"],
                &["A01:2021"],
            ),
            make_finding(
                "b.rs",
                1,
                "SEC001",
                "high",
                "security",
                "msg2",
                &["CWE-79"],
                &["A01:2021", "A03:2021"],
            ),
        ];
        let envelope = make_envelope(
            "2026-01-01T00:00:00Z-aabbcc",
            "2026-01-01T00:00:00Z",
            findings,
            default_scores(),
            default_stats(),
        );
        let a = compute_scan_analytics(&envelope);
        assert_eq!(a.cwe_counts.get("CWE-79"), Some(&2));
        assert_eq!(a.cwe_counts.get("CWE-80"), Some(&1));
        assert_eq!(a.owasp_counts.get("A01:2021"), Some(&2));
        assert_eq!(a.owasp_counts.get("A03:2021"), Some(&1));
    }

    // ── diff_identical_envelopes ─────────────────────────────────────────────

    #[test]
    fn diff_identical_envelopes() {
        let findings = vec![
            make_finding("a.rs", 1, "RULE1", "high", "security", "msg", &[], &[]),
            make_finding(
                "b.rs",
                2,
                "RULE2",
                "medium",
                "maintainability",
                "msg2",
                &[],
                &[],
            ),
        ];
        let env = make_envelope(
            "2026-01-01T00:00:00Z-aabbcc",
            "2026-01-01T00:00:00Z",
            findings,
            default_scores(),
            default_stats(),
        );
        let diff = compute_scan_diff(&env, &env);
        assert!(diff.new.is_empty());
        assert!(diff.resolved.is_empty());
        assert_eq!(diff.persisting.len(), 2);
    }

    // ── diff_one_added_one_removed ───────────────────────────────────────────

    #[test]
    fn diff_one_added_one_removed() {
        let shared = make_finding("a.rs", 1, "SHARED", "high", "security", "msg", &[], &[]);
        let removed = make_finding("b.rs", 5, "OLD", "low", "maintainability", "old", &[], &[]);
        let added = make_finding("c.rs", 3, "NEW", "critical", "security", "new", &[], &[]);

        let from_env = make_envelope(
            "2026-01-01T00:00:00Z-aaaaaa",
            "2026-01-01T00:00:00Z",
            vec![shared.clone(), removed],
            default_scores(),
            default_stats(),
        );
        let to_env = make_envelope(
            "2026-01-02T00:00:00Z-bbbbbb",
            "2026-01-02T00:00:00Z",
            vec![shared, added],
            default_scores(),
            default_stats(),
        );
        let diff = compute_scan_diff(&from_env, &to_env);
        assert_eq!(diff.new.len(), 1);
        assert_eq!(diff.resolved.len(), 1);
        assert_eq!(diff.persisting.len(), 1);
        assert_eq!(diff.new[0]["rule_id"], "NEW");
        assert_eq!(diff.resolved[0]["rule_id"], "OLD");
        assert_eq!(diff.persisting[0]["rule_id"], "SHARED");
    }

    // ── diff_is_deterministic ────────────────────────────────────────────────

    #[test]
    fn diff_is_deterministic() {
        let findings = vec![
            make_finding("a.rs", 1, "R1", "high", "security", "m1", &[], &[]),
            make_finding("b.rs", 2, "R2", "low", "maintainability", "m2", &[], &[]),
            make_finding("c.rs", 3, "R3", "medium", "complexity", "m3", &[], &[]),
        ];
        let from_env = make_envelope(
            "2026-01-01T00:00:00Z-aaaaaa",
            "2026-01-01T00:00:00Z",
            findings.clone(),
            default_scores(),
            default_stats(),
        );
        let to_env = make_envelope(
            "2026-01-02T00:00:00Z-bbbbbb",
            "2026-01-02T00:00:00Z",
            findings[1..].to_vec(),
            default_scores(),
            default_stats(),
        );
        let diff1 = compute_scan_diff(&from_env, &to_env);
        let diff2 = compute_scan_diff(&from_env, &to_env);
        let bytes1 = serde_json::to_vec(&diff1).expect("serialize");
        let bytes2 = serde_json::to_vec(&diff2).expect("serialize");
        assert_eq!(bytes1, bytes2);
    }

    // ── summary_no_previous_when_one_scan ────────────────────────────────────

    #[test]
    fn summary_no_previous_when_one_scan() {
        let meta = ProjectMeta {
            root: std::path::PathBuf::from("/tmp/proj"),
            name: "proj".to_owned(),
            first_seen: "2026-01-01T00:00:00Z".to_owned(),
        };
        let env = make_envelope(
            "2026-01-01T00:00:00Z-aaaaaa",
            "2026-01-01T00:00:00Z",
            vec![],
            default_scores(),
            default_stats(),
        );
        let summary = compute_project_summary(&meta, &[env]);
        assert!(summary.latest.is_some());
        assert!(summary.delta_vs_previous.is_none());
    }

    // ── summary_has_delta_for_two_scans ──────────────────────────────────────

    #[test]
    fn summary_has_delta_for_two_scans() {
        let meta = ProjectMeta {
            root: std::path::PathBuf::from("/tmp/proj"),
            name: "proj".to_owned(),
            first_seen: "2026-01-01T00:00:00Z".to_owned(),
        };

        let scores_old = json!({
            "maintainability": 70.0,
            "security": 80.0,
            "complexity": 90.0,
            "documentation": 60.0,
            "test_smell": 50.0,
        });
        let scores_new = json!({
            "maintainability": 75.0,
            "security": 85.0,
            "complexity": 90.0,
            "documentation": 55.0,
            "test_smell": 60.0,
        });

        let env_old = make_envelope(
            "2026-01-01T00:00:00Z-aaaaaa",
            "2026-01-01T00:00:00Z",
            vec![make_finding(
                "a.rs",
                1,
                "SEC001",
                "high",
                "security",
                "m1",
                &[],
                &[],
            )],
            scores_old,
            default_stats(),
        );
        let env_new = make_envelope(
            "2026-01-02T00:00:00Z-bbbbbb",
            "2026-01-02T00:00:00Z",
            vec![
                make_finding("a.rs", 1, "SEC001", "high", "security", "m1", &[], &[]),
                make_finding(
                    "b.rs",
                    1,
                    "MAINT001",
                    "medium",
                    "maintainability",
                    "m2",
                    &[],
                    &[],
                ),
            ],
            scores_new,
            default_stats(),
        );

        let summary = compute_project_summary(&meta, &[env_old, env_new]);
        assert!(summary.delta_vs_previous.is_some());
        let delta = summary.delta_vs_previous.unwrap();

        // score deltas: new - old
        let maint_delta = delta.score_deltas.get("maintainability").copied().unwrap();
        assert!(
            (maint_delta - 5.0).abs() < 0.001,
            "expected +5.0, got {maint_delta}"
        );

        let doc_delta = delta.score_deltas.get("documentation").copied().unwrap();
        assert!(
            (doc_delta - (-5.0)).abs() < 0.001,
            "expected -5.0, got {doc_delta}"
        );

        // finding count: 2 - 1 = +1
        assert_eq!(delta.finding_count_delta, 1);
    }

    // ── heatmap_empty_envelopes ──────────────────────────────────────────────

    #[test]
    fn heatmap_empty_envelopes() {
        let result = compute_heatmap(&[], None);
        assert!(result.is_empty());
    }

    // ── heatmap_single_scan_path_counts ─────────────────────────────────────

    #[test]
    fn heatmap_single_scan_path_counts() {
        let findings = vec![
            make_finding("a.rs", 1, "R1", "high", "security", "m1", &[], &[]),
            make_finding("a.rs", 2, "R1", "high", "security", "m2", &[], &[]),
            make_finding("b.rs", 1, "R1", "high", "security", "m3", &[], &[]),
        ];
        let env = make_envelope(
            "2026-01-01T00:00:00Z-aaaaaa",
            "2026-01-01T00:00:00Z",
            findings,
            default_scores(),
            default_stats(),
        );
        let result = compute_heatmap(&[env], None);
        // a.rs has 2, b.rs has 1 — sorted by total desc.
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].path, "a.rs");
        assert_eq!(result[0].total_findings_all_time, 2);
        assert_eq!(result[0].findings_per_scan, vec![2]);
        assert_eq!(result[0].peak_count, 2);
        assert_eq!(result[0].last_seen_scan_id, "2026-01-01T00:00:00Z-aaaaaa");

        assert_eq!(result[1].path, "b.rs");
        assert_eq!(result[1].total_findings_all_time, 1);
        assert_eq!(result[1].findings_per_scan, vec![1]);
    }

    // ── heatmap_multi_scan_trend ─────────────────────────────────────────────

    #[test]
    fn heatmap_multi_scan_trend() {
        let findings_1 = vec![make_finding(
            "a.rs",
            1,
            "R1",
            "high",
            "security",
            "m1",
            &[],
            &[],
        )];
        let findings_2 = vec![
            make_finding("a.rs", 1, "R1", "high", "security", "m1", &[], &[]),
            make_finding("a.rs", 2, "R1", "high", "security", "m2", &[], &[]),
            make_finding("b.rs", 1, "R1", "high", "security", "m3", &[], &[]),
        ];
        let env1 = make_envelope(
            "2026-01-01T00:00:00Z-aaaaaa",
            "2026-01-01T00:00:00Z",
            findings_1,
            default_scores(),
            default_stats(),
        );
        let env2 = make_envelope(
            "2026-01-02T00:00:00Z-bbbbbb",
            "2026-01-02T00:00:00Z",
            findings_2,
            default_scores(),
            default_stats(),
        );
        let result = compute_heatmap(&[env1, env2], None);
        // a.rs: total=3 (1 in scan0, 2 in scan1); b.rs: total=1 (0 in scan0, 1 in scan1).
        assert_eq!(result.len(), 2);

        let a = result.iter().find(|e| e.path == "a.rs").unwrap();
        assert_eq!(a.total_findings_all_time, 3);
        assert_eq!(a.findings_per_scan, vec![1, 2]);
        assert_eq!(a.peak_count, 2);
        assert_eq!(a.last_seen_scan_id, "2026-01-02T00:00:00Z-bbbbbb");

        let b = result.iter().find(|e| e.path == "b.rs").unwrap();
        assert_eq!(b.total_findings_all_time, 1);
        assert_eq!(b.findings_per_scan, vec![0, 1]);
        assert_eq!(b.peak_count, 1);
    }

    // ── heatmap_top_n_truncation ─────────────────────────────────────────────

    #[test]
    fn heatmap_top_n_truncation() {
        // Create 30 distinct files, each with 1 finding.
        let mut findings = Vec::new();
        for i in 0..30_u32 {
            findings.push(make_finding(
                &format!("file{i:02}.rs"),
                1,
                "R1",
                "high",
                "security",
                "m",
                &[],
                &[],
            ));
        }
        let env = make_envelope(
            "2026-01-01T00:00:00Z-aaaaaa",
            "2026-01-01T00:00:00Z",
            findings,
            default_scores(),
            default_stats(),
        );
        // Default top_n = 25.
        let result = compute_heatmap(&[env], None);
        assert_eq!(result.len(), 25);

        // Explicit top_n = 5.
        let env2 = make_envelope(
            "2026-01-01T00:00:00Z-cccccc",
            "2026-01-01T00:00:00Z",
            (0..30_u32)
                .map(|i| {
                    make_finding(
                        &format!("file{i:02}.rs"),
                        1,
                        "R1",
                        "high",
                        "security",
                        "m",
                        &[],
                        &[],
                    )
                })
                .collect(),
            default_scores(),
            default_stats(),
        );
        let result5 = compute_heatmap(&[env2], Some(5));
        assert_eq!(result5.len(), 5);
    }

    // ── heatmap_sort_order ───────────────────────────────────────────────────

    #[test]
    fn heatmap_sort_order() {
        // b.rs has 3, a.rs has 3 (tie) → a.rs first (alphabetical).
        // c.rs has 1 → last.
        let findings = vec![
            make_finding("b.rs", 1, "R1", "high", "security", "m", &[], &[]),
            make_finding("b.rs", 2, "R1", "high", "security", "m", &[], &[]),
            make_finding("b.rs", 3, "R1", "high", "security", "m", &[], &[]),
            make_finding("a.rs", 1, "R1", "high", "security", "m", &[], &[]),
            make_finding("a.rs", 2, "R1", "high", "security", "m", &[], &[]),
            make_finding("a.rs", 3, "R1", "high", "security", "m", &[], &[]),
            make_finding("c.rs", 1, "R1", "high", "security", "m", &[], &[]),
        ];
        let env = make_envelope(
            "2026-01-01T00:00:00Z-aaaaaa",
            "2026-01-01T00:00:00Z",
            findings,
            default_scores(),
            default_stats(),
        );
        let result = compute_heatmap(&[env], None);
        assert_eq!(result[0].path, "a.rs");
        assert_eq!(result[1].path, "b.rs");
        assert_eq!(result[2].path, "c.rs");
    }

    // ── severity_weight_table ────────────────────────────────────────────────

    #[test]
    fn severity_weight_table() {
        assert_eq!(severity_weight("info"), 1);
        assert_eq!(severity_weight("low"), 2);
        assert_eq!(severity_weight("medium"), 5);
        assert_eq!(severity_weight("high"), 10);
        assert_eq!(severity_weight("critical"), 20);
        // Unknown severity should map to 1 (info-level).
        assert_eq!(severity_weight("unknown"), 1);
    }

    // ── heatmap_severity_weighted ────────────────────────────────────────────

    #[test]
    fn heatmap_severity_weighted() {
        // a.rs: 1 Critical (weight 20)
        // b.rs: 4 Low (4 × 2 = 8)
        // a.rs should rank higher by weight even though count is lower.
        let findings = vec![
            make_finding(
                "a.rs",
                1,
                "SEC001",
                "critical",
                "security",
                "critical",
                &[],
                &[],
            ),
            make_finding(
                "b.rs",
                1,
                "MAINT001",
                "low",
                "maintainability",
                "low1",
                &[],
                &[],
            ),
            make_finding(
                "b.rs",
                2,
                "MAINT001",
                "low",
                "maintainability",
                "low2",
                &[],
                &[],
            ),
            make_finding(
                "b.rs",
                3,
                "MAINT001",
                "low",
                "maintainability",
                "low3",
                &[],
                &[],
            ),
            make_finding(
                "b.rs",
                4,
                "MAINT001",
                "low",
                "maintainability",
                "low4",
                &[],
                &[],
            ),
        ];
        let env = make_envelope(
            "2026-01-01T00:00:00Z-aaaaaa",
            "2026-01-01T00:00:00Z",
            findings,
            default_scores(),
            default_stats(),
        );
        let result = compute_heatmap(&[env], None);
        assert_eq!(result.len(), 2);
        // a.rs has weight 20, b.rs has weight 8 → a.rs first.
        assert_eq!(result[0].path, "a.rs");
        assert_eq!(result[0].total_weight_all_time, 20);
        assert_eq!(result[0].total_findings_all_time, 1);
        assert_eq!(result[1].path, "b.rs");
        assert_eq!(result[1].total_weight_all_time, 8);
        assert_eq!(result[1].total_findings_all_time, 4);
    }

    // ── heatmap_sidecar_v1_triggers_regen ───────────────────────────────────

    #[test]
    fn heatmap_sidecar_v1_triggers_regen() {
        use tempfile::TempDir;

        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("scan.analytics.json");

        // Write a v1-shaped sidecar (no `version` field, no `all_file_weighted`).
        let v1_json = serde_json::json!({
            "scan_id": "test-scan",
            "captured_at": "2026-01-01T00:00:00Z",
            "total_findings": 1,
            "severity_counts": {"critical": 1},
            "dimension_counts": {"security": 1},
            "top_rules": [],
            "top_files": [],
            "cwe_counts": {},
            "owasp_counts": {},
            "grades": {},
            "scores": {},
            "all_file_counts": {"a.rs": 1}
            // Note: no `version` field, no `all_file_weighted`
        });
        std::fs::write(&path, serde_json::to_vec(&v1_json).unwrap()).unwrap();

        let loaded: ScanAnalytics = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();

        // Version should default to 1 (old sidecar).
        assert_eq!(loaded.version, 1);
        // all_file_weighted should be empty (default).
        assert!(loaded.all_file_weighted.is_empty());
        // version != ANALYTICS_VERSION means it needs regen.
        assert_ne!(loaded.version, ANALYTICS_VERSION);
    }

    // ── heatmap_sidecar_v2_round_trips ───────────────────────────────────────

    #[test]
    fn heatmap_sidecar_v2_round_trips() {
        // Build a current-version ScanAnalytics and serialize/deserialize it.
        let findings = vec![make_finding(
            "a.rs",
            1,
            "SEC001",
            "critical",
            "security",
            "crit",
            &[],
            &[],
        )];
        let env = make_envelope(
            "2026-01-01T00:00:00Z-aaaaaa",
            "2026-01-01T00:00:00Z",
            findings,
            default_scores(),
            default_stats(),
        );
        let computed = compute_scan_analytics(&env);

        // Should have version 2.
        assert_eq!(computed.version, ANALYTICS_VERSION);
        assert_eq!(computed.version, 2);

        // Serialize then deserialize.
        let bytes = serde_json::to_vec(&computed).expect("serialize");
        let roundtrip: ScanAnalytics = serde_json::from_slice(&bytes).expect("deserialize");

        // Version should round-trip.
        assert_eq!(roundtrip.version, ANALYTICS_VERSION);
        // all_file_weighted should be populated.
        assert!(!roundtrip.all_file_weighted.is_empty());
        assert_eq!(roundtrip.all_file_weighted.get("a.rs"), Some(&20u32)); // Critical = 20
        // No regen needed since version matches.
        assert_eq!(roundtrip.version, computed.version);
    }

    // ── compute_scan_analytics_assigns_grades_to_all_score_dimensions ────────

    #[test]
    fn compute_scan_analytics_assigns_grades_to_all_score_dimensions() {
        // Build an envelope with v1 dims + newer dims.
        let scores = json!({
            "maintainability": 85.0,
            "security":        92.0,
            "complexity":      75.0,
            "documentation":   60.0,
            "test_smell":      55.0,
            // New dimensions absent from the old hardcoded list:
            "ci_release":      95.0,
            "performance":     50.0,
            "unsafe_soundness": 100.0,
        });
        let envelope = make_envelope(
            "2026-05-09T04:05:42Z-abc123",
            "2026-05-09T04:05:42Z",
            vec![],
            scores.clone(),
            default_stats(),
        );
        let a = compute_scan_analytics(&envelope);

        // Every key in `scores` must have a corresponding grade entry.
        let score_keys: Vec<&str> = scores
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        for key in &score_keys {
            let grade = a.grades.get(*key);
            assert!(
                grade.is_some(),
                "grades map missing entry for dimension '{key}'"
            );
            let g = grade.unwrap().as_str();
            assert!(
                ["A", "B", "C", "D", "F"].contains(&g),
                "grade for '{key}' is '{g}', expected one of A/B/C/D/F"
            );
        }
        // Spot-check specific expected grades.
        assert_eq!(a.grades.get("ci_release").map(String::as_str), Some("A")); // 95
        assert_eq!(a.grades.get("performance").map(String::as_str), Some("F")); // 50
        assert_eq!(
            a.grades.get("unsafe_soundness").map(String::as_str),
            Some("A")
        ); // 100
    }

    // ── trends_one_point_per_scan_chronological ──────────────────────────────

    #[test]
    fn trends_one_point_per_scan_chronological() {
        let env1 = make_envelope(
            "2026-01-01T00:00:00Z-aaaaaa",
            "2026-01-01T00:00:00Z",
            vec![make_finding(
                "a.rs",
                1,
                "R1",
                "high",
                "security",
                "m",
                &[],
                &[],
            )],
            default_scores(),
            json!({"files_scanned": 5, "parse_failures": 1, "elapsed_ms": 100}),
        );
        let env2 = make_envelope(
            "2026-01-02T00:00:00Z-bbbbbb",
            "2026-01-02T00:00:00Z",
            vec![
                make_finding("a.rs", 1, "R1", "high", "security", "m", &[], &[]),
                make_finding("b.rs", 2, "R2", "low", "maintainability", "m2", &[], &[]),
            ],
            default_scores(),
            json!({"files_scanned": 10, "parse_failures": 0, "elapsed_ms": 200}),
        );
        let trends = compute_trends(&[env1, env2]);
        assert_eq!(trends.len(), 2);
        assert_eq!(trends[0].scan_id, "2026-01-01T00:00:00Z-aaaaaa");
        assert_eq!(trends[0].total_findings, 1);
        assert_eq!(trends[0].files_scanned, 5);
        assert_eq!(trends[0].parse_failures, 1);
        assert_eq!(trends[0].elapsed_ms, 100);
        assert_eq!(trends[1].scan_id, "2026-01-02T00:00:00Z-bbbbbb");
        assert_eq!(trends[1].total_findings, 2);
        assert_eq!(trends[1].files_scanned, 10);
        assert_eq!(trends[1].severity_counts.get("high"), Some(&1));
        assert_eq!(trends[1].severity_counts.get("low"), Some(&1));
    }
}
