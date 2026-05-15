//! JSON formatter for zuit reports.
//!
//! Produces pretty-printed JSON with a stable field order documented in
//! `docs/json-schema.md`. The top-level object always contains exactly these
//! keys in this order:
//!
//! ```json
//! {
//!   "schema_version": 2,
//!   "tool": { "name": "zuit", "version": "0.1.0" },
//!   "scores": { "maintainability": 87.4, ... },
//!   "grades": { "maintainability": "B", ... },
//!   "findings": [ ... ],
//!   "stats": { ... }
//! }
//! ```
//!
//! **Score field order** in `scores` is guaranteed by rendering dimensions in a
//! fixed enum-driven sequence: `maintainability`, `security`, `complexity`,
//! `documentation`, `test_smell`, then any custom dimensions in insertion order.
//! The `grades` object follows the same ordering.

use std::collections::BTreeMap;

use serde::Serialize;
use zuit_core::analyzer::Dimension;
use zuit_core::engine::Report;

use crate::ReportError;

/// The v1 dimension ordering used to produce stable JSON output.
///
/// Custom dimensions follow in no guaranteed order (they are inserted via a
/// `BTreeMap` to remain deterministic on any given set of custom names).
const V1_DIMENSION_ORDER: &[Dimension] = &[
    Dimension::Maintainability,
    Dimension::Security,
    Dimension::Complexity,
    Dimension::Documentation,
    Dimension::TestSmell,
];

/// Metadata about the tool that produced this report.
#[derive(Serialize)]
struct ToolInfo {
    name: &'static str,
    version: &'static str,
}

/// Maps a 0–100 score to a letter grade.
///
/// - ≥ 90 → `"A"`
/// - ≥ 80 → `"B"`
/// - ≥ 70 → `"C"`
/// - ≥ 60 → `"D"`
/// - < 60 → `"F"`
fn score_to_grade(score: f32) -> &'static str {
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

/// The wire representation of scores: `{ "maintainability": 87.4, ... }`.
///
/// We use an `IndexMap`-like ordered structure by building an explicit `Vec`
/// of `(key, value)` pairs and serialising as a JSON object via a custom
/// `Serialize` impl, which lets us control insertion order.
struct OrderedScores(Vec<(String, f32)>);

impl Serialize for OrderedScores {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

/// The wire representation of grades: `{ "maintainability": "B", ... }`.
///
/// Uses the same ordered-pair approach as [`OrderedScores`] to guarantee
/// field order matches the `scores` object.
struct OrderedGrades(Vec<(String, &'static str)>);

impl Serialize for OrderedGrades {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

/// The root JSON object with a guaranteed field order.
#[derive(Serialize)]
struct JsonReport<'a> {
    schema_version: u32,
    tool: ToolInfo,
    scores: OrderedScores,
    grades: OrderedGrades,
    findings: &'a Vec<zuit_core::finding::Finding>,
    stats: &'a zuit_core::engine::RunStats,
}

/// Renders `report` as pretty-printed JSON.
///
/// The field order in the top-level object is:
/// `schema_version` → `tool` → `scores` → `grades` → `findings` → `stats`.
///
/// Scores within `scores` are in the fixed v1 order:
/// `maintainability`, `security`, `complexity`, `documentation`, `test_smell`,
/// followed by any custom dimensions in lexicographic order.
/// The `grades` object follows the same dimension ordering.
///
/// # Errors
///
/// Returns [`ReportError::Serialize`] if `serde_json` fails (extremely unlikely
/// because all types are well-formed).
pub fn render_json(report: &Report) -> Result<String, ReportError> {
    // Build ordered scores and grades (same order).
    let mut score_pairs: Vec<(String, f32)> = Vec::with_capacity(report.scores.len());
    let mut grade_pairs: Vec<(String, &'static str)> = Vec::with_capacity(report.scores.len());

    // Insert v1 dimensions first, in canonical order.
    for dim in V1_DIMENSION_ORDER {
        if let Some(score) = report.scores.get(dim) {
            let key = dim.to_string();
            let value = score.value();
            grade_pairs.push((key.clone(), score_to_grade(value)));
            score_pairs.push((key, value));
        }
    }

    // Then any custom dimensions, sorted lexicographically for determinism.
    let custom_scores: BTreeMap<String, f32> = report
        .scores
        .iter()
        .filter(|(dim, _)| !V1_DIMENSION_ORDER.contains(dim))
        .map(|(dim, s)| (dim.to_string(), s.value()))
        .collect();
    for (key, value) in &custom_scores {
        grade_pairs.push((key.clone(), score_to_grade(*value)));
    }
    score_pairs.extend(custom_scores);

    let json_report = JsonReport {
        schema_version: report.schema_version,
        tool: ToolInfo {
            name: "zuit",
            version: env!("CARGO_PKG_VERSION"),
        },
        scores: OrderedScores(score_pairs),
        grades: OrderedGrades(grade_pairs),
        findings: &report.findings,
        stats: &report.stats,
    };

    Ok(serde_json::to_string_pretty(&json_report)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use zuit_core::engine::RunStats;

    fn empty_report() -> Report {
        use std::collections::BTreeMap;
        use zuit_core::analyzer::Dimension;
        use zuit_core::score::aggregate_dimension_score;

        let mut scores = BTreeMap::new();
        for dim in [
            Dimension::Maintainability,
            Dimension::Security,
            Dimension::Complexity,
            Dimension::Documentation,
            Dimension::TestSmell,
        ] {
            scores.insert(dim, aggregate_dimension_score(&[], 1.0));
        }

        Report {
            schema_version: 1,
            findings: vec![],
            scores,
            stats: RunStats {
                files_scanned: 0,
                parse_failures: 0,
                elapsed_ms: 0,
                suppressed: 0,
                cache_hits: 0,
            },
        }
    }

    #[test]
    fn top_level_field_order() {
        let report = empty_report();
        let json = render_json(&report).unwrap();
        // Parse back and check keys appear in correct order.
        let v: serde_json::Map<String, Value> = serde_json::from_str(&json).unwrap();
        let keys: Vec<&str> = v.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            &[
                "schema_version",
                "tool",
                "scores",
                "grades",
                "findings",
                "stats"
            ]
        );
    }

    #[test]
    fn tool_block_present() {
        let report = empty_report();
        let json = render_json(&report).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["tool"]["name"], "zuit");
        assert!(v["tool"]["version"].is_string());
    }

    #[test]
    fn schema_version_is_1() {
        let report = empty_report();
        let json = render_json(&report).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["schema_version"], 1);
    }

    #[test]
    fn score_order_is_stable() {
        let report = empty_report();
        let json = render_json(&report).unwrap();
        let v: serde_json::Map<String, Value> = serde_json::from_str(&json).unwrap();
        let score_keys: Vec<&str> = v["scores"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        // The first five must be in canonical v1 order.
        assert_eq!(score_keys[0], "maintainability");
        assert_eq!(score_keys[1], "security");
        assert_eq!(score_keys[2], "complexity");
        assert_eq!(score_keys[3], "documentation");
        assert_eq!(score_keys[4], "test_smell");
    }

    #[test]
    fn grades_block_present_and_ordered() {
        let report = empty_report();
        let json = render_json(&report).unwrap();
        let v: serde_json::Map<String, Value> = serde_json::from_str(&json).unwrap();
        let grade_keys: Vec<&str> = v["grades"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(grade_keys[0], "maintainability");
        assert_eq!(grade_keys[1], "security");
        assert_eq!(grade_keys[2], "complexity");
        assert_eq!(grade_keys[3], "documentation");
        assert_eq!(grade_keys[4], "test_smell");
    }

    #[test]
    fn grade_boundaries() {
        assert_eq!(score_to_grade(100.0), "A");
        assert_eq!(score_to_grade(90.0), "A");
        assert_eq!(score_to_grade(89.99), "B");
        assert_eq!(score_to_grade(80.0), "B");
        assert_eq!(score_to_grade(70.0), "C");
        assert_eq!(score_to_grade(60.0), "D");
        assert_eq!(score_to_grade(0.0), "F");
    }

    #[test]
    fn grades_values_match_score_to_grade() {
        use std::collections::BTreeMap;
        use zuit_core::analyzer::Dimension;
        use zuit_core::score::Score;

        let mut scores: BTreeMap<Dimension, Score> = BTreeMap::new();
        scores.insert(Dimension::Security, Score(92.0));
        scores.insert(Dimension::Maintainability, Score(85.0));
        scores.insert(Dimension::Complexity, Score(75.0));
        scores.insert(Dimension::Documentation, Score(60.0));
        scores.insert(Dimension::TestSmell, Score(55.0));

        let report = Report {
            schema_version: 1,
            findings: vec![],
            scores,
            stats: zuit_core::engine::RunStats {
                files_scanned: 0,
                parse_failures: 0,
                elapsed_ms: 0,
                suppressed: 0,
                cache_hits: 0,
            },
        };

        let json = render_json(&report).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["grades"]["security"], "A"); // 92
        assert_eq!(v["grades"]["maintainability"], "B"); // 85
        assert_eq!(v["grades"]["complexity"], "C"); // 75
        assert_eq!(v["grades"]["documentation"], "D"); // 60
        assert_eq!(v["grades"]["test_smell"], "F"); // 55
    }
}
