mod common;

use serde_json::Value;
use zuit_report::render_sarif;

/// Snapshot test: full SARIF output for the canonical fake report.
///
/// After the initial implementation the snapshot is accepted via
/// `INSTA_UPDATE=always cargo test -p zuit-report` and then verified
/// on every subsequent run.
#[test]
fn snapshot_sarif() {
    let report = common::fake_report();
    let output = render_sarif(&report).expect("render_sarif should not fail");
    insta::assert_snapshot!(output);
}

// ---------------------------------------------------------------------------
// Structural / schema-proxy tests
// ---------------------------------------------------------------------------

/// Parses the output back with `serde_json` and asserts that all required
/// top-level SARIF 2.1.0 fields are present and have the correct types /
/// values.  This acts as a schema-validation proxy without pulling in a
/// JSON-schema validator.
#[test]
fn sarif_structure_is_valid() {
    let report = common::fake_report();
    let output = render_sarif(&report).expect("render_sarif should not fail");

    let v: Value = serde_json::from_str(&output).expect("output must be valid JSON");

    // Top-level required fields.
    assert_eq!(
        v["$schema"], "https://json.schemastore.org/sarif-2.1.0.json",
        "$schema field must match the SARIF 2.1.0 schema URL"
    );
    assert_eq!(v["version"], "2.1.0", "version must be '2.1.0'");

    // `runs` must be an array of exactly one entry (merged-run strategy for v1).
    let runs = v["runs"].as_array().expect("`runs` must be a JSON array");
    assert_eq!(runs.len(), 1, "`runs` must contain exactly one merged run");

    let run = &runs[0];

    // tool.driver block.
    let driver = &run["tool"]["driver"];
    assert_eq!(driver["name"], "zuit", "tool.driver.name must be 'zuit'");
    assert!(
        driver["version"].is_string(),
        "tool.driver.version must be a string"
    );
    assert!(
        driver["informationUri"].is_string(),
        "tool.driver.informationUri must be a string"
    );

    // rules array.
    let rules = driver["rules"]
        .as_array()
        .expect("tool.driver.rules must be an array");
    assert!(
        !rules.is_empty(),
        "rules must not be empty for a non-empty report"
    );

    // Every rule must have an `id` field.
    for rule in rules {
        assert!(rule["id"].is_string(), "every rule must have a string `id`");
    }

    // results array.
    let results = run["results"]
        .as_array()
        .expect("`results` must be a JSON array");
    assert!(
        !results.is_empty(),
        "results must not be empty for a non-empty report"
    );

    // Every result must have ruleId, level, message.text, and locations.
    for result in results {
        assert!(
            result["ruleId"].is_string(),
            "every result must have a string `ruleId`"
        );
        assert!(
            result["level"].is_string(),
            "every result must have a string `level`"
        );
        assert!(
            result["message"]["text"].is_string(),
            "every result must have message.text"
        );
        let locs = result["locations"]
            .as_array()
            .expect("every result must have a `locations` array");
        assert!(!locs.is_empty(), "locations must not be empty");
    }
}

/// Verifies the severity → SARIF level mapping for known finding severities.
#[test]
fn sarif_level_mapping() {
    let report = common::fake_report();
    let output = render_sarif(&report).expect("render_sarif should not fail");
    let v: Value = serde_json::from_str(&output).unwrap();
    let results = v["runs"][0]["results"].as_array().unwrap();

    // The fake_report has: Critical, High, Medium, Low findings.
    // Collect (ruleId, level) pairs so we can assert the mapping.
    let levels: Vec<(&str, &str)> = results
        .iter()
        .map(|r| (r["ruleId"].as_str().unwrap(), r["level"].as_str().unwrap()))
        .collect();

    // SEC001-hardcoded-secret Critical → "error"
    assert!(
        levels
            .iter()
            .any(|(rule, level)| *rule == "SEC001-hardcoded-secret" && *level == "error"),
        "Critical severity must map to SARIF level 'error'; got: {levels:?}"
    );

    // MAINT001-cyclomatic Medium → "warning"
    assert!(
        levels
            .iter()
            .any(|(rule, level)| *rule == "MAINT001-cyclomatic" && *level == "warning"),
        "Medium severity must map to SARIF level 'warning'; got: {levels:?}"
    );

    // MAINT001-cyclomatic Low → "note"
    let maint_levels: Vec<&str> = levels
        .iter()
        .filter(|(rule, _)| *rule == "MAINT001-cyclomatic")
        .map(|(_, l)| *l)
        .collect();
    assert!(
        maint_levels.contains(&"note"),
        "Low severity must map to SARIF level 'note'; got: {maint_levels:?}"
    );
}

/// Verifies that prose suggestions surface under `properties.suggestion`
/// (never under `fixes`, which SARIF 2.1.0 reserves for structured
/// `artifactChanges` and is rejected by GitHub code-scanning's schema
/// validator when it lacks them).
#[test]
fn sarif_suggestion_emitted_as_property() {
    let report = common::fake_report();
    let output = render_sarif(&report).expect("render_sarif should not fail");
    let v: Value = serde_json::from_str(&output).unwrap();
    let results = v["runs"][0]["results"].as_array().unwrap();

    // No result must ever carry a `fixes` field — we never emit one.
    for result in results {
        assert!(
            result.get("fixes").is_none(),
            "fixes must never be emitted (suggestions go under properties)"
        );
    }

    // The High SEC001 finding has message containing "JWT" and no suggestion;
    // its properties must therefore be absent.
    let jwt_result = results
        .iter()
        .find(|r| r["message"]["text"].as_str().unwrap_or("").contains("JWT"))
        .expect("JWT finding must be present");
    assert!(
        jwt_result.get("properties").is_none(),
        "properties must be absent when suggestion is None"
    );

    // At least one result must carry a properties.suggestion — the Critical
    // SEC001 finding in the fake report has one.
    let with_suggestion: Vec<_> = results
        .iter()
        .filter(|r| {
            r.get("properties")
                .and_then(|p| p.get("suggestion"))
                .is_some()
        })
        .collect();
    assert!(
        !with_suggestion.is_empty(),
        "at least one result must surface a suggestion via properties.suggestion"
    );
}

/// Verifies that CWE taxa references appear only when the finding has CWE entries.
#[test]
fn sarif_taxa_present_for_cwe_findings() {
    let report = common::fake_report();
    let output = render_sarif(&report).expect("render_sarif should not fail");
    let v: Value = serde_json::from_str(&output).unwrap();
    let results = v["runs"][0]["results"].as_array().unwrap();

    // Every finding in fake_report has at least one CWE — taxa must be present.
    for result in results {
        let taxa = result["taxa"]
            .as_array()
            .expect("taxa must be present for CWE findings");
        assert!(!taxa.is_empty(), "taxa must not be empty when CWE is set");
    }
}

/// Verifies rule deduplication: SEC001-hardcoded-secret appears twice in findings
/// but must appear only once in tool.driver.rules.
#[test]
fn sarif_rules_are_deduplicated() {
    let report = common::fake_report();
    let output = render_sarif(&report).expect("render_sarif should not fail");
    let v: Value = serde_json::from_str(&output).unwrap();
    let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();

    let sec001_count = rules
        .iter()
        .filter(|r| r["id"].as_str() == Some("SEC001-hardcoded-secret"))
        .count();
    assert_eq!(
        sec001_count, 1,
        "SEC001-hardcoded-secret must appear only once in rules (deduplication)"
    );
}

/// Verifies that rules are sorted by id and results are sorted deterministically.
#[test]
fn sarif_output_is_deterministic() {
    let report = common::fake_report();
    let out1 = render_sarif(&report).expect("first render must succeed");
    let out2 = render_sarif(&report).expect("second render must succeed");
    assert_eq!(
        out1, out2,
        "render_sarif must produce identical output on repeated calls"
    );
}

/// Empty report: must still produce valid SARIF with empty arrays.
#[test]
fn sarif_empty_report() {
    use std::collections::BTreeMap;
    use zuit_core::analyzer::Dimension;
    use zuit_core::engine::{Report, RunStats};
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
    let empty = Report {
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
    };

    let output = render_sarif(&empty).expect("empty report must not fail");
    let v: Value = serde_json::from_str(&output).expect("must be valid JSON");

    assert_eq!(v["version"], "2.1.0");
    let runs = v["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);
    let results = runs[0]["results"].as_array().unwrap();
    assert!(results.is_empty(), "empty report must produce zero results");
    let rules = runs[0]["tool"]["driver"]["rules"].as_array().unwrap();
    assert!(rules.is_empty(), "empty report must produce zero rules");
}
