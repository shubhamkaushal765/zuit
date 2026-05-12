//! `CHAIN004-unmaintained-transitive` — flags transitive dependencies whose
//! last-published time (from `package-lock.json` v3) is older than 18 months.
//!
//! A dependency that has not been updated in 18+ months may be unmaintained,
//! meaning security vulnerabilities are unlikely to be patched. This is a
//! Medium-severity supply-chain risk.
//!
//! # Data source
//!
//! The `packages` map in a package-lock.json v3 file may contain a `time` field
//! with an ISO-8601 timestamp indicating when that version was published. When
//! this field is absent the entry is silently skipped (the plan states: "skipped
//! silently if field absent"). No network call is ever made.
//!
//! # Lock-file version
//!
//! Only `lockfileVersion: 3` is processed. v1 and v2 schemas use a different
//! layout (`dependencies` map vs `packages` map) and are skipped silently.

use std::path::Path;
use std::time::{Duration, SystemTime};

use zuit_core::span::{ByteOffset, LineCol, Location, Span};
use zuit_core::{
    AnalysisContext, Analyzer, AnalyzerId, AnalyzerKind, Dimension, Finding, ParsedFile, Project,
    RuleMeta, Severity, SupportedLanguages,
};

/// Rule ID for the unmaintained-transitive check.
const RULE_ID: &str = "CHAIN004-unmaintained-transitive";

/// Number of months after which a dependency is considered potentially unmaintained.
const STALE_MONTHS: u64 = 18;

/// Approximate seconds in 18 months (18 × 30 days).
const STALE_SECS: u64 = STALE_MONTHS * 30 * 24 * 60 * 60;

/// Static metadata for this rule.
const META: RuleMeta = RuleMeta {
    id: RULE_ID,
    default_severity: Severity::Medium,
    doc_path: "docs/rules/CHAIN004-unmaintained-transitive.md",
    cwe: &[],
    owasp: &[],
};

/// Zero-width location anchored at `package.json` in the project root.
fn pkg_json_location(root: &Path) -> Location {
    let zero = Span::new(ByteOffset(0), ByteOffset(0));
    Location {
        file: root.join("package.json"),
        span: zero,
        start: LineCol::new(1, 1),
        end: LineCol::new(1, 1),
    }
}

/// Parses an ISO-8601 datetime string and returns `true` if it is older than
/// `STALE_SECS` relative to `now`.
///
/// Only a basic RFC-3339 / ISO-8601 subset is supported: `YYYY-MM-DDTHH:MM:SSZ`
/// and `YYYY-MM-DDTHH:MM:SS+HH:MM`. Missing or malformed timestamps return
/// `false` (skip silently).
fn is_stale(time_str: &str, now: SystemTime) -> bool {
    parse_rfc3339_approx(time_str)
        .and_then(|published| now.duration_since(published).ok())
        .is_some_and(|age| age > Duration::from_secs(STALE_SECS))
}

/// Very lightweight RFC-3339 parser that returns a `SystemTime`.
///
/// Supports the subset emitted by the npm registry:
/// - `YYYY-MM-DDTHH:MM:SS.mmmZ`
/// - `YYYY-MM-DDTHH:MM:SSZ`
/// - `YYYY-MM-DDTHH:MM:SS+00:00`
///
/// Returns `None` for any format that does not match.
fn parse_rfc3339_approx(s: &str) -> Option<SystemTime> {
    // Minimum length for "YYYY-MM-DDTHH:MM:SS"
    if s.len() < 19 {
        return None;
    }
    let bytes = s.as_bytes();
    // Validate the fixed separator positions.
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }

    let year: i64 = s[0..4].parse().ok()?;
    let month: i64 = s[5..7].parse().ok()?;
    let day: i64 = s[8..10].parse().ok()?;
    let hour: i64 = s[11..13].parse().ok()?;
    let minute: i64 = s[14..16].parse().ok()?;
    let second: i64 = s[17..19].parse().ok()?;

    // Convert to days since Unix epoch (1970-01-01).
    let days = days_from_civil(year, month, day)?;
    let unix_secs = days * 86_400 + hour * 3_600 + minute * 60 + second;
    if unix_secs < 0 {
        return None;
    }
    // Safety: unix_secs is checked to be non-negative above.
    #[allow(clippy::cast_sign_loss)]
    let unix_secs_u64 = unix_secs as u64;
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(unix_secs_u64))
}

/// Computes the number of days from the Unix epoch (1970-01-01) to the given
/// civil date.  Returns `None` for out-of-range month or day values.
///
/// Algorithm based on Howard Hinnant's date algorithms (public domain).
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let adj_year = if month <= 2 { year - 1 } else { year };
    let era = if adj_year >= 0 {
        adj_year
    } else {
        adj_year - 399
    } / 400;
    let yoe = adj_year - era * 400; // [0, 399]
    let adj_month = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * adj_month + 2) / 5 + day - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146_096]
    Some(era * 146_097 + doe - 719_468)
}

/// Core analysis logic — separated for unit testing.
///
/// Walks the `packages` map in a package-lock.json v3 value and emits one
/// finding per entry whose `time` field indicates staleness.
pub(crate) fn evaluate(
    root: &Path,
    lock_json: &serde_json::Value,
    now: SystemTime,
) -> Vec<Finding> {
    // Only process lockfileVersion 3.
    let version = lock_json
        .get("lockfileVersion")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if version != 3 {
        return vec![];
    }

    let Some(packages) = lock_json.get("packages").and_then(|p| p.as_object()) else {
        return vec![];
    };

    let mut findings = Vec::new();

    for (pkg_key, pkg_val) in packages {
        // Skip the root package entry (empty string key).
        if pkg_key.is_empty() {
            continue;
        }
        let pkg_name = pkg_key.trim_start_matches("node_modules/");

        let Some(time_str) = pkg_val.get("time").and_then(serde_json::Value::as_str) else {
            // No `time` field — skip silently.
            continue;
        };

        if is_stale(time_str, now) {
            let version_str = pkg_val
                .get("version")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");

            findings.push(Finding {
                analyzer: AnalyzerId::new(RULE_ID),
                dimension: Dimension::Custom("supply_chain".to_string()),
                rule_id: RULE_ID.to_string(),
                severity: Severity::Medium,
                message: format!(
                    "Transitive dependency `{pkg_name}@{version_str}` was last published \
                     on `{time_str}`, which is more than {STALE_MONTHS} months ago. \
                     The package may be unmaintained."
                ),
                location: pkg_json_location(root),
                suggestion: Some(format!(
                    "Update or replace `{pkg_name}` with an actively maintained \
                     alternative, or accept the risk and document it."
                )),
                references: vec![],
                cwe: META.cwe_vec(),
                owasp: META.owasp_vec(),
            });
        }
    }

    findings
}

/// Analyzer that emits `CHAIN004-unmaintained-transitive` for transitive
/// dependencies in `package-lock.json` v3 that have not been published in
/// 18 months or more.
pub struct Chain004UnmaintainedTransitiveAnalyzer;

impl Analyzer for Chain004UnmaintainedTransitiveAnalyzer {
    fn id(&self) -> AnalyzerId {
        AnalyzerId::new(RULE_ID)
    }

    fn dimension(&self) -> Dimension {
        Dimension::Custom("supply_chain".to_string())
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

    fn analyze_file(&self, _ctx: &AnalysisContext<'_>, _file: &ParsedFile) -> Vec<Finding> {
        vec![]
    }

    fn analyze_project(&self, _ctx: &AnalysisContext<'_>, project: &Project) -> Vec<Finding> {
        let manifest = crate::manifest::get_or_load(&project.root);
        let Some(lock) = manifest.lock_json.as_ref() else {
            return vec![];
        };
        evaluate(&project.root, lock, SystemTime::now())
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use zuit_core::{Config, Project};
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn write(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).expect("invariant: temp dir is writable");
    }

    fn run(dir: &Path) -> Vec<Finding> {
        let config = Config::default();
        let ctx = AnalysisContext::new(&config);
        let project = Project::new(dir.to_path_buf(), vec![]);
        Chain004UnmaintainedTransitiveAnalyzer.analyze_project(&ctx, &project)
    }

    /// Returns the current time minus `months` calendar months (approximate:
    /// 30 days per month) as an ISO-8601 string.
    fn months_ago_str(months: u64) -> String {
        let ago = SystemTime::now()
            .checked_sub(Duration::from_secs(months * 30 * 24 * 60 * 60))
            .expect("time arithmetic");
        let total_secs = ago
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("positive epoch")
            .as_secs();
        secs_to_iso8601(total_secs)
    }

    /// Converts a Unix timestamp (seconds) to a `YYYY-MM-DDTHH:MM:SSZ` string.
    fn secs_to_iso8601(total_secs: u64) -> String {
        let day_count = total_secs / 86_400;
        let day_secs = total_secs % 86_400;
        let (year, mon, day) = civil_from_days(
            // day_count fits easily in i64 for any modern date.
            #[allow(clippy::cast_possible_wrap)]
            (day_count as i64),
        );
        let hour = day_secs / 3_600;
        let minute = (day_secs % 3_600) / 60;
        let second = day_secs % 60;
        format!("{year:04}-{mon:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    }

    /// Inverse of `days_from_civil`: converts a day count (days since Unix
    /// epoch) to a `(year, month, day)` tuple.
    fn civil_from_days(z: i64) -> (i64, i64, i64) {
        let z = z + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let year_base = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = if month <= 2 { year_base + 1 } else { year_base };
        (year, month, day)
    }

    fn lock_json_v3(pkg_name: &str, version: &str, time_str: &str) -> String {
        format!(
            r#"{{
                "lockfileVersion": 3,
                "packages": {{
                    "node_modules/{pkg_name}": {{
                        "version": "{version}",
                        "time": "{time_str}"
                    }}
                }}
            }}"#
        )
    }

    fn lock_json_v3_no_time(pkg_name: &str, version: &str) -> String {
        format!(
            r#"{{
                "lockfileVersion": 3,
                "packages": {{
                    "node_modules/{pkg_name}": {{
                        "version": "{version}"
                    }}
                }}
            }}"#
        )
    }

    #[test]
    fn stale_transitive_dep_emits_medium() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        let time_str = months_ago_str(20); // 20 months ago → stale
        write(dir.path(), "package.json", r#"{"name":"my-app"}"#);
        write(
            dir.path(),
            "package-lock.json",
            &lock_json_v3("old-dep", "1.0.0", &time_str),
        );
        let findings = run(dir.path());
        assert_eq!(
            findings.len(),
            1,
            "20-month-old dep → 1 finding; got: {findings:#?}"
        );
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].rule_id, RULE_ID);
        assert!(findings[0].message.contains("old-dep"));
    }

    #[test]
    fn recent_dep_clean() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        let time_str = months_ago_str(1); // 1 month ago → fresh
        write(dir.path(), "package.json", r#"{"name":"my-app"}"#);
        write(
            dir.path(),
            "package-lock.json",
            &lock_json_v3("fresh-dep", "2.0.0", &time_str),
        );
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "1-month-old dep → 0 findings; got: {findings:#?}"
        );
    }

    #[test]
    fn no_time_field_clean() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(dir.path(), "package.json", r#"{"name":"my-app"}"#);
        write(
            dir.path(),
            "package-lock.json",
            &lock_json_v3_no_time("some-dep", "3.0.0"),
        );
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "no time field → 0 findings (skip silently); got: {findings:#?}"
        );
    }

    #[test]
    fn no_lock_file_emits_zero() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        write(dir.path(), "package.json", r#"{"name":"my-app"}"#);
        // No package-lock.json
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "no lock file → 0 findings; got: {findings:#?}"
        );
    }

    #[test]
    fn lockfile_v1_skipped_silently() {
        crate::manifest::reset_for_tests();
        let dir = TempDir::new().expect("tempdir");
        let time_str = months_ago_str(20);
        write(dir.path(), "package.json", r#"{"name":"my-app"}"#);
        // v1 lock file — different schema; must be silently skipped.
        write(
            dir.path(),
            "package-lock.json",
            &format!(
                r#"{{"lockfileVersion": 1, "dependencies": {{"old-dep": {{"version": "1.0.0", "time": "{time_str}"}}}}}}"#
            ),
        );
        let findings = run(dir.path());
        assert!(
            findings.is_empty(),
            "v1 lock file must be skipped; got: {findings:#?}"
        );
    }

    #[test]
    fn exactly_stale_threshold_emits_finding() {
        // A dep published just past the staleness boundary must be flagged.
        let now = SystemTime::now();
        let published = now
            .checked_sub(Duration::from_secs(STALE_SECS + 1))
            .expect("time arithmetic");
        let total_secs = published
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("positive epoch")
            .as_secs();
        let time_str = secs_to_iso8601(total_secs);

        let root = PathBuf::from("/tmp/chain004-test");
        let lock = serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/borderline-dep": {
                    "version": "1.0.0",
                    "time": time_str
                }
            }
        });
        let findings = evaluate(&root, &lock, now);
        assert_eq!(
            findings.len(),
            1,
            "dep just past stale threshold must flag; got: {findings:#?}"
        );
    }

    // ── parse_rfc3339_approx unit tests ───────────────────────────────────────

    #[test]
    fn parse_valid_timestamp() {
        let result = parse_rfc3339_approx("2020-01-15T12:30:00Z");
        assert!(result.is_some(), "valid timestamp must parse");
    }

    #[test]
    fn parse_invalid_timestamp_returns_none() {
        assert!(parse_rfc3339_approx("not-a-date").is_none());
        assert!(parse_rfc3339_approx("").is_none());
    }
}
