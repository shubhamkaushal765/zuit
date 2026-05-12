//! [`Config`]: the project-level configuration loaded from `zuit.toml`.
//!
//! All fields have sensible defaults so a project with no `zuit.toml` gets
//! reasonable behaviour out of the box.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::analyzer::Severity;
use crate::error::ConfigError;

/// Parses a per-rule severity override string.
///
/// Returns:
/// - `Ok(None)` for `"ignore"` (meaning suppress the finding).
/// - `Ok(Some(sev))` for a valid severity string (`"info"`, `"low"`, etc.).
/// - `Err(s)` when `s` is neither `"ignore"` nor a known severity.
///
/// # Errors
///
/// Returns `Err(String)` with a human-readable message if `s` is not a
/// recognised severity name or `"ignore"`.
pub fn parse_override_severity(s: &str) -> Result<Option<Severity>, String> {
    match s {
        "ignore" => Ok(None),
        "info" => Ok(Some(Severity::Info)),
        "low" => Ok(Some(Severity::Low)),
        "medium" => Ok(Some(Severity::Medium)),
        "high" => Ok(Some(Severity::High)),
        "critical" => Ok(Some(Severity::Critical)),
        other => Err(format!(
            "unknown severity '{other}'; expected one of: ignore, info, low, medium, high, critical"
        )),
    }
}

/// Project-level configuration parsed from `zuit.toml`.
///
/// All fields are optional in the file; missing keys fall back to defaults
/// implemented via [`Default`].
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// General project settings.
    pub general: GeneralConfig,

    /// Per-dimension settings, keyed by the lowercase dimension name
    /// (e.g. `"maintainability"`, `"security"`).
    pub dimensions: HashMap<String, DimensionConfig>,

    /// Per-rule overrides, keyed by the rule ID (e.g. `"MAINT001-cyclomatic"`).
    pub rules: HashMap<String, RuleConfig>,

    /// Scan-history persistence settings.
    pub history: HistoryConfig,
}

impl Config {
    /// Loads configuration from the given TOML file path.
    ///
    /// Returns [`Config::default()`] plus the values specified in the file.
    /// Fields not present in the file retain their default values.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] if the file cannot be read, or
    /// [`ConfigError::Parse`] if the TOML is syntactically invalid.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        Self::from_toml_str(&text)
    }

    /// Parses configuration from a TOML string.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Parse`] if the TOML is syntactically invalid or
    /// has unknown fields, or [`ConfigError::Validation`] if values are out of
    /// range.
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        let cfg: Self = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validates the parsed configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] for any of:
    /// - `rules.<id>.threshold == 0`
    /// - `rules.<id>.severity` is not a valid severity or `"ignore"`
    /// - any value in `rules.<id>.overrides` is not a valid severity or `"ignore"`
    /// - `history.max_scans_per_project == 0`
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate history section.
        if self.history.max_scans_per_project == 0 {
            return Err(ConfigError::Validation(
                "history.max_scans_per_project must be > 0".to_string(),
            ));
        }

        // Validate per-rule overrides.
        for (rule_id, rule) in &self.rules {
            if rule.threshold == Some(0) {
                return Err(ConfigError::Validation(format!(
                    "rules.{rule_id}.threshold must be > 0"
                )));
            }
            if let Some(sev) = &rule.severity {
                parse_override_severity(sev).map_err(|e| {
                    ConfigError::Validation(format!("rules.{rule_id}.severity: {e}"))
                })?;
            }
            if let Some(overrides) = &rule.overrides {
                for (glob, sev_str) in overrides {
                    parse_override_severity(sev_str).map_err(|e| {
                        ConfigError::Validation(format!(
                            "rules.{rule_id}.overrides[\"{glob}\"]: {e}"
                        ))
                    })?;
                }
            }
        }

        Ok(())
    }

    /// Returns the effective threshold for the named rule, or the given
    /// `default` if the rule has no configured threshold.
    #[must_use]
    pub fn rule_threshold(&self, rule_id: &str, default: u32) -> u32 {
        self.rules
            .get(rule_id)
            .and_then(|r| r.threshold)
            .unwrap_or(default)
    }

    /// Returns `true` if the named rule is enabled (defaults to `true`).
    #[must_use]
    pub fn rule_enabled(&self, rule_id: &str) -> bool {
        self.rules
            .get(rule_id)
            .and_then(|r| r.enabled)
            .unwrap_or(true)
    }

    /// Returns the per-glob overrides map for the named rule, or `None`.
    #[must_use]
    pub fn rule_overrides(&self, rule_id: &str) -> Option<&BTreeMap<String, String>> {
        self.rules.get(rule_id).and_then(|r| r.overrides.as_ref())
    }

    /// Returns the global severity override string for the named rule, or `None`.
    #[must_use]
    pub fn rule_severity(&self, rule_id: &str) -> Option<&str> {
        self.rules.get(rule_id).and_then(|r| r.severity.as_deref())
    }

    /// Returns `true` if the named dimension is enabled (defaults to `true`).
    #[must_use]
    pub fn dimension_enabled(&self, dimension: &str) -> bool {
        self.dimensions
            .get(dimension)
            .and_then(|d| d.enabled)
            .unwrap_or(true)
    }
}

/// General project-level settings.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeneralConfig {
    /// Restrict analysis to these language identifiers. Empty means all languages.
    pub languages: Vec<String>,

    /// Glob patterns for paths to exclude from analysis.
    pub exclude: Vec<String>,

    /// Whether to follow symbolic links during file walking.
    pub follow_symlinks: bool,
}

/// Per-dimension configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct DimensionConfig {
    /// Whether this dimension is included in analysis.
    pub enabled: Option<bool>,

    /// Weight multiplier used when aggregating a project-level score.
    pub weight: Option<f32>,
}

/// `[history]` section: controls scan-history persistence under `~/.zuit/`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HistoryConfig {
    /// When true, every successful `zuit analyze` writes a snapshot to
    /// `~/.zuit/projects/<hash>/scans/`. Default: `true`.
    pub auto_save: bool,
    /// Maximum scans retained per project. Older scans are pruned on write.
    /// Default: `100`.
    pub max_scans_per_project: u32,
    /// When true, `zuit analyze` uses the incremental file-hash cache to
    /// skip re-parsing files whose content has not changed.  Default: `true`.
    ///
    /// Note: the cache is keyed on file content hash only.  Changing
    /// `zuit.toml` does **not** invalidate cached results — callers must
    /// delete the `.zuit-cache/` directory manually after config changes
    /// that should affect per-file analysis.
    pub cache: bool,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            auto_save: true,
            max_scans_per_project: 100,
            cache: true,
        }
    }
}

/// Per-rule override configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RuleConfig {
    /// Whether this rule is enabled.
    pub enabled: Option<bool>,

    /// Rule-specific threshold (e.g. cyclomatic complexity limit).
    pub threshold: Option<u32>,

    /// Override the rule's default severity.
    pub severity: Option<String>,

    /// Per-glob path overrides: key is a glob pattern, value is `"ignore"` or
    /// a severity string (`"info"`, `"low"`, `"medium"`, `"high"`, `"critical"`).
    /// First matching glob wins.
    pub overrides: Option<BTreeMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    #[test]
    fn default_config_has_no_exclusions() {
        let cfg = Config::default();
        assert!(cfg.general.exclude.is_empty());
        assert!(!cfg.general.follow_symlinks);
    }

    #[test]
    fn load_happy_path() {
        let toml = r#"
[general]
languages = ["rust", "python"]
follow_symlinks = false

[dimensions.maintainability]
enabled = true
weight  = 1.0

[rules.MAINT001-cyclomatic]
enabled   = true
threshold = 10
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        assert_eq!(cfg.general.languages, vec!["rust", "python"]);
        assert!(!cfg.general.follow_symlinks);
        assert!(cfg.dimension_enabled("maintainability"));
        assert_eq!(cfg.rule_threshold("MAINT001-cyclomatic", 99), 10);
        assert!(cfg.rule_enabled("MAINT001-cyclomatic"));
    }

    #[test]
    fn load_from_file_happy_path() {
        let toml = "[general]\nfollow_symlinks = true\n";
        let mut tmp = NamedTempFile::new().unwrap();
        write!(tmp, "{toml}").unwrap();
        let cfg = Config::load(tmp.path()).unwrap();
        assert!(cfg.general.follow_symlinks);
    }

    #[test]
    fn malformed_toml_returns_parse_error() {
        let bad = "[[[[not valid toml";
        let err = Config::from_toml_str(bad).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn missing_file_returns_io_error() {
        let err = Config::load(Path::new("/nonexistent/zuit.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Io(_)));
    }

    #[test]
    fn rule_threshold_falls_back_to_default() {
        let cfg = Config::default();
        assert_eq!(cfg.rule_threshold("MAINT001-cyclomatic", 10), 10);
    }

    #[test]
    fn rule_enabled_defaults_true() {
        let cfg = Config::default();
        assert!(cfg.rule_enabled("ANYTHING"));
    }

    #[test]
    fn dimension_enabled_defaults_true() {
        let cfg = Config::default();
        assert!(cfg.dimension_enabled("security"));
    }

    #[test]
    fn history_config_defaults_when_section_absent() {
        let cfg: Config = Config::from_toml_str("").expect("empty toml parses");
        assert!(cfg.history.auto_save, "auto_save default = true");
        assert_eq!(cfg.history.max_scans_per_project, 100);
    }

    #[test]
    fn history_config_partial_override() {
        let cfg: Config = Config::from_toml_str(
            r"[history]
auto_save = false
",
        )
        .expect("partial history section parses");
        assert!(!cfg.history.auto_save);
        assert_eq!(cfg.history.max_scans_per_project, 100); // default
    }

    #[test]
    fn history_config_full_override() {
        let cfg: Config = Config::from_toml_str(
            r"[history]
auto_save = true
max_scans_per_project = 5
",
        )
        .expect("full history section parses");
        assert!(cfg.history.auto_save);
        assert_eq!(cfg.history.max_scans_per_project, 5);
    }

    #[test]
    fn history_config_rejects_unknown_field() {
        let err = Config::from_toml_str(
            r"[history]
not_a_field = 1
",
        )
        .unwrap_err();
        let s = format!("{err:#}");
        assert!(
            s.contains("not_a_field"),
            "error mentions the bad field: {s}"
        );
    }

    // ---- Feature 1: per-glob overrides round-trip ----------------------------

    #[test]
    fn rule_overrides_round_trips_in_toml() {
        let toml = r#"
[rules.SEC003]
overrides = { "tests/**" = "ignore", "fixtures/**" = "low" }
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        let overrides = cfg.rule_overrides("SEC003").expect("overrides present");
        assert_eq!(
            overrides.get("tests/**").map(String::as_str),
            Some("ignore")
        );
        assert_eq!(
            overrides.get("fixtures/**").map(String::as_str),
            Some("low")
        );
    }

    // ---- Feature 2: config schema validation ---------------------------------

    #[test]
    fn unknown_top_level_key_errors() {
        let err = Config::from_toml_str("[unknown_section]\nfoo = 1\n").unwrap_err();
        assert!(
            matches!(err, ConfigError::Parse(_)),
            "expected Parse error, got: {err:?}"
        );
    }

    #[test]
    fn unknown_rule_field_errors() {
        let err = Config::from_toml_str("[rules.SEC001]\nunknwn = true\n").unwrap_err();
        assert!(
            matches!(err, ConfigError::Parse(_)),
            "expected Parse error, got: {err:?}"
        );
    }

    #[test]
    fn zero_threshold_errors() {
        let err = Config::from_toml_str("[rules.MAINT001]\nthreshold = 0\n").unwrap_err();
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got: {err:?}"
        );
        let s = format!("{err}");
        assert!(s.contains("threshold"), "error mentions threshold: {s}");
    }

    #[test]
    fn bad_severity_string_errors() {
        let err = Config::from_toml_str(
            r#"[rules.SEC001]
severity = "BLOCKER"
"#,
        )
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got: {err:?}"
        );
    }

    #[test]
    fn valid_config_passes() {
        let toml = r#"
[general]
languages = ["rust"]
follow_symlinks = false

[rules.SEC001]
enabled = true
threshold = 5
severity = "high"
overrides = { "tests/**" = "ignore", "src/**" = "low" }

[history]
auto_save = true
max_scans_per_project = 50
"#;
        Config::from_toml_str(toml).expect("valid config should parse");
    }

    #[test]
    fn bad_override_severity_errors() {
        let err = Config::from_toml_str(
            r#"[rules.SEC001]
overrides = { "tests/**" = "BOGUS" }
"#,
        )
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::Validation(_)),
            "expected Validation error, got: {err:?}"
        );
    }
}
