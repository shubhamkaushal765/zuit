//! Plugin manifest type (`zuit-plugin.toml`) with parsing and validation.
//!
//! The manifest describes a third-party analyzer plugin: its identity, the command
//! zuit should invoke, and constraints such as timeout and output size limits.

use serde::{Deserialize, Serialize};

use crate::PluginError;

// ---------------------------------------------------------------------------
// Output format
// ---------------------------------------------------------------------------

/// The structured output format produced by the plugin's subprocess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputFormat {
    /// The plugin emits zuit-native JSON findings.
    ZuitJson,
    /// The plugin emits SARIF 2.1 output.
    Sarif,
}

// ---------------------------------------------------------------------------
// Raw deserialization helper (before validation)
// ---------------------------------------------------------------------------

/// Intermediate struct used for TOML deserialization before validation.
/// Fields that have defaults are marked with `#[serde(default)]`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    name: Option<String>,
    version: String,
    output: OutputFormat,
    command: Vec<String>,

    #[serde(default)]
    description: Option<String>,

    /// Raw prefix from TOML; empty string means "use default (`<name>/`)".
    #[serde(default)]
    rule_id_prefix: String,

    #[serde(default)]
    extensions: Vec<String>,

    #[serde(default = "default_timeout")]
    timeout_seconds: u64,

    #[serde(default = "default_max_output")]
    max_output_bytes: u64,

    #[serde(default)]
    license: Option<String>,

    #[serde(default)]
    homepage: Option<String>,
}

fn default_timeout() -> u64 {
    60
}

fn default_max_output() -> u64 {
    32 * 1024 * 1024
}

// ---------------------------------------------------------------------------
// Public manifest type
// ---------------------------------------------------------------------------

/// A fully-validated plugin manifest deserialized from `zuit-plugin.toml`.
///
/// Construct one via [`PluginManifest::load_from_str`]; direct construction is
/// intentionally unavailable to ensure all invariants are enforced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginManifest {
    /// Unique plugin name used as the install-directory name.
    ///
    /// Must match `^[a-z0-9][a-z0-9-]{0,63}$`.
    pub name: String,

    /// Plugin version string (free-form, not validated beyond being non-empty).
    pub version: String,

    /// Structured output format the plugin subprocess emits.
    pub output: OutputFormat,

    /// Subprocess argv. `argv[0]` is the executable; zuit appends
    /// its own arguments when invoking the plugin.
    pub command: Vec<String>,

    /// Human-readable description of the plugin (optional).
    pub description: Option<String>,

    /// Prefix prepended to every rule ID the plugin reports.
    ///
    /// Defaults to `"<name>/"` when omitted from the manifest.
    pub rule_id_prefix: String,

    /// File extensions this plugin is relevant for (informational only;
    /// zuit does not gate execution on this list).
    pub extensions: Vec<String>,

    /// Maximum wall-clock seconds to wait for the plugin subprocess.
    ///
    /// Must be > 0. Defaults to `60`.
    pub timeout_seconds: u64,

    /// Maximum byte length of subprocess stdout that zuit will read.
    ///
    /// Must be > 0. Defaults to `32 MiB` (33 554 432 bytes).
    pub max_output_bytes: u64,

    /// SPDX license identifier (optional, informational).
    pub license: Option<String>,

    /// Plugin homepage URL (optional, informational).
    pub homepage: Option<String>,
}

/// Validates that `name` matches `^[a-z0-9][a-z0-9-]{0,63}$`.
fn validate_name(name: &str) -> bool {
    // Must be 1-64 chars total.
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !matches!(first, 'a'..='z' | '0'..='9') {
        return false;
    }
    chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-'))
}

impl PluginManifest {
    /// Parse and validate a manifest from a TOML string.
    ///
    /// `default_name` is used when the manifest does not include a `name` field
    /// (e.g. when the caller derives the name from the install-directory). If
    /// `default_name` is `None` and the manifest also omits `name`, a
    /// [`PluginError::Manifest`] error is returned.
    ///
    /// When both `default_name` and the manifest's own `name` field are present,
    /// **the manifest's `name` takes precedence**.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::Toml`] if `s` is not valid TOML or contains unknown fields.
    /// Returns [`PluginError::Manifest`] if any of the following validation rules fail:
    ///
    /// - `name` is absent from both the manifest and `default_name`.
    /// - `name` does not match `^[a-z0-9][a-z0-9-]{0,63}$`.
    /// - `command` is empty.
    /// - `timeout_seconds` is `0`.
    /// - `max_output_bytes` is `0`.
    pub fn load_from_str(s: &str, default_name: Option<&str>) -> Result<Self, PluginError> {
        let raw: RawManifest = toml::from_str(s)?;

        // Resolve name: manifest wins over default_name.
        let name = match raw.name {
            Some(n) => n,
            None => match default_name {
                Some(n) => n.to_owned(),
                None => {
                    return Err(PluginError::Manifest(
                        "manifest is missing the required `name` field".to_owned(),
                    ));
                }
            },
        };

        // Validate name.
        if !validate_name(&name) {
            return Err(PluginError::Manifest(format!(
                "invalid plugin name {name:?}: must match ^[a-z0-9][a-z0-9-]{{0,63}}$"
            )));
        }

        // command must be non-empty.
        if raw.command.is_empty() {
            return Err(PluginError::Manifest(
                "`command` must have at least one element".to_owned(),
            ));
        }

        // timeout_seconds must be > 0.
        if raw.timeout_seconds == 0 {
            return Err(PluginError::Manifest(
                "`timeout_seconds` must be greater than 0".to_owned(),
            ));
        }

        // max_output_bytes must be > 0.
        if raw.max_output_bytes == 0 {
            return Err(PluginError::Manifest(
                "`max_output_bytes` must be greater than 0".to_owned(),
            ));
        }

        // Compute rule_id_prefix default.
        let rule_id_prefix = if raw.rule_id_prefix.is_empty() {
            format!("{name}/")
        } else {
            raw.rule_id_prefix
        };

        Ok(PluginManifest {
            name,
            version: raw.version,
            output: raw.output,
            command: raw.command,
            description: raw.description,
            rule_id_prefix,
            extensions: raw.extensions,
            timeout_seconds: raw.timeout_seconds,
            max_output_bytes: raw.max_output_bytes,
            license: raw.license,
            homepage: raw.homepage,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal manifest: only the four required fields. All optional fields
    /// should receive their documented defaults.
    #[test]
    fn parse_minimal_ok() {
        let toml = r#"
            name    = "acme-zig"
            version = "0.3.1"
            output  = "zuit-json"
            command = ["./bin/check"]
        "#;
        let m = PluginManifest::load_from_str(toml, None).expect("valid minimal manifest");
        assert_eq!(m.name, "acme-zig");
        assert_eq!(m.version, "0.3.1");
        assert_eq!(m.output, OutputFormat::ZuitJson);
        assert_eq!(m.command, vec!["./bin/check"]);
        // Defaults
        assert_eq!(m.timeout_seconds, 60);
        assert_eq!(m.max_output_bytes, 32 * 1024 * 1024);
        assert_eq!(m.rule_id_prefix, "acme-zig/");
        assert!(m.description.is_none());
        assert!(m.extensions.is_empty());
        assert!(m.license.is_none());
        assert!(m.homepage.is_none());
    }

    /// Full manifest: every field set. Round-trip equality via `load_from_str`.
    #[test]
    fn parse_full_ok() {
        let toml = r#"
            name             = "acme-zig"
            version          = "0.3.1"
            output           = "sarif"
            command          = ["./bin/check", "--fast"]
            description      = "Zig static analysis suite"
            rule_id_prefix   = "ZIG/"
            extensions       = ["zig", "zon"]
            timeout_seconds  = 120
            max_output_bytes = 16777216
            license          = "MIT"
            homepage         = "https://github.com/acme/zuit-zig"
        "#;
        let m = PluginManifest::load_from_str(toml, None).expect("valid full manifest");
        assert_eq!(m.name, "acme-zig");
        assert_eq!(m.version, "0.3.1");
        assert_eq!(m.output, OutputFormat::Sarif);
        assert_eq!(m.command, vec!["./bin/check", "--fast"]);
        assert_eq!(m.description.as_deref(), Some("Zig static analysis suite"));
        assert_eq!(m.rule_id_prefix, "ZIG/");
        assert_eq!(m.extensions, vec!["zig", "zon"]);
        assert_eq!(m.timeout_seconds, 120);
        assert_eq!(m.max_output_bytes, 16_777_216);
        assert_eq!(m.license.as_deref(), Some("MIT"));
        assert_eq!(
            m.homepage.as_deref(),
            Some("https://github.com/acme/zuit-zig")
        );
    }

    /// Names that should be rejected: capital letters, leading hyphen, > 64 chars.
    #[test]
    fn reject_invalid_name() {
        let cases: &[&str] = &[
            "AcmeZig",             // capital letters
            "-starts-with-hyphen", // leading hyphen
            &"a".repeat(65),       // > 64 chars
            "has_underscore",      // underscore not allowed
            "",                    // empty
        ];

        for bad_name in cases {
            // Build TOML inline (avoid multi-line to keep the test simple).
            let toml = format!(
                "name = \"{bad_name}\"\nversion = \"1.0\"\noutput = \"zuit-json\"\ncommand = [\"x\"]\n"
            );
            let result = PluginManifest::load_from_str(&toml, None);
            assert!(
                result.is_err(),
                "expected error for name {bad_name:?}, got Ok"
            );
        }
    }

    /// `output` values that are not in the enum must fail deserialization.
    #[test]
    fn reject_unknown_output_format() {
        let toml = r#"
            name    = "myplugin"
            version = "1.0"
            output  = "yaml"
            command = ["x"]
        "#;
        let result = PluginManifest::load_from_str(toml, None);
        assert!(
            result.is_err(),
            "expected error for unknown output format, got Ok"
        );
    }

    /// `command = []` (empty array) must be rejected.
    #[test]
    fn reject_empty_command() {
        let toml = r#"
            name    = "myplugin"
            version = "1.0"
            output  = "zuit-json"
            command = []
        "#;
        let result = PluginManifest::load_from_str(toml, None);
        assert!(
            matches!(result, Err(PluginError::Manifest(_))),
            "expected Manifest error for empty command, got {result:?}"
        );
    }

    /// `timeout_seconds = 0` must be rejected.
    #[test]
    fn reject_zero_timeout() {
        let toml = r#"
            name             = "myplugin"
            version          = "1.0"
            output           = "zuit-json"
            command          = ["x"]
            timeout_seconds  = 0
        "#;
        let result = PluginManifest::load_from_str(toml, None);
        assert!(
            matches!(result, Err(PluginError::Manifest(_))),
            "expected Manifest error for zero timeout, got {result:?}"
        );
    }

    /// When `rule_id_prefix` is omitted, it defaults to `"<name>/"`.
    #[test]
    fn default_rule_id_prefix_uses_name() {
        let toml = r#"
            name    = "my-plugin"
            version = "1.0"
            output  = "zuit-json"
            command = ["x"]
        "#;
        let m = PluginManifest::load_from_str(toml, None).expect("valid manifest");
        assert_eq!(m.rule_id_prefix, "my-plugin/");
    }
}
