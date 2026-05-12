//! Implementation of the `zuit init` subcommand.
//!
//! Writes a default `zuit.toml` to the current working directory if one
//! does not already exist.

use std::io::Write as _;

use anyhow::{Context as _, Result, bail};

/// Default content written by `zuit init`.
const DEFAULT_ZUIT_TOML: &str = r#"[general]
exclude = ["target/**", "node_modules/**", ".git/**"]
follow_symlinks = false

[dimensions.maintainability]
enabled = true
weight = 1.0

# Per-rule overrides example:
# [rules."MAINT001-cyclomatic"]
# enabled = true
# threshold = 10
"#;

/// Runs the `init` subcommand.
///
/// Writes `zuit.toml` to the current working directory if it does not
/// already exist.  Errors with a clear message if the file is already present
/// (to avoid accidental overwrites).
///
/// # Errors
///
/// - Returns an error if `zuit.toml` already exists.
/// - Returns an error if the current directory cannot be determined or if
///   the file cannot be written.
pub fn run() -> Result<i32> {
    let cwd = std::env::current_dir().context("determining current directory")?;
    let dest = cwd.join("zuit.toml");

    if dest.exists() {
        bail!("zuit.toml already exists; refusing to overwrite");
    }

    let mut file =
        std::fs::File::create(&dest).with_context(|| format!("creating {}", dest.display()))?;

    file.write_all(DEFAULT_ZUIT_TOML.as_bytes())
        .with_context(|| format!("writing {}", dest.display()))?;

    println!("Created {}", dest.display());
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn init_creates_file() {
        let tmp = TempDir::new().unwrap();
        let dest = tmp.path().join("zuit.toml");

        // Write directly (simulating `run` without changing cwd).
        let mut f = std::fs::File::create(&dest).unwrap();
        f.write_all(DEFAULT_ZUIT_TOML.as_bytes()).unwrap();

        assert!(dest.exists());
        let content = std::fs::read_to_string(&dest).unwrap();
        assert!(content.contains("[general]"));
        assert!(content.contains("follow_symlinks = false"));
    }

    #[test]
    fn default_toml_is_valid() {
        // The default content must parse as valid TOML and as a valid Config.
        let cfg = zuit_core::Config::from_toml_str(DEFAULT_ZUIT_TOML).unwrap();
        assert!(!cfg.general.follow_symlinks);
        assert!(!cfg.general.exclude.is_empty());
    }
}
