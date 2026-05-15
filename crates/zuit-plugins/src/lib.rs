#![warn(missing_docs)]

//! Subprocess-based third-party analyzer plugins for zuit.
//!
//! This crate provides infrastructure for loading and running external analyzer plugins
//! as subprocesses. Plugins communicate with zuit via JSON-RPC and can be installed
//! from Git repositories or local paths.

pub mod analyzer;
pub mod error;
pub mod install;
pub mod manifest;
pub mod parse_sarif;
pub mod parse_zuit;
pub mod remove;
pub mod store;
pub mod update;

pub use analyzer::PluginAnalyzer;
pub use error::PluginError;
pub use install::{
    install_git, install_git_in, install_local, install_local_in, looks_like_git_url,
};
pub use manifest::{OutputFormat, PluginManifest};
pub use parse_sarif::parse_sarif;
pub use parse_zuit::parse_ndjson;
pub use remove::remove;
pub use store::{InstalledPlugin, PluginSource, list_installed, list_installed_in, plugins_dir};
pub use update::update;

use std::path::Path;
use zuit_core::Analyzer;

/// Discovers all installed user plugins and returns a vector of [`Analyzer`] trait objects.
///
/// This function:
/// 1. Calls [`store::list_installed()`] to enumerate installed plugins.
/// 2. For each plugin, constructs a [`PluginAnalyzer`] from the manifest and plugin directory.
/// 3. Returns a vector of boxed analyzers.
///
/// Infallible at the surface: errors from environment-variable resolution and from
/// individual broken plugin directories are logged via `tracing::warn!` and skipped.
pub fn discover_user_plugins() -> Vec<Box<dyn Analyzer>> {
    match store::plugins_dir() {
        Ok(dir) => discover_user_plugins_in(&dir),
        Err(err) => {
            tracing::warn!(
                "zuit-plugins: cannot resolve plugins directory: {err}; no plugins will be loaded"
            );
            Vec::new()
        }
    }
}

/// Inner implementation of [`discover_user_plugins`] over an arbitrary directory.
///
/// This allows tests and downstream crates (e.g. `zuit-registry`) to pass a temporary
/// directory without mutating process environment. This is exposed as part of the public API
/// for test usage and custom registry construction.
///
/// Any errors reading the directory or individual plugin manifests are logged as warnings
/// and the broken entries are skipped.
pub fn discover_user_plugins_in(dir: &Path) -> Vec<Box<dyn Analyzer>> {
    let installed = match store::list_installed_in(dir) {
        Ok(plugins) => plugins,
        Err(err) => {
            tracing::warn!(
                "zuit-plugins: cannot read plugins directory: {err}; no plugins will be loaded"
            );
            return Vec::new();
        }
    };
    installed
        .into_iter()
        .map(|plugin| {
            let analyzer: Box<dyn Analyzer> =
                Box::new(PluginAnalyzer::new(plugin.manifest, plugin.plugin_dir));
            analyzer
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn discover_returns_one_per_installed_plugin() {
        let tmp = TempDir::new().unwrap();
        let plugins_root = tmp.path().join("plugins");
        fs::create_dir_all(&plugins_root).unwrap();

        // Create a valid plugin directory
        let plugin_path = plugins_root.join("echo");
        fs::create_dir_all(&plugin_path).unwrap();

        // Write manifest
        let manifest_toml = "name = \"echo\"\nversion = \"0.1.0\"\noutput = \"zuit-json\"\ncommand = [\"./run.sh\"]\n";
        fs::write(plugin_path.join("zuit-plugin.toml"), manifest_toml).unwrap();

        // Write source sidecar (sibling of the plugin dir, inside plugins_root)
        let source = store::PluginSource::Path {
            target: std::path::PathBuf::from("/tmp/fake-plugin"),
        };
        store::write_source_sidecar(&plugins_root, "echo", &source).unwrap();

        // Discover plugins
        let result = discover_user_plugins_in(&plugins_root);
        assert_eq!(result.len(), 1, "expected exactly one analyzer");
    }

    #[test]
    fn discover_skips_broken_manifests() {
        let tmp = TempDir::new().unwrap();
        let plugins_root = tmp.path().join("plugins");
        fs::create_dir_all(&plugins_root).unwrap();

        // Create a valid plugin
        let good_plugin_path = plugins_root.join("good-plugin");
        fs::create_dir_all(&good_plugin_path).unwrap();
        let manifest_toml = "name = \"good-plugin\"\nversion = \"0.1.0\"\noutput = \"zuit-json\"\ncommand = [\"./run.sh\"]\n";
        fs::write(good_plugin_path.join("zuit-plugin.toml"), manifest_toml).unwrap();
        let source = store::PluginSource::Path {
            target: std::path::PathBuf::from("/tmp/good-plugin"),
        };
        store::write_source_sidecar(&plugins_root, "good-plugin", &source).unwrap();

        // Create a broken plugin with malformed TOML
        let bad_plugin_path = plugins_root.join("broken-plugin");
        fs::create_dir_all(&bad_plugin_path).unwrap();
        let bad_toml = "not valid toml = =";
        fs::write(bad_plugin_path.join("zuit-plugin.toml"), bad_toml).unwrap();
        let source = store::PluginSource::Path {
            target: std::path::PathBuf::from("/tmp/broken-plugin"),
        };
        store::write_source_sidecar(&plugins_root, "broken-plugin", &source).unwrap();

        // Discover plugins - should skip the broken one
        let result = discover_user_plugins_in(&plugins_root);
        assert_eq!(
            result.len(),
            1,
            "expected exactly one analyzer (broken plugin skipped)"
        );
    }
}
