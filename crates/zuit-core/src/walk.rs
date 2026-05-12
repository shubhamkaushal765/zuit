//! [`walk_files`]: `.gitignore`-aware file discovery using the [`ignore`] crate.
//!
//! Files are returned in **lexicographic path order** so that downstream parallel
//! processing (via `rayon`) produces deterministic results regardless of
//! filesystem traversal order.

use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::error::EngineError;

/// Walks `root` recursively and returns all files whose extension is in
/// `extensions`, sorted lexicographically.
///
/// - Respects `.gitignore` and `.ignore` files via the [`ignore`] crate.
/// - Skips hidden directories and files (names starting with `.`) by default.
/// - Honours `config.general.follow_symlinks`.
/// - Applies `config.general.exclude` glob patterns (via [`ignore::overrides`]).
///
/// # Errors
///
/// Returns [`EngineError::Io`] if the root path does not exist or cannot be
/// read.
pub fn walk_files(
    root: &Path,
    extensions: &[&str],
    config: &Config,
) -> Result<Vec<PathBuf>, EngineError> {
    let mut overrides = ignore::overrides::OverrideBuilder::new(root);
    for pattern in &config.general.exclude {
        // `!` prefix means "exclude this pattern"
        overrides
            .add(&format!("!{pattern}"))
            .map_err(|e| EngineError::Io(std::io::Error::other(e.to_string())))?;
    }
    let overrides = overrides
        .build()
        .map_err(|e| EngineError::Io(std::io::Error::other(e.to_string())))?;

    let walker = ignore::WalkBuilder::new(root)
        .follow_links(config.general.follow_symlinks)
        .overrides(overrides)
        .build();

    let mut paths = Vec::new();
    for entry in walker {
        let entry = entry.map_err(|e| EngineError::Io(std::io::Error::other(e.to_string())))?;
        let path = entry.path().to_path_buf();
        if !path.is_file() {
            continue;
        }
        if let Some(ext) = path.extension().and_then(|e| e.to_str())
            && extensions.contains(&ext)
        {
            paths.push(path);
        }
    }

    paths.sort();
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write(dir: &Path, rel: &str, content: &str) {
        let full = dir.join(rel);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full, content).unwrap();
    }

    #[test]
    fn returns_sorted_paths() {
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "b.rs", "");
        write(tmp.path(), "a.rs", "");
        write(tmp.path(), "c.rs", "");

        let cfg = Config::default();
        let files = walk_files(tmp.path(), &["rs"], &cfg).unwrap();
        let names: Vec<_> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, vec!["a.rs", "b.rs", "c.rs"]);
    }

    #[test]
    fn filters_by_extension() {
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "main.rs", "");
        write(tmp.path(), "main.py", "");
        write(tmp.path(), "README.md", "");

        let cfg = Config::default();
        let files = walk_files(tmp.path(), &["rs"], &cfg).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].to_str().unwrap().ends_with("main.rs"));
    }

    #[test]
    fn honours_gitignore() {
        // Create an isolated temp directory that is its own git root so the
        // `ignore` crate uses the `.gitignore` we place there.
        let tmp = TempDir::new().unwrap();
        // Initialise a real git repo so `ignore` recognises the root.
        std::process::Command::new("git")
            .args(["init", "-q", tmp.path().to_str().unwrap()])
            .status()
            .unwrap();

        write(tmp.path(), ".gitignore", "target/\n");
        write(tmp.path(), "src/lib.rs", "");
        write(tmp.path(), "target/debug/build.rs", "");

        let cfg = Config::default();
        let files = walk_files(tmp.path(), &["rs"], &cfg).unwrap();
        // Only src/lib.rs should be included; target/ is gitignored
        let paths: Vec<_> = files.iter().map(|p| p.to_str().unwrap()).collect();
        assert_eq!(files.len(), 1, "expected 1 file, got: {paths:?}");
        let name = files[0].to_str().unwrap();
        assert!(name.contains("lib.rs"), "unexpected file: {name}");
    }

    #[test]
    fn excludes_via_config_pattern() {
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "src/lib.rs", "");
        write(tmp.path(), "vendor/dep/mod.rs", "");

        let mut cfg = Config::default();
        cfg.general.exclude.push("vendor/**".to_string());

        let files = walk_files(tmp.path(), &["rs"], &cfg).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].to_str().unwrap().contains("lib.rs"));
    }
}
