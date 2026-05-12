//! Project-root resolution: find the nearest ancestor containing `zuit.toml`.
//!
//! This is identical to the implementation in `zuit-show`, which will be
//! deleted by the orchestrator after the CLI is wired to this module.

use std::path::{Path, PathBuf};

/// Resolve the project root for an analyze invocation.
///
/// Rules (in order):
/// 1. If `config_flag` is `Some`, the caller supplied an explicit config path,
///    so we use the canonicalised `args_path` directly without walking ancestors.
/// 2. Otherwise walk up the directory tree from `args_path` looking for a
///    `zuit.toml` file.  Return the first directory that contains one.
/// 3. If no `zuit.toml` is found anywhere in the ancestor chain, fall back
///    to the canonicalised `args_path`.
///
/// Canonicalization uses [`Path::canonicalize`], falling back to the original
/// path when the path does not exist on disk.
#[must_use]
pub fn project_root(args_path: &Path, config_flag: Option<&Path>) -> PathBuf {
    let canonical = args_path
        .canonicalize()
        .unwrap_or_else(|_| args_path.to_path_buf());
    if config_flag.is_some() {
        return canonical;
    }
    let mut dir: &Path = canonical.as_path();
    loop {
        if dir.join("zuit.toml").exists() {
            return dir.to_path_buf();
        }
        match dir.parent() {
            Some(p) => dir = p,
            None => return canonical,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn no_toml_returns_args_path_canonical() {
        let tmp = TempDir::new().unwrap();
        let sub = tmp.path().join("a/b");
        std::fs::create_dir_all(&sub).unwrap();
        let got = project_root(&sub, None);
        assert_eq!(got, sub.canonicalize().unwrap());
    }

    #[test]
    fn finds_toml_in_ancestor() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::write(root.join("zuit.toml"), b"").unwrap();
        let sub = root.join("a/b");
        std::fs::create_dir_all(&sub).unwrap();
        let got = project_root(&sub, None);
        assert_eq!(got, root);
    }

    #[test]
    fn explicit_config_skips_walk() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::write(root.join("zuit.toml"), b"").unwrap();
        let sub = root.join("a/b");
        std::fs::create_dir_all(&sub).unwrap();
        let cfg_path = root.join("other.toml");
        std::fs::write(&cfg_path, b"").unwrap();
        let got = project_root(&sub, Some(&cfg_path));
        assert_eq!(got, sub); // canonicalized args.path, NOT the parent with toml
    }

    #[test]
    fn nonexistent_args_path_falls_back_to_lossy_path() {
        let p = std::path::Path::new("/definitely/does/not/exist/foo");
        let got = project_root(p, None);
        assert_eq!(got, p);
    }
}
