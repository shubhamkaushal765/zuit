//! Project-level metadata cache for JS / TS analyzers.
//!
//! Every `PKG` / `HEALTH` / `CHAIN` analyzer needs to look at the same handful
//! of files (`package.json`, `package-lock.json`, the output of `git log`).
//! Reading and parsing those repeatedly is wasteful and would force `git log`
//! to run once per analyzer. [`JsManifest`] memoises the parsed values so each
//! source is touched **at most once per engine run**.
//!
//! # Lifetime
//!
//! Entries are keyed on the canonicalised project root and stored in a
//! [`OnceLock<Mutex<HashMap<...>>>`]. Tests can call `reset_for_tests` to
//! drop the cache between assertions.
//!
//! # Scope
//!
//! Only `package.json` and `package-lock.json` are eagerly parsed. `pnpm-lock.yaml`
//! and `yarn.lock` are exposed as path-presence signals only; full parsing is
//! intentionally deferred (see `.agent/JS_PLAN.md` §3a).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// Output of `git log --format=...` shaped for analyzer consumption.
///
/// HEALTH analyzers operate on this struct, never on raw `git` output. Tests
/// build it with [`GitLog::for_tests`] to keep the suite hermetic.
#[derive(Debug, Clone, Default)]
pub struct GitLog {
    /// Author email (or name) for each commit, in reverse-chronological order.
    pub authors: Vec<String>,
    /// Days since the most recent commit, or `None` if the log is empty.
    pub days_since_last_commit: Option<u32>,
    /// Days since the most recent annotated tag, or `None` if no tag exists.
    pub days_since_last_tag: Option<u32>,
}

impl GitLog {
    /// Test-only constructor used by HEALTH unit tests to avoid invoking `git`.
    #[must_use]
    pub fn for_tests(
        authors: Vec<String>,
        days_since_last_commit: Option<u32>,
        days_since_last_tag: Option<u32>,
    ) -> Self {
        Self {
            authors,
            days_since_last_commit,
            days_since_last_tag,
        }
    }
}

/// Lazy, per-project metadata bundle.
///
/// All fields are populated on first access. `package_json` and `lock_json`
/// are read eagerly inside [`JsManifest::load`]; the `git_log` field is
/// computed lazily by HEALTH analyzers.
#[derive(Debug)]
pub struct JsManifest {
    /// Canonicalised project root (the parent of `package.json`).
    pub root: PathBuf,
    /// Parsed `package.json`, or `None` if absent / unparseable.
    pub package_json: Option<serde_json::Value>,
    /// Parsed `package-lock.json`, or `None` if absent / unparseable.
    pub lock_json: Option<serde_json::Value>,
    /// `true` if any of `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`
    /// exists at the project root.
    pub has_any_lockfile: bool,
    /// Lazily-computed git log; written once via `OnceLock::set`.
    pub git_log: OnceLock<Option<GitLog>>,
}

impl JsManifest {
    /// Loads `package.json` and `package-lock.json` from `root`, returning a
    /// fresh manifest. Missing or malformed files become `None` rather than
    /// errors — analyzers that need a present `package.json` should check
    /// `package_json.is_some()` and emit no findings otherwise.
    #[must_use]
    pub fn load(root: &Path) -> Self {
        let package_json = std::fs::read_to_string(root.join("package.json"))
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());

        let lock_json = std::fs::read_to_string(root.join("package-lock.json"))
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());

        let has_any_lockfile = root.join("package-lock.json").exists()
            || root.join("pnpm-lock.yaml").exists()
            || root.join("yarn.lock").exists();

        Self {
            root: root.to_path_buf(),
            package_json,
            lock_json,
            has_any_lockfile,
            git_log: OnceLock::new(),
        }
    }
}

type Cache = OnceLock<Mutex<HashMap<PathBuf, Arc<JsManifest>>>>;

/// Process-wide manifest cache. Keyed on canonicalised project root.
static CACHE: Cache = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<PathBuf, Arc<JsManifest>>> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Returns a shared [`JsManifest`] for `root`, loading it on first access.
///
/// Subsequent calls with the same `root` return the same `Arc` — including
/// the same `git_log` `OnceLock`, so `git` runs at most once per project per
/// process lifetime.
///
/// # Panics
///
/// Panics if the cache mutex has been poisoned by a previous panic in another
/// thread. This is an unrecoverable process-level invariant violation.
#[must_use]
pub fn get_or_load(root: &Path) -> Arc<JsManifest> {
    let key = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let mut guard = cache().lock().expect("manifest cache poisoned");
    if let Some(existing) = guard.get(&key) {
        return Arc::clone(existing);
    }
    let manifest = Arc::new(JsManifest::load(&key));
    guard.insert(key, Arc::clone(&manifest));
    manifest
}

/// Test-only helper: drop every cached manifest. Use between unit tests so
/// fixture changes are observed.
///
/// # Panics
///
/// Panics if the cache mutex is poisoned.
#[cfg(test)]
pub fn reset_for_tests() {
    if let Some(m) = CACHE.get() {
        m.lock().expect("manifest cache poisoned").clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).expect("write fixture");
    }

    #[test]
    fn load_returns_none_when_files_missing() {
        let dir = TempDir::new().expect("tempdir");
        let m = JsManifest::load(dir.path());
        assert!(m.package_json.is_none());
        assert!(m.lock_json.is_none());
        assert!(!m.has_any_lockfile);
    }

    #[test]
    fn load_parses_package_json() {
        let dir = TempDir::new().expect("tempdir");
        write(
            dir.path(),
            "package.json",
            r#"{"name":"x","version":"1.0.0"}"#,
        );
        let m = JsManifest::load(dir.path());
        let v = m.package_json.as_ref().expect("package.json must parse");
        assert_eq!(v["name"], "x");
    }

    #[test]
    fn load_handles_malformed_package_json() {
        let dir = TempDir::new().expect("tempdir");
        write(dir.path(), "package.json", "not json");
        let m = JsManifest::load(dir.path());
        assert!(m.package_json.is_none());
    }

    #[test]
    fn detects_pnpm_lockfile() {
        let dir = TempDir::new().expect("tempdir");
        write(dir.path(), "pnpm-lock.yaml", "lockfileVersion: 9");
        let m = JsManifest::load(dir.path());
        assert!(m.has_any_lockfile);
        assert!(m.lock_json.is_none(), "pnpm yaml must not be JSON-parsed");
    }

    #[test]
    fn detects_yarn_lockfile() {
        let dir = TempDir::new().expect("tempdir");
        write(dir.path(), "yarn.lock", "# yarn lockfile v1\n");
        let m = JsManifest::load(dir.path());
        assert!(m.has_any_lockfile);
    }

    #[test]
    fn cache_returns_same_arc_for_same_root() {
        let dir = TempDir::new().expect("tempdir");
        write(dir.path(), "package.json", r#"{"name":"x"}"#);
        reset_for_tests();
        let a = get_or_load(dir.path());
        let b = get_or_load(dir.path());
        assert!(Arc::ptr_eq(&a, &b), "second call must return cached Arc");
    }

    #[test]
    fn git_log_for_tests_constructor() {
        let g = GitLog::for_tests(vec!["a@x".into(), "b@x".into()], Some(10), Some(50));
        assert_eq!(g.authors.len(), 2);
        assert_eq!(g.days_since_last_commit, Some(10));
        assert_eq!(g.days_since_last_tag, Some(50));
    }
}
