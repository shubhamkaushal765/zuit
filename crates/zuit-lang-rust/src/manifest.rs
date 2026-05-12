//! `RustManifest` — per-project cache of parsed `Cargo.toml` and related
//! project-root metadata.
//!
//! All PKG (and HEALTH/CHAIN) analyzers share a single `Arc<RustManifest>`
//! per project root so that `Cargo.toml` is read and parsed at most once per
//! engine run.
//!
//! # Thread safety
//!
//! The global cache is a `OnceLock<Mutex<HashMap<PathBuf, Arc<RustManifest>>>>`.
//! Each `manifest_for` call holds the mutex only long enough to check or insert
//! the entry; the returned `Arc` is then used without the lock held.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use zuit_core::Project;

// ── Types ──────────────────────────────────────────────────────────────────────

/// Project-level metadata for a Rust project, derived from `Cargo.toml`
/// and neighbouring files in the project root.
///
/// Shared via `Arc` among all PKG/HEALTH/CHAIN analyzers so that file I/O and
/// TOML parsing happen at most once per project root per engine run.
pub(crate) struct RustManifest {
    /// Canonical project root path (used as the cache key).
    #[allow(dead_code)]
    pub root: PathBuf,

    /// Parsed `Cargo.toml` document, or `None` if the file does not exist or
    /// failed to parse.
    pub cargo_toml: Option<toml_edit::DocumentMut>,

    /// Absolute path to `Cargo.toml`, or `None` if absent.
    pub cargo_toml_path: Option<PathBuf>,

    /// Parse error from `Cargo.toml`, if the file exists but is not valid
    /// TOML.  The tuple is `(message, (line, col))` — best-effort from
    /// `toml_edit::TomlError`.
    pub cargo_toml_parse_error: Option<(String, (u32, u32))>,

    /// Absolute path to `Cargo.lock` if it exists in the project root.
    #[allow(dead_code)]
    pub cargo_lock_path: Option<PathBuf>,

    /// Path to the first README file found in the project root (`README.md`,
    /// `README.rst`, `README.txt`, `README`), or `None` if none exists.
    pub readme_path: Option<PathBuf>,

    /// Cached git log for this project root.
    ///
    /// Populated lazily on the first call to [`RustManifest::git_log`].
    /// `Err` means git is unavailable (no `.git`, binary missing, etc.).
    pub(crate) git_log_cache: OnceLock<Result<crate::analyzers::health::git_log::GitLog, String>>,
}

// ── RustManifest methods ──────────────────────────────────────────────────────

impl RustManifest {
    /// Returns a reference to the cached git log, collecting it on first call.
    ///
    /// `window_days` is passed to `collect_git_log` on the first (and only)
    /// invocation.  Subsequent calls ignore `window_days` and return the cached
    /// value — the window is effectively fixed at the value used on the first call.
    ///
    /// Returns `Err(&str)` when git is unavailable (no `.git`, binary missing,
    /// timeout, etc.).
    pub(crate) fn git_log(
        &self,
        project: &zuit_core::Project,
        window_days: u32,
    ) -> Result<&crate::analyzers::health::git_log::GitLog, &str> {
        self.git_log_cache
            .get_or_init(|| {
                // In tests, check the injection map before invoking real git.
                #[cfg(test)]
                {
                    let map = git_log_injection_map()
                        .lock()
                        .expect("git log injection map poisoned");
                    if let Some(v) = map.get(&self.root) {
                        return v.clone();
                    }
                }
                crate::analyzers::health::git_log::collect_git_log(&project.root, window_days)
                    .map_err(|e| e.to_string())
            })
            .as_ref()
            .map_err(String::as_str)
    }

    /// Test-only: pre-populate the git log cache with a fixed value.
    ///
    /// Stores the value in a global path-keyed map that survives `clear_cache()`
    /// evictions, so the injection is visible even when a parallel test evicts
    /// this manifest from the main cache.  The `git_log()` method checks the
    /// injection map before falling back to the real `git` invocation.
    #[cfg(test)]
    pub(crate) fn inject_git_log_for_test(
        &self,
        result: Result<crate::analyzers::health::git_log::GitLog, std::io::Error>,
    ) {
        // Store in the global injection map (survives clear_cache).
        let serialised = result.map_err(|e| e.to_string());
        {
            let mut map = git_log_injection_map()
                .lock()
                .expect("git log injection map poisoned");
            map.insert(self.root.clone(), serialised);
        }
        // Also pre-populate the OnceLock on this particular Arc (best-effort).
        let _ = self.git_log_cache.get_or_init(|| {
            let map = git_log_injection_map()
                .lock()
                .expect("git log injection map poisoned");
            if let Some(v) = map.get(&self.root) {
                v.clone()
            } else {
                Err("not injected".to_string())
            }
        });
    }
}

// ── Global cache ──────────────────────────────────────────────────────────────

/// Global per-root cache.  Keyed on canonical project root path.
static CACHE: OnceLock<Mutex<HashMap<PathBuf, Arc<RustManifest>>>> = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<PathBuf, Arc<RustManifest>>> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Returns the `RustManifest` for `project`, reading and parsing
/// `Cargo.toml` on the first call for each distinct project root.
///
/// Subsequent calls for the same canonical root return the cached `Arc`
/// without re-reading the file.
pub(crate) fn manifest_for(project: &Project) -> Arc<RustManifest> {
    // Canonicalize the root path so that relative vs. absolute paths for the
    // same directory collide in the cache correctly.
    let root = project
        .root
        .canonicalize()
        .unwrap_or_else(|_| project.root.clone());

    {
        let lock = cache().lock().expect("manifest cache mutex poisoned");
        if let Some(m) = lock.get(&root) {
            return Arc::clone(m);
        }
    }

    // Cache miss — build the manifest.
    let manifest = Arc::new(build_manifest(root.clone()));

    {
        let mut lock = cache().lock().expect("manifest cache mutex poisoned");
        // Another thread may have inserted while we were building; prefer the
        // cached version if so.
        lock.entry(root).or_insert(manifest).clone()
    }
}

/// Clears the global manifest cache.
///
/// Intended for use in tests that construct multiple temporary project roots
/// within the same process.  Not needed in production.
#[cfg(test)]
pub(crate) fn clear_cache() {
    if let Some(lock) = CACHE.get() {
        lock.lock().expect("manifest cache mutex poisoned").clear();
    }
}

// ── Test-only git log injection map ──────────────────────────────────────────

/// A secondary global map used in tests to inject git log data by project root
/// path.  Unlike the main `CACHE`, this map is NOT cleared by `clear_cache()`,
/// so injected data survives cache evictions caused by parallel test threads.
///
/// Only compiled in test builds.
#[cfg(test)]
static GIT_LOG_INJECTION: OnceLock<
    Mutex<HashMap<PathBuf, Result<crate::analyzers::health::git_log::GitLog, String>>>,
> = OnceLock::new();

#[cfg(test)]
fn git_log_injection_map()
-> &'static Mutex<HashMap<PathBuf, Result<crate::analyzers::health::git_log::GitLog, String>>> {
    GIT_LOG_INJECTION.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── Internal construction ─────────────────────────────────────────────────────

fn build_manifest(root: PathBuf) -> RustManifest {
    let cargo_toml_path = {
        let p = root.join("Cargo.toml");
        if p.exists() { Some(p) } else { None }
    };

    let (cargo_toml, cargo_toml_parse_error) = match &cargo_toml_path {
        None => (None, None),
        Some(path) => match std::fs::read_to_string(path) {
            Err(e) => {
                let msg = format!("cannot read Cargo.toml: {e}");
                (None, Some((msg, (1, 1))))
            }
            Ok(content) => match content.parse::<toml_edit::DocumentMut>() {
                Ok(doc) => (Some(doc), None),
                Err(e) => {
                    let (line, col) = e.span().map_or((1, 1), |span| {
                        // toml_edit spans are byte ranges; convert to (line, col)
                        let before = &content[..span.start.min(content.len())];
                        #[allow(clippy::cast_possible_truncation)]
                        let ln = before.bytes().filter(|&b| b == b'\n').count() as u32 + 1;
                        #[allow(clippy::cast_possible_truncation)]
                        let cl = before
                            .rfind('\n')
                            .map_or(before.len(), |i| before.len() - i - 1)
                            as u32
                            + 1;
                        (ln, cl)
                    });
                    (None, Some((e.to_string(), (line, col))))
                }
            },
        },
    };

    // Locate Cargo.lock.
    let cargo_lock_path = {
        let p = root.join("Cargo.lock");
        if p.exists() { Some(p) } else { None }
    };

    // Locate README.
    let readme_path = ["README.md", "README.rst", "README.txt", "README"]
        .iter()
        .map(|name| root.join(name))
        .find(|p| p.exists());

    RustManifest {
        root,
        cargo_toml,
        cargo_toml_path,
        cargo_toml_parse_error,
        cargo_lock_path,
        readme_path,
        git_log_cache: OnceLock::new(),
    }
}
