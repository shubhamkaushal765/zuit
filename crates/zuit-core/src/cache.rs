//! Incremental analysis cache: skip re-parsing files whose content is unchanged.
//!
//! # Design
//!
//! Each source file is identified by its **canonical absolute path**.  The cache
//! stores a `(content_hash, config_hash, Vec<Finding>, parse_failed)` tuple keyed
//! on that path.  Content is hashed with **BLAKE3**.
//!
//! When the engine sees a file it already holds in the cache and the freshly
//! computed BLAKE3 digest matches the stored one **and** the config hash also
//! matches, it reuses the cached findings and skips parse + analysis entirely.
//!
//! # Config-hash invalidation (§2.3)
//!
//! Each cache entry stores the BLAKE3 hash of the config at analysis time.  If
//! the config changes between runs the cache entry is treated as a miss.  A
//! warning is emitted once per run via `tracing::warn!`.
//!
//! # On-disk persistence
//!
//! [`JsonCacheStore`] serialises the in-memory [`AnalysisCache`] to a compact
//! JSON file.  Writes are atomic: data is written to `<path>.tmp`, fsynced,
//! then renamed over the target.
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use zuit_core::cache::{AnalysisCache, CacheStore, JsonCacheStore};
//!
//! let dir = Path::new("/tmp/my-cache");
//! let store = JsonCacheStore::new(dir.to_path_buf());
//! let mut cache = store.load().unwrap_or_default();
//! // ... run analysis with cache ...
//! store.save(&cache).expect("invariant: cache dir is writable");
//! ```

use std::collections::{BTreeMap, HashMap};
use std::io::{BufWriter, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::finding::Finding;

// -- content hashing ----------------------------------------------------------

/// Returns the BLAKE3 hex digest of the given byte slice.
#[must_use]
pub fn hash_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Computes a stable BLAKE3 hex digest of a [`Config`].
///
/// To guarantee determinism, `HashMap` fields (`dimensions` and `rules`) are
/// sorted into `BTreeMap` views before serialisation so that key order in the
/// source map does not affect the hash.
#[must_use]
pub fn hash_config(config: &Config) -> String {
    let dims_sorted: BTreeMap<&str, _> = config
        .dimensions
        .iter()
        .map(|(k, v)| (k.as_str(), v))
        .collect();
    let rules_sorted: BTreeMap<&str, _> =
        config.rules.iter().map(|(k, v)| (k.as_str(), v)).collect();

    let canonical = serde_json::json!({
        "general": config.general,
        "dimensions": dims_sorted,
        "rules": rules_sorted,
        "history": config.history,
    });

    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    blake3::hash(&bytes).to_hex().to_string()
}

// -- cache entry --------------------------------------------------------------

/// A single cached result for one source file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheEntry {
    /// BLAKE3 hex digest of the file's bytes at analysis time.
    pub content_hash: String,
    /// BLAKE3 hex digest of the [`Config`] used when this entry was written.
    ///
    /// If the config changes between runs the entry is treated as a miss even
    /// if the file content is unchanged.
    pub config_hash: String,
    /// Findings produced for this file.
    pub findings: Vec<Finding>,
    /// Whether parsing failed for this file on the last analysis pass.
    pub parse_failed: bool,
}

// -- in-memory cache ----------------------------------------------------------

/// In-memory map from canonical absolute path to cached analysis results.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AnalysisCache {
    entries: HashMap<PathBuf, CacheEntry>,
    /// Number of cache hits observed during a single analysis run.
    #[serde(skip)]
    hits: u32,
}

impl AnalysisCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Looks up the cache entry for `path`.
    #[must_use]
    pub fn get(&self, path: &Path) -> Option<&CacheEntry> {
        self.entries.get(path)
    }

    /// Inserts or replaces the cache entry for `path`.
    pub fn insert(&mut self, path: PathBuf, entry: CacheEntry) {
        self.entries.insert(path, entry);
    }

    /// Removes any path from the cache that is **not** present in `live_paths`.
    pub fn prune(&mut self, live_paths: &[PathBuf]) {
        let live: std::collections::HashSet<&PathBuf> = live_paths.iter().collect();
        self.entries.retain(|k, _| live.contains(k));
    }

    /// Returns the total number of entries currently held in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Increments the hit counter by one.
    pub fn record_hit(&mut self) {
        self.hits += 1;
    }

    /// Increments the hit counter by `n`.
    pub fn record_hit_n(&mut self, n: u32) {
        self.hits += n;
    }

    /// Resets the hit counter to zero.
    pub fn reset_hits(&mut self) {
        self.hits = 0;
    }

    /// Returns the number of cache hits since the last [`reset_hits`](Self::reset_hits).
    #[must_use]
    pub fn hits(&self) -> u32 {
        self.hits
    }
}

// -- persistence trait --------------------------------------------------------

/// Abstraction over cache serialisation / deserialization.
pub trait CacheStore {
    /// Error type returned by [`load`](Self::load) and [`save`](Self::save).
    type Error: std::error::Error;

    /// Loads the cache from the backing store.
    ///
    /// Returns `Ok(AnalysisCache::new())` if the store does not yet exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the store exists but is corrupt or unreadable.
    fn load(&self) -> Result<AnalysisCache, Self::Error>;

    /// Persists the cache to the backing store, replacing any previous content.
    ///
    /// # Errors
    ///
    /// Returns an error if the backing store cannot be written.
    fn save(&self, cache: &AnalysisCache) -> Result<(), Self::Error>;
}

// -- JSON on-disk store -------------------------------------------------------

/// Error type for [`JsonCacheStore`] operations.
#[derive(Debug, thiserror::Error)]
pub enum CacheStoreError {
    /// An I/O error occurred while reading or writing the cache file.
    #[error("cache store I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The cache file exists but its JSON is malformed.
    #[error("cache store parse error: {0}")]
    Parse(#[from] serde_json::Error),
}

/// On-disk JSON cache store.
///
/// Writes the [`AnalysisCache`] as a compact JSON file at `<dir>/v1.json`.
/// Writes are **atomic**: data is written to `<path>.tmp`, fsynced, then
/// renamed over the target to avoid partial-write corruption on power loss.
/// Uses [`BufWriter`] + [`serde_json::to_writer`] to avoid a large intermediate
/// `String` allocation.
#[derive(Debug, Clone)]
pub struct JsonCacheStore {
    path: PathBuf,
}

impl JsonCacheStore {
    /// Creates a new store rooted at `dir`.
    ///
    /// The file is written as `<dir>/v1.json`.  `dir` is created on first
    /// [`save`](Self::save) if it does not exist.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // API takes owned PathBuf for ergonomic construction
    pub fn new(dir: PathBuf) -> Self {
        Self {
            path: dir.join("v1.json"),
        }
    }

    /// Returns the path to the cache file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl CacheStore for JsonCacheStore {
    type Error = CacheStoreError;

    fn load(&self) -> Result<AnalysisCache, Self::Error> {
        if !self.path.exists() {
            return Ok(AnalysisCache::new());
        }
        let text = std::fs::read_to_string(&self.path)?;
        let cache: AnalysisCache = serde_json::from_str(&text)?;
        Ok(cache)
    }

    fn save(&self, cache: &AnalysisCache) -> Result<(), Self::Error> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Atomic write: write to .tmp -> fsync -> rename.
        // This ensures the destination file is never partially written.
        let tmp_path = self.path.with_extension("tmp");
        {
            let file = std::fs::File::create(&tmp_path)?;
            let mut writer = BufWriter::new(file);
            serde_json::to_writer(&mut writer, cache)?;
            writer.flush()?;
            // fsync before rename to guarantee durability.
            writer
                .into_inner()
                .map_err(std::io::IntoInnerError::into_error)?
                .sync_all()?;
        }
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }
}

// -- tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn dummy_finding() -> Finding {
        use crate::analyzer::{Dimension, Severity};
        use crate::id::AnalyzerId;
        use crate::span::{ByteOffset, LineCol, Location, Span};

        Finding {
            analyzer: AnalyzerId::new("test"),
            dimension: Dimension::Maintainability,
            rule_id: "TEST001".to_string(),
            severity: Severity::Low,
            message: "test finding".to_string(),
            location: Location {
                file: PathBuf::from("a.rs"),
                span: Span::new(ByteOffset(0), ByteOffset(1)),
                start: LineCol::new(1, 1),
                end: LineCol::new(1, 2),
            },
            suggestion: None,
            references: vec![],
            cwe: vec![],
            owasp: vec![],
        }
    }

    fn dummy_entry() -> CacheEntry {
        CacheEntry {
            content_hash: hash_bytes(b"fn main() {}"),
            config_hash: hash_config(&Config::default()),
            findings: vec![dummy_finding()],
            parse_failed: false,
        }
    }

    // -- hash_bytes -------------------------------------------------------------

    #[test]
    fn hash_bytes_is_deterministic() {
        let h1 = hash_bytes(b"hello");
        let h2 = hash_bytes(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_bytes_differs_on_different_input() {
        let h1 = hash_bytes(b"hello");
        let h2 = hash_bytes(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_bytes_is_hex_string() {
        let h = hash_bytes(b"test");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h.len(), 64, "BLAKE3 hex is 64 chars");
    }

    // -- hash_config (Task 5) ---------------------------------------------------

    #[test]
    fn hash_config_same_config_same_hash() {
        let c1 = Config::default();
        let c2 = Config::default();
        assert_eq!(hash_config(&c1), hash_config(&c2));
    }

    #[test]
    fn hash_config_changed_config_different_hash() {
        let c1 = Config::default();
        let mut c2 = Config::default();
        c2.general.follow_symlinks = true;
        assert_ne!(hash_config(&c1), hash_config(&c2));
    }

    #[test]
    fn hash_config_is_deterministic_across_calls() {
        let config = Config::default();
        let h1 = hash_config(&config);
        let h2 = hash_config(&config);
        assert_eq!(h1, h2);
    }

    // -- AnalysisCache ----------------------------------------------------------

    #[test]
    fn empty_cache_has_no_entries() {
        let c = AnalysisCache::new();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn insert_and_get_round_trips() {
        let mut c = AnalysisCache::new();
        let path = PathBuf::from("/project/src/main.rs");
        let entry = dummy_entry();
        c.insert(path.clone(), entry.clone());
        let got = c.get(&path).expect("entry should be present");
        assert_eq!(got.content_hash, entry.content_hash);
        assert_eq!(got.findings.len(), 1);
        assert!(!got.parse_failed);
    }

    #[test]
    fn get_returns_none_for_unknown_path() {
        let c = AnalysisCache::new();
        assert!(c.get(Path::new("/not/present")).is_none());
    }

    #[test]
    fn prune_removes_missing_paths() {
        let mut c = AnalysisCache::new();
        let pa = PathBuf::from("/a.rs");
        let pb = PathBuf::from("/b.rs");
        c.insert(
            pa.clone(),
            CacheEntry {
                content_hash: "abc".to_string(),
                config_hash: "cfghash".to_string(),
                findings: vec![],
                parse_failed: false,
            },
        );
        c.insert(
            pb.clone(),
            CacheEntry {
                content_hash: "def".to_string(),
                config_hash: "cfghash".to_string(),
                findings: vec![],
                parse_failed: false,
            },
        );
        c.prune(std::slice::from_ref(&pa));
        assert!(c.get(&pa).is_some());
        assert!(c.get(&pb).is_none());
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn prune_all_paths_removes_all() {
        let mut c = AnalysisCache::new();
        c.insert(
            PathBuf::from("/x.rs"),
            CacheEntry {
                content_hash: "h".to_string(),
                config_hash: "ch".to_string(),
                findings: vec![],
                parse_failed: false,
            },
        );
        c.prune(&[]);
        assert!(c.is_empty());
    }

    #[test]
    fn hit_counter_starts_at_zero() {
        let c = AnalysisCache::new();
        assert_eq!(c.hits(), 0);
    }

    #[test]
    fn record_hit_increments_counter() {
        let mut c = AnalysisCache::new();
        c.record_hit();
        c.record_hit();
        assert_eq!(c.hits(), 2);
    }

    #[test]
    fn record_hit_n_increments_by_n() {
        let mut c = AnalysisCache::new();
        c.record_hit_n(5);
        assert_eq!(c.hits(), 5);
    }

    #[test]
    fn reset_hits_zeroes_counter() {
        let mut c = AnalysisCache::new();
        c.record_hit();
        c.reset_hits();
        assert_eq!(c.hits(), 0);
    }

    // -- JsonCacheStore ---------------------------------------------------------

    #[test]
    fn load_missing_store_returns_empty_cache() {
        let tmp = TempDir::new().unwrap();
        let store = JsonCacheStore::new(tmp.path().join("no-such-dir"));
        let cache = store.load().expect("load from missing dir should succeed");
        assert!(cache.is_empty());
    }

    #[test]
    fn save_and_load_round_trips() {
        let tmp = TempDir::new().unwrap();
        let store = JsonCacheStore::new(tmp.path().to_path_buf());

        let mut cache = AnalysisCache::new();
        let path = PathBuf::from("/project/src/lib.rs");
        cache.insert(
            path.clone(),
            CacheEntry {
                content_hash: hash_bytes(b"pub fn hello() {}"),
                config_hash: hash_config(&Config::default()),
                findings: vec![dummy_finding()],
                parse_failed: false,
            },
        );
        store.save(&cache).expect("save should succeed");

        let loaded = store.load().expect("load should succeed");
        let entry = loaded.get(&path).expect("entry should survive round-trip");
        assert_eq!(entry.findings.len(), 1);
        assert_eq!(entry.findings[0].rule_id, "TEST001");
    }

    #[test]
    fn save_creates_missing_parent_dir() {
        let tmp = TempDir::new().unwrap();
        let store = JsonCacheStore::new(tmp.path().join("nested").join("dir"));
        let cache = AnalysisCache::new();
        store
            .save(&cache)
            .expect("should create parent dirs automatically");
        assert!(store.path().exists());
    }

    #[test]
    fn load_returns_error_on_corrupt_file() {
        let tmp = TempDir::new().unwrap();
        let store = JsonCacheStore::new(tmp.path().to_path_buf());
        std::fs::write(store.path(), b"not json at all !!!").unwrap();
        let err = store.load().expect_err("corrupt file should fail to load");
        assert!(matches!(err, CacheStoreError::Parse(_)));
    }

    #[test]
    fn hits_are_not_serialised() {
        let tmp = TempDir::new().unwrap();
        let store = JsonCacheStore::new(tmp.path().to_path_buf());
        let mut cache = AnalysisCache::new();
        cache.record_hit();
        cache.record_hit();
        assert_eq!(cache.hits(), 2);

        store.save(&cache).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.hits(), 0, "hits must not be persisted");
    }

    // -- Task 6: atomic write / power-fail simulation --------------------------

    #[test]
    fn partial_tmp_file_does_not_corrupt_existing_cache() {
        // Simulate a power-fail: write partial bytes to <path>.tmp but do NOT
        // rename it.  load() must return the old (unchanged) cache.
        let tmp = TempDir::new().unwrap();
        let store = JsonCacheStore::new(tmp.path().to_path_buf());

        let mut cache = AnalysisCache::new();
        cache.insert(
            PathBuf::from("/project/src/main.rs"),
            CacheEntry {
                content_hash: hash_bytes(b"original"),
                config_hash: hash_config(&Config::default()),
                findings: vec![dummy_finding()],
                parse_failed: false,
            },
        );
        store.save(&cache).unwrap();
        assert!(store.path().exists());

        // Write partial/corrupt bytes to the .tmp file (as if save() crashed).
        let tmp_path = store.path().with_extension("tmp");
        std::fs::write(&tmp_path, b"partial garbage bytes {{{").unwrap();

        // load() should read the real file, not the .tmp file.
        let loaded = store.load().unwrap();
        assert_eq!(
            loaded.len(),
            1,
            "existing cache must be intact after .tmp partial write"
        );
    }
}
