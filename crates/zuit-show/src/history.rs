//! On-disk history store at `~/.zuit/`.
//!
//! See `docs/superpowers/specs/2026-05-04-zuit-show-design.md` §4.

use crate::{analytics::ScanAnalytics, error::HistoryError, hash};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

const PROJECTS: &str = "projects";
const META: &str = "meta.json";
const META_LOCK: &str = "meta.lock";
const SCANS: &str = "scans";
const CONFIGS: &str = "configs";

/// Per-project metadata persisted to `meta.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectMeta {
    /// Canonical absolute project root.
    pub root: PathBuf,
    /// Display name (basename of root for v1).
    pub name: String,
    /// Wall-clock RFC-3339 timestamp of when this project was first recorded.
    pub first_seen: String,
}

/// 16-hex-char project identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProjectId(pub String);

/// 16-hex-char config-snapshot identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConfigId(pub String);

/// Filename-stem identifier for a scan: `<RFC3339Z>-<6hex>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScanId(pub String);

/// Lightweight scan summary used by `/api/projects/:hash/scans`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanIndexEntry {
    /// The scan id.
    pub id: String,
    /// RFC-3339 timestamp captured when the scan was recorded.
    pub captured_at: String,
    /// Config-snapshot id used for the scan.
    pub config_hash: String,
    /// Per-dimension scores at the time of the scan.
    pub scores: serde_json::Value,
    /// Counts of findings by severity.
    pub finding_count_by_severity: serde_json::Value,
    /// Optional free-form label (e.g. "release", "broken main").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Top-level handle to the on-disk history.
pub struct HistoryStore {
    root: PathBuf,
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), HistoryError> {
    let parent = path.parent().expect("invariant: path has parent");
    // SEC-H: create parent directories with mode 0o700 on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| HistoryError::Io {
                path: parent.into(),
                source: e,
            })?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(parent).map_err(|e| HistoryError::Io {
            path: parent.into(),
            source: e,
        })?;
    }
    let tmp = path.with_extension("tmp");
    {
        // SEC-H: create the temp file with mode 0o600 on Unix.
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt as _;
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| HistoryError::Io {
                    path: tmp.clone(),
                    source: e,
                })?
        };
        #[cfg(not(unix))]
        let mut f = fs::File::create(&tmp).map_err(|e| HistoryError::Io {
            path: tmp.clone(),
            source: e,
        })?;
        f.write_all(bytes).map_err(|e| HistoryError::Io {
            path: tmp.clone(),
            source: e,
        })?;
        f.sync_all().map_err(|e| HistoryError::Io {
            path: tmp.clone(),
            source: e,
        })?;
    }
    fs::rename(&tmp, path).map_err(|e| HistoryError::Io {
        path: path.into(),
        source: e,
    })?;
    Ok(())
}

/// Create a directory (and all parents) with mode 0o700 on Unix, or normal
/// permissions on non-Unix platforms.
fn create_dir_0o700(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
    }
}

fn rfc3339_now_seconds() -> String {
    let now = time::OffsetDateTime::now_utc();
    let fmt = time::format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]Z")
        .expect("invariant: format description is valid");
    now.format(&fmt).expect("invariant: now formats")
}

fn rand_hex6() -> String {
    let n: u32 = rand::random::<u32>() & 0x00FF_FFFF;
    format!("{n:06x}")
}

/// Returns true when the filename is a plain scan envelope (has a `.json`
/// extension but is NOT a `.label.json` or `.analytics.json` sidecar).
fn is_scan_json_file(name: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        && !name.ends_with(".label.json")
        && !name.ends_with(".analytics.json")
}

impl HistoryStore {
    /// Open (or create on first write) a store rooted at `dir`.
    /// `dir` is normally `~/.zuit`. Tests pass a tempdir.
    #[must_use]
    pub fn open(dir: impl Into<PathBuf>) -> Self {
        Self { root: dir.into() }
    }

    /// Compute the project id for an absolute path.
    #[must_use]
    pub fn project_id(root: &Path) -> ProjectId {
        ProjectId(hash::short_hex(root.as_os_str().as_encoded_bytes()))
    }

    fn project_dir(&self, id: &ProjectId) -> PathBuf {
        self.root.join(PROJECTS).join(&id.0)
    }

    /// Persist a scan. Returns the assigned scan id.
    ///
    /// `report_json` is the full v1 JSON output bytes (the same string the CLI
    /// would have printed with `--format json`); `config_toml` is the raw
    /// `zuit.toml` text (or `b""` if no toml was discovered).
    ///
    /// Atomicity: every file write goes via `<path>.tmp` + `fsync` + rename.
    /// `meta.json` is updated under a per-project `flock(meta.lock, EX)` and
    /// retention pruning happens inside the same lock.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::Io`] on filesystem errors or
    /// [`HistoryError::Json`] if `report_json` is not valid JSON.
    #[allow(clippy::too_many_lines)]
    pub fn record(
        &self,
        project_root: &Path,
        config_toml: &[u8],
        report_json: &[u8],
        max_scans: u32,
    ) -> Result<ScanId, HistoryError> {
        // 1. Compute IDs.
        let pid = HistoryStore::project_id(project_root);
        let cfg_id = ConfigId(hash::short_hex(config_toml));

        // 2. Build dir tree (SEC-H: mode 0o700 on Unix).
        let p_dir = self.project_dir(&pid);
        let scans_dir = p_dir.join(SCANS);
        let configs_dir = p_dir.join(CONFIGS);
        create_dir_0o700(&scans_dir).map_err(|e| HistoryError::Io {
            path: scans_dir.clone(),
            source: e,
        })?;
        create_dir_0o700(&configs_dir).map_err(|e| HistoryError::Io {
            path: configs_dir.clone(),
            source: e,
        })?;

        // 3. Write config snapshot if missing.
        let cfg_path = configs_dir.join(format!("{}.toml", cfg_id.0));
        if !cfg_path.exists() {
            atomic_write(&cfg_path, config_toml)?;
        }

        // 4. Build scan id and write envelope.
        let captured_at = rfc3339_now_seconds();
        let scan_id_str = format!("{}-{}", captured_at, rand_hex6());
        let report_value: serde_json::Value =
            serde_json::from_slice(report_json).map_err(|e| HistoryError::Json {
                path: scans_dir.clone(),
                source: e,
            })?;
        let envelope = serde_json::json!({
            "scan_id": scan_id_str,
            "captured_at": captured_at,
            "config_hash": cfg_id.0,
            "report": report_value,
        });
        let envelope_bytes = serde_json::to_vec(&envelope).map_err(|e| HistoryError::Json {
            path: scans_dir.clone(),
            source: e,
        })?;
        let scan_file = scans_dir.join(format!("{scan_id_str}.json"));
        atomic_write(&scan_file, &envelope_bytes)?;

        // 4b. Materialise the analytics sidecar next to the envelope.
        // Failure here MUST NOT abort the scan record — the lazy fallback in
        // the HTTP router will regenerate the sidecar on the next request.
        let analytics = crate::analytics::compute_scan_analytics(&envelope);
        match serde_json::to_vec(&analytics) {
            Ok(analytics_bytes) => {
                let analytics_file = scans_dir.join(format!("{scan_id_str}.analytics.json"));
                if let Err(err) = atomic_write(&analytics_file, &analytics_bytes) {
                    tracing::warn!("failed to materialise scan analytics sidecar: {err}");
                }
            }
            Err(err) => {
                tracing::warn!("failed to serialise scan analytics sidecar: {err}");
            }
        }

        // 5. Open meta.lock, lock exclusively.
        let lock_path = p_dir.join(META_LOCK);
        let lock_file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| HistoryError::Io {
                path: lock_path.clone(),
                source: e,
            })?;
        lock_file.lock_exclusive().map_err(|e| HistoryError::Io {
            path: lock_path.clone(),
            source: e,
        })?;

        // 6. Read or initialise meta.json.
        let meta_path = p_dir.join(META);
        let meta = if meta_path.exists() {
            let bytes = fs::read(&meta_path).map_err(|e| HistoryError::Io {
                path: meta_path.clone(),
                source: e,
            })?;
            serde_json::from_slice::<ProjectMeta>(&bytes).map_err(|e| HistoryError::Json {
                path: meta_path.clone(),
                source: e,
            })?
        } else {
            let first_seen = captured_at.clone();
            let name = project_root.file_name().map_or_else(
                || project_root.to_string_lossy().into_owned(),
                |n| n.to_string_lossy().into_owned(),
            );
            ProjectMeta {
                root: project_root.to_path_buf(),
                name,
                first_seen,
            }
        };

        // Write meta.json atomically.
        let meta_bytes = serde_json::to_vec(&meta).map_err(|e| HistoryError::Json {
            path: meta_path.clone(),
            source: e,
        })?;
        atomic_write(&meta_path, &meta_bytes)?;

        // 7. Prune oldest scans if over limit.
        let mut scan_entries: Vec<String> = fs::read_dir(&scans_dir)
            .map_err(|e| HistoryError::Io {
                path: scans_dir.clone(),
                source: e,
            })?
            .filter_map(|e| {
                e.ok().and_then(|de| {
                    let name = de.file_name().to_string_lossy().into_owned();
                    is_scan_json_file(&name).then_some(name)
                })
            })
            .collect();
        scan_entries.sort();

        let max = max_scans as usize;
        if scan_entries.len() > max {
            let excess = scan_entries.len() - max;
            for name in scan_entries.iter().take(excess) {
                let path = scans_dir.join(name);
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(HistoryError::Io { path, source: e });
                    }
                }
                // Also remove the label sidecar if present.
                let label_path = scans_dir.join(name.replace(".json", ".label.json"));
                match fs::remove_file(&label_path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(HistoryError::Io {
                            path: label_path,
                            source: e,
                        });
                    }
                }
                // Also remove the analytics sidecar if present.
                let analytics_path = scans_dir.join(name.replace(".json", ".analytics.json"));
                match fs::remove_file(&analytics_path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(HistoryError::Io {
                            path: analytics_path,
                            source: e,
                        });
                    }
                }
            }
        }

        // Unlock.
        lock_file.unlock().map_err(|e| HistoryError::Io {
            path: lock_path,
            source: e,
        })?;

        Ok(ScanId(scan_id_str))
    }

    /// List projects, sorted by id (deterministic).
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::Io`] on filesystem errors or
    /// [`HistoryError::Json`] if a `meta.json` is malformed.
    pub fn list_projects(&self) -> Result<Vec<(ProjectId, ProjectMeta)>, HistoryError> {
        let projects_dir = self.root.join(PROJECTS);
        if !projects_dir.exists() {
            return Ok(Vec::new());
        }
        let mut result = Vec::new();
        let mut entries: Vec<_> = fs::read_dir(&projects_dir)
            .map_err(|e| HistoryError::Io {
                path: projects_dir.clone(),
                source: e,
            })?
            .filter_map(std::result::Result::ok)
            .collect();
        entries.sort_by_key(fs::DirEntry::file_name);

        for entry in entries {
            let pid = ProjectId(entry.file_name().to_string_lossy().into_owned());
            let meta_path = entry.path().join(META);
            if !meta_path.exists() {
                continue;
            }
            let bytes = fs::read(&meta_path).map_err(|e| HistoryError::Io {
                path: meta_path.clone(),
                source: e,
            })?;
            let meta: ProjectMeta =
                serde_json::from_slice(&bytes).map_err(|e| HistoryError::Json {
                    path: meta_path,
                    source: e,
                })?;
            result.push((pid, meta));
        }
        Ok(result)
    }

    /// List scans for a project, sorted by id ascending (oldest first).
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::Io`] on filesystem errors or
    /// [`HistoryError::Json`] if a scan envelope is malformed.
    pub fn list_scans(&self, project: &ProjectId) -> Result<Vec<ScanIndexEntry>, HistoryError> {
        let scans_dir = self.project_dir(project).join(SCANS);
        if !scans_dir.exists() {
            return Ok(Vec::new());
        }
        let mut names: Vec<String> = fs::read_dir(&scans_dir)
            .map_err(|e| HistoryError::Io {
                path: scans_dir.clone(),
                source: e,
            })?
            .filter_map(|e| {
                e.ok().and_then(|de| {
                    let name = de.file_name().to_string_lossy().into_owned();
                    is_scan_json_file(&name).then_some(name)
                })
            })
            .collect();
        names.sort();

        let mut result = Vec::new();
        for name in names {
            let path = scans_dir.join(&name);
            let bytes = fs::read(&path).map_err(|e| HistoryError::Io {
                path: path.clone(),
                source: e,
            })?;
            let envelope: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|e| HistoryError::Json {
                    path: path.clone(),
                    source: e,
                })?;

            let id = envelope["scan_id"].as_str().unwrap_or_default().to_owned();
            let captured_at = envelope["captured_at"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let config_hash = envelope["config_hash"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let scores = envelope["report"]["scores"].clone();

            // Count findings by severity.
            let mut counts = serde_json::Map::new();
            if let Some(findings) = envelope["report"]["findings"].as_array() {
                for finding in findings {
                    if let Some(sev) = finding["severity"].as_str() {
                        let entry = counts
                            .entry(sev.to_owned())
                            .or_insert(serde_json::Value::Number(0.into()));
                        if let Some(n) = entry.as_i64() {
                            *entry = serde_json::Value::Number((n + 1).into());
                        }
                    }
                }
            }
            let finding_count_by_severity = serde_json::Value::Object(counts);

            // Read optional sidecar label.
            let stem = name.trim_end_matches(".json");
            let label = self.get_label(project, &ScanId(stem.to_owned()));

            result.push(ScanIndexEntry {
                id,
                captured_at,
                config_hash,
                scores,
                finding_count_by_severity,
                label,
            });
        }
        Ok(result)
    }

    /// Persist or clear the free-form label for a scan.
    ///
    /// Stores the label as `~/.zuit/projects/<hash>/scans/<scan_id>.label.json`.
    /// When `label` is `None` (or an empty string is treated as `None` by callers)
    /// the sidecar is deleted (idempotent).
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::Io`] on filesystem errors.
    ///
    /// # Panics
    ///
    /// Does not panic in practice; the `expect` inside serialises a static
    /// JSON literal that is always valid.
    pub fn set_label(
        &self,
        project: &ProjectId,
        scan: &ScanId,
        label: Option<&str>,
    ) -> Result<(), HistoryError> {
        let sidecar = self
            .project_dir(project)
            .join(SCANS)
            .join(format!("{}.label.json", scan.0));

        match label {
            None => {
                // Delete if it exists; ignore ENOENT.
                match fs::remove_file(&sidecar) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(HistoryError::Io {
                            path: sidecar,
                            source: e,
                        });
                    }
                }
            }
            Some(s) => {
                // Atomic write of `{"label": "<s>"}`.
                let bytes = serde_json::to_vec(&serde_json::json!({"label": s}))
                    .expect("invariant: serde_json::Value serializes");
                atomic_write(&sidecar, &bytes)?;
            }
        }
        Ok(())
    }

    /// Read the free-form label for a scan.
    ///
    /// Returns `None` when the sidecar is absent (no error).
    #[must_use]
    pub fn get_label(&self, project: &ProjectId, scan: &ScanId) -> Option<String> {
        let sidecar = self
            .project_dir(project)
            .join(SCANS)
            .join(format!("{}.label.json", scan.0));
        let bytes = fs::read(&sidecar).ok()?;
        let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        v["label"].as_str().map(str::to_owned)
    }

    /// Read the pre-computed analytics sidecar for a scan, if it exists.
    ///
    /// Returns `Ok(None)` when the sidecar is absent **or** cannot be
    /// deserialised (treat malformed as "regenerate me, don't 500").
    /// Returns `Ok(Some(_))` on success.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::Io`] only on unexpected filesystem errors other
    /// than `ENOENT`.
    pub fn read_scan_analytics(
        &self,
        project: &ProjectId,
        scan: &ScanId,
    ) -> Result<Option<ScanAnalytics>, HistoryError> {
        let path = self
            .project_dir(project)
            .join(SCANS)
            .join(format!("{}.analytics.json", scan.0));
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(HistoryError::Io { path, source: e });
            }
        };
        // Treat malformed JSON as "missing" — caller will regenerate.
        Ok(serde_json::from_slice::<ScanAnalytics>(&bytes).ok())
    }

    /// Write (or overwrite) the pre-computed analytics sidecar for a scan.
    ///
    /// Used by the HTTP router's lazy-regeneration path.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::Json`] if `analytics` cannot be serialised, or
    /// [`HistoryError::Io`] on filesystem errors.
    pub fn write_scan_analytics(
        &self,
        project: &ProjectId,
        scan: &ScanId,
        analytics: &ScanAnalytics,
    ) -> Result<(), HistoryError> {
        let path = self
            .project_dir(project)
            .join(SCANS)
            .join(format!("{}.analytics.json", scan.0));
        let bytes = serde_json::to_vec(analytics).map_err(|e| HistoryError::Json {
            path: path.clone(),
            source: e,
        })?;
        atomic_write(&path, &bytes)
    }

    /// Read a single scan's full JSON.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::NotFound`] if the scan does not exist, or
    /// [`HistoryError::Io`] on filesystem errors.
    pub fn read_scan(&self, project: &ProjectId, scan: &ScanId) -> Result<Vec<u8>, HistoryError> {
        let path = self
            .project_dir(project)
            .join(SCANS)
            .join(format!("{}.json", scan.0));
        if !path.exists() {
            return Err(HistoryError::NotFound(scan.0.clone()));
        }
        fs::read(&path).map_err(|e| HistoryError::Io { path, source: e })
    }

    /// Delete a single scan. `ENOENT` is treated as success (idempotent).
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::Io`] on filesystem errors other than `ENOENT`.
    pub fn delete_scan(&self, project: &ProjectId, scan: &ScanId) -> Result<(), HistoryError> {
        let p_dir = self.project_dir(project);
        let lock_path = p_dir.join(META_LOCK);
        let lock_file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| HistoryError::Io {
                path: lock_path.clone(),
                source: e,
            })?;
        lock_file.lock_exclusive().map_err(|e| HistoryError::Io {
            path: lock_path.clone(),
            source: e,
        })?;

        let scan_path = p_dir.join(SCANS).join(format!("{}.json", scan.0));
        match fs::remove_file(&scan_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(HistoryError::Io {
                    path: scan_path,
                    source: e,
                });
            }
        }

        lock_file.unlock().map_err(|e| HistoryError::Io {
            path: lock_path,
            source: e,
        })?;
        Ok(())
    }

    /// Delete an entire project directory (`<root>/projects/<hash>/`) and all its
    /// scans, configs, sidecars, and meta. Idempotent: missing directory is success.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::Io`] on filesystem errors other than `NotFound`.
    pub fn delete_project(&self, project: &ProjectId) -> Result<(), HistoryError> {
        let p_dir = self.project_dir(project);
        if !p_dir.exists() {
            return Ok(());
        }

        let lock_path = p_dir.join(META_LOCK);
        let lock_file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| HistoryError::Io {
                path: lock_path.clone(),
                source: e,
            })?;
        lock_file.lock_exclusive().map_err(|e| HistoryError::Io {
            path: lock_path.clone(),
            source: e,
        })?;

        match fs::remove_dir_all(&p_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(HistoryError::Io {
                    path: p_dir,
                    source: e,
                });
            }
        }

        // The lock fd stays valid on POSIX after the directory is removed; the
        // OS releases the lock when the fd is dropped at end of scope.
        Ok(())
    }

    /// Read a config snapshot's TOML bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HistoryError::NotFound`] if the config does not exist, or
    /// [`HistoryError::Io`] on filesystem errors.
    pub fn read_config(
        &self,
        project: &ProjectId,
        config: &ConfigId,
    ) -> Result<Vec<u8>, HistoryError> {
        let path = self
            .project_dir(project)
            .join(CONFIGS)
            .join(format!("{}.toml", config.0));
        if !path.exists() {
            return Err(HistoryError::NotFound(config.0.clone()));
        }
        fs::read(&path).map_err(|e| HistoryError::Io { path, source: e })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fixture_report() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "tool": {"name": "zuit", "version": "0.1.0"},
            "scores": {
                "maintainability": 90.0,
                "security": 100.0,
                "complexity": 100.0,
                "documentation": 80.0,
                "test_smell": 100.0
            },
            "findings": [],
            "stats": {"files_scanned": 1, "parse_failures": 0, "elapsed_ms": 1}
        }))
        .unwrap()
    }

    #[test]
    fn project_id_is_deterministic_per_path() {
        let p = Path::new("/tmp/foo");
        assert_eq!(HistoryStore::project_id(p), HistoryStore::project_id(p));
    }

    #[test]
    fn record_creates_directory_tree() {
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(tmp.path());
        let proj = tmp.path().join("project");
        std::fs::create_dir(&proj).unwrap();
        let id = store
            .record(&proj, b"[general]\n", &fixture_report(), 100)
            .unwrap();
        let pid = HistoryStore::project_id(&proj);
        let p_dir = tmp.path().join("projects").join(&pid.0);
        assert!(p_dir.is_dir());
        assert!(p_dir.join("meta.json").is_file());
        assert!(p_dir.join("scans").is_dir());
        assert!(p_dir.join("configs").is_dir());
        assert!(p_dir.join("scans").join(format!("{}.json", id.0)).is_file());
    }

    #[test]
    fn record_writes_unique_scan_ids_per_call() {
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(tmp.path());
        let proj = tmp.path().join("p");
        std::fs::create_dir(&proj).unwrap();
        let a = store.record(&proj, b"", &fixture_report(), 100).unwrap();
        let b = store.record(&proj, b"", &fixture_report(), 100).unwrap();
        assert_ne!(a.0, b.0);
    }

    #[test]
    fn record_dedups_identical_config() {
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(tmp.path());
        let proj = tmp.path().join("p");
        std::fs::create_dir(&proj).unwrap();
        store
            .record(&proj, b"[general]\n", &fixture_report(), 100)
            .unwrap();
        store
            .record(&proj, b"[general]\n", &fixture_report(), 100)
            .unwrap();
        let pid = HistoryStore::project_id(&proj);
        let cfg_dir = tmp.path().join("projects").join(&pid.0).join("configs");
        let count = std::fs::read_dir(&cfg_dir).unwrap().count();
        assert_eq!(count, 1, "identical configs should dedup");
    }

    #[test]
    fn record_writes_new_config_when_changed() {
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(tmp.path());
        let proj = tmp.path().join("p");
        std::fs::create_dir(&proj).unwrap();
        store.record(&proj, b"a", &fixture_report(), 100).unwrap();
        store.record(&proj, b"b", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&proj);
        let cfg_dir = tmp.path().join("projects").join(&pid.0).join("configs");
        let count = std::fs::read_dir(&cfg_dir).unwrap().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn retention_prunes_oldest_when_over_limit() {
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(tmp.path());
        let proj = tmp.path().join("p");
        std::fs::create_dir(&proj).unwrap();
        for _ in 0..5 {
            store.record(&proj, b"", &fixture_report(), 3).unwrap();
            // Sleep enough to advance the second-precision timestamp; the
            // 6-hex suffix breaks ties even within the same second.
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let pid = HistoryStore::project_id(&proj);
        let scans_dir = tmp.path().join("projects").join(&pid.0).join("scans");
        // Count only plain scan envelopes (excludes .label.json and .analytics.json
        // sidecars written alongside each envelope).
        let scan_count = std::fs::read_dir(&scans_dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|de| {
                let name = de.file_name().to_string_lossy().into_owned();
                is_scan_json_file(&name)
            })
            .count();
        assert_eq!(scan_count, 3);
    }

    #[test]
    fn list_projects_returns_recorded_projects_sorted() {
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(tmp.path());
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        store.record(&a, b"", &fixture_report(), 100).unwrap();
        store.record(&b, b"", &fixture_report(), 100).unwrap();
        let mut listed = store.list_projects().unwrap();
        listed.sort_by(|x, y| x.0.0.cmp(&y.0.0));
        let mut ids: Vec<String> = listed.iter().map(|(id, _)| id.0.clone()).collect();
        ids.sort();
        let mut expected = vec![
            HistoryStore::project_id(&a).0,
            HistoryStore::project_id(&b).0,
        ];
        expected.sort();
        assert_eq!(ids, expected);
    }

    #[test]
    fn list_scans_returns_summary_only() {
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(tmp.path());
        let proj = tmp.path().join("p");
        std::fs::create_dir(&proj).unwrap();
        store.record(&proj, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&proj);
        let scans = store.list_scans(&pid).unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].scores["maintainability"], 90.0);
    }

    #[test]
    fn delete_scan_removes_file_and_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(tmp.path());
        let proj = tmp.path().join("p");
        std::fs::create_dir(&proj).unwrap();
        let id = store.record(&proj, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&proj);
        store.delete_scan(&pid, &id).unwrap();
        store.delete_scan(&pid, &id).unwrap(); // idempotent
        let scans = store.list_scans(&pid).unwrap();
        assert!(scans.is_empty());
    }

    #[test]
    fn read_config_round_trips_toml_bytes() {
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(tmp.path());
        let proj = tmp.path().join("p");
        std::fs::create_dir(&proj).unwrap();
        let toml = b"[general]\nfollow_symlinks = true\n";
        store.record(&proj, toml, &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&proj);
        let scans = store.list_scans(&pid).unwrap();
        let cfg_id = ConfigId(scans[0].config_hash.clone());
        let bytes = store.read_config(&pid, &cfg_id).unwrap();
        assert_eq!(bytes, toml);
    }

    // ── label_set_get_round_trip ─────────────────────────────────────────────

    #[test]
    fn label_set_get_round_trip() {
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(tmp.path());
        let proj = tmp.path().join("p");
        std::fs::create_dir(&proj).unwrap();
        let id = store.record(&proj, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&proj);

        assert_eq!(store.get_label(&pid, &id), None);

        store.set_label(&pid, &id, Some("release")).unwrap();
        assert_eq!(store.get_label(&pid, &id), Some("release".to_owned()));
    }

    // ── label_clear ──────────────────────────────────────────────────────────

    #[test]
    fn label_clear() {
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(tmp.path());
        let proj = tmp.path().join("p");
        std::fs::create_dir(&proj).unwrap();
        let id = store.record(&proj, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&proj);

        store.set_label(&pid, &id, Some("release")).unwrap();
        assert_eq!(store.get_label(&pid, &id), Some("release".to_owned()));

        // Clear by passing None.
        store.set_label(&pid, &id, None).unwrap();
        assert_eq!(store.get_label(&pid, &id), None);

        // Clearing again is idempotent.
        store.set_label(&pid, &id, None).unwrap();
        assert_eq!(store.get_label(&pid, &id), None);
    }

    // ── label_replace ────────────────────────────────────────────────────────

    #[test]
    fn label_replace() {
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(tmp.path());
        let proj = tmp.path().join("p");
        std::fs::create_dir(&proj).unwrap();
        let id = store.record(&proj, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&proj);

        store.set_label(&pid, &id, Some("v1")).unwrap();
        store.set_label(&pid, &id, Some("v2")).unwrap();
        assert_eq!(store.get_label(&pid, &id), Some("v2".to_owned()));
    }

    // ── label_surfaces_in_list_scans ─────────────────────────────────────────

    #[test]
    fn label_surfaces_in_list_scans() {
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(tmp.path());
        let proj = tmp.path().join("p");
        std::fs::create_dir(&proj).unwrap();
        let id = store.record(&proj, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&proj);

        store.set_label(&pid, &id, Some("broken main")).unwrap();

        let scans = store.list_scans(&pid).unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].label.as_deref(), Some("broken main"));
    }

    // ── label_absent_in_list_scans_when_not_set ──────────────────────────────

    #[test]
    fn label_absent_in_list_scans_when_not_set() {
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(tmp.path());
        let proj = tmp.path().join("p");
        std::fs::create_dir(&proj).unwrap();
        store.record(&proj, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&proj);

        let scans = store.list_scans(&pid).unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].label, None);
    }

    // ── delete_project ──────────────────────────────────────────────────────

    #[test]
    fn delete_project_removes_dir_and_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(tmp.path());
        let proj = tmp.path().join("p");
        std::fs::create_dir(&proj).unwrap();
        store.record(&proj, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&proj);
        store.record(&proj, b"", &fixture_report(), 100).unwrap();

        store.delete_project(&pid).unwrap();

        // project must no longer appear in list_projects
        let projects = store.list_projects().unwrap();
        assert!(!projects.iter().any(|(p, _)| p == &pid));

        // the directory must be gone
        let p_dir = tmp.path().join("projects").join(&pid.0);
        assert!(!p_dir.exists());

        // second call must return Ok (idempotent)
        store.delete_project(&pid).unwrap();
    }

    // ── SEC-H: directory mode 0o700 ──────────────────────────────────────────

    /// Verify that `record` creates the project directory tree with mode 0o700.
    #[test]
    #[cfg(unix)]
    fn record_creates_dirs_with_mode_0o700() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = TempDir::new().unwrap();
        let store = HistoryStore::open(tmp.path());
        let proj = tmp.path().join("p");
        std::fs::create_dir(&proj).unwrap();
        store.record(&proj, b"", &fixture_report(), 100).unwrap();
        let pid = HistoryStore::project_id(&proj);
        let p_dir = tmp.path().join("projects").join(&pid.0);
        let scans_dir = p_dir.join("scans");
        let configs_dir = p_dir.join("configs");
        for dir in [&p_dir, &scans_dir, &configs_dir] {
            let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                0o700,
                "expected mode 0o700 for {}, got 0o{mode:o}",
                dir.display()
            );
        }
    }
}
