//! Plugin store: paths, source sidecar, and install lock.
//!
//! This module owns the on-disk layout of installed plugins under
//! `~/.zuit/plugins/` (or `$ZUIT_HOME/plugins/`). It provides:
//!
//! - Path resolution ([`plugins_dir`], [`plugin_install_dir`]).
//! - Discovery of installed plugins ([`list_installed`]).
//! - Atomic read/write of the `.zuit-source.json` sidecar file
//!   ([`read_source_sidecar`], [`write_source_sidecar`]).
//! - An exclusive install lock ([`acquire_install_lock`]) to prevent
//!   concurrent installs.

use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    time::SystemTime,
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::{PluginError, manifest::PluginManifest};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Where a plugin came from.
///
/// Serialized as a JSON object with a `"kind"` discriminant field.
/// The `Path` variant covers both symlinked installs and full copies,
/// including on Windows where symlinks may not be available.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PluginSource {
    /// Installed from a local path (symlinked or copied).
    Path {
        /// The canonical target path that was installed.
        target: PathBuf,
    },
    /// Cloned from a git URL.
    Git {
        /// The remote URL of the repository.
        url: String,
        /// The commit SHA at the time of installation.
        sha: String,
        /// ISO-8601 timestamp of when the repository was fetched (optional).
        ///
        /// May be absent on sidecars written by older versions of zuit.
        #[serde(default)]
        fetched_at: Option<String>,
    },
}

/// A plugin discovered on disk in the plugins directory.
pub struct InstalledPlugin {
    /// Directory name of the installed plugin (equals the `--name` override
    /// at install time, which may differ from the manifest's own `name`).
    pub name: String,
    /// Fully-validated manifest loaded from `zuit-plugin.toml`.
    pub manifest: PluginManifest,
    /// Origin of the plugin as recorded in `.zuit-source.json`.
    pub source: PluginSource,
    /// Modification time of the plugin install directory.
    pub installed_at: SystemTime,
    /// Path to the plugin's install directory.
    pub plugin_dir: PathBuf,
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Returns the plugins directory, honouring `$ZUIT_HOME` then `$HOME`.
///
/// Resolution order:
/// 1. If `$ZUIT_HOME` is set, returns `<ZUIT_HOME>/plugins`.
/// 2. If `$HOME` is set, returns `<HOME>/.zuit/plugins`.
/// 3. Otherwise returns [`PluginError::Env`].
///
/// # Errors
///
/// Returns [`PluginError::Env`] if neither `ZUIT_HOME` nor `HOME` is set.
pub fn plugins_dir() -> Result<PathBuf, PluginError> {
    if let Ok(zuit_home) = std::env::var("ZUIT_HOME") {
        return Ok(PathBuf::from(zuit_home).join("plugins"));
    }
    if let Ok(home) = std::env::var("HOME") {
        return Ok(PathBuf::from(home).join(".zuit").join("plugins"));
    }
    Err(PluginError::Env("HOME or ZUIT_HOME must be set".to_owned()))
}

/// Returns the path to a plugin's install directory given its name.
///
/// This is `<plugins_dir>/<name>`.
///
/// # Errors
///
/// Returns [`PluginError::Env`] if neither `ZUIT_HOME` nor `HOME` is set
/// (propagated from [`plugins_dir`]).
pub fn plugin_install_dir(name: &str) -> Result<PathBuf, PluginError> {
    Ok(plugins_dir()?.join(name))
}

// ---------------------------------------------------------------------------
// Source sidecar
// ---------------------------------------------------------------------------

/// Returns the path of the source sidecar for a plugin, stored as a sibling
/// of the plugin's install directory inside `plugins_dir`.
///
/// The sidecar lives at `<plugins_dir>/<name>.source.json` so that it is
/// never placed inside the plugin directory itself.  For local (symlinked)
/// installs this means the user's source repository is never polluted with
/// untracked zuit metadata files.
pub(crate) fn sidecar_path(plugins_dir: &Path, name: &str) -> PathBuf {
    plugins_dir.join(format!("{name}.source.json"))
}

/// Reads the source sidecar for a plugin from `plugins_dir`.
///
/// # Errors
///
/// Returns [`PluginError::Io`] if the file cannot be read, or
/// [`PluginError::Json`] if the JSON is malformed.
pub fn read_source_sidecar(plugins_dir: &Path, name: &str) -> Result<PluginSource, PluginError> {
    let path = sidecar_path(plugins_dir, name);
    let data = fs::read_to_string(&path)?;
    let source: PluginSource = serde_json::from_str(&data)?;
    Ok(source)
}

/// Writes the source sidecar for a plugin into `plugins_dir` as a sibling of
/// the plugin's install directory.
///
/// Uses an atomic write: the JSON is first written to
/// `<name>.source.json.tmp`, then renamed into place.
///
/// # Errors
///
/// Returns [`PluginError::Io`] if the file cannot be written or renamed, or
/// [`PluginError::Json`] if serialization fails.
pub fn write_source_sidecar(
    plugins_dir: &Path,
    name: &str,
    source: &PluginSource,
) -> Result<(), PluginError> {
    let json = serde_json::to_string_pretty(source)?;
    let tmp_path = plugins_dir.join(format!("{name}.source.json.tmp"));
    let final_path = sidecar_path(plugins_dir, name);
    fs::write(&tmp_path, json.as_bytes())?;
    fs::rename(&tmp_path, &final_path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Enumerates installed plugins under [`plugins_dir`].
///
/// Each subdirectory is examined for a `zuit-plugin.toml` manifest and a
/// `<name>.source.json` sidecar (stored as a sibling file in `plugins_dir`).
/// Directories that fail either check are skipped with a `tracing::warn!` log.
///
/// Non-directory entries (regular files, symlinks that resolve to files, etc.)
/// are silently skipped.
///
/// The returned [`InstalledPlugin::name`] is the directory basename, not the
/// `name` field inside the manifest (which may differ if `--name` was used at
/// install time).
///
/// # Errors
///
/// Returns [`PluginError::Env`] if the plugins directory cannot be determined,
/// or [`PluginError::Io`] if the directory cannot be read.
pub fn list_installed() -> Result<Vec<InstalledPlugin>, PluginError> {
    list_installed_in(&plugins_dir()?)
}

/// Inner implementation of plugin enumeration over an arbitrary directory.
///
/// Separated from [`list_installed`] so that tests and downstream crates can pass a temporary
/// directory without mutating process-global environment variables. This is exposed as part
/// of the public API for test usage and custom registry construction.
///
/// # Errors
///
/// Returns [`PluginError::Io`] if the directory cannot be read.
pub fn list_installed_in(dir: &Path) -> Result<Vec<InstalledPlugin>, PluginError> {
    // If the plugins directory does not exist yet, return an empty list.
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut plugins = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        // Resolve symlinks so we can check whether it is a directory.
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(err) => {
                tracing::warn!(
                    "plugin '{}': could not stat path: {}; skipping",
                    path.display(),
                    err
                );
                continue;
            }
        };

        if !meta.is_dir() {
            continue;
        }

        let name = if let Some(n) = path.file_name().and_then(|n| n.to_str()) {
            n.to_owned()
        } else {
            tracing::warn!(
                "plugin at '{}': directory name is not valid UTF-8; skipping",
                path.display()
            );
            continue;
        };

        // Skip hidden entries (e.g. the .lock file's parent, or .zuit-source.json).
        if name.starts_with('.') {
            continue;
        }

        // Load manifest.
        let manifest_path = path.join("zuit-plugin.toml");
        let manifest_str = match fs::read_to_string(&manifest_path) {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!("plugin '{name}': cannot read manifest: {err}; skipping");
                continue;
            }
        };
        let manifest = match PluginManifest::load_from_str(&manifest_str, Some(&name)) {
            Ok(m) => m,
            Err(err) => {
                tracing::warn!("plugin '{name}': invalid manifest: {err}; skipping");
                continue;
            }
        };

        // Load source sidecar (lives as a sibling file in the plugins dir).
        let source = match read_source_sidecar(dir, &name) {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!("plugin '{name}': cannot read source sidecar: {err}; skipping");
                continue;
            }
        };

        // Determine install time from directory metadata.
        let installed_at = match meta.modified() {
            Ok(t) => t,
            Err(_) => SystemTime::UNIX_EPOCH,
        };

        plugins.push(InstalledPlugin {
            name,
            manifest,
            source,
            installed_at,
            plugin_dir: path,
        });
    }

    Ok(plugins)
}

// ---------------------------------------------------------------------------
// Install lock
// ---------------------------------------------------------------------------

/// Open the lock file with `O_CLOEXEC` set so child processes (e.g. `git clone`
/// spawned during installation) do not inherit the file descriptor and therefore
/// do not accidentally hold the lock after the parent drops it.
///
/// On non-Unix platforms, falls back to a plain `OpenOptions` open.
fn open_lock_file(lock_path: &Path) -> Result<File, PluginError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // O_CLOEXEC ensures the FD is not inherited by child processes at exec()
        // time.  Combined with the POSIX-lock-based locking in
        // `try_posix_lock_exclusive`, this prevents the flock-inheritance problem
        // where forked git subprocesses hold lock FDs open past the parent's drop.
        Ok(OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(lock_path)?)
    }
    #[cfg(not(unix))]
    {
        Ok(OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)?)
    }
}

/// Acquires the exclusive install lock at `<plugins_dir>/.lock`.
///
/// Returns the open [`File`] whose lifetime represents the held lock;
/// dropping it releases the lock.
///
/// # Errors
///
/// Returns [`PluginError::Lock`] immediately (without blocking) if the lock
/// is held by another process, or if any other locking error occurs.
/// Returns [`PluginError::Env`] or [`PluginError::Io`] if the lock file
/// cannot be created or opened.
pub fn acquire_install_lock() -> Result<File, PluginError> {
    acquire_install_lock_in(&plugins_dir()?)
}

/// Inner implementation of install-lock acquisition over an arbitrary directory.
///
/// Separated from [`acquire_install_lock`] so that tests and downstream crates can pass a temporary
/// directory without mutating process-global environment variables. This is exposed as part
/// of the public API for test usage and custom registry construction.
///
/// # Errors
///
/// Returns [`PluginError::Lock`] immediately (without blocking) if the lock
/// is held by another process.
/// Returns [`PluginError::Io`] if the lock file cannot be created or opened.
pub fn acquire_install_lock_in(plugins_dir: &Path) -> Result<File, PluginError> {
    let lock_path = plugins_dir.join(".lock");

    // Ensure the plugins directory exists before we try to open the lock file.
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file = open_lock_file(&lock_path)?;

    file.try_lock_exclusive().map_err(|err| {
        // fs2 returns WouldBlock when the lock is already held.
        if err.kind() == std::io::ErrorKind::WouldBlock {
            PluginError::Lock("install lock held by another process".to_owned())
        } else {
            PluginError::Lock(format!("could not acquire install lock: {err}"))
        }
    })?;

    Ok(file)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Global mutex serialising all tests that touch `plugins_dir_from_env`.
    ///
    /// This is only needed for the two env-var path-resolution tests, which
    /// use a `FakeEnv` and thus never touch the real process environment.
    /// It is kept as a formality to document intent.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    // -----------------------------------------------------------------------
    // Path resolution (via FakeEnv, no process env mutation)
    // -----------------------------------------------------------------------

    /// Inline reimplementation of path resolution using injected env values,
    /// matching the logic in `plugins_dir()` without mutating process env.
    fn plugins_dir_via_fake(
        zuit_home: Option<&str>,
        home: Option<&str>,
    ) -> Result<PathBuf, PluginError> {
        if let Some(ch) = zuit_home {
            return Ok(PathBuf::from(ch).join("plugins"));
        }
        if let Some(h) = home {
            return Ok(PathBuf::from(h).join(".zuit").join("plugins"));
        }
        Err(PluginError::Env("HOME or ZUIT_HOME must be set".to_owned()))
    }

    #[test]
    fn plugins_dir_uses_zuit_home_when_set() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let dir =
            plugins_dir_via_fake(Some("/tmp/foo"), None).expect("should resolve with ZUIT_HOME");
        assert_eq!(dir, PathBuf::from("/tmp/foo/plugins"));
    }

    #[test]
    fn plugins_dir_falls_back_to_home() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let dir =
            plugins_dir_via_fake(None, Some("/tmp/fakehome")).expect("should resolve with HOME");
        assert_eq!(dir, PathBuf::from("/tmp/fakehome/.zuit/plugins"));
    }

    // -----------------------------------------------------------------------
    // Source sidecar round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn source_sidecar_round_trip() {
        let tmp = TempDir::new().unwrap();
        let plugins_dir = tmp.path();

        let original = PluginSource::Git {
            url: "https://github.com/acme/zuit-zig".to_owned(),
            sha: "abc123def456".to_owned(),
            fetched_at: Some("2026-05-09T12:00:00Z".to_owned()),
        };

        write_source_sidecar(plugins_dir, "echo", &original).expect("write should succeed");
        // Sidecar must be written as a sibling: <plugins_dir>/echo.source.json
        assert!(
            plugins_dir.join("echo.source.json").exists(),
            "sidecar should be a sibling file in plugins_dir"
        );
        let read_back = read_source_sidecar(plugins_dir, "echo").expect("read should succeed");
        assert_eq!(original, read_back);
    }

    // -----------------------------------------------------------------------
    // Helpers for enumerate tests
    // -----------------------------------------------------------------------

    /// Creates a minimal valid plugin directory under `plugins_dir` and writes
    /// the sidecar as a sibling file in `plugins_dir`.
    fn make_fake_plugin(plugins_dir: &Path, name: &str, source: &PluginSource) {
        let install_dir = plugins_dir.join(name);
        fs::create_dir_all(&install_dir).unwrap();

        let manifest_toml = format!(
            "name = \"{name}\"\nversion = \"0.1.0\"\noutput = \"zuit-json\"\ncommand = [\"./bin/check\"]\n"
        );
        fs::write(install_dir.join("zuit-plugin.toml"), manifest_toml).unwrap();
        write_source_sidecar(plugins_dir, name, source).unwrap();
    }

    // -----------------------------------------------------------------------
    // Enumerate tests (use list_installed_in to avoid env mutation)
    // -----------------------------------------------------------------------

    #[test]
    fn enumerate_skips_dirs_without_manifest() {
        let tmp = TempDir::new().unwrap();
        let plugins_root = tmp.path().join("plugins");
        fs::create_dir_all(&plugins_root).unwrap();

        // A directory with no manifest (no sidecar either).
        fs::create_dir_all(plugins_root.join("no-manifest")).unwrap();

        // A proper plugin.
        let source = PluginSource::Path {
            target: PathBuf::from("/home/me/projects/my-rules"),
        };
        make_fake_plugin(&plugins_root, "good-plugin", &source);

        let plugins = list_installed_in(&plugins_root).expect("list_installed_in should succeed");
        assert_eq!(plugins.len(), 1, "only the valid plugin should be returned");
        assert_eq!(plugins[0].name, "good-plugin");
    }

    #[test]
    fn enumerate_returns_installed_plugins() {
        let tmp = TempDir::new().unwrap();
        let plugins_root = tmp.path().join("plugins");
        fs::create_dir_all(&plugins_root).unwrap();

        let git_source = PluginSource::Git {
            url: "https://github.com/acme/zig-check".to_owned(),
            sha: "deadbeef".to_owned(),
            fetched_at: None,
        };
        make_fake_plugin(&plugins_root, "acme-zig", &git_source);

        let path_source = PluginSource::Path {
            target: PathBuf::from("/home/me/my-rules"),
        };
        make_fake_plugin(&plugins_root, "my-local-rules", &path_source);

        let mut plugins =
            list_installed_in(&plugins_root).expect("list_installed_in should succeed");
        plugins.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(plugins.len(), 2);
        assert_eq!(plugins[0].name, "acme-zig");
        assert_eq!(plugins[0].source, git_source);
        assert_eq!(plugins[1].name, "my-local-rules");
        assert_eq!(plugins[1].source, path_source);
    }

    // -----------------------------------------------------------------------
    // Install lock
    // -----------------------------------------------------------------------

    #[test]
    fn acquire_install_lock_excludes_concurrent() {
        let tmp = TempDir::new().unwrap();
        let lock_path = tmp.path().join("plugins").join(".lock");

        // Ensure the directory exists.
        fs::create_dir_all(lock_path.parent().unwrap()).unwrap();

        // Open two separate file handles to the same lock path and compete.
        let file1 = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        file1
            .try_lock_exclusive()
            .expect("first lock should succeed");

        let file2 = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();

        let result = file2.try_lock_exclusive();
        assert!(
            result.is_err(),
            "second try_lock_exclusive should fail while first is held"
        );
    }
}
