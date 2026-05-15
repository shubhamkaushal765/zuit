//! Plugin installation: local-path and git-URL variants.
//!
//! # Local-path install (`install_local`)
//!
//! On Unix the plugin directory is **symlinked** into the plugins store so
//! that edits to the source directory are immediately visible without
//! re-installing.  On Windows, where symlinks often require elevated
//! privileges, the directory is **recursively copied** instead; a warning is
//! emitted and the sidecar still records the original path so a future
//! `update` command can re-copy.
//!
//! # Git install (`install_git`)
//!
//! Performs a shallow clone (`git clone --depth 1`) into the plugins store.
//! No timeout is applied to the clone; users should abort with Ctrl-C if the
//! remote is unresponsive.  The name is resolved in two passes:
//!
//! 1. Pre-clone: derive a tentative slug from the URL (or use `name_override`).
//! 2. Post-clone: the manifest's `name` field is used as the final install name
//!    (unless `name_override` was set, in which case the override always wins).

use std::{fs, path::Path, process::Command, time::SystemTime};

use crate::{
    PluginError,
    manifest::PluginManifest,
    store::{self, InstalledPlugin, PluginSource},
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Install a plugin from a local directory (symlinked on Unix, copied on Windows).
///
/// `path` must point at a directory containing a valid `zuit-plugin.toml`.
/// If `name_override` is `Some`, that name is used as the install-directory
/// name; otherwise the manifest's `name` field is used.  Returns the installed
/// plugin descriptor.
///
/// # Errors
///
/// - [`PluginError::LocalPath`] if `path` is not a directory or the manifest
///   is missing.
/// - [`PluginError::Manifest`] / [`PluginError::Toml`] if the manifest is
///   invalid.
/// - [`PluginError::AlreadyInstalled`] if a plugin with the resolved name is
///   already present.
/// - [`PluginError::Lock`] if the install lock cannot be acquired.
/// - [`PluginError::Env`] if the plugins directory cannot be determined.
pub fn install_local(
    path: &Path,
    name_override: Option<&str>,
) -> Result<InstalledPlugin, PluginError> {
    let plugins_dir = store::plugins_dir()?;
    install_local_in(&plugins_dir, path, name_override)
}

// ---------------------------------------------------------------------------
// Inner implementation (pub so downstream tests and custom registries can inject a temp plugins_dir)
// ---------------------------------------------------------------------------

/// Inner implementation of [`install_local`] over an explicit `plugins_dir`.
///
/// Tests and downstream crates (e.g. `zuit-registry`) use this to avoid mutating
/// process-global environment variables. This is exposed as part of the public API
/// for test usage and custom registry construction.
///
/// # Errors
///
/// - [`PluginError::LocalPath`] if `path` is not a directory or the manifest
///   is missing.
/// - [`PluginError::Manifest`] / [`PluginError::Toml`] if the manifest is
///   invalid.
/// - [`PluginError::AlreadyInstalled`] if a plugin with the resolved name is
///   already present.
/// - [`PluginError::Lock`] if the install lock cannot be acquired.
pub fn install_local_in(
    plugins_dir: &Path,
    path: &Path,
    name_override: Option<&str>,
) -> Result<InstalledPlugin, PluginError> {
    // Validate that `path` is a directory.
    if !path.is_dir() {
        return Err(PluginError::LocalPath(format!(
            "not a directory: {}",
            path.display()
        )));
    }

    // Load and validate the manifest.
    let manifest_path = path.join("zuit-plugin.toml");
    let toml_str = fs::read_to_string(&manifest_path)
        .map_err(|_| PluginError::LocalPath("manifest not found: zuit-plugin.toml".to_owned()))?;

    // Parse with manifest's own name taking effect; we apply the override after.
    let mut manifest = PluginManifest::load_from_str(&toml_str, None)?;

    // Apply name_override: if caller provided one, it wins over the manifest name.
    if let Some(override_name) = name_override {
        // If rule_id_prefix was auto-derived from the manifest name, update it
        // to reflect the new install name.
        let manifest_default_prefix = format!("{}/", manifest.name);
        if manifest.rule_id_prefix == manifest_default_prefix {
            manifest.rule_id_prefix = format!("{override_name}/");
        }
        override_name.clone_into(&mut manifest.name);
    }

    let name = manifest.name.clone();

    // Acquire the exclusive install lock for the duration of the install.
    let _lock = store::acquire_install_lock_in(plugins_dir)?;

    // Refuse if a plugin with this name already exists.
    let target_dir = plugins_dir.join(&name);
    if target_dir.exists() {
        return Err(PluginError::AlreadyInstalled(name));
    }

    // Canonicalize the source path so the sidecar always holds an absolute path.
    let canonical_target = fs::canonicalize(path)?;

    // Install: symlink on Unix, recursive copy on Windows.
    do_install(&canonical_target, &target_dir)?;

    // Write the source sidecar as a sibling file in plugins_dir (not inside the
    // installed directory / symlink target), so the user's source repo is never
    // polluted with untracked zuit metadata.
    let source = PluginSource::Path {
        target: canonical_target.clone(),
    };
    store::write_source_sidecar(plugins_dir, &name, &source)?;

    Ok(InstalledPlugin {
        name,
        manifest,
        source,
        installed_at: SystemTime::now(),
        plugin_dir: target_dir,
    })
}

// ---------------------------------------------------------------------------
// Git install
// ---------------------------------------------------------------------------

/// Install a plugin by cloning a git URL (shallow, depth 1).
///
/// Name resolution (two-pass):
///
/// 1. **Pre-clone**: tentative name = `name_override` → `derive_name_from_url(url)`.
///    If neither can produce a name, returns `PluginError::Git { stage: "name", … }`.
/// 2. **Post-clone**: if `name_override` is `None`, the manifest's `name` field is
///    used as the final install name, and the cloned directory is renamed accordingly
///    (the tentative slug directory is moved).  If renaming would collide with an
///    existing plugin, the cloned directory is deleted and `AlreadyInstalled` is returned.
///
/// No network timeout is applied; abort with Ctrl-C if the remote is unresponsive.
///
/// # Errors
///
/// - [`PluginError::Git`] if `git clone` or `git rev-parse` fails.
/// - [`PluginError::AlreadyInstalled`] if a plugin with the resolved name is already present.
/// - [`PluginError::Manifest`] / [`PluginError::Toml`] if the cloned manifest is invalid
///   (the cloned directory is removed before returning).
/// - [`PluginError::Lock`] if the install lock cannot be acquired.
pub fn install_git(url: &str, name_override: Option<&str>) -> Result<InstalledPlugin, PluginError> {
    let plugins_dir = store::plugins_dir()?;
    install_git_in(&plugins_dir, url, name_override)
}

/// Inner implementation of [`install_git`] over an explicit `plugins_dir`.
///
/// Tests and downstream crates use this to avoid mutating process-global environment variables.
/// This is exposed as part of the public API for test usage and custom registry construction.
///
/// # Errors
///
/// - [`PluginError::Git`] if `git clone` or `git rev-parse` fails.
/// - [`PluginError::AlreadyInstalled`] if a plugin with the resolved name is already present.
/// - [`PluginError::Manifest`] / [`PluginError::Toml`] if the cloned manifest is invalid
///   (the cloned directory is removed before returning).
/// - [`PluginError::Lock`] if the install lock cannot be acquired.
pub fn install_git_in(
    plugins_dir: &Path,
    url: &str,
    name_override: Option<&str>,
) -> Result<InstalledPlugin, PluginError> {
    // Acquire a single lock that is held for the entire install operation,
    // including the git clone.  O_CLOEXEC is set on the lock fd (see
    // `store::open_lock_file`), so `posix_spawn` (used by std::process::Command
    // on macOS) does NOT propagate the fd to git.  A single lock window
    // eliminates the TOCTOU race that a split-lock approach would introduce.
    let _lock = store::acquire_install_lock_in(plugins_dir)?;

    // Pass 1 (pre-clone): resolve the tentative name and check for duplicates.
    let tentative_name = if let Some(n) = name_override {
        n.to_owned()
    } else {
        derive_name_from_url(url).ok_or_else(|| PluginError::Git {
            stage: "name",
            message: format!("cannot derive plugin name from URL: {url}"),
        })?
    };
    let tentative_dir = plugins_dir.join(&tentative_name);
    if tentative_dir.exists() {
        return Err(PluginError::AlreadyInstalled(tentative_name));
    }

    // Clone + rev-parse + manifest load (lock still held; O_CLOEXEC keeps the
    // fd from being inherited by the git child process).
    let dir_str = tentative_dir.to_string_lossy().into_owned();

    let clone_out = Command::new("git")
        .args(["clone", "--depth", "1", url, &dir_str])
        .output()
        .map_err(|e| PluginError::Git {
            stage: "clone",
            message: format!("failed to spawn git: {e}"),
        })?;
    if !clone_out.status.success() {
        return Err(PluginError::Git {
            stage: "clone",
            message: String::from_utf8_lossy(&clone_out.stderr).into_owned(),
        });
    }

    let rev_out = Command::new("git")
        .args(["-C", &dir_str, "rev-parse", "HEAD"])
        .output()
        .map_err(|e| {
            let _ = fs::remove_dir_all(&tentative_dir);
            PluginError::Git {
                stage: "rev-parse",
                message: format!("failed to spawn git: {e}"),
            }
        })?;
    if !rev_out.status.success() {
        let _ = fs::remove_dir_all(&tentative_dir);
        return Err(PluginError::Git {
            stage: "rev-parse",
            message: String::from_utf8_lossy(&rev_out.stderr).into_owned(),
        });
    }
    let sha = String::from_utf8_lossy(&rev_out.stdout).trim().to_owned();

    let manifest_path = tentative_dir.join("zuit-plugin.toml");
    let toml_str = fs::read_to_string(&manifest_path).map_err(|e| {
        let _ = fs::remove_dir_all(&tentative_dir);
        PluginError::Git {
            stage: "manifest",
            message: format!("cannot read zuit-plugin.toml: {e}"),
        }
    })?;
    let manifest = PluginManifest::load_from_str(&toml_str, None).inspect_err(|_e| {
        let _ = fs::remove_dir_all(&tentative_dir);
    })?;

    // Pass 2 (post-clone): if name_override was None, use the manifest name as
    // the final install name and rename the cloned directory accordingly.
    let final_name = if let Some(n) = name_override {
        n.to_owned()
    } else {
        manifest.name.clone()
    };
    let final_dir = plugins_dir.join(&final_name);
    if final_name != tentative_name {
        if final_dir.exists() {
            let _ = fs::remove_dir_all(&tentative_dir);
            return Err(PluginError::AlreadyInstalled(final_name));
        }
        fs::rename(&tentative_dir, &final_dir)?;
    }

    let fetched_at = {
        use time::format_description::well_known::Rfc3339;
        time::OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::new())
    };
    let source = PluginSource::Git {
        url: url.to_owned(),
        sha,
        fetched_at: Some(fetched_at),
    };
    if let Err(e) = store::write_source_sidecar(plugins_dir, &final_name, &source) {
        let _ = fs::remove_dir_all(&final_dir);
        return Err(e);
    }
    Ok(InstalledPlugin {
        name: final_name,
        manifest,
        source,
        installed_at: SystemTime::now(),
        plugin_dir: final_dir,
    })
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `arg` looks like a git URL (per spec §7 rules).
///
/// Detection rules (applied in order):
///
/// 1. Starts with `http://`, `https://`, `git://`, or `ssh://` → git.
/// 2. Ends with `.git` → git.
/// 3. Matches the bare scp-style pattern `user@host:path` (i.e.
///    `^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+:`) → git.
/// 4. Otherwise → local path (returns `false`).
#[must_use]
pub fn looks_like_git_url(arg: &str) -> bool {
    // Rule 1: protocol prefix
    if arg.starts_with("http://")
        || arg.starts_with("https://")
        || arg.starts_with("git://")
        || arg.starts_with("ssh://")
    {
        return true;
    }
    // Rule 2: .git suffix (case-insensitive per clippy recommendation)
    if std::path::Path::new(arg)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("git"))
    {
        return true;
    }
    // Rule 3: scp-style `user@host:path`
    // The pattern ^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+: matches git@github.com:foo/bar
    if is_scp_git_url(arg) {
        return true;
    }
    false
}

/// Returns `true` if `s` matches the bare scp-style git URL pattern
/// `^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+:`.
fn is_scp_git_url(s: &str) -> bool {
    // Split on '@'; the part before must be non-empty and all [A-Za-z0-9_.-].
    let Some((user, rest)) = s.split_once('@') else {
        return false;
    };
    if user.is_empty()
        || !user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return false;
    }
    // rest must contain ':' preceded by [A-Za-z0-9_.-]+ (the host).
    let Some((host, _path)) = rest.split_once(':') else {
        return false;
    };
    !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Derives a plugin name slug from a git URL.
///
/// Rules:
/// 1. Strip a trailing `.git` if present.
/// 2. Strip any trailing slashes.
/// 3. For protocol-prefixed URLs (`http://`, `https://`, `git://`, `ssh://`):
///    strip the prefix and the host component; the slug is the last `/`-separated
///    segment of the remaining path.  If no path segment remains, return `None`.
/// 4. For scp-style URLs (`user@host:path`): take everything after the `:` as the
///    path, then take the last `/`-separated segment.
/// 5. For everything else: take the last `/`-separated segment (or the whole string
///    if no `/` is present).
/// 6. Return `None` if the slug is empty.
///
/// Examples:
/// - `https://github.com/acme/zuit-zig.git` → `Some("zuit-zig")`
/// - `git@github.com:acme/zuit-zig.git`     → `Some("zuit-zig")`
/// - `ssh://git@host/foo/bar`                    → `Some("bar")`
/// - `https://example.com/`                      → `None`
/// - `""` (empty)                                → `None`
/// - `acme-zig`                                  → `Some("acme-zig")`
pub(crate) fn derive_name_from_url(url: &str) -> Option<String> {
    // Strip trailing `.git`.
    let s = url.strip_suffix(".git").unwrap_or(url);
    // Strip any trailing slashes.
    let s = s.trim_end_matches('/');

    if s.is_empty() {
        return None;
    }

    // Determine the "path" portion by stripping protocol+host for scheme URLs,
    // or stripping user@host: for scp-style URLs.
    let path: &str = {
        let known_schemes: &[&str] = &["https://", "http://", "git://", "ssh://"];
        if let Some(after_scheme) = known_schemes.iter().find_map(|pfx| s.strip_prefix(pfx)) {
            // Strip the host (everything up to and including the first '/').
            match after_scheme.find('/') {
                Some(slash_pos) => &after_scheme[slash_pos..], // keeps leading '/'
                None => return None,                           // bare host, no path
            }
        } else if let Some(colon_pos) = s.find(':') {
            // Check if this looks like scp-style: user@host:path
            // The colon must not be preceded by '//' (already handled above).
            let before_colon = &s[..colon_pos];
            if before_colon.contains('/') {
                s
            } else {
                // Treat everything after the ':' as the path.
                &s[colon_pos + 1..]
            }
        } else {
            s
        }
    };

    // Take the last non-empty '/'-separated segment.
    let slug = path.split('/').rfind(|seg| !seg.is_empty())?;

    if slug.is_empty() {
        None
    } else {
        Some(slug.to_owned())
    }
}

// ---------------------------------------------------------------------------
// Platform-specific install helpers
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn do_install(canonical_target: &Path, target_dir: &Path) -> Result<(), PluginError> {
    std::os::unix::fs::symlink(canonical_target, target_dir)?;
    Ok(())
}

#[cfg(windows)]
fn do_install(canonical_target: &Path, target_dir: &Path) -> Result<(), PluginError> {
    tracing::warn!(
        "symlink not supported on this platform; copied \
         (use zuit remove-analyzer + add-analyzer to refresh)"
    );
    copy_dir_recursive(canonical_target, target_dir)?;
    Ok(())
}

/// Recursively copy a directory tree from `src` to `dst`.
///
/// Used as the Windows fallback when symlinks are unavailable.
#[cfg(windows)]
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), PluginError> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serializes install-related tests in-process.
    ///
    /// On macOS (APFS), running many concurrent `flock(2)` exclusive locks on
    /// *different* files in the same filesystem can cause transient
    /// `EWOULDBLOCK` errors for unrelated lock acquisitions.  This is not BSD
    /// flock inheritance (Rust uses `posix_spawn`, which does not inherit OFDs),
    /// but rather an apparent macOS APFS VFS-layer quirk that surfaces when the
    /// in-process flock-holder count is high enough (empirically: ≥4 concurrent
    /// exclusive flocks across threads of the same process).
    ///
    /// Holding `INSTALL_MUTEX` for the duration of any test that calls
    /// `install_local_in` or `install_git_in` (which internally hold flocks)
    /// keeps the concurrent flock count low enough to avoid the interference.
    static INSTALL_MUTEX: Mutex<()> = Mutex::new(());

    /// Path to the echo-plugin fixture shipped with this crate.
    fn echo_fixture() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("tests/fixtures/echo-plugin");
        p
    }

    // -----------------------------------------------------------------------
    // derive_name_from_url (pure unit tests, no I/O)
    // -----------------------------------------------------------------------

    #[test]
    fn derive_name_https_with_git_suffix() {
        assert_eq!(
            derive_name_from_url("https://github.com/acme/zuit-zig.git"),
            Some("zuit-zig".to_owned())
        );
    }

    #[test]
    fn derive_name_scp_style() {
        assert_eq!(
            derive_name_from_url("git@github.com:acme/zuit-zig.git"),
            Some("zuit-zig".to_owned())
        );
    }

    #[test]
    fn derive_name_ssh_url() {
        assert_eq!(
            derive_name_from_url("ssh://git@host/foo/bar"),
            Some("bar".to_owned())
        );
    }

    #[test]
    fn derive_name_trailing_slash_returns_none() {
        assert_eq!(derive_name_from_url("https://example.com/"), None);
    }

    #[test]
    fn derive_name_empty_returns_none() {
        assert_eq!(derive_name_from_url(""), None);
    }

    #[test]
    fn derive_name_no_separators() {
        // Whole string is the slug (unlikely in practice but spec'd).
        assert_eq!(
            derive_name_from_url("acme-zig"),
            Some("acme-zig".to_owned())
        );
    }

    // -----------------------------------------------------------------------
    // looks_like_git_url (pure unit tests, no I/O)
    // -----------------------------------------------------------------------

    #[test]
    fn looks_like_git_https() {
        assert!(looks_like_git_url("https://github.com/foo/bar"));
    }

    #[test]
    fn looks_like_git_http() {
        assert!(looks_like_git_url("http://example.com/repo.git"));
    }

    #[test]
    fn looks_like_git_scp() {
        assert!(looks_like_git_url("git@github.com:foo/bar"));
    }

    #[test]
    fn looks_like_git_ssh_protocol() {
        assert!(looks_like_git_url("ssh://git@host/foo/bar"));
    }

    #[test]
    fn looks_like_git_dot_git_suffix() {
        assert!(looks_like_git_url("foo.git"));
    }

    #[test]
    fn not_git_url_relative() {
        assert!(!looks_like_git_url("./local-dir"));
    }

    #[test]
    fn not_git_url_abs_path() {
        assert!(!looks_like_git_url("/abs/path"));
    }

    #[test]
    fn not_git_url_plain_name() {
        assert!(!looks_like_git_url("my-plugin"));
    }

    // -----------------------------------------------------------------------
    // install_local tests (Unix only — symlink-dependent)
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn install_local_symlinks_into_plugins_dir() {
        let _g = INSTALL_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let plugins_dir = tmp.path().to_path_buf();
        let fixture = echo_fixture();

        let result = install_local_in(&plugins_dir, &fixture, None)
            .expect("install_local_in should succeed");

        // The installed directory should be a symlink.
        let installed_path = plugins_dir.join("echo");
        let meta = fs::symlink_metadata(&installed_path).expect("symlink_metadata should succeed");
        assert!(
            meta.file_type().is_symlink(),
            "expected a symlink at {installed_path:?}"
        );

        // The sidecar should be a sibling file in plugins_dir, not inside the
        // symlink target (which would pollute the user's source repo).
        let sidecar_path = plugins_dir.join("echo.source.json");
        assert!(
            sidecar_path.exists(),
            "sidecar should exist as a sibling at {sidecar_path:?}"
        );

        // The sidecar must not have been written into the fixture directory.
        assert!(
            !fixture.join(".zuit-source.json").exists(),
            "sidecar must NOT be written into the fixture (user's source dir)"
        );

        // The sidecar should record the canonical source path.
        let sidecar = store::read_source_sidecar(&plugins_dir, "echo")
            .expect("read_source_sidecar should succeed");
        let expected_target = fs::canonicalize(&fixture).unwrap();
        assert_eq!(
            sidecar,
            PluginSource::Path {
                target: expected_target
            },
            "sidecar target mismatch"
        );

        // The returned InstalledPlugin should have the correct name.
        assert_eq!(result.name, "echo");
    }

    #[cfg(unix)]
    #[test]
    fn install_local_uses_name_override() {
        let _g = INSTALL_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let plugins_dir = tmp.path().to_path_buf();
        let fixture = echo_fixture();

        let result = install_local_in(&plugins_dir, &fixture, Some("foo"))
            .expect("install_local_in with name override should succeed");

        // Symlink should be at <plugins_dir>/foo, not <plugins_dir>/echo.
        let installed_path = plugins_dir.join("foo");
        let meta = fs::symlink_metadata(&installed_path)
            .expect("symlink_metadata should succeed for 'foo'");
        assert!(
            meta.file_type().is_symlink(),
            "expected a symlink at {installed_path:?}"
        );

        // Sidecar lives as a sibling named after the install name, not the manifest name.
        let sidecar = store::read_source_sidecar(&plugins_dir, "foo")
            .expect("read_source_sidecar should succeed for overridden name");
        let expected_target = fs::canonicalize(&fixture).unwrap();
        assert_eq!(
            sidecar,
            PluginSource::Path {
                target: expected_target
            },
            "sidecar target mismatch for name-overridden install"
        );

        // The returned InstalledPlugin.name must be the override.
        assert_eq!(result.name, "foo");
    }

    #[cfg(unix)]
    #[test]
    fn install_local_rejects_duplicate_name() {
        let _g = INSTALL_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let plugins_dir = tmp.path().to_path_buf();
        let fixture = echo_fixture();

        // First install succeeds.
        install_local_in(&plugins_dir, &fixture, None).expect("first install should succeed");

        // Second install with the same name must return AlreadyInstalled.
        let second = install_local_in(&plugins_dir, &fixture, None);
        assert!(
            matches!(second, Err(PluginError::AlreadyInstalled(_))),
            "expected AlreadyInstalled error"
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_local_rejects_missing_manifest() {
        let _g = INSTALL_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let plugins_dir = tmp.path().to_path_buf();

        // Source directory with no manifest.
        let src_dir = TempDir::new().unwrap();

        let result = install_local_in(&plugins_dir, src_dir.path(), None);
        assert!(
            matches!(result, Err(PluginError::LocalPath(_))),
            "expected LocalPath error for missing manifest"
        );
    }

    // -----------------------------------------------------------------------
    // install_git_in — clones a local bare repo
    // -----------------------------------------------------------------------

    /// Helper: run a shell command, panic with output on failure.
    fn run(args: &[&str]) {
        let status = Command::new(args[0])
            .args(&args[1..])
            .status()
            .unwrap_or_else(|e| panic!("failed to spawn {:?}: {e}", args[0]));
        assert!(status.success(), "command failed: {args:?}");
    }

    /// Helper: run a git command with isolated config (no global user config needed).
    fn git(cwd: &Path, args: &[&str]) {
        let status = Command::new("git")
            .current_dir(cwd)
            .args(args)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "t@t.test")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "t@t.test")
            .status()
            .unwrap_or_else(|e| panic!("failed to spawn git: {e}"));
        assert!(status.success(), "git {args:?} failed");
    }

    #[test]
    fn install_git_in_clones_local_bare_repo() {
        let _g = INSTALL_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let bare = tmp.path().join("source.git");
        let work = tmp.path().join("work");
        let plugins_dir = tmp.path().join("plugins");
        fs::create_dir_all(&plugins_dir).unwrap();

        // 1. Initialise a bare repo.
        run(&["git", "init", "--bare", &bare.to_string_lossy()]);

        // 2. Clone the bare repo into a working tree.
        run(&[
            "git",
            "clone",
            &bare.to_string_lossy(),
            &work.to_string_lossy(),
        ]);

        // 3. Copy the echo-plugin fixture into the working tree.
        let fixture = echo_fixture();
        fs::copy(
            fixture.join("zuit-plugin.toml"),
            work.join("zuit-plugin.toml"),
        )
        .unwrap();
        fs::copy(fixture.join("run.sh"), work.join("run.sh")).unwrap();

        // 4. Commit and push.
        git(&work, &["add", "."]);
        git(&work, &["commit", "-m", "init"]);
        git(&work, &["push", "origin", "HEAD"]);

        // 5. Build the file:// URL.
        let url = format!("file://{}", bare.display());

        // 6. Install via install_git_in.
        let result =
            install_git_in(&plugins_dir, &url, None).expect("install_git_in should succeed");

        // 7. Assertions.
        assert_eq!(result.name, "echo", "plugin name should match manifest");

        // Plugin directory must exist and contain the manifest.
        let echo_dir = plugins_dir.join("echo");
        assert!(echo_dir.is_dir(), "plugin dir should be a directory");
        assert!(
            echo_dir.join("zuit-plugin.toml").exists(),
            "manifest must exist inside the cloned dir"
        );

        // Sidecar must record Git source.
        let sidecar =
            store::read_source_sidecar(&plugins_dir, "echo").expect("sidecar should be readable");
        match &sidecar {
            PluginSource::Git {
                url: u,
                sha,
                fetched_at,
            } => {
                assert_eq!(u, &url, "sidecar url mismatch");
                assert!(!sha.is_empty(), "sha should be non-empty");
                assert!(fetched_at.is_some(), "fetched_at should be present");
            }
            other @ PluginSource::Path { .. } => panic!("expected Git source, got {other:?}"),
        }

        // Sidecar must also match what was returned.
        assert!(
            matches!(result.source, PluginSource::Git { .. }),
            "returned source should be Git"
        );
    }

    #[test]
    fn install_git_in_rejects_duplicate() {
        let _g = INSTALL_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let bare = tmp.path().join("dup.git");
        let work = tmp.path().join("dup-work");
        let plugins_dir = tmp.path().join("plugins");
        fs::create_dir_all(&plugins_dir).unwrap();

        run(&["git", "init", "--bare", &bare.to_string_lossy()]);
        run(&[
            "git",
            "clone",
            &bare.to_string_lossy(),
            &work.to_string_lossy(),
        ]);

        let fixture = echo_fixture();
        fs::copy(
            fixture.join("zuit-plugin.toml"),
            work.join("zuit-plugin.toml"),
        )
        .unwrap();
        fs::copy(fixture.join("run.sh"), work.join("run.sh")).unwrap();
        git(&work, &["add", "."]);
        git(&work, &["commit", "-m", "init"]);
        git(&work, &["push", "origin", "HEAD"]);

        let url = format!("file://{}", bare.display());

        // First install succeeds.
        install_git_in(&plugins_dir, &url, None).expect("first install should succeed");

        // Second install with the same URL → same derived name → AlreadyInstalled.
        let second = install_git_in(&plugins_dir, &url, None);
        assert!(
            matches!(second, Err(PluginError::AlreadyInstalled(_))),
            "expected AlreadyInstalled error on second install"
        );
    }

    #[test]
    fn install_git_in_uses_name_override() {
        let _g = INSTALL_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let bare = tmp.path().join("override.git");
        let work = tmp.path().join("override-work");
        let plugins_dir = tmp.path().join("plugins");
        fs::create_dir_all(&plugins_dir).unwrap();

        run(&["git", "init", "--bare", &bare.to_string_lossy()]);
        run(&[
            "git",
            "clone",
            &bare.to_string_lossy(),
            &work.to_string_lossy(),
        ]);

        let fixture = echo_fixture();
        fs::copy(
            fixture.join("zuit-plugin.toml"),
            work.join("zuit-plugin.toml"),
        )
        .unwrap();
        fs::copy(fixture.join("run.sh"), work.join("run.sh")).unwrap();
        git(&work, &["add", "."]);
        git(&work, &["commit", "-m", "init"]);
        git(&work, &["push", "origin", "HEAD"]);

        let url = format!("file://{}", bare.display());

        let result = install_git_in(&plugins_dir, &url, Some("my-echo"))
            .expect("install with name_override should succeed");

        assert_eq!(result.name, "my-echo");
        assert!(plugins_dir.join("my-echo").is_dir());
        assert!(store::read_source_sidecar(&plugins_dir, "my-echo").is_ok());
    }
}
