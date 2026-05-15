//! Plugin removal: delete the install directory (or symlink) and its sidecar.

use std::{fs, io, path::Path};

use crate::{
    PluginError,
    store::{acquire_install_lock_in, plugins_dir, sidecar_path},
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Remove the installed plugin named `name`.
///
/// Deletes both the install directory (or symlink) and its sidecar.
/// Idempotent — removing an absent plugin is `Ok(())`.
///
/// # Errors
///
/// - [`PluginError::Lock`] if the install lock cannot be acquired.
/// - Other I/O errors except `NotFound`.
pub fn remove(name: &str) -> Result<(), PluginError> {
    let plugins_dir = plugins_dir()?;
    remove_in(&plugins_dir, name)
}

/// Inner implementation of [`remove`] over an explicit `plugins_dir`.
///
/// Tests use this to avoid mutating process-global environment variables.
pub(crate) fn remove_in(plugins_dir: &Path, name: &str) -> Result<(), PluginError> {
    // Acquire the exclusive install lock for the duration of the removal.
    let _lock = acquire_install_lock_in(plugins_dir)?;

    let install_dir = plugins_dir.join(name);

    // Determine what kind of filesystem object is at `install_dir`.
    match fs::symlink_metadata(&install_dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                // Symlink (Unix local install) — remove just the symlink.
                ignore_not_found(fs::remove_file(&install_dir))?;
            } else if meta.is_dir() {
                // Real directory (git clone or Windows copy) — remove recursively.
                ignore_not_found(fs::remove_dir_all(&install_dir))?;
            }
            // Anything else (plain file, etc.) — treat as not found; fall through.
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            // Plugin directory does not exist — that's fine, keep going to remove
            // the sidecar in case it was left behind.
        }
        Err(err) => return Err(PluginError::Io(err)),
    }

    // Remove the sidecar (sibling file in plugins_dir).
    let sc = sidecar_path(plugins_dir, name);
    ignore_not_found(fs::remove_file(&sc))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert `io::ErrorKind::NotFound` into `Ok(())` for idempotent deletes.
fn ignore_not_found(result: io::Result<()>) -> Result<(), PluginError> {
    match result {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(PluginError::Io(err)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::{install_git_in, install_local_in};
    use std::{path::PathBuf, process::Command, sync::Mutex};
    use tempfile::TempDir;

    /// Serializes install/remove tests that hold flocks.
    ///
    /// On macOS (APFS), running many concurrent `flock(2)` exclusive locks on
    /// *different* files in the same filesystem can cause transient
    /// `EWOULDBLOCK` errors for unrelated lock acquisitions.  Holding this mutex
    /// keeps the in-process flock count low enough to avoid that interference.
    /// See `install.rs::tests` for full rationale.
    static INSTALL_MUTEX: Mutex<()> = Mutex::new(());

    /// Path to the echo-plugin fixture shipped with this crate.
    fn echo_fixture() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("tests/fixtures/echo-plugin");
        p
    }

    // -----------------------------------------------------------------------
    // remove tests
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn remove_deletes_directory_and_is_idempotent() {
        let _g = INSTALL_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let plugins_dir = tmp.path().to_path_buf();
        let fixture = echo_fixture();

        // Install first so we have something to remove.
        install_local_in(&plugins_dir, &fixture, None).expect("install_local_in should succeed");

        let install_dir = plugins_dir.join("echo");
        let sidecar = plugins_dir.join("echo.source.json");

        assert!(
            install_dir.exists() || std::fs::symlink_metadata(&install_dir).is_ok(),
            "install dir should exist before removal"
        );
        assert!(sidecar.exists(), "sidecar should exist before removal");

        // First removal — should succeed.
        remove_in(&plugins_dir, "echo").expect("first remove should succeed");

        assert!(
            std::fs::symlink_metadata(&install_dir).is_err(),
            "install dir should be gone after removal"
        );
        assert!(!sidecar.exists(), "sidecar should be gone after removal");

        // Second removal — idempotent, should also succeed.
        remove_in(&plugins_dir, "echo").expect("second remove should be idempotent");
    }

    #[test]
    fn remove_unknown_name_is_ok() {
        let _g = INSTALL_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let plugins_dir = tmp.path().to_path_buf();
        // Ensure the plugins directory exists (lock file creation requires it).
        std::fs::create_dir_all(&plugins_dir).unwrap();

        remove_in(&plugins_dir, "never-installed")
            .expect("removing a non-existent plugin should be Ok");
    }

    // -----------------------------------------------------------------------
    // Helpers mirrored from install.rs::tests for the git-based remove test
    // -----------------------------------------------------------------------

    /// Run a git command with isolated author/committer config.
    fn git(cwd: &std::path::Path, args: &[&str]) {
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
    fn remove_git_plugin_deletes_clone_dir() {
        let _g = INSTALL_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let bare = tmp.path().join("remove-test.git");
        let work = tmp.path().join("work");
        let plugins_dir = tmp.path().join("plugins");
        std::fs::create_dir_all(&plugins_dir).unwrap();

        let run = |args: &[&str]| {
            let status = Command::new(args[0])
                .args(&args[1..])
                .status()
                .unwrap_or_else(|e| panic!("failed to spawn {:?}: {e}", args[0]));
            assert!(status.success(), "command failed: {args:?}");
        };

        run(&["git", "init", "--bare", &bare.to_string_lossy()]);
        run(&[
            "git",
            "clone",
            &bare.to_string_lossy(),
            &work.to_string_lossy(),
        ]);

        let fixture = echo_fixture();
        std::fs::copy(
            fixture.join("zuit-plugin.toml"),
            work.join("zuit-plugin.toml"),
        )
        .unwrap();
        std::fs::copy(fixture.join("run.sh"), work.join("run.sh")).unwrap();
        git(&work, &["add", "."]);
        git(&work, &["commit", "-m", "init"]);
        git(&work, &["push", "origin", "HEAD"]);

        let url = format!("file://{}", bare.display());
        install_git_in(&plugins_dir, &url, None).expect("install_git_in should succeed");

        let echo_dir = plugins_dir.join("echo");
        assert!(echo_dir.is_dir(), "plugin dir should exist after install");

        remove_in(&plugins_dir, "echo").expect("remove should succeed");

        assert!(!echo_dir.exists(), "plugin dir should be gone after remove");
        assert!(
            !plugins_dir.join("echo.source.json").exists(),
            "sidecar should be gone after remove"
        );
    }
}
