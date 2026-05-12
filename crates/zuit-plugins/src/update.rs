//! Plugin update: pull latest changes for git installs; no-op for local symlinks.

use std::{fs, io, path::Path, process::Command};

use crate::{
    store::{acquire_install_lock_in, plugins_dir, read_source_sidecar, write_source_sidecar, PluginSource},
    PluginError,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Update the installed plugin named `name`.
///
/// For `Git` sources: runs `git -C <dir> pull --ff-only` and refreshes the
/// sidecar's `sha` and `fetched_at`.
/// For `Path` sources installed as a Unix symlink: no-op (logs an info-level
/// message).
/// For `Path` sources installed as a copy (Windows fallback): re-copies the
/// recorded target into the install dir; returns `NotFound` if the recorded
/// source has vanished.
///
/// # Errors
///
/// - [`PluginError::NotFound`] if the plugin is not installed.
/// - [`PluginError::Git`] if `git pull` or `git rev-parse` fails.
/// - [`PluginError::Lock`] if the install lock cannot be acquired.
pub fn update(name: &str) -> Result<(), PluginError> {
    let plugins_dir = plugins_dir()?;
    update_in(&plugins_dir, name)
}

/// Inner implementation of [`update`] over an explicit `plugins_dir`.
///
/// Tests use this to avoid mutating process-global environment variables.
pub(crate) fn update_in(plugins_dir: &Path, name: &str) -> Result<(), PluginError> {
    // Acquire the exclusive install lock for the duration of the update.
    let _lock = acquire_install_lock_in(plugins_dir)?;

    let install_dir = plugins_dir.join(name);

    // If the install directory does not exist at all, the plugin is not installed.
    if !install_dir.exists() && fs::symlink_metadata(&install_dir).is_err() {
        return Err(PluginError::NotFound(name.to_owned()));
    }

    // Read the source sidecar.  If it is missing the install is broken; treat
    // as not-installed for update purposes.
    let source = read_source_sidecar(plugins_dir, name).map_err(|err| match err {
        PluginError::Io(io_err) if io_err.kind() == io::ErrorKind::NotFound => {
            PluginError::NotFound(name.to_owned())
        }
        other => other,
    })?;

    match source {
        PluginSource::Git { url, .. } => {
            update_git(plugins_dir, name, &install_dir, &url)?;
        }
        PluginSource::Path { target } => {
            update_local(plugins_dir, name, &install_dir, &target)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Git update
// ---------------------------------------------------------------------------

fn update_git(
    plugins_dir: &Path,
    name: &str,
    install_dir: &Path,
    url: &str,
) -> Result<(), PluginError> {
    let dir_str = install_dir.to_string_lossy().into_owned();

    // Run `git pull --ff-only`.
    let pull_out = Command::new("git")
        .args(["-C", &dir_str, "pull", "--ff-only"])
        .output()
        .map_err(|e| PluginError::Git {
            stage: "pull",
            message: format!("failed to spawn git: {e}"),
        })?;
    if !pull_out.status.success() {
        return Err(PluginError::Git {
            stage: "pull",
            message: String::from_utf8_lossy(&pull_out.stderr).into_owned(),
        });
    }

    // Capture the new HEAD SHA.
    let rev_out = Command::new("git")
        .args(["-C", &dir_str, "rev-parse", "HEAD"])
        .output()
        .map_err(|e| PluginError::Git {
            stage: "rev-parse",
            message: format!("failed to spawn git: {e}"),
        })?;
    if !rev_out.status.success() {
        return Err(PluginError::Git {
            stage: "rev-parse",
            message: String::from_utf8_lossy(&rev_out.stderr).into_owned(),
        });
    }
    let new_sha = String::from_utf8_lossy(&rev_out.stdout).trim().to_owned();

    let fetched_at = {
        use time::format_description::well_known::Rfc3339;
        time::OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::new())
    };

    write_source_sidecar(
        plugins_dir,
        name,
        &PluginSource::Git {
            url: url.to_owned(),
            sha: new_sha,
            fetched_at: Some(fetched_at),
        },
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Local-path update
// ---------------------------------------------------------------------------

fn update_local(
    plugins_dir: &Path,
    name: &str,
    install_dir: &Path,
    target: &Path,
) -> Result<(), PluginError> {
    let metadata = fs::symlink_metadata(install_dir)?;

    if metadata.file_type().is_symlink() {
        // Unix symlink install: edits in the source are already visible — nothing
        // to do.
        tracing::info!("plugin '{name}' is a local symlink; nothing to update");
        return Ok(());
    }

    // Windows copy fallback: re-copy from the recorded target path.
    if !target.exists() {
        return Err(PluginError::NotFound(format!(
            "source '{}' no longer exists",
            target.display()
        )));
    }

    fs::remove_dir_all(install_dir)?;
    copy_dir_recursive(target, install_dir)?;

    // Refresh the sidecar (path unchanged, but signals the update happened).
    write_source_sidecar(
        plugins_dir,
        name,
        &PluginSource::Path {
            target: target.to_owned(),
        },
    )?;

    Ok(())
}

/// Recursively copy a directory tree from `src` to `dst`.
///
/// Used as the Windows fallback for local-path updates when symlinks are
/// unavailable.
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
    use crate::{
        install::{install_git_in, install_local_in},
        store,
    };
    use std::{path::PathBuf, process::Command, sync::Mutex};
    use tempfile::TempDir;

    /// Serializes install/update tests that hold flocks.
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

    /// Run a git command with isolated author/committer config.
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

    /// Run a shell command, panic with message on failure.
    fn run(args: &[&str]) {
        let status = Command::new(args[0])
            .args(&args[1..])
            .status()
            .unwrap_or_else(|e| panic!("failed to spawn {:?}: {e}", args[0]));
        assert!(status.success(), "command failed: {args:?}");
    }

    // -----------------------------------------------------------------------
    // update_git_runs_pull
    // -----------------------------------------------------------------------

    #[test]
    fn update_git_runs_pull() {
        let _g = INSTALL_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let bare = tmp.path().join("update-test.git");
        let work = tmp.path().join("work");
        let plugins_dir = tmp.path().join("plugins");
        fs::create_dir_all(&plugins_dir).unwrap();

        // 1. Init a bare repo and a working clone.
        run(&["git", "init", "--bare", &bare.to_string_lossy()]);
        run(&["git", "clone", &bare.to_string_lossy(), &work.to_string_lossy()]);

        // 2. Populate the working tree with the echo fixture, commit, and push.
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

        // 3. Install.
        let url = format!("file://{}", bare.display());
        install_git_in(&plugins_dir, &url, None).expect("install_git_in should succeed");

        // Capture the initial SHA.
        let initial_sidecar = store::read_source_sidecar(&plugins_dir, "echo")
            .expect("initial sidecar should be readable");
        let initial_sha = match &initial_sidecar {
            PluginSource::Git { sha, .. } => sha.clone(),
            PluginSource::Path { .. } => panic!("expected Git source"),
        };

        // 4. Make a second commit in the working clone and push to the bare.
        fs::write(work.join("EXTRA.txt"), b"extra file").unwrap();
        git(&work, &["add", "EXTRA.txt"]);
        git(&work, &["commit", "-m", "second commit"]);
        git(&work, &["push", "origin", "HEAD"]);

        // 5. Update.
        update_in(&plugins_dir, "echo").expect("update_in should succeed");

        // 6. Assert the sidecar SHA changed.
        let updated_sidecar = store::read_source_sidecar(&plugins_dir, "echo")
            .expect("updated sidecar should be readable");
        let updated_sha = match &updated_sidecar {
            PluginSource::Git { sha, .. } => sha.clone(),
            PluginSource::Path { .. } => panic!("expected Git source after update"),
        };

        assert_ne!(
            initial_sha, updated_sha,
            "SHA should change after pulling a new commit"
        );
    }

    // -----------------------------------------------------------------------
    // update_local_symlink_is_no_op
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn update_local_symlink_is_no_op() {
        let _g = INSTALL_MUTEX.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let plugins_dir = tmp.path().to_path_buf();
        let fixture = echo_fixture();

        // Install as a symlink (Unix default).
        install_local_in(&plugins_dir, &fixture, None)
            .expect("install_local_in should succeed");

        // Update should return Ok without error.
        update_in(&plugins_dir, "echo")
            .expect("update of a local symlink should be a no-op Ok");

        // The sidecar should still be intact.
        let sidecar = store::read_source_sidecar(&plugins_dir, "echo")
            .expect("sidecar should still be readable after no-op update");
        let expected_target = std::fs::canonicalize(&fixture).unwrap();
        assert_eq!(
            sidecar,
            PluginSource::Path { target: expected_target },
            "sidecar should be unchanged after no-op update"
        );
    }
}
