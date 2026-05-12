//! Git archive extraction helper.
//!
//! `extract_ref_to_tempdir` shells out to `git archive <ref> | tar -x -C <tempdir>`
//! and returns the populated [`tempfile::TempDir`].
//!
//! This helper is only invoked from the production `baseline_ref` code path.
//! Tests bypass it entirely via `#[cfg(test)]`-gated constructors on the
//! analyzer structs.

use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Timeout for git archive + tar extraction.
const ARCHIVE_TIMEOUT_SECS: u64 = 60;

/// Runs `git archive <git_ref>` piped into `tar -x -C <tempdir>` and returns
/// the populated temporary directory.
///
/// # Errors
///
/// Returns `io::Error` on spawn failure, timeout, or non-zero exit.
pub(crate) fn extract_ref_to_tempdir(
    git_ref: &str,
    working_dir: &Path,
) -> Result<tempfile::TempDir, io::Error> {
    let tmp = tempfile::TempDir::new()?;

    // Spawn `git archive <ref>` with stdout piped.
    let mut archive = Command::new("git")
        .args(["archive", git_ref])
        .current_dir(working_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let archive_stdout = archive
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("git archive stdout not piped"))?;

    // Spawn `tar -x -C <tmpdir>` reading from git archive's stdout.
    let mut tar = Command::new("tar")
        .args(["-x", "-C", tmp.path().to_str().unwrap_or(".")])
        .stdin(archive_stdout)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let deadline = Instant::now() + Duration::from_secs(ARCHIVE_TIMEOUT_SECS);

    // Wait for both processes, respecting the deadline.
    loop {
        if Instant::now() > deadline {
            let _ = archive.kill();
            let _ = tar.kill();
            let _ = archive.wait();
            let _ = tar.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "git archive timed out",
            ));
        }
        match tar.try_wait()? {
            Some(tar_status) => {
                let archive_status = archive.wait()?;
                if !archive_status.success() {
                    return Err(io::Error::other(format!(
                        "git archive exited with status {archive_status}"
                    )));
                }
                if !tar_status.success() {
                    return Err(io::Error::other(format!(
                        "tar exited with status {tar_status}"
                    )));
                }
                break;
            }
            None => {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    Ok(tmp)
}

// ── Smoke test (Unix only) ────────────────────────────────────────────────────

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Smoke test: passing a bogus ref returns an error without panicking.
    /// We don't care about the specific error — just that it's an `Err`.
    #[test]
    fn bogus_ref_returns_error_not_panic() {
        // Use /tmp as working_dir so git won't be in a repo at all (or use the
        // crate's own root — either way "BOGUS_REF_XYZ" is invalid).
        let result = extract_ref_to_tempdir("BOGUS_REF_XYZ_DOES_NOT_EXIST", Path::new("/tmp"));
        // We expect an error (git archive fails), but must not panic.
        assert!(
            result.is_err(),
            "expected Err for bogus ref, got Ok (unexpected git archive success)"
        );
    }
}
