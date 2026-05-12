//! Shared infrastructure for external-tool adapters (cargo audit, cargo clippy, ...).
//!
//! This module provides:
//! - [`Outcome`]: the result enum returned by [`run_with_limits`].
//! - [`run_with_limits`]: spawns an arbitrary subprocess with a configurable
//!   timeout and stdout cap. Used by both the `cargo_audit` adapter and the `cargo_clippy` adapter.
//! - [`build_line_starts`] / [`compute_span`]: byte-offset helpers shared by
//!   both adapters.

use std::io::Read;
use std::path::Path;
use std::time::Instant;

use crate::{
    Project,
    span::{ByteOffset, LineCol, Span},
};

// ── Shared constants ──────────────────────────────────────────────────────────

/// Maximum time allowed for external sub-commands to complete, in seconds.
/// Protects against hung processes or network-dependent operations blocking the run.
pub const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Maximum size of stdout captured from external sub-commands, in bytes (32 MiB).
/// Protects against unbounded memory consumption.
pub const DEFAULT_MAX_STDOUT_BYTES: usize = 32 * 1024 * 1024;

// ── Subprocess outcome ────────────────────────────────────────────────────────

/// Outcome of running an external tool subprocess.
#[derive(Debug, PartialEq, Clone)]
pub enum Outcome {
    /// Successfully captured stdout (may be empty).
    Ok(Vec<u8>),
    /// Process exceeded the timeout.
    Timeout,
    /// Stdout exceeded the byte cap.
    OutputTooLarge,
    /// Failed to spawn the process.
    SpawnFailed(String),
}

/// Spawns `cmd args…` from `working_dir` with configurable timeout and stdout cap.
///
/// Returns an [`Outcome`] variant — never panics. A non-zero exit code is *not*
/// treated as an error (cargo audit and clippy both exit non-zero when findings exist).
///
/// The child's stderr is silenced (`Stdio::null()`) to keep CI output clean.
#[must_use]
pub fn run_with_limits(
    cmd: &str,
    args: &[&str],
    working_dir: &Path,
    max_stdout_bytes: usize,
    timeout_secs: u64,
) -> Outcome {
    use std::process::{Command, Stdio};

    let mut child = match Command::new(cmd)
        .args(args)
        .current_dir(working_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return Outcome::SpawnFailed(e.to_string()),
    };

    let Some(mut stdout) = child.stdout.take() else {
        return Outcome::SpawnFailed("stdout not piped".to_string());
    };

    let start = Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);

    let mut buffer = Vec::new();
    #[allow(clippy::large_stack_arrays)]
    let mut read_buf = [0u8; 65536]; // 64 KiB chunks

    loop {
        // Check timeout.
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Outcome::Timeout;
        }

        // Check if child exited.
        match child.try_wait() {
            Ok(Some(_status)) => {
                // Process exited; drain remaining stdout.
                loop {
                    match stdout.read(&mut read_buf) {
                        Ok(0) | Err(_) => return Outcome::Ok(buffer),
                        Ok(n) => {
                            if buffer.len() + n > max_stdout_bytes {
                                let _ = child.kill();
                                let _ = child.wait();
                                return Outcome::OutputTooLarge;
                            }
                            buffer.extend_from_slice(&read_buf[..n]);
                        }
                    }
                }
            }
            Ok(None) => {
                // Child still running; try to read.
                match stdout.read(&mut read_buf) {
                    Ok(0) => {
                        let _ = child.wait();
                        return Outcome::Ok(buffer);
                    }
                    Ok(n) => {
                        if buffer.len() + n > max_stdout_bytes {
                            let _ = child.kill();
                            let _ = child.wait();
                            return Outcome::OutputTooLarge;
                        }
                        buffer.extend_from_slice(&read_buf[..n]);
                    }
                    Err(_) => {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
            }
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

// ── Span helpers ──────────────────────────────────────────────────────────────

/// Builds a byte-offset-per-line-start table from raw source bytes.
///
/// `line_starts[i]` is the byte offset of the first byte of line `i + 1`
/// (one-indexed).
#[must_use]
pub fn build_line_starts(bytes: &[u8]) -> Vec<u32> {
    let mut starts = vec![0u32];
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
            #[allow(clippy::cast_possible_truncation)]
            starts.push((i + 2) as u32);
            i += 2;
        } else if bytes[i] == b'\n' {
            #[allow(clippy::cast_possible_truncation)]
            starts.push((i + 1) as u32);
            i += 1;
        } else {
            i += 1;
        }
    }
    starts
}

/// Computes a [`Span`] for a finding at `(line, column)` within the given file.
///
/// Searches `project.files` for a parsed file whose path matches `file_path`
/// (relative to root) or `raw_filename`.  If found, the line index from the
/// cached source is used; otherwise a zero-length span at offset 0 is returned.
#[must_use]
pub fn compute_span(
    project: &Project,
    project_root: &Path,
    file_path: &Path,
    raw_filename: &str,
    line: u32,
    column: u32,
) -> (Span, LineCol, LineCol) {
    let source = project.files.iter().find_map(|pf| {
        let src_path = &pf.source().path;
        let abs_candidate = project_root.join(file_path);
        if src_path == file_path
            || src_path == &abs_candidate
            || src_path.as_os_str() == raw_filename
        {
            Some(pf.source())
        } else {
            None
        }
    });

    let Some(src) = source else {
        let lc = LineCol::new(line.max(1), column.max(1));
        let zero = Span::new(ByteOffset(0), ByteOffset(0));
        return (zero, lc, lc);
    };

    let bytes = src.bytes();
    let line_starts = build_line_starts(bytes);

    let line_idx = (line.saturating_sub(1)) as usize;
    let col_idx = (column.saturating_sub(1)) as usize;

    let start_byte = if line_idx < line_starts.len() {
        let line_start = line_starts[line_idx] as usize;
        (line_start + col_idx).min(bytes.len())
    } else {
        bytes.len()
    };

    #[allow(clippy::cast_possible_truncation)]
    let start = ByteOffset(start_byte as u32);
    let span = Span::new(start, start);
    let start_lc = LineCol::new(line.max(1), column.max(1));
    (span, start_lc, start_lc)
}
