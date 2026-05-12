//! `zuit lsp` — start the LSP server on stdin/stdout.

use anyhow::Result;

/// Starts the `zuit-lsp` server, reading JSON-RPC messages from stdin and
/// writing responses to stdout.
///
/// # Errors
///
/// Returns an error if the underlying I/O fails (e.g. broken pipe).
pub(crate) fn run() -> Result<i32> {
    zuit_lsp::run_stdio().map_err(anyhow::Error::from)?;
    Ok(0)
}
