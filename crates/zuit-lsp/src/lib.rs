//! Minimum-viable LSP server for `zuit`.
//!
//! # Wire protocol
//!
//! The server speaks [Language Server Protocol] over stdio using the standard
//! `Content-Length` framing (no external LSP framework is used). It handles
//! exactly the subset of the protocol needed to deliver per-save diagnostics:
//!
//! | Method                       | Handled as          |
//! |------------------------------|---------------------|
//! | `initialize`                 | Returns server caps |
//! | `initialized`                | Notification (noop) |
//! | `textDocument/didOpen`       | Runs analysis       |
//! | `textDocument/didSave`       | Runs analysis       |
//! | `textDocument/didChange`     | Runs analysis       |
//! | `shutdown`                   | Replies `null`      |
//! | `exit`                       | Breaks the loop     |
//!
//! On each document event the server runs [`zuit_core::engine::Engine::analyze_path`]
//! against the file's path and publishes `textDocument/publishDiagnostics` with
//! one diagnostic per finding.
//!
//! [Language Server Protocol]: https://microsoft.github.io/language-server-protocol/
#![warn(missing_docs)]

pub mod diagnostics;
pub mod protocol;

use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use thiserror::Error;
use tracing::{debug, error, warn};
use zuit_core::config::Config;
use zuit_core::engine::Engine;

use diagnostics::finding_to_diagnostic;
use protocol::{
    RpcRequest, make_error, make_notification, make_response, parse_request, read_message_buffered,
    write_message,
};

/// Errors that can occur in the LSP server.
#[derive(Debug, Error)]
pub enum LspError {
    /// An I/O error on stdin/stdout.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A protocol-level error (malformed framing or JSON).
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Runs the LSP server on `stdin` / `stdout` until the client sends `exit`.
///
/// This is the primary public entry point.  The function blocks the calling
/// thread for the lifetime of the LSP session.
///
/// # Errors
///
/// Returns [`LspError::Io`] if reading from `stdin` or writing to `stdout`
/// fails fatally (individual message errors are logged and skipped).
pub fn run_stdio() -> Result<(), LspError> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run(stdin.lock(), stdout.lock())
}

/// Runs the LSP server reading from `reader` and writing to `writer`.
///
/// Useful in tests: pass a `std::io::Cursor<Vec<u8>>` as both reader and
/// writer to drive the server with synthetic input.
///
/// # Errors
///
/// Same as [`run_stdio`].
pub fn run<R: Read, W: Write>(reader: R, mut writer: W) -> Result<(), LspError> {
    let mut buf_reader = BufReader::new(reader);
    let registry = zuit_registry::build_registry();
    let engine = Engine::new(registry);
    let config = Config::default();

    loop {
        let raw = match read_message_buffered(&mut buf_reader) {
            Ok(msg) => msg,
            Err(LspError::Protocol(e)) => {
                warn!("protocol error reading message: {e}");
                continue;
            }
            Err(e) => return Err(e),
        };

        let req = match parse_request(&raw) {
            Ok(r) => r,
            Err(e) => {
                warn!("could not parse request: {e}");
                continue;
            }
        };

        debug!("← {}", req.method);

        if handle_message(&engine, &config, &req, &mut writer)? {
            // `exit` notification: break out of the loop.
            break;
        }
    }

    Ok(())
}

/// Handles one JSON-RPC message. Returns `true` when the server should exit.
///
/// # Errors
///
/// Returns [`LspError::Io`] when writing a response fails.
fn handle_message<W: Write>(
    engine: &Engine,
    config: &Config,
    req: &RpcRequest,
    writer: &mut W,
) -> Result<bool, LspError> {
    match req.method.as_str() {
        "initialize" => {
            let caps = server_capabilities();
            let result = json!({
                "capabilities": caps,
                "serverInfo": {
                    "name": "zuit-lsp",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            });
            let resp = make_response(req.id.as_ref().unwrap_or(&Value::Null), &result);
            send(
                &serde_json::to_string(&resp)
                    .map_err(|e| LspError::Protocol(format!("serialise error: {e}")))?,
                writer,
            )?;
        }

        "initialized" => {
            // Notification — no response required.
        }

        "textDocument/didOpen" | "textDocument/didSave" | "textDocument/didChange" => {
            if let Some(uri) = extract_uri(req.params.as_ref()) {
                if let Some(path) = uri_to_path(&uri) {
                    publish_diagnostics(engine, config, &path, &uri, writer)?;
                } else {
                    warn!("could not convert URI to path: {uri}");
                }
            } else {
                warn!("no URI in {} params", req.method);
            }
        }

        "shutdown" => {
            let resp = make_response(req.id.as_ref().unwrap_or(&Value::Null), &Value::Null);
            send(
                &serde_json::to_string(&resp)
                    .map_err(|e| LspError::Protocol(format!("serialise error: {e}")))?,
                writer,
            )?;
        }

        "exit" => {
            return Ok(true);
        }

        other => {
            // Unknown request — reply with MethodNotFound if it has an id.
            if let Some(id) = &req.id {
                let err = make_error(id, -32_601, &format!("method not found: {other}"));
                send(
                    &serde_json::to_string(&err)
                        .map_err(|e| LspError::Protocol(format!("serialise error: {e}")))?,
                    writer,
                )?;
            }
        }
    }

    Ok(false)
}

/// Runs `Engine::analyze_path` on `path` and sends `publishDiagnostics`.
fn publish_diagnostics<W: Write>(
    engine: &Engine,
    config: &Config,
    path: &Path,
    uri: &str,
    writer: &mut W,
) -> Result<(), LspError> {
    let report = match engine.analyze_path(path, config) {
        Ok(r) => r,
        Err(e) => {
            error!("analysis failed for {}: {e}", path.display());
            // Send an empty diagnostics list so the editor clears stale ones.
            let notif = make_notification(
                "textDocument/publishDiagnostics",
                &json!({"uri": uri, "diagnostics": []}),
            );
            send(
                &serde_json::to_string(&notif)
                    .map_err(|e2| LspError::Protocol(format!("serialise error: {e2}")))?,
                writer,
            )?;
            return Ok(());
        }
    };

    let diagnostics: Vec<Value> = report.findings.iter().map(finding_to_diagnostic).collect();

    let notif = make_notification(
        "textDocument/publishDiagnostics",
        &json!({
            "uri": uri,
            "diagnostics": diagnostics,
        }),
    );

    send(
        &serde_json::to_string(&notif)
            .map_err(|e| LspError::Protocol(format!("serialise error: {e}")))?,
        writer,
    )
}

/// Returns the server capabilities advertised during `initialize`.
fn server_capabilities() -> Value {
    json!({
        "textDocumentSync": 1,
        "diagnosticProvider": {
            "interFileDependencies": false,
            "workspaceDiagnostics": false,
        }
    })
}

/// Extracts the `textDocument.uri` from the params of a document event.
fn extract_uri(params: Option<&Value>) -> Option<String> {
    params?
        .get("textDocument")?
        .get("uri")?
        .as_str()
        .map(ToOwned::to_owned)
}

/// Converts a `file://` URI to a local [`PathBuf`].
///
/// Non-`file://` URIs (e.g. `untitled:`) return `None`.
fn uri_to_path(uri: &str) -> Option<PathBuf> {
    let path_str = uri.strip_prefix("file://")?;
    // On Unix, the URI path is the file path directly after stripping the
    // scheme. On Windows we'd need extra handling for drive letters, but since
    // the build target is Linux per CONVENTIONS, this is sufficient.
    Some(PathBuf::from(path_str))
}

/// Serialises `body` and sends it as a framed message.
fn send<W: Write>(body: &str, writer: &mut W) -> Result<(), LspError> {
    debug!("→ {body}");
    write_message(writer, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Parse all JSON objects out of a `publishDiagnostics`-style byte buffer.
    fn collect_notifications(output: &[u8]) -> Vec<Value> {
        let text = std::str::from_utf8(output).expect("output should be UTF-8");
        let mut results = Vec::new();
        let mut remaining = text;

        while let Some(header_end) = remaining.find("\r\n\r\n") {
            let header = &remaining[..header_end];
            let body_start = header_end + 4;
            let Some(len_str) = header.strip_prefix("Content-Length: ") else {
                break;
            };
            let n: usize = len_str.trim().parse().unwrap_or(0);
            if body_start + n > remaining.len() {
                break;
            }
            let body = &remaining[body_start..body_start + n];
            if let Ok(v) = serde_json::from_str::<Value>(body) {
                results.push(v);
            }
            remaining = &remaining[body_start + n..];
            if remaining.is_empty() {
                break;
            }
        }

        results
    }

    fn initialize_request(id: i64) -> String {
        serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "capabilities": {}
            }
        }))
        .unwrap()
    }

    fn initialized_notification() -> String {
        serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "method": "initialized",
            "params": {}
        }))
        .unwrap()
    }

    fn shutdown_request(id: i64) -> String {
        serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "shutdown"
        }))
        .unwrap()
    }

    fn exit_notification() -> String {
        serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "method": "exit"
        }))
        .unwrap()
    }

    // ── initialize / shutdown / exit ─────────────────────────────────────────

    #[test]
    fn initialize_returns_server_capabilities() {
        let mut input = Vec::new();
        write_message(&mut input, &initialize_request(1)).unwrap();
        write_message(&mut input, &initialized_notification()).unwrap();
        write_message(&mut input, &shutdown_request(2)).unwrap();
        write_message(&mut input, &exit_notification()).unwrap();

        let mut output = Vec::new();
        run(Cursor::new(input), &mut output).unwrap();

        let msgs = collect_notifications(&output);
        // First response should be the initialize result.
        let init_resp = &msgs[0];
        assert_eq!(init_resp["id"], 1);
        assert!(init_resp["result"]["capabilities"]["textDocumentSync"].is_number());
    }

    #[test]
    fn initialize_response_has_diagnostic_provider() {
        let mut input = Vec::new();
        write_message(&mut input, &initialize_request(1)).unwrap();
        write_message(&mut input, &exit_notification()).unwrap();

        let mut output = Vec::new();
        run(Cursor::new(input), &mut output).unwrap();

        let msgs = collect_notifications(&output);
        let caps = &msgs[0]["result"]["capabilities"];
        assert_eq!(caps["diagnosticProvider"]["interFileDependencies"], false);
        assert_eq!(caps["diagnosticProvider"]["workspaceDiagnostics"], false);
    }

    #[test]
    fn shutdown_responds_with_null() {
        let mut input = Vec::new();
        write_message(&mut input, &initialize_request(1)).unwrap();
        write_message(&mut input, &shutdown_request(99)).unwrap();
        write_message(&mut input, &exit_notification()).unwrap();

        let mut output = Vec::new();
        run(Cursor::new(input), &mut output).unwrap();

        let msgs = collect_notifications(&output);
        // Second message is the shutdown response.
        let shutdown_resp = msgs
            .iter()
            .find(|m| m["id"] == 99)
            .expect("shutdown response should be present");
        assert_eq!(shutdown_resp["result"], Value::Null);
    }

    #[test]
    fn exit_without_shutdown_terminates_cleanly() {
        let mut input = Vec::new();
        write_message(&mut input, &exit_notification()).unwrap();

        let mut output = Vec::new();
        let result = run(Cursor::new(input), &mut output);
        assert!(result.is_ok());
    }

    // ── unknown method ───────────────────────────────────────────────────────

    #[test]
    fn unknown_method_returns_method_not_found() {
        let body = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "workspace/unknown",
        }))
        .unwrap();

        let mut input = Vec::new();
        write_message(&mut input, &body).unwrap();
        write_message(&mut input, &exit_notification()).unwrap();

        let mut output = Vec::new();
        run(Cursor::new(input), &mut output).unwrap();

        let msgs = collect_notifications(&output);
        let err_resp = msgs
            .iter()
            .find(|m| m["id"] == 5)
            .expect("error response for id 5");
        assert_eq!(err_resp["error"]["code"], -32_601);
    }

    // ── didSave on a non-existent file ───────────────────────────────────────

    #[test]
    fn did_save_on_nonexistent_file_publishes_empty_diagnostics() {
        let body = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didSave",
            "params": {
                "textDocument": {
                    "uri": "file:///tmp/this_file_does_not_exist_zuit.rs"
                }
            }
        }))
        .unwrap();

        let mut input = Vec::new();
        write_message(&mut input, &body).unwrap();
        write_message(&mut input, &exit_notification()).unwrap();

        let mut output = Vec::new();
        run(Cursor::new(input), &mut output).unwrap();

        let msgs = collect_notifications(&output);
        let diag_notif = msgs
            .iter()
            .find(|m| m["method"] == "textDocument/publishDiagnostics")
            .expect("should have publishDiagnostics notification");
        assert!(diag_notif["params"]["diagnostics"].is_array());
    }

    // ── uri_to_path ──────────────────────────────────────────────────────────

    #[test]
    fn uri_to_path_strips_file_scheme() {
        let path = uri_to_path("file:///home/user/foo.rs");
        assert_eq!(path, Some(PathBuf::from("/home/user/foo.rs")));
    }

    #[test]
    fn non_file_uri_returns_none() {
        let path = uri_to_path("untitled:foo.rs");
        assert!(path.is_none());
    }
}
