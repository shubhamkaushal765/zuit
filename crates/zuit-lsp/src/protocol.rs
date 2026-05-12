//! JSON-RPC / LSP wire-protocol framing.
//!
//! The LSP spec defines a simple framing protocol on top of a byte stream:
//!
//! ```text
//! Content-Length: <N>\r\n
//! \r\n
//! <N bytes of UTF-8 JSON>
//! ```
//!
//! This module provides:
//! - [`read_message`]: reads exactly one framed message from a [`std::io::Read`].
//! - [`write_message`]: writes one framed message to a [`std::io::Write`].
//! - [`parse_request`]: parses the JSON body into a [`RpcRequest`].
//! - [`make_response`]: constructs a successful JSON-RPC response value.
//! - [`make_error`]: constructs a JSON-RPC error response value.
//! - [`make_notification`]: constructs a JSON-RPC notification (no `id`).

use std::io::{BufRead, Write};

use serde_json::Value;

use crate::LspError;

/// Maximum LSP message body size accepted by [`read_message`].
///
/// Caps `Content-Length` so a malformed or hostile client cannot trigger a
/// multi-GB allocation. 128 MiB is far above any legitimate LSP payload.
pub(crate) const MAX_CONTENT_LENGTH: usize = 128 * 1024 * 1024;

/// A parsed JSON-RPC request or notification.
///
/// Notifications have `id == None`; requests have `id == Some(...)`.
#[derive(Debug, Clone)]
pub struct RpcRequest {
    /// The `id` field, absent for notifications.
    pub id: Option<Value>,
    /// The `method` string.
    pub method: String,
    /// The `params` field, absent when omitted by the client.
    pub params: Option<Value>,
}

/// Reads one LSP-framed message from `reader`.
///
/// The format is:
/// ```text
/// Content-Length: <N>\r\n
/// \r\n
/// <N bytes of JSON>
/// ```
///
/// Additional headers (e.g. `Content-Type`) are silently ignored so the
/// implementation is forward-compatible.
///
/// # Errors
///
/// Returns [`LspError::Io`] on I/O failures and [`LspError::Protocol`] when
/// the framing is malformed (missing/invalid `Content-Length`, non-UTF-8
/// body).
pub fn read_message<R: std::io::Read>(reader: &mut R) -> Result<String, LspError> {
    // Wrap in a BufReader so we can use read_line.
    let mut buf_reader = std::io::BufReader::new(reader);
    read_message_buffered(&mut buf_reader)
}

/// Internal helper that works on an already-buffered reader to avoid
/// re-wrapping on every call from the server loop.
pub(crate) fn read_message_buffered<R: BufRead>(reader: &mut R) -> Result<String, LspError> {
    let mut content_length: Option<usize> = None;

    // Read headers until we hit the blank line.
    loop {
        let mut header_line = String::new();
        let bytes_read = reader.read_line(&mut header_line).map_err(LspError::Io)?;

        if bytes_read == 0 {
            // EOF before a blank line means the client disconnected.
            return Err(LspError::Protocol(
                "unexpected EOF while reading headers".into(),
            ));
        }

        // Strip trailing \r\n or \n.
        let trimmed = header_line.trim_end_matches(['\r', '\n']);

        if trimmed.is_empty() {
            // Blank line marks end of headers.
            break;
        }

        // Parse header.
        if let Some(value) = trimmed
            .strip_prefix("Content-Length:")
            .or_else(|| trimmed.strip_prefix("content-length:"))
        {
            let n: usize = value
                .trim()
                .parse()
                .map_err(|_| LspError::Protocol(format!("invalid Content-Length: {value}")))?;
            content_length = Some(n);
        }
        // Ignore unknown headers (e.g. Content-Type).
    }

    let n =
        content_length.ok_or_else(|| LspError::Protocol("missing Content-Length header".into()))?;

    if n > MAX_CONTENT_LENGTH {
        return Err(LspError::Protocol(format!(
            "Content-Length {n} exceeds {MAX_CONTENT_LENGTH}-byte cap"
        )));
    }

    let mut body = vec![0u8; n];
    reader.read_exact(&mut body).map_err(LspError::Io)?;

    String::from_utf8(body)
        .map_err(|e| LspError::Protocol(format!("message body is not valid UTF-8: {e}")))
}

/// Writes one LSP-framed message to `writer`.
///
/// The `body` string is written with `Content-Length: <len>\r\n\r\n` headers
/// prepended.
///
/// # Errors
///
/// Returns [`LspError::Io`] on any write failure.
pub fn write_message<W: Write>(writer: &mut W, body: &str) -> Result<(), LspError> {
    let bytes = body.as_bytes();
    write!(writer, "Content-Length: {}\r\n\r\n", bytes.len()).map_err(LspError::Io)?;
    writer.write_all(bytes).map_err(LspError::Io)?;
    writer.flush().map_err(LspError::Io)
}

/// Parses the JSON body of an LSP message into an [`RpcRequest`].
///
/// # Errors
///
/// Returns [`LspError::Protocol`] if `body` is not valid JSON or lacks the
/// required `method` string field.
pub fn parse_request(body: &str) -> Result<RpcRequest, LspError> {
    let value: Value = serde_json::from_str(body)
        .map_err(|e| LspError::Protocol(format!("JSON parse error: {e}")))?;

    let method = value
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| LspError::Protocol("missing 'method' field".into()))?
        .to_owned();

    let id = value.get("id").cloned();
    let params = value.get("params").cloned();

    Ok(RpcRequest { id, method, params })
}

/// Constructs a successful JSON-RPC 2.0 response.
///
/// The returned [`Value`] has `jsonrpc`, `id`, and `result` fields and is
/// ready to be serialised and sent via [`write_message`].
#[must_use]
pub fn make_response(id: &Value, result: &Value) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

/// Constructs a JSON-RPC 2.0 error response.
///
/// `code` should be a standard JSON-RPC error code (e.g. `-32600` for
/// `InvalidRequest`). `message` is a short description.
#[must_use]
pub fn make_error(id: &Value, code: i64, message: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        },
    })
}

/// Constructs a JSON-RPC 2.0 notification (a message without an `id`).
///
/// Notifications are sent from server to client with no expectation of a reply.
#[must_use]
pub fn make_notification(method: &str, params: &Value) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ── framing round-trip ───────────────────────────────────────────────────

    #[test]
    fn write_then_read_round_trips_body() {
        let body = r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{}}"#;
        let mut buf = Vec::new();
        write_message(&mut buf, body).expect("write should succeed");

        let mut cursor = Cursor::new(buf);
        let got = read_message(&mut cursor).expect("read should succeed");
        assert_eq!(got, body);
    }

    #[test]
    fn framing_includes_correct_content_length() {
        let body = "hello world";
        let mut buf = Vec::new();
        write_message(&mut buf, body).unwrap();
        let frame = String::from_utf8(buf).unwrap();
        assert!(frame.starts_with("Content-Length: 11\r\n\r\n"));
    }

    #[test]
    fn framing_handles_empty_body() {
        let body = "{}";
        let mut buf = Vec::new();
        write_message(&mut buf, body).unwrap();
        let mut cursor = Cursor::new(buf);
        let got = read_message(&mut cursor).unwrap();
        assert_eq!(got, "{}");
    }

    #[test]
    fn read_tolerates_content_type_header() {
        // LSP clients may send Content-Type alongside Content-Length.
        let body = r#"{"method":"initialized"}"#;
        let frame = format!(
            "Content-Length: {}\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n{}",
            body.len(),
            body
        );
        let mut cursor = Cursor::new(frame.into_bytes());
        let got = read_message(&mut cursor).unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn read_returns_error_on_missing_content_length() {
        let frame = "Content-Type: application/json\r\n\r\n{}";
        let mut cursor = Cursor::new(frame.as_bytes());
        let result = read_message(&mut cursor);
        assert!(matches!(result, Err(LspError::Protocol(_))));
    }

    #[test]
    fn read_returns_error_on_invalid_content_length() {
        let frame = "Content-Length: abc\r\n\r\n{}";
        let mut cursor = Cursor::new(frame.as_bytes());
        let result = read_message(&mut cursor);
        assert!(matches!(result, Err(LspError::Protocol(_))));
    }

    #[test]
    fn read_returns_error_on_eof_before_headers() {
        let frame = "";
        let mut cursor = Cursor::new(frame.as_bytes());
        let result = read_message(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn oversized_content_length_is_rejected_before_allocation() {
        let huge = MAX_CONTENT_LENGTH + 1;
        let frame = format!("Content-Length: {huge}\r\n\r\n");
        let mut cursor = Cursor::new(frame.into_bytes());
        let result = read_message(&mut cursor);
        match result {
            Err(LspError::Protocol(msg)) => {
                assert!(
                    msg.contains("exceeds") && msg.contains("cap"),
                    "expected cap message, got {msg}"
                );
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn content_length_at_cap_passes_validation() {
        let frame = format!("Content-Length: {MAX_CONTENT_LENGTH}\r\n\r\n");
        let mut cursor = Cursor::new(frame.into_bytes());
        let result = read_message(&mut cursor);
        assert!(
            !matches!(&result, Err(LspError::Protocol(m)) if m.contains("cap")),
            "expected non-cap error (Io EOF since body is missing), got {result:?}"
        );
    }

    // ── parse_request ────────────────────────────────────────────────────────

    #[test]
    fn parse_request_extracts_method_id_params() {
        let body = r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"x":42}}"#;
        let req = parse_request(body).unwrap();
        assert_eq!(req.method, "initialize");
        assert_eq!(req.id, Some(serde_json::json!(1)));
        assert_eq!(req.params, Some(serde_json::json!({"x": 42})));
    }

    #[test]
    fn parse_request_notification_has_no_id() {
        let body = r#"{"jsonrpc":"2.0","method":"initialized","params":{}}"#;
        let req = parse_request(body).unwrap();
        assert_eq!(req.method, "initialized");
        assert!(req.id.is_none());
    }

    #[test]
    fn parse_request_missing_method_is_error() {
        let body = r#"{"jsonrpc":"2.0","id":1}"#;
        let result = parse_request(body);
        assert!(matches!(result, Err(LspError::Protocol(_))));
    }

    #[test]
    fn parse_request_invalid_json_is_error() {
        let result = parse_request("not json");
        assert!(matches!(result, Err(LspError::Protocol(_))));
    }

    // ── response builders ────────────────────────────────────────────────────

    #[test]
    fn make_response_has_correct_shape() {
        let id = serde_json::json!(7);
        let result = serde_json::json!({"capabilities": {}});
        let resp = make_response(&id, &result);
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], id);
        assert_eq!(resp["result"], result);
    }

    #[test]
    fn make_error_has_correct_shape() {
        let id = serde_json::json!(3);
        let err = make_error(&id, -32_600, "Invalid Request");
        assert_eq!(err["jsonrpc"], "2.0");
        assert_eq!(err["id"], id);
        assert_eq!(err["error"]["code"], -32_600);
        assert_eq!(err["error"]["message"], "Invalid Request");
    }

    #[test]
    fn make_notification_has_no_id() {
        let notif = make_notification(
            "textDocument/publishDiagnostics",
            &serde_json::json!({"uri": "file:///foo.rs", "diagnostics": []}),
        );
        assert_eq!(notif["method"], "textDocument/publishDiagnostics");
        assert!(notif.get("id").is_none());
    }

    // ── multiple messages on the same stream ─────────────────────────────────

    #[test]
    fn multiple_messages_can_be_read_sequentially() {
        let mut buf = Vec::new();
        write_message(&mut buf, r#"{"method":"first"}"#).unwrap();
        write_message(&mut buf, r#"{"method":"second"}"#).unwrap();

        // Use a single persistent BufReader to preserve buffered state between
        // calls, mirroring how the server loop uses read_message_buffered.
        let mut reader = std::io::BufReader::new(Cursor::new(buf));
        let m1 = read_message_buffered(&mut reader).unwrap();
        let m2 = read_message_buffered(&mut reader).unwrap();
        assert_eq!(m1, r#"{"method":"first"}"#);
        assert_eq!(m2, r#"{"method":"second"}"#);
    }
}
