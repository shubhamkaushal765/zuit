//! Shared helper for converting `proc_macro2` line/column spans to real byte
//! offsets in a [`zuit_core::SourceFile`].
//!
//! Both the index builder (`index.rs`) and the SEC101 analyzer
//! (`analyzers/unsafe_block.rs`) need the same conversion, so it lives here to
//! avoid duplication.

use zuit_core::Span;
use zuit_core::{SourceFile, span::ByteOffset};

/// Convert a `proc_macro2` 1-indexed line / 0-indexed column to a byte offset
/// within `source`.
///
/// Walks the source bytes once to find the start of `line`, then adds `col`.
/// Returns the file length (clamped) when the line is out of range.
pub(crate) fn linecol_to_offset(source: &SourceFile, line: usize, col: usize) -> u32 {
    let bytes = source.bytes();
    let mut cur_line = 1usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if cur_line == line {
            let offset = i + col;
            #[allow(clippy::cast_possible_truncation)]
            return (offset.min(bytes.len())) as u32;
        }
        if bytes[i] == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
            cur_line += 1;
            i += 2;
        } else if bytes[i] == b'\n' {
            cur_line += 1;
            i += 1;
        } else {
            i += 1;
        }
    }
    // Line not found (shouldn't happen for valid syn output); clamp.
    #[allow(clippy::cast_possible_truncation)]
    {
        bytes.len() as u32
    }
}

/// Convert a `proc_macro2::Span` to a real [`Span`] (byte offsets) using the
/// provided source file's line index.
///
/// `proc_macro2` exposes 1-indexed lines and 0-indexed columns. This function
/// walks the source once per endpoint to compute exact byte offsets, so spans
/// round-trip correctly with [`zuit_core::SourceFile::span_to_linecols`].
pub(crate) fn proc_span_to_byte_span(span: proc_macro2::Span, source: &SourceFile) -> Span {
    let start = span.start();
    let end = span.end();
    let start_off = linecol_to_offset(source, start.line, start.column);
    let end_off = linecol_to_offset(source, end.line, end.column);
    // Ensure start <= end even for zero-width spans.
    let end_off = end_off.max(start_off);
    Span::new(ByteOffset(start_off), ByteOffset(end_off))
}
