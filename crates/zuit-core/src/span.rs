//! Source location types: [`ByteOffset`], [`Span`], [`LineCol`], and [`Location`].
//!
//! All positions in zuit findings use byte offsets (not character offsets)
//! consistent with how native parsers like `syn` and `rustpython-parser` report
//! positions. [`LineCol`] is derived on demand from a [`crate::source::SourceFile`]
//! line index.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// A byte offset into a source file, measured from the start of the file.
///
/// Uses `u32` rather than `usize` to reduce the memory footprint of the many
/// `Span` and `Location` values that live in a `SemanticIndex`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ByteOffset(pub u32);

impl ByteOffset {
    /// Returns the numeric value of this offset.
    #[must_use]
    pub fn value(self) -> u32 {
        self.0
    }
}

/// A half-open byte range `[start, end)` within a source file.
///
/// An empty span (where `start == end`) is valid and represents a cursor
/// position. The range is **half-open**: `start` is the first byte of the
/// region; `end` is the first byte *after* the region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    /// First byte of the region (inclusive).
    pub start: ByteOffset,
    /// First byte after the region (exclusive).
    pub end: ByteOffset,
}

impl Span {
    /// Creates a new span from two byte offsets.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `start > end`.
    #[must_use]
    pub fn new(start: ByteOffset, end: ByteOffset) -> Self {
        debug_assert!(start <= end, "Span::new: start must be <= end");
        Self { start, end }
    }

    /// Returns `true` if `offset` falls within this span (`start <= offset < end`).
    #[must_use]
    pub fn contains(self, offset: ByteOffset) -> bool {
        offset >= self.start && offset < self.end
    }

    /// Returns the number of bytes covered by this span.
    #[must_use]
    pub fn len(self) -> u32 {
        self.end.0.saturating_sub(self.start.0)
    }

    /// Returns `true` if this span covers zero bytes.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.start == self.end
    }
}

/// A one-indexed (line, column) position in a source file.
///
/// Both fields start at 1, matching the convention used by most editors,
/// language servers, and the SARIF output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LineCol {
    /// One-indexed line number.
    pub line: u32,
    /// One-indexed column number (byte column, not character column).
    pub column: u32,
}

impl LineCol {
    /// Creates a new `LineCol` with the given one-indexed line and column.
    #[must_use]
    pub fn new(line: u32, column: u32) -> Self {
        Self { line, column }
    }
}

/// The precise location of a finding within a source file.
///
/// Combines the file path, the raw byte [`Span`], and the human-readable
/// [`LineCol`] endpoints so that formatters can render either form without
/// re-computing line indices.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Location {
    /// Path to the source file, typically relative to the project root.
    pub file: PathBuf,
    /// Raw byte span within the file.
    pub span: Span,
    /// Human-readable start position (one-indexed line and column).
    pub start: LineCol,
    /// Human-readable end position (one-indexed line and column).
    pub end: LineCol,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_contains() {
        let s = Span::new(ByteOffset(10), ByteOffset(20));
        assert!(s.contains(ByteOffset(10)));
        assert!(s.contains(ByteOffset(15)));
        assert!(s.contains(ByteOffset(19)));
        assert!(!s.contains(ByteOffset(20))); // half-open: end is exclusive
        assert!(!s.contains(ByteOffset(9)));
    }

    #[test]
    fn span_len() {
        let s = Span::new(ByteOffset(5), ByteOffset(15));
        assert_eq!(s.len(), 10);
    }

    #[test]
    fn span_is_empty() {
        let empty = Span::new(ByteOffset(5), ByteOffset(5));
        let nonempty = Span::new(ByteOffset(5), ByteOffset(6));
        assert!(empty.is_empty());
        assert!(!nonempty.is_empty());
    }

    #[test]
    fn location_serde_round_trip() {
        let loc = Location {
            file: PathBuf::from("src/main.rs"),
            span: Span::new(ByteOffset(0), ByteOffset(10)),
            start: LineCol::new(1, 1),
            end: LineCol::new(1, 11),
        };
        let json = serde_json::to_string(&loc).unwrap();
        let back: Location = serde_json::from_str(&json).unwrap();
        assert_eq!(loc, back);
    }

    #[test]
    fn byte_offset_ordering() {
        assert!(ByteOffset(5) < ByteOffset(10));
        assert!(ByteOffset(10) > ByteOffset(5));
        assert_eq!(ByteOffset(7), ByteOffset(7));
    }
}
