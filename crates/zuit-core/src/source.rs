//! [`SourceFile`]: the in-memory representation of a source file with a
//! pre-computed line index for efficient [`crate::span::Span`] → [`crate::span::LineCol`] resolution.

use std::path::PathBuf;
use std::sync::OnceLock;

use crate::external::build_line_starts;
use crate::span::{ByteOffset, LineCol, Span};

/// An in-memory source file with a lazy, thread-safe line index.
///
/// The line index is computed once on the first call to [`SourceFile::offset_to_linecol`]
/// and then cached for subsequent calls. This amortises the O(n) scan across
/// all the offset lookups that happen during a single parse.
pub struct SourceFile {
    /// Path to the file on disk (may be relative to the workspace root).
    pub path: PathBuf,
    /// Raw UTF-8 bytes of the file content.
    bytes: Vec<u8>,
    /// Lazily-computed byte offsets of the first byte of each line.
    ///
    /// `line_starts[0]` is always `0` (the start of line 1).
    /// `line_starts[i]` is the byte offset of line `i + 1` (one-indexed).
    line_starts: OnceLock<Vec<u32>>,
}

impl SourceFile {
    /// Creates a `SourceFile` from a path and its UTF-8 content.
    ///
    /// The content is stored as-is; the line index is computed lazily.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, content: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            bytes: content.into(),
            line_starts: OnceLock::new(),
        }
    }

    /// Returns the raw byte content of the file.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the file content as a UTF-8 string slice.
    ///
    /// # Panics
    ///
    /// Panics if the content is not valid UTF-8. Files should be validated
    /// before constructing a `SourceFile` (see [`crate::error::ParseError::Encoding`]).
    #[must_use]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes).expect("invariant: SourceFile content must be valid UTF-8")
    }

    /// Returns the total number of bytes in the file.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the file is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Converts a [`ByteOffset`] to a one-indexed [`LineCol`].
    ///
    /// If `offset` is beyond the end of the file it is clamped to the last
    /// valid position. The line index is computed on the first call.
    #[must_use]
    pub fn offset_to_linecol(&self, offset: ByteOffset) -> LineCol {
        let starts = self.line_starts();
        // Clamp: files are limited to 4 GiB in practice (u32 range); truncation is safe.
        #[allow(clippy::cast_possible_truncation)]
        let pos = offset.0.min(self.bytes.len() as u32);

        // Binary-search for the last line that starts at or before `pos`.
        let line_idx = starts.partition_point(|&s| s <= pos).saturating_sub(1);

        // line_idx < 2^32 because the index is bounded by the file's byte count.
        #[allow(clippy::cast_possible_truncation)]
        let line = (line_idx + 1) as u32; // one-indexed
        let column = (pos - starts[line_idx]) + 1; // one-indexed
        LineCol::new(line, column)
    }

    /// Converts a [`Span`] to a pair of one-indexed [`LineCol`] positions.
    #[must_use]
    pub fn span_to_linecols(&self, span: Span) -> (LineCol, LineCol) {
        (
            self.offset_to_linecol(span.start),
            self.offset_to_linecol(span.end),
        )
    }

    /// Returns the count of lines in the file (counting a trailing newline as
    /// not producing an extra empty line).
    #[must_use]
    pub fn line_count(&self) -> u32 {
        // File line counts fit in u32 (bounded by byte count).
        #[allow(clippy::cast_possible_truncation)]
        let n = self.line_starts().len() as u32;
        n
    }

    // ── private helpers ───────────────────────────────────────────────────

    fn line_starts(&self) -> &[u32] {
        self.line_starts
            .get_or_init(|| build_line_starts(&self.bytes))
    }
}

impl std::fmt::Debug for SourceFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceFile")
            .field("path", &self.path)
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn make(content: &str) -> SourceFile {
        SourceFile::new("test.rs", content.as_bytes().to_vec())
    }

    #[test]
    fn single_line_offset_zero() {
        let sf = make("hello");
        assert_eq!(sf.offset_to_linecol(ByteOffset(0)), LineCol::new(1, 1));
        assert_eq!(sf.offset_to_linecol(ByteOffset(4)), LineCol::new(1, 5));
    }

    #[test]
    fn multi_line_lf() {
        // "abc\ndef\nghi"
        let sf = make("abc\ndef\nghi");
        // line 1: bytes 0..3 ("abc"), newline at 3
        // line 2: bytes 4..6 ("def"), newline at 7
        // line 3: bytes 8..10 ("ghi")
        assert_eq!(sf.offset_to_linecol(ByteOffset(0)), LineCol::new(1, 1));
        assert_eq!(sf.offset_to_linecol(ByteOffset(3)), LineCol::new(1, 4)); // the '\n' itself
        assert_eq!(sf.offset_to_linecol(ByteOffset(4)), LineCol::new(2, 1));
        assert_eq!(sf.offset_to_linecol(ByteOffset(7)), LineCol::new(2, 4)); // the '\n'
        assert_eq!(sf.offset_to_linecol(ByteOffset(8)), LineCol::new(3, 1));
        assert_eq!(sf.offset_to_linecol(ByteOffset(10)), LineCol::new(3, 3));
    }

    #[test]
    fn crlf_line_endings() {
        // "ab\r\ncd\r\nef"
        let sf = make("ab\r\ncd\r\nef");
        // line 1: 0..1 ("ab"), crlf at 2-3
        // line 2: 4..5 ("cd"), crlf at 6-7
        // line 3: 8..9 ("ef")
        assert_eq!(sf.offset_to_linecol(ByteOffset(0)), LineCol::new(1, 1));
        assert_eq!(sf.offset_to_linecol(ByteOffset(4)), LineCol::new(2, 1));
        assert_eq!(sf.offset_to_linecol(ByteOffset(8)), LineCol::new(3, 1));
    }

    #[test]
    fn final_line_without_newline() {
        let sf = make("a\nb");
        assert_eq!(sf.offset_to_linecol(ByteOffset(2)), LineCol::new(2, 1));
    }

    #[test]
    fn offset_beyond_end_is_clamped() {
        let sf = make("hi");
        // "hi" has len 2; offset 100 should clamp gracefully
        let lc = sf.offset_to_linecol(ByteOffset(100));
        assert_eq!(lc.line, 1);
    }

    #[test]
    fn line_count_no_trailing_newline() {
        let sf = make("a\nb\nc");
        assert_eq!(sf.line_count(), 3);
    }

    #[test]
    fn line_count_with_trailing_newline() {
        // "a\nb\n" — trailing newline starts a new (empty) logical line
        let sf = make("a\nb\n");
        // build_line_starts gives [0, 2, 4, 5] for this content... let's verify
        // Actually "a\nb\n": offset 0='a', 1='\n', 2='b', 3='\n' → starts = [0, 2, 4]
        assert_eq!(sf.line_count(), 3);
    }

    #[test]
    fn span_to_linecols() {
        let sf = make("hello\nworld");
        let (start, end) = sf.span_to_linecols(Span::new(ByteOffset(0), ByteOffset(5)));
        assert_eq!(start, LineCol::new(1, 1));
        assert_eq!(end, LineCol::new(1, 6)); // exclusive end = character after 'o'
    }

    #[test]
    fn empty_file() {
        let sf = make("");
        assert_eq!(sf.line_count(), 1);
        assert_eq!(sf.offset_to_linecol(ByteOffset(0)), LineCol::new(1, 1));
    }

    // ── property tests ────────────────────────────────────────────────────────
    //
    // These properties must hold for *any* valid source and *any* valid span,
    // regardless of the exact content.  We keep case counts low (50) so CI
    // stays fast.

    /// Generates a short ASCII+newline source string that remains valid UTF-8.
    fn ascii_source_strategy() -> impl Strategy<Value = String> {
        // Characters: printable ASCII (0x20–0x7e) plus newline.
        let ch = prop_oneof![Just('\n'), (0x20u8..=0x7eu8).prop_map(|b| b as char),];
        proptest::collection::vec(ch, 0..80).prop_map(|v| v.into_iter().collect())
    }

    /// Generates a source that mixes ASCII lines with a short multibyte UTF-8
    /// segment ("héllo"), exercising multi-byte handling.
    fn mixed_source_strategy() -> impl Strategy<Value = String> {
        ascii_source_strategy().prop_map(|s| {
            // Append a multibyte segment so the source always contains at least
            // one multi-byte character.
            format!("{s}héllo\nwörld\n")
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        /// For any valid span inside an ASCII source, both endpoints must have
        /// line >= 1 and column >= 1, and the start must be lexicographically
        /// <= the end.
        #[test]
        fn span_linecols_start_le_end_ascii(
            source in ascii_source_strategy(),
            raw_start in 0usize..200,
            raw_end   in 0usize..200,
        ) {
            let len = source.len();
            // Clamp both to valid byte positions and ensure start <= end.
            // We must also ensure we don't slice in the middle of a UTF-8
            // codepoint; since ascii_source_strategy produces ASCII+newline
            // only, every byte boundary is a valid char boundary, so this is
            // trivially satisfied.
            let start = raw_start.min(len);
            let end   = raw_end.min(len).max(start);

            let sf = SourceFile::new("t.rs", source.as_bytes().to_vec());
            // start and end are clamped to source.len() (≤ 80 bytes) so the
            // cast from usize to u32 cannot truncate on any target.
            #[allow(clippy::cast_possible_truncation)]
            let (lc_start, lc_end) = sf.span_to_linecols(Span::new(
                ByteOffset(start as u32),
                ByteOffset(end   as u32),
            ));

            // Both line and column must be >= 1 (one-indexed).
            prop_assert!(lc_start.line   >= 1, "start.line < 1");
            prop_assert!(lc_start.column >= 1, "start.column < 1");
            prop_assert!(lc_end.line     >= 1, "end.line < 1");
            prop_assert!(lc_end.column   >= 1, "end.column < 1");

            // Lexicographic ordering: start <= end.
            let start_le_end =
                (lc_start.line, lc_start.column) <= (lc_end.line, lc_end.column);
            prop_assert!(
                start_le_end,
                "start linecol ({},{}) > end linecol ({},{})",
                lc_start.line, lc_start.column,
                lc_end.line,   lc_end.column,
            );
        }

        /// An empty span (start == end) must map to identical start and end
        /// LineCol values.
        #[test]
        fn empty_span_produces_identical_linecols(
            source in ascii_source_strategy(),
            raw_offset in 0usize..200,
        ) {
            let len = source.len();
            let offset = raw_offset.min(len);
            let sf = SourceFile::new("t.rs", source.as_bytes().to_vec());
            // offset is clamped to len (≤ 80 bytes); cast cannot truncate.
            #[allow(clippy::cast_possible_truncation)]
            let bo = ByteOffset(offset as u32);
            let (lc_start, lc_end) = sf.span_to_linecols(Span::new(bo, bo));
            prop_assert_eq!(
                lc_start, lc_end,
                "empty span must yield identical linecols"
            );
        }

        /// For any span where the start byte is the first byte of a line (i.e.
        /// immediately after a newline), the start column must be 1.
        #[test]
        fn byte_after_newline_has_column_one(
            // Build a source from 1–5 lines of 1–15 chars each.
            lines in proptest::collection::vec("[a-z ]{1,15}", 1usize..=5),
        ) {
            let source = lines.join("\n") + "\n";
            let sf = SourceFile::new("t.rs", source.as_bytes().to_vec());

            // Collect the byte positions of every character immediately after a
            // '\n' (i.e., the start of each line after the first).
            // Source len is bounded by strategy (≤ ~80 bytes); cast is safe.
            #[allow(clippy::cast_possible_truncation)]
            let starts: Vec<u32> = source
                .bytes()
                .enumerate()
                .filter(|&(i, b)| b == b'\n' && i + 1 < source.len())
                .map(|(i, _)| (i + 1) as u32)
                .collect();

            for &pos in &starts {
                let lc = sf.offset_to_linecol(ByteOffset(pos));
                prop_assert_eq!(
                    lc.column, 1,
                    "byte offset {} (start of a line) must have column 1, got {}",
                    pos, lc.column
                );
            }
        }

        /// span_to_linecols works correctly for sources containing multibyte
        /// UTF-8 characters: same structural invariants hold.
        #[test]
        fn span_linecols_start_le_end_multibyte(
            source in mixed_source_strategy(),
            raw_start in 0usize..200,
            raw_end   in 0usize..200,
        ) {
            let bytes = source.as_bytes();
            let len = bytes.len();

            // Clamp to valid, aligned byte boundaries.
            let start_raw = raw_start.min(len);
            let end_raw   = raw_end.min(len).max(start_raw);

            // Walk forward until we hit a UTF-8 char boundary.
            let start = (start_raw..=len).find(|&i| source.is_char_boundary(i)).unwrap_or(len);
            let end   = (end_raw.max(start)..=len).find(|&i| source.is_char_boundary(i)).unwrap_or(len);

            let sf = SourceFile::new("t.rs", bytes.to_vec());
            // start and end are clamped to len (bounded by strategy); cast is safe.
            #[allow(clippy::cast_possible_truncation)]
            let (lc_start, lc_end) = sf.span_to_linecols(Span::new(
                ByteOffset(start as u32),
                ByteOffset(end   as u32),
            ));

            prop_assert!(lc_start.line   >= 1);
            prop_assert!(lc_start.column >= 1);
            prop_assert!(lc_end.line     >= 1);
            prop_assert!(lc_end.column   >= 1);

            let start_le_end =
                (lc_start.line, lc_start.column) <= (lc_end.line, lc_end.column);
            prop_assert!(
                start_le_end,
                "start ({},{}) > end ({},{}) for multibyte source",
                lc_start.line, lc_start.column,
                lc_end.line,   lc_end.column,
            );
        }
    }
}
