//! blake3 helpers — 16-hex-char prefix for project and config IDs.

/// Hash bytes with blake3 and return the first 16 lowercase hex characters.
#[must_use]
pub fn short_hex(bytes: &[u8]) -> String {
    let h = blake3::hash(bytes);
    let hex = h.to_hex(); // returns ArrayString<64>
    hex[..16].to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_hex_is_16_lowercase_hex() {
        let h = short_hex(b"hello");
        assert_eq!(h.len(), 16);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn short_hex_is_deterministic() {
        assert_eq!(short_hex(b"x"), short_hex(b"x"));
        assert_ne!(short_hex(b"x"), short_hex(b"y"));
    }
}
