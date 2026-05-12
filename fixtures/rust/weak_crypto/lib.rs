//! Weak-crypto fixture for Rust — positive case for SEC004-weak-crypto.
//!
//! Demonstrates use of deprecated hash algorithms SHA-1 and MD5 via `use`
//! statements that reference known weak-crypto crate paths.

use sha1::Sha1;

/// Placeholder — the `use sha1::Sha1` import is what triggers SEC004.
///
/// In real code this would call `Sha1::new()` etc.  The analyzer detects
/// the import without needing the code to compile.
pub fn placeholder() -> &'static str {
    "sha1-usage"
}
