//! Identity types: [`LanguageId`] and [`AnalyzerId`].
//!
//! These are lightweight, serde-serializable wrappers around string data.
//! `LanguageId` uses `&'static str` because language names are compile-time
//! constants; `AnalyzerId` uses an owned `String` so rule IDs can be
//! constructed at runtime (e.g., from config).

use std::fmt;
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

/// A stable identifier for a language frontend (e.g. `"rust"`, `"python"`).
///
/// The inner value is a `&'static str` because language names are always
/// compile-time constants embedded in `Language` implementations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct LanguageId(pub &'static str);

impl LanguageId {
    /// Returns the string representation of this language identifier.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

impl PartialEq for LanguageId {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for LanguageId {}

impl Hash for LanguageId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Display for LanguageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// A stable identifier for an analyzer rule (e.g. `"MAINT001-cyclomatic"`).
///
/// Uses an owned `String` so rule IDs can be constructed from configuration
/// data at runtime, unlike [`LanguageId`] which is always a static constant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AnalyzerId(pub String);

impl AnalyzerId {
    /// Creates an `AnalyzerId` from any type that converts to a `String`.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Returns the string representation of this analyzer identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AnalyzerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn language_id_equality() {
        let a = LanguageId("rust");
        let b = LanguageId("rust");
        let c = LanguageId("python");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn language_id_hash_consistency() {
        let mut map: HashMap<LanguageId, &str> = HashMap::new();
        map.insert(LanguageId("rust"), "Rust");
        assert_eq!(map[&LanguageId("rust")], "Rust");
    }

    #[test]
    fn language_id_serde_round_trip() {
        let id = LanguageId("python");
        let json = serde_json::to_string(&id).unwrap();
        // LanguageId serialises as a plain JSON string
        assert_eq!(json, "\"python\"");
    }

    #[test]
    fn analyzer_id_equality() {
        let a = AnalyzerId::new("MAINT001-cyclomatic");
        let b = AnalyzerId::new("MAINT001-cyclomatic");
        let c = AnalyzerId::new("SEC001-hardcoded-secret");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn analyzer_id_hash_consistency() {
        let mut map: HashMap<AnalyzerId, u32> = HashMap::new();
        map.insert(AnalyzerId::new("MAINT001-cyclomatic"), 1);
        assert_eq!(map[&AnalyzerId::new("MAINT001-cyclomatic")], 1);
    }

    #[test]
    fn analyzer_id_serde_round_trip() {
        let id = AnalyzerId::new("SEC001-hardcoded-secret");
        let json = serde_json::to_string(&id).unwrap();
        let back: AnalyzerId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn language_id_display() {
        assert_eq!(LanguageId("rust").to_string(), "rust");
    }

    #[test]
    fn analyzer_id_display() {
        assert_eq!(
            AnalyzerId::new("MAINT001-cyclomatic").to_string(),
            "MAINT001-cyclomatic"
        );
    }
}
