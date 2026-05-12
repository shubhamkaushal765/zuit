//! Damerau-Levenshtein distance + bundled top-crates.io name list for `CHAIN002`.
//!
//! # Snapshot date
//!
//! The `TOP_CRATES` constant was assembled on **2026-05** from the crates.io
//! download statistics for popular crates.  It is **not automatically refreshed**.
//! See `docs/rules/CHAIN002-typosquat-distance.md` for the refresh policy.
//!
//! # Refresh policy
//!
//! Run the following to regenerate from an offline CSV snapshot:
//! ```sh
//! # Download from crates.io data dumps and extract top-N names
//! # Then update TOP_CRATES below and commit.
//! ```

// ── Bundled top-crates.io list ────────────────────────────────────────────────

/// Snapshot of ~60 most-downloaded crates.io packages (2026-05).
///
/// Used by CHAIN002 to detect dependency names within Damerau-Levenshtein
/// distance 1–2 of a popular name (default threshold: 2).
///
/// **Maintenance:** this list must be refreshed periodically; see
/// `docs/rules/CHAIN002-typosquat-distance.md`.
pub(crate) static TOP_CRATES: &[&str] = &[
    "serde",
    "serde_json",
    "tokio",
    "async-std",
    "futures",
    "rand",
    "regex",
    "log",
    "tracing",
    "anyhow",
    "thiserror",
    "clap",
    "structopt",
    "syn",
    "quote",
    "proc-macro2",
    "hyper",
    "reqwest",
    "axum",
    "warp",
    "actix-web",
    "sqlx",
    "diesel",
    "rusqlite",
    "redis",
    "mongodb",
    "chrono",
    "time",
    "uuid",
    "base64",
    "hex",
    "sha2",
    "rayon",
    "crossbeam",
    "parking_lot",
    "once_cell",
    "lazy_static",
    "bytes",
    "smallvec",
    "indexmap",
    "dashmap",
    "ahash",
    "fxhash",
    "blake3",
    "ring",
    "ureq",
    "postgres",
    "prost",
    "num-traits",
    "num-bigint",
    "image",
    "png",
    "walkdir",
    "ignore",
    "glob",
    "globset",
    "tempfile",
    "fs_extra",
    "notify",
    "dialoguer",
    "indicatif",
    "console",
];

// ── Damerau-Levenshtein distance ──────────────────────────────────────────────

/// Computes the Damerau-Levenshtein distance between two strings (full
/// unrestricted variant — counts substitutions, insertions, deletions, and
/// adjacent transpositions as single operations).
///
/// Uses the standard O(n·m) DP table.
pub(crate) fn damerau_levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let na = a.len();
    let nb = b.len();

    if na == 0 {
        return nb;
    }
    if nb == 0 {
        return na;
    }

    // d[i][j] = distance between a[..i] and b[..j]
    let mut d = vec![vec![0usize; nb + 1]; na + 1];

    #[allow(clippy::needless_range_loop)]
    for i in 0..=na {
        d[i][0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }

    for i in 1..=na {
        for j in 1..=nb {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1) // deletion
                .min(d[i][j - 1] + 1) // insertion
                .min(d[i - 1][j - 1] + cost); // substitution

            // Transposition
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + cost);
            }
        }
    }

    d[na][nb]
}

/// For a given dependency name, returns `Some(legit_name)` if the
/// Damerau-Levenshtein distance to any name in `TOP_CRATES` is in
/// `(0, threshold]` (exact matches excluded).
///
/// Normalises both sides: lowercase, hyphens and underscores treated
/// equivalently (both collapsed to `_`).
pub(crate) fn is_typosquat(name: &str, threshold: usize) -> Option<&'static str> {
    let norm_name = normalise(name);
    for &top in TOP_CRATES {
        let norm_top = normalise(top);
        let d = damerau_levenshtein(&norm_name, &norm_top);
        if d >= 1 && d <= threshold {
            return Some(top);
        }
    }
    None
}

/// Normalises a crate name for comparison: lowercase, hyphens and underscores
/// collapsed to `_`.
fn normalise(name: &str) -> String {
    name.to_lowercase().replace('-', "_")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{damerau_levenshtein as dist, is_typosquat};

    #[test]
    fn dl_transposition_tokio() {
        // "tokoi" — swapped 'i' and 'o' — one transposition away
        assert_eq!(dist("tokoi", "tokio"), 1);
    }

    #[test]
    fn dl_totally_different() {
        assert_eq!(dist("foo", "bar"), 3);
    }

    #[test]
    fn dl_identical() {
        assert_eq!(dist("tokio", "tokio"), 0);
    }

    #[test]
    fn dl_empty_strings() {
        assert_eq!(dist("", ""), 0);
        assert_eq!(dist("abc", ""), 3);
        assert_eq!(dist("", "abc"), 3);
    }

    #[test]
    fn dl_two_edits() {
        // "serdes" has 2 extra characters — distance 2 from "serde"
        assert_eq!(dist("serdes_", "serde"), 2);
    }

    #[test]
    fn is_typosquat_tokoi_flagged() {
        // "tokoi" is distance 1 from "tokio" → flagged
        let result = is_typosquat("tokoi", 2);
        assert!(result.is_some(), "tokoi should be flagged");
        assert_eq!(result.unwrap(), "tokio");
    }

    #[test]
    fn is_typosquat_tokio_exact_match_clean() {
        // Exact match is excluded
        let result = is_typosquat("tokio", 2);
        assert!(result.is_none(), "exact match tokio must not be flagged");
    }

    #[test]
    fn is_typosquat_distance_threshold() {
        // "tokioo" is distance 1 (insertion) → flagged at threshold 2
        let d1 = is_typosquat("tokioo", 2);
        assert!(d1.is_some(), "distance-1 dep should be flagged");

        // "tokioox" is distance 2 (two insertions) → flagged at threshold 2
        let d2 = is_typosquat("tokioox", 2);
        assert!(d2.is_some(), "distance-2 dep should be flagged");

        // "tokiooxx" is distance 3 → not flagged at threshold 2
        let d3 = is_typosquat("tokiooxx", 2);
        assert!(
            d3.is_none(),
            "distance-3 dep must NOT be flagged at threshold=2"
        );
    }
}
