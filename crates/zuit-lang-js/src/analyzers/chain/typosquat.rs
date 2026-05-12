//! Typosquatting detection helpers for the `CHAIN002` analyzer.
//!
//! # Bundled package list
//!
//! [`TOP_NPM_NAMES`] is a static snapshot of well-known npm package names used
//! as the reference set for Damerau-Levenshtein distance comparisons. The list
//! was assembled from the npm download-count top-100 (2024-Q4 snapshot) and
//! includes the most frequently depended-upon libraries across the ecosystem.
//!
//! **Refresh policy:** update this list quarterly by consulting the npm
//! download-count API (`https://api.npmjs.org/downloads/point/last-month`) in
//! offline mode (export a CSV, then paste the package names here). Never make
//! network calls at runtime. See `.agent/JS_PLAN.md` §4 risk #3.

/// A static snapshot (~50 names) of the most widely-used npm packages.
///
/// Used as the reference corpus for [`is_typosquat_of`]. Names are lower-case
/// ASCII as published on the npm registry. The list is intentionally small to
/// keep compile time and false-positive rate low; expand it via a quarterly
/// offline refresh (see module-level doc comment).
pub const TOP_NPM_NAMES: &[&str] = &[
    "react",
    "react-dom",
    "lodash",
    "express",
    "axios",
    "webpack",
    "typescript",
    "vue",
    "next",
    "eslint",
    "prettier",
    "jest",
    "chalk",
    "commander",
    "dotenv",
    "moment",
    "uuid",
    "cors",
    "body-parser",
    "mocha",
    "babel-core",
    "underscore",
    "jquery",
    "async",
    "request",
    "bluebird",
    "rxjs",
    "debug",
    "glob",
    "minimist",
    "semver",
    "yaml",
    "inquirer",
    "yargs",
    "winston",
    "morgan",
    "helmet",
    "passport",
    "socket.io",
    "mongoose",
    "sequelize",
    "knex",
    "nodemailer",
    "multer",
    "sharp",
    "date-fns",
    "ramda",
    "immutable",
    "redux",
    "mobx",
];

/// Computes the Damerau-Levenshtein (optimal string alignment) distance
/// between two strings.
///
/// This variant includes transpositions of adjacent characters as a single
/// edit operation, which is the most common typo type and essential for
/// detecting package-name typosquatting (e.g. `lodahs` for `lodash`).
///
/// # Examples
///
/// ```
/// use zuit_lang_js::analyzers::chain::typosquat::damerau_levenshtein;
/// assert_eq!(damerau_levenshtein("lodash", "lodahs"), 1);
/// assert_eq!(damerau_levenshtein("react", "recat"), 1);
/// ```
#[must_use]
pub fn damerau_levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let la = a.len();
    let lb = b.len();

    // dp[i][j] = edit distance between a[..i] and b[..j].
    let mut dp = vec![vec![0usize; lb + 1]; la + 1];

    // Initialise base cases: distance from empty string is the string length.
    for (i, row) in dp.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in dp[0].iter_mut().enumerate() {
        *cell = j;
    }

    for i in 1..=la {
        for j in 1..=lb {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            dp[i][j] = (dp[i - 1][j] + 1) // deletion
                .min(dp[i][j - 1] + 1) // insertion
                .min(dp[i - 1][j - 1] + cost); // substitution

            // Transposition of adjacent characters.
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                dp[i][j] = dp[i][j].min(dp[i - 2][j - 2] + cost);
            }
        }
    }

    dp[la][lb]
}

/// Returns `Some(target)` if `name` is within `threshold` edits of any entry
/// in [`TOP_NPM_NAMES`] but is not an exact match; returns `None` otherwise.
///
/// The default threshold recommended by `.agent/JS_PLAN.md` is `2`. Lower
/// values produce fewer false positives but may miss single-character swaps.
///
/// The project's own `name` field should be excluded from comparisons before
/// calling this function (see `CHAIN002` analyzer).
#[must_use]
pub fn is_typosquat_of(name: &str, threshold: usize) -> Option<&'static str> {
    for &target in TOP_NPM_NAMES {
        if name == target {
            // Exact match — not a typosquat.
            return None;
        }
        if damerau_levenshtein(name, target) <= threshold {
            return Some(target);
        }
    }
    None
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── damerau_levenshtein unit tests ────────────────────────────────────────

    #[test]
    fn dl_empty_strings_distance_zero() {
        assert_eq!(damerau_levenshtein("", ""), 0);
    }

    #[test]
    fn dl_equal_strings_distance_zero() {
        assert_eq!(damerau_levenshtein("lodash", "lodash"), 0);
    }

    #[test]
    fn dl_one_substitution() {
        // "lodash" → "lodaXh": one substitution
        assert_eq!(damerau_levenshtein("lodash", "lodaXh"), 1);
    }

    #[test]
    fn dl_one_transposition() {
        // "lodash" → "lodahs": swap last two chars
        assert_eq!(damerau_levenshtein("lodash", "lodahs"), 1);
    }

    #[test]
    fn dl_three_edits() {
        // "react" → "rxact_z": 3 edits (substitution + insertion + no-op)
        // Actually let's measure "react" vs "zxact": z→r (sub), nothing else? No.
        // "react" vs "zxacy": z(sub r), a stays, c stays, y(sub t) = 2 edits, x(sub e) = 3
        assert_eq!(damerau_levenshtein("react", "zxacy"), 3);
    }

    #[test]
    fn dl_insertion_distance() {
        // "" to "abc" = 3 insertions
        assert_eq!(damerau_levenshtein("", "abc"), 3);
    }

    #[test]
    fn dl_deletion_distance() {
        // "abc" to "" = 3 deletions
        assert_eq!(damerau_levenshtein("abc", ""), 3);
    }

    // ── is_typosquat_of tests ─────────────────────────────────────────────────

    #[test]
    fn exact_match_returns_none() {
        assert!(is_typosquat_of("lodash", 2).is_none());
        assert!(is_typosquat_of("react", 2).is_none());
    }

    #[test]
    fn one_edit_away_returns_some() {
        // "lodahs" is 1 transposition away from "lodash"
        let result = is_typosquat_of("lodahs", 2);
        assert_eq!(
            result,
            Some("lodash"),
            "expected Some(\"lodash\"), got {result:?}"
        );
    }

    #[test]
    fn two_edits_away_returns_some() {
        // "lodaXY" → "lodash": X→s (sub) + Y→h (sub) = 2 substitutions
        let result = is_typosquat_of("lodaXY", 2);
        assert_eq!(
            result,
            Some("lodash"),
            "expected Some(\"lodash\"), got {result:?}"
        );
    }

    #[test]
    fn three_edits_returns_none() {
        // "loXYZh" → "lodash": 3 substitutions → distance 3 > threshold 2
        assert!(is_typosquat_of("loXYZh", 2).is_none());
    }

    #[test]
    fn completely_different_name_returns_none() {
        assert!(is_typosquat_of("my-totally-unique-lib-xyz9", 2).is_none());
    }
}
