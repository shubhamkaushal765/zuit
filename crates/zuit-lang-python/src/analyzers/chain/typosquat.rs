//! Damerau-Levenshtein distance + bundled top-PyPI name list for `CHAIN002`.
//!
//! # Snapshot date
//! The `TOP_PYPI` constant was assembled on **2026-05** from the `PyPI` download
//! statistics for the top ~50 packages.  It is **not automatically refreshed**.
//! See `docs/rules/CHAIN002-typosquat-distance.md` §Future Maintenance for the
//! refresh policy; the maintenance burden is also noted in `.agent/PYTHON_PLAN.md`
//! §8.

// ── Bundled top-PyPI list ─────────────────────────────────────────────────────

/// Snapshot of the ~50 most-downloaded `PyPI` packages (2026-05).
///
/// Used by CHAIN002 to detect dependency names within Damerau-Levenshtein
/// distance 1–4 of a popular name (default threshold: 2).
///
/// **Maintenance:** this list must be refreshed periodically; see
/// `docs/rules/CHAIN002-typosquat-distance.md` §Future Maintenance.
pub(crate) static TOP_PYPI: &[&str] = &[
    "requests",
    "numpy",
    "pandas",
    "scipy",
    "matplotlib",
    "scikit-learn",
    "tensorflow",
    "torch",
    "keras",
    "django",
    "flask",
    "fastapi",
    "sqlalchemy",
    "pytest",
    "pytest-cov",
    "click",
    "pyyaml",
    "jinja2",
    "lxml",
    "beautifulsoup4",
    "urllib3",
    "idna",
    "certifi",
    "charset-normalizer",
    "six",
    "setuptools",
    "wheel",
    "pip",
    "packaging",
    "tomli",
    "attrs",
    "typing-extensions",
    "importlib-metadata",
    "more-itertools",
    "python-dateutil",
    "pytz",
    "cryptography",
    "bcrypt",
    "passlib",
    "redis",
    "celery",
    "gunicorn",
    "uvicorn",
    "httpx",
    "aiohttp",
    "websockets",
    "pillow",
    "opencv-python",
    "transformers",
    "langchain",
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

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::damerau_levenshtein as dist;

    #[test]
    fn dl_transposition_requessts() {
        // "requessts" has a doubled 's' — one deletion away from "requests"
        assert_eq!(dist("requessts", "requests"), 1);
    }

    #[test]
    fn dl_transposition_reuqests() {
        // "reuqests" — swapped 'u' and 'q' — one transposition away
        assert_eq!(dist("reuqests", "requests"), 1);
    }

    #[test]
    fn dl_totally_different() {
        assert_eq!(dist("foo", "bar"), 3);
    }

    #[test]
    fn dl_identical() {
        assert_eq!(dist("requests", "requests"), 0);
    }

    #[test]
    fn dl_empty_strings() {
        assert_eq!(dist("", ""), 0);
        assert_eq!(dist("abc", ""), 3);
        assert_eq!(dist("", "abc"), 3);
    }

    #[test]
    fn dl_two_edits() {
        // "numpyyy" has 2 extra characters compared to "numpy" — distance 2
        assert_eq!(dist("numpyyy", "numpy"), 2);
        // "numpyyxx" has 3 extra characters — distance 3
        assert_eq!(dist("numpyyxx", "numpy"), 3);
    }
}
