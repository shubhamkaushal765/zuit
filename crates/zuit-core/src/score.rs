//! [`Score`] type and the [`aggregate_dimension_score`] formula.
//!
//! The scoring formula is defined in `ARCH_SPEC` §5.6:
//!
//! ```text
//! weights      = { Info: 0, Low: 1, Medium: 4, High: 12, Critical: 30 }
//! weighted_sum = Σ weights[finding.severity]
//! penalty      = clamp(weighted_sum / max(kloc, 1), 0, 100)
//! score        = 100 − penalty
//! ```
//!
//! `kloc` is the effective lines of code in languages supported by the analyzer.

use serde::{Deserialize, Serialize};

use crate::analyzer::Severity;

/// A quality score in the range `[0.0, 100.0]` where 100 means no findings.
///
/// Higher is better.  The value is produced by [`aggregate_dimension_score`]
/// and stored in the [`crate::engine::Report`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Score(pub f32);

impl Score {
    /// Returns the numeric value of the score.
    #[must_use]
    pub fn value(self) -> f32 {
        self.0
    }
}

/// The integer weight of each severity level used in the scoring formula.
///
/// Returns 0 for `Info` (informational findings do not affect the score).
#[must_use]
pub fn severity_weight(sev: Severity) -> u32 {
    match sev {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 4,
        Severity::High => 12,
        Severity::Critical => 30,
    }
}

/// Computes a dimension score from a list of finding severities and a `kloc` value.
///
/// The formula (`ARCH_SPEC` §5.6):
/// ```text
/// weighted_sum = Σ weights[severity]
/// penalty      = clamp(weighted_sum / max(kloc, 1.0), 0.0, 100.0)
/// score        = 100.0 − penalty
/// ```
///
/// `kloc` is the project's effective lines of code in the languages covered by
/// the dimension's analyzers.  When no findings are present, the score is 100.
///
/// The return value is always in `[0.0, 100.0]`.
#[must_use]
pub fn aggregate_dimension_score(severities: &[Severity], kloc: f32) -> Score {
    let weighted_sum: u32 = severities.iter().copied().map(severity_weight).sum();
    let effective_kloc = kloc.max(1.0);
    #[allow(clippy::cast_precision_loss)]
    let penalty = (weighted_sum as f32 / effective_kloc).clamp(0.0, 100.0);
    Score(100.0 - penalty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn empty_findings_score_is_100() {
        let score = aggregate_dimension_score(&[], 10.0);
        assert!((score.0 - 100.0).abs() < f32::EPSILON);
    }

    #[test]
    fn score_bounds_high_severity() {
        // Many critical findings should bottom out at 0.0, not go negative.
        let many: Vec<Severity> = vec![Severity::Critical; 1000];
        let score = aggregate_dimension_score(&many, 1.0);
        assert!(score.0 >= 0.0);
        assert!(score.0 <= 100.0);
    }

    #[test]
    fn score_never_exceeds_100() {
        let score = aggregate_dimension_score(&[], 0.0);
        assert!(score.0 <= 100.0);
    }

    #[test]
    fn info_severity_does_not_change_score() {
        let without = aggregate_dimension_score(&[], 10.0);
        let with_info = aggregate_dimension_score(&[Severity::Info; 100], 10.0);
        assert!((without.0 - with_info.0).abs() < f32::EPSILON);
    }

    #[test]
    fn kloc_zero_treated_as_one() {
        // kloc = 0 should be treated as 1 to avoid division by zero
        let score = aggregate_dimension_score(&[Severity::High], 0.0);
        // weight(High) = 12, penalty = 12 / 1 = 12, score = 88
        assert!((score.0 - 88.0).abs() < f32::EPSILON);
    }

    #[test]
    fn known_formula_values() {
        // weight(Medium) = 4, kloc = 2.0 → penalty = 4/2 = 2 → score = 98
        let score = aggregate_dimension_score(&[Severity::Medium], 2.0);
        assert!((score.0 - 98.0).abs() < f32::EPSILON);
    }

    proptest! {
        #[test]
        fn score_always_in_bounds(
            sev_indices in proptest::collection::vec(0u8..5, 0..200),
            kloc in 0.0f32..=1_000_000.0f32
        ) {
            let sevs: Vec<Severity> = sev_indices.iter().map(|&i| match i {
                0 => Severity::Info,
                1 => Severity::Low,
                2 => Severity::Medium,
                3 => Severity::High,
                _ => Severity::Critical,
            }).collect();
            let score = aggregate_dimension_score(&sevs, kloc);
            prop_assert!(score.0 >= 0.0, "score below 0: {}", score.0);
            prop_assert!(score.0 <= 100.0, "score above 100: {}", score.0);
        }

        #[test]
        fn empty_findings_always_score_100(kloc in 0.0f32..=1_000_000.0f32) {
            let score = aggregate_dimension_score(&[], kloc);
            prop_assert!((score.0 - 100.0).abs() < 1e-5, "expected 100 got {}", score.0);
        }

        #[test]
        fn adding_nonzero_weight_finding_never_increases_score(
            sev_indices in proptest::collection::vec(0u8..5, 0..100),
            kloc in 0.01f32..=10_000.0f32,
            // Add a non-Info finding (index 1..=4 → Low through Critical)
            extra_sev_idx in 1u8..5
        ) {
            let sevs: Vec<Severity> = sev_indices.iter().map(|&i| match i {
                0 => Severity::Info,
                1 => Severity::Low,
                2 => Severity::Medium,
                3 => Severity::High,
                _ => Severity::Critical,
            }).collect();
            let base_score = aggregate_dimension_score(&sevs, kloc);

            let extra = match extra_sev_idx {
                1 => Severity::Low,
                2 => Severity::Medium,
                3 => Severity::High,
                _ => Severity::Critical,
            };
            let mut with_extra = sevs.clone();
            with_extra.push(extra);
            let new_score = aggregate_dimension_score(&with_extra, kloc);

            prop_assert!(
                new_score.0 <= base_score.0 + 1e-5,
                "score increased: {} -> {} after adding {:?}",
                base_score.0, new_score.0, extra
            );
        }
    }
}
