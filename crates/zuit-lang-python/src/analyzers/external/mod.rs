//! Shared infrastructure for external-tool adapters (ruff, bandit, mypy, radon).
//!
//! [`Outcome`], [`run_with_limits`], [`build_line_starts`], and [`compute_span`]
//! are re-exported from [`zuit_core::external`]; no local copies are kept.

pub mod bandit;
pub mod mypy;
pub mod radon;
pub mod ruff;

pub use zuit_core::external::{
    DEFAULT_MAX_STDOUT_BYTES, DEFAULT_TIMEOUT_SECS, Outcome, build_line_starts, compute_span,
    run_with_limits,
};
