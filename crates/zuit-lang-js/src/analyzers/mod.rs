//! JS/TS-specific analyzers.
//!
//! All analyzers in this module implement [`zuit_core::Analyzer`] and are
//! registered alongside the language frontend via [`crate::register`].

pub mod chain;
pub mod empty_block;
pub mod eval_sink;
pub mod external;
pub mod health;
pub mod perf;
pub mod pkg;
