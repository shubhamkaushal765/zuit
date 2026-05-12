//! Rust external-tool adapters (cargo audit, cargo clippy, cargo deny, cargo geiger).
//!
//! Shared subprocess infrastructure (`Outcome`, `run_with_limits`,
//! `build_line_starts`, `compute_span`, and the default timeout/cap constants)
//! now lives in [`zuit_core::external`].

pub mod cargo_audit;
pub mod cargo_clippy;
pub mod cargo_deny;
pub mod cargo_geiger;
