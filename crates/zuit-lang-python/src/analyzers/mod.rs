//! Python-specific analyzers that ship alongside the Python language frontend.
//!
//! Currently implemented:
//! - [`eval_sink`]: `SEC002-eval-sink` — detects bare calls to `eval`, `exec`,
//!   and `__import__`.
//! - [`pkg`]: `PKG001`–`PKG010` — Packaging & Distribution rule family.
//! - [`external`]: External-tool adapters for `ruff` and `bandit`.
//! - [`health`]: `HEALTH001`–`HEALTH005` — Project Health rule family.
//! - [`api`]: `API001`–`API003` — API Stability rule family.

pub mod active_debug_code;
pub mod api;
pub mod chain;
pub mod empty_block;
pub mod eval_sink;
pub mod external;
pub mod health;
pub mod perf;
pub mod pkg;
