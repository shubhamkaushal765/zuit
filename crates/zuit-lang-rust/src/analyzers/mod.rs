//! Rust-specific analyzers.
//!
//! - [`unsafe_block`]: `SEC101-rust-unsafe` — records every `unsafe` block,
//!   function, impl, or trait in a Rust source file.
//! - [`sound`]: `SOUND001`–`SOUND006` — unsafe soundness sub-rules.
//! - [`pkg`]: `PKG001`–`PKG010` — Cargo.toml metadata rules.
//! - [`health`]: `HEALTH001`–`HEALTH005` — project health rules.
//! - [`chain`]: `CHAIN001`–`CHAIN004` — supply chain rules.
//! - [`perf`]: `PERF001`–`PERF003` — performance heuristic rules.
//! - [`eco`]: `ECO001`–`ECO004` — ecosystem compatibility rules.
//! - [`ci`]: `CI001`–`CI005` — CI/CD & release hygiene rules.
//! - [`empty_block`]: `MAINT013-empty-block` — flags empty `if`/`for`/`while` blocks.
//! - [`external`]: external-tool adapters (`cargo audit`, `cargo clippy`,
//!   `cargo geiger`, `cargo deny`).

pub mod active_debug_code;
pub mod bind_all_interfaces;
pub mod chain;
pub mod ci;
pub mod eco;
pub mod empty_block;
pub mod external;
pub mod hardcoded_security_constant;
pub mod health;
pub mod log_injection;
pub mod missing_default_case;
pub mod perf;
pub mod pkg;
pub mod sound;
pub mod unsafe_block;
