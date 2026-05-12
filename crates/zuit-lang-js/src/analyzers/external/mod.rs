//! External-tool adapters for JS/TS analysis.
//!
//! Each adapter follows the canonical external-tool shape (60 s timeout, 32 MiB
//! stdout cap, missing-binary `Info` finding, suppression-compatible): a pure
//! `parse_<tool>_output` function, an `<Tool>Outcome` enum, and a subprocess
//! runner with a configurable timeout and stdout cap.

pub mod dependency_cruiser;
pub mod eslint;
pub mod npm_audit;
pub mod tsc;
