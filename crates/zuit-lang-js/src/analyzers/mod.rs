//! JS/TS-specific analyzers.
//!
//! All analyzers in this module implement [`zuit_core::Analyzer`] and are
//! registered alongside the language frontend via [`crate::register`].

pub mod active_debug_code;
pub mod assignment_in_condition;
pub mod bind_all_interfaces;
pub mod block_delimitation;
pub mod chain;
pub mod dead_store;
pub mod deprecated_function;
pub mod empty_block;
pub mod eval_sink;
pub mod external;
pub mod hardcoded_security_constant;
pub mod health;
pub mod infinite_loop_no_exit;
pub mod log_injection;
pub mod missing_default_case;
pub mod operator_precedence;
pub mod perf;
pub mod pkg;
pub mod switch_fallthrough;
pub mod unreachable_code;
