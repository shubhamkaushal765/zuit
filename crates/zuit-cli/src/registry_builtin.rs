//! Re-exports the built-in registry constructor from `zuit-registry`.
//!
//! The actual implementation lives in the `zuit-registry` crate so that
//! both `zuit-cli` and `zuit-lsp` can share the same registry without
//! duplicating the wiring.

pub(crate) use zuit_registry::build_registry;
