//! Unsafe soundness analyzers (`SOUND001`–`SOUND006`).
//!
//! Each sub-module provides one analyzer that targets a specific unsafe-code
//! pattern. All six share `Dimension::Custom("unsafe_soundness")`.
//!
//! | Rule | Severity | What it detects |
//! |---|---|---|
//! | `SOUND001` | Medium | `unsafe { }` block without a `// SAFETY:` comment |
//! | `SOUND002` | High | `pub unsafe fn` exposed at the module boundary |
//! | `SOUND003` | High | `mem::transmute` call (CWE-704) |
//! | `SOUND004` | High | `pub fn` with raw pointer in signature |
//! | `SOUND005` | High | function body mixing `unsafe` block with parser/decoder call |
//! | `SOUND006` | Medium | `unsafe fn` inside `extern "…"` block without `SAFETY:` doc |

pub mod sound001_unsafe_block_missing_safety_comment;
pub mod sound002_unsafe_in_pub_api_signature;
pub mod sound003_transmute_usage;
pub mod sound004_raw_pointer_in_pub_api;
pub mod sound005_unsafe_and_parsing_combo;
pub mod sound006_ffi_without_safety_doc;

pub use sound001_unsafe_block_missing_safety_comment::Sound001UnsafeBlockMissingSafetyComment;
pub use sound002_unsafe_in_pub_api_signature::Sound002UnsafeInPubApiSignature;
pub use sound003_transmute_usage::Sound003TransmuteUsage;
pub use sound004_raw_pointer_in_pub_api::Sound004RawPointerInPubApi;
pub use sound005_unsafe_and_parsing_combo::Sound005UnsafeAndParsingCombo;
pub use sound006_ffi_without_safety_doc::Sound006FfiWithoutSafetyDoc;
