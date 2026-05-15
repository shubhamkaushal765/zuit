//! Daemon lifecycle dispatcher.
//!
//! The scan-history daemon (`zuit show`) is a POSIX double-fork daemon and is
//! only fully functional on Unix targets. To keep the `zuit-cli` surface
//! identical across platforms (so `cargo install zuit` and `pip install zuit`
//! produce a binary that links cleanly on Windows), this module exposes a
//! cross-platform public API: on Unix it forwards to the `unix` submodule;
//! on other targets it forwards to a `windows` stub whose `spawn*` calls
//! return a "not supported" error and whose other entry points are inert.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(not(unix))]
mod windows;
#[cfg(not(unix))]
pub use windows::*;
