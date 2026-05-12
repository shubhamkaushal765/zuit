//! Fan-out fixture for Rust — positive case for CPLX001-fan-out.
//!
//! This file contains more than 20 `use` statements referencing distinct
//! modules to trigger the fan-out rule.

use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::sync::atomic::AtomicUsize;
use std::path::Path;
use std::path::PathBuf;
use std::io::Read;
use std::io::Write;
use std::io::BufReader;
use std::io::BufWriter;
use std::fs::File;
use std::env;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use std::fmt;
use std::str;
use std::num::ParseIntError;

/// Placeholder — the many `use` statements above trigger CPLX001.
pub fn placeholder() -> &'static str {
    "fan-out-example"
}
