//! PERF — Performance heuristics rule family.
//!
//! Rules in this family identify patterns that impose hidden performance costs
//! (load-time penalties, large artifact sizes, import side effects) without
//! requiring runtime measurement.
//!
//! All rules use `Dimension::Custom("performance")`.
//!
//! | Rule ID | Description | Kind |
//! |---------|-------------|------|
//! | `PERF001-heavy-import` | Top-level import of heavyweight packages in a library | FileLevel |
//! | `PERF002-wheel-size` | `dist/*.whl` > 50 MiB or `.tar.gz` > 100 MiB | ProjectLevel |
//! | `PERF003-import-side-effect` | Top-level side-effectful statement at import time | FileLevel |

pub mod perf001_heavy_import;
pub mod perf002_wheel_size;
pub mod perf003_import_side_effect;
