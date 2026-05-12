//! Output formatters for zuit analysis reports.
//!
//! This crate provides six output formats for a [`zuit_core::engine::Report`]:
//!
//! | Format | Function | Notes |
//! |--------|----------|-------|
//! | JSON | [`json::render_json`] | Pretty-printed, stable field order. Documented in `docs/json-schema.md`. |
//! | Terminal | [`terminal::render_terminal`] | Grouped by dimension → severity. Optional ANSI colour and OSC-8 hyperlinks. |
//! | Markdown | [`markdown::render_markdown`] | Scoreboard table + collapsible `<details>` blocks, PR-comment friendly. |
//! | SARIF | [`sarif::render_sarif`] | Valid SARIF 2.1.0; single merged run strategy for v1. |
//! | Checkstyle | [`checkstyle::render_checkstyle`] | Checkstyle v8 XML; consumed by `IntelliJ` and `SonarQube`. |
//! | `JUnit` | [`junit::render_junit`] | `JUnit` XML (Surefire/Maven flavour); consumed by GitHub Actions, Jenkins, and GitLab CI. |
//!
//! The top-level entry point is [`render`], which dispatches to the appropriate
//! sub-module based on a [`ReportFormat`] value.
#![warn(missing_docs)]

pub mod checkstyle;
pub mod json;
pub mod junit;
pub mod markdown;
pub mod sarif;
pub mod terminal;

use zuit_core::engine::Report;

pub use checkstyle::render_checkstyle;
pub use json::render_json;
pub use junit::render_junit;
pub use markdown::render_markdown;
pub use sarif::render_sarif;
pub use terminal::render_terminal;

/// The output format to render a [`Report`] into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// Pretty-printed JSON with stable field order.
    Json,
    /// Coloured terminal output grouped by dimension and severity.
    Terminal,
    /// Markdown suitable for GitHub PR comments.
    Markdown,
    /// SARIF 2.1.0 — single merged run, valid per the SARIF 2.1.0 schema.
    Sarif,
    /// Checkstyle v8 XML — consumed by `IntelliJ` (Checkstyle plugin) and `SonarQube`.
    Checkstyle,
    /// `JUnit` XML (Surefire/Maven flavour) — consumed by GitHub Actions, Jenkins, and GitLab CI.
    Junit,
}

/// Options that control how a report is rendered.
///
/// The default is CI-friendly (no colour, no hyperlinks).
#[derive(Debug, Clone, Default)]
pub struct RenderOptions {
    /// When `true`, ANSI colour escape codes are emitted in terminal output.
    /// When `false`, output is plain ASCII.
    pub use_color: bool,
    /// When `true`, file paths in terminal output are wrapped in OSC-8 hyperlinks.
    pub use_hyperlinks: bool,
}

/// Errors that can occur while rendering a report.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    /// The requested format is not implemented.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    /// A `serde_json` serialization failure.
    #[error("serialization error: {0}")]
    Serialize(#[from] serde_json::Error),
    /// A `std::fmt::Write` failure (should never occur in practice because
    /// `String`'s `Write` impl is infallible, but the `?` operator requires it).
    #[error(transparent)]
    Fmt(#[from] std::fmt::Error),
    /// A `quick_xml` write or encoding failure.
    #[error("XML error: {0}")]
    Xml(#[from] quick_xml::Error),
}

/// Renders `report` in the requested format.
///
/// For [`ReportFormat::Terminal`] the default [`RenderOptions`] are used
/// (no colour, no hyperlinks). Call [`render_terminal`] directly for full control.
///
/// # Errors
///
/// Returns [`ReportError::Serialize`] if JSON serialization fails (JSON or SARIF).
/// Returns [`ReportError::Fmt`] if string formatting fails (Markdown or terminal).
pub fn render(
    format: ReportFormat,
    report: &Report,
    opts: &RenderOptions,
) -> Result<String, ReportError> {
    match format {
        ReportFormat::Json => render_json(report),
        ReportFormat::Terminal => render_terminal(report, opts),
        ReportFormat::Markdown => render_markdown(report),
        ReportFormat::Sarif => render_sarif(report),
        ReportFormat::Checkstyle => render_checkstyle(report),
        ReportFormat::Junit => render_junit(report),
    }
}
