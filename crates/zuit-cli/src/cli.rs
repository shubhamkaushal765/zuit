//! Clap-derived CLI argument types.
//!
//! All top-level types are re-exported from `main.rs` where needed.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

/// `zuit` — multi-language static analysis.
#[derive(Debug, Parser)]
#[command(name = "zuit", version, about, long_about = None)]
#[command(propagate_version = true)]
pub(crate) struct Cli {
    /// Increase log verbosity. Pass once for INFO, twice for DEBUG.
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// Analyse source files under a path and emit findings.
    Analyze(AnalyzeArgs),
    /// Alias for `analyze` — scan source files under a path and emit findings.
    Scan(AnalyzeArgs),
    /// Read a JSON report file and re-render it in another format.
    Report(ReportArgs),
    /// List registered languages or analyzers.
    #[command(subcommand)]
    List(ListCommand),
    /// Write a default `zuit.toml` to the current directory.
    Init,
    /// Open the scan-history viewer in a browser. Starts a local daemon if
    /// one is not already running.
    Show,
    /// Stop the running scan-history daemon.
    Stop,
    /// Print the daemon status.
    Status,
    /// Install a pre-commit git hook that runs `zuit analyze`.
    InstallHook(InstallHookArgs),
    /// Compute a finding-level diff between two JSON report files.
    Diff(DiffArgs),
    /// Baseline management subcommands.
    #[command(subcommand)]
    Baseline(BaselineCommand),
    /// Watch a directory for changes and re-run analysis on each change.
    Watch(WatchArgs),
    /// Start the Language Server Protocol server on stdin/stdout.
    Lsp,
    /// Emit a shell completion script to stdout.
    ///
    /// Pipe the output into the appropriate file or `eval` it in your shell
    /// configuration.  For example:
    ///
    /// ```sh
    /// zuit completions bash > ~/.local/share/bash-completion/completions/zuit
    /// zuit completions zsh > ~/.zfunc/_zuit
    /// ```
    Completions(CompletionsArgs),
    /// Install a third-party analyzer plugin from a local path or git URL.
    AddAnalyzer(AddAnalyzerArgs),
    /// Remove an installed plugin by name.
    RemoveAnalyzer(RemoveAnalyzerArgs),
    /// Update an installed git-sourced plugin.
    UpdateAnalyzer(UpdateAnalyzerArgs),
}

/// Arguments for `zuit completions`.
#[derive(Debug, Args)]
pub(crate) struct CompletionsArgs {
    /// The shell to generate completions for.
    pub shell: Shell,
}

/// Subcommands for `zuit baseline`.
#[derive(Debug, Subcommand)]
pub(crate) enum BaselineCommand {
    /// Capture the current findings as a baseline JSON file.
    Save(BaselineSaveArgs),
}

/// Arguments for `zuit baseline save`.
#[derive(Debug, Args)]
pub(crate) struct BaselineSaveArgs {
    /// Root path to analyse (default: `.`).
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Output file path (default: `zuit-baseline.json`).
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Analyse the tree at this git ref instead of the working tree.
    ///
    /// The ref is materialised via `git archive | tar -x` into a temp dir.
    /// Requires `git` to be in `PATH` and the path to be inside a git repo.
    #[arg(long = "ref", value_name = "GIT_REF")]
    pub git_ref: Option<String>,

    /// Path to a `zuit.toml` config file (overrides auto-discovery).
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,
}

/// Arguments for `zuit watch`.
#[derive(Debug, Args)]
pub(crate) struct WatchArgs {
    /// Root path to watch and analyse (default: `.`).
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Path to a `zuit.toml` config file (overrides auto-discovery).
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Disable ANSI colour in terminal output.
    #[arg(long)]
    pub no_color: bool,

    /// Disable the incremental file-hash cache.
    #[arg(long)]
    pub no_cache: bool,
}

/// Arguments for `zuit install-hook`.
#[derive(Debug, Args)]
pub(crate) struct InstallHookArgs {
    /// Overwrite an existing pre-commit hook.
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `zuit diff`.
#[derive(Debug, Args)]
pub(crate) struct DiffArgs {
    /// Path to the FROM report (JSON file produced by `zuit analyze --format json`).
    #[arg(value_name = "FROM")]
    pub from: PathBuf,

    /// Path to the TO report (JSON file produced by `zuit analyze --format json`).
    #[arg(value_name = "TO")]
    pub to: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = DiffFormat::Json)]
    pub format: DiffFormat,
}

/// Output format for `zuit diff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum DiffFormat {
    /// Pretty-printed JSON (default).
    Json,
    /// Human-readable terminal summary.
    Terminal,
}

/// Arguments for `zuit analyze`.
#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)] // CLI structs use many boolean flags by design
pub(crate) struct AnalyzeArgs {
    /// Root path to analyse (file or directory).
    #[arg(value_name = "PATH")]
    pub path: PathBuf,

    /// Comma-separated list of dimensions to include (e.g. `security,maintainability`).
    #[arg(long, value_delimiter = ',')]
    pub dimensions: Vec<String>,

    /// Comma-separated list of language IDs to restrict analysis to.
    #[arg(long, value_delimiter = ',')]
    pub languages: Vec<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Terminal)]
    pub format: Format,

    /// Write output to this file instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Path to a `zuit.toml` config file (overrides auto-discovery).
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Exit with code 1 if any finding has severity ≥ this level.
    #[arg(long, value_enum)]
    pub fail_on: Option<FailOnLevel>,

    /// Path to a baseline JSON file; findings present in the baseline are suppressed.
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    /// Disable ANSI colour in terminal output.
    #[arg(long)]
    pub no_color: bool,

    /// Emit OSC-8 hyperlinks for file paths in terminal output.
    #[arg(long)]
    pub hyperlinks: bool,

    /// Skip writing this run to `~/.zuit/`.
    #[arg(long)]
    pub no_save: bool,

    /// Disable the incremental file-hash cache for this run.
    ///
    /// By default, files whose content hash has not changed since the last run
    /// are not re-parsed.  Pass `--no-cache` to force a full re-analysis.
    #[arg(long)]
    pub no_cache: bool,

    /// Keep only findings whose OWASP category array contains at least one of
    /// these values (e.g. `A03:2021`).  Repeatable; comma-delimited within one
    /// flag.  Case-insensitive.
    #[arg(long = "owasp", value_delimiter = ',')]
    pub owasp: Vec<String>,

    /// Keep only findings whose CWE array contains at least one of these
    /// values (e.g. `CWE-89`).  Repeatable; comma-delimited within one flag.
    /// Case-insensitive.
    #[arg(long = "cwe", value_delimiter = ',')]
    pub cwe: Vec<String>,
}

/// Arguments for `zuit report`.
#[derive(Debug, Args)]
pub(crate) struct ReportArgs {
    /// Path to a JSON report file produced by `zuit analyze --format json`,
    /// or `-` to read from stdin.
    #[arg(value_name = "INPUT")]
    pub input: String,

    /// Output format (default: `terminal`).
    #[arg(long, value_enum, default_value_t = Format::Terminal)]
    pub format: Format,

    /// Write output to this file instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Disable ANSI colour in terminal output.
    #[arg(long)]
    pub no_color: bool,

    /// Emit OSC-8 hyperlinks for file paths in terminal output.
    #[arg(long)]
    pub hyperlinks: bool,
}

/// Output format for `zuit analyze`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Format {
    /// Pretty-printed JSON.
    Json,
    /// Coloured terminal output (default).
    Terminal,
    /// Markdown (GitHub PR-comment friendly).
    Markdown,
    /// SARIF 2.1.0 (not implemented in v1).
    Sarif,
    /// Checkstyle v8 XML (`IntelliJ` and `SonarQube` compatible).
    Checkstyle,
    /// `JUnit` XML (Surefire/Maven flavour); consumed by GitHub Actions, Jenkins, and GitLab CI.
    Junit,
}

/// The `--fail-on` severity threshold.
///
/// The threshold is *inclusive*: `--fail-on high` exits non-zero on any
/// `High` **or** `Critical` finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum FailOnLevel {
    /// Fail on any finding (includes Info).
    Info,
    /// Fail on Low or above.
    Low,
    /// Fail on Medium or above.
    Medium,
    /// Fail on High or above.
    High,
    /// Fail only on Critical findings.
    Critical,
}

/// Subcommands for `zuit list`.
#[derive(Debug, Subcommand)]
pub(crate) enum ListCommand {
    /// Print a table of registered language frontends and their file extensions.
    Languages,
    /// Print a table of registered analyzers and their metadata.
    Analyzers(ListAnalyzersArgs),
    /// Print a table of installed third-party analyzer plugins.
    Plugins,
}

/// Arguments for `zuit list analyzers`.
#[derive(Debug, Args)]
pub(crate) struct ListAnalyzersArgs {
    /// Print the documentation for the given rule ID.
    #[arg(long, value_name = "RULE_ID")]
    pub explain: Option<String>,
}

/// Arguments for `zuit add-analyzer`.
#[derive(Debug, Args)]
pub(crate) struct AddAnalyzerArgs {
    /// Local directory path or git URL.
    #[arg(value_name = "PATH_OR_URL")]
    pub source: String,

    /// Override the plugin's installed name (defaults to the manifest's name
    /// or, for git URLs, the slug derived from the URL).
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
}

/// Arguments for `zuit remove-analyzer`.
#[derive(Debug, Args)]
pub(crate) struct RemoveAnalyzerArgs {
    /// The installed plugin name.
    #[arg(value_name = "NAME")]
    pub name: String,
}

/// Arguments for `zuit update-analyzer`.
#[derive(Debug, Args)]
pub(crate) struct UpdateAnalyzerArgs {
    /// The installed plugin name.
    #[arg(value_name = "NAME")]
    pub name: String,
}
