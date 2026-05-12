//! `zuit` — static analysis CLI for Rust, Python, and more.
//!
//! Run `zuit --help` for usage information.
//!
//! # Subcommands
//!
//! - `zuit analyze <path>` — analyse source files and emit findings.
//! - `zuit scan <path>` — alias for `analyze`.
//! - `zuit report <input>` — re-render an existing JSON report in another format.
//! - `zuit list languages` — list registered language frontends.
//! - `zuit list analyzers [--explain <rule_id>]` — list analyzers or explain a rule.
//! - `zuit init` — write a default `zuit.toml` to the current directory.
//! - `zuit show` — open scan-history viewer in a browser (starts daemon if needed).
//! - `zuit stop` — stop the running scan-history daemon.
//! - `zuit status` — print the daemon status.
//! - `zuit install-hook` — install a pre-commit git hook.
//! - `zuit diff <FROM> <TO>` — compute a finding-level diff between two reports.
//! - `zuit baseline save [--output FILE] [--ref GIT_REF] [PATH]` — capture a baseline.
//! - `zuit watch [PATH]` — watch for changes and re-run analysis.
//! - `zuit lsp` — start the LSP server on stdin/stdout.
//! - `zuit completions <shell>` — emit a shell completion script to stdout.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0 | Success (or findings below the `--fail-on` threshold). |
//! | 1 | Analysis produced findings at or above the `--fail-on` threshold. |
//! | 2 | Fatal error (bad arguments, I/O failure, etc.). |
#![warn(missing_docs)]

mod analyze;
mod baseline;
mod completions;
mod diff;
mod init;
mod install_hook;
mod list;
mod lsp;
mod plugins;
mod registry_builtin;
mod report;
mod show;
mod status;
mod stop;
mod watch;

/// CLI argument types shared across subcommand modules.
pub(crate) mod cli;

use clap::Parser as _;
use tracing_subscriber::EnvFilter;

use cli::{BaselineCommand, Cli, Commands, DiffFormat};

fn main() {
    let cli = Cli::parse();

    // Initialise tracing subscriber.  Verbosity levels:
    //   default  → WARN
    //   -v       → INFO
    //   -vv      → DEBUG
    //   -vvv+    → TRACE
    let default_level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .init();

    let result = match cli.command {
        Commands::Analyze(args) | Commands::Scan(args) => analyze::run(&args),
        Commands::Report(args) => report::run(&args),
        Commands::List(cmd) => list::run(cmd),
        Commands::Init => init::run(),
        Commands::Show => show::run(),
        Commands::Stop => stop::run(),
        Commands::Status => status::run(),
        Commands::InstallHook(args) => install_hook::run(args.force),
        Commands::Diff(args) => {
            let fmt = match args.format {
                DiffFormat::Json => diff::DiffFormat::Json,
                DiffFormat::Terminal => diff::DiffFormat::Terminal,
            };
            diff::run(&args.from, &args.to, fmt)
        }
        Commands::Baseline(BaselineCommand::Save(args)) => baseline::run(&args),
        Commands::Watch(args) => watch::run(&args),
        Commands::Lsp => lsp::run(),
        Commands::Completions(args) => completions::run(args.shell),
        Commands::AddAnalyzer(ref args) => plugins::add(args),
        Commands::RemoveAnalyzer(ref args) => plugins::remove(args),
        Commands::UpdateAnalyzer(ref args) => plugins::update(args),
    };

    match result {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::exit(2);
        }
    }
}
