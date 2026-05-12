//! Handlers for the plugin-management CLI subcommands.

use anyhow::{Context, Result};
use zuit_plugins::{
    install_git, install_local, list_installed, looks_like_git_url, remove as remove_plugin,
    update as update_plugin, PluginSource,
};

use crate::cli::{AddAnalyzerArgs, RemoveAnalyzerArgs, UpdateAnalyzerArgs};

/// Handle `zuit add-analyzer`.
pub(crate) fn add(args: &AddAnalyzerArgs) -> Result<i32> {
    let installed = if looks_like_git_url(&args.source) {
        install_git(&args.source, args.name.as_deref())
            .with_context(|| format!("install plugin from git URL '{}'", args.source))?
    } else {
        let path = std::path::Path::new(&args.source);
        install_local(path, args.name.as_deref())
            .with_context(|| format!("install plugin from local path '{}'", args.source))?
    };
    println!(
        "Installed plugin '{}' (version {})",
        installed.name, installed.manifest.version
    );
    Ok(0)
}

/// Handle `zuit remove-analyzer`.
pub(crate) fn remove(args: &RemoveAnalyzerArgs) -> Result<i32> {
    remove_plugin(&args.name)
        .with_context(|| format!("remove plugin '{}'", args.name))?;
    println!("Removed plugin '{}'", args.name);
    Ok(0)
}

/// Handle `zuit update-analyzer`.
pub(crate) fn update(args: &UpdateAnalyzerArgs) -> Result<i32> {
    update_plugin(&args.name)
        .with_context(|| format!("update plugin '{}'", args.name))?;
    println!("Updated plugin '{}'", args.name);
    Ok(0)
}

/// Handle `zuit list plugins`.
pub(crate) fn list() -> Result<i32> {
    let plugins = list_installed().context("list installed plugins")?;
    if plugins.is_empty() {
        println!("No plugins installed.");
        return Ok(0);
    }
    println!("{:<24} {:<10} {:<8} SOURCE", "NAME", "VERSION", "OUTPUT");
    for p in plugins {
        let output = match p.manifest.output {
            zuit_plugins::OutputFormat::ZuitJson => "ndjson",
            zuit_plugins::OutputFormat::Sarif => "sarif",
        };
        let source = match &p.source {
            PluginSource::Path { target } => format!("path: {}", target.display()),
            PluginSource::Git { url, sha, .. } => {
                format!("git: {url} @ {}", &sha[..sha.len().min(8)])
            }
        };
        println!(
            "{:<24} {:<10} {:<8} {}",
            p.name, p.manifest.version, output, source
        );
    }
    Ok(0)
}
