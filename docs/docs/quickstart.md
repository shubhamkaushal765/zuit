---
title: Quickstart
description: Install zuit, run your first scan, read the output, and open the dashboard — five minutes start to finish.
---

# Quickstart

Get zuit running, scan a project, and learn to read the output — in about five minutes. This is the single page to send a new teammate.

## Install

Pick the package manager you already have. All three paths give you the same `zuit` binary.

**Rust — cargo** (canonical; ships the binary directly):

```bash
cargo install --locked zuit
```

You'll need cargo installed first. If you don't have it, get it from [rustup.rs](https://rustup.rs) — the installer sets up cargo and the Rust toolchain in one step.

**Python — pip** (wheels bundle the precompiled binary, so `zuit analyze .` works right after install):

```bash
pip install zuit
```

**Node.js — npm** (installs a launcher; pair it with `cargo install zuit` or set `ZUIT_BIN` to point at an existing binary):

```bash
npm install -g zuit
```

Verify the binary is on your `PATH`:

```bash
zuit --version
```

The pip and npm packages are launchers — they resolve a `zuit` binary via `ZUIT_BIN`, a bundled binary, or your OS `PATH`. The pip wheel already includes a binary; the npm package does not, so install via cargo or point `ZUIT_BIN` at an existing binary.

**Build from source** (for the latest unreleased changes):

```bash
git clone https://github.com/shubhamkaushal765/zuit
cd zuit
cargo build --release -p zuit-cli
```

The binary lands at `target/release/zuit`. Add that directory to your `PATH` or invoke it directly.

**GitHub Action** — to run zuit in CI without managing a Rust install, see [GitHub Action](/integrations/github-action).

### Language support

| Language                | Status | Extensions                                                   |
| ----------------------- | ------ | ------------------------------------------------------------ |
| Rust                    | Full   | `.rs`                                                        |
| Python                  | Full   | `.py`                                                        |
| JavaScript / TypeScript | Full   | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.mts`, `.cts`, `.tsx` |
| Go                      | Stub   | Not yet supported                                            |

Files in unsupported languages are skipped silently.

## Run your first scan

Point `zuit analyze` at any directory. No configuration file is required.

```bash
zuit analyze ./src
```

zuit scans every Rust, Python, and JavaScript/TypeScript file it finds, respecting `.gitignore` and skipping common vendor directories automatically. Results appear in the terminal as soon as the scan finishes.

For a one-off scan that doesn't get saved to history, add `--no-save`:

```bash
zuit analyze ./src --no-save
```

## Read the output

The terminal report lists findings grouped by dimension and severity. Each finding takes two lines:

```text
[MAINT001-cyclomatic] medium  src/lib.rs:42:1
  function `process_request` has cyclomatic complexity 14 (threshold 10)
```

The rule ID (`MAINT001-...`) is stable across releases and used in config and baselines. The severity is one of `info`, `low`, `medium`, `high`, or `critical`. Findings are sorted by file, then line, then rule ID — two scans of unchanged source produce identical output.

After the findings, a scoreboard shows one 0–100 score and an A–F grade per dimension:

```text
Maintainability  87.4  B
Security         98.1  A
Complexity      100.0  A
Documentation    73.5  C
TestSmell        91.0  A
```

For the scoring formula see [Severity and scoring](/concepts/severity-and-scoring). For the full terminal format reference see [Terminal output](/output/terminal).

## See the dashboard

After any scan, open the interactive history dashboard:

```bash
zuit show
```

This starts a local HTTP server and opens a browser tab with Overview, Scans, Findings, Trends, Diff, Heatmap, and Config tabs. Every `zuit analyze` run is saved automatically, so the Trends and Diff views fill in over time. See [Track trends across releases](/workflows/track-trends) for the full flow.

## Set up a config (optional)

Once you know which rules and thresholds matter for your project, generate a `zuit.toml` starter file:

```bash
zuit init
```

This writes `zuit.toml` to the current directory with commented sections for general settings, per-dimension thresholds, and per-rule overrides. See the [zuit.toml reference](/configuration/zuit-toml) for every available field.

## What's next

- [Your daily dev loop](/workflows/daily-dev-loop) — watch mode, LSP diagnostics, and inline suppression
- [Gate CI on quality](/workflows/gate-ci) — `--fail-on`, the GitHub Action, and SARIF upload
- [Adopt on a legacy codebase](/workflows/adopt-legacy) — baselines so existing findings don't block you
