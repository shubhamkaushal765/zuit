---
title: zuit analyze
description: Scan your code for quality issues and get findings in the terminal, JSON, Markdown, or SARIF.
---

:::tip Looking for the recipe?
See [Workflows → Gate CI on quality](/workflows/gate-ci) for the task-driven guide. This page is the reference.
:::

# zuit analyze

```
zuit analyze <PATH> [OPTIONS]
zuit scan <PATH> [OPTIONS]    # alias
```

Use `zuit analyze` to scan a file or directory and report quality findings. It checks every supported source file under `<PATH>`, applies the enabled rules, and prints results in your chosen format. `scan` is a full alias for `analyze` — both accept the same flags.

## When to use this

- Run a one-off scan during development to see current findings.
- Gate a CI pipeline: exit non-zero when findings exceed a severity threshold.
- Combine with a baseline file to surface only newly introduced issues.

## Arguments

| Argument | Description                                         |
| -------- | --------------------------------------------------- |
| `<PATH>` | File or directory to scan. Required.                |

## Options

| Flag                    | Type                                                  | Default    | Description                                                                                           |
| ----------------------- | ----------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------- |
| `--dimensions <LIST>`   | comma-separated string                                | all        | Restrict to these dimensions (e.g. `security,maintainability`).                                       |
| `--languages <LIST>`    | comma-separated string                                | all        | Restrict to these language IDs (e.g. `rust,python`).                                                 |
| `--format <FORMAT>`     | `json` \| `terminal` \| `markdown` \| `sarif` \| `checkstyle` \| `junit` | `terminal` | Output format.                                                                                        |
| `--output <FILE>`       | path                                                  | stdout     | Write output to `<FILE>` instead of stdout.                                                           |
| `--config <FILE>`       | path                                                  | auto       | Path to a `zuit.toml`. Overrides the default upward search.                                       |
| `--fail-on <LEVEL>`     | `info` \| `low` \| `medium` \| `high` \| `critical`   | unset      | Exit with code 1 if any finding reaches or exceeds this severity.                                     |
| `--baseline <FILE>`     | path                                                  | unset      | Suppress findings already recorded in this baseline file.                                             |
| `--no-save`             | flag                                                  | off        | Skip saving this run to history.                                                                      |
| `--no-cache`            | flag                                                  | off        | Ignore the incremental cache and re-analyse every file from scratch.                                  |
| `--cwe <ID>`            | string (repeatable)                                   | unset      | Show only findings tagged with this CWE ID (e.g. `CWE-798`). Repeatable.                             |
| `--owasp <CAT>`         | string (repeatable)                                   | unset      | Show only findings tagged with this OWASP category (e.g. `A07:2021`). Repeatable.                    |
| `--no-color`            | flag                                                  | off        | Disable colour in terminal output.                                                                    |
| `--hyperlinks`          | flag                                                  | off        | Emit clickable file-path links in terminal output (requires a supporting terminal).                   |
| `-v`, `--verbose`       | flag (repeatable)                                     | off        | Increase log verbosity. `-v` = INFO, `-vv` = DEBUG.                                                  |
| `-h`, `--help`          | flag                                                  |            | Print help.                                                                                           |
| `-V`, `--version`       | flag                                                  |            | Print version.                                                                                        |

## Examples

Scan the current directory and print findings in the terminal:

```bash
zuit analyze .
```

Scan a single file:

```bash
zuit analyze src/auth.rs
```

Save findings as JSON for later use:

```bash
zuit analyze ./src --format json --output report.json
```

Fail CI on any high-severity finding:

```bash
zuit analyze . --fail-on high
```

Scan only security rules and fail on medium+:

```bash
zuit analyze . --config ./zuit.toml --dimensions security --fail-on medium
```

Suppress pre-existing findings and only fail on new ones:

```bash
zuit analyze . --baseline zuit-baseline.json --fail-on medium
```

Filter to a specific CWE or OWASP category:

```bash
zuit analyze . --cwe CWE-798
zuit analyze . --owasp A07:2021 --fail-on high
```

Run without writing to history (useful for quick one-off checks):

```bash
zuit analyze . --no-save
```

## Incremental cache

By default, zuit caches per-file findings so unchanged files are skipped on the next run. The cache is stored in your project directory. Use `--no-cache` to force a full re-scan. To disable the cache globally, set `cache = false` under `[history]` in `zuit.toml`.

## Exit codes

| Code | Meaning                                                                                           |
| ---- | ------------------------------------------------------------------------------------------------- |
| `0`  | Scan complete. No finding met the `--fail-on` threshold (or the flag was not set).                |
| `1`  | At least one finding met or exceeded the `--fail-on` threshold.                                   |
| `2`  | Configuration or argument error (invalid flag, malformed `zuit.toml`, missing path).          |

:::note
`--fail-on` has no default. Without it, `zuit analyze` always exits `0` regardless of how many findings it reports — the command is informational unless you set a threshold.
:::

## See also

- [zuit.toml reference](/configuration/zuit-toml)
- [Baselines and fail-on workflows](/configuration/baselines-and-fail-on)
- [Output formats](/output/terminal)
- [`zuit report`](/cli/report)
- [`zuit watch`](/cli/watch)
