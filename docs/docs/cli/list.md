---
title: zuit list
description: List the languages and rules zuit supports, and look up rule documentation by ID.
---

:::tip Looking for the recipe?
See [Workflows → Your daily dev loop](/workflows/daily-dev-loop) for the task-driven guide. This page is the reference.
:::

# zuit list

```bash
zuit list languages
zuit list analyzers [--explain <RULE_ID>]
zuit list plugins
```

Use `zuit list` to discover what languages zuit recognises and what rules are available. This is how you find a rule ID to disable or configure in `zuit.toml`.

## When to use this

- Check which file types will be included in a scan.
- Browse all available rules and their default severities.
- Look up what a specific rule checks before enabling or disabling it.

## zuit list languages

Prints a table of supported languages and the file extensions zuit scans for each.

```bash
zuit list languages
```

Example output:

```text
ID          Extensions
rust        rs
python      py
javascript  js, jsx, ts, tsx, mjs, cjs
go          go
```

:::note
`go` appears in the registry but is not yet fully supported. JavaScript and TypeScript are fully supported. See [language support](/quickstart#install) for the current support matrix.
:::

## zuit list plugins

Prints a table of installed third-party analyzer plugins.

```bash
zuit list plugins
```

## zuit list analyzers

Prints every available rule with its rule ID, dimension, default severity, and supported languages. Use this to see what runs by default and to find the exact rule ID you need for configuration.

```bash
zuit list analyzers
```

### `--explain <RULE_ID>`

Prints the full documentation for a single rule. Use this to understand what a rule checks and why, without leaving the terminal.

```bash
zuit list analyzers --explain MAINT001-cyclomatic
```

## Options

| Flag                  | Type   | Default | Description                                             |
| --------------------- | ------ | ------- | ------------------------------------------------------- |
| `--explain <RULE_ID>` | string | unset   | Print documentation for the given rule ID and exit.     |
| `-v`, `--verbose`     | flag   | off     | Increase log verbosity. `-v` = INFO, `-vv` = DEBUG.    |
| `-h`, `--help`        | flag   |         | Print help.                                             |

## See also

- [Rules reference](/rules)
- [Analyzers and findings](/concepts/analyzers-and-findings)
