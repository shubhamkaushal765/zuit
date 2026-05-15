---
title: Terminal output
sidebar_label: Terminal
description: Read zuit findings in your terminal as you work — colored by severity, grouped by dimension, with clickable file paths in supported terminals.
---

# Terminal output

Use terminal output when you are running zuit locally to review findings as you work. It is the default format — no `--format` flag needed.

```bash
zuit analyze ./src
```

For CI pipelines that need to parse results, use [JSON](./json). For PR comments, use [Markdown](./markdown).

## What it looks like

```text
── Maintainability ────────────────────────────────────────────────

  [High]    MAINT001-cyclomatic   src/lib.rs:12:1
            Function 'parse_request' has cyclomatic complexity 14 (threshold: 10)

  [Low]     MAINT003-fn-length    src/lib.rs:60:1
            Function 'render' is 92 lines (threshold: 80)

  Score: 84.5 / 100   Findings: 1 high, 1 low

── Security ───────────────────────────────────────────────────────

  Score: 100.0 / 100   Findings: none

──────────────────────────────────────────────────────────────────
```

Each finding shows: severity in brackets, rule ID, `file:line:column`, and the finding message on the next line. Output is grouped by dimension. Within each dimension, findings are ordered from highest severity to lowest, then by file path. Each dimension closes with its score and a count of findings by severity.

## Colors

Colors are on by default and map to severity:

| Severity   | Color  |
| ---------- | ------ |
| `critical` | Red    |
| `high`     | Red    |
| `medium`   | Yellow |
| `low`      | Cyan   |
| `info`     | White  |

Color is automatically disabled when output is piped or redirected — zuit detects that stdout is not a TTY. To force color off regardless, pass `--no-color`:

```bash
zuit analyze ./src --no-color
zuit analyze ./src | tee report.txt   # color auto-disables when piped
```

## Clickable file paths

Pass `--hyperlinks` to make file paths clickable. In supported terminals, clicking a file path opens it at the exact line in your configured editor or file handler — useful for jumping directly to a finding without copying and pasting.

```bash
zuit analyze ./src --hyperlinks
```

| Terminal          | Clickable paths |
| ----------------- | --------------- |
| iTerm2            | Yes             |
| WezTerm           | Yes             |
| Kitty             | Yes             |
| Windows Terminal  | Yes             |
| GNOME Terminal    | Yes             |
| macOS Terminal    | No              |

:::tip
For a broader list of terminals that support clickable paths, see [Hyperlinks in terminal emulators on Wikipedia](https://en.wikipedia.org/wiki/Hyperlink#Hyperlinks_in_terminal_emulators).
:::

## When to use other formats

| You want to…                                    | Use                            |
| ----------------------------------------------- | ------------------------------ |
| Parse results in a script or CI pipeline        | [JSON](./json)                 |
| Post a formatted comment on a pull request      | [Markdown](./markdown)         |
| Upload to GitHub code scanning or Azure DevOps  | [SARIF](./sarif)               |
