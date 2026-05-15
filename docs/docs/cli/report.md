---
title: zuit report
description: Convert a saved zuit JSON report to Markdown, SARIF, or terminal output without re-scanning.
---

:::tip Looking for the recipe?
See [Workflows → Gate CI on quality](/workflows/gate-ci) for the task-driven guide. This page is the reference.
:::

# zuit report

```
zuit report <INPUT> [OPTIONS]
```

Use `zuit report` to re-render a previously saved JSON report in a different format. This lets you produce Markdown summaries, upload SARIF to a security dashboard, or view a historical result in the terminal — all without running a new scan.

## When to use this

- Convert a CI-generated JSON report to Markdown for a pull request comment.
- Produce a SARIF file from a saved scan for upload to GitHub Advanced Security or another SAST platform.
- View an archived report in a more readable format.

## Arguments

| Argument  | Description                                                       |
| --------- | ----------------------------------------------------------------- |
| `<INPUT>` | Path to a JSON file saved by `zuit analyze --format json`. Required. |

## Options

| Flag                | Type                                                                          | Default    | Description                                                                 |
| ------------------- | ----------------------------------------------------------------------------- | ---------- | --------------------------------------------------------------------------- |
| `--format <FORMAT>` | `json` \| `terminal` \| `markdown` \| `sarif` \| `checkstyle` \| `junit`     | `terminal` | Target output format.                                                       |
| `--output <FILE>`   | path                                                                          | stdout     | Write output to `<FILE>` instead of stdout.                                 |
| `--no-color`        | flag                                                                          | off        | Disable ANSI colour in terminal output.                                     |
| `--hyperlinks`      | flag                                                                          | off        | Emit clickable file-path links in terminal output (requires a supporting terminal). |
| `-h`, `--help`      | flag                                                                          |            | Print help.                                                                 |

## Examples

View a saved report in the terminal:

```bash
zuit report report.json
```

Convert to Markdown:

```bash
zuit report report.json --format markdown
```

Convert to SARIF and save to a file:

```bash
zuit report report.json --format sarif --output results.sarif
```

Post a Markdown summary as a GitHub PR comment:

```bash
zuit report report.json --format markdown | gh pr comment --body-file -
```

## See also

- [`zuit analyze`](/cli/analyze)
- [Output formats](/output/terminal)
- [`zuit diff`](/cli/diff)
