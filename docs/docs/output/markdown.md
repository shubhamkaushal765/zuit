---
title: Markdown output
sidebar_label: Markdown
description: Post zuit findings as a formatted pull request comment — a scoreboard table plus collapsible per-dimension details.
---

# Markdown output

Use Markdown output to post analysis results as a comment on a pull request. It renders cleanly on GitHub, GitLab, and most other platforms that support GitHub-flavoured Markdown.

```bash
zuit analyze ./src --format md
```

Both `md` and `markdown` are accepted:

```bash
zuit analyze ./src --format markdown --output report.md
```

## What the rendered output looks like

The report starts with a scoreboard table, followed by one collapsible block per dimension. Reviewers can expand only the dimensions they care about — the rest stay collapsed and keep the comment short.

````markdown
# zuit report

| Dimension       | Score | Findings |
| --------------- | ----- | -------- |
| Maintainability | 84.5  | 3        |
| Security        | 100.0 | 0        |
| Complexity      | 100.0 | 0        |
| Documentation   | 78.0  | 4        |
| Test smell      | 95.0  | 1        |

<details>
<summary>Maintainability — 3 findings</summary>

- **MAINT001-cyclomatic** [Medium] `src/lib.rs:12:1` — Function 'parse_request' has cyclomatic complexity 14 (threshold: 10).
- **MAINT003-fn-length** [Low] `src/lib.rs:60:1` — Function 'render' is 92 lines (threshold: 80).
- **MAINT004-file-length** [Low] `src/parse.rs:1:1` — File is 612 lines (threshold: 500).

</details>
````

## Layout

| Section         | Form                                                      |
| --------------- | --------------------------------------------------------- |
| Top-level title | `# zuit report`                                       |
| Scoreboard      | A table with one row per dimension                        |
| Per-dimension   | A `<details>` block, collapsed by default, with findings  |

## Post directly to a pull request

:::tip
Pipe directly to `gh pr comment` to post the report on the current PR:

```bash
zuit analyze ./src --format md | gh pr comment --body-file -
```
:::

## When to prefer JSON

For programmatic access — extracting findings, gating CI, or aggregating across runs — use [JSON](./json) instead. Markdown is a presentation format; JSON is the stable contract.
