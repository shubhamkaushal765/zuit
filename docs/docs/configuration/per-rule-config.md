---
title: Per-rule configuration
description: Silence noisy rules, adjust severities, and tune thresholds — without touching rules you want to leave at their defaults.
---

:::tip Looking for the recipe?
See [Workflows → Gate CI on quality](/workflows/gate-ci) for the task-driven guide. This page is the reference.
:::

# Per-rule configuration

Tune individual rules without touching the rest. Use a `[rules.<rule_id>]` table in `zuit.toml` for any rule you want to change. Every rule has a stable ID (for example `MAINT001-cyclomatic`) that you use as the table name.

## Common tasks

### Disable a rule entirely

When a rule isn't relevant to your project, turn it off completely. Disabled rules produce no findings — they do not appear in the report and are not counted by `--fail-on`.

```toml
[rules.DOC002-todo-fixme]
enabled = false
```

### Keep a rule visible without blocking CI

If you want findings reported but don't want them to fail CI, lower the severity so it falls below your `--fail-on` threshold:

```toml
[rules.MAINT003-fn-length]
severity = "low"
```

With `--fail-on high`, this rule still shows up in the report, but never fails the build. Use `severity = "info"` to keep findings visible with zero CI impact.

### Raise a rule's severity

```toml
[rules.SEC001-hardcoded-secret]
severity = "critical"
```

### Adjust a numeric threshold

Some rules fire when a measured value crosses a threshold. Raise or lower the threshold to match your codebase's conventions:

```toml
[rules.MAINT001-cyclomatic]
threshold = 15
```

:::note
`enabled = false` is different from `severity = "info"`. With `enabled = false`, the rule's findings are completely absent — no report entry, no score impact, no `--fail-on` consideration. With `severity = "info"`, findings still appear in the report, but contribute zero weight to the dimension score.
:::

## Keys available on every rule

| Key        | Type   | Default        | Description                                                            |
| ---------- | ------ | -------------- | ---------------------------------------------------------------------- |
| `enabled`  | bool   | `true`         | Turn the rule off entirely.                                            |
| `severity` | string | rule's default | Override severity. One of `info`, `low`, `medium`, `high`, `critical`. |

## Rules with additional options

These rules accept a `threshold` key in addition to `enabled` and `severity`. Rules not listed here only accept `enabled` and `severity`.

| Rule ID                 | Knob        | Default | Description                                              |
| ----------------------- | ----------- | ------- | -------------------------------------------------------- |
| `MAINT001-cyclomatic`   | `threshold` | `10`    | Cyclomatic complexity at which a function is flagged.    |
| `MAINT003-fn-length`    | `threshold` | `80`    | Maximum function length in lines before a finding fires. |
| `MAINT004-file-length`  | `threshold` | `600`   | Maximum file length in lines.                            |
| `MAINT005-deep-nesting` | `threshold` | `4`     | Maximum block-nesting depth.                             |

For what each rule measures and any per-language notes, see the [Rules reference](/rules).

## See also

- [`zuit.toml` reference](/configuration/zuit-toml)
- [Baselines and fail-on](/configuration/baselines-and-fail-on)
- [Severity and scoring](/concepts/severity-and-scoring)
