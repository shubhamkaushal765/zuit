---
title: zuit.toml
description: Configure zuit for your project — set languages, exclude paths, tune rules, and keep settings consistent across your team.
slug: /configuration/zuit-toml
---

:::tip Looking for the recipe?
See [Workflows → Gate CI on quality](/workflows/gate-ci) for the task-driven guide. This page is the reference.
:::

# zuit.toml

`zuit.toml` is how you tune zuit for your project. Drop it in your project root, commit it, and every team member and CI run uses the same settings. The file is entirely optional — zuit works without one — but a shared config is the best way to keep analysis consistent.

Not sure where to start? Run this to generate a starter file:

```bash
zuit init
```

Then edit the generated `zuit.toml` from there.

## Common tasks

### Restrict analysis to specific languages

```toml
[general]
languages = ["rust", "python"]
```

### Ignore folders

```toml
[general]
exclude = ["target/**", "node_modules/**", "dist/**", "vendor/**"]
```

Globs are also combined with `.gitignore`, so files already ignored by git are automatically skipped.

### Disable a rule

```toml
[rules.DOC002-todo-fixme]
enabled = false
```

Disabled rules produce no findings at all — they do not appear in the report and do not count toward `--fail-on`.

### Downgrade a noisy rule so it doesn't block CI

```toml
[rules.MAINT003-fn-length]
severity = "low"
```

With `--fail-on high`, this rule still reports findings but never fails the build. Use `severity = "info"` to keep findings visible without any CI impact.

### Tighten a threshold

```toml
[rules.MAINT001-cyclomatic]
threshold = 8
```

### Escalate a rule's severity

```toml
[rules.SEC001-hardcoded-secret]
severity = "critical"
```

### Reduce the weight of a dimension's score

```toml
[dimensions.documentation]
weight = 0.5
```

### Disable an entire dimension

```toml
[dimensions.documentation]
enabled = false
```

### Turn off scan history

```toml
[history]
auto_save = false
```

### Run only security rules in CI

Combine `languages`, `enabled = false` on unwanted dimensions, and `--fail-on` to create a focused security gate:

```toml
[general]
languages = ["python", "javascript"]

[dimensions.maintainability]
enabled = false

[dimensions.complexity]
enabled = false

[dimensions.documentation]
enabled = false

[dimensions.testsmell]
enabled = false

[rules.SEC001-hardcoded-secret]
severity = "critical"
```

Then in CI:

```bash
zuit analyze . --fail-on high
```

## Full working example

```toml
[general]
languages = ["rust", "python"]
exclude   = ["target/**", "node_modules/**", "dist/**"]
follow_symlinks = false

# Documentation still runs but contributes half as much to the overall score.
[dimensions.documentation]
enabled = true
weight  = 0.5

# Tighter complexity limit for this codebase.
[rules.MAINT001-cyclomatic]
enabled   = true
threshold = 8

# Treat hardcoded secrets as critical instead of the default high.
[rules.SEC001-hardcoded-secret]
enabled  = true
severity = "critical"

# Too many legacy TODOs to fix right now — silence the rule.
[rules.DOC002-todo-fixme]
enabled = false
```

## How zuit finds your config

The CLI loads exactly one config per run, in this order:

1. `--config <FILE>` — explicit path on the command line. Always wins.
2. Walk upward from the current working directory — the first `zuit.toml` found in `.`, the parent, the grandparent, and so on.
3. Built-in defaults — applied when no file is found.

## All options

| Section                  | Key                     | Type            | Default                            | Description                                                                                                      |
| ------------------------ | ----------------------- | --------------- | ---------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `[general]`              | `languages`             | array of string | all registered                     | Restrict analysis to these language IDs.                                                                         |
| `[general]`              | `exclude`               | array of glob   | `["target/**", "node_modules/**"]` | Globs to skip during the file walk. Combined with `.gitignore`.                                                  |
| `[general]`              | `follow_symlinks`       | bool            | `false`                            | Follow symbolic links while walking.                                                                             |
| `[dimensions.<dim>]`     | `enabled`               | bool            | `true`                             | Toggle a whole dimension (`maintainability`, `security`, `complexity`, `documentation`, `testsmell`).            |
| `[dimensions.<dim>]`     | `weight`                | float           | `1.0`                              | Weight applied when aggregating per-dimension scores.                                                            |
| `[rules.<rule_id>]`      | `enabled`               | bool            | `true`                             | Toggle a single rule on or off.                                                                                  |
| `[rules.<rule_id>]`      | `severity`              | string          | rule's default                     | Override severity. One of `info`, `low`, `medium`, `high`, `critical`.                                           |
| `[rules.<rule_id>]`      | *(rule-specific)*       | various         | per rule                           | Some rules accept extra knobs such as `threshold`. See [Per-rule configuration](/configuration/per-rule-config). |
| `[history]`              | `auto_save`             | bool            | `true`                             | When false, runs are never written to `~/.zuit/` history.                                                    |
| `[history]`              | `max_scans_per_project` | integer         | `100`                              | Older scans are pruned on write when this limit is exceeded.                                                     |
| `[history]`              | `cache`                 | bool            | `true`                             | Enable the incremental file-hash cache at `<project_root>/.zuit-cache/v1.json`.                              |

If you pass an unknown key, a wrong type, or an out-of-range value, zuit reports an error pointing at the exact line in your TOML file.

## See also

- [`zuit init`](/cli/init)
- [Per-rule configuration](/configuration/per-rule-config)
- [Baselines and fail-on](/configuration/baselines-and-fail-on)
