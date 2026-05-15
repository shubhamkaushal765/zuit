---
title: zuit init
description: Create a zuit.toml config file in the current directory to start customising your scan.
---

:::tip Looking for the recipe?
See [Workflows → Your daily dev loop](/workflows/daily-dev-loop) for the task-driven guide. This page is the reference.
:::

# zuit init

```bash
zuit init
```

Use `zuit init` to create a `zuit.toml` configuration file in the current directory. The generated file includes every supported section with inline comments, so you can edit it to match your project without consulting the full reference first.

## What it writes

```toml
[general]
languages = ["rust", "python"]
exclude   = ["target/**", "node_modules/**"]
follow_symlinks = false

[dimensions.maintainability]
enabled = true
weight  = 1.0

[rules.MAINT001-cyclomatic]
enabled   = true
threshold = 10

[rules.SEC001-hardcoded-secret]
enabled  = true
severity = "high"
```

See the [`zuit.toml` reference](/configuration/zuit-toml) for the full set of available options.

## Options

| Flag              | Type | Default | Description                                      |
| ----------------- | ---- | ------- | ------------------------------------------------ |
| `-v`, `--verbose` | flag | off     | Increase log verbosity (`-v` = INFO, `-vv` = DEBUG). |
| `-h`, `--help`    | flag |         | Print help.                                      |

:::caution
If `zuit.toml` already exists in the current directory, `zuit init` will not overwrite it. Delete or rename the existing file first, then re-run.
:::

## See also

- [zuit.toml reference](/configuration/zuit-toml)
- [Per-rule configuration](/configuration/per-rule-config)
