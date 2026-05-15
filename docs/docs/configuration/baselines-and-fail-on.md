---
title: Baselines and fail-on
description: Block merges on new findings with --fail-on, and ignore pre-existing issues with --baseline so you can adopt zuit incrementally.
---

:::tip Looking for the recipe?
See [Workflows → Adopt on a legacy codebase](/workflows/adopt-legacy) for the task-driven guide. This page is the reference.
:::

# Baselines and fail-on

Two flags give you precise control over how zuit gates your CI pipeline:

- **`--fail-on`** — exit non-zero when any finding reaches a given severity level. Use this to block merges on serious issues.
- **`--baseline`** — suppress findings that were already present in a known-good run. Use this to adopt zuit on a codebase that already has issues without being swamped by pre-existing noise.

```mermaid
flowchart TD
    classDef primary fill:#1e4d8c,color:#fff,stroke:none
    classDef accent fill:#d4a017,color:#fff,stroke:none

    RUN[zuit analyze]
    BL{Baseline\nprovided?}
    FILTER[Suppress baseline\nfindings]
    THRESH{Severity meets\nfail-on threshold?}
    OK[Exit 0\nno gate failure]
    FAIL[Exit non-zero\nblock merge]

    RUN --> BL
    BL -- yes --> FILTER --> THRESH
    BL -- no --> THRESH
    THRESH -- no --> OK
    THRESH -- yes --> FAIL

    class RUN accent
    class FAIL primary
    class OK primary
```

## `--fail-on`

Without `--fail-on`, `zuit analyze` always exits `0` — useful for informational runs, but not for blocking merges.

Add `--fail-on` to fail CI whenever a finding reaches or exceeds the severity you specify:

```bash
zuit analyze . --fail-on high
```

| Value      | Fails when a finding is…    |
| ---------- | --------------------------- |
| `info`     | Info or above (any finding) |
| `low`      | Low or above                |
| `medium`   | Medium or above             |
| `high`     | High or above               |
| `critical` | Critical only               |

Default: unset — no threshold, always exits `0`.

### GitHub Actions example

```yaml
name: zuit

on: [pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: shubhamkaushal765/zuit@main
        with:
          path: "."
          fail-on: "high"
```

See [GitHub Action](/integrations/github-action) for the full input reference.

## `--baseline`

A baseline file records every finding from a run on your main branch (or any chosen reference point). On subsequent runs, findings that match the baseline are suppressed — only **new** findings reach the formatter and `--fail-on`. This lets you adopt zuit on a codebase that already has issues without failing CI on things you haven't fixed yet.

### Set up a baseline in three steps

**Step 1.** Capture today's findings:

```bash
zuit baseline save -o zuit-baseline.json
```

**Step 2.** Commit the baseline file so CI can use it:

```bash
git add zuit-baseline.json
git commit -m "chore: zuit baseline"
```

**Step 3.** Update your CI command to apply the baseline:

```bash
zuit analyze . --baseline zuit-baseline.json --fail-on high
```

From this point on, pre-existing findings are silenced. Any new finding at `high` or above fails CI.

### Capture a baseline from a historical git ref

```bash
zuit baseline save --ref v1.0.0 -o baseline-v1.0.0.json
```

See [`zuit baseline`](/cli/baseline) for the full reference.

:::tip
Refresh the baseline periodically as legacy findings get fixed. Use `zuit diff` to compare two saved reports and track your progress over time.
:::

## Cache and baseline interaction

The incremental cache (`--no-cache` / `[history] cache = false`) affects analysis speed but not baseline suppression. Baseline matching is applied after all findings are collected, regardless of whether the cache was used.

## See also

- [`zuit analyze` reference](/cli/analyze)
- [`zuit baseline`](/cli/baseline)
- [`zuit diff`](/cli/diff)
- [`zuit.toml` reference](/configuration/zuit-toml)
- [Per-rule configuration](/configuration/per-rule-config)
