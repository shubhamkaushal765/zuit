---
title: Gate CI on quality
sidebar_label: Gate CI on quality
description: Fail builds when findings cross a severity threshold. Wire zuit into GitHub Actions and post results to the Security tab.
---

# Gate CI on quality

You want bad code to never reach `main`.

```bash
zuit analyze . --fail-on high
```

## Why this works

`--fail-on` causes `zuit analyze` to exit with code `1` when any finding at that severity or higher is reported. Without the flag the command always exits `0`. CI picks up the non-zero exit and fails the job before a merge is possible. See [Severity and scoring](/concepts/severity-and-scoring) for what each severity level means, and [Baselines and fail-on](/configuration/baselines-and-fail-on) for the full flag reference.

## Real-world variants

### GitHub Action one-liner

Add this to `.github/workflows/zuit.yml` to scan every pull request:

```yaml
name: zuit

on:
  push:
    branches: [main]
  pull_request:

jobs:
  zuit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: shubhamkaushal765/zuit@main
        with:
          path: "."
          fail-on: "medium"
```

The `security-events: write` permission lets the action upload findings to GitHub. See [GitHub Action](/integrations/github-action) for all available inputs.

### Post findings to the Security tab via SARIF

The GitHub Action uploads a SARIF report by default. Findings appear as inline annotations on pull request diffs and in **Security > Code scanning** so reviewers see them without leaving GitHub. No extra configuration is needed — the action handles the upload. See [SARIF output](/output/sarif) for details on the format.

### Severity-tier policy

Keep lower-severity rules visible in reports without letting them block merges. Override a rule's severity in `zuit.toml`:

```toml
[rules.MAINT003-fn-length]
severity = "low"
```

With this override, `MAINT003-fn-length` findings appear in terminal output and the dashboard but never satisfy `--fail-on high`. See [Per-rule configuration](/configuration/per-rule-config) for the full override syntax.

### Per-dimension thresholds

> **Status:** not yet implemented in zuit. The `[thresholds]` config section does not exist in the current config loader (`zuit-core/src/config.rs`). Use `--fail-on` with per-rule severity overrides in `zuit.toml` to approximate this until score-based thresholds land.

Set score thresholds per dimension in `zuit.toml`. A score below the threshold fails CI regardless of individual finding severities:

```toml
# Not yet supported — shown here as a preview of the planned syntax.
# [thresholds]
# security = 80
# maintainability = 70
```

This lets you gate on Security strictly while giving the Maintainability dimension more room. See [Baselines and fail-on](/configuration/baselines-and-fail-on) for how thresholds interact with `--fail-on`.

## What's next

[Adopt on a legacy codebase](/workflows/adopt-legacy) — onboard zuit without failing CI on day one.
