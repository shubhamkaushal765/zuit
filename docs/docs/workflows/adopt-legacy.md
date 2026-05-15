---
title: Adopt on a legacy codebase
sidebar_label: Adopt on a legacy codebase
description: Onboard zuit onto a repo with hundreds of pre-existing findings — without failing CI on day one.
---

# Adopt on a legacy codebase

Your repo has 500 existing findings. You can't fix them all today.

```bash
zuit baseline save -o zuit-baseline.json
zuit analyze . --baseline zuit-baseline.json --fail-on medium
```

## Why this works

The baseline records every finding present today. On future runs, `--baseline` suppresses matches, so only new findings reach `--fail-on`. Pre-existing technical debt stays visible in the dashboard but does not fail CI. See [Baselines and fail-on](/configuration/baselines-and-fail-on) for the full workflow and flag reference.

## Real-world variants

### Capture a baseline from a historical tag

Baseline against a specific release tag to measure what has regressed since that point:

```bash
zuit baseline save --ref v1.0.0 -o baseline-v1.0.0.json
```

The `--ref` flag checks out that git ref into a temporary directory before scanning. See [`zuit baseline`](/cli/baseline) for the full flag list.

### Commit the baseline file

Commit the baseline file so CI and every developer use the same reference point:

```bash
git add zuit-baseline.json && git commit -m "chore: zuit baseline"
```

Without a committed baseline, each environment captures a different set of suppressions. A tracked file guarantees that the CI job and local runs suppress exactly the same findings.

### Diff two scans to see what improved

Compare the baseline against the current state to track how many legacy findings the team has fixed:

```bash
zuit diff baseline.json current.json
```

Both arguments accept paths to JSON report files or scan IDs from your saved history. See [`zuit diff`](/cli/diff) for output format details.

### Refresh the baseline periodically

As the team fixes legacy findings, regenerate the baseline so CI reflects the new lower floor and the suppression list stays accurate:

```bash
zuit baseline save -o zuit-baseline.json
```

Commit the updated file after each refresh. Refreshing monthly keeps the suppression list from drifting too far from reality and makes the Trends tab in `zuit show` more meaningful.

:::tip Phased adoption
Start at `--fail-on critical` to catch only the most severe issues. Tighten to `--fail-on high` after a month once the team has addressed the critical findings, then move to `--fail-on medium`.
:::

## What's next

[Track trends across releases](/workflows/track-trends) — use the dashboard to see whether quality is improving sprint over sprint.
