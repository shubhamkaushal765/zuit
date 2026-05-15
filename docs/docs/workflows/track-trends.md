---
title: Track trends across releases
sidebar_label: Track trends
description: Use zuit show to see whether quality is improving sprint over sprint — Trends, Heatmap, and Diff dashboard tabs.
---

# Track trends across releases

You want to see if quality is improving sprint over sprint.

```bash
zuit show
```

This assumes at least one prior `zuit analyze` run has been saved to history.

## Why this works

Every `zuit analyze` run is saved automatically under `~/.zuit/`. `zuit show` starts a local server and reads that history to render Overview, Scans, Findings, Trends, Diff, Heatmap, and Config tabs. Nothing extra to configure — history accumulates in the background as you and your CI pipeline run scans. See [`zuit show`](/cli/show) for the full tab reference and HTTP API.

## Real-world variants

### Label your release scans

Attach a human-readable label to any scan so you can find it quickly in the Scans tab and compare it on the Diff tab. Labels are free-form strings such as `"v1.0"` or `"release-2026-Q2"`.

Set a label via the dashboard's Scans tab, or call the HTTP API directly:

```bash
curl -X PUT http://localhost:7878/api/projects/:hash/scans/:id/label \
  -H "Content-Type: application/json" \
  -d '{"label": "v2.0"}'
```

The `:hash` and `:id` values are visible in the Scans tab URL or the `GET /api/projects` response. See [`zuit show`](/cli/show) for the full API reference.

### See per-dimension trends

The Trends tab plots score sparklines per dimension over time. A downward slope on Security means new vulnerabilities have been introduced faster than they are being fixed. A flat line on Documentation means the team is not improving or worsening that dimension — useful signal when you have an active documentation sprint.

### Diff two specific scans

From the Scans tab, select any two saved scans and switch to the Diff tab to see findings categorised as new, resolved, or persisting. To do the same from the terminal using scan IDs or JSON files:

```bash
zuit diff <scan-id-1> <scan-id-2>
```

Minor line-number drift from reformatting does not cause a finding to appear as new. See [`zuit diff`](/cli/diff) for output format options.

### Find the worst files

The Heatmap tab rolls findings up per file across all saved scans. The top rows show the files that have accumulated the most findings over time — your hotspots. Open a hotspot file in your editor, filter the Findings tab to that file, and work through the per-finding detail to plan the cleanup.

## What's next

[Dimensions](/concepts/dimensions) — refresh on what each of the five quality scores actually measures.
