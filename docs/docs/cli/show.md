---
title: zuit show / stop / status
sidebar_label: zuit show
description: Open a local browser dashboard to browse scan history, trends, and findings across runs.
---

:::tip Looking for the recipe?
See [Workflows → Track trends across releases](/workflows/track-trends) for the task-driven guide. This page is the reference.
:::

# zuit show / stop / status

Use `zuit show` to open a local browser dashboard where you can explore your scan history, track quality trends over time, and compare findings across runs.

Three subcommands manage the dashboard:

| Command            | Effect                                                                   |
| ------------------ | ------------------------------------------------------------------------ |
| `zuit show`    | Start the dashboard server (if not already running) and open the browser.|
| `zuit stop`    | Stop the running dashboard server.                                        |
| `zuit status`  | Show whether the server is running, and on which port.                   |

```mermaid
flowchart LR
    A[zuit analyze] -->|saves scan history| B[(history\nunder home directory)]
    B --> C[dashboard server\nport 7878]
    C --> D[browser\ndashboard]

    classDef accent fill:#d4a017,color:#000,stroke:#b8860b
    classDef primary fill:#1e4d8c,color:#fff,stroke:#163c6e
    class C primary
    class D accent
```

## How history works

Every `zuit analyze` run automatically saves its results to history under your home directory. The dashboard reads from this history to populate all tabs and charts. By default, up to 100 scans are kept per project; older scans are removed when that limit is reached.

To skip saving a single run:

```bash
zuit analyze . --no-save
```

To disable saving globally, add to `zuit.toml`:

```toml
[history]
auto_save = false
```

## Dashboard tabs

| Tab       | What you see                                                          |
| --------- | --------------------------------------------------------------------- |
| Overview  | Latest scores, grade summary, and change since the previous scan      |
| Scans     | All saved scans; delete or label any scan                             |
| Findings  | Findings for a selected scan, filterable by dimension and severity    |
| Trends    | Score history per dimension over time                                 |
| Diff      | Finding-level comparison between any two scans                        |
| Heatmap   | Per-file finding counts across all scans                              |
| Config    | The configuration snapshot recorded with each scan                    |

## HTTP API

The dashboard server also exposes a JSON API if you want to build your own tooling on top of the scan history.

| Method · Path | Returns |
| --- | --- |
| `GET /api/healthz` | `{ok, version}` |
| `GET /api/projects` | List of projects with latest scores and scan count |
| `GET /api/projects/:hash` | Project metadata and scans index |
| `GET /api/projects/:hash/scans` | Scans index |
| `GET /api/projects/:hash/scans/:id` | Full scan result |
| `GET /api/projects/:hash/scans/:id/analytics` | Finding counts by severity, dimension, rule, and file |
| `GET /api/projects/:hash/summary` | Latest analytics plus delta vs. previous scan |
| `GET /api/projects/:hash/diff?from=&to=` | Finding diff: new, resolved, and persisting |
| `GET /api/projects/:hash/trends` | Per-scan time-series data |
| `GET /api/projects/:hash/heatmap` | Per-file finding rollups |
| `GET /api/projects/:hash/configs/:cfg` | Configuration snapshot |
| `DELETE /api/projects/:hash/scans/:id` | Delete a scan |
| `PUT /api/projects/:hash/scans/:id/label` | Set or clear a label on a scan |

## Configuration

| Field                            | Default | Description                                       |
| -------------------------------- | ------- | ------------------------------------------------- |
| `history.auto_save`              | `true`  | Set to `false` to stop saving scans automatically.|
| `history.max_scans_per_project`  | `100`   | Older scans are removed when this limit is reached.|
| `history.cache`                  | `true`  | Enable the incremental file cache between runs.   |

:::note
On Unix, the dashboard server runs in the background and outlives your terminal session. On Windows, it runs in the foreground.
:::

## See also

- [`zuit diff`](/cli/diff)
- [Baselines and fail-on](/configuration/baselines-and-fail-on)
