---
title: Authoring plugins
sidebar_label: Authoring plugins
---

# Authoring zuit Plugins

A zuit plugin is a directory containing a `zuit-plugin.toml` manifest
and an executable (any language). At scan time zuit spawns the executable,
passes `--project-root <abs>` and `--output-format <zuit-json|sarif>`, and
parses its stdout as findings. Plugins are global (per user) and run as
`ExternalTool` analyzers alongside the built-in language frontends.

---

## Install / remove / update / list

```bash
zuit add-analyzer <PATH | GIT_URL> [--name NAME]  # install
zuit remove-analyzer <NAME>                        # uninstall (idempotent)
zuit update-analyzer <NAME>                        # git pull --ff-only; no-op for local
zuit list plugins                                  # show installed plugins + metadata
```

Source detection (in order): `http://`/`https://`/`git://`/`ssh://` prefix,
`.git` suffix, bare `git@host:path` form → git clone. Otherwise → local path
(must exist).

Name resolution: `--name` wins, then manifest `name`, then slug from git URL
(`last-path-segment`, `.git` stripped). Duplicate name → error; use
`update` or `remove` first.

---

## Manifest reference (`zuit-plugin.toml`)

| Field | Req | Default | Description |
| ----- | --- | ------- | ----------- |
| `name` | yes | — | Install dir name. Pattern: `^[a-z0-9][a-z0-9-]{0,63}$` |
| `version` | yes | — | Semver string (informational) |
| `output` | yes | — | `"zuit-json"` or `"sarif"` |
| `command` | yes | — | Argv array; zuit appends `--project-root` + `--output-format` |
| `description` | no | — | One-line summary |
| `rule_id_prefix` | no | `"<name>/"` | Prefix prepended to rule IDs that don't already have it |
| `extensions` | no | — | Informational list (e.g. `["zig", "zon"]`); does not gate execution |
| `timeout_seconds` | no | `60` | Kill after N seconds |
| `max_output_bytes` | no | `33554432` | Truncate stdout after 32 MiB |
| `license` | no | — | SPDX expression |
| `homepage` | no | — | URL |

---

## Output format: ndjson vs SARIF

| | `zuit-json` | `sarif` |
|---|---|---|
| Format | One JSON object per line | SARIF 2.1.0 single-document |
| Best when | Writing a new plugin from scratch | Wrapping an existing SARIF-emitting tool |
| Span precision | byte offsets or line/col (byte-offset authoritative) | `physicalLocation` region only |
| Custom dimensions | `dimension` field — any v1 string or custom | Not supported (mapped to `security`) |

---

## Sample plugin: Bash + ndjson

### Layout

```
my-plugin/
├── zuit-plugin.toml
└── run.sh
```

### `zuit-plugin.toml`

```toml
name        = "my-plugin"
version     = "0.1.0"
output      = "zuit-json"
command     = ["./run.sh"]
description = "Example Bash plugin"
```

### `run.sh`

```bash
#!/usr/bin/env bash
# zuit passes: --project-root <abs> --output-format zuit-json
set -euo pipefail
ROOT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-root) ROOT="$2"; shift 2 ;;
    *) shift ;;
  esac
done

# Emit one finding per matching line; blank lines are tolerated.
grep -rn "TODO" "$ROOT" --include="*.rs" | while IFS=: read -r file line rest; do
  printf '{"rule_id":"my-plugin/todo","severity":"info","file":"%s","line":%s,"message":"TODO comment","dimension":"maintainability"}\n' \
    "$file" "$line"
done
```

Install: `zuit add-analyzer ./my-plugin`

Example output line:
```
{"rule_id":"my-plugin/todo","severity":"info","file":"src/main.rs","line":5,"message":"TODO comment","dimension":"maintainability"}
```

---

## Sample plugin: Python + SARIF

### Layout

```
sarif-plugin/
├── zuit-plugin.toml
└── check.py
```

### `zuit-plugin.toml`

```toml
name    = "sarif-plugin"
version = "0.1.0"
output  = "sarif"
command = ["python3", "./check.py"]
```

### `check.py`

```python
#!/usr/bin/env python3
"""Minimal SARIF-emitting plugin. Flags files larger than 500 lines."""
import argparse, json, os, sys

parser = argparse.ArgumentParser()
parser.add_argument("--project-root", required=True)
parser.add_argument("--output-format")        # consumed but unused — we always emit SARIF
args = parser.parse_args()

results = []
for dirpath, _, filenames in os.walk(args.project_root):
    for name in filenames:
        if not name.endswith(".py"):
            continue
        path = os.path.join(dirpath, name)
        with open(path, errors="replace") as f:
            lines = f.readlines()
        if len(lines) > 500:
            results.append({
                "ruleId": "large-file",
                "level": "warning",
                "message": {"text": f"File has {len(lines)} lines (> 500)"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": 1}
                }}],
            })

sarif = {"version": "2.1.0", "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
         "runs": [{"tool": {"driver": {"name": "sarif-plugin", "rules": []}}, "results": results}]}
json.dump(sarif, sys.stdout)
```

Install: `zuit add-analyzer ./sarif-plugin`

---

## Trust & safety

Plugins run as the calling user with full OS privileges — equivalent to
running `pip install` or `cargo install`. There is no sandboxing in v1.
**Read the plugin source before installing from an untrusted URL.** Future
work: per-plugin allowlist in `~/.zuit/plugins/policy.toml` and
first-run confirmation prompt.
