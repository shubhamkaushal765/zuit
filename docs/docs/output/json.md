---
title: JSON output
sidebar_label: JSON
description: Feed zuit findings into CI scripts, dashboards, or other tools using the stable JSON report format.
---

# JSON output

Use JSON output when another tool, script, or CI step needs to consume zuit results. The JSON report has a stable schema — field names and sort order are guaranteed not to change without a `schema_version` bump.

```bash
zuit analyze ./src --format json
```

To write the report to a file instead of stdout:

```bash
zuit analyze ./src --format json --output report.json
```

## Example output

A minimal report with one finding:

```json
{
  "schema_version": 2,
  "tool": {
    "name": "zuit",
    "version": "0.1.0"
  },
  "scores": {
    "maintainability": 84.5,
    "security": 100.0,
    "complexity": 100.0,
    "documentation": 78.0,
    "test_smell": 95.0
  },
  "grades": {
    "maintainability": "B",
    "security": "A",
    "complexity": "A",
    "documentation": "C",
    "test_smell": "A"
  },
  "findings": [
    {
      "analyzer": "MAINT001-cyclomatic",
      "dimension": "maintainability",
      "rule_id": "MAINT001-cyclomatic",
      "severity": "medium",
      "message": "Function 'parse_request' has cyclomatic complexity 14 (threshold: 10).",
      "location": {
        "file": "src/lib.rs",
        "span": { "start": 200, "end": 900 },
        "start": { "line": 12, "column": 1 },
        "end": { "line": 45, "column": 2 }
      },
      "suggestion": "Extract sub-routines to reduce branching.",
      "references": [
        "https://docs.zuit.dev/rules/MAINT001-cyclomatic"
      ],
      "cwe": ["CWE-1121"]
    }
  ],
  "stats": {
    "files_scanned": 12,
    "parse_failures": 0,
    "elapsed_ms": 237
  }
}
```

## Filtering with jq

Any JSON-aware tool works. `jq` is convenient for ad-hoc filtering:

```bash
# Show only critical findings
zuit analyze ./src --format json | jq '.findings[] | select(.severity == "critical")'

# Count findings by severity
zuit analyze ./src --format json | jq '[.findings[].severity] | group_by(.) | map({(.[0]): length}) | add'
```

## Stability guarantees

| Property         | Value                                                                                       |
| ---------------- | ------------------------------------------------------------------------------------------- |
| Pretty-printed   | Always (two-space indent)                                                                   |
| Field order      | Stable; documented per object                                                               |
| `schema_version` | Integer; current value is `2`. New optional fields are added without bumping it; we only bump on breaking changes. |
| Sort order       | Findings sorted by `(file, span.start, rule_id)` — deterministic given the same input, safe to diff in CI |

For the complete field-by-field reference — every property, constraint, severity weights, and the scoring formula — see [JSON schema](./json-schema).
