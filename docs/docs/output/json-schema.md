---
title: JSON schema
sidebar_label: JSON schema
description: Complete field-by-field reference for the zuit JSON report — every property, severity weights, the scoring formula, and version history.
---

# JSON schema

This is the complete reference for the JSON document produced by `zuit analyze --format json`. For a usage-oriented overview and filtering examples, see [JSON output](./json).

The canonical source lives at [`docs/json-schema.md` in the zuit repo](https://github.com/shubhamkaushal765/zuit/blob/main/docs/json-schema.md).

**Schema version:** 2  
**Stability:** v2 is stable. Any breaking change bumps `schema_version`.

---

## Top-level shape

```json
{
  "schema_version": 2,
  "tool": {
    "name": "zuit",
    "version": "0.1.0"
  },
  "scores": {
    "maintainability": 87.4,
    "security": 92.1,
    "complexity": 100.0,
    "documentation": 78.3,
    "test_smell": 95.0
  },
  "grades": {
    "maintainability": "B",
    "security": "A",
    "complexity": "A",
    "documentation": "C",
    "test_smell": "A"
  },
  "findings": [],
  "stats": {
    "files_scanned": 412,
    "parse_failures": 0,
    "elapsed_ms": 1837
  }
}
```

Field order in the top-level object is always:
`schema_version` → `tool` → `scores` → `grades` → `findings` → `stats`.

---

## Fields

### `schema_version`

| Property      | Value                                                 |
| ------------- | ----------------------------------------------------- |
| Type          | integer                                               |
| Current value | `2`                                                   |
| Constraints   | Positive integer. Incremented on any breaking change. |

If you consume this output in a script or tool, check `schema_version` first. Reject documents whose version is higher than your tool supports, and warn on versions lower than expected.

---

### `tool`

| Property | Value  |
| -------- | ------ |
| Type     | object |

| Sub-field | Type   | Description                                                                |
| --------- | ------ | -------------------------------------------------------------------------- |
| `name`    | string | Always `"zuit"`                                                        |
| `version` | string | Version of the binary that produced this report (e.g. `"0.1.0"`)          |

---

### `scores`

| Property   | Value                                          |
| ---------- | ---------------------------------------------- |
| Type       | object                                         |
| Key type   | string (dimension name)                        |
| Value type | number (float)                                 |
| Range      | `0.0` to `100.0` inclusive. Higher is better. |

**Field order guarantee:** The five standard dimension keys always appear in this order:

1. `maintainability`
2. `security`
3. `complexity`
4. `documentation`
5. `test_smell`

Custom dimensions (if any) follow in lexicographic order.

**Precision:** Scores are produced at full `f32` precision. Display formats (terminal, markdown) round to one decimal place.

**Scoring formula:**

```text
weights      = { info: 0, low: 1, medium: 4, high: 12, critical: 30 }
weighted_sum = sum of weights[finding.severity] for all findings in this dimension
penalty      = clamp(weighted_sum / max(kloc, 1), 0, 100)
score        = 100 - penalty
```

where `kloc` is the effective lines of code of the project (approximated from total bytes / 80).

**Dimension values:**

| Value               | Description                                                            |
| ------------------- | ---------------------------------------------------------------------- |
| `"maintainability"` | Readability, modifiability, function/file length                       |
| `"security"`        | Hardcoded secrets, eval sinks, shell injection, weak crypto            |
| `"complexity"`      | Cyclomatic / cognitive complexity, fan-out, cyclic dependencies        |
| `"documentation"`   | Missing public API docs, TODO/FIXME inventory                          |
| `"test_smell"`      | Test ratio, no-assert tests, skipped tests                             |

---

### `grades`

| Property   | Value                          |
| ---------- | ------------------------------ |
| Type       | object                         |
| Key type   | string (dimension name)        |
| Value type | string (letter grade `A`–`F`)  |

Letter grade assigned to each dimension based on its score:

| Grade | Score range |
| ----- | ----------- |
| `"A"` | ≥ 90        |
| `"B"` | ≥ 80        |
| `"C"` | ≥ 70        |
| `"D"` | ≥ 60        |
| `"F"` | < 60        |

Field order in `grades` matches the field order of `scores`.

---

### `findings`

| Property | Value                    |
| -------- | ------------------------ |
| Type     | array of finding objects |

**Sort order guarantee:** Findings are sorted by `(location.file, location.span.start, rule_id)`. This order is deterministic across runs given the same input, so the output is safe to diff in CI.

#### Finding object

```json
{
  "analyzer": "MAINT001-cyclomatic",
  "dimension": "maintainability",
  "rule_id": "MAINT001-cyclomatic",
  "severity": "medium",
  "message": "Function 'parse_request' has cyclomatic complexity 14 (threshold: 10).",
  "location": {
    "file": "src/lib.rs",
    "span": {
      "start": 200,
      "end": 900
    },
    "start": {
      "line": 12,
      "column": 1
    },
    "end": {
      "line": 45,
      "column": 2
    }
  },
  "suggestion": "Extract sub-routines to reduce branching.",
  "references": [
    "https://docs.zuit.dev/rules/MAINT001-cyclomatic"
  ],
  "cwe": ["CWE-1121"],
  "owasp": []
}
```

| Field        | Type             | Constraints         | Description                                                                               |
| ------------ | ---------------- | ------------------- | ----------------------------------------------------------------------------------------- |
| `analyzer`   | string           | Non-empty           | Stable ID of the analyzer instance (e.g. `"MAINT001-cyclomatic"`)                        |
| `dimension`  | string           | See dimension table | Quality dimension addressed                                                               |
| `rule_id`    | string           | Non-empty           | Stable rule identifier (same format as `analyzer` for single-rule analyzers)             |
| `severity`   | string           | See severity table  | How severe the finding is                                                                 |
| `message`    | string           | Non-empty           | Human-readable explanation                                                                |
| `location`   | object           | —                   | Precise source location (see below)                                                       |
| `suggestion` | string \| null   | —                   | Optional fix guidance                                                                     |
| `references` | array of string  | —                   | Links to external documentation (rule pages, vendor advisories, etc.)                    |
| `cwe`        | array of string  | —                   | CWE identifiers (e.g. `"CWE-798"`). Omitted from output when empty.                      |
| `owasp`      | array of string  | —                   | OWASP categories (e.g. `"A07:2021"`). Omitted from output when empty.                    |

**Severity values** (lowest to highest):

| Value        | Weight | Description                                |
| ------------ | ------ | ------------------------------------------ |
| `"info"`     | 0      | Informational; does not affect the score   |
| `"low"`      | 1      | Minor issue                                |
| `"medium"`   | 4      | Moderate issue                             |
| `"high"`     | 12     | Serious issue                              |
| `"critical"` | 30     | Must fix immediately                       |

#### Location object

| Field          | Type    | Description                                                          |
| -------------- | ------- | -------------------------------------------------------------------- |
| `file`         | string  | Path to the source file (relative to project root)                   |
| `span.start`   | integer | Byte offset of the first byte of the region (inclusive)              |
| `span.end`     | integer | Byte offset of the first byte after the region (exclusive)           |
| `start.line`   | integer | One-indexed line number of the start of the region                   |
| `start.column` | integer | One-indexed byte-column of the start of the region                   |
| `end.line`     | integer | One-indexed line number of the end of the region                     |
| `end.column`   | integer | One-indexed byte-column of the end of the region                     |

---

### `stats`

| Field            | Type    | Description                                                          |
| ---------------- | ------- | -------------------------------------------------------------------- |
| `files_scanned`  | integer | Number of files successfully parsed and analysed                     |
| `parse_failures` | integer | Number of files that could not be parsed (non-fatal)                 |
| `elapsed_ms`     | integer | Wall-clock time of the full analysis run in milliseconds             |

---

## End-to-end example

Input: a small Rust project with two files (`src/auth.rs`, `src/lib.rs`).

```json
{
  "schema_version": 2,
  "tool": {
    "name": "zuit",
    "version": "0.1.0"
  },
  "scores": {
    "maintainability": 84.5,
    "security": 62.0,
    "complexity": 100.0,
    "documentation": 78.0,
    "test_smell": 95.0
  },
  "grades": {
    "maintainability": "B",
    "security": "F",
    "complexity": "A",
    "documentation": "C",
    "test_smell": "A"
  },
  "findings": [
    {
      "analyzer": "SEC001-hardcoded-secret",
      "dimension": "security",
      "rule_id": "SEC001-hardcoded-secret",
      "severity": "critical",
      "message": "High-entropy string resembles a secret: 'AKIAIOSFODNN7EXAMPLE...'",
      "location": {
        "file": "src/auth.rs",
        "span": { "start": 42, "end": 80 },
        "start": { "line": 3, "column": 15 },
        "end": { "line": 3, "column": 53 }
      },
      "suggestion": "Move credentials to environment variables or a secrets manager.",
      "references": [
        "https://docs.zuit.dev/rules/SEC001-hardcoded-secret"
      ],
      "cwe": ["CWE-798"],
      "owasp": ["A07:2021"]
    },
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
    "parse_failures": 1,
    "elapsed_ms": 237
  }
}
```

---

## Version history

| Version | Changes |
| ------- | ------- |
| 2 | Added `grades` top-level object (breaking: new required field). Added optional `cwe` and `owasp` arrays to findings (omitted when empty). Bumped `schema_version` from 1 to 2. |
| 1 | Initial stable release. |
