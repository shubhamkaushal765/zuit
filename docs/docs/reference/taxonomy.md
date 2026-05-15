---
title: CWE / OWASP taxonomy
sidebar_label: Taxonomy
---

# Rule taxonomy (CWE / OWASP)

Each rule carries a static CWE (and where applicable OWASP) mapping in its
`RuleMeta`. Every emitted `crates/zuit-core/src/finding.rs`
ships `cwe` and `owasp` arrays alongside its `references` field. The CLI
`--cwe` / `--owasp` filters use these arrays for rule-pack selection (see
`AGENTS.md` and `crates/zuit-cli/src/analyze.rs`).

## Mapping

| Rule                              | CWE              | OWASP    |
| --------------------------------- | ---------------- | -------- |
| MAINT001-cyclomatic               | CWE-1121         | —        |
| MAINT002-cognitive                | CWE-1121         | —        |
| MAINT003-fn-length                | CWE-1121         | —        |
| MAINT004-file-length              | CWE-1080         | —        |
| MAINT005-deep-nesting             | CWE-1124         | —        |
| MAINT006-too-many-params          | CWE-1121         | —        |
| DOC001-public-api-undoc           | CWE-1059         | —        |
| DOC002-todo-fixme                 | CWE-546          | —        |
| DOC004-stale-doc                  | —                | —        |
| SEC001-hardcoded-secret           | CWE-798          | A07:2021 |
| SEC002-eval-sink                  | CWE-95, CWE-79   | A03:2021 |
| SEC003-shell-injection            | CWE-78           | A03:2021 |
| SEC004-weak-crypto                | CWE-327          | A02:2021 |
| SEC005-insecure-deser             | CWE-502          | A08:2021 |
| SEC006-sql-injection              | CWE-89           | A03:2021 |
| SEC007-path-traversal             | CWE-22           | A01:2021 |
| SEC008-csrf-missing               | CWE-352          | A01:2021 |
| SEC009-open-redirect              | CWE-601          | A01:2021 |
| SEC010-ssrf                       | CWE-918          | A10:2021 |
| SEC011-cors-permissive            | CWE-942          | A05:2021 |
| SEC101-rust-unsafe                | CWE-758          | —        |
| CPLX001-fan-out                   | —                | —        |
| CPLX002-cyclic-deps               | —                | —        |
| PKG001-install-script-present     | CWE-506          | —        |
| SOUND003-transmute-usage          | CWE-704          | —        |
| TEST001-test-ratio                | —                | —        |
| TEST002-no-asserts                | —                | —        |
| TEST003-skipped                   | —                | —        |
| TEST004-flaky-time                | CWE-362          | —        |
| TEST005-assert-count              | —                | —        |
| TEST006-shared-mutable-state      | CWE-820          | —        |

> All other rule families (`SOUND001-002,004-006`, `PKG002-005`, `HEALTH`,
> `CHAIN`, `PERF`, `ECO`, `CI`) are operational/quality rules and do not
> carry CWE/OWASP tags.

## Where these flow

- **JSON output** — `cwe` / `owasp` arrays per finding (omitted when empty).
- **SARIF 2.1.0** — emitted as result-level `taxa` references.
- **Terminal / Markdown** — printed alongside the rule id when present.
- **`zuit list analyzers`** — shown next to the rule's metadata.
- **`zuit analyze --owasp <CAT>` / `--cwe <ID>`** — post-analysis allowlist filters; case-insensitive, repeatable, intersect when combined.
