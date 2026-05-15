---
title: DEP001 — Known Vulnerable Dependency
sidebar_label: DEP001
description: Checks dependency lock files against a bundled database of known CVEs
---

# DEP001-vulnerable-deps — Known Vulnerable Dependency

**Dimension:** Security
**Default severity:** High
**Languages:** All (project-level)
**CWE:** [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html)
**OWASP:** A06:2021 – Vulnerable and Outdated Components
**Last reviewed:** 2026-05-06

## What it detects

Checks dependency lock files at the project root against a small bundled offline database of known-vulnerable package versions.

### Supported lock files

| File | Ecosystem |
|---|---|
| `Cargo.lock` | Rust / Cargo |
| `package-lock.json` | Node.js / npm (v2 format) |
| `requirements.txt` | Python / pip (exact `==` pins) |

### Offline database

The bundled database covers a representative set of well-known historical CVEs:

| Package | Affected prefix | CVE |
|---|---|---|
| `serde_yaml` | `0.*` | GHSA-qwqr-xp34-m6mj |
| `lodash` | `4.17.*` (< 4.17.21) | CVE-2021-23337 |
| `requests` | `2.*` (< 2.31.0) | CVE-2023-32681 |
| `tar` | `6.1.*` (< 6.1.2) | CVE-2021-32803 |
| `pyyaml` | `5.*` | CVE-2020-14343 |
| `minimist` | `1.2.*` (< 1.2.6) | CVE-2021-44906 |
| `werkzeug` | `2.1.*` | CVE-2023-25577 |
| `ansi-regex` | `5.0.*` (< 5.0.1) | CVE-2021-3807 |
| `setuptools` | `6*` (< 65.5.1) | CVE-2022-40897 |
| `flask` | `1.*` | CVE-2023-30861 |

> **Important:** This is a static snapshot — it is **not** updated automatically. For up-to-date scanning use `cargo-audit`, `npm audit`, or `pip-audit` alongside zuit.

## Configuration

The rule runs automatically. To opt out:

```toml
[rules."DEP001-vulnerable-deps"]
enabled = false
```

## Fix guidance

Upgrade the identified package to a non-vulnerable version. Check the linked CVE advisory for the minimum safe version.

## Implementation

- Source: [crates/zuit-analyzers/src/vulnerable_deps.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/vulnerable_deps.rs)
- Project-level analyzer: `analyze_file` returns empty; `analyze_project` reads lock files from `project.root`.

## References

- [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html)
- [OWASP A06:2021](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
- [cargo-audit](https://crates.io/crates/cargo-audit)
- [pip-audit](https://pypi.org/project/pip-audit/)
