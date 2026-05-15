---
title: Rules reference
description: All rules built into zuit v1, indexed by dimension and severity.
---

# Rules reference

A *rule* is a single check zuit performs against your code. Each rule has a stable id (e.g. `MAINT001-cyclomatic`) that never changes once shipped, a dimension, and a default severity.

## All rules by dimension

### Complexity

| Rule ID | Title | Default severity | Languages |
| --- | --- | --- | --- |
| [CPLX001-fan-out](/rules/CPLX001-fan-out) | Module Fan-Out | Low | All |
| [CPLX002-cyclic-deps](/rules/CPLX002-cyclic-deps) | Cyclic Imports | High | All |
| [CPLX003-duplicate-code](/rules/CPLX003-duplicate-code) | Duplicate Code Block Detected | Medium | All |

### Documentation

| Rule ID | Title | Default severity | Languages |
| --- | --- | --- | --- |
| [DOC001-public-api-undoc](/rules/DOC001-public-api-undoc) | Public API Documentation | Medium | All |
| [DOC002-todo-fixme](/rules/DOC002-todo-fixme) | TODO / FIXME Marker Inventory | Info | All |
| [DOC003-empty-doc](/rules/DOC003-empty-doc) | Empty or Placeholder Documentation Comment | Info | All |

### Maintainability

| Rule ID | Title | Default severity | Languages |
| --- | --- | --- | --- |
| [MAINT001-cyclomatic](/rules/MAINT001-cyclomatic) | Cyclomatic Complexity | Medium | All |
| [MAINT002-cognitive](/rules/MAINT002-cognitive) | Cognitive Complexity | Medium | All |
| [MAINT003-fn-length](/rules/MAINT003-fn-length) | Function Length | Low | All |
| [MAINT004-file-length](/rules/MAINT004-file-length) | File Length | Low | All |
| [MAINT005-deep-nesting](/rules/MAINT005-deep-nesting) | Deep Nesting | Medium | All |
| [MAINT006-too-many-params](/rules/MAINT006-too-many-params) | Too Many Parameters | Low | All |
| [MAINT007-return-complexity](/rules/MAINT007-return-complexity) | Excessive Return Statements | Low | All |

### Security

| Rule ID | Title | Default severity | Languages |
| --- | --- | --- | --- |
| [SEC001-hardcoded-secret](/rules/SEC001-hardcoded-secret) | Hardcoded Secrets | High | All |
| [SEC002-eval-sink](/rules/SEC002-eval-sink) | Unsafe Code Execution | High | Python, JS/TS |
| [SEC003-shell-injection](/rules/SEC003-shell-injection) | Shell Injection Sink | High | All |
| [SEC004-weak-crypto](/rules/SEC004-weak-crypto) | Weak Cryptographic Hash Algorithm | Medium | All |
| [SEC005-insecure-deser](/rules/SEC005-insecure-deser) | Insecure Deserialization | High | Python, JS/TS |
| [SEC006-sql-injection](/rules/SEC006-sql-injection) | SQL Injection via String Interpolation | High | All |
| [SEC007-path-traversal](/rules/SEC007-path-traversal) | Path Traversal via Unvalidated File Paths | High | All |
| [SEC101-rust-unsafe](/rules/SEC101-rust-unsafe) | Unsafe Code Audit Trail | Info | Rust only |

### Dependency Security

| Rule ID | Title | Default severity | Languages |
| --- | --- | --- | --- |
| [DEP001-vulnerable-deps](/rules/DEP001-vulnerable-deps) | Known Vulnerable Dependency | High | All (project-level) |

### Test Smells

| Rule ID | Title | Default severity | Languages |
| --- | --- | --- | --- |
| [TEST001-test-ratio](/rules/TEST001-test-ratio) | Low Test-to-Source Ratio | Low | All |
| [TEST002-no-asserts](/rules/TEST002-no-asserts) | Test File With No Assertions | Medium | All |
| [TEST003-skipped](/rules/TEST003-skipped) | Skipped or Ignored Tests | Info | All |
| [TEST004-flaky-time](/rules/TEST004-flaky-time) | Test Uses Time or Randomness | Medium | All |
| [TEST005-assert-count](/rules/TEST005-assert-count) | Too Many Assertions in One Test | Low | All |

## Severity levels

Severity controls how heavily a finding is weighted in the dimension score. Higher severity = larger penalty.

| Severity   | Weight | Use                                          |
| ---------- | ------ | -------------------------------------------- |
| `info`     | 0      | Informational; does not affect the score    |
| `low`      | 1      | Minor issue                                  |
| `medium`   | 4      | Moderate issue                               |
| `high`     | 12     | Serious issue                                |
| `critical` | 30     | Must fix immediately                         |

See [Severity and scoring](/concepts/severity-and-scoring) for the score formula.

## Suppression

All rules support inline suppression via special comments. See [Finding Suppression](./suppression.md) for syntax and examples.
