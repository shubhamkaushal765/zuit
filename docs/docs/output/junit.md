---
title: JUnit XML output
sidebar_label: JUnit
---

# JUnit XML Integration

JUnit XML (Surefire / Maven flavour) is the lingua-franca test-report format
consumed by GitHub Actions, Jenkins, GitLab, CircleCI, and most other CI
systems. `zuit` can emit findings in JUnit XML so they show up as test
results in the same UI as your unit tests.

## Generate a JUnit report

```sh
zuit analyze --format junit src/ > zuit-junit.xml
```

## Schema overview

```xml
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="zuit" tests="N" failures="F" errors="E" time="0">
  <testsuite name="Security" tests="3" failures="1" errors="2" time="0">
    <testcase name="SEC001-hardcoded-secret at src/lib.rs:42"
              classname="src/lib.rs" time="0">
      <error message="Hardcoded secret detected"
             type="SEC001-hardcoded-secret">
        File: src/lib.rs
        Line: 42
        Severity: high
        CWE: CWE-798
        OWASP: A07:2021
      </error>
    </testcase>
    ...
  </testsuite>
  ...
</testsuites>
```

One `<testsuite>` is emitted per `crates/zuit-core/src/analyzer.rs`
that has at least one finding (Maintainability → Documentation → Security →
Complexity → TestSmell → Custom). Each finding becomes a single `<testcase>`.

## Severity mapping

| zuit Severity | JUnit element | Notes |
|-------------------|---------------|-------|
| `Critical`        | `<error>`     | Critical bugs surface as errors. |
| `High`            | `<error>`     | High-severity findings surface as errors. |
| `Medium`          | `<failure>`   | Medium severity surfaces as a test failure. |
| `Low`             | `<failure>`   | Low severity surfaces as a test failure. |
| `Info`            | (none)        | Informational findings emit a bare `<testcase>` so the result counts but does not fail the build. |

The top-level `tests`, `failures`, `errors` attributes count actual children;
the same per-suite counts are also rolled up.

## GitHub Actions

Most JUnit-aware actions work out of the box. Example with
[`mikepenz/action-junit-report`](https://github.com/mikepenz/action-junit-report):

```yaml
- name: Run zuit
  run: zuit analyze --format junit src/ > zuit-junit.xml

- name: Surface findings as a JUnit report
  if: always()
  uses: mikepenz/action-junit-report@v4
  with:
    report_paths: zuit-junit.xml
    check_name: zuit
    fail_on_failure: true
```

## Jenkins

Use the built-in JUnit publisher:

```groovy
post {
  always {
    junit 'zuit-junit.xml'
  }
}
```

## GitLab CI

```yaml
zuit:
  script: zuit analyze --format junit src/ > zuit-junit.xml
  artifacts:
    when: always
    reports:
      junit: zuit-junit.xml
```

## Notes

- Findings are sorted deterministically by `(dimension, file, line, column,
  rule_id)` so two runs over identical source produce byte-identical XML.
- XML attribute values are escaped automatically; messages containing `&`,
  `<`, `"`, `'` are safe.
- `time="0"` is emitted on every element — `zuit` does not measure
  per-finding wall time.
