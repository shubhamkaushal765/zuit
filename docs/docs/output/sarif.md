---
title: SARIF output
sidebar_label: SARIF
description: Upload zuit findings to GitHub code scanning, Azure DevOps, or any other SARIF-compatible security platform.
---

# SARIF output

Use SARIF output to feed zuit findings into a security platform. SARIF (Static Analysis Results Interchange Format) is an open standard that GitHub code scanning, Azure DevOps, and many other tools accept natively. Uploading a SARIF file lets those platforms annotate pull requests, track findings over time, and manage alerts in their security dashboards.

```bash
zuit analyze ./src --format sarif --output results.sarif
```

## What is emitted

zuit produces a SARIF 2.1.0 document containing:

- A single `run` object with all findings as `results`.
- CWE and OWASP taxonomy references attached to each relevant result.
- Each finding's location mapped to a SARIF `physicalLocation` with line and column.
- `rule` objects in `tool.driver.rules` carrying the rule ID, short description, and severity.

## GitHub Actions integration

The [GitHub Action](/integrations/github-action) handles SARIF analysis and upload automatically:

```yaml
- uses: shubhamkaushal765/zuit@main
  with:
    format: "sarif"
    fail-on: "high"
```

For manual upload — useful when you want more control over which step runs zuit and which uploads the results:

```yaml
- run: zuit analyze . --format sarif --output results.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

`continue-on-error: true` on the zuit step ensures the upload step still runs even when `--fail-on` triggers a non-zero exit.

## When to prefer JSON

For programmatic access — extracting findings, gating CI, or aggregating across runs — use [JSON](./json) instead. JSON is the stable contract; SARIF is a presentation format designed for code-scanning platform integrations.

## References

- [SARIF 2.1.0 specification (OASIS)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [GitHub code scanning documentation](https://docs.github.com/en/code-security/code-scanning)
