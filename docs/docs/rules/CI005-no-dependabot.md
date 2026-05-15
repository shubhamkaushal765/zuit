---
title: CI005-no-dependabot
sidebar_label: CI005-no-dependabot
---
# CI005-no-dependabot

**Dimension:** `ci_release`
**Default severity:** Low
**Languages:** Rust (project-level)
**CWE:** (none)

## What it detects

Fires when `.github/dependabot.yml` (or `.github/dependabot.yaml`) does not exist in the project root.

## Why it matters

Dependabot automatically opens pull requests to keep dependencies up to date, including security patches. Without it, dependency updates are entirely manual and may be delayed — increasing exposure to known vulnerabilities.

## Example — flagged

No `.github/dependabot.yml` file exists.

## Example — not flagged

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
```

## Fix guidance

Create `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

This enables weekly PRs for all Cargo dependencies. Adjust `interval` and `open-pull-requests-limit` to match your workflow.

## References

- [GitHub Dependabot documentation](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuring-dependabot-version-updates)
- [Cargo ecosystem support in Dependabot](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file#package-ecosystem)
