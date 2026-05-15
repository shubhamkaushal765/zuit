---
title: Checkstyle XML output
sidebar_label: Checkstyle
---

# Checkstyle XML Integration

Checkstyle XML is a widely-supported interchange format for static analysis
results. `zuit` can emit findings in Checkstyle v8 XML format, which is
natively understood by IntelliJ IDEA (via the Checkstyle plugin), SonarQube,
and many CI/CD tools.

## Generate a Checkstyle report

```sh
zuit analyze --format checkstyle src/ > checkstyle.xml
```

## IntelliJ IDEA

1. Install the **Checkstyle-IDEA** plugin from the JetBrains Marketplace
   (Settings → Plugins → search "CheckStyle-IDEA").
2. Open Settings → Tools → Checkstyle.
3. Under "Configuration File", click **+** → "Use a local Checkstyle file" →
   select `checkstyle.xml`.
4. Run the check via Analyze → Run Inspection by Name → "Checkstyle".

Findings appear in the Checkstyle tool window with file, line, and severity.

## SonarQube

Add the following property to your `sonar-project.properties` (or pass it as a
CLI argument):

```properties
sonar.externalReportPaths.checkstyle=checkstyle.xml
```

SonarQube 7.2+ can import Checkstyle XML directly without a dedicated plugin.

## GitHub Actions

Many CI steps can parse Checkstyle XML and annotate pull requests. Example
using the `jwgmeligmeyling/checkstyle-github-action` action:

```yaml
- name: Run zuit
  run: zuit analyze --format checkstyle src/ > checkstyle.xml

- name: Annotate PR with findings
  uses: jwgmeligmeyling/checkstyle-github-action@master
  with:
    path: checkstyle.xml
```

## Jenkins

Use the **Warnings Next Generation** plugin and point it at the Checkstyle
report:

```groovy
recordIssues(tools: [checkStyle(pattern: 'checkstyle.xml')])
```
