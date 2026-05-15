---
title: Severity and scoring
description: How severity levels map to score penalties, and how to read the 0–100 per-dimension score.
---

import SeverityWeights from '@site/src/components/diagrams/SeverityWeights';

# Severity and scoring

*Severity* tells you how serious a single finding is. *Score* tells you how clean a dimension is overall, across your whole project.

## Severity levels

<SeverityWeights />

| Severity   | Weight | What it means                                                                 |
| ---------- | ------ | ----------------------------------------------------------------------------- |
| `info`     | 0      | Informational only — appears in the report but does not lower your score      |
| `low`      | 1      | Minor issue, worth fixing but not urgent                                      |
| `medium`   | 4      | Noticeable quality problem; plan to address it                                |
| `high`     | 12     | Significant issue that should be fixed before shipping                        |
| `critical` | 30     | Severe risk — fix this immediately                                            |

The weight values matter because they feed directly into the score formula below.

## How scores are calculated

Each dimension gets a score from 0 to 100. A higher score means cleaner code. zuit calculates it like this:

1. Add up the weights of all findings in that dimension.
2. Divide by your project's size in thousands of lines of code, so a large project is not unfairly penalized for having more findings than a small one.
3. Subtract the result from 100, clamped so the score never goes below 0.

```text
weighted_sum = sum of weights for all findings in this dimension
penalty      = clamp(weighted_sum / max(kloc, 1), 0, 100)
score        = 100 - penalty
```

The clamping step means a single file with many severe findings cannot drag an entire dimension to zero on its own — the penalty is always scaled against project size.

:::note
`kloc` is your project's effective lines of code in supported languages. In v1, zuit estimates this from total source bytes divided by 80. A real line counter will replace this heuristic in a future release.
:::

## Worked example

A 5,000-line project (kloc = 5) has these Security findings:

- 1 critical (weight 30)
- 2 high (weight 12 each, total 24)
- 3 medium (weight 4 each, total 12)

```text
weighted_sum = 30 + 24 + 12 = 66
penalty      = clamp(66 / 5, 0, 100) = 13.2
security     = 100 - 13.2 = 86.8
```

The Security score is **86.8**.

## Setting CI thresholds

You can tell zuit to fail a CI run when any dimension score drops below a threshold:

```toml
# zuit.toml
[thresholds]
security = 80
maintainability = 70
```

See [Baselines and fail-on](/configuration/baselines-and-fail-on) for the full set of options.

## Overriding severity for a specific rule

If a rule's default severity does not match your project's risk profile, you can override it in `zuit.toml`:

```toml
[rules.SEC001-hardcoded-secret]
severity = "critical"
```

See [Per-rule configuration](/configuration/per-rule-config).
