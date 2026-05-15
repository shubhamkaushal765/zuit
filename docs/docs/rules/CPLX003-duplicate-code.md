---
title: CPLX003 — Duplicate Code Block Detected
sidebar_label: CPLX003
description: Detects blocks of identical lines that appear in multiple files
---

# CPLX003-duplicate-code — Duplicate Code Block Detected

**Dimension:** Complexity
**Default severity:** Medium
**Languages:** All
**Last reviewed:** 2026-05-06

## What it detects

Performs a project-wide sliding-window hash scan to identify blocks of identical non-blank, non-comment lines that appear more than once across any combination of files in the project.

### Algorithm

1. For each parsed file, extract normalised non-blank, non-comment lines (stripping leading `//`, `#`, `*`, `--` markers and whitespace).
2. Slide a window of `threshold` lines over the normalised line list and compute a 64-bit hash per window.
3. The first occurrence of each hash is recorded. Every subsequent occurrence at a different location emits one finding at that site, referencing the original location in the message.

## Configuration

```toml
[rules."CPLX003-duplicate-code"]
threshold = 6   # window size in lines; default 6
```

## Why it matters

Copy-pasted logic means bug fixes and refactors must be applied in multiple places. Missing even one copy creates a divergence that is hard to spot in code review and leads to subtle inconsistencies.

## Example — flagged

Two files (`a.rs` and `b.rs`) containing the same 6-line loop body will each produce a finding referencing the other file.

## Fix guidance

Extract the duplicated block into a shared function or module that both call sites can import.

## Limitations

- Blank lines and comment-only lines are excluded from windows, so purely structural duplication (same structure, different comments) may be missed.
- Hash collisions on 64-bit hashes are astronomically unlikely but theoretically possible.
- Only cross-file detection is performed within a single project run; no historical comparison across scan sessions.

## Implementation

- Source: [crates/zuit-analyzers/src/duplicate_code.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/duplicate_code.rs)
- Project-level analyzer: `analyze_file` returns empty; all work is in `analyze_project`.
