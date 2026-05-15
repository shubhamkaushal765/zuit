---
title: TEST001 — Low Test-to-Source Ratio
sidebar_label: TEST001
description: Flags directories with insufficient test coverage by file count
---

# TEST001-test-ratio — Low Test-to-Source Ratio

**Dimension:** TestSmell
**Default severity:** Low
**Languages:** All
**Last reviewed:** 2026-05-05

## What it detects

Flags directories where the ratio of test files to source files is below a configurable threshold. One finding is emitted per under-tested directory, anchored at the lexicographically-first source file in that directory.

## Why it matters

A low test ratio is an early indicator of technical debt accumulation:

- Bugs introduced by refactoring go undetected.
- New contributors have no safety net when modifying code they don't know.
- Confidence in releases decreases as the codebase grows untested.

The per-directory grouping surfaces hot spots: a single directory with many source files and no tests is more actionable than a project-level summary.

## Algorithm

### 1. File classification

Each parsed file is classified as `Test` or `Source`. A file is `Test` when **any** of the following hold (checked in order):

| Heuristic | Examples |
|-----------|---------|
| Path component is a known test directory | `tests/`, `__tests__/`, `spec/`, `test_*/` |
| Filename stem starts with `test_` | `test_utils.py`, `test_models.rs` |
| Filename stem ends with `_test` | `foo_test.rs` |
| Full filename contains `.test.` or `.spec.` | `foo.test.ts`, `bar.spec.tsx` |
| `SemanticIndex` has ≥1 function with `is_test = true` | functions annotated `#[test]` (Rust) or named `test_*` (Python/JS) |

All other files are classified as `Source`.

### 2. Directory grouping

Files are grouped by their immediate parent directory (`file_path.parent()`).

### 3. Threshold check

For each directory that:

- Contains at least `MIN_SOURCE_FILES = 3` source files (hard-coded, not configurable in v1 — see below), **and**
- Has `(test_count * 100) / source_count < threshold`,

one finding is emitted.

## Minimum source files

The constant `MIN_SOURCE_FILES = 3` prevents noise from small directories: a single-file utility module with no tests would otherwise always trigger at the default threshold. This value is intentionally **not** exposed as a configuration knob in v1 to keep the rule simple. Future versions may add a `min_source_files` config key.

## Configuration

| Parameter   | Type  | Default | Notes |
|-------------|-------|---------|-------|
| `threshold` | u32   | `10`    | Percentage; a directory with fewer than this percent test files is flagged. |

Example `zuit.toml`:

```toml
[rules.TEST001-test-ratio]
threshold = 20   # require 20% test coverage by file count
```

A threshold of `0` disables the ratio check (every directory with enough source files would pass).

## Example — flagged

**Fixture:** `fixtures/python/no_tests/`

Contains 5 source files (`alpha.py` … `epsilon.py`) and 0 test files. Ratio = 0% < 10% threshold.

```
TEST001-test-ratio [Low]
fixtures/python/no_tests/alpha.py:1:1
directory 'fixtures/python/no_tests' has a low test:source ratio (0%, target ≥10%)
```

## Example — not flagged

A directory with 3 source files and 1 test file has a 33% ratio — well above the default 10% threshold. No finding is emitted.

A directory with only 2 source files is also not flagged because it is below `MIN_SOURCE_FILES = 3`.

## Fix guidance

- Add unit-test files named `test_<module>.py` (Python), `<module>.test.ts` (JS), or a `#[cfg(test)] mod tests { … }` block (Rust) for each source module.
- Start with the most critical modules (authentication, data validation, core business logic) and expand coverage incrementally.
- Consider a per-PR policy that requires at least one test file for every new source file added.

## Implementation

- Source: [crates/zuit-analyzers/src/test_ratio.rs](https://github.com/shubhamkaushal765/zuit/blob/main/crates/zuit-analyzers/src/test_ratio.rs)
- Classification helper: `classify_file` (public; testable in isolation).
- `MIN_SOURCE_FILES = 3` (constant; not configurable in v1).
- Fixtures: `fixtures/{python,js,rust}/no_tests/`.

## References

- [Test Coverage — Fowler, M. "Refactoring"](https://martinfowler.com/books/refactoring.html)
- [The Practical Test Pyramid — Ham Vocke](https://martinfowler.com/articles/practical-test-pyramid.html)
