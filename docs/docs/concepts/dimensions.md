---
title: Dimensions
description: The quality dimensions zuit measures, what each one checks, and why it matters for your project.
---

import DimensionsHexagon from '@site/src/components/diagrams/DimensionsHexagon';

# Dimensions

zuit groups every finding it reports into one of several dimensions. Each dimension gets its own 0–100 score, so you can see at a glance where your project is healthy and where it needs attention. CI gates work per-dimension, so you can enforce a Security floor without blocking on Documentation.

## At a glance

| Dimension       | Serialised name    | Rules | What it measures                                                                 |
| --------------- | ------------------ | -----:| -------------------------------------------------------------------------------- |
| Security        | `security`         | 16    | Patterns commonly exploited by attackers                                         |
| Maintainability | `maintainability`  | 14    | How easy the code is to read and modify (length, nesting, branching)             |
| Complexity      | `complexity`       | 3     | Structural complexity across files (fan-out, cyclic deps, duplicate code)        |
| Documentation   | `documentation`    | 4     | Public-API doc coverage and inline TODO/FIXME inventory                          |
| Test smell      | `test_smell`       | 6     | Quality of tests themselves (test ratio, no-assert tests, skipped tests, flaky)  |
| Supply chain    | `supply_chain`     | 8     | Dependency provenance, typosquatting, lockfiles, stale transitives               |
| Packaging       | `packaging`        | 23    | Package metadata correctness and consumer usability                              |
| Performance     | `performance`      | 8     | Bundle size, heavy imports, compile-time and runtime overhead                    |
| Soundness       | `unsafe_soundness` | 6     | Rust memory safety and unsoundness patterns                                      |
| Project health  | `project_health`   | 5     | Repository health (bus factor, release cadence, changelog)                       |
| CI / release    | `ci_release`       | 5     | CI pipeline completeness (MSRV, multi-OS, deny job, Dependabot)                  |
| Ecosystem       | `ecosystem`        | 4     | Rust ecosystem compatibility (no_std, async runtime, Send/Sync)                  |
| API stability   | `api_stability`    | 3     | Public-API drift across releases (removed symbols, semver alignment)             |

:::note
Each dimension produces an independent 0–100 score. There is no single composite score — you choose which dimensions to gate on in CI. The five v1 dimensions (Security through Test smell) are first-class variants of `Dimension`; the rest serialise as `Dimension::Custom("...")` and round-trip through every formatter unchanged.
:::

<DimensionsHexagon />

---

## Security

**What this catches:** Code patterns that are commonly exploited by attackers — hardcoded credentials, dangerous functions like `eval`, use of memory-unsafe blocks, and similar issues that create real attack surface.

**Why you should care:** A single hardcoded secret or injection sink can compromise your entire application. Security findings are the highest-stakes issues zuit reports, and most of them come with a concrete suggestion for how to fix the problem.

**Examples of issues you'll see:**

- A database password embedded directly in source code (`SEC001-hardcoded-secret`)
- A call to `eval()` with user-controlled input (`SEC002-eval-sink`)
- An `unsafe` block in Rust that bypasses memory safety guarantees (`SEC101-rust-unsafe`)

Rules: [SEC001-hardcoded-secret](/rules/SEC001-hardcoded-secret), [SEC002-eval-sink](/rules/SEC002-eval-sink), [SEC101-rust-unsafe](/rules/SEC101-rust-unsafe)

---

## Maintainability

**What this catches:** Code that is technically correct today but difficult to read, change, or review — functions that are too long, too deeply nested, or have too many decision branches.

**Why you should care:** High-maintainability code is easier to onboard new contributors to, cheaper to extend, and less likely to hide bugs. When this score drops, it usually means functions are doing too many things at once.

**Examples of issues you'll see:**

- A function with a cyclomatic complexity score above your threshold (`MAINT001-cyclomatic`)
- A function over 100 lines long (`MAINT003-fn-length`)
- A file that has grown to several hundred lines and should be split (`MAINT004-file-length`)
- `if` blocks nested five or more levels deep (`MAINT005-deep-nesting`)

Rules: [MAINT001-cyclomatic](/rules/MAINT001-cyclomatic), [MAINT003-fn-length](/rules/MAINT003-fn-length), [MAINT004-file-length](/rules/MAINT004-file-length), [MAINT005-deep-nesting](/rules/MAINT005-deep-nesting)

---

## Complexity

**What this catches:** Structural complexity that spans multiple files — modules with too many dependencies on other modules (fan-out), circular dependencies between modules, and blocks of copy-pasted code that should be consolidated.

**Why you should care:** Even when individual functions look clean, a codebase can become brittle if modules are tightly entangled or if the same logic is duplicated in five places. Changes in one part unexpectedly break another.

**Examples of issues you'll see:**

- A module that imports from 20 other modules (`CPLX001-fan-out`)
- Two or more modules that depend on each other, creating a cycle (`CPLX002-cyclic-deps`)
- Near-identical code blocks repeated across multiple files (`CPLX003-duplicate-code`)

Rules: [CPLX001-fan-out](/rules/CPLX001-fan-out), [CPLX002-cyclic-deps](/rules/CPLX002-cyclic-deps), [CPLX003-duplicate-code](/rules/CPLX003-duplicate-code)

---

## Documentation

**What this catches:** Public functions, classes, and modules that have no documentation, plus `TODO` and `FIXME` comments that have accumulated and never been resolved.

**Why you should care:** Undocumented public APIs slow down anyone trying to use or extend your code. A pile of unresolved `TODO` comments is a signal that technical debt is being deferred rather than addressed.

**Examples of issues you'll see:**

- A public function with no docstring or doc comment (`DOC001-public-api-undoc`)
- A `FIXME` comment that has been in the codebase for months (`DOC002-todo-fixme`)
- An empty or placeholder doc comment that satisfies the linter but says nothing (`DOC003-empty-doc`)

Rules: [DOC001-public-api-undoc](/rules/DOC001-public-api-undoc), [DOC002-todo-fixme](/rules/DOC002-todo-fixme), [DOC003-empty-doc](/rules/DOC003-empty-doc), [DOC004-stale-doc](/rules/DOC004-stale-doc)

---

## Test smell

**What this catches:** Problems with the tests themselves — not enough tests overall, test functions with no assertions, skipped tests that nobody has re-enabled, and patterns that make tests flaky.

**Why you should care:** Tests that exist but don't assert anything give you false confidence. Skipped tests mean coverage gaps you may have forgotten about. Flaky tests erode trust in your CI pipeline.

**Examples of issues you'll see:**

- A project where less than 20% of source files have corresponding test files (`TEST001-test-ratio`)
- A test function with zero `assert` calls (`TEST002-no-asserts`)
- A test marked with `skip` or `pytest.mark.skip` (`TEST003-skipped`)
- A test that compares against `time.time()` or `Date.now()` (`TEST004-flaky-time`)
- A single test crammed with more than ten assertions (`TEST005-assert-count`)

Rules: [TEST001-test-ratio](/rules/TEST001-test-ratio), [TEST002-no-asserts](/rules/TEST002-no-asserts), [TEST003-skipped](/rules/TEST003-skipped), [TEST004-flaky-time](/rules/TEST004-flaky-time), [TEST005-assert-count](/rules/TEST005-assert-count)

---

## Supply chain (`supply_chain`)

**What this catches:** Risks introduced by the dependency graph — typosquatted package names, missing lockfiles, unpinned runtime dependencies, missing provenance attestations, and stale transitive dependencies.

**Why you should care:** Supply-chain attacks are among the fastest-growing threat vectors. Catching suspicious dependency names, missing provenance, and unpinned deps at the point of declaration is cheaper than post-compromise remediation.

**Examples of issues you'll see:**

- A dependency name suspiciously close to a popular package (`CHAIN002-typosquat-suspicion`)
- No `package-lock.json` or `Cargo.lock` (`CHAIN001-no-lockfile`)
- A `dist/` directory with no provenance attestation (`CHAIN003-provenance-bundle-missing`)
- A transitive npm dependency last published more than 18 months ago (`CHAIN004-unmaintained-transitive`)

---

## Packaging (`packaging`)

**What this catches:** Package metadata problems that affect installability, usability, or correctness of the distributed artifact — missing type declarations, dual-package hazards, unpinned npm deps, and missing engine constraints.

**Why you should care:** Packaging issues hurt the consumer experience: missing types break TypeScript users, dual-package hazards silently break singleton state, and unpinned deps create reproducibility problems.

**Examples of issues you'll see:**

- An npm package with no `.d.ts` type declarations (`PKG002-missing-types`)
- A package exposing both CJS and ESM without a conditional exports map (`PKG003-dual-package-hazard`)
- A `package.json` with `*` or `latest` version ranges (`PKG004-unpinned-deps`)
- No `engines.node` field in `package.json` (`PKG005-engines-missing`)

---

## Performance (`performance`)

**What this catches:** Patterns that degrade runtime or bundle performance — oversized distribution bundles, top-level imports of heavyweight libraries, excess `Arc<Mutex<T>>` usage, and similar.

**Why you should care:** Performance regressions are often invisible until production. zuit catches them statically before they ship.

**Examples of issues you'll see:**

- A `dist/` directory over 1 MiB (`PERF001-bundle-size`)
- A top-level import of `lodash` or `moment` (`PERF002-heavy-import`)
- A Rust crate enabling `features = ["full"]` on a heavy async framework (`PERF001-heavy-default-features`)

---

## Soundness (`unsafe_soundness`)

**What this catches:** Rust-specific unsoundness patterns — `unsafe` blocks without a `# Safety` comment, `transmute` usage, raw pointers in public API signatures, FFI functions without safety documentation.

Rules: SOUND001 through SOUND006.

---

## Project health (`project_health`)

**What this catches:** Repository-level health signals — single-author bus factor, stale releases, missing changelogs, and commit staleness.

Rules: HEALTH001 through HEALTH005.

---

## CI / release (`ci_release`)

**What this catches:** Missing or incomplete CI configuration — no CI config at all, no MSRV test job, no Windows job, no `cargo-deny` job, no Dependabot config.

Rules: CI001 through CI005.

---

## Ecosystem (`ecosystem`)

**What this catches:** Rust-specific ecosystem compatibility issues — missing `no_std` support, hard-wired async runtime choices, missing `Send`/`Sync` bounds on public types, and fragmented feature graphs.

Rules: ECO001 through ECO004.

---

## API stability (`api_stability`)

**What this catches:** Public-API drift between releases — symbols removed without a major-version bump, function signatures whose arity changed in a minor release, and version numbers that disagree with their semver implications.

Rules: API001 through API003.

---

All ~105 rules across all dimensions are enabled by default. Browse the full list under [Rules reference](/rules/).

For how scores are calculated from findings, see [Severity and scoring](/concepts/severity-and-scoring).
