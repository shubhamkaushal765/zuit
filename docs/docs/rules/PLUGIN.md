---
title: Plugin Rule IDs
sidebar_label: PLUGIN
---
# PLUGIN — Operational Plugin Rule IDs

**Last reviewed:** 2026-05-10

These rule IDs are emitted by `zuit-plugins` when a third-party plugin
encounters an operational problem (missing binary, spawn failure, timeout,
etc.). They are **emitted-but-unregistered**: they appear in findings like any
other rule but have no static registration in the rule registry. This mirrors
the precedent set by `cargo_clippy`, `cargo_audit`, and other external-tool
adapters.

The `<name>` placeholder is the installed plugin name (e.g. `acme-zig`).

---

## Rule table

| Rule ID | Severity | When emitted |
| ------- | -------- | ------------ |
| `PLUGIN/<name>-binary-missing` | Info | argv[0] is not found in the plugin directory or `$PATH` at spawn time |
| `PLUGIN/<name>-spawn-failed` | High | The OS rejected the `posix_spawn` / `CreateProcess` call |
| `PLUGIN/<name>-timeout` | Medium | The subprocess ran past `timeout_seconds` (default 60 s) |
| `PLUGIN/<name>-output-too-large` | Medium | Stdout exceeded `max_output_bytes` (default 32 MiB) |
| `PLUGIN/<name>-output-parse-error` | Medium | Stdout did not parse as the format declared by `output` in the manifest |
| `PLUGIN/<name>-manifest-error` | Info | The manifest failed validation at startup; plugin is skipped for this scan |

---

## `PLUGIN/<name>-binary-missing`

**Severity:** Info — the scan continues; findings from this plugin are absent.

**Cause:** The first element of `command` in `zuit-plugin.toml` could not
be resolved relative to the plugin directory or via `$PATH`.

**Fix:** Verify the executable exists in the plugin directory, is executable
(`chmod +x`), or is available on `$PATH`. Re-run `zuit add-analyzer` if
the plugin was mis-installed.

---

## `PLUGIN/<name>-spawn-failed`

**Severity:** High — indicates a system-level failure (permissions, OOM, etc.).

**Cause:** The OS returned an error when zuit tried to spawn the
subprocess. The error message is included in the finding's `details` field.

**Fix:** Check OS permissions on the binary. Check system resource limits
(`ulimit -u`). Inspect the `details` field for the raw OS error.

---

## `PLUGIN/<name>-timeout`

**Severity:** Medium — the plugin produced no findings for this scan.

**Cause:** The subprocess was still running after `timeout_seconds` (manifest
field; default 60 s). zuit kills the process and emits this finding.

**Fix:** Increase `timeout_seconds` in the manifest if the plugin legitimately
needs more time. Or profile the plugin for performance regressions.

---

## `PLUGIN/<name>-output-too-large`

**Severity:** Medium — findings beyond the cap are discarded.

**Cause:** Stdout exceeded `max_output_bytes` (manifest field; default 32 MiB).
zuit truncates the stream and emits this finding; any partial last line is
discarded.

**Fix:** Increase `max_output_bytes` in the manifest. Or reduce plugin
verbosity / scope.

---

## `PLUGIN/<name>-output-parse-error`

**Severity:** Medium — the plugin produced no usable findings.

**Cause:** The plugin's stdout could not be parsed as the format declared by
`output` in the manifest (`zuit-json` ndjson or `sarif`). The parse
error text is in `details`.

**Fix:** Run the plugin manually and verify its stdout matches the expected
format. Check for stray non-JSON lines (e.g. debug prints to stdout instead of
stderr).

---

## `PLUGIN/<name>-manifest-error`

**Severity:** Info — the plugin is skipped for the current scan.

**Cause:** `zuit-plugin.toml` failed schema validation at discovery time
(unknown field, invalid `name` pattern, empty `command`, etc.). The validation
error is in `details`.

**Fix:** Correct the manifest. Re-run `zuit list plugins` to confirm the
plugin is now discovered cleanly.

---

## Implementation

- Emitter: `crates/zuit-plugins/src/analyzer.rs`
- Manifest validation: `crates/zuit-plugins/src/manifest.rs`
- Spec: `docs/superpowers/specs/2026-05-09-custom-analyzer-plugins-design.md §6`
