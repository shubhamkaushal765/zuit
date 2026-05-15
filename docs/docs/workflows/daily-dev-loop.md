---
title: Your daily dev loop
sidebar_label: Daily dev loop
description: Get zuit findings as you type — watch mode, editor LSP, dashboard tab, and inline suppression.
---

# Your daily dev loop

You want findings as you type, not as a CI surprise.

```bash
zuit watch ./src
```

## Why this works

Watch mode re-runs analysis only on files you have changed, using zuit's incremental cache, so you see findings within a second of saving. The cache is the same one `zuit analyze` maintains between runs — nothing extra to configure. See the [`zuit watch` reference](/cli/watch) for the full flag list.

## Real-world variants

### See findings inline in your editor

If your editor supports LSP, start the zuit language server instead of running a terminal watcher. Findings appear as underlines and gutter icons without any terminal window.

```bash
zuit lsp
```

Configure your editor to launch this command on startup. See [LSP integration](/integrations/lsp) for VS Code, Neovim, Helix, and Zed setup snippets.

### Open the dashboard tab

When something looks off, open the browser dashboard to drill into the Findings list or Heatmap for the current scan.

```bash
zuit show
```

This starts a local server and opens the dashboard in your browser. Use the Findings tab to filter by dimension or severity, and the Heatmap tab to spot files with the most accumulated issues. See [`zuit show`](/cli/show) for the full tab reference.

### Silence a false positive inline

When a finding is intentional or irrelevant, suppress it with a comment on the line above the flagged code.

For Rust, JavaScript, and TypeScript:

```rust
// zuit: ignore SEC001
let api_key = std::env::var("API_KEY").unwrap();
```

For Python:

```python
# zuit: ignore SEC001
api_key = os.environ["API_KEY"]
```

To suppress all findings in a file, add the comment at the top of the file:

```rust
// zuit: ignore-file
```

See [Suppression](/rules/suppression) for all supported comment forms and the `ignore-file` directive.

### Block bad commits locally

Install a git pre-commit hook so zuit runs before every commit and blocks the commit if any finding at `medium` severity or above is found.

```bash
zuit install-hook
```

The hook runs `zuit analyze --fail-on medium` automatically. See [`zuit install-hook`](/cli/install-hook) to customise the threshold or combine it with a baseline.

## What's next

[Gate CI on quality](/workflows/gate-ci) — fail builds when findings cross a severity threshold.
