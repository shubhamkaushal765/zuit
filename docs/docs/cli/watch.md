---
title: zuit watch
description: Automatically re-scan your code whenever a file is saved, and see findings immediately in the terminal.
---

:::tip Looking for the recipe?
See [Workflows → Your daily dev loop](/workflows/daily-dev-loop) for the task-driven guide. This page is the reference.
:::

# zuit watch

```
zuit watch [PATH]
```

Use `zuit watch` to get instant feedback as you code. It monitors `<PATH>` for saved changes and re-runs analysis automatically, printing any findings to the terminal. Only the files you changed are re-scanned, so results appear quickly. Press Ctrl-C to stop.

## When to use this

- Get immediate quality feedback while editing, without switching context.
- Catch new findings the moment they are introduced rather than at commit time.
- Use alongside your editor as a lightweight alternative to the LSP server.

## Arguments

| Argument | Description                                         |
| -------- | --------------------------------------------------- |
| `[PATH]` | Root path to watch. Defaults to `.`.                |

## Behaviour

- Picks up changes across all supported file types under `<PATH>` on all major operating systems.
- Rapid saves (such as editor auto-save) are grouped together so only one re-scan fires per burst.
- Only files that have actually changed are re-scanned; unmodified files are skipped automatically.
- Findings are printed to the terminal after each triggered run.

## Flags

| Flag              | Default | Description                                                              |
| ----------------- | ------- | ------------------------------------------------------------------------ |
| `--config <FILE>` | auto    | Path to a `zuit.toml`. Overrides the default upward search.              |
| `--no-color`      | off     | Disable ANSI colour in terminal output.                                  |
| `--no-cache`      | off     | Disable the incremental file-hash cache for each triggered run.          |
| `-h`, `--help`    |         | Print help.                                                              |

## Example

```bash
zuit watch ./src
```

## See also

- [`zuit analyze`](/cli/analyze)
- [`zuit lsp`](/cli/lsp)
