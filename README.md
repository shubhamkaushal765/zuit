# zuit

Static code analysis for Rust, Python, and JavaScript/TypeScript with structured, multi-dimensional findings.

## Quick start

```bash
git clone <repo>
cd zuit
cargo build --workspace
cargo run -p zuit -- analyze ./fixtures/rust/unhealthy --format terminal
```

## Features

- Five quality dimensions: Maintainability, Security, Complexity, Documentation, TestSmell.
- Three languages via native Rust parsers: `syn` (Rust), `rustpython-parser` (Python), `oxc_parser` (JS/TS — `.js`/`.mjs`/`.cjs`/`.jsx`/`.ts`/`.mts`/`.cts`/`.tsx`). Go is deferred (no maintained pure-Rust parser).
- Cross-language analyzers via a normalized `SemanticIndex`; language-specific analyzers ship in their language crate.
- JSON, SARIF 2.1.0, terminal (with optional OSC-8 hyperlinks), and Markdown output. A–F grades per dimension. CWE / OWASP taxonomy on every finding (filterable via `--cwe` / `--owasp`).
- Local scan-history dashboard: `zuit show` runs a tiny HTTP server with Overview / Scans / Findings / Trends / Diff / Config tabs.

## Extensibility

- **New language**: add a `zuit-lang-X` crate, implement `Language`, register in the CLI's `build_registry()`. No analyzer changes needed.
- **New analyzer**: add to `zuit-analyzers` (cross-language) or your language crate (language-specific), implement `Analyzer`, register. No language changes needed.

## Development

```bash
cargo xtask ci          # fmt-check + clippy + test
just ci                 # equivalent
```

## License

MIT — see [LICENSE](./LICENSE).
