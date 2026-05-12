# zuit (Node.js)

Multi-language static analysis CLI — Node.js bindings via napi-rs.

## Installation

```bash
npm install zuit
```

## Usage

```js
const { analyze, version } = require('zuit');
const report = JSON.parse(analyze('/path/to/your/project'));
report.findings.forEach(f => {
  console.log(`${f.rule_id}: ${f.message} (${f.location.file})`);
});
console.log(`zuit version: ${version()}`);
```

## Command-line usage

After `npm install -g zuit`, the `zuit` command is on PATH:

```bash
npm install -g zuit
zuit analyze .
zuit analyze . --format json
```

The `ZUIT_BIN` environment variable overrides binary lookup — useful for
pointing at a locally built binary:

```bash
ZUIT_BIN=./target/release/zuit zuit analyze .
```

## Building from source

```bash
npm install
npm run build        # release build
npm run build:debug  # debug build
```

Requires the Rust toolchain and `@napi-rs/cli` (installed as a dev dependency).
