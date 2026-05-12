# zuit (Python)

Multi-language static analysis CLI — Python bindings via PyO3 + maturin.

## Installation

```bash
pip install zuit
```

## Usage

```python
import zuit
import json

# Analyse a project directory and parse the JSON report.
report = json.loads(zuit.analyze("/path/to/your/project"))
for finding in report["findings"]:
    print(f"{finding['rule_id']}: {finding['message']} ({finding['location']['file']})")

print(f"zuit version: {zuit.version()}")
```

## Command-line usage

After `pip install zuit`, the `zuit` command is on PATH:

```bash
pip install zuit
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
pip install maturin
maturin develop          # install into the current virtualenv
maturin build --release  # produce a wheel in target/wheels/
```
