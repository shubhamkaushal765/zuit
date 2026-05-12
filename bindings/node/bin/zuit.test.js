'use strict';
/**
 * Smoke tests for the zuit Node.js launcher (bin/zuit.js).
 *
 * Run with:
 *   node --test bindings/node/bin/zuit.test.js
 *
 * Uses only Node.js built-in test runner (node:test) and stdlib modules.
 * No devDependency changes required.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const LAUNCHER = path.resolve(__dirname, 'zuit.js');
const IS_WIN = os.platform() === 'win32';

/**
 * Write a small executable shell script (Unix) or batch file (Windows) to a
 * temporary directory.  Returns the path to the fake binary.
 */
function makeFakeBin(tmpDir, name, scriptLines) {
  if (IS_WIN) {
    const p = path.join(tmpDir, name + '.cmd');
    fs.writeFileSync(p, scriptLines.join('\r\n'));
    return p;
  }
  const p = path.join(tmpDir, name);
  fs.writeFileSync(p, '#!/bin/sh\n' + scriptLines.join('\n') + '\n');
  fs.chmodSync(p, 0o755);
  return p;
}

// ---------------------------------------------------------------------------
// Test 1: ZUIT_BIN env override is honoured
// ---------------------------------------------------------------------------
test('ZUIT_BIN env override is used', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'zuit-test-'));
  try {
    // Fake binary that exits 0 so the launcher can exec it successfully.
    const fake = makeFakeBin(tmp, 'fake-zuit', ['exit 0']);

    const result = spawnSync(
      process.execPath,
      [LAUNCHER],
      {
        env: { ...process.env, ZUIT_BIN: fake },
        stdio: 'pipe',
      }
    );

    // The fake binary exited 0; the launcher must forward that.
    assert.equal(result.status, 0, `expected exit 0, got ${result.status}; stderr: ${result.stderr.toString()}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Test 2: Missing binary path produces exit 1 and a helpful stderr message
// ---------------------------------------------------------------------------
test('missing binary produces exit 1 and stderr message', () => {
  // Remove ZUIT_BIN and point PATH to an empty dir so nothing is found.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'zuit-empty-'));
  try {
    const env = { ...process.env };
    delete env.ZUIT_BIN;
    // Redirect PATH to an empty directory so zuit is not on PATH.
    env.PATH = tmp;

    const result = spawnSync(
      process.execPath,
      [LAUNCHER],
      {
        env,
        stdio: 'pipe',
        // Run from the tmp dir so the relative bundled-binary lookup also misses.
        cwd: tmp,
      }
    );

    assert.equal(result.status, 1, `expected exit 1, got ${result.status}`);
    const stderr = result.stderr.toString();
    assert.ok(
      stderr.includes('zuit binary not found'),
      `stderr must contain "zuit binary not found"; got: ${stderr}`
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Test 3: Argument forwarding — fake binary echoes its argv
// ---------------------------------------------------------------------------
test('arguments are forwarded to the binary', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'zuit-args-'));
  try {
    // Fake binary that echoes all its arguments to stdout and exits 0.
    const fake = makeFakeBin(tmp, 'zuit-echo', [
      'echo "$@"',
    ]);

    const result = spawnSync(
      process.execPath,
      [LAUNCHER, 'analyze', '--format', 'json'],
      {
        env: { ...process.env, ZUIT_BIN: fake },
        stdio: 'pipe',
      }
    );

    const stdout = result.stdout.toString().trim();
    assert.ok(
      stdout.includes('analyze') && stdout.includes('--format') && stdout.includes('json'),
      `expected forwarded args in stdout; got: ${stdout}`
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
