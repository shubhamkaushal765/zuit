#!/usr/bin/env node
/**
 * Command-line entry point for the zuit npm package.
 *
 * Locates the native zuit binary and forwards all arguments to it.
 * Lookup order:
 *   1. process.env.ZUIT_BIN (if set).
 *   2. A bundled zuit[.exe] binary in the package root (future binary wheels).
 *   3. zuit[.exe] on PATH via spawnSync OS resolution.
 *   4. Exit 1 with a human-readable message if none found.
 *
 * Uses only Node.js built-in modules (child_process, fs, os, path).
 */

'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const IS_WIN = os.platform() === 'win32';
const BIN_NAME = IS_WIN ? 'zuit.exe' : 'zuit';

/**
 * Attempt to find an executable zuit binary.
 * Returns the path string, or null if not found.
 */
function findBinary() {
  // 1. Environment override.
  const envBin = process.env.ZUIT_BIN;
  if (envBin) {
    return envBin;
  }

  // 2. Bundled binary: package root is one level above this script's __dirname.
  const pkgRoot = path.join(__dirname, '..');
  const bundled = path.join(pkgRoot, BIN_NAME);
  try {
    fs.accessSync(bundled, fs.constants.X_OK);
    return bundled;
  } catch (_) {
    // Not present — fall through.
  }

  // 3. PATH resolution: let the OS find it.  We do this by running a no-op
  //    spawnSync with the bare name; if the OS resolves it, result.pid is set
  //    and result.error is absent.  We use shell:false so ENOENT means "not
  //    found on PATH".
  const probe = spawnSync(BIN_NAME, ['--version'], { stdio: 'pipe' });
  if (!probe.error) {
    // Binary was found and ran (exit code doesn't matter for probe purposes).
    return BIN_NAME;
  }

  return null;
}

const binary = findBinary();

if (!binary) {
  process.stderr.write(
    'zuit binary not found.\n' +
    'Install the native binary via one of:\n' +
    '  cargo install zuit\n' +
    '  npm install -g zuit  (once binary wheels are published)\n'
  );
  process.exit(1);
}

const result = spawnSync(binary, process.argv.slice(2), { stdio: 'inherit' });
process.exit(result.status != null ? result.status : 1);
