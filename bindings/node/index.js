// index.js — napi-rs loader for the zuit Node.js binding.
// This file is a hand-written stub; `napi build` will generate a
// platform-specific `.node` file alongside it at build time.
'use strict';

const { existsSync, readdirSync } = require('fs');
const { join } = require('path');

// Try to load the pre-built platform binary produced by `napi build`.
function loadBinding() {
  const candidates = [
    join(__dirname, 'zuit_node.node'),
    // napi-rs optional-dependency layout (npm platform packages):
    ...readdirSync(__dirname)
      .filter(f => f.startsWith('zuit.') && f.endsWith('.node'))
      .map(f => join(__dirname, f)),
  ];

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return require(candidate); // eslint-disable-line global-require
    }
  }

  throw new Error(
    'zuit: no pre-built binary found. ' +
      'Run `napi build --platform --release` to build from source.'
  );
}

module.exports = loadBinding();
