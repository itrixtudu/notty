'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const { spawnSync } = require('node:child_process');

const project = path.resolve(__dirname, '..');

function loadConfig(origins = '') {
  const configPath = require.resolve('../next.config.js');
  const previous = process.env.NOTTY_ALLOWED_DEV_ORIGINS;
  if (origins) {
    process.env.NOTTY_ALLOWED_DEV_ORIGINS = origins;
  } else {
    delete process.env.NOTTY_ALLOWED_DEV_ORIGINS;
  }
  delete require.cache[configPath];
  try {
    return require(configPath);
  } finally {
    delete require.cache[configPath];
    if (previous === undefined) {
      delete process.env.NOTTY_ALLOWED_DEV_ORIGINS;
    } else {
      process.env.NOTTY_ALLOWED_DEV_ORIGINS = previous;
    }
  }
}

test('development origins default to loopback and accept exact configured hosts', () => {
  assert.deepEqual(loadConfig().allowedDevOrigins, ['localhost', '127.0.0.1', '[::1]']);
  assert.deepEqual(
    loadConfig('review.example.test,172.17.0.3,review.example.test').allowedDevOrigins,
    ['localhost', '127.0.0.1', '[::1]', 'review.example.test', '172.17.0.3'],
  );
});

test('development origins reject schemes, ports, paths, and wildcards', () => {
  for (const value of [
    'http://localhost',
    'localhost:3000',
    'review.example.test/path',
    '*.example.test',
  ]) {
    const result = spawnSync(process.execPath, ['-e', "require('./next.config.js')"], {
      cwd: project,
      encoding: 'utf8',
      env: { ...process.env, NOTTY_ALLOWED_DEV_ORIGINS: value },
    });
    assert.notEqual(result.status, 0, value);
    assert.match(result.stderr, /exact hostnames or IP addresses/, value);
  }
});

test('managed policy review page is explicitly no-store', async () => {
  const rules = await loadConfig().headers();
  assert.deepEqual(rules, [{
    source: '/policy-review',
    headers: [
      { key: 'Cache-Control', value: 'no-store' },
      { key: 'Referrer-Policy', value: 'no-referrer' },
      { key: 'X-Content-Type-Options', value: 'nosniff' },
    ],
  }]);
});
