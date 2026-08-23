'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  classifyAgentHealth,
  normalizeHealthOverride,
  parseRetryAt,
} = require('../lib/collab/health.cjs');

test('rate-limit health classification recognizes provider-neutral failures', () => {
  const now = Date.parse('2026-07-22T12:00:00.000Z');
  const health = classifyAgentHealth('HTTP 429: Too many requests. Retry after 30 seconds.', {
    now,
  });
  assert.deepEqual(health, {
    code: 'rate-limited',
    message: 'Agent model runtime reported a rate limit.',
    source: 'automatic',
    retryAt: '2026-07-22T12:00:30.000Z',
    updatedAt: '2026-07-22T12:00:00.000Z',
  });
  assert.equal(classifyAgentHealth('Command completed successfully.', { now }), null);
});

test('retry parsing supports milliseconds, seconds, and minutes', () => {
  const now = Date.parse('2026-07-22T12:00:00.000Z');
  assert.equal(parseRetryAt('retry in 500 ms', now), '2026-07-22T12:00:00.500Z');
  assert.equal(parseRetryAt('retry after 2s', now), '2026-07-22T12:00:02.000Z');
  assert.equal(parseRetryAt('retry in 3 minutes', now), '2026-07-22T12:03:00.000Z');
});

test('operator health overrides are bounded and clearable', () => {
  const now = Date.parse('2026-07-22T12:00:00.000Z');
  assert.deepEqual(normalizeHealthOverride({
    code: 'rate-limited',
    message: 'Corrected by the operator.',
  }, now), {
    code: 'rate-limited',
    message: 'Corrected by the operator.',
    source: 'operator',
    retryAt: '',
    updatedAt: '2026-07-22T12:00:00.000Z',
  });
  assert.deepEqual(normalizeHealthOverride({ code: null }, now), {
    code: '',
    message: 'Operator cleared the rate-limit status for this session.',
    source: 'operator',
    cleared: true,
    retryAt: '',
    updatedAt: '2026-07-22T12:00:00.000Z',
  });
  assert.throws(() => normalizeHealthOverride({ code: 'offline' }, now), /rate-limited or null/);
});
