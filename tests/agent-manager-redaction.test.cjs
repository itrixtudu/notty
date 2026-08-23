'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

test('terminal context redaction covers compound environment keys and auth headers', async () => {
  const { redactTerminalSecrets } = await import('../lib/agentManager.js');
  const redacted = redactTerminalSecrets([
    'OPENAI_API_KEY=provider-secret',
    'export KUBERNETES_AUTH_TOKEN = cluster-secret',
    'Authorization: Bearer header-secret',
    'kubectl get pods --token cluster-token',
    'ordinary output remains visible',
  ].join('\n'));

  assert.doesNotMatch(redacted, /provider-secret|cluster-secret|header-secret|cluster-token/);
  assert.match(redacted, /OPENAI_API_KEY=\[redacted\]/);
  assert.match(redacted, /KUBERNETES_AUTH_TOKEN = \[redacted\]/);
  assert.match(redacted, /Authorization: Bearer \[redacted\]/);
  assert.match(redacted, /--token \[redacted\]/);
  assert.match(redacted, /ordinary output remains visible/);
});
