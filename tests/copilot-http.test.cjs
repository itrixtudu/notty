const assert = require('node:assert/strict');
const test = require('node:test');

async function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function createOperations() {
  const bindings = new Map();
  const subscribers = new Set();
  return {
    list: () => [...bindings.values()],
    get: (id) => bindings.get(id),
    catalog: () => ({ defaults: { runtime: 'ollama' } }),
    create(input) {
      if (!input.sourceTerminalUuid) {
        throw Object.assign(new Error('sourceTerminalUuid is required'), {
          statusCode: 422,
          code: 'COPILOT_SOURCE_REQUIRED'
        });
      }
      const binding = { id: 'binding-one', ...input };
      bindings.set(binding.id, binding);
      return binding;
    },
    update(id, input) {
      const binding = { ...bindings.get(id), ...input };
      bindings.set(id, binding);
      return binding;
    },
    stop(id) {
      bindings.delete(id);
    },
    ask(id, input) {
      return { copilot: bindings.get(id), message: input };
    },
    renew(id, input) {
      return {
        copilot: bindings.get(id),
        lease: { purpose: input.target || 'visible', status: 'active' }
      };
    },
    approveProposal(id, proposalId) {
      return { copilot: bindings.get(id), proposal: { id: proposalId, status: 'approved' } };
    },
    subscribe(listener) {
      subscribers.add(listener);
      return () => subscribers.delete(listener);
    },
    emit(event) {
      for (const listener of subscribers) {
        listener(event);
      }
    }
  };
}

test('copilot HTTP routes expose lifecycle operations and structured validation errors', async (t) => {
  const express = (await import('express')).default;
  const { registerCopilotHttpRoutes } = await import('../lib/copilotHttpApi.js');
  const app = express();
  const operations = createOperations();
  registerCopilotHttpRoutes(app, { operations });
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}/api/copilots`;

  const invalid = await fetch(baseUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}'
  });
  assert.equal(invalid.status, 422);
  assert.deepEqual(await invalid.json(), {
    error: 'sourceTerminalUuid is required',
    code: 'COPILOT_SOURCE_REQUIRED'
  });

  const createdResponse = await fetch(baseUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sourceTerminalUuid: 'source-one', runtime: 'ollama' })
  });
  assert.equal(createdResponse.status, 201);
  const created = (await createdResponse.json()).copilot;
  assert.equal(created.id, 'binding-one');

  const list = await fetch(baseUrl).then((response) => response.json());
  assert.equal(list.copilots.length, 1);
  assert.equal(list.catalog.defaults.runtime, 'ollama');

  const patched = await fetch(`${baseUrl}/${created.id}`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ observationMode: 'active' })
  }).then((response) => response.json());
  assert.equal(patched.copilot.observationMode, 'active');

  const asked = await fetch(`${baseUrl}/${created.id}/ask`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ question: 'What failed?', selectedText: 'kubectl get pods' })
  });
  assert.equal(asked.status, 202);
  assert.equal((await asked.json()).message.question, 'What failed?');

  const approved = await fetch(`${baseUrl}/${created.id}/proposals/proposal-one/approve`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}'
  }).then((response) => response.json());
  assert.equal(approved.proposal.status, 'approved');

  const removed = await fetch(`${baseUrl}/${created.id}`, { method: 'DELETE' });
  assert.equal(removed.status, 204);
  assert.equal(operations.list().length, 0);
});

test('copilot HTTP event stream forwards manager events and releases its subscription', async (t) => {
  const express = (await import('express')).default;
  const { registerCopilotHttpRoutes } = await import('../lib/copilotHttpApi.js');
  const app = express();
  const operations = createOperations();
  operations.create({ sourceTerminalUuid: 'source-one', runtime: 'ollama' });
  registerCopilotHttpRoutes(app, { operations });
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();
  const controller = new AbortController();
  const response = await fetch(`http://127.0.0.1:${port}/api/copilots/events`, {
    signal: controller.signal
  });
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type'), /text\/event-stream/);

  operations.emit({
    id: 'event-one',
    type: 'copilot.feedback',
    bindingId: 'binding-one'
  });
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let received = '';
  while (!received.includes('event-one')) {
    const chunk = await reader.read();
    assert.equal(chunk.done, false);
    received += decoder.decode(chunk.value, { stream: true });
  }
  assert.match(received, /event: copilot/);
  assert.match(received, /"type":"copilot.feedback"/);
  assert.match(received, /"copilot":\{"id":"binding-one"/);
  controller.abort();
  await reader.cancel().catch(() => {});
});
