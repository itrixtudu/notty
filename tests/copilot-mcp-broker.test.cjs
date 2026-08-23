const assert = require('node:assert/strict');
const test = require('node:test');

async function createClient(url, token) {
  const [clientModule, transportModule] = await Promise.all([
    import('@modelcontextprotocol/sdk/client/index.js'),
    import('@modelcontextprotocol/sdk/client/streamableHttp.js')
  ]);
  const client = new clientModule.Client({
    name: 'notty-copilot-broker-test',
    version: '1.0.0'
  });
  const transport = new transportModule.StreamableHTTPClientTransport(new URL(url), {
    requestInit: {
      headers: { Authorization: `Bearer ${token}` }
    }
  });
  await client.connect(transport);
  return { client, transport };
}

test('copilot MCP broker isolates binding roles and command authority', async (t) => {
  const { startCopilotMcpBroker } = await import('../lib/copilotMcpBroker.js');
  const tokens = {
    visible: 'visible-secret-token',
    analyzer: 'analyzer-secret-token'
  };
  const calls = [];
  const binding = {
    id: 'binding-one',
    sourceTerminalUuid: 'source-one',
    leases: {
      visible: { id: 'visible-lease', status: 'active' },
      analyzer: { id: 'analyzer-lease', status: 'active' }
    }
  };
  const operations = {
    get(id) {
      if (id !== binding.id) {
        const error = new Error('not found');
        error.statusCode = 404;
        throw error;
      }
      return structuredClone(binding);
    },
    authorizeBroker(id, { role, token }) {
      this.get(id);
      if (tokens[role] !== token) {
        const error = new Error('invalid broker token');
        error.statusCode = 403;
        throw error;
      }
    },
    getEventSnapshot({ bindingId, limit }) {
      calls.push({ operation: 'events', bindingId, limit });
      return [{ type: 'terminal.command', bindingId }];
    },
    postFeedback(id, input) {
      calls.push({ operation: 'feedback', id, input });
      return { feedback: input };
    },
    submitCommand(id, input) {
      calls.push({ operation: 'command', id, input });
      return { proposal: { command: input.command, status: 'pending' } };
    }
  };

  const broker = await startCopilotMcpBroker({ operations });
  t.after(async () => broker.close());

  await assert.rejects(
    createClient(broker.urlFor(binding.id, 'visible', 'codex'), 'wrong-token'),
    /403|invalid broker token/i
  );
  await assert.rejects(
    createClient(broker.urlFor(binding.id, 'analyzer', 'ollama'), tokens.visible),
    /403|invalid broker token/i
  );

  const visible = await createClient(
    broker.urlFor(binding.id, 'visible', 'codex'),
    tokens.visible
  );
  t.after(async () => visible.client.close());
  const visibleTools = await visible.client.listTools();
  assert.ok(visibleTools.tools.some((tool) => tool.name === 'submit_command'));
  const commandResult = await visible.client.callTool({
    name: 'submit_command',
    arguments: { command: 'kubectl get pods' }
  });
  assert.equal(commandResult.isError, undefined);
  assert.deepEqual(calls.at(-1), {
    operation: 'command',
    id: binding.id,
    input: {
      command: 'kubectl get pods',
      sourceTerminalUuid: 'source-one',
      source: 'agent-mcp'
    }
  });

  const analyzer = await createClient(
    broker.urlFor(binding.id, 'analyzer', 'ollama'),
    tokens.analyzer
  );
  t.after(async () => analyzer.client.close());
  const analyzerTools = await analyzer.client.listTools();
  assert.equal(analyzerTools.tools.some((tool) => tool.name === 'submit_command'), false);
  const feedbackResult = await analyzer.client.callTool({
    name: 'post_feedback',
    arguments: { body: 'The current kubectl context may be wrong.', kind: 'tip' }
  });
  assert.equal(feedbackResult.isError, undefined);
  assert.deepEqual(calls.at(-1), {
    operation: 'feedback',
    id: binding.id,
    input: {
      body: 'The current kubectl context may be wrong.',
      kind: 'tip',
      source: 'analyzer'
    }
  });

  const agyUrl = broker.urlFor(binding.id, 'visible', 'agy', tokens.visible);
  assert.match(agyUrl, /\/visible\/sse\?access_token=/);
});
