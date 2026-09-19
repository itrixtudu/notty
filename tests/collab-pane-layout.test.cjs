'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveCollabTmuxTarget } = require('../lib/collab/tmux-target.cjs');

test('MCP tmux targets use exact active roster identities and reject channel names', () => {
  const session = { channel: 'lobby', agents: [{ id: 'id-a', identity: 'coder', tmuxTarget: 'collab-123-coder' }] };
  for (const name of ['coder', 'id-a', 'collab-123-coder']) {
    assert.equal(resolveCollabTmuxTarget(name, session), 'collab-123-coder');
  }
  assert.throws(() => resolveCollabTmuxTarget('lobby', session), /read_messages/);
  assert.throws(() => resolveCollabTmuxTarget('collab-other-coder', session), /Unknown/);
  assert.equal(resolveCollabTmuxTarget('coder', null, { coder: { target: 'legacy-coder' } }), 'legacy-coder');
  assert.equal(resolveCollabTmuxTarget('explicit:0.0', null), 'explicit:0.0');
});

test('Collab uses terminal split trees with stable divider ratios', async () => {
  const { buildChatLayout } = await import('../components/collab/chatLayout.js');
  const ids = ['channel', 'dev', 'coder', 'qa'];
  const layout = buildChatLayout(ids, 2);
  assert.equal(layout.direction, 'horizontal');
  assert.equal(layout.children.length, 2);
  assert.equal(layout.children[0].direction, 'vertical');
  const rowId = layout.children[0].id;
  const resized = buildChatLayout(ids, 2, 'grid', { [rowId]: [0.7, 0.3] });
  assert.deepEqual(resized.children[0].ratios, [0.7, 0.3]);
  assert.equal(buildChatLayout(ids, 0, 'lead-grid').children[0].id, 'channel');
  assert.equal(buildChatLayout([], 2), null);
});
