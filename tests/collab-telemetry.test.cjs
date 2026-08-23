'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  createTelemetryStore,
  stampChannelRecord,
} = require('../lib/collab/telemetry.cjs');

function createFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-collab-telemetry-'));
  const feedbackPath = path.join(root, 'collab', 'intragent', 'message_feedback.jsonl');
  const messages = [];
  const events = [];
  let session = {
    id: 'session-one',
    agents: [
      {
        id: 'reviewer-row',
        identity: 'reviewer',
        role: 'reviewer',
        runtime: 'agy',
        model: 'gemini-3.6-flash-medium',
        think: 'high',
      },
      {
        id: 'observer-row',
        identity: 'observer',
        role: 'observer',
        runtime: 'ollama',
        model: 'qwen3:4b',
        think: 'low',
      },
    ],
  };
  const store = createTelemetryStore({
    feedbackPath,
    getSession: () => session,
    findMessage: (channel, messageId) => messages.find(
      (message) => message.channel === channel && message.id === messageId,
    ) || null,
    forEachMessage: (visit) => messages.forEach(visit),
    eventHub: { emit: (type, data) => events.push({ type, data }) },
  });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return {
    events,
    feedbackPath,
    messages,
    store,
    setSession(value) {
      session = value;
    },
  };
}

test('channel records are stamped only from the active roster with legacy runtime mapping', () => {
  const session = {
    id: 'session-one',
    agents: [
      {
        id: 'agent-row',
        identity: 'observer',
        prompt: 'observer',
        runtime: 'ollama',
        model: 'qwen3:4b',
        think: 'low',
      },
    ],
  };
  const attributed = stampChannelRecord({
    id: 'message-one',
    kind: 'message',
    agent_id: 'observer',
  }, { session });

  assert.equal(attributed.schema_version, 2);
  assert.equal(attributed.session_id, 'session-one');
  assert.equal(attributed.session_agent_id, 'agent-row');
  assert.equal(attributed.author_type, 'agent');
  assert.deepEqual(attributed.author_snapshot, {
    role: 'observer',
    harness: 'codex',
    backend: 'ollama',
    model: 'qwen3:4b',
    think: 'low',
  });

  const human = stampChannelRecord({ agent_id: 'observer' }, {
    session,
    authorType: 'human',
  });
  assert.equal(human.author_type, 'human');
  assert.equal(human.session_id, null);
  assert.equal(human.author_snapshot, null);

  const unknown = stampChannelRecord({ agent_id: 'legacy-agent' }, { session });
  assert.equal(unknown.author_type, 'unknown');
  assert.equal(unknown.session_id, null);
});

test('feedback is append-only, idempotent, changeable, clearable, and viewer-specific', (t) => {
  const fixture = createFixture(t);
  const message = fixture.store.stamp({
    id: 'message-one',
    timestamp: '2026-07-22T00:00:00.000Z',
    kind: 'message',
    agent_id: 'reviewer',
    channel: 'lobby',
    to: 'all',
    body: 'review complete',
  });
  fixture.messages.push(message);

  const first = fixture.store.rate({
    channel: 'lobby',
    messageId: message.id,
    operator: 'alice',
    rating: 'helpful',
  });
  assert.equal(first.changed, true);
  assert.equal(first.feedback.viewerRating, 'helpful');
  assert.equal(first.feedback.helpfulPercentage, 100);

  const duplicate = fixture.store.rate({
    channel: 'lobby',
    messageId: message.id,
    operator: 'alice',
    rating: 'helpful',
  });
  assert.equal(duplicate.changed, false);

  fixture.store.rate({
    channel: 'lobby',
    messageId: message.id,
    operator: 'bob',
    rating: 'unhelpful',
  });
  const changed = fixture.store.rate({
    channel: 'lobby',
    messageId: message.id,
    operator: 'alice',
    rating: 'unhelpful',
  });
  assert.deepEqual(changed.feedback, {
    helpful: 0,
    unhelpful: 2,
    rated: 2,
    helpfulRatio: 0,
    helpfulPercentage: 0,
    viewerRating: 'unhelpful',
    operatorVote: 'unhelpful',
  });

  const cleared = fixture.store.rate({
    channel: 'lobby',
    messageId: message.id,
    operator: 'alice',
    rating: null,
  });
  assert.equal(cleared.feedback.viewerRating, null);
  assert.equal(cleared.feedback.unhelpful, 1);

  const lines = fs.readFileSync(fixture.feedbackPath, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(lines.length, 4);
  assert.equal(lines.at(-1).tombstone, true);
  assert.equal(lines.at(-1).rating, null);
  assert.equal(fixture.events.length, 4);
  assert.ok(fixture.events.every((event) => event.type === 'message.feedback'));

  const alice = fixture.store.enrich([message], 'alice')[0].feedback;
  const bob = fixture.store.enrich([message], 'bob')[0].feedback;
  assert.equal(alice.viewerRating, null);
  assert.equal(bob.viewerRating, 'unhelpful');
  assert.equal(bob.operatorVote, 'unhelpful');
});

test('session and lifetime stats count only stamped agent messages and preserve exact ratings', (t) => {
  const fixture = createFixture(t);
  const first = fixture.store.stamp({
    id: 'first',
    kind: 'message',
    agent_id: 'reviewer',
    channel: 'lobby',
  });
  const direct = fixture.store.stamp({
    id: 'direct',
    kind: 'message',
    agent_id: 'reviewer',
    channel: 'lobby',
    to: 'coordinator',
  });
  const join = fixture.store.stamp({
    id: 'join',
    kind: 'join',
    agent_id: 'reviewer',
    channel: 'lobby',
  });
  const human = fixture.store.stamp({
    id: 'human',
    kind: 'message',
    agent_id: 'operator',
    channel: 'lobby',
  }, { authorType: 'human' });
  const legacy = {
    id: 'legacy',
    kind: 'message',
    agent_id: 'reviewer',
    channel: 'lobby',
  };
  fixture.messages.push(first, direct, join, human, legacy);

  fixture.store.rate({
    channel: 'lobby',
    messageId: first.id,
    operator: 'alice',
    rating: 'helpful',
  });
  fixture.store.rate({
    channel: 'lobby',
    messageId: first.id,
    operator: 'bob',
    rating: 'unhelpful',
  });

  const sessionStats = fixture.store.stats('session');
  assert.equal(sessionStats.scope, 'session');
  assert.equal(sessionStats.sessionId, 'session-one');
  assert.equal(sessionStats.rows.length, 1);
  assert.equal(sessionStats.rows[0].messages, 2);
  assert.equal(sessionStats.rows[0].harness, 'agy');
  assert.equal(sessionStats.rows[0].backend, 'default');
  assert.equal(sessionStats.rows[0].runtime, 'agy');
  assert.equal(sessionStats.rows[0].sessionAgentId, 'reviewer-row');
  assert.equal(sessionStats.totals.helpful, 1);
  assert.equal(sessionStats.totals.unhelpful, 1);
  assert.equal(sessionStats.totals.helpfulRatio, 0.5);
  assert.equal(sessionStats.totals.helpfulPercentage, 50);

  fixture.setSession({
    id: 'session-two',
    agents: [{
      id: 'observer-row',
      identity: 'observer',
      role: 'observer',
      harness: 'codex',
      backend: 'ollama',
      model: 'qwen3:4b',
      think: 'low',
    }],
  });
  fixture.messages.push(fixture.store.stamp({
    id: 'later',
    kind: 'message',
    agent_id: 'observer',
    channel: 'lobby',
  }));

  assert.equal(fixture.store.stats('session').totals.messages, 1);
  const lifetime = fixture.store.stats('lifetime');
  assert.equal(lifetime.sessionId, null);
  assert.equal(lifetime.totals.messages, 3);
  assert.deepEqual(lifetime.rows.map((row) => row.role), ['observer', 'reviewer']);
  assert.equal(lifetime.rows.find((row) => row.role === 'observer').runtime, 'ollama');

  assert.equal(fixture.store.clear(), 1);
  assert.equal(fs.existsSync(fixture.feedbackPath), false);
  assert.equal(fixture.store.stats('lifetime').totals.rated, 0);
});

test('feedback rejects invalid ratings, missing records, and unattributed messages', (t) => {
  const fixture = createFixture(t);
  const attributed = fixture.store.stamp({
    id: 'attributed',
    kind: 'message',
    agent_id: 'reviewer',
    channel: 'lobby',
  });
  fixture.messages.push(attributed, {
    id: 'legacy',
    kind: 'message',
    agent_id: 'reviewer',
    channel: 'lobby',
  });

  assert.throws(() => fixture.store.rate({
    channel: 'lobby',
    messageId: attributed.id,
    operator: 'alice',
    rating: 'maybe',
  }), /rating must be helpful/);
  assert.throws(() => fixture.store.rate({
    channel: 'lobby',
    messageId: 'missing',
    operator: 'alice',
    rating: 'helpful',
  }), /message not found/);
  assert.throws(() => fixture.store.rate({
    channel: 'lobby',
    messageId: 'legacy',
    operator: 'alice',
    rating: 'helpful',
  }), /attributed agent messages/);
});
