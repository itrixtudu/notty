'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const test = require('node:test');

function createResponse() {
  return {
    status: null,
    headers: null,
    chunks: [],
    ended: false,
    writeHead(status, headers) {
      this.status = status;
      this.headers = headers;
    },
    write(chunk) {
      this.chunks.push(String(chunk));
    },
    end() {
      this.ended = true;
    },
  };
}

test('event hub trims history and replays events after Last-Event-ID', () => {
  const { createEventHub } = require('../lib/collab/events.cjs');
  const hub = createEventHub({ historyLimit: 2 });
  const first = hub.emit('session.changed', { sequence: 1 });
  const second = hub.emit('agent.status', { sequence: 2 });
  const third = hub.emit('channel.message', { sequence: 3 });
  const req = new EventEmitter();
  req.headers = { 'last-event-id': second.id };
  const res = createResponse();

  assert.deepEqual(hub.history().map((event) => event.id), [second.id, third.id]);
  hub.attach(req, res);

  assert.equal(res.status, 200);
  assert.equal(res.headers['Content-Type'], 'text/event-stream; charset=utf-8');
  assert.match(res.chunks.join(''), /collab events connected/);
  assert.doesNotMatch(res.chunks.join(''), new RegExp(first.id));
  assert.doesNotMatch(res.chunks.join(''), new RegExp(second.id));
  assert.match(res.chunks.join(''), new RegExp(third.id));

  const fourth = hub.emit('session.changed', { sequence: 4 });
  assert.match(res.chunks.join(''), new RegExp(fourth.id));
  req.emit('close');
  const chunksAfterClose = res.chunks.length;
  hub.emit('session.changed', { sequence: 5 });
  assert.equal(res.chunks.length, chunksAfterClose);

  hub.close();
});

test('event hub removes failed clients and closes attached responses', () => {
  const { createEventHub } = require('../lib/collab/events.cjs');
  const hub = createEventHub();
  const failingReq = new EventEmitter();
  failingReq.headers = {};
  const failingRes = createResponse();
  hub.attach(failingReq, failingRes);
  failingRes.write = () => {
    throw new Error('closed stream');
  };

  assert.doesNotThrow(() => hub.emit('agent.status', {}));

  const liveReq = new EventEmitter();
  liveReq.headers = {};
  const liveRes = createResponse();
  hub.attach(liveReq, liveRes);
  hub.close();
  assert.equal(liveRes.ended, true);
});
