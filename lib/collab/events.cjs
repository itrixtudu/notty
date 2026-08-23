'use strict';

const { randomUUID } = require('crypto');

function createEventHub(options = {}) {
  const clients = new Map();
  const historyLimit = Number.isInteger(options.historyLimit) ? options.historyLimit : 200;
  const history = [];

  function emit(type, data) {
    const event = {
      id: randomUUID(),
      type,
      timestamp: new Date().toISOString(),
      data,
    };
    history.push(event);
    if (history.length > historyLimit) {
      history.splice(0, history.length - historyLimit);
    }
    const payload = `id: ${event.id}\nevent: ${type}\ndata: ${JSON.stringify(event)}\n\n`;
    for (const [id, client] of clients) {
      try {
        client.write(payload);
      } catch (_error) {
        clients.delete(id);
      }
    }
    return event;
  }

  function attach(req, res) {
    const id = randomUUID();
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    res.write(': collab events connected\n\n');
    const lastEventId = String(req.headers['last-event-id'] || '');
    if (lastEventId) {
      const offset = history.findIndex((entry) => entry.id === lastEventId);
      for (const event of offset === -1 ? [] : history.slice(offset + 1)) {
        res.write(`id: ${event.id}\nevent: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`);
      }
    }
    clients.set(id, res);
    const cleanup = () => clients.delete(id);
    req.on('close', cleanup);
    req.on('error', cleanup);
  }

  const keepAlive = setInterval(() => {
    for (const client of clients.values()) {
      client.write(': keepalive\n\n');
    }
  }, 15000);
  keepAlive.unref();

  return {
    emit,
    attach,
    history: () => history.slice(),
    close() {
      clearInterval(keepAlive);
      for (const client of clients.values()) {
        client.end();
      }
      clients.clear();
    },
  };
}

module.exports = { createEventHub };
