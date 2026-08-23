'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');

const appRoot = path.resolve(__dirname, '..');

async function dockerModule() {
  return import(
    pathToFileURL(path.join(appRoot, 'lib/guardd/docker-client.js')).href
  );
}

function dockerFrame(stream, value) {
  const payload = Buffer.from(value, 'utf8');
  const header = Buffer.alloc(8);
  header[0] = stream;
  header.writeUInt32BE(payload.length, 4);
  return Buffer.concat([header, payload]);
}

function fakeLogRequest(chunks, statusCode = 200) {
  let requestOptions = null;
  let requestDestroyed = false;
  return {
    get requestOptions() {
      return requestOptions;
    },
    get requestDestroyed() {
      return requestDestroyed;
    },
    requestImpl(options, callback) {
      requestOptions = options;
      const request = new EventEmitter();
      request.destroy = () => {
        requestDestroyed = true;
      };
      request.end = () => {
        queueMicrotask(() => {
          const response = new PassThrough();
          response.statusCode = statusCode;
          response.headers = {
            'content-type': 'application/vnd.docker.raw-stream',
          };
          callback(response);
          for (const chunk of chunks) {
            if (!response.destroyed) {
              response.write(chunk);
            }
          }
          if (!response.destroyed) {
            response.end();
          }
        });
      };
      return request;
    },
  };
}

test('Docker logs decode split stdout/stderr frames and request a finite tail', async () => {
  const { DockerClient } = await dockerModule();
  const wire = Buffer.concat([
    dockerFrame(1, 'stdout one\n'),
    dockerFrame(2, 'stderr two\n'),
  ]);
  const fake = fakeLogRequest([
    wire.subarray(0, 3),
    wire.subarray(3, 11),
    wire.subarray(11, 19),
    wire.subarray(19),
  ]);
  const client = new DockerClient({
    requestImpl: fake.requestImpl,
    requestTimeoutMs: 100,
  });

  const tail = await client.containerLogs('container/id', {
    tailLines: 7,
    maxWireBytes: 1024,
    maxTextBytes: 1024,
  });

  assert.deepEqual(tail, {
    text: 'stdout one\nstderr two',
    truncated: false,
  });
  const requestUrl = new URL(fake.requestOptions.path, 'http://docker.local');
  assert.equal(requestUrl.pathname, '/v1.44/containers/container%2Fid/logs');
  assert.equal(requestUrl.searchParams.get('follow'), 'false');
  assert.equal(requestUrl.searchParams.get('stdout'), 'true');
  assert.equal(requestUrl.searchParams.get('stderr'), 'true');
  assert.equal(requestUrl.searchParams.get('tail'), '7');
  assert.equal(requestUrl.searchParams.get('timestamps'), 'false');
  assert.equal(fake.requestDestroyed, false);

  const empty = fakeLogRequest([]);
  const emptyClient = new DockerClient({
    requestImpl: empty.requestImpl,
    requestTimeoutMs: 100,
  });
  assert.deepEqual(await emptyClient.containerLogs('empty'), {
    text: '',
    truncated: false,
  });
});

test('Docker logs remain bounded across incomplete frames, lines, and UTF-8 bytes', async () => {
  const {
    DockerClient,
    sanitizeDockerRuntimeLogTail,
  } = await dockerModule();
  const fake = fakeLogRequest([dockerFrame(2, 'abcdefghijklmnop')]);
  const client = new DockerClient({
    requestImpl: fake.requestImpl,
    requestTimeoutMs: 100,
  });

  assert.deepEqual(
    await client.containerLogs('bounded', {
      tailLines: 4,
      maxWireBytes: 12,
      maxTextBytes: 8,
    }),
    { text: 'abcd', truncated: true },
  );
  assert.equal(fake.requestDestroyed, true);

  const sanitized = sanitizeDockerRuntimeLogTail(
    {
      text: 'drop\nTOKEN=super-secret\nlast\u001bline',
      truncated: false,
    },
    { maxLines: 2, maxBytes: 100 },
  );
  assert.deepEqual(sanitized, {
    text: 'TOKEN=[redacted]\nlast\ufffdline',
    truncated: true,
  });

  const sensitiveAssignments = sanitizeDockerRuntimeLogTail(
    [
      'OPENAI_API_KEY=sk-openai',
      'AWS_SECRET_ACCESS_KEY=aws-secret',
      'DATABASE_PASSWORD=db-secret',
      'NOTTY_OAUTH_CLIENT_SECRET=oauth-secret',
      'safe diagnostic',
    ].join('\n'),
    { maxLines: 10, maxBytes: 4096 },
  );
  assert.equal(
    sensitiveAssignments.text,
    [
      'OPENAI_API_KEY=[redacted]',
      'AWS_SECRET_ACCESS_KEY=[redacted]',
      'DATABASE_PASSWORD=[redacted]',
      'NOTTY_OAUTH_CLIENT_SECRET=[redacted]',
      'safe diagnostic',
    ].join('\n'),
  );
  assert.equal(sensitiveAssignments.truncated, false);
  assert.deepEqual(
    sanitizeDockerRuntimeLogTail({ text: '', truncated: false }),
    { text: '', truncated: false },
  );

  const utf8 = sanitizeDockerRuntimeLogTail('old\n\u00e9\u00e9\u00e9\u00e9', {
    maxLines: 4,
    maxBytes: 8,
  });
  assert.equal(utf8.text, '\u00e9\u00e9\u00e9\u00e9');
  assert.equal(Buffer.byteLength(utf8.text, 'utf8') <= 8, true);
  assert.equal(utf8.truncated, true);
});
