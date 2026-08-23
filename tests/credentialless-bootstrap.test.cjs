'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const bootstrapSource = fs.readFileSync(
  path.resolve(__dirname, '..', 'public', 'credentialless-bootstrap.js'),
  'utf8',
);

function runBootstrap(documentUrl) {
  const replacements = [];
  vm.runInNewContext(bootstrapSource, {
    URL,
    document: { URL: documentUrl },
    window: {
      location: {
        replace(value) {
          replacements.push(value);
        },
      },
    },
  });
  return replacements;
}

test('credential bootstrap replaces a document URL with a credential-free equivalent', () => {
  assert.deepEqual(
    runBootstrap('http://notty:s%40fe@127.0.0.1:3100/collab?view=grid#agent'),
    ['http://127.0.0.1:3100/collab?view=grid#agent'],
  );
});

test('credential bootstrap leaves an ordinary document URL alone', () => {
  assert.deepEqual(runBootstrap('https://notty.example/collab'), []);
});
