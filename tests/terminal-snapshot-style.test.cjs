'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { terminalSnapshotStyle } = require('../lib/terminalSnapshot.cjs');

test('copy view inherits terminal typography and measured cell line spacing', () => {
  const options = {
    fontFamily: 'JetBrains Mono, Fira Code, Consolas, Monaco, monospace',
    fontSize: 14, fontWeight: 'normal', lineHeight: 1, letterSpacing: 0,
  };
  assert.deepEqual(terminalSnapshotStyle(options, 624, 39), {
    fontFamily: options.fontFamily, fontSize: '14px', fontWeight: 'normal',
    fontStyle: 'normal', lineHeight: '16px', letterSpacing: '0px', fontVariantLigatures: 'none',
  });
  assert.equal(terminalSnapshotStyle({ ...options, fontSize: 18, letterSpacing: 2 }, 780, 39).fontSize, '18px');
  assert.equal(terminalSnapshotStyle({ ...options, lineHeight: 1.2 }, 0, 0).lineHeight, 1.2);
});

test('copy textarea uses inline typography so general form font inheritance cannot override it', () => {
  const source = fs.readFileSync(path.join(__dirname, '../components/XtermRenderer.js'), 'utf8');
  assert.match(source, /style: terminalSnapshotStyle\(terminal\.options/);
  assert.match(source, /<textarea[^>]*style=\{snapshot\.style\}[^>]*wrap="off"/s);
});
