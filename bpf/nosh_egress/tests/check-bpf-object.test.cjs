'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { checkInstructions, checkObject } = require('./check-bpf-object.cjs');

test('bytecode check rejects branches outside a function and into LDDW tails', () => {
  const code = Buffer.alloc(32);
  code[0] = 0x05;
  code[8] = 0x18;
  code[24] = 0x95;
  assert.equal(checkInstructions(code, 'valid'), 4);
  code.writeInt16LE(1, 2);
  assert.throws(() => checkInstructions(code, 'tail'), /branch at 0 targets 2/);
  code.writeInt16LE(3, 2);
  assert.throws(() => checkInstructions(code, 'outside'), /branch at 0 targets 4/);
  code.writeInt16LE(-2, 2);
  assert.throws(() => checkInstructions(code, 'negative'), /branch at 0 targets -1/);
});

test('bytecode check handles signed offsets and skips helper calls', () => {
  const code = Buffer.alloc(24);
  code[0] = 0x85;
  code.writeInt32LE(123, 4);
  code[8] = 0x15;
  code.writeInt16LE(-2, 10);
  code[16] = 0x95;
  assert.equal(checkInstructions(code, 'loop'), 3);
  code.writeInt16BE(-2, 10);
  assert.equal(checkInstructions(code, 'big-endian-loop', false), 3);
  assert.throws(() => checkInstructions(Buffer.alloc(7), 'truncated'), /instruction size/);
  assert.throws(() => checkObject(Buffer.alloc(64)), /ELF64/);
});
