'use strict';

// Structural bytecode validation, not a replacement for the kernel verifier.
const fs = require('node:fs');

function checkInstructions(bytes, label, littleEndian = true) {
  if (!bytes.length || bytes.length % 8) throw new Error(`${label}: invalid instruction size`);
  const count = bytes.length / 8;
  const starts = new Set();
  const branches = [];
  for (let index = 0; index < count; index++) {
    starts.add(index);
    const offset = index * 8;
    const opcode = bytes[offset];
    if (opcode === 0x18) {
      if (++index >= count || bytes[index * 8] !== 0) {
        throw new Error(`${label}: invalid LDDW at ${index - 1}`);
      }
      continue;
    }
    const instructionClass = opcode & 7;
    const operation = opcode & 0xf0;
    if ((instructionClass === 5 || instructionClass === 6)
        && operation !== 0x80 && operation !== 0x90) {
      const displacement = opcode === 0x06
        ? bytes[littleEndian ? 'readInt32LE' : 'readInt32BE'](offset + 4)
        : bytes[littleEndian ? 'readInt16LE' : 'readInt16BE'](offset + 2);
      branches.push({ index, target: index + 1 + displacement });
    }
  }
  for (const { index, target } of branches) {
    if (!starts.has(target)) {
      throw new Error(`${label}: branch at ${index} targets ${target}, outside a valid instruction in this function (${count} slots)`);
    }
  }
  return count;
}

function checkObject(bytes) {
  if (bytes.length < 64 || bytes.toString('hex', 0, 4) !== '7f454c46'
      || bytes[4] !== 2 || ![1, 2].includes(bytes[5])) {
    throw new Error('expected an ELF64 BPF object');
  }
  const littleEndian = bytes[5] === 1;
  const suffix = littleEndian ? 'LE' : 'BE';
  const u16 = (offset) => bytes[`readUInt16${suffix}`](offset);
  const u32 = (offset) => bytes[`readUInt32${suffix}`](offset);
  const u64 = (offset) => {
    const value = bytes[`readBigUInt64${suffix}`](offset);
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('oversized ELF field');
    return Number(value);
  };
  if (u16(18) !== 247) throw new Error('ELF machine is not BPF');
  const sectionOffset = u64(40);
  const stride = u16(58);
  const count = u16(60);
  if (stride < 64 || !count || sectionOffset + stride * count > bytes.length) {
    throw new Error('invalid ELF section table');
  }
  const sections = Array.from({ length: count }, (_, index) => {
    const offset = sectionOffset + index * stride;
    return {
      index, type: u32(offset + 4), flags: u64(offset + 8),
      offset: u64(offset + 24), size: u64(offset + 32),
      link: u32(offset + 40), stride: u64(offset + 56),
    };
  });
  const data = (section) => {
    if (!section || section.offset + section.size > bytes.length) throw new Error('invalid ELF section data');
    return bytes.subarray(section.offset, section.offset + section.size);
  };
  const functions = [];
  for (const symbols of sections.filter((section) => section.type === 2)) {
    if (symbols.stride !== 24 || symbols.size % 24) throw new Error('invalid ELF symbols');
    data(symbols);
    const strings = data(sections[symbols.link]);
    for (let offset = symbols.offset; offset < symbols.offset + symbols.size; offset += 24) {
      if ((bytes[offset + 4] & 15) !== 2) continue;
      const section = sections[u16(offset + 6)];
      if (!section || !(section.flags & 4)) continue;
      const start = u64(offset + 8);
      const size = u64(offset + 16);
      const nameOffset = u32(offset);
      const end = strings.indexOf(0, nameOffset);
      if (end < nameOffset || start % 8 || start + size > section.size) throw new Error('invalid ELF function');
      const name = strings.toString('utf8', nameOffset, end);
      const instructions = checkInstructions(data(section).subarray(start, start + size), name, littleEndian);
      functions.push({ name, instructions });
    }
  }
  if (!functions.length) throw new Error('no BPF functions found');
  return functions;
}

if (require.main === module) {
  try {
    if (process.argv.length !== 3) throw new Error('usage: check-bpf-object.cjs OBJECT');
    process.stdout.write(`${JSON.stringify(checkObject(fs.readFileSync(process.argv[2])), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`BPF bytecode check: ${error.message}\n`);
    process.exitCode = 1;
  }
}
module.exports = { checkInstructions, checkObject };
