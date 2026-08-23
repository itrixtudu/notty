#!/usr/bin/env node

/**
 * txt2ogham.js - Simple translator from Latin text to Ogham script (Unicode U+1680 - U+169C).
 *
 * Usage via CLI:
 *   node txt2ogham.js "Hello World"
 *   node txt2ogham.js -f "Hello World"
 *   echo "Hello World" | node txt2ogham.js
 *
 * Usage as Module:
 *   import { txt2ogham } from './txt2ogham.js';
 *   console.log(txt2ogham('Hello World'));
 */

import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

export const OGHAM_MAP = {
  // Digraphs / Forfeda (checked before single characters)
  'ng': '\u168D', // ᚍ Ngeidal
  'ea': '\u1695', // ᚕ Éabhadh
  'oi': '\u1696', // ᚖ Óir
  'ui': '\u1697', // ᚗ Uilleann
  'ia': '\u1698', // ᚘ Ifín
  'ae': '\u1699', // ᚙ Eamhancholl
  'ch': '\u1699', // ᚙ Eamhancholl / ch

  // Single letters
  'a': '\u1690', // ᚐ Ailm
  'b': '\u1681', // ᚁ Beith
  'c': '\u1689', // ᚉ Coll
  'd': '\u1687', // ᚇ Dair
  'e': '\u1693', // ᚓ Edad
  'f': '\u1683', // ᚃ Fearn
  'g': '\u168C', // ᚌ Gort
  'h': '\u1686', // ᚆ Uath
  'i': '\u1694', // ᚔ Idad
  'j': '\u1694', // ᚔ (Mapped to Idad / I)
  'k': '\u1689', // ᚉ (Mapped to Coll / C)
  'l': '\u1682', // ᚂ Luis
  'm': '\u168B', // ᚋ Muin
  'n': '\u1685', // ᚅ Nion
  'o': '\u1691', // ᚑ Onn
  'p': '\u169A', // ᚚ Peith
  'q': '\u168A', // ᚊ Ceirt
  'r': '\u168F', // ᚏ Ruis
  's': '\u1684', // ᚄ Sail
  't': '\u1688', // ᚈ Tinne
  'u': '\u1692', // ᚒ Úr
  'v': '\u1683', // ᚃ (Mapped to Fearn / F)
  'w': '\u1692', // ᚒ (Mapped to Úr / U)
  'x': '\u168E', // ᚎ Straif
  'y': '\u1694', // ᚔ (Mapped to Idad / I)
  'z': '\u168E', // ᚎ Straif

  // Space
  ' ': '\u1680', //   Ogham space mark
};

export const FEATHER_START = '\u169B'; // ᚛ Feather mark (start of text)
export const FEATHER_END = '\u169C';   // ᚜ Reversed feather mark (end of text)

/**
 * Translates Latin text string into Ogham script.
 * @param {string} text - The input text to translate.
 * @param {object} [options] - Translation options.
 * @param {boolean} [options.feathers=false] - Whether to surround output with feather marks (᚛...᚜).
 * @param {boolean} [options.forfeda=true] - Whether to convert diphthongs/digraphs (ea, oi, ui, ia, ae, ng).
 * @param {boolean} [options.preserveUnknown=true] - Whether to preserve unmapped characters (punctuation, digits).
 * @returns {string} - The translated Ogham string.
 */
export function txt2ogham(text, options = {}) {
  const {
    feathers = false,
    forfeda = true,
    preserveUnknown = true,
  } = options;

  if (typeof text !== 'string') {
    return '';
  }

  let result = '';
  const lower = text.toLowerCase();
  let i = 0;

  while (i < lower.length) {
    if (forfeda && i + 1 < lower.length) {
      const pair = lower.slice(i, i + 2);
      if (pair in OGHAM_MAP && pair.length === 2) {
        result += OGHAM_MAP[pair];
        i += 2;
        continue;
      }
    }

    const char = lower[i];
    if (char in OGHAM_MAP) {
      result += OGHAM_MAP[char];
    } else if (preserveUnknown) {
      result += text[i];
    }
    i++;
  }

  if (feathers && result.length > 0) {
    return `${FEATHER_START}${result}${FEATHER_END}`;
  }

  return result;
}

export default txt2ogham;

// CLI execution handling
const isDirectRun = process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1]);

if (isDirectRun) {
  const args = process.argv.slice(2);
  let feathers = false;
  let forfeda = true;
  let preserveUnknown = true;
  const inputWords = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '-f' || arg === '--feathers') {
      feathers = true;
    } else if (arg === '--no-feathers') {
      feathers = false;
    } else if (arg === '--no-forfeda') {
      forfeda = false;
    } else if (arg === '--strip-unknown') {
      preserveUnknown = false;
    } else if (arg === '-h' || arg === '--help') {
      console.log(`txt2ogham - Translate Latin text into Ogham script

Usage:
  node txt2ogham.js [options] [text...]
  echo "text" | node txt2ogham.js [options]

Options:
  -f, --feathers     Add traditional start/end feather marks (᚛ ... ᚜)
  --no-forfeda       Disable digraph conversions (ng, ea, oi, ui, ia, ae)
  --strip-unknown    Omit characters that cannot be mapped
  -h, --help         Show this help message
`);
      process.exit(0);
    } else {
      inputWords.push(arg);
    }
  }

  const options = { feathers, forfeda, preserveUnknown };

  if (inputWords.length > 0) {
    const inputText = inputWords.join(' ');
    console.log(txt2ogham(inputText, options));
  } else if (!process.stdin.isTTY) {
    let stdinData = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      stdinData += chunk;
    });
    process.stdin.on('end', () => {
      // Process input line by line or entire string preserving linebreaks
      const lines = stdinData.split('\n');
      if (lines.length > 1 && lines[lines.length - 1] === '') {
        lines.pop(); // remove trailing newline from split
      }
      for (const line of lines) {
        console.log(txt2ogham(line, options));
      }
    });
  } else {
    console.error('Error: No input provided. Run with --help for usage instructions.');
    process.exit(1);
  }
}
