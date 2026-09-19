const test = require('node:test');
const assert = require('node:assert/strict');
function field() {
  return { value: 'start 😀 αβ end', selectionStart: 6, selectionEnd: 11, focused: false,
    focus() { this.focused = true; }, setSelectionRange(start, end) { this.selectionStart = start; this.selectionEnd = end; } };
}
test('secure clipboard copies the exact Unicode selection without terminal input', async () => {
  const { copyTerminalText } = await import('../lib/terminalClipboard.js');
  const textarea = field();
  let copied;
  assert.equal(await copyTerminalText(textarea, false, { writeText: async (text) => { copied = text; } }, {}), 'Copied');
  assert.equal(copied, '😀 αβ');
  assert.equal(textarea.focused, false);
});
test('HTTP fallback selects all text and preserves it when browser copying fails', async () => {
  const { copyTerminalText } = await import('../lib/terminalClipboard.js');
  const textarea = field();
  let command;
  assert.match(await copyTerminalText(textarea, true, undefined, { execCommand: (value) => { command = value; return false; } }), /Copy unavailable/);
  assert.equal(command, 'copy');
  assert.equal(textarea.focused, true);
  assert.equal(textarea.selectionStart, 0);
  assert.equal(textarea.selectionEnd, textarea.value.length);
  assert.equal(textarea.value, 'start 😀 αβ end');
});
test('clipboard permission rejection restores the original selection before fallback', async () => {
  const { copyTerminalText } = await import('../lib/terminalClipboard.js');
  const textarea = field();
  const clipboard = { writeText: async () => {
    textarea.selectionStart = 0; textarea.selectionEnd = 0;
    throw new Error('Permission denied');
  } };
  assert.equal(await copyTerminalText(textarea, false, clipboard, { execCommand: () => true }), 'Copied');
  assert.equal(textarea.selectionStart, 6);
  assert.equal(textarea.selectionEnd, 11);
});
test('empty selection does not invoke either clipboard mechanism', async () => {
  const { copyTerminalText } = await import('../lib/terminalClipboard.js');
  const textarea = field(); textarea.selectionEnd = textarea.selectionStart;
  const unexpected = () => assert.fail('Clipboard should not be invoked');
  assert.equal(await copyTerminalText(textarea, false, { writeText: unexpected }, { execCommand: unexpected }), 'Select some text first.');
});
test('a closed copy view cannot regain focus after delayed permission rejection', async () => {
  const { copyTerminalText } = await import('../lib/terminalClipboard.js');
  const textarea = field();
  const clipboard = { writeText: async () => {
    textarea.isConnected = false;
    throw new Error('Permission denied');
  } };
  assert.equal(await copyTerminalText(textarea, false, clipboard, {
    execCommand: () => assert.fail('Detached field must not be copied')
  }), 'Copy view closed.');
  assert.equal(textarea.focused, false);
});
