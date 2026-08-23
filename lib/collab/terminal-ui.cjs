'use strict';

const readline = require('readline');

function createIrcTerminalUi(options = {}) {
  const input = options.input || process.stdin;
  const output = options.output || process.stdout;
  const getPrompt = typeof options.prompt === 'function'
    ? options.prompt
    : () => String(options.prompt || '');
  const terminal = options.terminal === undefined
    ? Boolean(input.isTTY && output.isTTY)
    : Boolean(options.terminal);
  const rl = readline.createInterface({ input, output, terminal });
  let promptVisible = false;

  function prompt(preserveCursor = false) {
    rl.setPrompt(String(getPrompt()));
    rl.prompt(Boolean(preserveCursor));
  }

  function clearPrompt() {
    if (!terminal || !promptVisible) {
      return;
    }

    const cursor = typeof rl.getCursorPos === 'function'
      ? rl.getCursorPos()
      : { rows: 0 };
    if (cursor.rows > 0) {
      readline.moveCursor(output, 0, -cursor.rows);
    }
    readline.cursorTo(output, 0);
    readline.clearScreenDown(output);
  }

  function write(text) {
    const rendered = String(text ?? '');
    clearPrompt();
    output.write(rendered.endsWith('\n') ? rendered : `${rendered}\n`);
    if (promptVisible) {
      prompt(true);
    }
  }

  function setPromptVisible(visible) {
    promptVisible = Boolean(visible);
  }

  return {
    readline: rl,
    isTerminal: terminal,
    isPromptVisible: () => promptVisible,
    prompt,
    setPromptVisible,
    write,
  };
}

module.exports = {
  createIrcTerminalUi,
};
