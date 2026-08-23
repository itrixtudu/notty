// Manual test harness notes:
// - `node scripts/sse-roundtrip.mjs` verifies the SSE transport roundtrip by
//   spawning server.js in MCP_TRANSPORT=sse mode and calling listTools.


import * as os from 'node:os';
import * as pty from 'node-pty';

const shell = os.platform() === 'win32' ? 'powershell.exe' : 'bash';

const ptyProcess = pty.spawn(shell, [], {
  name: 'xterm-color',
  cols: 80,
  rows: 30,
  cwd: process.env.HOME,
  env: process.env
});

ptyProcess.onData((data) => {
  process.stdout.write(data);
});

ptyProcess.write('ls\r');
ptyProcess.resize(100, 40);
ptyProcess.write('ls\r');

