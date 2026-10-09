import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../../scripts/nosh-tool-policy.py', import.meta.url));
function invoke(command, document, workdir, mode) {
  const args = ['-I', '-S', script, command, '--workdir', workdir];
  if (mode) args.push('--tool-mode', mode);
  return new Promise((resolve, reject) => {
    const child = spawn('python3', args, { stdio: ['pipe', 'pipe', 'pipe'] });
    const output = [], errors = [];
    let size = 0;
    let failure;
    const timer = setTimeout(() => { failure = new Error('Environment policy verification timed out'); child.kill(); }, 30000);
    for (const [stream, chunks] of [[child.stdout, output], [child.stderr, errors]]) {
      stream.on('data', chunk => {
        size += chunk.length;
        if (size > 32 * 1024 * 1024) {
          failure = new Error('Environment policy output exceeded its limit'); child.kill();
        } else chunks.push(chunk);
      });
    }
    child.on('error', error => { failure = error; });
    child.stdin.on('error', error => { failure ||= error; });
    child.on('close', code => {
      clearTimeout(timer);
      if (failure || code !== 0) {
        reject(new Error(`Nosh environment policy rejected the container: ${failure?.message || Buffer.concat(errors).toString().trim()}`));
        return;
      }
      try { resolve(JSON.parse(Buffer.concat(output).toString())); } catch (error) { reject(error); }
    });
    child.stdin.end(JSON.stringify(document));
  });
}
export const applyToolEnvironment = (spec, workdir, mode) => invoke('spec', spec, workdir, mode);
export const verifyToolEnvironment = (inspected, workdir, mode) => invoke('verify-spec', inspected, workdir, mode);
