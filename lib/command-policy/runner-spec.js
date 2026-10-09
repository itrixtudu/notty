// Candidate execution boundary for host acceptance testing. Not an activation API.
import { authorizePipeline, parseInvocation } from '../../policy-review/modules/command-policy/model.js';

const imageId = /^sha256:[a-f0-9]{64}$/;
const safePath = value => typeof value === 'string' && /^\/[a-zA-Z0-9_./-]+$/.test(value)
  && !value.split('/').some(piece => piece === '..' || piece === '.');

export function workerProfiles(name, command) {
  if (!/^nosh-command-probe-[a-f0-9]{16}$/.test(name) || !/^[a-z][a-z0-9-]*$/.test(command)) throw new Error('Invalid worker identity');
  return `#include <tunables/global>
profile ${name} flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  /usr/local/libexec/nosh-command-bootstrap mr,
  /usr/local/libexec/nosh-command-bootstrap ix,
  /usr/bin/${command} r,
  /usr/bin/${command} px -> ${name}-worker,
  /proc/** r,
}
profile ${name}-worker flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  /** r,
  /{,usr/}lib{,32,64}/** mr,
  /workspace/ rw,
  /workspace/** rwkl,
  /tmp/ rw,
  /tmp/** rwkl,
  /dev/null rw,
  deny /** x,
  deny /workspace/** m,
  deny /tmp/** m,
  deny /proc/** w,
  deny /sys/** w,
  deny network,
  deny capability,
}
`;
}

export function candidateWorkerSpec({ image, workspace, uid, gid, name, argv, mode = 'read-only', rules }) {
  if (!imageId.test(image) || !safePath(workspace) || !Number.isSafeInteger(uid) || uid <= 0
      || !Number.isSafeInteger(gid) || gid < 0 || !['read-only', 'implementation'].includes(mode)) throw new Error('Invalid worker binding');
  const evaluation = authorizePipeline(rules, [argv], mode);
  if (!evaluation.allowed) throw new Error(evaluation.reason);
  const command = parseInvocation(argv).command;
  const profile = workerProfiles(name, command);
  return { candidate: true, enforcing: false, profile,
    args: ['run', '--rm', '--pull=never', '--name', name, '--network=none', '--read-only',
      '--cap-drop=ALL', '--security-opt=no-new-privileges:true', `--security-opt=apparmor=${name}`,
      '--user', `${uid}:${gid}`, '--pids-limit=32', '--memory=256m', '--cpus=1',
      '--ulimit', 'core=0:0', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=16777216,mode=1777',
      '--mount', `type=bind,src=${workspace},dst=/workspace${mode === 'read-only' ? ',readonly' : ''}`,
      '--workdir=/workspace', '--entrypoint=/usr/local/libexec/nosh-command-bootstrap',
      '--interactive', image, `/usr/bin/${command}`, ...argv.slice(1)] };
}
