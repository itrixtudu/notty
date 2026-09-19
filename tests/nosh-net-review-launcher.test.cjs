const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');
const repo = path.resolve(__dirname, '..');
const hasJq = spawnSync('jq', ['--version']).status === 0;

test('Apply help explains setup without Docker or signing configuration', () => {
  const result = spawnSync('bash', [path.join(repo, 'nosh.sh'), 'net', 'apply', '--help'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /mode 0600/);
  assert.match(result.stdout, /reviewPrivateKey/);
  assert.match(result.stdout, /deploymentPrivateKey/);
});

test('host Apply isolates signing roles and repeating the active selection issues no grant', { skip: !hasJq }, t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-apply-launcher-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const directories = ['bin', 'workspace', 'review', 'review/runtime', 'review/decisions', 'export', 'export/key', 'export/key/revision', 'state', 'keys'];
  for (const name of directories) fs.mkdirSync(path.join(root, name), { mode: 0o700 });
  const write = (name, data, mode = 0o600) => fs.writeFileSync(path.join(root, name), data, { mode });
  const digest = `sha256:${'d'.repeat(64)}`;
  const tooling = `sha256:${'a'.repeat(64)}`;
  const session = { toolingImage: tooling, runtimeCandidate: path.join(root, 'export/key/revision'), workdir: path.join(root, 'workspace'), revision: 'revision', imageDigest: tooling };
  write('review/runtime/review-session.json', JSON.stringify(session));
  for (const key of ['review', 'public', 'deployment']) write(`keys/${key}.pem`, 'fixture');
  write('apply.json', JSON.stringify({ schemaVersion: 1, reviewPrivateKey: path.join(root, 'keys/review.pem'), reviewPublicKey: path.join(root, 'keys/public.pem'), deploymentPrivateKey: path.join(root, 'keys/deployment.pem'), reviewAudience: 'review', deploymentAudience: 'guard' }));
  write('bin/sudo', '#!/bin/sh\n[ "$1" != -- ] || shift\nexec "$@"\n', 0o700);
  write('bin/docker', `#!/usr/bin/env node
const fs = require('node:fs'), path = require('node:path');
const args = process.argv.slice(2), root = process.env.TEST_APPLY_ROOT;
fs.appendFileSync(path.join(root, 'events.jsonl'), JSON.stringify(args)+'\\n');
if (args[0] === 'image') { console.log(process.env.TEST_TOOLING+'|1'); process.exit(0); }
const mounts = args.filter((v,i) => args[i-1] === '--mount');
const io = mounts.find(v => v.includes('dst=/policy-io'));
const stage = io ? io.split(',')[1].slice(4) : args[args.indexOf('--output')+1];
const write = (name, value) => { const file=path.join(stage,name); fs.mkdirSync(path.dirname(file),{recursive:true}); fs.writeFileSync(file,JSON.stringify(value)); };
if (args.includes('snapshot')) console.log(JSON.stringify({session:JSON.parse(fs.readFileSync(path.join(root,'review/runtime/review-session.json'))),reviewer:'Operator'}));
else if (args.includes('project')) {
 write('projected/rendered/ebpf-policy.json',{rules:[]});
 console.log(JSON.stringify({activationEligible:true,leafBundleDigest:'leaf',targetReviewSetDigest:'confirmation',targetBindingDigest:'binding'}));
} else if (args.includes('approve')) { write('approval/approval-envelope.dsse.json',{}); console.log('{}'); }
else if (args.includes('grant')) { write('deployment/deployment-grant.dsse.json',{}); console.log('{}'); }
else process.exit(2);
`, 0o700);
  write('bin/guard', `#!/usr/bin/env node
const fs=require('node:fs'), path=require('node:path');
const file=path.join(process.env.TEST_APPLY_ROOT,'active.json');
if (process.argv[3] === 'activate') fs.writeFileSync(file,JSON.stringify({leafBundleDigest:'leaf',decisionSetDigest:process.env.TEST_DECISIONS,activatedAt:'2026-09-16T00:00:00Z'}));
console.log(JSON.stringify({activeGrantSetDigest:'grants',activation:fs.existsSync(file)?JSON.parse(fs.readFileSync(file)):null}));
`, 0o700);
  const env = { ...process.env, PATH: `${root}/bin:${process.env.PATH}`, TEST_APPLY_ROOT: root, TEST_TOOLING: tooling, TEST_DECISIONS: digest,
    NOSH_NET_REVIEW_DOCKER_BIN: path.join(root, 'bin/docker'), NOSH_GUARD_PRIVILEGED_BIN: path.join(root, 'bin/guard'),
    NOSH_POLICY_APPLY_CONFIG: path.join(root, 'apply.json'), NOSH_PROFILE_REVIEW_STATE_ROOT: path.join(root, 'state'),
    NOSH_PROFILE_REVIEW_IMAGE_CONFIG: path.join(root, 'absent'), NOSH_POLICY_TOOLING_IMAGE: tooling };
  const launch = () => spawnSync('bash', [path.join(repo, 'nosh.sh'), 'net', 'apply', '--review', path.join(root, 'review'), '--decision-digest', digest, '--yes'], { env, encoding: 'utf8' });
  let result = launch();
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const events = () => fs.readFileSync(path.join(root, 'events.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
  const approval = events().find(args => args.includes('approve'));
  const grant = events().find(args => args.includes('grant'));
  assert.ok(approval.some(arg => arg.includes('keys/review.pem')));
  assert.ok(!approval.some(arg => arg.includes('keys/deployment.pem')));
  assert.ok(grant.some(arg => arg.includes('keys/deployment.pem')));
  assert.ok(!grant.some(arg => arg.includes('keys/review.pem')));
  assert.equal(JSON.parse(fs.readFileSync(path.join(root, 'review/decisions/applied.json'))).decisionDigest, digest);
  result = launch();
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /already applied/);
  assert.equal(events().filter(args => args.includes('grant')).length, 1);
});
