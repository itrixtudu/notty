#!/usr/bin/env node
// Small assertions and review preparation; executed only in a pinned local image.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const [action, ...args] = process.argv.slice(2);
const read = async (file) => JSON.parse(await fs.readFile(file, 'utf8'));
if (action === 'decisions') {
  const [bundle, output, address, port] = args;
  const { readReviewBundleArtifact } = await import(pathToFileURL('/app/lib/guard/review/bundle-store.js'));
  const { createDecisionSet } = await import(pathToFileURL('/app/lib/guard/review/documents.js'));
  const { graph } = await readReviewBundleArtifact(bundle);
  let accepted = 0;
  const decisions = graph.proposals.map((proposal) => {
    const intent = proposal.intent;
    const allow = intent?.domain === 'network' && intent.direction === 'egress'
      && ['ipv4', 'ipv4-cidr'].includes(intent.peer?.kind)
      && [address, `${address}/32`].includes(intent.peer.value)
      && intent.transport?.protocol === 'tcp'
      && intent.transport.ports.length === 1 && intent.transport.ports[0] === Number(port);
    if (allow) accepted += 1;
    return { proposalId: proposal.id, disposition: allow ? 'accept' : 'reject',
      rationale: allow ? 'Disposable QEMU fixture: permit the exact approved endpoint.'
        : 'Disposable QEMU fixture: no authority outside the approved literal endpoint.' };
  });
  assert.equal(accepted, 1, 'review must contain exactly one literal approved endpoint proposal');
  const document = createDecisionSet({ graph, reviewer: 'qemu-test', decisions });
  await fs.writeFile(output, `${JSON.stringify(document, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
} else if (action === 'evidence') {
  const [manifestPath, mode, approved, rejected, evidencePath] = args;
  const manifest = await read(manifestPath);
  assert.equal(manifest.complete, true, 'incomplete Guard evidence');
  assert.equal(manifest.mode, `egress-${mode}`);
  assert.equal(manifest.egressEvaluation?.complete, true);
  const records = (await fs.readFile(evidencePath, 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);
  const has = (ip, verdict) => records.some((entry) => entry.recordKind === 'decision'
    && entry.destinationAddress === ip && entry.verdict === verdict);
  assert.ok(has(approved, 'allow'), 'missing approved endpoint allow evidence');
  if (mode === 'audit') {
    assert.ok(manifest.egressEvaluation.wouldDenyCount > 0);
    assert.ok(has(rejected, 'would-deny'), 'missing rejected endpoint would-deny evidence');
  } else if (mode === 'enforce') {
    assert.ok(manifest.egressEvaluation.deniedCount > 0);
    assert.ok(has(rejected, 'deny'), 'missing rejected endpoint deny evidence');
  } else {
    assert.ok(has(rejected, 'allow'), 'learning did not allow both fixture endpoints');
  }
  console.log(JSON.stringify({ test: `egress-${mode}`, status: 'passed', evaluation: manifest.egressEvaluation }));
} else if (action === 'projection') {
  const receipt = await read(args[0]);
  assert.equal(receipt.activationEligible, true, 'projection is not activation eligible');
  assert.match(receipt.targetReviewSetDigest, /^sha256:[a-f0-9]{64}$/);
  assert.match(receipt.targetBindingDigest, /^sha256:[a-f0-9]{64}$/);
} else {
  throw new Error(`unknown scenario helper action: ${action}`);
}
