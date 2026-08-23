'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const repository = path.resolve(__dirname, '..');
const project = path.join(repository, 'policy-review');

const requiredFiles = [
  '.dockerignore',
  '.gitignore',
  'Dockerfile',
  'README.md',
  'components/policy-review/PolicyReview.module.css',
  'components/policy-review/PolicyReviewCanvas.js',
  'components/policy-review/PolicyReviewPage.js',
  'components/policy-review/PolicyReviewTimeline.js',
  'modules/__tests__/semanticGraph.spec.js',
  'modules/__tests__/iptablesExport.spec.js',
  'modules/__tests__/proposalSelectionState.spec.js',
  'modules/__tests__/runtimeAttestation.spec.js',
  'modules/__tests__/timelineState.spec.js',
  'modules/__tests__/timelineProjection.spec.js',
  'modules/policy-review/proposalDerivation.js',
  'modules/policy-review/iptablesExport.js',
  'modules/policy-review/reviewStore.js',
  'modules/policy-review/runtimeAttestation.js',
  'modules/policy-review/semanticGraph.js',
  'modules/policy-review/timelineProjection.js',
  'next.config.js',
  'package-lock.json',
  'package.json',
  'pages/_app.js',
  'pages/api/policy-review-attestation.js',
  'pages/api/policy-review-decision-set.js',
  'pages/index.js',
  'pages/policy-review.js',
  'styles/globals.css',
  'tests/dev-runtime.test.cjs',
  'tests/next-config.test.cjs',
  'tests/runtime-attestation-api.test.cjs',
  'tests/decision-set-api.test.cjs',
  'tests/selected-iptables-export-ui.test.cjs',
];

test('policy reviewer is a standalone minimal Next.js application', () => {
  for (const relative of requiredFiles) {
    const file = path.join(project, relative);
    assert.equal(fs.statSync(file).isFile(), true, relative);
  }

  const manifest = JSON.parse(fs.readFileSync(path.join(project, 'package.json'), 'utf8'));
  assert.equal(manifest.name, 'nosh-policy-review');
  assert.equal(manifest.private, true);
  assert.deepEqual(manifest.dependencies, {
    next: '16.3.1',
    react: '18.2.0',
    'react-dom': '18.2.0',
    reactflow: '11.11.4',
  });
  assert.deepEqual(manifest.devDependencies, { vitest: '4.0.6' });

  const lock = JSON.parse(fs.readFileSync(path.join(project, 'package-lock.json'), 'utf8'));
  assert.equal(lock.lockfileVersion, 3);
  assert.deepEqual(lock.packages[''].dependencies, manifest.dependencies);
  assert.deepEqual(lock.packages[''].devDependencies, manifest.devDependencies);
  assert.equal(lock.packages['node_modules/next'].version, manifest.dependencies.next);
  assert.equal(lock.packages['node_modules/reactflow'].version, manifest.dependencies.reactflow);
  assert.equal(lock.packages['node_modules/vitest'].version, manifest.devDependencies.vitest);

  for (const [packagePath, entry] of Object.entries(lock.packages)) {
    if (packagePath === '' || entry.link === true) continue;
    assert.match(entry.resolved, /^https:\/\/registry\.npmjs\.org\//, packagePath);
    assert.match(entry.integrity, /^sha512-[A-Za-z0-9+/]+={0,2}$/, packagePath);
  }
});

test('policy reviewer has no dependency on the former example application', () => {
  const reviewedFiles = requiredFiles.filter(relative => /\.(?:js|cjs|css|md|json)$/.test(relative));
  const content = reviewedFiles
    .map(relative => fs.readFileSync(path.join(project, relative), 'utf8'))
    .join('\n');
  assert.doesNotMatch(content, /examples\/3jsui-cleaning|externalCallGuard|styles\/legacy\.css/);

  const docs = fs.readFileSync(path.join(repository, 'docs/nosh-policy-review.md'), 'utf8');
  assert.match(docs, /standalone application from `policy-review\/`/);
  assert.match(docs, /NOSH_POLICY_REVIEW_UI_IMAGE/);
  assert.match(docs, /arbitrary pre-existing server/);
  assert.match(
    docs,
    /\.\/nosh\.sh recreate --no-start-app --publish 127\.0\.0\.1:3001/,
  );
  assert.match(docs, /http:\/\/localhost:3001\/policy-review/);
  assert.match(docs, /HMR or diagnostics only/);
  assert.doesNotMatch(docs, /examples\/3jsui-cleaning/);

  const dockerfile = fs.readFileSync(path.join(project, 'Dockerfile'), 'utf8');
  assert.match(dockerfile, /node:24\.18\.0-bookworm-slim@sha256:[a-f0-9]{64}/);
  assert.match(dockerfile, /npm ci --include=dev --ignore-scripts/);
  assert.match(dockerfile, /npm run test:run/);
  assert.match(dockerfile, /USER node/);
  assert.match(dockerfile, /io\.notty\.policy-review\.ui-abi="1"/);
  assert.match(dockerfile, /HEALTHCHECK/);

  const canvas = fs.readFileSync(
    path.join(project, 'components/policy-review/PolicyReviewCanvas.js'),
    'utf8',
  );
  assert.match(canvas, /createTimelineProjection\(state\.graph\)/);
  assert.match(canvas, /selectTimelineActivity\(timelineProjection/);
  assert.match(canvas, /data-temporal=/);
  assert.match(canvas, /selectedRecords/);
  assert.match(canvas, /Ctrl\/Cmd-click nodes or evidence edges to multi-select/);

  const page = fs.readFileSync(
    path.join(project, 'components/policy-review/PolicyReviewPage.js'),
    'utf8',
  );
  assert.match(page, /<PolicyReviewTimeline \/>/);
  assert.match(page, /Allow selected telemetry/);
  assert.match(page, /resolveAllowProposalSelection/);
  assert.match(page, /createSelectedIptablesExport/);
  assert.match(page, /Unsigned selected-rule iptables sketch/);
  assert.match(page, /Download unsigned print-only sketch/);
  assert.match(page, /Run status/);
  assert.match(page, /Incomplete source coverage:/);
  assert.match(page, /Candidate/);
  assert.match(page, /DNS loss/);
  assert.match(page, /Blocking findings/);
  assert.match(page, /Activation/);
  assert.match(page, /signed-activation-handoff/);
  assert.match(page, /nosh policy project .*--target/);
  assert.match(page, /nosh-guard ebpf activate/);
  assert.match(page, /fetchPolicyReviewRuntimeAttestation/);
});
