const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const verifierModule = import(
  pathToFileURL(
    path.join(appRoot, 'scripts', 'nosh-guard-tetragon-verify.mjs'),
  ).href
);

function tetraResult(policies) {
  return {
    status: 0,
    stdout: JSON.stringify({ policies }),
    stderr: '',
  };
}

test('Tetragon verifier requires one exact enabled enforcement policy', async () => {
  const { verifyTetragonPolicy } = await verifierModule;
  const attestation = await verifyTetragonPolicy(
    {
      tetra: 'tetra',
      serverAddress: 'unix:///run/tetragon.sock',
      policyName: 'nosh-profile-a1b2c3',
      expectedMode: 'enforce',
      timeoutMs: 100,
    },
    {
      now: () => 1_784_980_803_000,
      spawnSyncImpl: () =>
        tetraResult([
          {
            id: '42',
            name: 'nosh-profile-a1b2c3',
            enabled: true,
            state: 'TP_STATE_ENABLED',
            mode: 'TP_MODE_ENFORCE',
            kernel_memory_bytes: '4096',
          },
        ]),
    },
  );

  assert.equal(attestation.policy.name, 'nosh-profile-a1b2c3');
  assert.equal(attestation.policy.state, 'TP_STATE_ENABLED');
  assert.equal(attestation.policy.mode, 'TP_MODE_ENFORCE');
});

test('Tetragon verifier rejects monitor-only and duplicate policy results', async () => {
  const { verifyTetragonPolicy } = await verifierModule;
  const options = {
    tetra: 'tetra',
    serverAddress: 'unix:///run/tetragon.sock',
    policyName: 'nosh-profile-a1b2c3',
    expectedMode: 'enforce',
    timeoutMs: 100,
  };
  await assert.rejects(
    verifyTetragonPolicy(options, {
      spawnSyncImpl: () =>
        tetraResult([
          {
            name: options.policyName,
            enabled: true,
            state: 'TP_STATE_ENABLED',
            mode: 'TP_MODE_MONITOR_ONLY',
          },
        ]),
    }),
    /policy mode is TP_MODE_MONITOR_ONLY/,
  );
  await assert.rejects(
    verifyTetragonPolicy(options, {
      spawnSyncImpl: () =>
        tetraResult([
          {
            name: options.policyName,
            state: 'TP_STATE_ENABLED',
            mode: 'TP_MODE_ENFORCE',
          },
          {
            name: options.policyName,
            state: 'TP_STATE_ENABLED',
            mode: 'TP_MODE_ENFORCE',
          },
        ]),
    }),
    /returned 2 policies/,
  );
});

test('Tetragon verifier rejects a false enabled flag', async () => {
  const { verifyTetragonPolicy } = await verifierModule;
  await assert.rejects(
    verifyTetragonPolicy(
      {
        tetra: 'tetra',
        serverAddress: 'unix:///run/tetragon.sock',
        policyName: 'nosh-profile-disabled',
        expectedMode: 'enforce',
        timeoutMs: 100,
      },
      {
        spawnSyncImpl: () =>
          tetraResult([
            {
              name: 'nosh-profile-disabled',
              enabled: false,
              state: 'TP_STATE_ENABLED',
              mode: 'TP_MODE_ENFORCE',
            },
          ]),
      },
    ),
    /enabled flag is not true/,
  );
});
