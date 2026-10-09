'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const CREATED_AT = '2026-08-22T12:00:00.000Z';

async function modules() {
  const [core, bundles, cli] = await Promise.all([
    import('../lib/guard/review/index.js'),
    import('../lib/guard/review/bundle-store.js'),
    import('../lib/guard/review/cli.js'),
  ]);
  return { core, bundles, cli };
}

function bridgeInterfaces(...addresses) {
  return () => Object.fromEntries(addresses.map((address, index) => [
    `eth${index}`,
    [{
      address,
      netmask: '255.255.0.0',
      family: index % 2 === 0 ? 'IPv4' : 4,
      mac: '00:00:00:00:00:00',
      internal: false,
      cidr: `${address}/16`,
    }],
  ]));
}

async function reviewBundle(t) {
  const { core, bundles } = await modules();
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-review-graph-server-'));
  fs.chmodSync(parent, 0o700);
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const destination = path.join(parent, 'bundle');
  const subjectId = core.createStableId('subject', { fixture: 'graph-server' });
  const scope = core.createScope({ class: 'build', subjectId });
  const subject = core.createGraphNode({
    id: subjectId,
    scopeDigest: scope.scopeDigest,
    nodeType: 'project',
    label: 'graph server fixture',
    identity: { fixture: 'graph-server' },
    properties: {},
    evidenceRefs: [],
  });
  const artifact = bundles.createReviewBundleArtifact({
    createdAt: CREATED_AT,
    scope,
    sources: [],
    records: {
      nodes: [subject],
      observations: [],
      coverage: [],
      findings: [],
      proposals: [],
      diff: [],
    },
    basePolicyDigest: core.sha256Digest(null),
    privacyProfile: 'private-review',
  });
  await bundles.writeReviewBundleArtifact(destination, artifact);
  return destination;
}

test('wildcard graph binding auto-advertises the one Docker bridge address', async () => {
  const { cli } = await modules();
  for (const address of ['10.0.0.2', '10.255.255.254', '172.16.0.2',
    '172.23.0.7', '172.31.255.254', '192.168.16.2', '192.168.255.254']) {
    assert.deepEqual(cli.resolveReviewGraphHosts({
      host: '0.0.0.0',
      advertiseHost: 'auto',
    }, {
      networkInterfaces: bridgeInterfaces(address),
    }), {
      listenHost: '0.0.0.0',
      advertiseHost: address,
    });
    assert.deepEqual(cli.resolveReviewGraphHosts({ host: address }), {
      listenHost: address,
      advertiseHost: address,
    });
  }
});

test('automatic graph advertisement fails closed on missing or ambiguous addresses', async () => {
  const { cli } = await modules();
  for (const [addresses, expected] of [
    [[], /found 0/],
    [['172.20.0.3', '172.21.0.4'], /found 2/],
    [['192.168.16.2', '10.0.0.2'], /found 2/],
    [['192.169.1.3'], /found 0/],
  ]) {
    assert.throws(() => cli.resolveReviewGraphHosts({
      host: '0.0.0.0',
      advertiseHost: 'auto',
    }, {
      networkInterfaces: bridgeInterfaces(...addresses),
    }), expected);
  }
  assert.throws(() => cli.resolveReviewGraphHosts({
    host: '127.0.0.1',
    advertiseHost: 'auto',
  }, {
    networkInterfaces: bridgeInterfaces('172.20.0.3'),
  }), /requires the wildcard bind host/);
  assert.throws(() => cli.resolveReviewGraphHosts({
    host: '0.0.0.0',
    advertiseHost: '127.0.0.1',
  }), /requires automatic Docker bridge advertisement/);
});

test('graph addresses reject public, link-local, and noncanonical IPv4', async () => {
  const { cli } = await modules();
  for (const address of ['9.255.255.254', '11.0.0.2', '172.15.255.254',
    '172.32.0.2', '192.167.255.254', '192.169.0.2', '169.254.1.2',
    '100.64.0.2', '10.1.2.256', '10.01.2.3', '10.1.2', '10.1.2.3.']) {
    assert.throws(() => cli.resolveReviewGraphHosts({ host: address }), /IPv4|Docker bridge/);
    assert.throws(() => cli.resolveReviewGraphHosts({
      host: '0.0.0.0', advertiseHost: 'auto',
    }, { networkInterfaces: bridgeInterfaces(address) }), /found 0/);
  }
});

test('wildcard graph service keeps token access, no-store, and exact-origin CORS', async (t) => {
  const bundle = await reviewBundle(t);
  const { cli } = await modules();
  const token = 'a'.repeat(64);
  const origin = 'http://192.168.16.2:3000';
  const running = await cli.listenReviewGraph({
    bundle,
    port: 0,
    host: '0.0.0.0',
    advertiseHost: 'auto',
    origin,
    token,
  }, {
    networkInterfaces: bridgeInterfaces('192.168.16.7'),
  });
  t.after(async () => {
    await new Promise((resolve, reject) => running.server.close((error) => (
      error ? reject(error) : resolve()
    )));
  });

  const advertised = new URL(running.url);
  assert.equal(advertised.hostname, '192.168.16.7');
  const localUrl = `http://127.0.0.1:${advertised.port}${advertised.pathname}`;
  const accepted = await fetch(localUrl, { headers: { Origin: origin } });
  assert.equal(accepted.status, 200);
  assert.equal(accepted.headers.get('access-control-allow-origin'), origin);
  assert.equal(accepted.headers.get('cache-control'), 'no-store');
  await accepted.text();

  const foreign = await fetch(localUrl, {
    headers: { Origin: 'http://192.168.16.99:3000' },
  });
  assert.equal(foreign.status, 403);
  assert.equal(foreign.headers.get('access-control-allow-origin'), null);
  assert.equal(foreign.headers.get('cache-control'), 'no-store');
  await foreign.text();

  const wrongToken = await fetch(localUrl.replace(token, 'b'.repeat(64)), {
    headers: { Origin: origin },
  });
  assert.equal(wrongToken.status, 404);
  await wrongToken.text();

  const nonCanonical = await fetch(`${localUrl}?extra=1`, {
    headers: { Origin: origin },
  });
  assert.equal(nonCanonical.status, 404);
  await nonCanonical.text();
});
