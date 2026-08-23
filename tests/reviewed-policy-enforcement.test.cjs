'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { pathToFileURL } = require('node:url');
const path = require('node:path');

const policyModule = import(pathToFileURL(path.resolve(
  __dirname,
  '../lib/guardd/egress-policy.js',
)).href);

test('reviewed enforce policy blocks example.org and its direct IP while allowing the selected control', async () => {
  const { generateNftRules } = await policyModule;
  const reviewed = {
    runId: 'reviewed-example-org',
    mode: 'egress-enforce',
    profileRevision: 'decision-set-1',
    networkName: 'nosh-reviewed-example-org',
    sourceIpv4: '10.240.8.3',
    gatewayIpv4: '10.240.8.2',
    attemptedInteractions: [
      { hostname: 'example.org', resolvedAddress: '93.184.216.34', protocol: 'tcp', port: 80 },
      { address: '93.184.216.34', protocol: 'tcp', port: 80 },
    ],
    // This is the only interaction selected in the reviewed DecisionSet.
    egress: [{ destination: '198.51.100.7/32', protocol: 'tcp', ports: [8080] }],
  };
  const rules = generateNftRules([reviewed]);
  assert.deepEqual(reviewed.attemptedInteractions.map((entry) => entry.hostname || entry.address), [
    'example.org',
    '93.184.216.34',
  ]);

  // example.org and its resolved address (used by the direct-IP attempt) are
  // absent from the allowlist, so the terminal enforce rule must drop them.
  assert.match(rules, /egress-enforce deny/);
  assert.match(rules, /ip saddr 10\.240\.8\.3/);
  assert.doesNotMatch(rules, /93\.184\.216\.34/);
  assert.match(rules, /198\.51\.100\.7/);
  assert.match(rules, /tcp dport 8080/);

  // Manual editing uses the same JSON contract as the UI: changing the
  // selected disposition changes the projected allowlist, never the runtime
  // mode or source binding.
  const manuallyEdited = JSON.parse(JSON.stringify(reviewed));
  manuallyEdited.egress = [{ destination: '93.184.216.34/32', protocol: 'tcp', ports: [80] }];
  const editedRules = generateNftRules([manuallyEdited]);
  assert.match(editedRules, /93\.184\.216\.34/);
  assert.doesNotMatch(editedRules, /198\.51\.100\.7/);
});
