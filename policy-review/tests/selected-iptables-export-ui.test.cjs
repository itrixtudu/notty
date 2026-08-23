'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const pagePath = path.resolve(
  __dirname,
  '../components/policy-review/PolicyReviewPage.js',
);

test('selected iptables UI is an unsigned, selected-only, non-authoritative sketch', () => {
  const page = fs.readFileSync(pagePath, 'utf8');
  const start = page.indexOf('function SelectedIptablesExport');
  const end = page.indexOf('function MultiSelectionSummary', start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const component = page.slice(start, end);

  assert.match(page, /createSelectedIptablesExport/);
  assert.match(component, /proposalIds,/);
  assert.match(component, /decisions: state\.decisions/);
  assert.match(component, /sourceIpv4: sourceIpv4\.trim\(\)/);
  assert.match(component, /uplinkInterface: uplinkInterface\.trim\(\)/);
  assert.match(component, /includeMasquerade,/);
  assert.match(component, /Unsigned selected-rule iptables sketch/);
  assert.match(component, /adds no implicit RFC1918 or DNS-port/);
  assert.match(component, /Generate unsigned sketch/);
  assert.match(component, /preview\.mappings|generatedExport\.mappings/);
  assert.match(component, /preview\.warnings|generatedExport\.warnings/);
  assert.match(component, /Download unsigned print-only sketch/);
  assert.match(component, /not a DecisionSet, PolicyIR, target projection/);
  assert.doesNotMatch(component, /dispatch\s*\(/);
});

test('shell download uses a sanitized filename, shell MIME, and revokes its object URL', () => {
  const page = fs.readFileSync(pagePath, 'utf8');

  assert.match(page, /safeDownloadFilename\(generatedExport\.filename/);
  assert.match(page, /text\/x-shellscript;charset=utf-8/);
  assert.match(page, /URL\.revokeObjectURL\(url\)/);
});
