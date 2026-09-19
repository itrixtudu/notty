const assert = require('node:assert/strict');
const test = require('node:test');
const crypto = require('node:crypto');

function rules(kind, count) {
  const used = new Set();
  return Array.from({ length: count }, (_, i) => {
    let id = `${kind}-${i}`;
    while (true) {
      const hash = crypto.createHash('sha256').update('nosh-egress-rule-id-v1\0').update(id).digest();
      let numeric = 0;
      for (let offset = 0; !numeric && offset < 32; offset += 4) numeric = hash.readUInt32BE(offset);
      if (!used.has(numeric)) { used.add(numeric); break; }
      id += '-retry';
    }
    return { id, peer: { kind, value: kind === 'ipv4-cidr'
      ? `198.18.${i >> 8}.${i & 255}/32`
      : kind === 'ipv6-cidr' ? `2001:db8::${(i + 1).toString(16)}/128` : `d${i}.example` },
      transport: { protocol: 'tcp', ports: [443] } };
  });
}
async function implementations() {
  const { assertEbpfRuleCapacity } = await import('../lib/guard/review/policy-compilers.js');
  const { renderEbpfEgressManifest } = await import('../lib/guardd/enforcement-backend.js');
  return [assertEbpfRuleCapacity, rules => renderEbpfEgressManifest(rules, ['192.0.2.53'], ['192.0.2.1/32'])];
}
for (const [kind, limit] of [['ipv4-cidr', 16384], ['ipv6-cidr', 16384], ['fqdn', 8192]]) {
  test(`${kind}: compiler and renderer accept N-1/N and reject N+1 (${limit})`, async () => {
    const entries = rules(kind, limit + 1);
    for (const check of await implementations()) {
      assert.doesNotThrow(() => check(entries.slice(0, limit - 1)));
      assert.doesNotThrow(() => check(entries.slice(0, limit)));
      assert.throws(() => check(entries), /map limit/);
    }
  });
}
test('capacity counts expanded ports; exact and wildcard DNS share eight slots', async () => {
  for (const check of await implementations()) {
    const ip = rules('ipv4-cidr', 1)[0];
    ip.transport.ports = Array.from({ length: 16384 }, (_, i) => i + 1);
    assert.doesNotThrow(() => check([ip]));
    ip.transport.ports.push(16385);
    assert.throws(() => check([ip]), /map limit/);
    const exact = rules('fqdn', 1)[0];
    exact.peer.value = 'host.capacity.example';
    const wildcard = { ...exact, id: 'wildcard', peer: { kind: 'fqdn', value: '*.capacity.example' },
      transport: { protocol: 'tcp', ports: [80, 81, 82, 83] } };
    exact.transport.ports = [443, 444, 445];
    assert.doesNotThrow(() => check([exact, wildcard]));
    exact.transport.ports.push(446);
    assert.doesNotThrow(() => check([exact, wildcard]));
    exact.transport.ports.push(447);
    assert.throws(() => check([exact, wildcard]), /8-rule slot limit/);
  }
});
test('full-capacity socket proof builds both policies and rejects overflow', async () => {
  const { createPocPolicies } = await import('../scripts/nosh-egress-poc.mjs');
  const result = createPocPolicies('172.30.0.2', '172.30.0.3', '172.30.0.1', 16384);
  for (const phase of Object.values(result.phases)) assert.equal(phase.policy.rules.length, 16384);
  assert.throws(() => createPocPolicies('172.30.0.2', '172.30.0.3', '172.30.0.1', 16385), /rule count/);
});
test('review graph limits accept N-1/N and reject N+1 independently', async () => {
  const { assertReviewableSemanticGraph, REVIEW_VIEW_LIMITS } = await import('../lib/guard/review/bundle-store.js');
  for (const [role, limit] of Object.entries(REVIEW_VIEW_LIMITS)) {
    if (role === 'bytes') continue;
    const graph = Object.fromEntries(Object.keys(REVIEW_VIEW_LIMITS).filter(key => key !== 'bytes').map(key => [key, []]));
    for (const size of [limit - 1, limit]) {
      graph[role] = Array(size).fill(null);
      assert.doesNotThrow(() => assertReviewableSemanticGraph(graph));
    }
    graph[role].push(null);
    assert.throws(() => assertReviewableSemanticGraph(graph), /review limit/);
  }
});
