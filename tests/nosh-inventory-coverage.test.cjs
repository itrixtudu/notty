const assert = require('node:assert/strict');
const test = require('node:test');
const { inventoryDocument } = require('./helpers/inventory-fixture.cjs');
const image = 'sha256:' + 'a'.repeat(64);

async function fixture() {
  const sbom = await import('../lib/guard/review/sbom.js');
  const { createScope, createStableId } = await import('../lib/guard/review/ids.js');
  const scope = createScope({class:'runtime',projectKey:'inventory-test',
    subjectId:createStableId('subject','inventory-test'),imageDigest:image,
    workspaceDigest:'sha256:'+'b'.repeat(64),target:null});
  const graph = (role, document) => sbom.sbomGraphRecords({role,scope,digest:'sha256:'+'c'.repeat(64),
    sbom:sbom.normalizeSbomDocument(document)});
  return {sbom,graph};
}

test('external or empty SPDX does not manufacture inventory coverage', async () => {
  const {graph} = await fixture();
  for (const packages of [[],[{SPDXID:'SPDXRef-a',name:'unverified'}]]) {
    const result = graph('source',{spdxVersion:'SPDX-2.3',packages});
    assert.equal(result.coverage.status,'degraded');
    assert.equal(result.coverage.blocking,true);
    assert.match(result.coverage.gaps[0],/no collection report/);
  }
});

test('collection report binds source metadata and exact image; unmanaged limitation is visible', async () => {
  const {graph} = await fixture();
  const source = graph('source',inventoryDocument('source',image));
  assert.equal(source.coverage.blocking,false);
  assert.ok(source.sourceNode.properties.collection.limitations.length);
  assert.ok(!Object.hasOwn(source.sourceNode.properties.collection,'metadataFiles'));
  assert.match(source.sourceNode.properties.collection.reportDigest,/^sha256:/);
  const wrong = graph('image',inventoryDocument('image','sha256:'+'d'.repeat(64)));
  assert.equal(wrong.coverage.blocking,true);
  assert.match(wrong.coverage.gaps.join(' '),/reviewed image/);
  assert.equal(graph('image',inventoryDocument('source',image)).coverage.blocking,true);
});

test('tampered metadata, ambiguous reports, and false complete states are rejected', async () => {
  const {sbom} = await fixture();
  const mutate = change => {
    const doc=inventoryDocument('source',image);
    const report=JSON.parse(doc.annotations[0].comment.split('nosh-inventory-collection:')[1]);
    change(report);
    doc.annotations[0].comment='nosh-inventory-collection:'+JSON.stringify(report);
    return doc;
  };
  assert.throws(()=>sbom.normalizeSbomDocument(mutate(r=>r.metadataFiles[0].sha256='sha256:'+'f'.repeat(64))),/digest/);
  assert.throws(()=>sbom.normalizeSbomDocument(mutate(r=>r.metadataFiles[0].path='../escape')),/metadata binding/);
  assert.throws(()=>sbom.normalizeSbomDocument(mutate(r=>r.gaps.push({code:'truncated',message:'Truncated',blocking:true}))),/blocking gaps/);
  assert.throws(()=>sbom.normalizeSbomDocument(mutate(r=>r.counts.packages=0)),/counts/);
  const empty=mutate(r=>r.counts.packages=0); empty.packages=[];
  assert.throws(()=>sbom.normalizeSbomDocument(empty),/no identifiable packages/);
  const ambiguous=inventoryDocument('source',image); ambiguous.annotations.push(ambiguous.annotations[0]);
  assert.throws(()=>sbom.normalizeSbomDocument(ambiguous),/ambiguous/);
});

test('incomplete collector output stays reviewable with blocking coverage', async () => {
  const {graph} = await fixture();
  const result=graph('image',inventoryDocument('image',image,{status:'incomplete',
    gaps:[{code:'missing-db',message:'Missing package database',blocking:true}]}));
  assert.equal(result.coverage.blocking,true);
  assert.deepEqual(result.coverage.gaps,['Missing package database']);
});
