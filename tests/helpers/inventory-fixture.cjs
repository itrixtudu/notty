const crypto = require('node:crypto');
const hash = value => 'sha256:' + crypto.createHash('sha256').update(value).digest('hex');
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  return JSON.stringify(value);
}
function inventoryDocument(role, imageDigest, overrides = {}) {
  const metadataFiles = [{path: role === 'image' ? 'var/lib/dpkg/status' : 'package-lock.json', sha256: hash('metadata fixture'), kind: role === 'image' ? 'dpkg' : 'npm-lock'}];
  const packages = [{SPDXID:'SPDXRef-Package',name:`${role}-fixture`,versionInfo:'1.0.0'}];
  const report = {schemaVersion:1,kind:'NoshInventoryCollection',role,
    collector:{name:'nosh-inventory',version:'1'},status:'complete',
    input: role === 'image' ? {imageDigest} : {metadataDigest:hash(canonical(metadataFiles))},
    exclusions:[],gaps:[],limitations:['Package metadata only.'],metadataFiles,
    counts:{metadataFiles:1,packages:1},...overrides};
  return {spdxVersion:'SPDX-2.3',name:`${role}-fixture`,packages,
    annotations:[{annotationType:'OTHER',annotator:'Tool: nosh-inventory-1',annotationDate:'1970-01-01T00:00:00Z',
      comment:'nosh-inventory-collection:'+JSON.stringify(report)}]};
}
module.exports = {inventoryDocument};
