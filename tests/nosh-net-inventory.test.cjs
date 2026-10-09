'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const wrapper = path.resolve(__dirname, '../scripts/nosh-net-review.sh');
const collector = path.resolve(__dirname, '../scripts/nosh-inventory.py');
const IMAGE = `sha256:${'b'.repeat(64)}`;
const TOOLING = `sha256:${'a'.repeat(64)}`;
const hasPython = spawnSync('python3', ['--version']).status === 0;

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'nosh-net-inventory-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const workspace = path.join(root, 'workspace with spaces');
  const state = path.join(root, 'state');
  const bin = path.join(root, 'bin');
  const config = path.join(root, 'config');
  for (const directory of [workspace, bin, config]) fs.mkdirSync(directory);
  fs.writeFileSync(path.join(workspace, 'package.json'), JSON.stringify({
    name: 'fixture-project', version: '1.0.0', dependencies: { dependency: '*' },
  }));
  const writeLock = version => fs.writeFileSync(path.join(workspace, 'package-lock.json'), JSON.stringify({
    name: 'fixture-project', lockfileVersion: 3, packages: {
      '': { name: 'fixture-project', version: '1.0.0' },
      'node_modules/dependency': { version },
    },
  }));
  writeLock('1.0.0');
  const archive = path.join(root, 'fixture.tar');
  const tar = spawnSync('python3', ['-I', '-S', '-c', `
import io,sys,tarfile
with tarfile.open(sys.argv[1], 'w') as archive:
    for name, data in [
        ('var/lib/dpkg/status', b'Package: fixture-package\\nStatus: install ok installed\\nVersion: 1.0-1\\nArchitecture: amd64\\n'),
        ('usr/lib/os-release', b'ID=debian\\n')]:
        entry=tarfile.TarInfo(name);entry.size=len(data);archive.addfile(entry,io.BytesIO(data))
    entry=tarfile.TarInfo('etc/os-release');entry.type=tarfile.SYMTYPE
    entry.linkname='../usr/lib/os-release';archive.addfile(entry)
`, archive], { encoding: 'utf8' });
  assert.equal(tar.status, 0, tar.stderr);
  const calls = path.join(root, 'calls.jsonl');
  fs.writeFileSync(calls, '');
  fs.writeFileSync(path.join(bin, 'docker'), `#!${process.execPath}
const fs=require('node:fs');const {spawnSync}=require('node:child_process');
const args=process.argv.slice(2);const value=flag=>args[args.indexOf(flag)+1];
fs.appendFileSync(process.env.INVENTORY_CALLS,JSON.stringify(args)+'\\n');
const fail=message=>{process.stderr.write(message);process.exit(99);};
if(args[0]==='image'&&args[1]==='inspect'){
  if(args.includes('--format'))process.stdout.write(value('--format').includes('policy-tooling-abi')?'${TOOLING}|1':args.at(-1));
  else process.stdout.write(JSON.stringify([{Id:'${IMAGE}',Config:{Volumes:null}}]));
}else if(args[0]==='run'){
  if(value('--network')!=='none'||value('--pull')!=='never')fail('collector must remain offline');
  if(value('--entrypoint')!=='/usr/bin/python3')fail('unexpected collector entrypoint');
  if(args.includes('--cidfile'))fs.writeFileSync(value('--cidfile'),'e'.repeat(64));
  const mounts=new Map();
  args.forEach((arg,i)=>{if(arg==='--mount'){
    const fields=Object.fromEntries(args[i+1].split(',').map(part=>{const n=part.indexOf('=');return n===-1?[part,true]:[part.slice(0,n),part.slice(n+1)];}));
    mounts.set(fields.dst,fields.src);
  }});
  const index=args.indexOf('/app/scripts/nosh-inventory.py');if(index<0)fail('unexpected program');
  const command=args.slice(index+1).map(arg=>mounts.get(arg)||arg);
  const child=spawnSync('python3',['-I','-S',process.env.INVENTORY_COLLECTOR,...command],{encoding:'utf8'});
  process.stdout.write(child.stdout||'');process.stderr.write(child.stderr||'');process.exit(child.status??99);
}else if(args[0]==='create'){
  fs.writeFileSync(process.env.INVENTORY_CLIENT,'d'.repeat(64));
  fs.writeFileSync(value('--cidfile'),'d'.repeat(64));process.stdout.write('d'.repeat(64));
}else if(args[0]==='container'&&args[1]==='inspect'){
  if(args.includes('--format'))process.stdout.write('${IMAGE}|created|0');
  else process.exit(args.at(-1)==='d'.repeat(64)&&fs.existsSync(process.env.INVENTORY_CLIENT)?0:1);
}else if(args[0]==='export')fs.copyFileSync(process.env.INVENTORY_ARCHIVE,value('--output'));
else if(args[0]==='rm')fs.rmSync(process.env.INVENTORY_CLIENT,{force:true});
else fail('unexpected Docker operation '+args.join(' '));
`, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, 'jq'), `#!${process.execPath}
const fs=require('node:fs');const args=process.argv.slice(2);const vars={};let i=0;let nullInput=false;
while(i<args.length&&args[i].startsWith('-')){
 if(args[i]==='--arg'||args[i]==='--argjson'){vars[args[i+1]]=args[i]==='--argjson'?JSON.parse(args[i+2]):args[i+2];i+=3;}
 else {if(args[i].includes('n'))nullInput=true;i++;}
}
const expression=args[i++];const doc=nullInput?null:JSON.parse(fs.readFileSync(args[i]||0,'utf8'));let result;
switch(expression){
 case '.[0].Id':result=doc[0].Id;break;
 case '.[0].Config.Volumes // {} | length == 0':result=Object.keys(doc[0].Config.Volumes||{}).length===0;break;
 case '.image == $image and .tooling == $tooling':result=doc.image===vars.image&&doc.tooling===vars.tooling;break;
 case '.directory':result=doc.directory;break;
 case '.status == "complete" and .input.imageDigest == $image and .sbomDigest == $digest':result=doc.status==='complete'&&doc.input.imageDigest===vars.image&&doc.sbomDigest===vars.digest;break;
 case '{schemaVersion:1,image:$image,tooling:$tooling,directory:$directory}':result={schemaVersion:1,...vars};break;
 case '{ready:$ready,source:$source,image:$image}':result=vars;break;
 default:process.stderr.write('unsupported fixture jq expression: '+expression);process.exit(99);
}
process.stdout.write((typeof result==='string'?result:JSON.stringify(result))+'\\n');
if(result===false||result===null||result===undefined)process.exit(1);
`, { mode: 0o755 });
  return { root, workspace, state, calls, writeLock,
    run() {
      const result = spawnSync('bash', [wrapper, 'inventory', '--workdir', workspace, '--image', IMAGE], {
        encoding: 'utf8', timeout: 15000,
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}`,
          XDG_CONFIG_HOME: config, NOSH_PROFILE_REVIEW_IMAGE_CONFIG: path.join(config, 'images.conf'),
          NOSH_POLICY_TOOLING_IMAGE: TOOLING, NOSH_PROFILE_REVIEW_STATE_ROOT: state,
          NOSH_NET_REVIEW_DOCKER_BIN: path.join(bin, 'docker'), INVENTORY_CALLS: calls,
          INVENTORY_CLIENT: path.join(root, 'client'), INVENTORY_COLLECTOR: collector,
          INVENTORY_ARCHIVE: archive },
      });
      assert.equal(result.status, 0, result.stdout + result.stderr);
      return JSON.parse(result.stdout);
    },
    commands() { return fs.readFileSync(calls, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse); },
  };
}

function privateFile(file) {
  const info = fs.lstatSync(file);
  assert.equal(info.mode & 0o777, 0o600, file);
  assert.equal(info.uid, process.getuid(), file);
  assert.equal(info.nlink, 1, file);
  assert.ok(info.isFile() && !info.isSymbolicLink(), file);
}

test('net inventory reuses the exact image while collecting and binding current source metadata', { skip: !hasPython }, async t => {
  const { loadSbom } = await import('../lib/guard/review/sbom.js');
  const f = fixture(t);
  const first = f.run();
  assert.equal(first.ready, true);
  const indexPath = path.join(f.state, `inventory-${crypto.createHash('sha256').update(f.workspace).digest('hex')}.json`);
  privateFile(indexPath);
  const index = JSON.parse(fs.readFileSync(indexPath, 'utf8'));
  assert.equal(index.image, IMAGE);
  assert.equal(index.tooling, TOOLING);
  assert.equal(first.source, path.join(index.directory, 'source.spdx.json'));
  assert.equal(first.image, path.join(index.directory, 'image.spdx.json'));
  for (const role of ['source', 'image']) {
    privateFile(path.join(index.directory, `${role}.spdx.json`));
    privateFile(path.join(index.directory, `${role}.collection.json`));
  }
  const source = (await loadSbom(first.source)).normalized;
  const image = (await loadSbom(first.image)).normalized;
  assert.equal(source.collection.status, 'complete');
  assert.equal(image.collection.status, 'complete');
  assert.equal(image.collection.input.imageDigest, IMAGE);
  assert.equal(image.packages[0].name, 'fixture-package');
  const second = f.run();
  assert.notEqual(first.source, second.source);
  assert.deepEqual(fs.readFileSync(second.image), fs.readFileSync(first.image));
  assert.equal((await loadSbom(second.source)).normalized.collection.input.metadataDigest,
    source.collection.input.metadataDigest);
  f.writeLock('2.0.0');
  const third = f.run();
  const changed = (await loadSbom(third.source)).normalized;
  assert.notEqual(changed.collection.input.metadataDigest, source.collection.input.metadataDigest);
  assert.equal(changed.packages.find(entry => entry.name === 'dependency').version, '2.0.0');
  assert.equal(f.commands().filter(args => args[0] === 'export').length, 1);
  assert.equal(f.commands().filter(args => args[0] === 'run' && args.includes('source')).length, 3);
  assert.equal(f.commands().some(args => ['pull', 'start', 'exec', 'build'].includes(args[0])), false);
  assert.equal(fs.existsSync(path.join(f.root, 'client')), false);
  assert.equal(fs.statSync(f.state).mode & 0o777, 0o700);
});

test('tampered cached image inventory is regenerated instead of reused', { skip: !hasPython }, t => {
  const f = fixture(t);
  const first = f.run();
  fs.appendFileSync(first.image, '\n');
  const second = f.run();
  assert.equal(second.ready, true);
  assert.equal(f.commands().filter(args => args[0] === 'export').length, 2);
  const report = JSON.parse(fs.readFileSync(path.join(path.dirname(second.image), 'image.collection.json'), 'utf8'));
  assert.equal(report.sbomDigest, `sha256:${crypto.createHash('sha256').update(fs.readFileSync(second.image)).digest('hex')}`);
});
