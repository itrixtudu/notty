'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const dockerfile = fs.readFileSync(
  path.join(appRoot, 'Dockerfile.nosh'),
  'utf8',
);

function parseStages(source) {
  const headers = [...source.matchAll(
    /^FROM\s+(\S+)\s+AS\s+([A-Za-z0-9_.-]+)\s*$/gmi,
  )];
  const stages = new Map();

  for (const [index, match] of headers.entries()) {
    const next = headers[index + 1];
    stages.set(match[2].toLowerCase(), {
      base: match[1].toLowerCase(),
      body: source.slice(match.index + match[0].length, next?.index),
    });
  }

  return { headers, stages };
}

function stageAncestors(stages, target) {
  const ancestors = [];
  let current = target;

  while (stages.has(current)) {
    assert.ok(
      !ancestors.includes(current),
      `Docker stage dependency cycle at ${current}`,
    );
    ancestors.push(current);
    current = stages.get(current).base;
  }

  return ancestors;
}

test('Ollama is pinned in an isolated artifact stage and copied narrowly', () => {
  const { stages } = parseStages(dockerfile);
  const globalArguments = dockerfile.slice(0, dockerfile.indexOf('\nFROM '));
  const dist = stages.get('ollama-dist');
  const ollama = stages.get('ollama');

  assert.ok(dist, 'missing internal ollama-dist stage');
  assert.ok(ollama, 'missing public ollama stage');
  assert.equal(dist.base, '${node_image}');
  assert.equal(ollama.base, 'agent');

  assert.match(globalArguments, /^ARG OLLAMA_VERSION=0\.31\.2$/m);
  assert.match(
    globalArguments,
    /^ARG OLLAMA_SHA256_AMD64=2c88f0f31a959bac5a3cad4cc5296ec568551d4aa79f548f554adb2b575b3133$/m,
  );
  assert.match(
    globalArguments,
    /^ARG OLLAMA_SHA256_ARM64=07a0adfcf3ed48ff110e2a3bcec897ca4d3f77d6f817d6ff63e83debfd102a31$/m,
  );

  assert.match(dist.body, /^\s+zstd \\$/m);
  assert.match(
    dist.body,
    /releases\/download\/v\$\{OLLAMA_VERSION\}\/ollama-linux-\$\{arch\}\.tar\.zst/,
  );
  assert.match(dist.body, /sha256sum --check --strict/);
  assert.match(dist.body, /tar --use-compress-program=unzstd/);
  assert.match(dist.body, /ollama --version/);
  assert.doesNotMatch(dist.body, /^COPY\s/m);

  const copiedPaths = [...ollama.body.matchAll(
    /^COPY --from=ollama-dist\s+(\S+)\s+(\S+)$/gm,
  )].map((match) => match.slice(1));
  assert.deepEqual(copiedPaths, [
    ['/usr/local/bin/ollama', '/usr/local/bin/ollama'],
    ['/usr/local/lib/ollama', '/usr/local/lib/ollama'],
  ]);
  assert.doesNotMatch(
    ollama.body,
    /^COPY --from=ollama-dist \/usr\/local\/?\s/m,
    'the public image must not copy the complete artifact filesystem',
  );
  assert.match(ollama.body, /io\.notty\.feature\.ollama="true"/);
  assert.match(
    ollama.body,
    /io\.notty\.feature\.ollama\.version="\$\{OLLAMA_VERSION\}"/,
  );

  const rootUser = ollama.body.indexOf('USER root');
  const firstCopy = ollama.body.indexOf('COPY --from=ollama-dist');
  const restoredUser = ollama.body.lastIndexOf('USER $USERNAME');
  const restoredWorkdir = ollama.body.lastIndexOf('WORKDIR /app');
  assert.ok(rootUser >= 0 && firstCopy > rootUser);
  assert.ok(restoredUser > firstCopy);
  assert.ok(restoredWorkdir > restoredUser);
});

test('all existing public image targets remain Ollama-free', () => {
  const { headers, stages } = parseStages(dockerfile);
  const expectedParents = new Map([
    ['base', '${node_image}'],
    ['local', 'base'],
    ['agent', 'base'],
    ['ansi-dos', 'base'],
    ['hardware', 'ansi-dos'],
    ['cdev', 'ansi-dos'],
    ['full', 'cdev'],
  ]);

  for (const [target, parent] of expectedParents) {
    assert.equal(stages.get(target)?.base, parent, `${target} stage parent`);
    assert.ok(
      !stageAncestors(stages, target).some(
        (stage) => stage === 'ollama' || stage === 'ollama-dist',
      ),
      `${target} must not inherit an Ollama stage`,
    );
  }

  const base = stages.get('base').body;
  assert.match(base, /io\.notty\.feature\.ollama="false"/);
  assert.doesNotMatch(
    base,
    /OLLAMA_(?:VERSION|SHA256)|ollama-linux|\/usr\/local\/(?:bin|lib)\/ollama|\bzstd\b/,
  );
  assert.equal(
    headers.at(-1)[2].toLowerCase(),
    'full',
    'a target-less Docker build must still finish at an Ollama-free stage',
  );
});
