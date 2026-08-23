'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function switchDocument(collab) {
  return {
    schemaVersion: 1,
    switches: { collab },
  };
}

function createFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'notty-runtime-config-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const paths = {
    builtinPath: path.join(root, 'app', 'config', 'config.json'),
    userPath: path.join(root, 'config-home', 'notty', 'config.json'),
    workspacePath: path.join(root, 'workspace', '.notty', 'config.json'),
    explicitPath: path.join(root, 'explicit.json'),
  };
  writeJson(paths.builtinPath, switchDocument(false));
  return { root, paths };
}

test('runtime collab config layers resolve from builtin through explicit config', async (t) => {
  const { resolveRuntimeConfig } = await import('../lib/runtimeConfig.js');
  const { paths } = createFixture(t);

  let resolved = resolveRuntimeConfig({
    ...paths,
    env: {},
  });
  assert.equal(resolved.switches.collab, false);
  assert.equal(resolved.sources.collab, 'builtin');

  writeJson(paths.userPath, switchDocument(true));
  resolved = resolveRuntimeConfig({ ...paths, env: {} });
  assert.equal(resolved.switches.collab, true);
  assert.equal(resolved.sources.collab, 'user');

  writeJson(paths.workspacePath, switchDocument(false));
  resolved = resolveRuntimeConfig({ ...paths, env: {} });
  assert.equal(resolved.switches.collab, false);
  assert.equal(resolved.sources.collab, 'workspace');

  writeJson(paths.explicitPath, switchDocument(true));
  resolved = resolveRuntimeConfig({
    ...paths,
    argv: ['--config', paths.explicitPath],
    env: {},
  });
  assert.equal(resolved.switches.collab, true);
  assert.equal(resolved.sources.collab, 'explicit');
  assert.equal(resolved.paths.explicit, paths.explicitPath);
});

test('environment overrides files and the last CLI collab switch wins', async (t) => {
  const { resolveRuntimeConfig } = await import('../lib/runtimeConfig.js');
  const { paths } = createFixture(t);
  writeJson(paths.workspacePath, switchDocument(true));

  const fromEnvironment = resolveRuntimeConfig({
    ...paths,
    env: { NOTTY_COLLAB_ENABLED: 'off' },
  });
  assert.equal(fromEnvironment.switches.collab, false);
  assert.equal(fromEnvironment.sources.collab, 'environment');

  const enabledByCli = resolveRuntimeConfig({
    ...paths,
    argv: ['--no-collab', '--collab'],
    env: { NOTTY_COLLAB_ENABLED: 'false' },
  });
  assert.equal(enabledByCli.switches.collab, true);
  assert.equal(enabledByCli.sources.collab, 'cli');

  const disabledByCli = resolveRuntimeConfig({
    ...paths,
    argv: ['--collab', '--no-collab'],
    env: { NOTTY_COLLAB_ENABLED: 'true' },
  });
  assert.equal(disabledByCli.switches.collab, false);
  assert.equal(disabledByCli.sources.collab, 'cli');
});

test('runtime collab switches reject malformed config and invalid values', async (t) => {
  const { resolveRuntimeConfig } = await import('../lib/runtimeConfig.js');
  const { paths } = createFixture(t);

  const invalidDocuments = [
    [{ schemaVersion: 2, switches: { collab: true } }, /schemaVersion must be 1/],
    [{ schemaVersion: 1, switches: [] }, /switches must be an object/],
    [{ schemaVersion: 1, switches: { collab: 'yes' } }, /switches\.collab must be a boolean/],
    [{ schemaVersion: 1, switches: { unknown: true } }, /unknown switch "unknown"/],
  ];

  for (const [document, expected] of invalidDocuments) {
    writeJson(paths.workspacePath, document);
    assert.throws(
      () => resolveRuntimeConfig({ ...paths, env: {} }),
      expected,
    );
  }

  fs.writeFileSync(paths.workspacePath, '{', 'utf8');
  assert.throws(
    () => resolveRuntimeConfig({ ...paths, env: {} }),
    /invalid Notty config/,
  );

  fs.rmSync(paths.workspacePath);
  assert.throws(
    () => resolveRuntimeConfig({
      ...paths,
      env: { NOTTY_COLLAB_ENABLED: 'sometimes' },
    }),
    /NOTTY_COLLAB_ENABLED must be one of/,
  );
});

test('resolved collab state is mirrored into the server environment', async (t) => {
  const {
    applyRuntimeConfigToEnv,
    resolveRuntimeConfig,
    runtimeHelp,
  } = await import('../lib/runtimeConfig.js');
  const { paths } = createFixture(t);
  const environment = {};
  const resolved = resolveRuntimeConfig({
    ...paths,
    argv: ['--collab'],
    env: environment,
  });

  assert.equal(applyRuntimeConfigToEnv(resolved, environment), environment);
  assert.equal(environment.NOTTY_COLLAB_ENABLED, 'true');
  assert.match(runtimeHelp(), /--collab/);
  assert.match(runtimeHelp(), /--no-collab/);
});

test('runtime option values are required and help bypasses runtime validation', async (t) => {
  const {
    parseRuntimeArgs,
    resolveRuntimeConfig,
  } = await import('../lib/runtimeConfig.js');
  const { paths } = createFixture(t);

  assert.throws(() => parseRuntimeArgs(['--config=']), /--config requires a value/);
  assert.throws(() => parseRuntimeArgs(['--config', '-h']), /--config requires a value/);
  assert.throws(() => parseRuntimeArgs(['--mode=']), /--mode requires a value/);

  fs.writeFileSync(paths.builtinPath, '{', 'utf8');
  const help = resolveRuntimeConfig({
    ...paths,
    argv: ['--help'],
    env: {
      NOTTY_COLLAB_ENABLED: 'true',
      NOTTY_MODE: 'stdio',
    },
  });
  assert.equal(help.help, true);
});

test('an explicit duplicate config path still receives explicit precedence', async (t) => {
  const { resolveRuntimeConfig } = await import('../lib/runtimeConfig.js');
  const { paths } = createFixture(t);
  writeJson(paths.workspacePath, switchDocument(true));

  const resolved = resolveRuntimeConfig({
    ...paths,
    argv: ['--config', paths.workspacePath],
    env: {},
  });
  assert.equal(resolved.switches.collab, true);
  assert.equal(resolved.sources.collab, 'explicit');
});

test('required builtin and explicit config paths must exist', async (t) => {
  const { resolveRuntimeConfig } = await import('../lib/runtimeConfig.js');
  const { paths } = createFixture(t);

  fs.rmSync(paths.builtinPath);
  assert.throws(
    () => resolveRuntimeConfig({ ...paths, env: {} }),
    /Notty config does not exist/,
  );

  writeJson(paths.builtinPath, switchDocument(false));
  assert.throws(
    () => resolveRuntimeConfig({
      ...paths,
      argv: ['--config', paths.explicitPath],
      env: {},
    }),
    /Notty config does not exist/,
  );
});
