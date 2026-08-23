#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';

const PROGRAM = 'render-nosh-guard-install';
const PREFIX_MARKER = '@@NOSH_GUARD_PREFIX@@';
const DEFAULT_PREFIX = '/usr/local';

const textArtifacts = Object.freeze([
  {
    source: 'payload/templates/deploy/host/nosh-gateway',
    output: 'deploy/host/nosh-gateway',
    mode: 0o755,
  },
  {
    source: 'payload/templates/deploy/host/nosh-guard',
    output: 'deploy/host/nosh-guard',
    mode: 0o755,
  },
  {
    source: 'payload/templates/deploy/host/nosh-guardd',
    output: 'deploy/host/nosh-guardd',
    mode: 0o755,
  },
  {
    source: 'payload/templates/deploy/host/nosh-guard-fail-closed',
    output: 'deploy/host/nosh-guard-fail-closed',
    mode: 0o755,
  },
  {
    source: 'payload/templates/deploy/host/nosh-guard-tetragon-verify',
    output: 'deploy/host/nosh-guard-tetragon-verify',
    mode: 0o755,
  },
  {
    source: 'payload/templates/deploy/systemd/nosh-guard-bpffs.service',
    output: 'deploy/systemd/nosh-guard-bpffs.service',
    mode: 0o644,
  },
  {
    source: 'payload/templates/deploy/systemd/nosh-guardd.service',
    output: 'deploy/systemd/nosh-guardd.service',
    mode: 0o644,
  },
  {
    source: 'payload/templates/libexec/nosh-guard/nosh-guard-host-verify',
    output: 'libexec/nosh-guard/nosh-guard-host-verify',
    mode: 0o755,
  },
]);

const jsonArtifacts = Object.freeze([
  {
    source: 'payload/config/nosh-guard/adapters.json',
    output: 'config/nosh-guard/adapters.json',
    mode: 0o644,
    topLevelKeys: ['adapters', 'schemaVersion'],
    transform(document, prefix) {
      const egress = findNamedAdapter(document, 'nosh-egress', this.source);
      for (const operation of ['health', 'attach']) {
        replaceJsonString(
          egress,
          [operation, 'command'],
          `${DEFAULT_PREFIX}/libexec/nosh-guard/nosh-egress-loader`,
          `${prefix}/libexec/nosh-guard/nosh-egress-loader`,
          this.source,
        );
      }

      const l4 = findNamedAdapter(document, 'nosh-l4', this.source);
      replaceJsonString(
        l4,
        ['health', 'command'],
        `${DEFAULT_PREFIX}/libexec/nosh-guard/nosh-l4-loader`,
        `${prefix}/libexec/nosh-guard/nosh-l4-loader`,
        this.source,
      );
      replaceJsonString(
        l4,
        ['attach', 'command'],
        `${DEFAULT_PREFIX}/libexec/nosh-guard/nosh-l4-loader`,
        `${prefix}/libexec/nosh-guard/nosh-l4-loader`,
        this.source,
      );

      const tetragon = findNamedAdapter(
        document,
        'tetragon-enforce-policy',
        this.source,
      );
      replaceJsonString(
        tetragon,
        ['verify', 'command'],
        'nosh-guard-tetragon-verify',
        `${prefix}/bin/nosh-guard-tetragon-verify`,
        this.source,
      );
    },
  },
  {
    source: 'payload/config/nosh-guard/versions.json',
    output: 'config/nosh-guard/versions.json',
    mode: 0o644,
    topLevelKeys: [
      'inspektorGadget',
      'noshEgress',
      'noshL4',
      'schemaVersion',
      'supplyChain',
      'tetragon',
    ],
    transform(document, prefix) {
      replaceJsonString(
        document,
        ['noshEgress', 'loaderPath'],
        `${DEFAULT_PREFIX}/libexec/nosh-guard/nosh-egress-loader`,
        `${prefix}/libexec/nosh-guard/nosh-egress-loader`,
        this.source,
      );
      replaceJsonString(
        document,
        ['noshL4', 'loaderPath'],
        `${DEFAULT_PREFIX}/libexec/nosh-guard/nosh-l4-loader`,
        `${prefix}/libexec/nosh-guard/nosh-l4-loader`,
        this.source,
      );
    },
  },
  {
    source: 'payload/config/nosh-build/adapters.json',
    output: 'config/nosh-build/adapters.json',
    mode: 0o644,
    topLevelKeys: ['adapters', 'kind', 'limitations', 'schemaVersion'],
    transform(document, prefix) {
      const build = findNamedAdapter(document, 'nosh-build', this.source);
      for (const operation of ['health', 'attach']) {
        replaceJsonString(
          build,
          [operation, 'command'],
          `${DEFAULT_PREFIX}/libexec/nosh-build/nosh-build-loader`,
          `${prefix}/libexec/nosh-build/nosh-build-loader`,
          this.source,
        );
      }

      const l4 = findNamedAdapter(document, 'nosh-l4', this.source);
      for (const operation of ['health', 'attach']) {
        replaceJsonString(
          l4,
          [operation, 'command'],
          `${DEFAULT_PREFIX}/libexec/nosh-guard/nosh-l4-loader`,
          `${prefix}/libexec/nosh-guard/nosh-l4-loader`,
          this.source,
        );
      }

      const url = findNamedAdapter(document, 'nosh-url', this.source);
      for (const operation of ['health', 'attach']) {
        replaceJsonString(
          url,
          [operation, 'command'],
          `${DEFAULT_PREFIX}/libexec/nosh-build/nosh-url-loader`,
          `${prefix}/libexec/nosh-build/nosh-url-loader`,
          this.source,
        );
      }
    },
  },
  {
    source: 'payload/config/nosh-build/versions.json',
    output: 'config/nosh-build/versions.json',
    mode: 0o644,
    topLevelKeys: [
      'buildkit',
      'kind',
      'noshBuild',
      'noshL4',
      'noshUrl',
      'schemaVersion',
      'supplyChain',
    ],
    transform(document, prefix) {
      replaceJsonString(
        document,
        ['noshBuild', 'loaderPath'],
        `${DEFAULT_PREFIX}/libexec/nosh-build/nosh-build-loader`,
        `${prefix}/libexec/nosh-build/nosh-build-loader`,
        this.source,
      );
      replaceJsonString(
        document,
        ['noshL4', 'loaderPath'],
        `${DEFAULT_PREFIX}/libexec/nosh-guard/nosh-l4-loader`,
        `${prefix}/libexec/nosh-guard/nosh-l4-loader`,
        this.source,
      );
      replaceJsonString(
        document,
        ['noshUrl', 'loaderPath'],
        `${DEFAULT_PREFIX}/libexec/nosh-build/nosh-url-loader`,
        `${prefix}/libexec/nosh-build/nosh-url-loader`,
        this.source,
      );
    },
  },
]);

const generatedArtifacts = Object.freeze([
  {
    output: 'sudoers/nosh-build-session.alias',
    mode: 0o644,
    render(prefix) {
      const guard = `${prefix}/bin/nosh-guard`;
      return `Cmnd_Alias NOSH_BUILD_SESSION = ${guard} build-session begin, ${guard} build-session finish, ${guard} build-session abort, ${guard} build-session exported\n`;
    },
  },
]);

function usage(stream = process.stdout) {
  stream.write(`Usage: ${PROGRAM} --prefix ABSOLUTE_PREFIX --source-root RELEASE_ROOT --output-dir EMPTY_DIR\n`);
}

function fail(message) {
  throw new Error(message);
}

function takeOptionValue(argv, index, option) {
  const argument = argv[index];
  if (argument === option) {
    if (!argv[index + 1]) {
      fail(`${option} requires a value`);
    }
    return { value: argv[index + 1], consumed: 2 };
  }
  if (argument.startsWith(`${option}=`)) {
    const value = argument.slice(option.length + 1);
    if (!value) {
      fail(`${option} requires a value`);
    }
    return { value, consumed: 1 };
  }
  return null;
}

function parseArguments(argv) {
  const options = new Map();
  for (let index = 0; index < argv.length;) {
    const argument = argv[index];
    if (argument === '-h' || argument === '--help') {
      return { help: true };
    }

    let matched = false;
    for (const option of ['--prefix', '--source-root', '--output-dir']) {
      const parsed = takeOptionValue(argv, index, option);
      if (!parsed) {
        continue;
      }
      if (options.has(option)) {
        fail(`${option} was provided more than once`);
      }
      options.set(option, parsed.value);
      index += parsed.consumed;
      matched = true;
      break;
    }
    if (!matched) {
      fail(`unknown option: ${argument}`);
    }
  }

  for (const option of ['--prefix', '--source-root', '--output-dir']) {
    if (!options.has(option)) {
      fail(`${option} is required`);
    }
  }
  return {
    help: false,
    prefix: options.get('--prefix'),
    sourceRoot: options.get('--source-root'),
    outputDir: options.get('--output-dir'),
  };
}

function validatePrefix(prefix) {
  if (!path.posix.isAbsolute(prefix)) {
    fail('prefix must be absolute');
  }
  if (/[^\x21-\x7e]/u.test(prefix)) {
    fail('prefix must not contain whitespace or control characters');
  }
  if (path.posix.normalize(prefix) !== prefix || prefix.endsWith('/')) {
    fail('prefix must be normalized without a trailing slash');
  }

  const components = prefix.slice(1).split('/');
  if (components.some((component) => !/^[A-Za-z0-9][A-Za-z0-9._+-]*$/u.test(component))) {
    fail('prefix contains an unsafe path component');
  }

  const broadSystemRoots = new Set([
    '/',
    '/bin',
    '/boot',
    '/dev',
    '/etc',
    '/home',
    '/lib',
    '/lib64',
    '/media',
    '/mnt',
    '/opt',
    '/proc',
    '/root',
    '/run',
    '/sbin',
    '/srv',
    '/sys',
    '/tmp',
    '/usr',
    '/var',
  ]);
  if (broadSystemRoots.has(prefix)) {
    fail(`prefix is a broad system root: ${prefix}`);
  }

  let cursor = '/';
  for (const component of components) {
    cursor = path.posix.join(cursor, component);
    let metadata;
    try {
      metadata = fs.lstatSync(cursor);
    } catch (error) {
      if (error?.code === 'ENOENT') {
        break;
      }
      throw error;
    }
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      fail(`prefix ancestor is not a real directory: ${cursor}`);
    }
    if (metadata.uid !== 0 || (metadata.mode & 0o022) !== 0) {
      fail(`prefix ancestor is not root-owned and protected: ${cursor}`);
    }
  }
}

function validateAbsoluteDirectory(directory, label, { empty = false } = {}) {
  if (!path.isAbsolute(directory) || path.normalize(directory) !== directory) {
    fail(`${label} must be an absolute normalized path`);
  }
  const metadata = fs.lstatSync(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail(`${label} must be a real directory`);
  }
  if (fs.realpathSync(directory) !== directory) {
    fail(`${label} must not traverse a symlink`);
  }
  if (empty && fs.readdirSync(directory).length !== 0) {
    fail(`${label} must be empty`);
  }
}

function listTree(root) {
  const files = [];
  const directories = [];

  function visit(relative) {
    const current = relative ? path.join(root, relative) : root;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const child = relative ? path.posix.join(relative, entry.name) : entry.name;
      const absolute = path.join(root, ...child.split('/'));
      const metadata = fs.lstatSync(absolute);
      if (metadata.isSymbolicLink()) {
        fail(`unsupported symlink in inventory: ${absolute}`);
      }
      if (metadata.isDirectory()) {
        directories.push(child);
        visit(child);
      } else if (metadata.isFile()) {
        if (metadata.nlink !== 1) {
          fail(`multiply linked source file: ${absolute}`);
        }
        files.push(child);
      } else {
        fail(`unsupported filesystem object in inventory: ${absolute}`);
      }
    }
  }

  visit('');
  return {
    files: files.sort(),
    directories: directories.sort(),
  };
}

function parentDirectories(relativePaths) {
  const directories = new Set();
  for (const relative of relativePaths) {
    let cursor = path.posix.dirname(relative);
    while (cursor !== '.') {
      directories.add(cursor);
      cursor = path.posix.dirname(cursor);
    }
  }
  return [...directories].sort();
}

function assertInventory(actual, expected, label) {
  if (JSON.stringify(actual.files) !== JSON.stringify(expected.files)
    || JSON.stringify(actual.directories) !== JSON.stringify(expected.directories)) {
    fail(`${label} has an unexpected inventory`);
  }
}

function checkRegularSource(sourceRoot, relative) {
  const absolute = path.join(sourceRoot, ...relative.split('/'));
  const metadata = fs.lstatSync(absolute);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
    fail(`source is not a singly linked regular file: ${relative}`);
  }
  return absolute;
}

function renderTextTemplate(source, prefix, relative) {
  const template = fs.readFileSync(source, 'utf8');
  const markers = template.match(/@@[^@\r\n]+@@/gu) || [];
  if (markers.length === 0) {
    fail(`template is missing ${PREFIX_MARKER}: ${relative}`);
  }
  if (markers.some((marker) => marker !== PREFIX_MARKER)) {
    fail(`template contains an unknown marker: ${relative}`);
  }
  const rendered = template.replaceAll(PREFIX_MARKER, prefix);
  if (rendered.includes('@@')) {
    fail(`template contains an unresolved marker: ${relative}`);
  }
  return rendered;
}

function assertPlainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
}

function assertTopLevelKeys(document, expected, relative) {
  assertPlainObject(document, relative);
  const actual = Object.keys(document).sort();
  if (JSON.stringify(actual) !== JSON.stringify([...expected].sort())) {
    fail(`JSON document has unexpected top-level fields: ${relative}`);
  }
  if (document.schemaVersion !== 1) {
    fail(`JSON document has an unsupported schemaVersion: ${relative}`);
  }
}

function findNamedAdapter(document, name, relative) {
  if (!Array.isArray(document.adapters)) {
    fail(`JSON document is missing adapters: ${relative}`);
  }
  const matches = document.adapters.filter((adapter) => adapter?.name === name);
  if (matches.length !== 1) {
    fail(`JSON document must contain exactly one ${name} adapter: ${relative}`);
  }
  assertPlainObject(matches[0], `${relative} adapter ${name}`);
  return matches[0];
}

function replaceJsonString(document, fields, expected, replacement, relative) {
  let cursor = document;
  for (const field of fields.slice(0, -1)) {
    assertPlainObject(cursor, `${relative} ${fields.join('.')}`);
    cursor = cursor[field];
  }
  assertPlainObject(cursor, `${relative} ${fields.join('.')}`);
  const leaf = fields.at(-1);
  if (cursor[leaf] !== expected) {
    fail(`JSON field has an unexpected value: ${relative} ${fields.join('.')}`);
  }
  cursor[leaf] = replacement;
}

function findForbiddenJsonString(value, prefix = '') {
  if (typeof value === 'string') {
    if (value.includes(PREFIX_MARKER) || value.includes(DEFAULT_PREFIX)) {
      return prefix || '<root>';
    }
    return null;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const found = findForbiddenJsonString(value[index], `${prefix}[${index}]`);
      if (found) {
        return found;
      }
    }
    return null;
  }
  if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      const found = findForbiddenJsonString(child, prefix ? `${prefix}.${key}` : key);
      if (found) {
        return found;
      }
    }
  }
  return null;
}

function renderJsonArtifact(source, artifact, prefix) {
  let document;
  try {
    document = JSON.parse(fs.readFileSync(source, 'utf8'));
  } catch (error) {
    fail(`invalid JSON in ${artifact.source}: ${error.message}`);
  }
  assertTopLevelKeys(document, artifact.topLevelKeys, artifact.source);
  artifact.transform(document, prefix);
  const forbidden = findForbiddenJsonString(document);
  if (forbidden && prefix !== DEFAULT_PREFIX) {
    fail(`JSON contains an unrendered installation path: ${artifact.source} ${forbidden}`);
  }
  if (JSON.stringify(document).includes(PREFIX_MARKER)) {
    fail(`JSON contains an unresolved marker: ${artifact.source}`);
  }
  return `${JSON.stringify(document, null, 2)}\n`;
}

function writeArtifact(outputDir, artifact, contents) {
  const destination = path.join(outputDir, ...artifact.output.split('/'));
  fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o755 });
  fs.writeFileSync(destination, contents, { encoding: 'utf8', flag: 'wx', mode: artifact.mode });
  fs.chmodSync(destination, artifact.mode);
}

function render(options) {
  validatePrefix(options.prefix);
  validateAbsoluteDirectory(options.sourceRoot, 'source root');
  validateAbsoluteDirectory(options.outputDir, 'output directory', { empty: true });
  if (options.sourceRoot === options.outputDir
    || options.outputDir.startsWith(`${options.sourceRoot}${path.sep}`)) {
    fail('output directory must be outside the source root');
  }

  const templateRoot = path.join(options.sourceRoot, 'payload', 'templates');
  validateAbsoluteDirectory(templateRoot, 'template root');
  const expectedTemplateFiles = textArtifacts.map((artifact) => (
    artifact.source.slice('payload/templates/'.length)
  )).sort();
  assertInventory(
    listTree(templateRoot),
    {
      files: expectedTemplateFiles,
      directories: parentDirectories(expectedTemplateFiles),
    },
    'template root',
  );

  const renderedArtifacts = [];
  for (const artifact of textArtifacts) {
    const source = checkRegularSource(options.sourceRoot, artifact.source);
    renderedArtifacts.push({
      artifact,
      contents: renderTextTemplate(source, options.prefix, artifact.source),
    });
  }
  for (const artifact of jsonArtifacts) {
    const source = checkRegularSource(options.sourceRoot, artifact.source);
    renderedArtifacts.push({
      artifact,
      contents: renderJsonArtifact(source, artifact, options.prefix),
    });
  }
  for (const artifact of generatedArtifacts) {
    renderedArtifacts.push({
      artifact,
      contents: artifact.render(options.prefix),
    });
  }

  for (const { artifact, contents } of renderedArtifacts) {
    writeArtifact(options.outputDir, artifact, contents);
  }

  const expectedOutputs = [
    ...textArtifacts,
    ...jsonArtifacts,
    ...generatedArtifacts,
  ].map((artifact) => artifact.output).sort();
  assertInventory(
    listTree(options.outputDir),
    {
      files: expectedOutputs,
      directories: parentDirectories(expectedOutputs),
    },
    'rendered output',
  );
}

try {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    usage();
    process.exit(0);
  }
  render(options);
} catch (error) {
  process.stderr.write(`${PROGRAM}: ${error.message}\n`);
  usage(process.stderr);
  process.exit(1);
}
