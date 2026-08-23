import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { createStableId } from './ids.js';
import { readTrustedJson } from './io.js';
import { createCoverageMarker, createGraphNode, createObservation } from './records.js';

const DEFAULT_TOOL_CONFIG = new URL(
  '../../../config/nosh-review/tools.json',
  import.meta.url,
);
const MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024;
const MAX_SBOM_BYTES = 64 * 1024 * 1024;
const PORTABLE_SENSITIVE = Object.freeze({
  classification: 'portable-sensitive',
  fields: [],
});

function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function boundedText(value, label, maximum = 4096) {
  if (
    typeof value !== 'string'
    || !value.trim()
    || value.length > maximum
    || /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new TypeError(`${label} must be a bounded non-empty string`);
  }
  return value;
}

async function runBounded(command, args, options = {}) {
  const timeoutMs = options.timeoutMs ?? 15 * 60 * 1000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new TypeError('command timeout must be a positive safe integer');
  }
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env || process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let overflow = false;
    let timedOut = false;
    let settled = false;
    let terminationRequested = false;
    let forceKill = null;
    const terminate = () => {
      if (terminationRequested || settled) return;
      terminationRequested = true;
      child.kill('SIGTERM');
      forceKill = setTimeout(() => child.kill('SIGKILL'), 5_000);
    };
    const timeout = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      terminate();
    }, timeoutMs);
    const capture = (chunks, maximum, chunk, update) => {
      const remaining = maximum - update();
      if (remaining <= 0) {
        overflow = true;
        terminate();
        return;
      }
      chunks.push(chunk.subarray(0, remaining));
      if (chunk.length > remaining) {
        overflow = true;
        terminate();
      }
    };
    child.stdout.on('data', (chunk) => {
      capture(stdout, MAX_COMMAND_OUTPUT_BYTES, chunk, () => stdoutBytes);
      stdoutBytes += Math.min(chunk.length, Math.max(0, MAX_COMMAND_OUTPUT_BYTES - stdoutBytes));
    });
    child.stderr.on('data', (chunk) => {
      capture(stderr, MAX_COMMAND_OUTPUT_BYTES, chunk, () => stderrBytes);
      stderrBytes += Math.min(chunk.length, Math.max(0, MAX_COMMAND_OUTPUT_BYTES - stderrBytes));
    });
    child.once('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (forceKill) clearTimeout(forceKill);
      reject(error);
    });
    child.once('close', (status, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (forceKill) clearTimeout(forceKill);
      const result = {
        status,
        signal,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      };
      if (timedOut) {
        reject(new Error(`${command} exceeded its execution timeout`));
      } else if (overflow) {
        reject(new Error(`${command} output exceeded its byte limit`));
      } else if (status !== 0) {
        reject(new Error(
          `${command} failed with ${signal || `status ${status}`}: ${
            result.stderr.trim().slice(-2048)
          }`,
        ));
      } else {
        resolve(result);
      }
    });
  });
}

export async function loadSbomToolConfig(configFile = DEFAULT_TOOL_CONFIG) {
  const file = configFile instanceof URL ? configFile : path.resolve(configFile);
  const document = JSON.parse(await fs.readFile(file, 'utf8'));
  plainObject(document, 'SBOM tool config');
  if (document.schemaVersion !== 1) {
    throw new TypeError('unsupported SBOM tool config schema');
  }
  const syft = plainObject(document.syft, 'Syft config');
  const image = boundedText(syft.image, 'Syft image', 512);
  if (!/@sha256:[a-f0-9]{64}$/.test(image)) {
    throw new TypeError('Syft image must be pinned by OCI digest');
  }
  if (syft.format !== 'spdx-json' || syft.network !== 'none') {
    throw new TypeError('Syft must use offline SPDX JSON output');
  }
  return { schemaVersion: 1, syft: { ...syft, image } };
}

async function assertPrivateOutputDirectory(directory) {
  const resolved = path.resolve(directory);
  const parent = path.dirname(resolved);
  const resolvedParent = await fs.realpath(parent);
  if (resolvedParent !== parent) {
    throw new Error('SBOM output parent must not traverse a symlink');
  }
  const parentStat = await fs.lstat(parent);
  const uid = typeof process.geteuid === 'function' ? process.geteuid() : null;
  if (
    !parentStat.isDirectory()
    || parentStat.isSymbolicLink()
    || (uid != null && parentStat.uid !== uid)
    || (parentStat.mode & 0o022) !== 0
  ) {
    throw new Error('SBOM output parent must be trusted and caller-owned');
  }
  await fs.mkdir(resolved, { mode: 0o700 });
  const stat = await fs.lstat(resolved);
  if (
    !stat.isDirectory()
    || stat.isSymbolicLink()
    || (uid != null && stat.uid !== uid)
    || (stat.mode & 0o7777) !== 0o700
  ) {
    throw new Error('SBOM output directory must be private and caller-owned');
  }
  return resolved;
}

async function verifyGeneratedSbom(file) {
  const before = await fs.lstat(file);
  const uid = typeof process.geteuid === 'function' ? process.geteuid() : null;
  if (
    !before.isFile()
    || before.isSymbolicLink()
    || before.nlink !== 1
    || (uid != null && before.uid !== uid)
  ) {
    throw new Error('generated SBOM is not a caller-owned regular file');
  }
  await fs.chmod(file, 0o600);
  const loaded = await readTrustedJson(file, { maximumBytes: MAX_SBOM_BYTES });
  const normalized = normalizeSbomDocument(loaded.document);
  return {
    path: file,
    digest: loaded.digest,
    format: normalized.format,
    packages: normalized.packages.length,
  };
}

export async function generateBuildSboms(input, dependencies = {}) {
  const context = await fs.realpath(path.resolve(input.context));
  if (!(await fs.lstat(context)).isDirectory()) {
    throw new TypeError('SBOM context must be a directory');
  }
  const imageReference = input.imageReference == null
    ? null
    : boundedText(input.imageReference, 'image reference', 512);
  if (imageReference && (imageReference.startsWith('-') || /\s/.test(imageReference))) {
    throw new TypeError('image reference contains unsupported characters');
  }
  const output = await assertPrivateOutputDirectory(input.output);
  const config = await loadSbomToolConfig(input.configFile);
  const docker = dependencies.dockerCommand || 'docker';
  const run = dependencies.runCommand || runBounded;
  const uid = typeof process.getuid === 'function' ? process.getuid() : 1000;
  const gid = typeof process.getgid === 'function' ? process.getgid() : 1000;
  const sourceFile = path.join(output, 'source.spdx.json');
  try {
    await run(docker, [
      'run', '--rm',
      '--pull', 'never',
      '--network', config.syft.network,
      '--user', `${uid}:${gid}`,
      '--env', 'SYFT_CHECK_FOR_APP_UPDATE=false',
      '--volume', `${context}:/source:ro`,
      '--volume', `${output}:/output:rw`,
      config.syft.image,
      'dir:/source',
      '-o', 'spdx-json=/output/source.spdx.json',
    ]);
    const source = await verifyGeneratedSbom(sourceFile);
    let image = null;
    if (imageReference) {
      const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'nosh-review-sbom-'));
      await fs.chmod(temporary, 0o700);
      try {
        const archive = path.join(temporary, 'image.tar');
        await run(docker, ['image', 'save', '--output', archive, imageReference]);
        await fs.chmod(archive, 0o600);
        const imageFile = path.join(output, 'image.spdx.json');
        await run(docker, [
          'run', '--rm',
          '--pull', 'never',
          '--network', config.syft.network,
          '--user', `${uid}:${gid}`,
          '--env', 'SYFT_CHECK_FOR_APP_UPDATE=false',
          '--volume', `${temporary}:/input:ro`,
          '--volume', `${output}:/output:rw`,
          config.syft.image,
          'docker-archive:/input/image.tar',
          '-o', 'spdx-json=/output/image.spdx.json',
        ]);
        image = await verifyGeneratedSbom(imageFile);
      } finally {
        await fs.rm(temporary, { recursive: true, force: true });
      }
    }
    return {
      tool: {
        name: 'syft',
        version: config.syft.version,
        image: config.syft.image,
        network: config.syft.network,
      },
      source,
      image,
    };
  } catch (error) {
    await fs.rm(output, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
}

function normalizeSpdx(document) {
  const packages = Array.isArray(document.packages) ? document.packages : [];
  return {
    format: 'spdx-json',
    version: boundedText(document.spdxVersion, 'SPDX version', 64),
    documentName: typeof document.name === 'string' ? document.name : null,
    packages: packages.map((entry, index) => {
      const packageEntry = plainObject(entry, `SPDX package ${index}`);
      return {
        id: boundedText(packageEntry.SPDXID || `SPDXRef-Package-${index}`, 'SPDX package ID'),
        name: boundedText(packageEntry.name, 'SPDX package name'),
        version: typeof packageEntry.versionInfo === 'string'
          ? packageEntry.versionInfo
          : null,
        purl: Array.isArray(packageEntry.externalRefs)
          ? packageEntry.externalRefs.find((ref) => (
            ref?.referenceType === 'purl'
            || String(ref?.referenceType || '').endsWith('/purl')
          ))
            ?.referenceLocator || null
          : null,
        supplier: typeof packageEntry.supplier === 'string' ? packageEntry.supplier : null,
        license: typeof packageEntry.licenseConcluded === 'string'
          ? packageEntry.licenseConcluded
          : null,
      };
    }),
  };
}

function normalizeCycloneDx(document) {
  const components = Array.isArray(document.components) ? document.components : [];
  return {
    format: 'cyclonedx-json',
    version: boundedText(document.specVersion, 'CycloneDX spec version', 64),
    documentName: document.metadata?.component?.name || null,
    packages: components.map((entry, index) => {
      const component = plainObject(entry, `CycloneDX component ${index}`);
      return {
        id: boundedText(component['bom-ref'] || `component-${index}`, 'CycloneDX component ID'),
        name: boundedText(component.name, 'CycloneDX component name'),
        version: typeof component.version === 'string' ? component.version : null,
        purl: typeof component.purl === 'string' ? component.purl : null,
        supplier: component.supplier?.name || component.author || null,
        license: Array.isArray(component.licenses)
          ? component.licenses.map((entry) => entry?.license?.id || entry?.expression)
            .filter(Boolean).join(' AND ') || null
          : null,
      };
    }),
  };
}

export function normalizeSbomDocument(document) {
  plainObject(document, 'SBOM document');
  if (typeof document.spdxVersion === 'string') return normalizeSpdx(document);
  if (document.bomFormat === 'CycloneDX') return normalizeCycloneDx(document);
  throw new TypeError('SBOM must be SPDX JSON or CycloneDX JSON');
}

export async function loadSbom(file) {
  const loaded = await readTrustedJson(file, {
    maximumBytes: MAX_SBOM_BYTES,
    allowGroupRead: true,
  });
  return {
    ...loaded,
    normalized: normalizeSbomDocument(loaded.document),
  };
}

export function sbomGraphRecords(input) {
  const sourceNode = createGraphNode({
    semanticKey: {
      scopeDigest: input.scope.scopeDigest,
      role: input.role,
      digest: input.digest,
    },
    scopeDigest: input.scope.scopeDigest,
    nodeType: 'evidenceSource',
    label: `${input.role} SBOM`,
    identity: { role: input.role, digest: input.digest, format: input.sbom.format },
    properties: {
      version: input.sbom.version,
      packageCount: String(input.sbom.packages.length),
    },
    evidenceRefs: [],
    privacy: { ...PORTABLE_SENSITIVE, fields: [] },
  });
  const nodes = [sourceNode];
  const observations = [];
  for (const packageEntry of input.sbom.packages) {
    const identity = {
      name: packageEntry.name,
      version: packageEntry.version,
      purl: packageEntry.purl,
    };
    const packageNode = createGraphNode({
      semanticKey: { role: input.role, identity },
      scopeDigest: input.scope.scopeDigest,
      nodeType: 'package',
      label: `${packageEntry.name}${packageEntry.version ? `@${packageEntry.version}` : ''}`,
      identity,
      properties: {
        supplier: packageEntry.supplier,
        license: packageEntry.license,
        sbomId: packageEntry.id,
        sourceRole: input.role,
      },
      evidenceRefs: [sourceNode.id],
      privacy: { ...PORTABLE_SENSITIVE, fields: [] },
    });
    nodes.push(packageNode);
    observations.push(createObservation({
      scopeDigest: input.scope.scopeDigest,
      observationType: 'installs',
      subjectId: input.scope.subjectId,
      objectId: packageNode.id,
      basis: 'observed',
      confidence: 100,
      count: '1',
      evidenceRefs: [sourceNode.id],
      properties: { sourceRole: input.role },
      privacy: { ...PORTABLE_SENSITIVE, fields: [] },
    }));
  }
  const coverage = createCoverageMarker({
    scopeDigest: input.scope.scopeDigest,
    domain: input.role === 'source' ? 'sbom-source' : 'sbom-image',
    status: 'complete',
    sourceIds: [sourceNode.id],
    counters: { packages: String(input.sbom.packages.length) },
    gaps: [],
    blocking: false,
    privacy: { classification: 'portable', fields: [] },
  });
  return { nodes, observations, coverage, sourceNode };
}
