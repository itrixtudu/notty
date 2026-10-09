import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createStableId } from './ids.js';
import { sha256Digest } from './jcs.js';
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
  const collector = plainObject(document.collector, 'Inventory collector config');
  if (collector.name !== 'nosh-inventory' || collector.version !== '1'
      || collector.format !== 'spdx-json' || collector.network !== 'none') {
    throw new TypeError('Inventory requires the built-in offline collector');
  }
  return { schemaVersion: 1, collector };
}

export async function generateBuildSboms(input, dependencies = {}) {
  const context = await fs.realpath(path.resolve(input.context));
  const output = path.resolve(input.output);
  const tooling = input.toolingImage || process.env.NOSH_POLICY_TOOLING_IMAGE;
  if (!/^sha256:[a-f0-9]{64}$/.test(tooling || '')) {
    throw new TypeError('Set NOSH_POLICY_TOOLING_IMAGE to an exact local policy tooling image ID');
  }
  const config = await loadSbomToolConfig(input.configFile);
  const args = [fileURLToPath(new URL('../../../scripts/nosh-inventory.sh', import.meta.url)),
    '--workdir', context, '--tooling', tooling, '--output', output];
  if (input.imageReference) args.push('--image', boundedText(input.imageReference, 'image reference', 512));
  else args.push('--source-only');
  await (dependencies.runCommand || runBounded)('bash', args, {
    env: { ...process.env, NOSH_NET_REVIEW_DOCKER_BIN: dependencies.dockerCommand || 'docker' },
    timeoutMs: 45 * 60 * 1000,
  });
  const describe = async role => {
    const file = path.join(output, `${role}.spdx.json`);
    const loaded = await loadSbom(file);
    if (loaded.normalized.collection?.status !== 'complete') {
      throw new Error(`${role} inventory is incomplete; inspect its collection report`);
    }
    return { path: file, digest: loaded.digest, format: loaded.normalized.format,
      packages: loaded.normalized.packages.length, collection: loaded.normalized.collection };
  };
  return { tool: { ...config.collector, image: tooling },
    source: await describe('source'), image: input.imageReference ? await describe('image') : null };
}

const COLLECTION_PREFIX = 'nosh-inventory-collection:';
const SHA256 = /^sha256:[a-f0-9]{64}$/;

function collectionReport(document) {
  const annotations = (document.annotations || []).filter(entry =>
    typeof entry?.comment === 'string' && entry.comment.startsWith(COLLECTION_PREFIX));
  if (!annotations.length) return null;
  if (annotations.length !== 1) throw new TypeError('Inventory has ambiguous collection reports');
  const report = plainObject(JSON.parse(annotations[0].comment.slice(COLLECTION_PREFIX.length)), 'Collection report');
  if (report.kind !== 'NoshInventoryCollection' || report.schemaVersion !== 1
      || !['source', 'image'].includes(report.role)
      || report.collector?.name !== 'nosh-inventory' || report.collector?.version !== '1'
      || !['complete', 'incomplete'].includes(report.status)
      || !Array.isArray(report.gaps) || !Array.isArray(report.limitations)
      || !Array.isArray(report.exclusions) || !Array.isArray(report.metadataFiles)) {
    throw new TypeError('Invalid inventory collection report');
  }
  if (report.metadataFiles.length > 200000 || (report.status === 'complete' && !report.metadataFiles.length)
      || report.gaps.some(gap => typeof gap?.message !== 'string' || typeof gap.blocking !== 'boolean')
      || report.limitations.some(item => typeof item !== 'string')
      || report.exclusions.some(item => typeof item !== 'string')) {
    throw new TypeError('Invalid collection coverage');
  }
  const paths = new Set();
  for (const entry of report.metadataFiles) {
    if (typeof entry.path !== 'string' || entry.path.startsWith('/') || entry.path.split('/').includes('..')
        || paths.has(entry.path) || !/^sha256:[a-f0-9]{64}$/.test(entry.sha256)
        || typeof entry.kind !== 'string') throw new TypeError('Invalid collection metadata binding');
    paths.add(entry.path);
  }
  const binding = report.role === 'source' ? report.input?.metadataDigest : report.input?.imageDigest;
  if (!SHA256.test(binding || '')) throw new TypeError('Collection input binding is missing');
  if (report.role === 'source' && sha256Digest(report.metadataFiles) !== binding) {
    throw new TypeError('Collection metadata digest does not match its inputs');
  }
  if (report.counts?.metadataFiles !== report.metadataFiles.length
      || report.counts?.packages !== (document.packages || []).length) {
    throw new TypeError('Collection counts do not match inventory contents');
  }
  if (report.status === 'complete' && !(document.packages || []).length) {
    throw new TypeError('Complete collection has no identifiable packages');
  }
  if (report.status === 'complete' && report.gaps.some(gap => gap.blocking)) {
    throw new TypeError('Complete inventory contains blocking gaps');
  }
  return report;
}

function collectionSummary(report) {
  const { metadataFiles, ...summary } = report;
  return { ...summary, reportDigest: sha256Digest(report) };
}

function packageEvidence(entry) {
  const locations = [];
  for (const annotation of entry.annotations || []) {
    if (typeof annotation.comment !== 'string') continue;
    try {
      const item = JSON.parse(annotation.comment);
      if (['declared', 'installed', 'copied'].includes(item.evidence)
          && typeof item.path === 'string' && item.path.length <= 4096) {
        locations.push({ evidence: item.evidence, path: item.path });
      }
    } catch { /* Ordinary SPDX annotations remain informational. */ }
  }
  return locations.length ? { ...locations[0], locations } : null;
}

function normalizeSpdx(document) {
  const packages = Array.isArray(document.packages) ? document.packages : [];
  return {
    format: 'spdx-json',
    version: boundedText(document.spdxVersion, 'SPDX version', 64),
    documentName: typeof document.name === 'string' ? document.name : null,
    collection: collectionReport(document),
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
        evidence: packageEvidence(packageEntry),
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
      ...(input.sbom.collection ? { collection: collectionSummary(input.sbom.collection) } : {}),
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
      ...(packageEntry.evidence?.path ? { location: packageEntry.evidence.path } : {}),
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
        ...(packageEntry.evidence ? { inventoryEvidence: packageEntry.evidence } : {}),
      },
      evidenceRefs: [sourceNode.id],
      privacy: { ...PORTABLE_SENSITIVE, fields: [] },
    });
    nodes.push(packageNode);
    observations.push(createObservation({
      scopeDigest: input.scope.scopeDigest,
      observationType: packageEntry.evidence?.evidence === 'installed' ? 'contains' : 'derivedFrom',
      subjectId: input.scope.subjectId,
      objectId: packageNode.id,
      basis: 'observed',
      confidence: 100,
      count: '1',
      evidenceRefs: [sourceNode.id],
      properties: { sourceRole: input.role, evidenceKind: packageEntry.evidence?.evidence || 'external-inventory' },
      privacy: { ...PORTABLE_SENSITIVE, fields: [] },
    }));
  }
  const report = input.sbom.collection;
  const gaps = [];
  if (!report) gaps.push('Inventory has no collection report; regenerate with the offline collector.');
  else {
    if (report.role !== input.role) gaps.push('Inventory role does not match its collection report.');
    if (report.role === 'image' && report.input.imageDigest !== input.scope.imageDigest) {
      gaps.push('Image inventory does not match the reviewed image.');
    }
    for (const gap of report.gaps) if (gap.blocking) gaps.push(gap.message);
    if (report.status !== 'complete' && !gaps.length) gaps.push('Inventory collection is incomplete.');
  }
  const coverage = createCoverageMarker({
    scopeDigest: input.scope.scopeDigest,
    domain: input.role === 'source' ? 'sbom-source' : 'sbom-image',
    status: gaps.length ? 'degraded' : 'complete',
    sourceIds: [sourceNode.id],
    counters: { packages: String(input.sbom.packages.length) },
    gaps,
    blocking: gaps.length > 0,
    privacy: { classification: 'portable', fields: [] },
  });
  return { nodes, observations, coverage, sourceNode };
}
