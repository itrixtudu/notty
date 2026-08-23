import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

function sha256(content) {
  return `sha256:${crypto.createHash('sha256').update(content).digest('hex')}`;
}

function renderValue(value, substitutions, used) {
  if (Array.isArray(value)) {
    return value.map((entry) => renderValue(entry, substitutions, used));
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        key,
        renderValue(entry, substitutions, used),
      ]),
    );
  }
  if (typeof value !== 'string') {
    return value;
  }
  return value.replace(/\{([A-Za-z][A-Za-z0-9]*)\}/g, (match, key) => {
    if (substitutions[key] == null || substitutions[key] === '') {
      throw new Error(`runtime Tetragon placeholder has no value: ${match}`);
    }
    used.add(key);
    return String(substitutions[key]);
  });
}

function runtimeName(name, runId) {
  const suffix = crypto.createHash('sha256').update(runId).digest('hex').slice(0, 10);
  const base = String(name || 'nosh-profile')
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 52);
  return `${base || 'nosh-profile'}-${suffix}`.slice(0, 63);
}

const ENFORCEMENT_ACTIONS = new Set(['Override', 'Sigkill', 'Signal']);

function enforcementSelectors(policy) {
  const selectors = [];
  for (const field of ['kprobes', 'lsmhooks', 'tracepoints', 'uprobes']) {
    for (const hook of policy?.spec?.[field] || []) {
      for (const selector of hook?.selectors || []) {
        if (
          (selector.matchActions || []).some((action) =>
            ENFORCEMENT_ACTIONS.has(action?.action),
          )
        ) {
          selectors.push(selector);
        }
      }
    }
  }
  return selectors;
}

function hasExactCgroupValue(selector, expected) {
  return (selector?.matchNamespaces || []).some(
    (entry) =>
      entry?.namespace === 'Cgroup' &&
      entry?.operator === 'In' &&
      Array.isArray(entry.values) &&
      entry.values.length === 1 &&
      String(entry.values[0]) === String(expected),
  );
}

export async function renderApprovedTetragonPolicy(options) {
  const templatePath = path.resolve(options.templatePath);
  const templateSource = await fs.readFile(templatePath, 'utf8');
  const templateHash = sha256(templateSource);
  if (
    options.approvedTemplateHash &&
    templateHash !== options.approvedTemplateHash
  ) {
    throw new Error('Tetragon template no longer matches its approval hash');
  }
  const template = JSON.parse(templateSource);
  const enforcement = enforcementSelectors(template);
  if (
    !enforcement.length ||
    enforcement.some(
      (selector) =>
        !hasExactCgroupValue(selector, '{cgroupNamespace}'),
    )
  ) {
    throw new Error(
      'every runtime Tetragon enforcement selector must target only {cgroupNamespace}',
    );
  }
  const used = new Set();
  const rendered = renderValue(
    template,
    {
      runId: options.runId,
      containerId: options.containerId,
      initPid: options.initPid,
      cgroupNamespace: options.namespaces?.cgroup,
      mountNamespace: options.namespaces?.mnt,
      networkNamespace: options.namespaces?.net,
      pidNamespace: options.namespaces?.pid,
    },
    used,
  );
  if (!used.has('cgroupNamespace') && !used.has('initPid')) {
    throw new Error(
      'Tetragon enforcement template did not consume a cgroupNamespace or initPid scope',
    );
  }
  if (
    enforcementSelectors(rendered).some(
      (selector) =>
        !hasExactCgroupValue(selector, options.namespaces?.cgroup),
    )
  ) {
    throw new Error(
      'rendered Tetragon enforcement escaped the exact runner cgroup namespace',
    );
  }
  rendered.metadata ||= {};
  rendered.metadata.name = runtimeName(rendered.metadata.name, options.runId);
  rendered.metadata.annotations = {
    ...(rendered.metadata.annotations || {}),
    'notty.dev/approved-template-hash': templateHash,
    'notty.dev/runtime-run-id': options.runId,
    'notty.dev/runtime-container-id': options.containerId,
    'notty.dev/runtime-renderer': 'nosh-guard/v1',
  };
  const renderedSource = `${JSON.stringify(rendered, null, 2)}\n`;
  const renderedHash = sha256(renderedSource);
  await fs.mkdir(options.outputDir, { recursive: true, mode: 0o700 });
  const policyPath = path.join(options.outputDir, 'rendered-tetragon.yaml');
  const attestationPath = path.join(
    options.outputDir,
    'rendered-tetragon-attestation.json',
  );
  await fs.writeFile(policyPath, renderedSource, { mode: 0o600 });
  const attestation = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshRuntimePolicyAttestation',
    generatedAt: new Date().toISOString(),
    renderer: 'nosh-guard/v1',
    runId: options.runId,
    containerId: options.containerId,
    imageDigest: options.imageDigest,
    templatePath,
    templateHash,
    renderedPath: policyPath,
    renderedHash,
    substitutions: [...used].sort(),
    namespaceIdentity: options.namespaces,
    initPid: options.initPid,
  };
  await fs.writeFile(attestationPath, `${JSON.stringify(attestation, null, 2)}\n`, {
    mode: 0o600,
  });
  return {
    policyPath,
    policyName: rendered.metadata.name,
    attestationPath,
    attestation,
  };
}
