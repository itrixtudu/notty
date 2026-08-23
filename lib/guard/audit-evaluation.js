const HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;

export const AUDIT_BACKEND_ARTIFACTS = Object.freeze({
  tetragon: 'tetragon.yaml',
  seccomp: 'seccomp.json',
  apparmor: 'apparmor.profile',
  docker: 'docker.json',
  network: 'network-policy.yaml',
});

export const AUDIT_BACKENDS = Object.freeze(
  Object.keys(AUDIT_BACKEND_ARTIFACTS),
);

export const AUDIT_ARTIFACT_FILES = Object.freeze(
  Object.values(AUDIT_BACKEND_ARTIFACTS),
);

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {
      missing: [...expected],
      unexpected: [],
    };
  }
  const actual = Object.keys(value);
  return {
    missing: expected.filter((key) => !Object.hasOwn(value, key)),
    unexpected: actual.filter((key) => !expected.includes(key)),
  };
}

export function artifactHashesFromCompiledArtifacts(artifacts) {
  return Object.fromEntries(
    AUDIT_BACKENDS.map((backend) => {
      const filename = AUDIT_BACKEND_ARTIFACTS[backend];
      const artifact = artifacts?.[backend];
      return [filename, artifact?.hash || null];
    }),
  );
}

export function artifactHashesFromProfile(profile) {
  const descriptors = profile?.spec?.artifacts || {};
  const hashes = {};
  for (const backend of AUDIT_BACKENDS) {
    const filename = AUDIT_BACKEND_ARTIFACTS[backend];
    const descriptor = descriptors[backend];
    hashes[filename] =
      descriptor?.fileName === filename ? descriptor?.hash || null : null;
  }
  return hashes;
}

export function evaluateAuditEvaluation(value, expectedArtifacts = null) {
  const errors = [];
  const artifactHashes = {};
  const backendResults = {};
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {
      valid: false,
      complete: false,
      clean: false,
      wouldDenyCount: 0,
      artifactHashes,
      backendResults,
      errors: ['audit evaluation is missing'],
    };
  }
  if (value.schemaVersion !== 1) {
    errors.push('audit evaluation schemaVersion must be 1');
  }

  const artifactKeys = exactKeys(
    value.candidateArtifacts,
    AUDIT_ARTIFACT_FILES,
  );
  if (artifactKeys.missing.length) {
    errors.push(
      `audit evaluation is missing candidate artifact hashes: ${artifactKeys.missing.join(', ')}`,
    );
  }
  if (artifactKeys.unexpected.length) {
    errors.push(
      `audit evaluation contains unexpected candidate artifacts: ${artifactKeys.unexpected.join(', ')}`,
    );
  }
  for (const filename of AUDIT_ARTIFACT_FILES) {
    const hash = value.candidateArtifacts?.[filename];
    artifactHashes[filename] = hash ?? null;
    if (!HASH_PATTERN.test(hash || '')) {
      errors.push(`audit evaluation requires an exact SHA-256 for ${filename}`);
    } else if (
      expectedArtifacts &&
      expectedArtifacts[filename] !== hash
    ) {
      errors.push(
        `audit evaluation ${filename} hash does not match the candidate`,
      );
    }
  }

  const backendKeys = exactKeys(value.backends, AUDIT_BACKENDS);
  if (backendKeys.missing.length) {
    errors.push(
      `audit evaluation is missing backends: ${backendKeys.missing.join(', ')}`,
    );
  }
  if (backendKeys.unexpected.length) {
    errors.push(
      `audit evaluation contains unexpected backends: ${backendKeys.unexpected.join(', ')}`,
    );
  }
  let wouldDenyCount = 0;
  let allBackendsComplete = true;
  for (const backend of AUDIT_BACKENDS) {
    const result = value.backends?.[backend];
    backendResults[backend] = result || null;
    if (!result || typeof result !== 'object' || Array.isArray(result)) {
      allBackendsComplete = false;
      continue;
    }
    if (typeof result.evaluator !== 'string' || !result.evaluator.trim()) {
      errors.push(`audit evaluation backend ${backend} requires an evaluator`);
    }
    if (typeof result.complete !== 'boolean') {
      errors.push(
        `audit evaluation backend ${backend} requires a complete boolean`,
      );
      allBackendsComplete = false;
    } else if (!result.complete) {
      errors.push(`audit evaluation backend ${backend} is incomplete`);
      allBackendsComplete = false;
    }
    if (
      !Number.isSafeInteger(result.wouldDenyCount) ||
      result.wouldDenyCount < 0
    ) {
      errors.push(
        `audit evaluation backend ${backend} requires a non-negative wouldDenyCount`,
      );
    } else {
      wouldDenyCount += result.wouldDenyCount;
    }
  }

  const complete =
    errors.length === 0 &&
    allBackendsComplete &&
    AUDIT_ARTIFACT_FILES.every((filename) =>
      HASH_PATTERN.test(artifactHashes[filename] || ''),
    );
  return {
    valid: errors.length === 0,
    complete,
    clean: complete && wouldDenyCount === 0,
    wouldDenyCount,
    artifactHashes,
    backendResults,
    errors: [...new Set(errors)].sort(),
  };
}
