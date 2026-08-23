import net from 'node:net';
import path from 'node:path';

import { createTargetReviewSet } from './documents.js';
import {
  readPrivateSigningKey,
  readPublicVerificationKey,
  readTrustedFile,
  readTrustedJson,
  writeArtifactDirectory,
} from './io.js';
import { jcsCanonicalize, sha256Digest } from './jcs.js';
import { readPolicyLeafArtifact } from './leaf-store.js';
import { compileEbpfPolicy } from './policy-compilers.js';
import { deriveTargetProjection } from './projection-service.js';
import {
  createDsseEnvelope,
  createDeploymentGrantStatement,
  createGatewayGrantStatement,
  DEPLOYMENT_GRANT_PAYLOAD_TYPE,
  ed25519KeyId,
  GATEWAY_GRANT_PAYLOAD_TYPE,
  REVIEW_APPROVAL_PAYLOAD_TYPE,
  validateReviewApprovalStatement,
  validateDeploymentGrantStatement,
  verifyDsseEnvelope,
} from './signing.js';

function assertApprovalPolicyBindings(statement, policy) {
  const expected = {
    graphDigest: policy.policyIR.graphDigest,
    proposalSetDigest: policy.policyIR.proposalSetDigest,
    decisionSetDigest: policy.policyIR.decisionSetDigest,
    policyIrDigest: policy.policyIR.contentDigest,
    targetReviewSetDigest: policy.targetReviewSet.contentDigest,
    scopeDigest: policy.policyIR.scope.scopeDigest,
    confirmationDigest: sha256Digest(policy.targetReviewSet.contentDigest),
  };
  for (const [name, value] of Object.entries(expected)) {
    if (statement[name] !== value) {
      throw new Error(`review approval ${name} does not bind the policy leaf`);
    }
  }
}

function assertKnownEbpfProjection(policy, expected, policyText) {
  const recompiled = compileEbpfPolicy(policy.policyIR, {
    backendAbi: expected.backendAbi,
    objectDigest: expected.objectDigest,
    subject: {
      workspaceKey: expected.workspaceKey,
      workspaceIdentity: expected.workspaceIdentity,
      imageDigest: expected.imageDigest,
    },
    capabilities: expected.capabilities,
    resolvers: expected.resolvers,
    platformContainment: expected.platformContainment,
  });
  if (jcsCanonicalize(recompiled) !== jcsCanonicalize(policy.projection)) {
    throw new Error('guard-ebpf projection does not match a fresh trusted compilation');
  }
  if (
    recompiled.activationEligible !== true
    || recompiled.artifacts?.['ebpf-policy.json'] !== policyText
  ) {
    throw new Error('guard-ebpf projection is not activation eligible or rendered exactly');
  }
  const rederivedTargetReviewSet = createTargetReviewSet({
    policyIR: policy.policyIR,
    projections: [deriveTargetProjection(policy.policyIR, recompiled)],
    createdAt: policy.targetReviewSet.createdAt,
  });
  if (
    jcsCanonicalize(rederivedTargetReviewSet)
      !== jcsCanonicalize(policy.targetReviewSet)
  ) {
    throw new Error(
      'guard-ebpf target review projection does not match a fresh trusted compilation',
    );
  }
  const targetProjection = policy.targetReviewSet.projections?.[0];
  const compilerId = 'nosh-guard-ebpf-policy-v2';
  const compilerVersion = '2';
  if (
    policy.targetReviewSet.projections.length !== 1
    || policy.leaf.activationEligible !== true
    || targetProjection?.activationEligible !== true
    || policy.projection.activationEligible !== true
    || policy.leaf.target !== 'guard-ebpf'
    || targetProjection?.target !== 'guard-ebpf'
    || policy.projection.target !== 'guard-ebpf'
    || targetProjection.compiler?.id !== compilerId
    || targetProjection.compiler?.version !== compilerVersion
    || targetProjection.compiler?.digest
      !== sha256Digest({ id: compilerId, version: compilerVersion })
  ) {
    throw new Error('guard-ebpf leaf has an unsupported projection or compiler');
  }
  const expectedPaths = [
    'policy-ir.json',
    'projection.json',
    'rendered/ebpf-policy.json',
    'target-review-set.json',
  ];
  const actualPaths = policy.leaf.artifacts.map((entry) => entry.path).sort();
  if (
    actualPaths.length !== expectedPaths.length
    || actualPaths.some((entry, index) => entry !== expectedPaths[index])
    || targetProjection.artifacts?.length !== 1
    || targetProjection.artifacts[0]?.name !== 'ebpf-policy.json'
    || targetProjection.artifacts[0]?.sha256 !== sha256Digest(policyText)
    || targetProjection.artifacts[0]?.bytes !== String(Buffer.byteLength(policyText))
  ) {
    throw new Error('guard-ebpf leaf has an unsupported rendered artifact inventory');
  }
  return recompiled;
}

export async function createGatewayGrantArtifact(input) {
  const policy = await readPolicyLeafArtifact(input.policy);
  if (!['guard-ebpf', 'guard-nftables', 'gateway-iptables'].includes(policy.leaf.target)) {
    throw new Error('deployment grants are valid only for Guard enforcement targets');
  }
  if (!policy.leaf.activationEligible) {
    throw new Error('cannot grant a target projection that is not activation eligible');
  }
  if (policy.leaf.target === 'guard-ebpf' && !input.reviewAudience) {
    throw new TypeError('guard-ebpf deployment grants require a review audience');
  }
  const reviewAudience = input.reviewAudience || input.audience;
  const reviewPublicKey = await readPublicVerificationKey(
    path.resolve(input.reviewPublicKey),
  );
  const approvalEnvelope = (await readTrustedJson(path.resolve(input.approval), {
    maximumBytes: 16 * 1024 * 1024,
    allowGroupRead: true,
  })).document;
  const approval = verifyDsseEnvelope(approvalEnvelope, {
    payloadType: REVIEW_APPROVAL_PAYLOAD_TYPE,
    trustedKeys: [{
      publicKey: reviewPublicKey,
      roles: ['review-approval'],
      audiences: [reviewAudience],
    }],
    role: 'review-approval',
    audience: reviewAudience,
  });
  validateReviewApprovalStatement(approval.statement, {
    audience: reviewAudience,
  });
  assertApprovalPolicyBindings(approval.statement, policy);
  const now = input.now instanceof Date ? input.now : new Date(input.now || Date.now());
  if (!Number.isFinite(now.getTime())) {
    throw new TypeError('deployment grant clock is invalid');
  }
  if (Date.parse(approval.statement.issuedAt) > now.getTime()) {
    throw new Error('review approval is future-dated');
  }
  const seconds = input.ttlSeconds == null ? 3600 : Number(input.ttlSeconds);
  if (!Number.isSafeInteger(seconds) || seconds < 1 || seconds > 24 * 60 * 60) {
    throw new TypeError('deployment grant TTL must be from 1 through 86400 seconds');
  }
  let ebpfBinding = null;
  if (policy.leaf.target === 'guard-ebpf') {
    const ebpfPolicy = (await readTrustedJson(
      path.join(policy.directory, 'rendered', 'ebpf-policy.json'),
      { maximumBytes: 64 * 1024 * 1024 },
    )).document;
    if (
      ebpfPolicy?.kind !== 'NoshEbpfEgressPolicy'
      || ebpfPolicy?.backend?.target !== 'guard-ebpf'
      || typeof ebpfPolicy?.backend?.abi !== 'string'
      || !ebpfPolicy?.subject
    ) {
      throw new Error('guard-ebpf leaf has an invalid rendered policy binding');
    }
    ebpfBinding = {
      backendAbi: ebpfPolicy.backend.abi,
      subjectBindingDigest: sha256Digest(jcsCanonicalize(ebpfPolicy.subject)),
      targetBindingDigest: sha256Digest(jcsCanonicalize({
        backend: ebpfPolicy.backend,
        subject: ebpfPolicy.subject,
      })),
    };
    if (input.targetBindingDigest !== ebpfBinding.targetBindingDigest) {
      throw new Error('target binding digest does not confirm the guard-ebpf subject and ABI');
    }
  }
  const statementInput = {
    audience: input.audience,
    target: policy.leaf.target,
    leafBundleDigest: policy.leaf.bundleDigest,
    approvalEnvelopeDigest: approval.envelopeDigest,
    targetBindingDigest: input.targetBindingDigest,
    capabilityDigest: policy.leaf.capabilityDigest,
    activeGrantSetDigest: input.activeGrantSetDigest,
    renderedArtifactsDigest: policy.projection.artifactsDigest,
    notBefore: now.toISOString(),
    expiresAt: new Date(now.getTime() + seconds * 1000).toISOString(),
    ...(ebpfBinding ? {
      subjectBindingDigest: ebpfBinding.subjectBindingDigest,
      backendAbi: ebpfBinding.backendAbi,
    } : {}),
  };
  const statement = ebpfBinding
    ? createDeploymentGrantStatement(statementInput, { now })
    : createGatewayGrantStatement(statementInput, { now });
  const deploymentPrivateKey = await readPrivateSigningKey(
    path.resolve(input.deploymentPrivateKey),
  );
  if (
    ebpfBinding
    && ed25519KeyId(deploymentPrivateKey) === ed25519KeyId(reviewPublicKey)
  ) {
    throw new Error(
      'guard-ebpf review approval and deployment grant require distinct signing keys',
    );
  }
  const payloadType = ebpfBinding
    ? DEPLOYMENT_GRANT_PAYLOAD_TYPE
    : GATEWAY_GRANT_PAYLOAD_TYPE;
  const envelope = createDsseEnvelope(
    payloadType,
    statement,
    deploymentPrivateKey,
  );
  const receipt = {
    ...statement,
    kind: ebpfBinding ? 'NoshDeploymentGrantReceipt' : 'NoshGatewayGrantReceipt',
    createdAt: statement.issuedAt,
    keyId: ed25519KeyId(deploymentPrivateKey),
    grantEnvelopeDigest: sha256Digest(jcsCanonicalize(envelope)),
  };
  return Object.freeze({
    policy,
    approval,
    statement,
    envelope,
    receipt,
    artifacts: Object.freeze(ebpfBinding
      ? {
          'deployment-grant.dsse.json': `${jcsCanonicalize(envelope)}\n`,
          'deployment-grant-receipt.json': `${jcsCanonicalize(receipt)}\n`,
        }
      : {
          'gateway-grant.dsse.json': `${jcsCanonicalize(envelope)}\n`,
          'gateway-grant-receipt.json': `${jcsCanonicalize(receipt)}\n`,
        }),
  });
}

export const createDeploymentGrantArtifact = createGatewayGrantArtifact;

export async function writeGatewayGrantArtifact(directory, artifact) {
  const written = await writeArtifactDirectory(path.resolve(directory), artifact.artifacts, {
    maximumBytes: 16 * 1024 * 1024,
  });
  return { ...written, receipt: artifact.receipt };
}

export const writeDeploymentGrantArtifact = writeGatewayGrantArtifact;

function exactEbpfExpected(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('expected guard-ebpf authority binding is required');
  }
  const required = [
    'imageDigest',
    'workspaceKey',
    'workspaceIdentity',
    'backendAbi',
    'objectDigest',
    'capabilities',
    'resolvers',
    'platformContainment',
  ];
  const keys = Object.keys(input);
  if (
    keys.length !== required.length
    || required.some((key) => !Object.hasOwn(input, key))
  ) {
    throw new TypeError('expected guard-ebpf authority binding has unsupported fields');
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(input.imageDigest || '')) {
    throw new TypeError('expected imageDigest must be an immutable SHA-256 digest');
  }
  if (!/^(?:[a-f0-9]{64}|sha256:[a-f0-9]{64})$/.test(input.workspaceKey || '')) {
    throw new TypeError('expected workspaceKey must be a workspace hash');
  }
  if (
    !input.workspaceIdentity
    || typeof input.workspaceIdentity !== 'object'
    || Array.isArray(input.workspaceIdentity)
    || Object.keys(input.workspaceIdentity).sort().join(',') !== 'dev,ino'
  ) {
    throw new TypeError('expected workspaceIdentity must contain dev and ino');
  }
  const workspaceIdentity = Object.fromEntries(['dev', 'ino'].map((key) => {
    const value = String(input.workspaceIdentity[key]);
    if (!/^(0|[1-9][0-9]*)$/.test(value)) {
      throw new TypeError(`expected workspaceIdentity.${key} must be a decimal string`);
    }
    return [key, value];
  }));
  if (input.backendAbi !== 'nosh-egress-v2') {
    throw new TypeError('expected backendAbi must be nosh-egress-v2');
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(input.objectDigest || '')) {
    throw new TypeError('expected objectDigest must be a SHA-256 digest');
  }
  if (
    !input.capabilities
    || typeof input.capabilities !== 'object'
    || Array.isArray(input.capabilities)
    || Object.keys(input.capabilities).length === 0
  ) {
    throw new TypeError('expected capabilities must be a non-empty object');
  }
  const capabilities = Object.fromEntries(
    Object.entries(input.capabilities)
      .map(([name, value]) => {
        if (!/^[A-Za-z][A-Za-z0-9]*$/.test(name) || typeof value !== 'boolean') {
          throw new TypeError('expected capabilities must contain boolean capability tokens');
        }
        return [name, value];
      })
      .sort(([left], [right]) => left.localeCompare(right)),
  );
  if (capabilities.exactPlatformContainment !== true) {
    throw new TypeError(
      'expected capabilities must attest exactPlatformContainment',
    );
  }
  if (
    !Array.isArray(input.resolvers)
    || input.resolvers.length < 1
    || input.resolvers.length > 32
    || input.resolvers.some((value) => typeof value !== 'string' || !net.isIP(value))
    || new Set(input.resolvers).size !== input.resolvers.length
  ) {
    throw new TypeError('expected resolvers must contain 1..32 unique IP addresses');
  }
  if (
    !input.platformContainment
    || typeof input.platformContainment !== 'object'
    || Array.isArray(input.platformContainment)
    || Object.keys(input.platformContainment).sort().join(',')
      !== 'ipv4PrefixLength,ipv6PrefixLength,strategy'
    || input.platformContainment.strategy !== 'per-run-docker-bridge-gateways'
    || input.platformContainment.ipv4PrefixLength !== 32
    || input.platformContainment.ipv6PrefixLength !== 128
  ) {
    throw new TypeError(
      'expected platformContainment must bind exact per-run Docker bridge gateway /32 and /128 identities',
    );
  }
  return {
    ...input,
    workspaceIdentity,
    capabilities,
    resolvers: [...input.resolvers],
    platformContainment: { ...input.platformContainment },
  };
}

export async function verifyEbpfDeploymentAuthority(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('guard-ebpf deployment authority input is required');
  }
  const expected = exactEbpfExpected(input.expected);
  for (const name of ['reviewAudience', 'deploymentAudience']) {
    if (
      typeof input[name] !== 'string'
      || !input[name]
      || input[name].length > 255
      || /[\u0000-\u001f\u007f]/.test(input[name])
    ) {
      throw new TypeError(`${name} must be a bounded non-empty audience`);
    }
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(input.activeGrantSetDigest || '')) {
    throw new TypeError('activeGrantSetDigest must be the current root-owned state digest');
  }
  const policy = await readPolicyLeafArtifact(path.resolve(input.policy));
  if (policy.leaf.target !== 'guard-ebpf' || !policy.leaf.activationEligible) {
    throw new Error('deployment authority requires an activation-eligible guard-ebpf leaf');
  }
  const policyPath = path.join(policy.directory, 'rendered', 'ebpf-policy.json');
  const policyFile = await readTrustedFile(policyPath, {
    maximumBytes: 64 * 1024 * 1024,
  });
  const ebpfPolicy = JSON.parse(policyFile.toString('utf8'));
  if (`${jcsCanonicalize(ebpfPolicy)}\n` !== policyFile.toString('utf8')) {
    throw new Error('rendered guard-ebpf policy is not canonical');
  }
  if (
    ebpfPolicy.kind !== 'NoshEbpfEgressPolicy'
    || ebpfPolicy.schemaVersion !== 2
    || ebpfPolicy.backend?.target !== 'guard-ebpf'
    || ebpfPolicy.backend?.abi !== expected.backendAbi
    || ebpfPolicy.backend?.objectDigest !== expected.objectDigest
    || ebpfPolicy.subject?.imageDigest !== expected.imageDigest
    || ebpfPolicy.subject?.workspaceKey !== expected.workspaceKey
    || jcsCanonicalize(ebpfPolicy.subject?.workspaceIdentity)
      !== jcsCanonicalize(expected.workspaceIdentity)
  ) {
    throw new Error('rendered guard-ebpf policy does not match the exact deployment subject');
  }
  const expectedWorkspaceDigest = sha256Digest(jcsCanonicalize({
    workspaceKey: expected.workspaceKey,
    workspaceIdentity: expected.workspaceIdentity,
  }));
  if (
    ebpfPolicy.subject.workspaceDigest !== expectedWorkspaceDigest
    || ebpfPolicy.subject.scopeDigest !== policy.policyIR.scope.scopeDigest
    || ebpfPolicy.subject.subjectId !== policy.policyIR.scope.subjectId
    || policy.policyIR.scope.class !== 'runtime'
    || policy.policyIR.scope.imageDigest !== expected.imageDigest
    || policy.policyIR.scope.workspaceDigest !== expectedWorkspaceDigest
  ) {
    throw new Error('guard-ebpf subject and reviewed runtime scope binding disagree');
  }
  if (
    !expected.capabilities
    || !Array.isArray(expected.resolvers)
    || !expected.platformContainment
  ) {
    throw new TypeError(
      'guard-ebpf deployment verification requires the live backend context',
    );
  }
  const expectedContextDigest = sha256Digest(jcsCanonicalize({
    backendAbi: expected.backendAbi,
    objectDigest: expected.objectDigest,
    subject: ebpfPolicy.subject,
    capabilities: expected.capabilities,
    resolvers: expected.resolvers,
    platformContainment: expected.platformContainment,
  }));
  const expectedCapabilityDigest = sha256Digest(
    jcsCanonicalize(expected.capabilities),
  );
  if (
    ebpfPolicy.bindings?.targetContextDigest !== expectedContextDigest
    || policy.leaf.targetContextDigest !== expectedContextDigest
    || policy.projection.targetContextDigest !== expectedContextDigest
    || policy.leaf.capabilityDigest !== expectedCapabilityDigest
    || policy.projection.capabilityDigest !== expectedCapabilityDigest
    || jcsCanonicalize(ebpfPolicy.dns?.resolvers)
      !== jcsCanonicalize(expected.resolvers)
    || jcsCanonicalize(ebpfPolicy.platformContainment)
      !== jcsCanonicalize(expected.platformContainment)
    || ebpfPolicy.dns?.tcp !== (expected.capabilities.tcpDns === true)
    || ebpfPolicy.dns?.udp !== true
  ) {
    throw new Error(
      'rendered guard-ebpf policy does not match the live backend context',
    );
  }
  assertKnownEbpfProjection(policy, expected, policyFile.toString('utf8'));
  const reviewPublicKey = await readPublicVerificationKey(
    path.resolve(input.reviewPublicKey),
  );
  const approvalEnvelope = (await readTrustedJson(path.resolve(input.approval), {
    maximumBytes: 16 * 1024 * 1024,
    allowGroupRead: true,
  })).document;
  const approval = verifyDsseEnvelope(approvalEnvelope, {
    payloadType: REVIEW_APPROVAL_PAYLOAD_TYPE,
    trustedKeys: [{
      publicKey: reviewPublicKey,
      roles: ['review-approval'],
      audiences: [input.reviewAudience],
    }],
    role: 'review-approval',
    audience: input.reviewAudience,
  });
  validateReviewApprovalStatement(approval.statement, {
    audience: input.reviewAudience,
  });
  assertApprovalPolicyBindings(approval.statement, policy);
  const deploymentPublicKey = await readPublicVerificationKey(
    path.resolve(input.deploymentPublicKey),
  );
  const grantEnvelope = (await readTrustedJson(path.resolve(input.grant), {
    maximumBytes: 16 * 1024 * 1024,
    allowGroupRead: true,
  })).document;
  const grant = verifyDsseEnvelope(grantEnvelope, {
    payloadType: DEPLOYMENT_GRANT_PAYLOAD_TYPE,
    trustedKeys: [{
      publicKey: deploymentPublicKey,
      roles: ['guard-ebpf-deployment'],
      audiences: [input.deploymentAudience],
    }],
    role: 'guard-ebpf-deployment',
    audience: input.deploymentAudience,
  });
  const reviewKeyIds = new Set(approval.verifiedKeys.map((entry) => entry.keyId));
  if (grant.verifiedKeys.some((entry) => reviewKeyIds.has(entry.keyId))) {
    throw new Error(
      'guard-ebpf review approval and deployment grant require distinct signing keys',
    );
  }
  const subjectBindingDigest = sha256Digest(jcsCanonicalize(ebpfPolicy.subject));
  const targetBindingDigest = sha256Digest(jcsCanonicalize({
    backend: ebpfPolicy.backend,
    subject: ebpfPolicy.subject,
  }));
  validateDeploymentGrantStatement(grant.statement, {
    now: input.now,
    audience: input.deploymentAudience,
    target: 'guard-ebpf',
    backendAbi: expected.backendAbi,
    subjectBindingDigest,
  });
  const verificationTime = input.now instanceof Date
    ? input.now.getTime()
    : Number(input.now ?? Date.now());
  if (!Number.isFinite(verificationTime)) {
    throw new TypeError('guard-ebpf deployment verification clock is invalid');
  }
  if (Date.parse(approval.statement.issuedAt) > verificationTime) {
    throw new Error('review approval is future-dated');
  }
  if (Date.parse(grant.statement.issuedAt) < Date.parse(approval.statement.issuedAt)) {
    throw new Error('guard-ebpf deployment grant predates its review approval');
  }
  const grantBindings = {
    leafBundleDigest: policy.leaf.bundleDigest,
    approvalEnvelopeDigest: approval.envelopeDigest,
    targetBindingDigest,
    capabilityDigest: policy.leaf.capabilityDigest,
    renderedArtifactsDigest: policy.projection.artifactsDigest,
    activeGrantSetDigest: input.activeGrantSetDigest,
  };
  for (const [name, value] of Object.entries(grantBindings)) {
    if (grant.statement[name] !== value) {
      throw new Error(`deployment grant ${name} does not bind the guard-ebpf leaf`);
    }
  }
  return Object.freeze({
    policy,
    ebpfPolicy: Object.freeze(ebpfPolicy),
    policyPath,
    policyDigest: sha256Digest(policyFile),
    approval,
    grant,
    subjectBindingDigest,
    targetBindingDigest,
  });
}
