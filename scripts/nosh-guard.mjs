#!/usr/bin/env node

import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { constants as osConstants } from 'node:os';
import net from 'node:net';
import path from 'node:path';
import process from 'node:process';
import { createInterface } from 'node:readline/promises';
import { fileURLToPath } from 'node:url';

import {
  approveArtifactSet,
  assertTrustedCandidateDirectory,
  verifyArtifactSet,
} from '../lib/guardd/approval.js';
import { GuardClient } from '../lib/guardd/client.js';
import { executeBuildProfile } from '../lib/guardd/build-orchestrator.js';
import { BuildProfileStore } from '../lib/guardd/build-profile-store.js';
import {
  createPortableBuildReport,
  renderBuildProfileReport,
} from '../lib/guardd/build-profile-report.js';
import {
  DEFAULT_DOCKER_SOCKET,
  DEFAULT_GUARD_PROFILE_DIR,
  DEFAULT_GUARD_SOCKET,
  RUN_ACTIONS,
  SECURITY_MODES,
} from '../lib/guardd/constants.js';
import { listenGuardGateway } from '../lib/guardd/gateway.js';
import { GrantStore } from '../lib/guardd/grants.js';
import { EbpfActivationStore } from '../lib/guardd/ebpf-activation-store.js';
import {
  DEFAULT_EBPF_EGRESS_RESOLVERS,
  EBPF_EGRESS_BACKEND_ABI,
  normalizeEbpfResolvers,
  readInstalledEbpfBackendHealth,
  validateEbpfTargetContextDocument,
} from '../lib/guardd/enforcement-backend.js';
import {
  approveEgressCandidateBundle,
  canonicalWorkspace,
  createEgressCandidateBundle,
  NetProfileRegistry,
  verifyEgressApprovalBundle,
  verifyEgressCandidateBundle,
  workspaceKey,
} from '../lib/guardd/net-profile-store.js';
import {
  readCurrentUserMirror,
  reviewCandidateDirectory,
  resolveInvokingUser,
  writeInvokingUserMirror,
} from '../lib/guardd/net-profile-mirror.js';
import { PrincipalStore } from '../lib/guardd/principals.js';
import { normalizeGatewayPublicOrigin } from '../lib/guardd/proxy-contract.js';
import { buildRunnerSpec, summarizeRunnerSpec } from '../lib/guardd/runner-spec.js';
import { listenGuardServer } from '../lib/guardd/server.js';
import { commandReview } from '../lib/guard/review/cli.js';
import { commandPolicy } from '../lib/guard/review/policy-cli.js';
import { commandGateway } from '../lib/guard/review/gateway-cli.js';
import { commandDeployment } from '../lib/guard/review/deployment-cli.js';
import { readTrustedJson } from '../lib/guard/review/io.js';

const DOCTOR_SCRIPT = fileURLToPath(
  new URL('./nosh-guard-doctor.sh', import.meta.url),
);
const PRIVILEGED_BUILD_SOCKET = '/run/nosh-guardd.sock';
const PRIVILEGED_BUILD_STATE_DIR = '/var/lib/nosh-guard';
const MAX_BUILD_EVIDENCE_EXPORT_BYTES = 128 * 1024 * 1024;

const HELP = `Usage: nosh-guard <command> [options]

Commands:
  daemon                     Run the root-owned Unix-socket supervisor
  doctor                     Check Docker, kernel, Tetragon, IG, AppArmor, and nftables
  run                        Start or manage a guarded runner
  runs                       List guarded runners
  profile compile            Compile evidence into independent candidate artifacts
  profile approve            Approve and hash an artifact set
  profile verify             Verify an approved artifact set
  net learn|audit|approve|enforce|status
                             Learn and audit per-workspace outbound behavior;
                             enforce uses only an active signed guard-ebpf deployment
  build profile|status       Profile a Docker build with BuildKit and eBPF
  build net learn|status     Learn a clean build's outbound network behavior
  review bundle|inspect|serve|keygen|approve|sbom
                             Build and inspect the semantic policy-review graph
  policy project             Compile accepted graph decisions for one target
  deployment grant           Issue a short-lived eBPF activation grant
  ebpf status|activate       Inspect or atomically activate signed eBPF policy
  gateway grant              Issue a legacy external-gateway grant
  principal add|list|revoke  Bind a short-lived mTLS identity to one runner
  grant create|list|revoke   Manage audited dependency-fetch egress grants

Run options:
  --mode learn|audit|enforce|egress-learn|egress-audit|egress-enforce
  --action start|attach|stop|rm|recreate
  --image IMAGE
  --name NAME
  --workdir PATH
  --agent-id ID
  --profile ROLE[,ROLE...]
  --profile-dir PATH          Candidate/approved security artifact directory
  --resolver IP               Scoped egress resolver; repeatable
  --network INTERNAL_NETWORK
  --socket PATH               Root-owned guard management socket
  --collab | --no-collab
  --start-app | --no-start-app
  --persist                   Keep an interactive start after its shell exits
  --dry-run

Principal add options:
  --id ID
  --fingerprint SHA256
  --run RUN_ID | --agent-id AGENT_ID
  --prefix PATH               Narrow the runner route set; repeat as needed
  --ttl-seconds NUMBER

Profile compile options:
  --evidence PATH             Completed evidence-manifest.json or direct fixture;
                              repeat for distinct completed runs
  --output PATH               New candidate artifact directory
  --tetragon-rules PATH       Reviewed JSON hook fragments for Tetragon
  --reviewed-tetragon-enforcement
                              Confirm the supplied blocking actions were reviewed

Environment:
  NOSH_GUARD_SOCKET           Unix socket (default: ${DEFAULT_GUARD_SOCKET})
  NOSH_GUARD_STATE_DIR        Host-owned state directory
  NOSH_GUARD_CONFIG_DIR       Host-owned configuration directory
  NOSH_GUARD_ADAPTER_CONFIG   Sensor/enforcement adapter configuration
  NOSH_GUARD_BUILD_ADAPTER_CONFIG
                              Build-profile sensor configuration
  NOSH_GUARD_PRIVILEGED_BIN   Root-owned helper used only for build sessions
  NOSH_GUARD_GATEWAY_PUBLIC_ORIGIN
                              Exact external HTTPS origin for guarded UI/API
`;

const EBPF_HELP = `Usage: nosh-guard ebpf <command> [options]

Commands:
  status                     Show installed backend and activation state
  activate                   Import a reviewed policy using its one-time grant

Status options:
  --json                     Emit machine-readable JSON

Activate options:
  --bundle DIR               Private DecisionSet projection, approval, and grant
  --target-context FILE      User-owned Guard eBPF target context from profiling

Both commands require root. Activation reads the bundle and target context as
the invoking sudo user, verifies the installed loader object digest, consumes
the signed one-time deployment grant, and advances root-owned state atomically.
`;

const BUILD_HELP = `Usage: nosh-guard build <command> [options]

Commands:
  profile [CONTEXT] [-- BUILDX_ARGS...]
                            Capture BuildKit timing plus cgroup-scoped eBPF
                            process, syscall, DNS, and L3/L4 evidence
  status [CONTEXT]          Show build profile state for a project
  net learn [CONTEXT] [-- BUILDX_ARGS...]
                            Learn outbound behavior from a fresh, no-cache build
  net status [CONTEXT]      Show build-network candidate state

Profile and net-learn selectors:
  --file PATH               Dockerfile path (default: CONTEXT/Dockerfile)
  --variant NAME            Select CONTEXT/Dockerfile.NAME
  --tag IMAGE               Output tag; repeatable
  --target STAGE            Dockerfile target
  --platform PLATFORM       Exactly one platform (default: local architecture)
  --build-arg NAME[=VALUE]  Build argument; repeatable and redacted in reports
  --push                    Push the result instead of loading it locally
  --output SPEC             Buildx exporter; repeatable
  --no-load                 Do not inject the default local image load
  --json                    With net learn: print the redacted portable result
  --private-json            Print the full private result; may expose host and
                            observed build details in logs
  --http-capture MODE       With net learn: none (default) or mitmproxy
  --dry-run                 Resolve and validate without Docker or elevation

Profile-only options:
  --cache-mode compare|cold|warm
                            Default compare runs a cold pass then a warm pass
  --depth balanced|policy|deep
                            Policy adds required file-open evidence; deep requires separate sensors

Status options:
  --run ID                  Show one run instead of the project history
  --json                    Emit JSON

Build profiles and runtime Guard profiles are independent. Build output
digests are informational only; v1 creates reviewable candidates but does not
approve or enforce them.
`;

const NET_HELP = `Usage: nosh-guard net <command> [options]

Commands:
  learn      Open a network-learning shell, or observe headlessly for a duration,
             then finalize evidence and remember it
  audit      Run the current candidate in non-blocking would-deny mode
  approve    Record a legacy local review acknowledgement (non-activating)
  enforce    Run the active signed guard-ebpf deployment with default-deny egress
  status     Show the current workspace network policy state

Common options:
  --workdir PATH            Workspace to identify (default: cwd)
  --dry-run                 Print the resolved operation without changing state

Learn, audit, and enforce launch options:
  --image IMAGE             Runner image (learn default: nosh)
  --name NAME               Runner name (learn default: workspace plus path hash)
  --agent-id ID             Guard agent identity
  --profile ROLE[,ROLE...]  Guard role metadata to replay with the launch
  --resolver IP             Explicit runtime resolver; repeatable and saved
  --config PATH             Explicit Notty configuration inside the workspace
  --collab | --no-collab
  --start-app | --no-start-app
  --socket PATH             Root-owned guard management socket

Learn-only options:
  --duration SECONDS        Observe headlessly for 1..86400 seconds with
                            periodic runner and adapter health validation
  --json                    With --duration, print exact learned revision,
                            artifact paths, hashes, mirror, evidence, and timing

Timed learn treats the first SIGINT/SIGTERM as an orderly cleanup request.
Repeat the signal only to force an emergency exit from a wedged cleanup RPC.

Approve options:
  --reviewer ID             Reviewer identity (required with non-interactive --yes)
  --revision REVISION       Require this exact current candidate revision
  --yes                     Approve without the interactive confirmation

Enforce options:
  --revision REVISION       Require this exact learned launch-settings revision;
                            policy authority requires prior 'nosh-guard ebpf activate'

Status options:
  --json                    Print the receipt as JSON
  --repair                  Rebuild the invoking user's non-authoritative mirror
`;

const BOOLEAN_FLAGS = new Set([
  'all',
  'allow-incomplete',
  'collab',
  'dry-run',
  'help',
  'json',
  'no-collab',
  'no-load',
  'no-start-app',
  'noauth',
  'persist',
  'private-json',
  'push',
  'repair',
  'replace',
  'reviewed-tetragon-enforcement',
  'start-app',
  'yes',
]);
const REPEAT_FLAGS = new Set([
  'build-arg',
  'evidence',
  'output',
  'prefix',
  'profile',
  'publish',
  'resolver',
  'tag',
]);
const RUN_FLAGS = new Set([
  'action',
  'agent-id',
  'allow-incomplete',
  'collab',
  'config',
  'dry-run',
  'help',
  'image',
  'mode',
  'name',
  'network',
  'no-collab',
  'no-start-app',
  'persist',
  'profile',
  'profile-dir',
  'profile-revision',
  'publish',
  'resolver',
  'socket',
  'start-app',
  'workdir',
]);
const DAEMON_FLAGS = new Set([
  'adapter-config',
  'allow-incomplete',
  'build-adapter-config',
  'gateway-ca',
  'gateway-cert',
  'gateway-host',
  'gateway-key',
  'gateway-port',
  'gateway-public-origin',
  'help',
  'socket',
  'state-dir',
]);

const BUILD_PROFILE_FLAGS = new Set([
  'build-arg',
  'cache-mode',
  'depth',
  'dry-run',
  'file',
  'help',
  'no-load',
  'output',
  'platform',
  'private-json',
  'push',
  'tag',
  'target',
  'variant',
]);
const BUILD_NET_LEARN_FLAGS = new Set(
  [
    ...[...BUILD_PROFILE_FLAGS].filter((name) => !['cache-mode', 'depth'].includes(name)),
    'http-capture',
    'json',
  ],
);
const BUILD_STATUS_FLAGS = new Set(['dry-run', 'help', 'json', 'run']);
const BUILD_SESSION_FLAGS = new Set();

const NET_LAUNCH_FLAGS = [
  'agent-id',
  'collab',
  'config',
  'dry-run',
  'help',
  'image',
  'name',
  'no-collab',
  'no-start-app',
  'profile',
  'resolver',
  'socket',
  'start-app',
  'state-dir',
  'workdir',
];

const NET_FLAGS = Object.freeze({
  learn: new Set([...NET_LAUNCH_FLAGS, 'duration', 'json']),
  audit: new Set(NET_LAUNCH_FLAGS),
  enforce: new Set([...NET_LAUNCH_FLAGS, 'revision']),
  approve: new Set([
    'dry-run',
    'help',
    'reviewer',
    'revision',
    'state-dir',
    'workdir',
    'yes',
  ]),
  status: new Set([
    'dry-run',
    'help',
    'json',
    'repair',
    'state-dir',
    'workdir',
  ]),
});

function flagName(value) {
  return value.slice(2).replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`);
}

function parseFlags(argv) {
  const options = {};
  const positionals = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--') {
      positionals.push(...argv.slice(index + 1));
      break;
    }
    if (!argument.startsWith('--')) {
      positionals.push(argument);
      continue;
    }
    const separator = argument.indexOf('=');
    const name = flagName(separator === -1 ? argument : argument.slice(0, separator));
    if (BOOLEAN_FLAGS.has(name)) {
      if (separator !== -1) {
        throw new TypeError(`--${name} does not take a value`);
      }
      options[name] = true;
      continue;
    }
    let value;
    if (separator !== -1) {
      value = argument.slice(separator + 1);
    } else {
      value = argv[index + 1];
      if (value == null || value.startsWith('--')) {
        throw new TypeError(`--${name} requires a value`);
      }
      index += 1;
    }
    if (REPEAT_FLAGS.has(name)) {
      options[name] ||= [];
      options[name].push(value);
    } else {
      if (name === 'http-capture' && Object.hasOwn(options, name)) {
        throw new TypeError('--http-capture may be supplied only once');
      }
      options[name] = value;
    }
  }
  return { options, positionals };
}

function requireOption(options, name) {
  const value = options[name];
  if (typeof value !== 'string' || !value) {
    throw new TypeError(`--${name} is required`);
  }
  return value;
}

function requireSingleOption(options, name) {
  const value = options[name];
  if (!Array.isArray(value)) {
    return requireOption(options, name);
  }
  if (value.length !== 1) {
    throw new TypeError(`--${name} must be specified exactly once`);
  }
  return requireOption({ [name]: value[0] }, name);
}

function assertKnownOptions(options, allowed, command) {
  const unknown = Object.keys(options).filter((name) => !allowed.has(name));
  if (unknown.length) {
    throw new TypeError(
      `${command} does not support ${unknown.map((name) => `--${name}`).join(', ')}`,
    );
  }
}

function printJson(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function profileRoles(options) {
  return (options.profile || [])
    .flatMap((value) => value.split(','))
    .map((value) => value.trim())
    .filter(Boolean);
}

async function ensureConfigVisible(configPath, workdir) {
  if (!configPath) {
    return null;
  }
  const resolved = await fs.realpath(configPath);
  const relative = path.relative(workdir, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(
      'secure runner config must be inside the mounted workdir; copy it into .notty/',
    );
  }
  return resolved;
}

async function runRequest(options) {
  if (options['allow-incomplete']) {
    throw new TypeError('--allow-incomplete is disabled for guarded runners');
  }
  const mode = requireOption(options, 'mode');
  const action = options.action || 'start';
  if (!SECURITY_MODES.includes(mode)) {
    throw new TypeError(`--mode must be one of: ${SECURITY_MODES.join(', ')}`);
  }
  if (!RUN_ACTIONS.includes(action)) {
    throw new TypeError(`--action must be one of: ${RUN_ACTIONS.join(', ')}`);
  }
  const name = requireOption(options, 'name');
  const workdir = path.resolve(requireOption(options, 'workdir'));
  const image = requireOption(options, 'image');
  const requestedPublishes = options.publish || [];
  if (requestedPublishes.length) {
    throw new TypeError(
      'guarded runners cannot publish Docker ports; use the authenticated mTLS gateway',
    );
  }
  const requestedNetwork =
    options.network || process.env.NOSH_GUARD_NETWORK || null;
  if (requestedNetwork) {
    throw new TypeError(
      'guarded runners cannot select a Docker network; the guard creates one isolated network per run',
    );
  }

  if (!['start', 'recreate'].includes(action)) {
    return { action, name };
  }

  const configPath = await ensureConfigVisible(options.config, workdir);
  const collab = options.collab ? true : options['no-collab'] ? false : false;
  const startApp = options['start-app']
    ? true
    : options['no-start-app']
      ? false
      : false;
  const roles = profileRoles(options);
  const resolverInput = options.resolver == null
    ? null
    : Array.isArray(options.resolver)
      ? options.resolver
      : [options.resolver];
  if (resolverInput?.some((value) => !net.isIP(String(value)))) {
    throw new TypeError('--resolver accepts only IPv4 or IPv6 addresses');
  }
  const resolvers = resolverInput
    ? normalizeEbpfResolvers(resolverInput)
    : null;
  const requestedProfileDir =
    options['profile-dir'] || (
      String(mode).startsWith('egress-')
        ? null
        : process.env.NOSH_GUARD_PROFILE_DIR || null
    );
  const environment = {
    NOTTY_COLLAB_ENABLED: String(collab),
    NOTTY_COLLAB_UNSANDBOXED: 'false',
    NOTTY_NOSH_PROFILES: roles.join(','),
  };
  // The runner lives on an internal network and is reachable only through the
  // mTLS guard gateway. Do not copy host control-plane credentials into it.
  environment.NOTTY_BASIC_AUTH_ENABLED = 'false';
  if (configPath) {
    environment.NOTTY_CONFIG = configPath;
  }

  return {
    action,
    mode,
    image,
    name,
    workdir,
    agentId: options['agent-id'] || name,
    roles,
    ...(resolvers ? { resolvers } : {}),
    profileDir: requestedProfileDir ? path.resolve(requestedProfileDir) : null,
    profileRevision: options['profile-revision'] || null,
    startApp,
    persist: Boolean(options.persist),
    allowIncomplete: Boolean(options['allow-incomplete']),
    environment,
  };
}

export function assertRootManagement(geteuid = process.geteuid) {
  if (typeof geteuid === 'function' && geteuid() !== 0) {
    const error = new Error(
      'guard lifecycle control requires explicit root authority for the '
        + 'root-only management socket; re-run nosh or nosh-guard with sudo '
        + '(credentials are not forwarded)',
    );
    error.code = 'GUARD_ROOT_REQUIRED';
    throw error;
  }
}

export function guardClientForOptions(options = {}) {
  return new GuardClient({
    socketPath: options.socket || process.env.NOSH_GUARD_SOCKET,
  });
}

function interactiveTerminal(streams = process) {
  return Boolean(streams.stdin?.isTTY && streams.stdout?.isTTY);
}

function netLearnDuration(options = {}) {
  if (options.duration == null) {
    return null;
  }
  if (
    typeof options.duration !== 'string'
    || !/^[1-9][0-9]*$/.test(options.duration)
  ) {
    throw new TypeError('--duration must be an integer from 1 to 86400');
  }
  const durationSeconds = Number(options.duration);
  if (!Number.isSafeInteger(durationSeconds) || durationSeconds > 86_400) {
    throw new TypeError('--duration must be an integer from 1 to 86400');
  }
  return durationSeconds;
}

function createObservationSignalLifecycle(options = {}) {
  const signalSource = options.signalSource || process;
  const signalNow = options.signalNow || Date.now;
  const duplicateSignalWindowMs = 1_000;
  let signal = null;
  let status = null;
  let committed = false;
  let lateSignal = null;
  let lastSignal = null;
  let lastSignalAt = null;
  let resolveSignal;
  const promise = new Promise((resolve) => {
    resolveSignal = resolve;
  });
  const handlers = new Map();
  const forceExit = options.forceExitImpl || ((exitStatus) => {
    process.exit(exitStatus);
  });
  const removeSignalListener = (name, listener) => {
    if (typeof signalSource.off === 'function') {
      signalSource.off(name, listener);
    } else {
      signalSource.removeListener(name, listener);
    }
  };
  const dispose = () => {
    for (const [name, listener] of handlers) {
      removeSignalListener(name, listener);
    }
    handlers.clear();
  };
  for (const name of ['SIGINT', 'SIGTERM']) {
    const listener = () => {
      const receivedAt = Number(signalNow());
      if (
        name === lastSignal
        && Number.isFinite(receivedAt)
        && Number.isFinite(lastSignalAt)
        && receivedAt >= lastSignalAt
        && receivedAt - lastSignalAt <= duplicateSignalWindowMs
      ) {
        // A foreground terminal signal reaches both this process and the
        // supervising shell's process group. The shell relays it as well;
        // coalesce that immediate duplicate without weakening a later,
        // deliberate second-signal escape.
        return;
      }
      lastSignal = name;
      lastSignalAt = receivedAt;
      const signalNumber = osConstants.signals[name];
      const signalStatus = Number.isInteger(signalNumber)
        ? 128 + signalNumber
        : 1;
      if (committed) {
        if (lateSignal !== null) {
          dispose();
          forceExit(signalStatus, name);
          return;
        }
        lateSignal = name;
        return;
      }
      if (signal !== null) {
        dispose();
        forceExit(signalStatus, name);
        return;
      }
      signal = name;
      status = signalStatus;
      resolveSignal(status);
    };
    handlers.set(name, listener);
    signalSource.on(name, listener);
  }
  return {
    get signal() {
      return signal;
    },
    get status() {
      return status;
    },
    get lateSignal() {
      return lateSignal;
    },
    promise,
    beginCommit() {
      if (status !== null) {
        return false;
      }
      committed = true;
      return true;
    },
    dispose,
  };
}

function monotonicMilliseconds() {
  return Number(process.hrtime.bigint()) / 1_000_000;
}

async function waitForObservationTick(milliseconds, signalLifecycle, options) {
  const setTimeoutImpl = options.setTimeoutImpl || setTimeout;
  const clearTimeoutImpl = options.clearTimeoutImpl || clearTimeout;
  let timer = null;
  const elapsed = new Promise((resolve) => {
    timer = setTimeoutImpl(() => resolve('elapsed'), milliseconds);
  });
  try {
    return await Promise.race([
      elapsed,
      signalLifecycle.promise.then(() => 'signal'),
    ]);
  } finally {
    if (timer != null) {
      clearTimeoutImpl(timer);
    }
  }
}

export async function waitForObservationWindow(durationSeconds, options = {}) {
  if (
    !Number.isSafeInteger(durationSeconds)
    || durationSeconds < 1
    || durationSeconds > 86_400
  ) {
    throw new TypeError('observation duration must be an integer from 1 to 86400');
  }
  const pollIntervalMilliseconds = options.pollIntervalMilliseconds ?? 5_000;
  if (
    !Number.isSafeInteger(pollIntervalMilliseconds)
    || pollIntervalMilliseconds < 1
    || pollIntervalMilliseconds > 60_000
  ) {
    throw new TypeError('observation poll interval must be an integer from 1 to 60000');
  }
  const now = options.monotonicNow || monotonicMilliseconds;
  const ownSignalLifecycle = !options.signalLifecycle;
  const signalLifecycle = options.signalLifecycle
    || createObservationSignalLifecycle(options);
  const startedAt = now();
  const requestedMilliseconds = durationSeconds * 1000;
  try {
    for (;;) {
      const beforeWait = Math.max(0, now() - startedAt);
      if (signalLifecycle.status !== null) {
        return {
          status: signalLifecycle.status,
          signal: signalLifecycle.signal,
          requestedDurationSeconds: durationSeconds,
          observedDurationMilliseconds: Math.floor(beforeWait),
          observationComplete: false,
        };
      }
      const remaining = requestedMilliseconds - beforeWait;
      if (remaining <= 0) {
        return {
          status: 0,
          signal: null,
          requestedDurationSeconds: durationSeconds,
          observedDurationMilliseconds: Math.floor(beforeWait),
          observationComplete: true,
        };
      }
      const outcome = await waitForObservationTick(
        Math.min(remaining, pollIntervalMilliseconds),
        signalLifecycle,
        options,
      );
      if (outcome === 'signal') {
        const observed = Math.max(0, now() - startedAt);
        return {
          status: signalLifecycle.status,
          signal: signalLifecycle.signal,
          requestedDurationSeconds: durationSeconds,
          observedDurationMilliseconds: Math.floor(observed),
          observationComplete: false,
        };
      }
      if (typeof options.revalidate === 'function') {
        // This is deliberately serialized. A signal is latched while the RPC
        // is in flight, but stop never races a pending attach revalidation.
        await options.revalidate();
      }
      const observed = Math.max(0, now() - startedAt);
      if (observed >= requestedMilliseconds) {
        return {
          status: signalLifecycle.status ?? 0,
          signal: signalLifecycle.signal,
          requestedDurationSeconds: durationSeconds,
          observedDurationMilliseconds: Math.floor(observed),
          observationComplete: true,
        };
      }
    }
  } finally {
    if (ownSignalLifecycle) {
      signalLifecycle.dispose();
    }
  }
}

function shellExitStatus(result) {
  if (result.error) {
    throw result.error;
  }
  if (Number.isInteger(result.status)) {
    return result.status;
  }
  if (result.signal) {
    const signalNumber = osConstants.signals[result.signal];
    if (Number.isInteger(signalNumber)) {
      return 128 + signalNumber;
    }
  }
  throw new Error('guarded shell exited without a status');
}

export function execGuardedShell(run, options = {}) {
  if (
    typeof run?.containerId !== 'string'
    || !/^[a-f0-9]{64}$/i.test(run.containerId)
  ) {
    throw new Error('revalidated run did not return an exact Docker container ID');
  }
  if (typeof run.workdir !== 'string' || !path.isAbsolute(run.workdir)) {
    throw new Error('revalidated run did not return an absolute workdir');
  }
  const dockerSocket =
    run.attachment?.dockerSocket || DEFAULT_DOCKER_SOCKET;
  if (
    typeof dockerSocket !== 'string'
    || !path.isAbsolute(dockerSocket)
    || /[\r\n]/.test(dockerSocket)
  ) {
    throw new Error('revalidated run did not return an absolute Docker socket');
  }
  const spawnSyncImpl = options.spawnSyncImpl || spawnSync;
  return shellExitStatus(
    spawnSyncImpl(
      'docker',
      [
        '--host',
        `unix://${dockerSocket}`,
        'exec',
        '-it',
        '--workdir',
        run.workdir,
        run.containerId,
        '/bin/bash',
      ],
      {
        stdio: 'inherit',
      },
    ),
  );
}

async function removeInteractiveRun(client, runId) {
  let stopError = null;
  try {
    await client.action(runId, 'stop');
  } catch (error) {
    stopError = error;
  }
  try {
    await client.action(runId, 'rm');
  } catch (removeError) {
    if (stopError) {
      throw new AggregateError(
        [stopError, removeError],
        'guarded run stop and removal both failed',
      );
    }
    throw removeError;
  }
  if (stopError) {
    throw stopError;
  }
}

export async function executeRunRequest(request, options = {}) {
  const client = options.client || new GuardClient();
  const interactive =
    options.interactive == null
      ? interactiveTerminal(options.streams || process)
      : Boolean(options.interactive);
  const print = options.print || printJson;
  const spawnSyncImpl = options.spawnSyncImpl || spawnSync;

  if (request.action === 'attach') {
    const attached = await client.action(request.name, 'attach');
    if (!interactive) {
      print(attached);
      return 0;
    }
    return execGuardedShell(attached, { spawnSyncImpl });
  }
  if (request.action === 'stop' || request.action === 'rm') {
    print(await client.action(request.name, request.action));
    return 0;
  }
  if (request.action === 'recreate') {
    try {
      await client.action(request.name, 'rm');
    } catch (error) {
      if (error.statusCode !== 404) {
        throw error;
      }
    }
  }

  const started = await client.startRun(request);
  if (!interactive) {
    print(started);
    return 0;
  }

  let shellStatus = 0;
  let shellError = null;
  try {
    const attached = await client.action(started.runId, 'attach');
    shellStatus = execGuardedShell(attached, { spawnSyncImpl });
  } catch (error) {
    shellError = error;
  }
  if (!request.persist) {
    try {
      await removeInteractiveRun(client, started.runId);
    } catch (cleanupError) {
      if (shellError) {
        throw new AggregateError(
          [shellError, cleanupError],
          'guarded shell failed and lifecycle cleanup was incomplete',
        );
      }
      throw cleanupError;
    }
  }
  if (shellError) {
    throw shellError;
  }
  return shellStatus;
}

async function commandRun(argv) {
  const { options, positionals } = parseFlags(argv);
  assertKnownOptions(options, RUN_FLAGS, 'run');
  if (options.help || positionals.length) {
    process.stdout.write(HELP);
    return options.help && !positionals.length ? 0 : 2;
  }
  const request = await runRequest(options);
  if (options['dry-run']) {
    const runner = ['start', 'recreate'].includes(request.action)
      ? buildRunnerSpec(request)
      : null;
    printJson({
      dryRun: true,
      action: request.action,
      name: request.name,
      runner: runner ? summarizeRunnerSpec(runner) : undefined,
    });
    return 0;
  }
  assertRootManagement();
  return executeRunRequest(request, {
    client: guardClientForOptions(options),
  });
}

function commandDoctor(argv) {
  const result = spawnSync('bash', [DOCTOR_SCRIPT, ...argv], {
    stdio: 'inherit',
  });
  if (result.error) {
    throw result.error;
  }
  if (Number.isInteger(result.status)) {
    return result.status;
  }
  const signalNumber = result.signal
    ? osConstants.signals[result.signal]
    : null;
  if (Number.isInteger(signalNumber)) {
    return 128 + signalNumber;
  }
  throw new Error(
    `nosh-guard doctor terminated by ${result.signal || 'an unknown signal'}`,
  );
}

async function commandDaemon(argv) {
  const { options, positionals } = parseFlags(argv);
  assertKnownOptions(options, DAEMON_FLAGS, 'daemon');
  if (options.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (positionals.length) {
    throw new TypeError('daemon does not accept positional arguments');
  }
  assertRootManagement();
  if (
    options['allow-incomplete']
    || process.env.NOSH_GUARD_ALLOW_INCOMPLETE === '1'
  ) {
    throw new TypeError('allow-incomplete is disabled for the guard daemon');
  }
  const gatewayPaths = {
    certPath:
      options['gateway-cert'] || process.env.NOSH_GUARD_GATEWAY_CERT || null,
    keyPath: options['gateway-key'] || process.env.NOSH_GUARD_GATEWAY_KEY || null,
    caPath: options['gateway-ca'] || process.env.NOSH_GUARD_GATEWAY_CA || null,
  };
  const configuredGatewayPaths = Object.values(gatewayPaths).filter(Boolean);
  const configuredPublicOrigin =
    options['gateway-public-origin'] ||
    process.env.NOSH_GUARD_GATEWAY_PUBLIC_ORIGIN ||
    null;
  if (configuredGatewayPaths.length && configuredGatewayPaths.length !== 3) {
    throw new Error(
      'mTLS gateway requires NOSH_GUARD_GATEWAY_CERT, NOSH_GUARD_GATEWAY_KEY, and NOSH_GUARD_GATEWAY_CA',
    );
  }
  if (configuredGatewayPaths.length === 3 && !configuredPublicOrigin) {
    throw new Error(
      'mTLS gateway requires NOSH_GUARD_GATEWAY_PUBLIC_ORIGIN',
    );
  }
  if (!configuredGatewayPaths.length && configuredPublicOrigin) {
    throw new Error(
      'NOSH_GUARD_GATEWAY_PUBLIC_ORIGIN requires an enabled mTLS gateway',
    );
  }
  const gatewayPublicOrigin = configuredPublicOrigin
    ? normalizeGatewayPublicOrigin(configuredPublicOrigin).origin
    : null;
  const instance = await listenGuardServer({
    socketPath: options.socket || process.env.NOSH_GUARD_SOCKET,
    stateDir: options['state-dir'] || process.env.NOSH_GUARD_STATE_DIR,
    adapterConfig:
      options['adapter-config'] || process.env.NOSH_GUARD_ADAPTER_CONFIG,
    buildAdapterConfig:
      options['build-adapter-config']
      || process.env.NOSH_GUARD_BUILD_ADAPTER_CONFIG,
    gatewayPublicOrigin,
  });
  process.stderr.write(`nosh-guardd listening on ${instance.socketPath}\n`);
  let gateway = null;
  try {
    if (configuredGatewayPaths.length) {
      gateway = await listenGuardGateway({
        ...gatewayPaths,
        service: instance.service,
        stateDir: options['state-dir'] || process.env.NOSH_GUARD_STATE_DIR,
        publicOrigin: gatewayPublicOrigin,
        host:
          options['gateway-host'] ||
          process.env.NOSH_GUARD_GATEWAY_HOST ||
          '127.0.0.1',
        port: Number(
          options['gateway-port'] ||
            process.env.NOSH_GUARD_GATEWAY_PORT ||
            3443,
        ),
      });
      process.stderr.write(
        `nosh-guard mTLS gateway listening on ${
          options['gateway-host'] ||
          process.env.NOSH_GUARD_GATEWAY_HOST ||
          '127.0.0.1'
        }:${options['gateway-port'] || process.env.NOSH_GUARD_GATEWAY_PORT || 3443}\n`,
      );
    }
  } catch (error) {
    await new Promise((resolve) => instance.server.close(resolve));
    throw error;
  }
  let shuttingDown = false;
  const shutdown = async () => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    try {
      await Promise.all([
        instance.service.shutdown(),
        instance.buildService.shutdown(),
      ]);
    } catch (error) {
      process.stderr.write(
        `nosh-guard shutdown quarantine failed: ${error.message}\n`,
      );
    } finally {
      gateway?.server.close();
      instance.server.close();
    }
  };
  process.once('SIGINT', () => void shutdown());
  process.once('SIGTERM', () => void shutdown());
  await new Promise((resolve, reject) => {
    instance.server.once('close', resolve);
    instance.server.once('error', reject);
  });
  return 0;
}

function expiryFrom(options) {
  if (options.expires) {
    const parsed = new Date(options.expires);
    if (!Number.isFinite(parsed.getTime())) {
      throw new TypeError('--expires must be an ISO timestamp');
    }
    return parsed.toISOString();
  }
  const ttlSeconds = Number(options['ttl-seconds'] || 3600);
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > 86_400) {
    throw new TypeError('--ttl-seconds must be an integer from 1 to 86400');
  }
  return new Date(Date.now() + ttlSeconds * 1000).toISOString();
}

async function commandPrincipal(argv) {
  const [subcommand, ...rest] = argv;
  const { options, positionals } = parseFlags(rest);
  if (positionals.length) {
    throw new TypeError(`unexpected principal arguments: ${positionals.join(' ')}`);
  }
  const allowed = {
    add: new Set([
      'agent-id',
      'expires',
      'fingerprint',
      'id',
      'prefix',
      'run',
      'state-dir',
      'ttl-seconds',
    ]),
    list: new Set(['state-dir']),
    revoke: new Set(['id', 'state-dir']),
  }[subcommand];
  if (!allowed) {
    throw new TypeError('principal command must be add, list, or revoke');
  }
  assertKnownOptions(options, allowed, `principal ${subcommand}`);
  assertRootManagement();
  const store = new PrincipalStore({
    stateDir: options['state-dir'] || process.env.NOSH_GUARD_STATE_DIR,
  });
  await store.initialize();
  if (subcommand === 'list') {
    printJson({ principals: await store.read() });
    return 0;
  }
  if (subcommand === 'add') {
    printJson(
      await store.add({
        id: requireOption(options, 'id'),
        certificateFingerprint: requireOption(options, 'fingerprint'),
        runId: options.run || null,
        agentId: options['agent-id'] || null,
        allowedPrefixes: options.prefix,
        expiresAt: expiryFrom(options),
      }),
    );
    return 0;
  }
  if (subcommand === 'revoke') {
    const id = requireOption(options, 'id');
    printJson({ id, revoked: await store.revoke(id) });
    return 0;
  }
  throw new TypeError('principal command must be add, list, or revoke');
}

async function commandGrant(argv) {
  const [subcommand, ...rest] = argv;
  const { options, positionals } = parseFlags(rest);
  if (positionals.length) {
    throw new TypeError(`unexpected grant arguments: ${positionals.join(' ')}`);
  }
  const allowed = {
    create: new Set([
      'actor',
      'destination',
      'icmp-code',
      'icmp-type',
      'ports',
      'protocol',
      'reason',
      'run',
      'state-dir',
      'ttl-seconds',
    ]),
    list: new Set(['all', 'state-dir']),
    revoke: new Set(['actor', 'id', 'reason', 'state-dir']),
  }[subcommand];
  if (!allowed) {
    throw new TypeError('grant command must be create, list, or revoke');
  }
  assertKnownOptions(options, allowed, `grant ${subcommand}`);
  assertRootManagement();
  const store = new GrantStore({
    stateDir: options['state-dir'] || process.env.NOSH_GUARD_STATE_DIR,
  });
  await store.initialize();
  if (subcommand === 'list') {
    printJson({
      grants: await store.list({ includeExpired: Boolean(options.all) }),
    });
    return 0;
  }
  if (subcommand === 'create') {
    printJson(
      await store.create({
        runId: options.run || null,
        destination: requireOption(options, 'destination'),
        protocol: requireOption(options, 'protocol'),
        ports: options.ports,
        icmpType: options['icmp-type'],
        icmpCode: options['icmp-code'],
        ttlSeconds: Number(options['ttl-seconds'] || 3600),
        actor:
          options.actor ||
          process.env.SUDO_USER ||
          process.env.USER ||
          'unknown',
        reason: requireOption(options, 'reason'),
      }),
    );
    return 0;
  }
  if (subcommand === 'revoke') {
    const revoked = await store.revoke(
      requireOption(options, 'id'),
      options.actor || process.env.SUDO_USER || process.env.USER || 'unknown',
      requireOption(options, 'reason'),
    );
    printJson({ revoked });
    return revoked ? 0 : 1;
  }
  throw new TypeError('grant command must be create, list, or revoke');
}

async function commandRuns(argv) {
  const { options, positionals } = parseFlags(argv);
  assertKnownOptions(options, new Set(['socket']), 'runs');
  if (positionals.length) {
    throw new TypeError('runs does not accept positional arguments');
  }
  assertRootManagement();
  printJson(
    await guardClientForOptions(options).listRuns(),
  );
  return 0;
}

function netStateDir(options = {}) {
  return options['state-dir'] || process.env.NOSH_GUARD_STATE_DIR;
}

function netTrustedRoot(options = {}) {
  const stateDir = netStateDir(options);
  return stateDir
    ? path.join(path.resolve(stateDir), 'profiles', 'net')
    : path.join(DEFAULT_GUARD_PROFILE_DIR, 'net');
}

function netRegistry(options = {}) {
  return new NetProfileRegistry({ stateDir: netStateDir(options) });
}

async function sha256Path(filePath) {
  if (!filePath) {
    return null;
  }
  const content = await fs.readFile(filePath);
  return `sha256:${crypto.createHash('sha256').update(content).digest('hex')}`;
}

function sameStrings(left = [], right = []) {
  return JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
}

function selectedBoolean(options, positive, negative) {
  if (options[positive]) {
    return true;
  }
  if (options[negative]) {
    return false;
  }
  return undefined;
}

async function defaultConfirm(message, options = {}) {
  if (!interactiveTerminal(options.streams || process)) {
    return false;
  }
  const input = options.input || process.stdin;
  const output = options.output || process.stderr;
  const reader = createInterface({ input, output });
  try {
    const answer = (await reader.question(message)).trim().toLowerCase();
    return answer === 'y' || answer === 'yes' || answer === 'approve';
  } finally {
    reader.close();
  }
}

function netName(workdir, key) {
  const slug = path.basename(workdir)
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 42) || 'workspace';
  return `nosh-${slug}-${key.slice(0, 12)}`.slice(0, 63);
}

async function learnedLaunchConfig(options, started, workdir) {
  const configPath = options.config
    ? await ensureConfigVisible(options.config, workdir)
    : null;
  return {
    image: options.image || 'nosh',
    imageReference: started.imageReference || null,
    imageDigest: started.imageDigest,
    name: started.name,
    agentId: options['agent-id'] || started.agentId || started.name,
    roles: profileRoles(options),
    resolvers: normalizeEbpfResolvers(
      started.egress?.resolvers
        || (options.resolver == null
          ? null
          : Array.isArray(options.resolver)
            ? options.resolver
            : [options.resolver])
        || DEFAULT_EBPF_EGRESS_RESOLVERS,
    ),
    configPath,
    configHash: await sha256Path(configPath),
    collab: selectedBoolean(options, 'collab', 'no-collab') === true,
    startApp: selectedBoolean(options, 'start-app', 'no-start-app') === true,
    ...(options.duration == null
      ? {}
      : { observationDurationSeconds: netLearnDuration(options) }),
  };
}

async function launchMismatches(options, stored) {
  const mismatches = [];
  const compare = (label, requested, learned) => {
    if (requested !== undefined && requested !== learned) {
      mismatches.push({ label, requested, learned });
    }
  };
  compare('image', options.image, stored.image);
  compare('name', options.name, stored.name);
  compare('agent-id', options['agent-id'], stored.agentId);
  const requestedRoles = profileRoles(options);
  if (requestedRoles.length && !sameStrings(requestedRoles, stored.roles)) {
    mismatches.push({
      label: 'profile roles',
      requested: requestedRoles.join(','),
      learned: (stored.roles || []).join(','),
    });
  }
  if (options.resolver != null) {
    const requestedResolvers = normalizeEbpfResolvers(
      Array.isArray(options.resolver) ? options.resolver : [options.resolver],
    );
    if (!sameStrings(requestedResolvers, stored.resolvers || [])) {
      mismatches.push({
        label: 'resolvers',
        requested: requestedResolvers.join(','),
        learned: (stored.resolvers || []).join(','),
      });
    }
  }
  compare('config', options.config ? path.resolve(options.config) : undefined, stored.configPath);
  compare(
    'collab',
    selectedBoolean(options, 'collab', 'no-collab'),
    stored.collab,
  );
  compare(
    'start-app',
    selectedBoolean(options, 'start-app', 'no-start-app'),
    stored.startApp,
  );
  if (stored.configPath) {
    let currentHash = null;
    try {
      currentHash = await sha256Path(stored.configPath);
    } catch (error) {
      mismatches.push({
        label: 'config contents',
        requested: error.code === 'ENOENT' ? 'missing' : error.message,
        learned: stored.configHash,
        fatal: true,
      });
    }
    if (currentHash && currentHash !== stored.configHash) {
      mismatches.push({
        label: 'config contents',
        requested: currentHash,
        learned: stored.configHash,
        fatal: true,
      });
    }
  }
  return mismatches;
}

function storedLaunchOptions(stored, workdir, profileDir) {
  return {
    mode: null,
    action: 'start',
    image: stored.imageReference || stored.image,
    name: stored.name,
    workdir,
    'agent-id': stored.agentId,
    profile: stored.roles || [],
    resolver: stored.resolvers || DEFAULT_EBPF_EGRESS_RESOLVERS,
    ...(stored.configPath ? { config: stored.configPath } : {}),
    ...(stored.collab ? { collab: true } : { 'no-collab': true }),
    ...(stored.startApp ? { 'start-app': true } : { 'no-start-app': true }),
    ...(profileDir ? { 'profile-dir': profileDir } : {}),
  };
}

async function resolveReplay(options, reference, workdir, dependencies = {}) {
  const stored = reference?.launchConfig;
  if (!stored) {
    throw new Error('remembered network profile has no launch configuration; learn again');
  }
  const mismatches = await launchMismatches(options, stored);
  if (mismatches.length) {
    const details = mismatches
      .map((entry) => `  ${entry.label}: requested ${entry.requested}; learned ${entry.learned}`)
      .join('\n');
    process.stderr.write(`nosh net: incompatible launch overrides:\n${details}\n`);
    if (mismatches.some((entry) => entry.fatal)) {
      throw new Error('learned configuration changed; run nosh net learn again');
    }
    const confirm = dependencies.confirm || defaultConfirm;
    const replay = await confirm(
      'Discard those overrides and replay the learned settings? [y/N] ',
      dependencies,
    );
    if (!replay) {
      throw new Error('network launch cancelled; relearn with the new settings');
    }
  }
  return storedLaunchOptions(stored, workdir, reference.directory);
}

function assertExactObservationAttachment(started, attached, previous = null) {
  if (attached?.runId !== started.runId || attached.status !== 'running') {
    throw new Error('timed observation revalidation returned a different or stopped run');
  }
  if (
    typeof attached.containerId !== 'string'
    || !/^[a-f0-9]{64}$/i.test(attached.containerId)
    || attached.containerId !== started.containerId
    || (previous && attached.containerId !== previous.containerId)
  ) {
    throw new Error('timed observation revalidation changed container identity');
  }
  for (const field of ['name', 'imageDigest', 'imageReference']) {
    if (
      typeof started[field] === 'string'
      && attached[field] !== started[field]
    ) {
      throw new Error(`timed observation revalidation changed ${field}`);
    }
  }
  if (
    attached.attachment?.validated !== true
    || attached.attachment.containerId !== attached.containerId
    || !Array.isArray(attached.attachment.adapters)
    || attached.attachment.adapters.some(
      (adapter) => adapter?.required !== false && adapter?.ok !== true,
    )
  ) {
    throw new Error('timed observation runner or adapter health was not validated');
  }
  return attached;
}

function normalizeObservationResult(result, durationSeconds) {
  if (result == null || Number.isSafeInteger(result)) {
    const status = result ?? 0;
    if (status < 0 || status > 255) {
      throw new Error('observation wait returned an invalid exit status');
    }
    return {
      status,
      signal: null,
      requestedDurationSeconds: durationSeconds,
      observedDurationMilliseconds: status === 0 ? durationSeconds * 1000 : 0,
      observationComplete: status === 0,
    };
  }
  if (
    typeof result !== 'object'
    || !Number.isSafeInteger(result.status)
    || result.status < 0
    || result.status > 255
    || result.requestedDurationSeconds !== durationSeconds
    || !Number.isSafeInteger(result.observedDurationMilliseconds)
    || result.observedDurationMilliseconds < 0
    || typeof result.observationComplete !== 'boolean'
    || (
      result.observationComplete
      && result.observedDurationMilliseconds < durationSeconds * 1000
    )
    || (!result.observationComplete && result.status === 0)
  ) {
    throw new Error('observation wait returned an invalid result');
  }
  return {
    status: result.status,
    signal: result.signal || null,
    requestedDurationSeconds: durationSeconds,
    observedDurationMilliseconds: result.observedDurationMilliseconds,
    observationComplete: result.observationComplete,
  };
}

export async function executeNetShellRun(request, finalize, options = {}) {
  const client = options.client || new GuardClient();
  const spawnSyncImpl = options.spawnSyncImpl || spawnSync;
  const durationSeconds = options.durationSeconds ?? null;
  if (
    durationSeconds !== null
    && (
      !Number.isSafeInteger(durationSeconds)
      || durationSeconds < 1
      || durationSeconds > 86_400
    )
  ) {
    throw new TypeError('observation duration must be an integer from 1 to 86400');
  }
  const waitForDuration = options.waitForDuration || waitForObservationWindow;
  const signalLifecycle = durationSeconds === null
    ? null
    : createObservationSignalLifecycle(options);
  try {
    const started = await client.startRun(request);
    let shellStatus = 0;
    let shellError = null;
    let attached = false;
    let observation = null;
    try {
      if (durationSeconds !== null && signalLifecycle.status !== null) {
        observation = {
          status: signalLifecycle.status,
          signal: signalLifecycle.signal,
          requestedDurationSeconds: durationSeconds,
          observedDurationMilliseconds: 0,
          observationComplete: false,
        };
        shellStatus = observation.status;
      } else {
        let attachmentResult = await client.action(started.runId, 'attach');
        attached = true;
        if (durationSeconds === null) {
          shellStatus = execGuardedShell(attachmentResult, { spawnSyncImpl });
        } else {
          attachmentResult = assertExactObservationAttachment(
            started,
            attachmentResult,
          );
          const revalidate = async () => {
            const checked = await client.action(started.runId, 'attach');
            attachmentResult = assertExactObservationAttachment(
              started,
              checked,
              attachmentResult,
            );
          };
          observation = normalizeObservationResult(
            await waitForDuration(durationSeconds, {
              ...options,
              signalLifecycle,
              revalidate,
            }),
            durationSeconds,
          );
          shellStatus = observation.status;
        }
      }
    } catch (error) {
      shellError = error;
    }

    let stopped;
    if (shellError) {
      try {
        stopped = await client.action(started.runId, 'stop');
      } catch (stopError) {
        throw new AggregateError(
          [shellError, stopError],
          'network shell and evidence finalization both failed',
        );
      }
    } else {
      stopped = await client.action(started.runId, 'stop');
    }

    if (shellError) {
      const retained = new Error(
        `guarded shell failed: ${shellError.message}; stopped run ${started.runId} retained for diagnostics${
          stopped?.evidenceManifest
            ? ` (${stopped.evidenceManifest})`
            : ''
        }`,
        { cause: shellError },
      );
      retained.code = shellError.code || 'GUARD_NET_SHELL_FAILED';
      retained.runId = started.runId;
      retained.evidenceManifest = stopped?.evidenceManifest || null;
      throw retained;
    }

    if (observation) {
      const mayCommit =
        observation.observationComplete === true
        && observation.status === 0
        && signalLifecycle.status === null
        && signalLifecycle.beginCommit();
      if (!mayCommit) {
        observation = {
          ...observation,
          status: signalLifecycle.status ?? observation.status,
          signal: signalLifecycle.signal || observation.signal,
          observationComplete: false,
        };
        shellStatus = observation.status;
      }
    }
    if (
      attached
      && (!observation || observation.observationComplete === true)
      && typeof finalize === 'function'
    ) {
      await finalize({
        started,
        stopped,
        shellStatus,
        shellError,
        observation,
      });
    }
    const finalStatus = signalLifecycle?.status ?? shellStatus;
    const completed = {
      status: finalStatus,
      started,
      stopped,
      observation: observation
        ? {
            ...observation,
            status: finalStatus,
            signal: signalLifecycle?.signal || observation.signal,
          }
        : null,
    };
    if (observation && observation.observationComplete !== true) {
      return completed;
    }
    await client.action(started.runId, 'rm');
    return completed;
  } finally {
    signalLifecycle?.dispose();
  }
}

function requireEvidenceManifest(stopped) {
  if (typeof stopped?.evidenceManifest !== 'string' || !stopped.evidenceManifest) {
    throw new Error(
      `network evidence was not finalized for ${stopped?.runId || 'the run'}; `
        + 'the stopped run was retained for diagnostics',
    );
  }
  return stopped.evidenceManifest;
}

function bundleReference(bundle, launchConfig, evidenceManifest) {
  return {
    runId: bundle.revision,
    revision: bundle.revision,
    directory: bundle.directory,
    workspaceKey: bundle.workspaceKey,
    imageDigest: bundle.profile?.spec?.target?.imageDigest || launchConfig.imageDigest,
    imageReference: launchConfig.imageReference,
    manifestHash: bundle.manifestHash || null,
    profileHash: bundle.artifacts?.['egress-profile.json'] || null,
    policyHash: bundle.artifacts?.['egress-policy.json'] || bundle.policyHash || null,
    rulesHash: bundle.rulesHash || null,
    evidenceManifestHash:
      bundle.profile?.spec?.evidence?.manifestHash || null,
    evidenceManifest,
    launchConfig,
    createdAt: bundle.profile?.metadata?.createdAt || new Date().toISOString(),
  };
}

async function policyText(reference) {
  if (!reference?.directory) {
    return null;
  }
  try {
    return await fs.readFile(path.join(reference.directory, 'egress-policy.json'), 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

function receiptFor(workdir, state) {
  return {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshEgressProfileReceipt',
    authoritative: false,
    workspace: {
      id: state?.workspaceKey || null,
      path: workdir,
    },
    enforcementScope: 'egress-only',
    latestCandidate: state?.latestCandidate || null,
    approved: state?.approved || null,
    audits: state?.audits || [],
    lastLaunch: state?.lastLaunch || null,
    limitations: [
      'outbound policy only',
      'inbound traffic receives baseline isolation but no compiled ingress policy',
      'saved launch settings are replay guidance, not policy authority',
      'this user-owned receipt is never an enforcement authority',
    ],
    updatedAt: new Date().toISOString(),
  };
}

function assertVerifiedReference(reference, verification, kind) {
  if (verification?.ok !== true) {
    throw new Error(`${kind} bundle verification returned no success result`);
  }
  const expected = {
    directory: verification.directory,
    revision: verification.revision,
    workspaceKey: verification.workspaceKey,
    imageDigest: verification.imageDigest,
    policyHash: verification.policyHash,
    manifestHash: verification.manifestHash,
    rulesHash: verification.rulesHash,
    launchConfig: verification.profile?.spec?.launch?.config,
    ...(kind === 'approved'
      ? {
          approvalHash:
            verification.approvalHash
            || verification.approval?.contentHash,
        }
      : {}),
  };
  const mismatches = Object.entries(expected).filter(([field, value]) => {
    if (value == null) return false;
    if (field === 'directory') {
      return path.resolve(reference?.[field] || '') !== path.resolve(value);
    }
    if (field === 'launchConfig') {
      return stableStringify(reference?.[field]) !== stableStringify(value);
    }
    return reference?.[field] !== value;
  });
  if (mismatches.length) {
    throw new Error(
      `${kind} workspace reference does not match its verified bundle: ${
        mismatches.map(([field]) => field).join(', ')
      }`,
    );
  }
  return verification;
}

async function updateNetMirror(registry, workdir, dependencies = {}) {
  const state = await registry.readWorkspace(workdir);
  if (!state) {
    return null;
  }
  const writer = dependencies.mirrorWriter || writeInvokingUserMirror;
  try {
    return await writer({
      workdir,
      receipt: receiptFor(workdir, state),
      candidatePolicy: await policyText(state.latestCandidate),
      approvedPolicy: await policyText(state.approved),
      ...(dependencies.reviewCandidate
        ? { reviewCandidate: dependencies.reviewCandidate }
        : {}),
    }, dependencies);
  } catch (error) {
    if (dependencies.requireMirror) {
      throw error;
    }
    process.stderr.write(
      `nosh net: warning: ${error.message}; run sudo nosh net status --repair\n`,
    );
    return null;
  }
}

async function readReviewCandidateSources(
  reference,
  stopped,
  evidenceManifestPath,
  dependencies = {},
) {
  if (dependencies.reviewCandidateSources) {
    return dependencies.reviewCandidateSources({
      reference,
      stopped,
      evidenceManifestPath,
    });
  }
  const returnedTargetContext = stopped?.egress?.targetContextPath || '';
  const targetContextPath = path.resolve(returnedTargetContext);
  const evidenceDirectory = path.dirname(path.resolve(evidenceManifestPath));
  if (
    !path.isAbsolute(returnedTargetContext)
    || path.basename(targetContextPath) !== 'guard-ebpf-target-context.json'
    || path.dirname(targetContextPath) !== evidenceDirectory
  ) {
    throw new Error(
      'stopped egress run did not return its exact Guard eBPF target context',
    );
  }
  const expectedUid = (dependencies.geteuid || process.geteuid)?.();
  const readJson = dependencies.readTrustedJson || readTrustedJson;
  const sources = await Promise.all([
    ['profileSource', path.join(reference.directory, 'egress-profile.json')],
    ['policySource', path.join(reference.directory, 'egress-policy.json')],
    ['manifestSource', path.join(reference.directory, 'manifest.json')],
    ['targetContextSource', targetContextPath],
  ].map(async ([field, sourcePath]) => {
    const trusted = await readJson(sourcePath, {
      expectedUid,
      maximumBytes: 16 * 1024 * 1024,
    });
    return [field, trusted.content.toString('utf8')];
  }));
  return Object.fromEntries(sources);
}

function auditWouldDeny(manifest) {
  return Number(
    manifest?.egressEvaluation?.wouldDenyCount ??
      manifest?.auditEvaluation?.backends?.network?.wouldDenyCount ??
      0,
  );
}

function auditDnsWouldDeny(manifest) {
  return Number(manifest?.egressEvaluation?.dnsWouldDenyCount ?? 0);
}

function auditDenied(manifest) {
  return Number(manifest?.egressEvaluation?.deniedCount ?? 0);
}

function displayRule(rule) {
  const ports = Array.isArray(rule.ports) && rule.ports.length
    ? `:${rule.ports.join(',')}`
    : '';
  return `${rule.protocol} ${rule.destination}${ports}`;
}

function displayRules(verification, previous = null) {
  const lines = (verification.rules || []).map((rule) => {
    return `  ${displayRule(rule)}`;
  });
  const previousRules = new Map(
    (previous?.rules || []).map((rule) => [JSON.stringify(rule), rule]),
  );
  const currentRules = new Map(
    (verification.rules || []).map((rule) => [JSON.stringify(rule), rule]),
  );
  const additions = [...currentRules]
    .filter(([key]) => !previousRules.has(key))
    .map(([, rule]) => `  + ${displayRule(rule)}`);
  const removals = [...previousRules]
    .filter(([key]) => !currentRules.has(key))
    .map(([, rule]) => `  - ${displayRule(rule)}`);
  const changes = previous
    ? [
        `Changes from approved ${previous.revision}:`,
        ...(
          additions.length || removals.length
            ? [...additions, ...removals]
            : ['  (no rule changes)']
        ),
      ]
    : [];
  const unresolved = verification.policy?.spec?.unresolvedObservations || [];
  const unresolvedLines = unresolved.slice(0, 10).map((observation) =>
    `    - ${observation.reason || 'unresolved network observation'}`,
  );
  const wildcardRules = (verification.rules || []).filter((rule) =>
    String(rule.destination || '').startsWith('*.'),
  );
  process.stderr.write(
    [
      `Outbound policy ${verification.revision}:`,
      ...(lines.length ? lines : ['  (empty: all outbound traffic will be denied)']),
      ...changes,
      ...(unresolved.length
        ? [
            `  warning: ${unresolved.length} unresolved observation(s):`,
            ...unresolvedLines,
            ...(unresolved.length > unresolvedLines.length
              ? [`    - ... ${unresolved.length - unresolvedLines.length} more`]
              : []),
          ]
        : []),
      ...(wildcardRules.length
        ? ['  warning: wildcard rules match exactly one DNS label']
        : []),
      '  limitation: ingress policy is not enforced',
      '  limitation: saved launch settings are replay guidance, not policy authority',
      '',
    ].join('\n'),
  );
}

function humanNetStatus(receipt) {
  const candidate = receipt.latestCandidate;
  const approved = receipt.approved;
  const lastProfile = [approved, candidate].find(
    (reference) =>
      reference?.revision && reference.revision === receipt.lastLaunch?.revision,
  );
  const launch = candidate?.launchConfig || approved?.launchConfig || {};
  const audits = Array.isArray(receipt.audits)
    ? receipt.audits.filter(
        (audit) => !candidate?.revision || audit.revision === candidate.revision,
      )
    : [];
  const completeAudits = audits.filter((audit) => audit.complete === true);
  const wouldDeny = audits.reduce(
    (total, audit) => total + Number(audit.wouldDenyCount || 0),
    0,
  );
  const dnsWouldDeny = audits.reduce(
    (total, audit) => total + Number(audit.dnsWouldDenyCount || 0),
    0,
  );
  const denied = audits.reduce(
    (total, audit) => total + Number(audit.deniedCount || 0),
    0,
  );
  return [
    `Workspace: ${receipt.workspace?.path || 'unknown'}`,
    `Scope: ${receipt.enforcementScope || 'egress-only'}`,
    `Candidate: ${candidate?.revision || 'none'}`,
    `Approved: ${approved?.revision || 'none'}`,
    `Image: ${candidate?.imageDigest || approved?.imageDigest || 'unknown'}`,
    `Learned roles: ${launch.roles?.length ? launch.roles.join(', ') : 'none'}`,
    `Learned collab/start-app: ${Boolean(launch.collab)}/${Boolean(launch.startApp)}`,
    `Learned observation: ${
      Number.isSafeInteger(launch.observationDurationSeconds)
        ? `${launch.observationDurationSeconds}s headless window`
        : 'interactive shell'
    }`,
    `Candidate audits: ${completeAudits.length}/${audits.length} complete, ${wouldDeny} network would-deny, ${dnsWouldDeny} DNS would-deny, ${denied} invariant deny decision(s)`,
    `Last launch: ${receipt.lastLaunch?.mode || 'none'}${
      receipt.lastLaunch?.revision ? ` (${receipt.lastLaunch.revision})` : ''
    }${receipt.lastLaunch?.runId ? `, run ${receipt.lastLaunch.runId}` : ''}`,
    `Last profile bundle: ${
      receipt.lastLaunch?.profileDirectory
      || lastProfile?.directory
      || 'none'
    }`,
    `Authoritative integrity: ${
      receipt.integrity?.ok === true
        ? 'verified'
        : receipt.integrity?.ok === false
          ? 'FAILED'
          : 'not checked (user receipt)'
    }`,
    'Ingress policy: not enforced (baseline isolation only)',
  ].join('\n');
}

async function authoritativeIntegrity(state, workdir, options, dependencies) {
  const checks = {};
  const failures = [];
  for (const [label, reference, verifier] of [
    [
      'candidate',
      state.latestCandidate,
      dependencies.verifyCandidate || verifyEgressCandidateBundle,
    ],
    [
      'approved',
      state.approved,
      dependencies.verifyApproval || verifyEgressApprovalBundle,
    ],
  ]) {
    if (!reference) {
      checks[label] = { present: false, ok: true };
      continue;
    }
    try {
      const verified = await verifier(reference.directory, {
        trustedRoot: netTrustedRoot(options),
        workdir,
      });
      assertVerifiedReference(reference, verified, label);
      checks[label] = {
        present: true,
        ok: verified?.ok === true,
        revision: reference.revision,
      };
    } catch (error) {
      checks[label] = {
        present: true,
        ok: false,
        revision: reference.revision,
        error: error.message,
      };
      failures.push(`${label}: ${error.message}`);
    }
  }
  return { ok: failures.length === 0, checks, failures };
}

async function commandNetLearn(options, dependencies = {}, durationSeconds = null) {
  const workdir = await canonicalWorkspace(options.workdir || process.cwd());
  const key = await workspaceKey(workdir);
  const registry = dependencies.registry || netRegistry(options);
  await registry.initialize();
  const requestOptions = {
    ...options,
    mode: 'egress-learn',
    action: 'start',
    image: options.image || 'nosh',
    name: options.name || netName(workdir, key),
    workdir,
  };
  const request = await runRequest(requestOptions);
  let learnedResult = null;
  const result = await executeNetShellRun(
    request,
    async ({ started, stopped, observation }) => {
      if (durationSeconds !== null && observation?.observationComplete !== true) {
        return;
      }
      const evidenceManifestPath = requireEvidenceManifest(stopped);
      const evidenceManifest = JSON.parse(
        await fs.readFile(evidenceManifestPath, 'utf8'),
      );
      if (evidenceManifest.complete !== true) {
        throw new Error(
          `network evidence is incomplete: ${evidenceManifestPath}; stopped run retained`,
        );
      }
      const compiler = await import('../lib/guard/index.js');
      const loadEvidence = dependencies.loadEvidenceInputs || compiler.loadEvidenceInputs;
      const compileNetwork = dependencies.compileNetworkArtifact || compiler.compileNetworkArtifact;
      const loaded = await loadEvidence([evidenceManifestPath]);
      const policy = compileNetwork(loaded.records, {
        name: `${path.basename(workdir)}-${key.slice(0, 12)}`,
        runProvenance: loaded.runProvenance,
        ingestion: loaded.ingestion,
      });
      const launchConfig = await learnedLaunchConfig(requestOptions, started, workdir);
      const createCandidate = dependencies.createCandidate || createEgressCandidateBundle;
      const bundle = await createCandidate({
        stateDir: netStateDir(options),
        workdir,
        runId: stopped.runId,
        imageDigest: stopped.imageDigest || started.imageDigest,
        imageReference: stopped.imageReference || started.imageReference,
        evidenceManifestPath,
        rules: policy.spec?.egress || [],
        unresolvedObservations: (policy.spec?.unresolvedObservations || [])
          .filter((entry) => entry.direction !== 'ingress'),
        launchConfig,
      });
      const reference = bundleReference(bundle, launchConfig, evidenceManifestPath);
      if (bundle.registryRegistered !== true) {
        await registry.setLatestCandidate(workdir, reference);
      }
      await registry.recordLastLaunch(workdir, {
        mode: 'egress-learn',
        revision: reference.revision,
        profileDirectory: reference.directory,
        runId: stopped.runId,
        at: new Date().toISOString(),
      });
      const reviewCandidate = options.json
        ? await readReviewCandidateSources(
            reference,
            stopped,
            evidenceManifestPath,
            dependencies,
          )
        : null;
      const mirrorDirectory = await updateNetMirror(registry, workdir, {
        ...dependencies,
        requireMirror: Boolean(options.json) || dependencies.requireMirror,
        ...(reviewCandidate ? { reviewCandidate } : {}),
      });
      const authoritativePolicy = path.join(
        reference.directory,
        'egress-policy.json',
      );
      const mirrorPolicy = typeof mirrorDirectory === 'string'
        ? path.join(mirrorDirectory, 'candidate-egress-policy.json')
        : null;
      const exportedReviewCandidate = reviewCandidate && mirrorDirectory
        ? reviewCandidateDirectory(
            mirrorDirectory,
            reference.workspaceKey,
            reference.revision,
          )
        : null;
      const exportedTargetContext = exportedReviewCandidate
        ? path.join(
            exportedReviewCandidate,
            'guard-ebpf-target-context.json',
          )
        : null;
      learnedResult = {
        apiVersion: 'notty.dev/v1alpha1',
        kind: 'NoshEgressLearnResult',
        runId: stopped.runId,
        revision: reference.revision,
        imageDigest: reference.imageDigest,
        imageReference: reference.imageReference,
        profileDirectory: reference.directory,
        mirrorDirectory,
        authoritativePolicy,
        mirrorPolicy,
        candidatePolicy: mirrorPolicy,
        reviewCandidateDirectory: exportedReviewCandidate,
        reviewTargetContext: exportedTargetContext,
        evidenceManifest: evidenceManifestPath,
        durationSeconds,
        requestedDurationSeconds: durationSeconds,
        observedDurationMilliseconds:
          observation?.observedDurationMilliseconds ?? null,
        observationComplete:
          durationSeconds === null ? null : observation?.observationComplete === true,
        policyHash: reference.policyHash,
        profileHash: reference.profileHash,
        manifestHash: reference.manifestHash,
      };
      if (options.json) {
        if (
          learnedResult.runId !== learnedResult.revision
          || typeof learnedResult.runId !== 'string'
          || !learnedResult.runId
          || /[\0\r\n]/.test(learnedResult.runId)
          || typeof learnedResult.profileDirectory !== 'string'
          || !path.isAbsolute(learnedResult.profileDirectory)
          || typeof learnedResult.evidenceManifest !== 'string'
          || !path.isAbsolute(learnedResult.evidenceManifest)
          || typeof learnedResult.authoritativePolicy !== 'string'
          || learnedResult.authoritativePolicy
            !== path.join(learnedResult.profileDirectory, 'egress-policy.json')
          || typeof learnedResult.mirrorPolicy !== 'string'
          || learnedResult.mirrorPolicy
            !== path.join(
              learnedResult.mirrorDirectory || '',
              'candidate-egress-policy.json',
            )
          || typeof learnedResult.reviewCandidateDirectory !== 'string'
          || !path.isAbsolute(learnedResult.reviewCandidateDirectory)
          || typeof learnedResult.reviewTargetContext !== 'string'
          || learnedResult.reviewTargetContext !== path.join(
            learnedResult.reviewCandidateDirectory,
            'guard-ebpf-target-context.json',
          )
        ) {
          throw new Error('learned network result has invalid identity or paths');
        }
        for (const [label, value] of [
          ['policyHash', learnedResult.policyHash],
          ['profileHash', learnedResult.profileHash],
          ['manifestHash', learnedResult.manifestHash],
          ['imageDigest', learnedResult.imageDigest],
        ]) {
          if (!/^sha256:[a-f0-9]{64}$/.test(value || '')) {
            throw new Error(`learned network result is missing exact ${label}`);
          }
        }
        if (
          typeof learnedResult.mirrorDirectory !== 'string'
          || !path.isAbsolute(learnedResult.mirrorDirectory)
          || typeof learnedResult.mirrorPolicy !== 'string'
        ) {
          throw new Error('learned network result is missing its user mirror');
        }
      }
      process.stderr.write(
        `nosh net: learned ${reference.revision}; review with nosh net status\n`,
      );
    },
    {
      client: guardClientForOptions(options),
      ...dependencies,
      durationSeconds,
    },
  );
  if (durationSeconds !== null && result.observation?.observationComplete !== true) {
    process.stderr.write(
      `nosh net: timed observation ended before ${durationSeconds} seconds; `
        + `no candidate was created and stopped run ${result.started.runId} `
        + 'was retained for diagnostics\n',
    );
    return result.status || 1;
  }
  if (options.json) {
    if (!learnedResult) {
      throw new Error('network learning completed without a structured result');
    }
    (dependencies.print || printJson)(learnedResult);
  }
  return result.status;
}

async function currentReference(registry, workdir, kind, revision) {
  const state = await registry.readWorkspace(workdir);
  const reference = state?.[kind] || null;
  if (!reference) {
    throw new Error(
      kind === 'approved'
        ? 'this workspace has no approved outbound policy'
        : 'this workspace has no learned outbound policy; run nosh net learn',
    );
  }
  if (revision && reference.revision !== revision) {
    throw new Error(
      `revision ${revision} is not the workspace's current ${kind} revision`,
    );
  }
  return { state, reference };
}

async function commandNetAudit(options, dependencies = {}) {
  const workdir = await canonicalWorkspace(options.workdir || process.cwd());
  const registry = dependencies.registry || netRegistry(options);
  await registry.initialize();
  const { reference } = await currentReference(
    registry,
    workdir,
    'latestCandidate',
    null,
  );
  const verifyCandidate = dependencies.verifyCandidate || verifyEgressCandidateBundle;
  const verification = await verifyCandidate(reference.directory, {
    trustedRoot: netTrustedRoot(options),
    workdir,
  });
  assertVerifiedReference(reference, verification, 'candidate');
  const replay = await resolveReplay(options, reference, workdir, dependencies);
  const request = await runRequest({ ...replay, mode: 'egress-audit' });
  const result = await executeNetShellRun(
    request,
    async ({ stopped }) => {
      const evidenceManifestPath = requireEvidenceManifest(stopped);
      const manifest = JSON.parse(await fs.readFile(evidenceManifestPath, 'utf8'));
      await registry.recordAudit(workdir, {
        revision: reference.revision,
        runId: stopped.runId,
        evidenceManifest: evidenceManifestPath,
        complete:
          manifest.complete === true
          && manifest.egressEvaluation?.complete === true,
        wouldDenyCount: auditWouldDeny(manifest),
        dnsWouldDenyCount: auditDnsWouldDeny(manifest),
        deniedCount: auditDenied(manifest),
        at: new Date().toISOString(),
      });
      await registry.recordLastLaunch(workdir, {
        mode: 'egress-audit',
        revision: reference.revision,
        profileDirectory: reference.directory,
        runId: stopped.runId,
        at: new Date().toISOString(),
      });
      await updateNetMirror(registry, workdir, dependencies);
    },
    { client: guardClientForOptions(options), ...dependencies },
  );
  return result.status;
}

async function commandNetApprove(options, dependencies = {}) {
  const workdir = await canonicalWorkspace(options.workdir || process.cwd());
  const registry = dependencies.registry || netRegistry(options);
  await registry.initialize();
  const { state, reference } = await currentReference(
    registry,
    workdir,
    'latestCandidate',
    options.revision,
  );
  const verifyCandidate = dependencies.verifyCandidate || verifyEgressCandidateBundle;
  const verification = await verifyCandidate(reference.directory, {
    trustedRoot: netTrustedRoot(options),
    workdir,
  });
  assertVerifiedReference(reference, verification, 'candidate');
  if (state.approved?.directory === reference.directory) {
    throw new Error(`outbound policy ${reference.revision} is already approved`);
  }
  const verifyApproval = dependencies.verifyApproval || verifyEgressApprovalBundle;
  let existingApproval = null;
  try {
    existingApproval = await verifyApproval(reference.directory, {
      trustedRoot: netTrustedRoot(options),
      workdir,
    });
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
  if (
    existingApproval?.approval
    && /^sha256:[a-f0-9]{64}$/.test(
      existingApproval.approvalHash
        || existingApproval.approval.contentHash
        || '',
    )
  ) {
    const recoveredReference = {
      ...reference,
      revision: existingApproval.revision,
      approvalHash:
        existingApproval.approvalHash || existingApproval.approval?.contentHash,
      approvedAt: existingApproval.approval?.approvedAt,
      reviewer: existingApproval.approval?.reviewer,
    };
    await registry.setApproved(workdir, recoveredReference);
    await updateNetMirror(registry, workdir, dependencies);
    printJson({ approved: recoveredReference, recovered: true });
    return 0;
  }
  let previous = null;
  if (state.approved) {
    previous = await verifyApproval(state.approved.directory, {
      trustedRoot: netTrustedRoot(options),
      workdir,
    });
    assertVerifiedReference(state.approved, previous, 'approved');
  }
  displayRules(verification, previous);
  const interactive = dependencies.interactive == null
    ? interactiveTerminal(dependencies.streams || process)
    : Boolean(dependencies.interactive);
  let reviewer = options.reviewer;
  if (!reviewer && interactive) {
    reviewer = (dependencies.invokingUser || resolveInvokingUser()).username;
  }
  if (!interactive && (!options.yes || !reviewer)) {
    throw new Error('non-interactive approval requires --yes and --reviewer');
  }
  if (!options.yes) {
    const confirm = dependencies.confirm || defaultConfirm;
    if (!await confirm('Approve this egress-only policy? [y/N] ', dependencies)) {
      throw new Error('network policy approval cancelled');
    }
  }
  const approveCandidate = dependencies.approveCandidate || approveEgressCandidateBundle;
  const approval = await approveCandidate(reference.directory, {
    trustedRoot: netTrustedRoot(options),
    reviewer,
    revision: reference.revision,
    workdir,
  });
  const approvedReference = {
    ...reference,
    approvalHash: approval.contentHash,
    approvedAt: approval.approvedAt,
    reviewer: approval.reviewer,
  };
  if (approval.registryRegistered !== true) {
    await registry.setApproved(workdir, approvedReference);
  }
  await updateNetMirror(registry, workdir, dependencies);
  printJson({ approved: approvedReference });
  return 0;
}

async function commandNetEnforce(options, dependencies = {}) {
  const workdir = await canonicalWorkspace(options.workdir || process.cwd());
  const registry = dependencies.registry || netRegistry(options);
  await registry.initialize();
  const state = await registry.readWorkspace(workdir);
  const reference = state?.latestCandidate;
  if (!reference) {
    throw new Error(
      'this workspace has no learned launch settings; run nosh net learn before signed activation',
    );
  }
  if (options.revision && options.revision !== reference.revision) {
    throw new Error(
      `revision ${options.revision} is not the current learned launch-settings revision`,
    );
  }
  const verifyCandidate = dependencies.verifyCandidate || verifyEgressCandidateBundle;
  const verification = await verifyCandidate(reference.directory, {
    trustedRoot: netTrustedRoot(options),
    workdir,
  });
  assertVerifiedReference(reference, verification, 'candidate');
  const replay = await resolveReplay(options, reference, workdir, dependencies);
  // The candidate is consulted only for its verified launch configuration.
  // A caller-selected or legacy locally approved profile must never cross the
  // Guard boundary for egress-enforce; the root activation store is the sole
  // policy authority.
  delete replay['profile-dir'];
  const request = await runRequest({ ...replay, mode: 'egress-enforce' });
  const interactive = dependencies.interactive == null
    ? interactiveTerminal(dependencies.streams || process)
    : Boolean(dependencies.interactive);
  if (!interactive) {
    const client = dependencies.client || guardClientForOptions(options);
    const started = await client.startRun(request);
    try {
      await registry.recordLastLaunch(workdir, {
        mode: 'egress-enforce',
        revision: reference.revision,
        activationRevision: started.profileRevision || null,
        launchCandidateRevision: reference.revision,
        profileDirectory: null,
        runId: started.runId,
        status: 'running',
        at: new Date().toISOString(),
      });
      await updateNetMirror(registry, workdir, dependencies);
    } catch (recordError) {
      try {
        await client.action(started.runId, 'stop');
      } catch (stopError) {
        throw new AggregateError(
          [recordError, stopError],
          'network launch registration failed and the runner could not be stopped',
        );
      }
      throw recordError;
    }
    (dependencies.print || printJson)(started);
    return 0;
  }
  const result = await executeNetShellRun(
    request,
    async ({ stopped }) => {
      const evidenceManifestPath = requireEvidenceManifest(stopped);
      await registry.recordLastLaunch(workdir, {
        mode: 'egress-enforce',
        revision: reference.revision,
        activationRevision: stopped.profileRevision || null,
        launchCandidateRevision: reference.revision,
        profileDirectory: null,
        runId: stopped.runId,
        evidenceManifest: evidenceManifestPath,
        at: new Date().toISOString(),
      });
      await updateNetMirror(registry, workdir, dependencies);
    },
    { client: guardClientForOptions(options), ...dependencies },
  );
  return result.status;
}

async function commandNetStatus(options, dependencies = {}) {
  const workdir = await canonicalWorkspace(options.workdir || process.cwd());
  const geteuid = dependencies.geteuid || process.geteuid;
  const isRoot = typeof geteuid !== 'function' || geteuid() === 0;
  let receipt;
  let status = 0;
  if (isRoot) {
    const registry = dependencies.registry || netRegistry(options);
    await registry.initialize();
    const state = await registry.readWorkspace(workdir);
    if (!state) {
      throw new Error('this workspace has no learned outbound policy');
    }
    const integrity = await authoritativeIntegrity(
      state,
      workdir,
      options,
      dependencies,
    );
    receipt = { ...receiptFor(workdir, state), integrity };
    status = integrity.ok ? 0 : 1;
    if (options.repair) {
      if (!integrity.ok) {
        throw new Error(
          `cannot repair a mirror from failed authoritative state: ${integrity.failures.join('; ')}`,
        );
      }
      await updateNetMirror(registry, workdir, {
        ...dependencies,
        requireMirror: true,
      });
    }
  } else {
    if (options.repair) {
      throw new Error('nosh net status --repair requires root');
    }
    const readMirror = dependencies.readMirror || readCurrentUserMirror;
    ({ receipt } = await readMirror(workdir, dependencies));
  }
  if (options.json) {
    printJson(receipt);
  } else {
    process.stdout.write(`${humanNetStatus(receipt)}\n`);
  }
  return status;
}

export async function executeNetCommand(subcommand, options, dependencies = {}) {
  if (subcommand !== 'learn' && options.duration != null) {
    throw new TypeError('--duration is supported only by nosh net learn');
  }
  const durationSeconds = subcommand === 'learn'
    ? netLearnDuration(options)
    : null;
  if (subcommand === 'learn' && options.json && durationSeconds === null) {
    throw new TypeError('nosh net learn --json requires --duration');
  }
  if (options['dry-run']) {
    (dependencies.print || printJson)({
      dryRun: true,
      command: `net ${subcommand}`,
      workdir: path.resolve(options.workdir || process.cwd()),
      scope: 'egress-only',
      ...(options.resolver == null
        ? {}
        : {
            resolvers: normalizeEbpfResolvers(
              Array.isArray(options.resolver)
                ? options.resolver
                : [options.resolver],
            ),
          }),
      ...(durationSeconds === null ? {} : { durationSeconds }),
    });
    return 0;
  }
  if (subcommand !== 'status') {
    assertRootManagement(dependencies.geteuid || process.geteuid);
  }
  if (['learn', 'audit'].includes(subcommand)) {
    const interactive = dependencies.interactive == null
      ? interactiveTerminal(dependencies.streams || process)
      : Boolean(dependencies.interactive);
    if (!interactive && !(subcommand === 'learn' && durationSeconds !== null)) {
      throw new Error(`nosh net ${subcommand} requires an interactive terminal`);
    }
  }
  if (subcommand === 'learn') {
    return commandNetLearn(options, dependencies, durationSeconds);
  }
  if (subcommand === 'audit') {
    return commandNetAudit(options, dependencies);
  }
  if (subcommand === 'approve') {
    return commandNetApprove(options, dependencies);
  }
  if (subcommand === 'enforce') {
    return commandNetEnforce(options, dependencies);
  }
  if (subcommand === 'status') {
    return commandNetStatus(options, dependencies);
  }
  throw new TypeError('net command must be learn, audit, approve, enforce, or status');
}

async function commandNet(argv) {
  const [subcommand, ...rest] = argv;
  const allowed = NET_FLAGS[subcommand];
  if (!allowed) {
    if (!subcommand || subcommand === 'help' || subcommand === '--help') {
      process.stdout.write(NET_HELP);
      return 0;
    }
    throw new TypeError('net command must be learn, audit, approve, enforce, or status');
  }
  const { options, positionals } = parseFlags(rest);
  assertKnownOptions(options, allowed, `net ${subcommand}`);
  if (positionals.length) {
    throw new TypeError(`unexpected net arguments: ${positionals.join(' ')}`);
  }
  if (options.help) {
    process.stdout.write(NET_HELP);
    return 0;
  }
  return executeNetCommand(subcommand, options);
}

function splitBuildArguments(argv) {
  const separator = argv.indexOf('--');
  const owned = separator === -1 ? argv : argv.slice(0, separator);
  const passthrough = separator === -1 ? [] : argv.slice(separator + 1);
  const parsed = parseFlags(owned);
  if (parsed.positionals.length > 1) {
    throw new TypeError('nosh build accepts exactly one build context');
  }
  return {
    options: parsed.options,
    context: parsed.positionals[0] || '.',
    passthrough,
  };
}

function buildProfileInput(mode, context, options, passthrough) {
  return {
    mode,
    context,
    file: options.file,
    variant: options.variant,
    tag: options.tag || [],
    target: options.target,
    platform: options.platform,
    buildArg: options['build-arg'] || [],
    cacheMode: options['cache-mode'],
    depth: options.depth,
    push: Boolean(options.push),
    output: options.output || [],
    noLoad: Boolean(options['no-load']),
    httpCapture: options['http-capture'],
    dryRun: Boolean(options['dry-run']),
    passthrough,
  };
}

async function executeBuildStatus(mode, context, options, dependencies = {}) {
  const resolved = await fs.realpath(path.resolve(context));
  if (options['dry-run']) {
    printJson({
      dryRun: true,
      command: mode === 'build-profile' ? 'build status' : 'build net status',
      context: resolved,
      runId: options.run || null,
      independentFromRuntimeProfiles: true,
    });
    return 0;
  }
  const store = dependencies.store || new BuildProfileStore();
  if (options.run) {
    const selected = await store.read(resolved, options.run, { mode });
    if (options.json) {
      printJson(selected);
    } else {
      process.stdout.write(renderBuildProfileReport(
        selected.manifest,
        selected.candidate,
      ));
      process.stdout.write(`Private bundle: ${selected.directory}\n`);
      process.stdout.write(`Portable bundle: ${selected.portableDirectory}\n`);
      if (mode === 'build-net-learn') {
        process.stdout.write(
          `Editable policy draft: ${path.join(selected.directory, 'build-network-policy-draft.json')}\n`,
        );
      }
    }
    return selected.manifest.complete ? 0 : 1;
  }
  const runs = await store.list(resolved, { mode });
  if (options.json) {
    printJson({ context: resolved, mode, runs });
  } else if (!runs.length) {
    process.stdout.write('No build profiles recorded for this context.\n');
  } else {
    for (const run of runs) {
      process.stdout.write(
        `${run.runId}\t${run.complete ? 'complete' : 'incomplete'}\t${run.generatedAt}\n`,
      );
    }
  }
  return runs.some((run) => !run.complete) ? 1 : 0;
}

export async function executeBuildCommand(
  subcommand,
  options,
  context,
  passthrough = [],
  dependencies = {},
) {
  const printResult = (result) => {
    if (result.dryRun) {
      printJson(result);
      return;
    }
    if (options.json) {
      printJson(createPortableBuildReport(result.manifest, result.candidate));
      return;
    }
    if (options['private-json']) {
      printJson(result);
      return;
    }
    process.stdout.write(renderBuildProfileReport(result.manifest, result.candidate));
    process.stdout.write(`Private bundle: ${result.bundleDir}\n`);
    process.stdout.write(`Portable bundle: ${result.portableBundleDir}\n`);
    if (result.mode === 'build-net-learn') {
      process.stdout.write(
        `Editable policy draft: ${path.join(result.bundleDir, 'build-network-policy-draft.json')}\n`,
      );
    }
  };
  if (subcommand === 'profile') {
    const result = await (dependencies.executeProfile || executeBuildProfile)(
      buildProfileInput('build-profile', context, options, passthrough),
      dependencies,
    );
    printResult(result);
    return result.status || 0;
  }
  if (subcommand === 'net-learn') {
    const result = await (dependencies.executeProfile || executeBuildProfile)(
      buildProfileInput('build-net-learn', context, options, passthrough),
      dependencies,
    );
    printResult(result);
    return result.status || 0;
  }
  if (subcommand === 'status') {
    return executeBuildStatus('build-profile', context, options, dependencies);
  }
  if (subcommand === 'net-status') {
    return executeBuildStatus('build-net-learn', context, options, dependencies);
  }
  throw new TypeError('build command must be profile, status, net learn, or net status');
}

async function commandBuild(argv) {
  let subcommand = argv[0];
  let rest = argv.slice(1);
  if (subcommand === 'net') {
    const netCommand = rest[0];
    rest = rest.slice(1);
    if (netCommand === 'learn') {
      subcommand = 'net-learn';
    } else if (netCommand === 'status') {
      subcommand = 'net-status';
    } else if (!netCommand || ['help', '--help'].includes(netCommand)) {
      process.stdout.write(BUILD_HELP);
      return 0;
    } else {
      throw new TypeError('build net command must be learn or status');
    }
  }
  if (!subcommand || ['help', '--help', '-h'].includes(subcommand)) {
    process.stdout.write(BUILD_HELP);
    return 0;
  }
  const { options, context, passthrough } = splitBuildArguments(rest);
  const allowed = {
    profile: BUILD_PROFILE_FLAGS,
    status: BUILD_STATUS_FLAGS,
    'net-learn': BUILD_NET_LEARN_FLAGS,
    'net-status': BUILD_STATUS_FLAGS,
  }[subcommand];
  if (!allowed) {
    throw new TypeError('build command must be profile, status, net learn, or net status');
  }
  assertKnownOptions(options, allowed, `build ${subcommand.replace('-', ' ')}`);
  if (options.help) {
    process.stdout.write(BUILD_HELP);
    return 0;
  }
  if (['status', 'net-status'].includes(subcommand) && passthrough.length) {
    throw new TypeError('build status does not accept Buildx passthrough arguments');
  }
  return executeBuildCommand(subcommand, options, context, passthrough);
}

async function readBoundedStdin(maximumBytes = 1024 * 1024) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > maximumBytes) {
      throw new Error('build session request exceeds the input limit');
    }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw.trim()) {
    throw new TypeError('build session request body is required');
  }
  return JSON.parse(raw);
}

async function assertTrustedBuildExportRoot() {
  const exportRoot = '/tmp';
  const resolved = await fs.realpath(exportRoot);
  const stat = await fs.lstat(exportRoot);
  if (
    resolved !== exportRoot
    || !stat.isDirectory()
    || stat.isSymbolicLink()
    || stat.uid !== 0
    || (stat.mode & 0o1000) === 0
    || (stat.mode & 0o002) === 0
  ) {
    throw new Error('temporary build evidence root is not root-owned and sticky');
  }
  return exportRoot;
}

async function stageBuildEvidenceForUser(run, invokingUser) {
  if (
    run?.client?.uid !== invokingUser.uid
    || run?.client?.gid !== invokingUser.gid
  ) {
    throw new Error('build session owner does not match the invoking user');
  }
  const source = await fs.realpath(path.resolve(run.evidenceDir || ''));
  const expectedSource = path.join(
    PRIVILEGED_BUILD_STATE_DIR,
    'build-evidence',
    run.runId,
  );
  const sourceStat = await fs.lstat(source);
  if (
    source !== expectedSource
    || !sourceStat.isDirectory()
    || sourceStat.isSymbolicLink()
    || sourceStat.uid !== 0
    || path.basename(source) !== run.runId
  ) {
    throw new Error('daemon returned an invalid build evidence directory');
  }
  const exportRoot = await assertTrustedBuildExportRoot();
  const temporary = await fs.mkdtemp(path.join(exportRoot, 'nosh-build-evidence-'));
  await fs.chmod(temporary, 0o700);
  try {
    for (const entry of await fs.readdir(source, { withFileTypes: true })) {
      if (!entry.isFile()) {
        throw new Error(`unsupported entry in daemon build evidence: ${entry.name}`);
      }
      const sourceFile = path.join(source, entry.name);
      const sourceFileStat = await fs.lstat(sourceFile);
      if (
        sourceFileStat.isSymbolicLink()
        || !sourceFileStat.isFile()
        || sourceFileStat.nlink !== 1
        || sourceFileStat.uid !== 0
        || sourceFileStat.size > MAX_BUILD_EVIDENCE_EXPORT_BYTES
      ) {
        throw new Error(`daemon build evidence file is not trusted: ${entry.name}`);
      }
      const destinationFile = path.join(temporary, entry.name);
      await fs.copyFile(sourceFile, destinationFile, fsConstants.COPYFILE_EXCL);
      await fs.chmod(destinationFile, 0o600);
      await fs.chown(destinationFile, invokingUser.uid, invokingUser.gid);
    }
    await fs.chmod(temporary, 0o700);
    await fs.chown(temporary, invokingUser.uid, invokingUser.gid);
  } catch (error) {
    await fs.rm(temporary, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
  return path.join(temporary, 'build-evidence-manifest.json');
}

async function assertOwnedBuildSession(client, runId, invokingUser) {
  const listed = await client.listBuildRuns();
  const run = listed?.runs?.find((entry) => entry.runId === runId);
  if (
    !run
    || run.client?.uid !== invokingUser.uid
    || run.client?.gid !== invokingUser.gid
  ) {
    throw new Error('build session owner does not match the invoking user');
  }
}

async function assertTrustedBuildManagementSocket() {
  const socket = await fs.lstat(PRIVILEGED_BUILD_SOCKET);
  const parent = await fs.lstat(path.dirname(PRIVILEGED_BUILD_SOCKET));
  if (
    !socket.isSocket()
    || socket.uid !== 0
    || (socket.mode & 0o7777) !== 0o600
    || !parent.isDirectory()
    || parent.isSymbolicLink()
    || parent.uid !== 0
    || (parent.mode & 0o022) !== 0
  ) {
    throw new Error('build-session management socket is not root-owned and private');
  }
}

async function commandBuildSession(argv) {
  const [action, ...rest] = argv;
  if (!['begin', 'finish', 'abort', 'exported'].includes(action)) {
    throw new TypeError('build-session action must be begin, finish, abort, or exported');
  }
  const { options, positionals } = parseFlags(rest);
  assertKnownOptions(options, BUILD_SESSION_FLAGS, 'build-session');
  if (positionals.length) {
    throw new TypeError('build-session does not accept positional arguments');
  }
  assertRootManagement();
  await assertTrustedBuildManagementSocket();
  const input = await readBoundedStdin();
  const invokingUser = resolveInvokingUser();
  const client = new GuardClient({ socketPath: PRIVILEGED_BUILD_SOCKET });
  let result;
  if (action === 'begin') {
    if (
      Number(input.clientUid) !== invokingUser.uid
      || Number(input.clientGid) !== invokingUser.gid
    ) {
      throw new Error('build session request does not match the invoking user');
    }
    result = await client.startBuildRun(input);
  } else {
    if (typeof input.runId !== 'string' || !input.runId) {
      throw new TypeError('build session finalization requires runId');
    }
    await assertOwnedBuildSession(client, input.runId, invokingUser);
    if (action === 'exported') {
      if (input.exportEvidence === true) {
        throw new TypeError('build-session exported does not export root evidence');
      }
      result = await client.acknowledgeBuildExport(input.runId, {
        portableBundleHash: input.portableBundleHash,
      });
    } else {
      result = action === 'finish'
        ? await client.finishBuildRun(input.runId, input.result || {})
        : await client.abortBuildRun(input.runId, { reason: input.reason });
    }
    if (input.exportEvidence === true) {
      result.userEvidenceManifest = await stageBuildEvidenceForUser(
        result,
        invokingUser,
      );
    }
  }
  printJson(result);
  return 0;
}

async function commandProfileCompile(options) {
  const evidencePaths = Array.isArray(options.evidence)
    ? options.evidence
    : typeof options.evidence === 'string'
      ? [options.evidence]
      : [];
  if (!evidencePaths.length) {
    throw new TypeError('--evidence is required');
  }
  const outputDir = path.resolve(requireSingleOption(options, 'output'));
  const compiler = await import('../lib/guard/index.js');
  const loaded = await compiler.loadEvidenceInputs(evidencePaths);
  const reviewedTetragon = Boolean(options['reviewed-tetragon-enforcement']);
  if (Boolean(options['tetragon-rules']) !== reviewedTetragon) {
    throw new TypeError(
      '--tetragon-rules and --reviewed-tetragon-enforcement must be supplied together',
    );
  }
  let tetragon = undefined;
  if (reviewedTetragon) {
    const rulesPath = await fs.realpath(
      path.resolve(options['tetragon-rules']),
    );
    const rules = JSON.parse(await fs.readFile(rulesPath, 'utf8'));
    tetragon = {
      reviewedEnforcement: true,
      enforcementRules: rules.spec || rules,
    };
  }
  const result = compiler.compileGuardProfile(loaded.records, {
    name: options.name || path.basename(outputDir),
    imageDigest: options['image-digest'],
    role: options.role,
    architecture: options.architecture || process.arch,
    kernel: options.kernel,
    runProvenance: loaded.runProvenance,
    ingestion: loaded.ingestion,
    tetragon,
  });
  if (typeof compiler.writeCompiledProfile !== 'function') {
    throw new Error('profile compiler does not export writeCompiledProfile');
  }
  const written = await compiler.writeCompiledProfile(outputDir, result);
  printJson({
    outputDir,
    written,
    status: result.status || 'candidate',
    promotion: result.profile.spec.promotion,
  });
  return 0;
}

async function commandProfile(argv) {
  const [subcommand, ...rest] = argv;
  const { options, positionals } = parseFlags(rest);
  if (positionals.length) {
    throw new TypeError(`unexpected profile arguments: ${positionals.join(' ')}`);
  }
  const allowed = {
    approve: new Set([
      'candidate',
      'promotion-override-reason',
      'replace',
      'reviewer',
      'revision',
    ]),
    compile: new Set([
      'architecture',
      'evidence',
      'image-digest',
      'kernel',
      'name',
      'output',
      'reviewed-tetragon-enforcement',
      'role',
      'tetragon-rules',
    ]),
    verify: new Set(['candidate']),
  }[subcommand];
  if (allowed) {
    assertKnownOptions(options, allowed, `profile ${subcommand}`);
  }
  if (subcommand === 'compile') {
    return commandProfileCompile(options);
  }
  if (subcommand === 'approve') {
    const candidate = path.resolve(requireOption(options, 'candidate'));
    if (typeof process.geteuid === 'function' && process.geteuid() !== 0) {
      throw new Error('profile approval must run as root');
    }
    await assertTrustedCandidateDirectory(candidate, {
      trustedRoot:
        process.env.NOSH_GUARD_TRUSTED_PROFILE_ROOT ||
        DEFAULT_GUARD_PROFILE_DIR,
    });
    printJson(
      await approveArtifactSet(candidate, {
        revision: options.revision,
        reviewer: options.reviewer,
        replace: Boolean(options.replace),
        promotionOverrideReason: options['promotion-override-reason'],
      }),
    );
    return 0;
  }
  if (subcommand === 'verify') {
    const result = await verifyArtifactSet(
      path.resolve(requireOption(options, 'candidate')),
    );
    printJson(result);
    return result.ok ? 0 : 1;
  }
  throw new TypeError('profile command must be compile, approve, or verify');
}

function publicEbpfActivationState(state, backendHealth) {
  const current = state.current
    ? {
        activatedAt: state.current.activatedAt,
        previousActiveGrantSetDigest:
          state.current.previousActiveGrantSetDigest,
        leafBundleDigest: state.current.leafBundleDigest,
        approvalEnvelopeDigest: state.current.approvalEnvelopeDigest,
        grantEnvelopeDigest: state.current.grantEnvelopeDigest,
        nonce: state.current.nonce,
        imageDigest: state.current.imageDigest,
        workspaceKey: state.current.workspaceKey,
        workspaceIdentity: structuredClone(state.current.workspaceIdentity),
        backendAbi: state.current.backendAbi,
        objectDigest: state.current.objectDigest,
      }
    : null;
  return {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshGuardEbpfActivationStatus',
    schemaVersion: 1,
    status: backendHealth.status,
    backend: {
      backendAbi: EBPF_EGRESS_BACKEND_ABI,
      objectDigest: backendHealth.objectDigest,
      mapAbi: backendHealth.mapAbi,
      programAbi: backendHealth.programAbi,
    },
    activeGrantSetDigest: state.activeGrantSetDigest,
    stateDigest: state.stateDigest,
    consumedGrantCount: state.usedGrants.length,
    activation: current,
  };
}

function printEbpfStatus(status, dependencies, json = false) {
  if (json) {
    (dependencies.print || printJson)(status);
    return;
  }
  const write = dependencies.write || ((value) => process.stdout.write(value));
  write(`Guard eBPF backend: ${status.status}\n`);
  write(`Backend ABI: ${status.backend.backendAbi}\n`);
  write(`Object digest: ${status.backend.objectDigest}\n`);
  write(`Active grant set: ${status.activeGrantSetDigest}\n`);
  write(
    status.activation
      ? `Activated: ${status.activation.activatedAt}\n`
      : 'Activated: no signed policy\n',
  );
}

export async function commandEbpf(argv, dependencies = {}) {
  const [subcommand, ...rest] = argv;
  if (!subcommand || ['help', '--help', '-h'].includes(subcommand)) {
    (dependencies.write || ((value) => process.stdout.write(value)))(EBPF_HELP);
    return 0;
  }
  const { options, positionals } = parseFlags(rest);
  if (positionals.length) {
    throw new TypeError(`unexpected ebpf arguments: ${positionals.join(' ')}`);
  }
  const allowed = {
    activate: new Set(['bundle', 'help', 'target-context']),
    status: new Set(['help', 'json']),
  }[subcommand];
  if (!allowed) {
    throw new TypeError('ebpf command must be status or activate');
  }
  assertKnownOptions(options, allowed, `ebpf ${subcommand}`);
  if (options.help) {
    (dependencies.write || ((value) => process.stdout.write(value)))(EBPF_HELP);
    return 0;
  }
  assertRootManagement(dependencies.geteuid || process.geteuid);

  const store = dependencies.store || new EbpfActivationStore();
  const readHealth = dependencies.readHealth || readInstalledEbpfBackendHealth;
  if (subcommand === 'status') {
    const state = await store.initialize();
    const backendHealth = await readHealth();
    printEbpfStatus(
      publicEbpfActivationState(state, backendHealth),
      dependencies,
      Boolean(options.json),
    );
    return 0;
  }

  const bundle = path.resolve(requireOption(options, 'bundle'));
  const targetContextPath = path.resolve(
    requireOption(options, 'target-context'),
  );
  const invokingUser = dependencies.invokingUser
    || (dependencies.resolveInvokingUser || resolveInvokingUser)();
  if (!Number.isSafeInteger(invokingUser?.uid) || invokingUser.uid < 0) {
    throw new Error('cannot resolve the invoking user for eBPF activation');
  }
  const trustedContext = await (
    dependencies.readTrustedJson || readTrustedJson
  )(targetContextPath, {
    expectedUid: invokingUser.uid,
    maximumBytes: 4 * 1024 * 1024,
  });
  const validatedContext = (
    dependencies.validateTargetContext || validateEbpfTargetContextDocument
  )(trustedContext.document);
  const backendHealth = await readHealth();
  if (backendHealth.objectDigest !== validatedContext.expected.objectDigest) {
    const error = new Error(
      'guard-ebpf target context object digest does not match the installed loader',
    );
    error.code = 'GUARD_EBPF_OBJECT_DIGEST_MISMATCH';
    throw error;
  }
  const imported = await store.importActivation(bundle, {
    sourceUid: invokingUser.uid,
    expected: validatedContext.expected,
    now: dependencies.now,
  });
  const status = publicEbpfActivationState(imported.state, backendHealth);
  (dependencies.print || printJson)({
    ...status,
    kind: 'NoshGuardEbpfActivationReceipt',
    targetContextHash: validatedContext.document.contentHash,
  });
  return 0;
}

export async function main(argv = process.argv.slice(2)) {
  const [command, ...rest] = argv;
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    process.stdout.write(HELP);
    return 0;
  }
  if (command === 'daemon') {
    return commandDaemon(rest);
  }
  if (command === 'doctor') {
    return commandDoctor(rest);
  }
  if (command === 'run') {
    return commandRun(rest);
  }
  if (command === 'runs') {
    return commandRuns(rest);
  }
  if (command === 'profile') {
    return commandProfile(rest);
  }
  if (command === 'net') {
    return commandNet(rest);
  }
  if (command === 'build') {
    return commandBuild(rest);
  }
  if (command === 'review') {
    return commandReview(rest);
  }
  if (command === 'policy') {
    return commandPolicy(rest);
  }
  if (command === 'gateway') {
    return commandGateway(rest);
  }
  if (command === 'deployment') {
    return commandDeployment(rest);
  }
  if (command === 'ebpf') {
    return commandEbpf(rest);
  }
  if (command === 'build-session') {
    return commandBuildSession(rest);
  }
  if (command === 'principal') {
    return commandPrincipal(rest);
  }
  if (command === 'grant') {
    return commandGrant(rest);
  }
  throw new TypeError(`unknown command: ${command}`);
}

export function emitPreservedBuildBundleNotice(
  error,
  argv = process.argv.slice(2),
  write = (value) => process.stdout.write(value),
) {
  if (!error || typeof error.bundleDir !== 'string' || !path.isAbsolute(error.bundleDir)) {
    return false;
  }
  const delimiter = argv.indexOf('--');
  const ownedArguments = delimiter === -1 ? argv : argv.slice(0, delimiter);
  if (
    ownedArguments[0] !== 'build'
    || ownedArguments[1] !== 'net'
    || ownedArguments[2] !== 'learn'
    || ownedArguments.some((argument) => (
      argument === '--json'
      || argument === '--private-json'
      || argument === '--dry-run'
    ))
  ) {
    return false;
  }
  write(`Private bundle: ${error.bundleDir}\n`);
  return true;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main()
    .then((status) => {
      process.exitCode = status;
    })
    .catch((error) => {
      emitPreservedBuildBundleNotice(error);
      process.stderr.write(`nosh-guard: ${error.message}\n`);
      if (process.env.NOSH_GUARD_DEBUG === '1') {
        process.stderr.write(`${error.stack}\n`);
      }
      process.exitCode = 1;
    });
}
