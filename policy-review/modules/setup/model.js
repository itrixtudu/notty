import schema from './profile-schema.json' with { type: 'json' };

export { schema };
export function defaults(definition = schema) {
  if (definition.type === 'object') return Object.fromEntries(Object.entries(definition.properties).map(([key, value]) => [key, defaults(value)]));
  return structuredClone(definition.default);
}

export function validate(value, definition = schema, label = 'profile') {
  const fail = message => { throw new Error(`${label}: ${message}`); };
  if (definition.type === 'object') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail('expected an object');
    if (Object.keys(value).some(key => !Object.hasOwn(definition.properties, key))) fail('unknown field');
    for (const key of definition.required) {
      if (!Object.hasOwn(value, key)) fail(`missing ${key}`);
      validate(value[key], definition.properties[key], `${label}.${key}`);
    }
  } else if (definition.type === 'array') {
    if (!Array.isArray(value) || value.length > definition.maxItems) fail('invalid list');
    value.forEach((item, index) => validate(item, definition.items, `${label}[${index}]`));
  } else if (definition.type === 'string') {
    if (typeof value !== 'string' || value.length > definition.maxLength || value.length < (definition.minLength || 0)
      || /[\x00-\x1f\x7f]/.test(value) || (definition.pattern && !new RegExp(definition.pattern).test(value))) fail('invalid text');
  } else if (definition.type === 'boolean') {
    if (typeof value !== 'boolean') fail('expected true or false');
  } else if (definition.type === 'integer') {
    if (!Number.isSafeInteger(value) || value < definition.minimum || value > definition.maximum) fail('invalid number');
  }
  if (definition.enum && !definition.enum.includes(value)) fail('unsupported selection');
  return value;
}

export function validateProfile(value) {
  validate(value);
  if (value.host.guardPrefix.split('/').some(part => part === '.' || part === '..')) throw new Error('Use a normalized Guard prefix.');
  const { build, runtime } = value.settings;
  if (runtime.run.agents !== 'none' || runtime.run.baselines.length || runtime.run.presets.length) throw new Error('Run workloads cannot select agent homes, baselines or development presets.');
  for (const arg of build.buildArgs) {
    if (/secret|token|password|credential|private.?key/i.test(arg.split('=')[0])) throw new Error('Use external secret delivery; build arguments must be non-secret.');
  }
  if (build.tags.some(tag => !tag)) throw new Error('Image tags cannot be empty.');
  if (build.outputMode === 'push' && !build.tags.length) throw new Error('Push requires an image tag.');
  return value;
}

export const quote = value => `'${String(value).replaceAll("'", "'\\''")}'`;
export const shell = args => args.map(quote).join(' ');
const join = (root, relative) => `${root}/${relative}`;

export function buildArguments(build, workspace) {
  const args = ['build', ...(build.mode === 'network' ? ['net', 'learn', '--http-capture', build.httpCapture] : ['profile', '--cache-mode', build.cacheMode, '--depth', build.depth]),
    '--file', join(workspace, build.dockerfile)];
  for (const key of ['target', 'platform']) if (build[key]) args.push(`--${key}`, build[key]);
  for (const tag of build.tags) args.push('--tag', tag);
  for (const arg of build.buildArgs) args.push('--build-arg', arg);
  if (build.outputMode === 'push') args.push('--push');
  if (build.outputMode === 'cache') args.push('--no-load');
  if (build.outputMode === 'local') args.push('--output', `type=local,dest=${join(workspace, build.outputDirectory)}`);
  args.push(join(workspace, build.context));
  return args;
}

export function commands(profile, binding, revision = 1) {
  validateProfile(profile);
  const { settings, host } = profile;
  const { workspace, launcher, scripts } = binding;
  const base = [launcher];
  const init = step => [...base, 'init', '--workdir', workspace.path, '--guard-prefix', host.guardPrefix, '--step', step];
  const cards = [];
  const add = (id, title, args, note = '', blocked = '') => cards.push({ id, title, command: blocked ? '' : shell(args), note, blocked });
  add('refresh', 'Refresh saved status', [...base, 'config', 'refresh', '--workdir', workspace.path], 'Read-only host discovery. Does not verify active policy.');
  add('privileged-refresh', 'Check active policy and refresh', [...base, 'config', 'refresh', '--privileged', '--workdir', workspace.path], 'Uses sudo for installed Guard status; records when the check was made.');
  add('install', 'Build, verify and install Guard', init('install'), 'The terminal wizard builds and verifies the host bundle before asking to run its installer with sudo.');
  const setup = ['bash', `${scripts}/setup-nosh.sh`, '--guard-prefix', host.guardPrefix, '--require-guard'];
  if (host.toolingImage) setup.push('--policy-tooling-image', host.toolingImage);
  if (host.reviewImage) setup.push('--policy-review-ui-image', host.reviewImage);
  add('setup', 'Configure launchers and review images', setup, '', Boolean(host.toolingImage) !== Boolean(host.reviewImage) ? 'Set both exact tooling and review image IDs, or leave both blank to retain host configuration.' : '');
  add('advanced', 'Open advanced terminal setup', [...base, 'init', '--advanced', '--workdir', workspace.path, '--guard-prefix', host.guardPrefix], 'Includes optional launcher setup and individual wizard steps.');
  add('preflight', 'Inspect host networking', init('preflight'), 'Read-only inspection; incomplete permissions may require sudo.');
  const network = ['python3', '-I', '-S', `${scripts}/nosh-review-network.py`, 'configure', '--check-host', '--pool', host.reviewPool];
  for (const cidr of host.excludedCidrs) network.push('--exclude', cidr);
  add('network', 'Reserve review network pool', host.reviewPool ? network : init('network'), 'Shared host configuration, not repository-specific authority. Existing allocations are checked.');
  add('build', 'Capture build evidence', [...base, ...buildArguments(settings.build, workspace.path)], 'Runs as your normal user; collector lifecycle uses sudo. Network learning always uses a clean build.');
  add('signing', 'Prepare signing', init('signing'), 'Key generation runs offline; installing public trust requires sudo.');
  for (const workload of ['dev', 'run']) {
    const runtime = settings.runtime[workload];
    const selectors = ['--workdir', workspace.path, '--workload', workload];
    const options = ['--image', runtime.image, runtime.startApp ? '--start-app' : '--no-start-app', '--no-collab'];
    if (workload === 'dev') {
      options.push('--agents', runtime.agents);
      if (host.codexHome) options.push('--codex-home', host.codexHome);
      if (runtime.presets.length) options.push('--profile', runtime.presets.join(','));
    }
    const runtimeCommand = operation => [...base, 'config', 'runtime', '--operation', operation, ...selectors, '--revision', String(revision)];
    const learn = runtimeCommand('learn');
    add(`learn-${workload}`, `Learn ${workload} runtime`, learn, 'Uses sudo. Exercise representative traffic, then exit. Requires a Guard-compatible local image.', runtime.image ? '' : 'Select an image first.');
    add(`inventory-${workload}`, `Prepare ${workload} inventories`, [...base, 'net', 'inventory', '--workdir', workspace.path, '--image', runtime.image], 'Uses the existing offline inventory workflow.', runtime.image ? '' : 'Select an image first.');
    add(`prepare-${workload}`, `Check ${workload} review prerequisites`, [...base, 'net', 'prepare', ...selectors]);
    add(`review-${workload}`, `Open ${workload} network review`, [...base, 'net', 'review', ...selectors], 'Opens the existing managed reviewer. Save decisions there.');
    const review = host.reviews[workload];
    add(`apply-${workload}`, `Apply ${workload} network review`, [...base, 'net', 'apply', ...selectors, '--review', review.directory, '--decision-digest', review.decisionDigest], 'Verifies and signs the exact review; activation uses sudo.', review.directory && review.decisionDigest ? '' : 'Enter the saved review directory and decision digest from Network Review.');
    for (const action of ['start', 'recreate']) {
      const enforced = runtime.launchMode === 'enforce';
      const args = enforced
        ? runtimeCommand('enforce')
        : [...base, action, ...selectors, ...options, '--security-mode', 'legacy'];
      if (workload === 'dev' && !enforced) args.push('--tool-mode', settings.tools.mode);
      add(`${action}-${workload}`, `${action === 'start' ? (enforced ? 'Start enforced' : 'Start / attach') : 'Recreate'} ${workload}`, args,
        `${enforced ? 'Uses sudo. Requires an activated network policy; Guard validates the learned launch settings.' : 'Explicitly launches without Guard network enforcement.'} ${workload === 'dev' ? 'Requires an applied tool environment policy; implementation must be approved.' : ''}`,
        enforced && action === 'recreate' ? 'Exit the existing guarded session so Guard completes cleanup, then use Start enforced. The network workflow has no recreate command.' : '');
    }
  }
  add('audit-tools', 'Audit historical tool requests', ['python3', `${scripts}/audit-codex-tools.py`], 'Historical requests are evidence only and are never executed.');
  for (const action of ['review', 'check', 'apply', 'status']) {
    const args = [...base, 'tools', action, '--workdir', workspace.path, '--guard-prefix', host.guardPrefix];
    if (action !== 'status') args.push('--review', host.toolReport);
    if (action === 'apply') args.push('--policy-digest', host.toolPolicyDigest);
    add(`tools-${action}`, `${action} tool environment`, args, action === 'apply' ? 'Uses sudo; applies to future containers. Recreate existing containers explicitly.' : 'Tool choices are informational; the environment policy controls filesystem writes.',
      action !== 'status' && !host.toolReport ? 'Enter an audit report directory.' : action === 'apply' && !host.toolPolicyDigest ? 'Enter the exact environment-policy digest from Tools Check.' : '');
  }
  add('export', 'Export portable settings', [...base, 'config', 'export', '--workdir', workspace.path], 'Prints portable JSON to stdout; save it to a file for CI. Review non-secret build arguments before sharing.');
  return cards;
}
