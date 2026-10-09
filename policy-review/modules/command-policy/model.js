import catalogue from './catalogue.json' with { type: 'json' };

export const COMMANDS = Object.freeze(Object.keys(catalogue).sort());
export const ENFORCEMENT = Object.freeze({ ready: false,
  reason: 'Strict runner activation is unavailable: MCP broker and startup integration are unfinished, and live Docker/AppArmor bypass tests have not passed.' });
const text = (value, max = 1024) => typeof value === 'string' && value.length <= max && !value.includes('\0');
const fail = reason => ({ supported: false, reason, switches: [], operands: [], values: {} });

// Anchored token globs, never regular expressions or shell evaluation.
export function globMatch(pattern, value) {
  if (!text(pattern) || !text(value, 64 * 1024 * 1024)) return false;
  let p = 0, v = 0, star = -1, retry = 0;
  while (v < value.length) {
    if (pattern[p] === '?' || pattern[p] === value[v]) { p++; v++; }
    else if (pattern[p] === '*') { star = p++; retry = v; }
    else if (star >= 0) { p = star + 1; v = ++retry; }
    else return false;
  }
  while (pattern[p] === '*') p++;
  return p === pattern.length;
}

const aliases = {
  sed: { '--quiet': '-n', '--silent': '-n', '--expression': '-e', '--file': '-f',
    '--in-place': '-i', '--regexp-extended': '-E', '-r': '-E', '--separate': '-s',
    '--unbuffered': '-u', '--null-data': '-z', '--zero-terminated': '-z', '--line-length': '-l' },
};
export const switchName = (command, name) => aliases[command]?.[name] || name;

export function parseInvocation(argv) {
  if (!Array.isArray(argv) || !argv.length || argv.some(arg => !text(arg, 64 * 1024 * 1024))) return fail('Invalid argument vector');
  const command = argv[0].split('/').at(-1);
  if (![command, '/usr/bin/' + command, '/bin/' + command].includes(argv[0])) return { ...fail('Untrusted executable path'), command, argv };
  const spec = catalogue[command];
  if (!spec) return { ...fail(command === 'xargs' ? 'xargs is blocked: child invocations are not mediated' : 'No supported command parser'), command, argv };
  const switches = [], operands = [], values = {};
  let options = true;
  const add = (name, value) => {
    const key = switchName(command, name);
    switches.push(key);
    if (value !== undefined) (values[key] ||= []).push(value);
  };
  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    if (options && arg === '--') { options = false; continue; }
    if (!options || arg === '-' || !arg.startsWith('-')) { operands.push(arg); continue; }
    if (arg.startsWith('--')) {
      const at = arg.indexOf('=');
      const name = arg.slice(2, at < 0 ? undefined : at);
      const value = at < 0 ? undefined : arg.slice(at + 1);
      if (spec.longValues.includes(name)) {
        const next = value === undefined ? argv[++i] : value;
        if (next === undefined) return { ...fail('Missing option value'), command, argv };
        add('--' + name, next);
      } else if ((spec.optionalLong || []).includes(name)) add('--' + name, value ?? '');
      else if (spec.long.includes(name) && value === undefined) add('--' + name);
      else return { ...fail('Unknown or ambiguous switch: --' + name), command, argv };
    } else {
      for (let offset = 1; offset < arg.length; offset++) {
        const name = arg[offset];
        if (spec.shortValues.includes(name) || (spec.optionalShort || []).includes(name)) {
          const optional = (spec.optionalShort || []).includes(name);
          const value = arg.slice(offset + 1) || (optional ? '' : argv[++i]);
          if (value === undefined) return { ...fail('Missing option value'), command, argv };
          add('-' + name, value);
          break;
        } else if (spec.short.includes(name)) add('-' + name);
        else return { ...fail('Unknown switch: -' + name), command, argv };
      }
    }
  }
  let files = operands;
  if (command === 'sed' && !values['-e'] && !values['-f']) files = operands.slice(1);
  return { supported: true, command, argv, switches, values, operands, files,
    input: files.length === 0 || files.includes('-') ? 'stdin' : 'files',
    scriptFiles: command === 'sed' ? values['-f'] || [] : [] };
}

export function emptyRules(snapshotDigest) {
  return { kind: 'NoshCommandPolicyDraft', schemaVersion: 1, enforcing: false, snapshotDigest, rules: [] };
}

export function validateRules(document, snapshotDigest) {
  if (!document || document.kind !== 'NoshCommandPolicyDraft' || document.schemaVersion !== 1
      || document.enforcing !== false || document.snapshotDigest !== snapshotDigest
      || !Array.isArray(document.rules) || document.rules.length > 500) throw new Error('Invalid command-policy draft or different audit.');
  const ids = new Set();
  const rules = document.rules.map(rule => {
    if (!rule || !text(rule.id, 100) || !rule.id || ids.has(rule.id) || !COMMANDS.includes(rule.command)
        || typeof rule.anySwitches !== 'boolean' || !['read-only', 'implementation'].includes(rule.mode)
        || !Array.isArray(rule.allowedSwitches) || !Array.isArray(rule.requiredSwitches)
        || [...rule.allowedSwitches, ...rule.requiredSwitches].some(x => !text(x, 100) || !/^--?[^\s=]+$/.test(x))
        || rule.allowedSwitches.length + rule.requiredSwitches.length > 100
        || !rule.optionValues || typeof rule.optionValues !== 'object' || Array.isArray(rule.optionValues)
        || Object.entries(rule.optionValues).length > 100
        || Object.entries(rule.optionValues).some(([key, value]) => !/^--?[^\s=*?]+$/.test(key)
          || !Array.isArray(value) || !value.length || value.length > 100 || value.some(x => !text(x)))) {
      throw new Error('Invalid command, switches, value patterns, or duplicate rule.');
    }
    ids.add(rule.id);
    const valueKeys = Object.keys(rule.optionValues).map(key => switchName(rule.command, key));
    if (new Set(valueKeys).size !== valueKeys.length) throw new Error('Option value conditions contain duplicate switch aliases.');
    return { id: rule.id, command: rule.command, mode: rule.mode, anySwitches: rule.anySwitches,
      allowedSwitches: [...new Set(rule.allowedSwitches.map(x => switchName(rule.command, x)))],
      requiredSwitches: [...new Set([...rule.requiredSwitches.map(x => switchName(rule.command, x)),
        ...(rule.command === 'sed' ? ['--sandbox'] : [])])],
      optionValues: Object.fromEntries(Object.entries(rule.optionValues).map(([key, value]) => [switchName(rule.command, key), value])) };
  });
  return { ...emptyRules(snapshotDigest), rules };
}

export function matchRule(rule, invocation, mode = 'read-only') {
  if (!invocation.supported) return { matches: false, reason: invocation.reason };
  if (invocation.command !== rule.command) return { matches: false, reason: 'Different command' };
  if (rule.mode === 'implementation' && mode !== 'implementation') return { matches: false, reason: 'Implementation mode required' };
  if (invocation.command === 'sed') {
    if (!invocation.switches.includes('--sandbox')) return { matches: false, reason: 'sed requires --sandbox' };
    if (invocation.switches.includes('-i') && (mode !== 'implementation' || rule.mode !== 'implementation')) {
      return { matches: false, reason: 'In-place editing requires an implementation rule and workspace' };
    }
  }
  for (const pattern of rule.requiredSwitches) {
    if (!invocation.switches.some(flag => globMatch(pattern, flag))) return { matches: false, reason: 'Required switch: ' + pattern };
  }
  for (const flag of invocation.switches) {
    if (!rule.anySwitches && ![...rule.allowedSwitches, ...rule.requiredSwitches].some(pattern => globMatch(pattern, flag))) {
      return { matches: false, reason: 'Switch not permitted: ' + flag };
    }
  }
  for (const [flag, patterns] of Object.entries(rule.optionValues)) {
    for (const value of invocation.values[flag] || []) {
      if (!patterns.some(pattern => globMatch(pattern, value))) return { matches: false, reason: 'Option value does not match: ' + flag };
    }
  }
  return { matches: true, reason: 'Matches proposed rule; enforcement is not active' };
}

export function authorizePipeline(document, stages, mode = 'read-only') {
  if (!['read-only', 'implementation'].includes(mode)) return { allowed: false, reason: 'Invalid workspace mode' };
  if (!Array.isArray(stages) || !stages.length || stages.length > 16) return { allowed: false, reason: 'Invalid pipeline' };
  const rules = validateRules(document, document.snapshotDigest).rules;
  for (const argv of stages) {
    const invocation = parseInvocation(argv);
    if (!invocation.supported) return { allowed: false, reason: invocation.reason };
    if (!rules.some(rule => matchRule(rule, invocation, mode).matches)) return { allowed: false, reason: 'No matching rule for ' + invocation.command };
  }
  return { allowed: true };
}
