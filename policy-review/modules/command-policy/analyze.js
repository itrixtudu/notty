import { parse } from 'acorn';
import { parseInvocation } from './model.js';

// Deliberately limited literal shell parser. This is evidence, never execution.
export function literalPipeline(source) {
  if (Array.isArray(source)) {
    return source.length && source.every(x => typeof x === 'string' && !x.includes('\0')) ? [source] : null;
  }
  if (typeof source !== 'string' || source.includes('\0')) return null;
  const stages = [[]];
  let token = '', started = false, quote = null, escaped = false;
  const flush = () => { if (started) stages.at(-1).push(token); token = ''; started = false; };
  for (const char of source) {
    if (escaped) {
      if (char === '\n' || char === '\r') return null;
      if (quote === '"' && !'\\$`"'.includes(char)) token += '\\';
      token += char; escaped = false; started = true; continue;
    }
    if (quote === "'") { if (char === "'") quote = null; else token += char; continue; }
    if (char === '\\') { escaped = true; started = true; continue; }
    if (char === '$' || char === '`') return null;
    if (quote === '"') { if (char === '"') quote = null; else token += char; continue; }
    if (char === "'" || char === '"') { quote = char; started = true; continue; }
    if (';&<>()\n\r*?[]{}~!#'.includes(char)) return null;
    if (char === '|') {
      flush();
      if (!stages.at(-1).length) return null;
      stages.push([]);
    } else if (/\s/.test(char)) flush();
    else { started = true; token += char; }
  }
  if (escaped || quote) return null;
  flush();
  return stages.at(-1).length ? stages : null;
}

function literal(node) {
  if (!node) throw new Error('Dynamic argument');
  if (node.type === 'Literal' && !node.regex && typeof node.value !== 'bigint') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) return node.quasis[0].value.cooked;
  if (node.type === 'ArrayExpression') return node.elements.map(literal);
  if (node.type === 'ObjectExpression') return Object.fromEntries(node.properties.map(prop => {
    if (prop.type !== 'Property' || prop.computed || prop.kind !== 'init' || prop.method || prop.shorthand) throw new Error('Dynamic object');
    return [prop.key.name ?? prop.key.value, literal(prop.value)];
  }));
  throw new Error('Dynamic argument');
}

export function analyzeRequest(tool, input) {
  const commands = [];
  let unresolved = false;
  const add = (value, nested = false) => {
    const source = typeof value === 'object' && value !== null ? value.cmd ?? value.command : value;
    const pipeline = literalPipeline(source);
    if (!pipeline) { unresolved = true; return; }
    pipeline.forEach((argv, index) => commands.push({ ...parseInvocation(argv), piped: index > 0, nested,
      input: index > 0 ? 'stdin' : parseInvocation(argv).input ?? 'unknown' }));
  };
  if (['exec_command', 'shell_command', 'shell'].includes(tool)) add(input);
  else if (tool === 'exec' && typeof input === 'string') {
    try {
      const tree = parse(input, { ecmaVersion: 'latest', sourceType: 'module', allowAwaitOutsideFunction: true });
      const stack = [tree];
      while (stack.length) {
        const node = stack.pop();
        if (!node || typeof node !== 'object') continue;
        if (node.type === 'CallExpression') {
          const name = node.callee?.type === 'MemberExpression' ? node.callee.property?.name ?? node.callee.property?.value : null;
          if (['exec_command', 'shell_command', 'shell'].includes(name)) {
            try { add(literal(node.arguments[0]), true); } catch { unresolved = true; }
          }
        }
        for (const value of Object.values(node)) {
          if (Array.isArray(value)) stack.push(...value);
          else if (value && typeof value === 'object') stack.push(value);
        }
      }
    } catch { unresolved = true; }
  } else unresolved = true;
  return { commands, unresolved: unresolved || commands.length === 0,
    basis: 'Static literal candidates only; recorded code is never executed.' };
}
