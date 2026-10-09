import fs, { constants } from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { analyzeRequest } from '../command-policy/analyze.js';
import { globMatch, matchRule, validateRules } from '../command-policy/model.js';

const MAX_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_DETAIL = 64 * 1024;
const PAGE_SIZE = 50;
let cached;
const signature = stat => [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs, stat.mode, stat.uid, stat.nlink].join(':');

export function validateDescriptor(value) {
  if (!value || value.schemaVersion !== 1 || value.file !== 'requests.sqlite3' || value.originalInputs !== true
      || !/^sha256:[a-f0-9]{64}$/.test(value.digest)
      || !Number.isSafeInteger(value.bytes) || value.bytes < 1 || value.bytes > MAX_BYTES
      || !Number.isSafeInteger(value.uniqueRequests) || value.uniqueRequests < 0
      || !Number.isSafeInteger(value.recordedRequests) || value.recordedRequests < value.uniqueRequests) {
    throw new Error('Invalid request evidence descriptor.');
  }
  return value;
}

export async function openEvidence(snapshot) {
  if (!snapshot.requestEvidence) throw new Error('Request details were not captured. Run nosh tools init for a fresh audit.');
  const descriptor = validateDescriptor(snapshot.requestEvidence);
  const filename = path.join(process.env.NOTTY_TOOL_REVIEW_INPUT_DIR, descriptor.file);
  const file = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await file.stat({ bigint: true });
    if (!stat.isFile() || stat.nlink !== 1n || stat.uid !== BigInt(process.geteuid()) || (stat.mode & 0o077n)
        || stat.size !== BigInt(descriptor.bytes)) throw new Error('Request evidence must be a private, singly linked owned file.');
    const key = `${filename}:${snapshot.digest}:${signature(stat)}`;
    if (cached?.key === key) return cached.db;
    cached?.db.close(); cached = null;
    const hash = crypto.createHash('sha256');
    for await (const chunk of file.createReadStream({ autoClose: false })) hash.update(chunk);
    if (`sha256:${hash.digest('hex')}` !== descriptor.digest || signature(await file.stat({ bigint: true })) !== signature(stat)) {
      throw new Error('Request evidence changed since the audit.');
    }
    // Open the verified inode, not a replaceable pathname. The review container mounts it read-only.
    const db = new DatabaseSync(`/proc/self/fd/${file.fd}`, { readOnly: true, allowExtension: false });
    try {
      db.exec('PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;');
      if (db.prepare('PRAGMA user_version').get().user_version !== 1) throw new Error('Unsupported evidence database.');
      const counts = db.prepare('SELECT count(*) AS uniqueRequests, coalesce(sum(occurrences),0) AS recordedRequests FROM requests').get();
      if (counts.uniqueRequests !== descriptor.uniqueRequests || counts.recordedRequests !== descriptor.recordedRequests) {
        throw new Error('Request evidence counts disagree.');
      }
      const groups = new Map(snapshot.groups.map(group => [group.id, group.count]));
      for (const row of db.prepare('SELECT group_id, sum(occurrences) AS count FROM requests GROUP BY group_id').iterate()) {
        if (groups.get(row.group_id) !== row.count) throw new Error('Request evidence group counts disagree.');
        groups.delete(row.group_id);
      }
      if ([...groups.values()].some(count => count !== 0)) throw new Error('Missing request evidence groups.');
      cached = { key, db };
      return db;
    } catch (error) { db.close(); throw error; }
  } finally { await file.close(); }
}

export async function requestEvidence(snapshot, query, rulesDocument = null) {
  const db = await openEvidence(snapshot);
  const validId = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  if (query.id !== undefined) {
    if (!validId(query.id)) throw new Error('Invalid request identifier.');
    const offset = Number(query.offset || 0);
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > MAX_BYTES) throw new Error('Invalid detail offset.');
    const row = db.prepare('SELECT tool, cwd, length(input_json) AS total, substr(input_json, ?, ?) AS input FROM requests WHERE id=?')
      .get(offset + 1, MAX_DETAIL, query.id);
    if (!row) throw new Error('Unknown request.');
    return { ...row, offset, nextOffset: offset + MAX_DETAIL < row.total ? offset + MAX_DETAIL : null };
  }
  const page = Number(query.page || 0);
  if (!Number.isSafeInteger(page) || page < 0 || page > 1000000) throw new Error('Invalid evidence page.');
  for (const key of ['q', 'command', 'switch', 'input', 'group', 'rule']) {
    if (query[key] !== undefined && (typeof query[key] !== 'string' || query[key].length > 256)) throw new Error('Invalid evidence filter.');
  }
  if (query.group && (!validId(query.group) || !snapshot.groups.some(group => group.id === query.group))) throw new Error('Unknown group.');
  const rule = query.rule && rulesDocument ? validateRules(rulesDocument, snapshot.digest).rules.find(item => item.id === query.rule) : null;
  if (query.rule && !rule) throw new Error('Unknown saved rule.');
  const conditions = [], parameters = [];
  if (query.group) { conditions.push('group_id=?'); parameters.push(query.group); }
  if (query.q) { conditions.push("instr(lower(input_json || char(10) || coalesce(cwd,'') || char(10) || tool),lower(?)) > 0"); parameters.push(query.q); }
  const where = conditions.length ? ' WHERE ' + conditions.join(' AND ') : '';
  const needsAnalysis = Boolean(query.command || query.switch || query.input || rule);
  const sql = 'SELECT * FROM requests' + where + ' ORDER BY id' + (needsAnalysis ? '' : ' LIMIT ? OFFSET ?');
  const rows = db.prepare(sql).iterate(...parameters, ...(needsAnalysis ? [] : [PAGE_SIZE, page * PAGE_SIZE]));
  const entries = [];
  let total = 0, occurrences = 0;
  for (const row of rows) {
    const analysis = analyzeRequest(row.tool, JSON.parse(row.input_json));
    const candidates = analysis.commands.filter(command => (!query.command || globMatch(query.command, command.command || ''))
      && (!query.switch || command.switches.some(flag => globMatch(query.switch, flag)))
      && (!query.input || command.input === query.input));
    if ((query.command || query.switch || query.input) && candidates.length === 0) continue;
    const matching = rule ? analysis.commands.map(invocation => matchRule(rule, invocation, rule.mode)) : [];
    if (rule && !matching.some(result => result.matches)) continue;
    if ((!needsAnalysis || total >= page * PAGE_SIZE) && entries.length < PAGE_SIZE) entries.push({
      id: row.id, tool: row.tool, groupId: row.group_id, cwd: row.cwd, occurrences: row.occurrences,
      source: row.source, line: row.line, preview: row.input_json.slice(0, 500),
      analysis: { ...analysis, commands: analysis.commands.slice(0, 20).map(({ argv, ...command }) => ({
        ...command, argv: argv?.map(arg => arg.slice(0, 500)), values: undefined, operands: undefined,
        files: command.files?.slice(0, 10).map(arg => arg.slice(0, 500)), scriptFiles: undefined,
      })) },
    });
    total++; occurrences += row.occurrences;
  }
  if (!needsAnalysis) {
    const counts = db.prepare('SELECT count(*) AS total, coalesce(sum(occurrences),0) AS occurrences FROM requests' + where).get(...parameters);
    total = counts.total; occurrences = counts.occurrences;
  }
  return { entries, total, occurrences, page, pageSize: PAGE_SIZE };
}
