'use strict';

const FILTER_ENV = 'NOTTY_MCP_ALLOWED_TOOLS';

function normalizeAllowedMcpTools(value) {
  if (value === undefined || value === null || value === '') return null;
  const source = Array.isArray(value) ? value : String(value).split(',');
  const names = [];
  const seen = new Set();
  for (const entry of source) {
    const name = String(entry || '').trim();
    if (!name || seen.has(name)) continue;
    if (!/^[A-Za-z0-9_.:-]+$/.test(name)) {
      throw new Error(`invalid MCP tool name in allowlist: ${name}`);
    }
    seen.add(name);
    names.push(name);
  }
  return names;
}

function createMcpToolFilter(toolDefinitions, value = process.env[FILTER_ENV]) {
  const definitions = Array.isArray(toolDefinitions) ? toolDefinitions : [];
  const allowedNames = normalizeAllowedMcpTools(value);
  if (allowedNames === null) {
    return {
      active: false,
      allowedNames: definitions.map((tool) => tool.name),
      definitions: [...definitions],
      assertAllowed() {},
    };
  }

  const available = new Set(definitions.map((tool) => tool.name));
  const unknown = allowedNames.filter((name) => !available.has(name));
  if (unknown.length) {
    throw new Error(
      `unknown MCP tool${unknown.length === 1 ? '' : 's'}: ${unknown.join(', ')}; `
      + `available tools: ${[...available].join(', ') || '(none)'}`,
    );
  }
  const allowed = new Set(allowedNames);
  return {
    active: true,
    allowedNames,
    definitions: definitions.filter((tool) => allowed.has(tool.name)),
    assertAllowed(name) {
      if (allowed.has(name)) return;
      const error = new Error(
        `MCP tool ${name} is not available in the active tool profile; `
        + `allowed tools: ${allowedNames.join(', ') || '(none)'}. `
        + 'Inspect tools/list once and use a safe listed alternative. If none can complete the task, '
        + 'report “Human help needed” with one concrete next action.',
      );
      error.code = 'TOOL_NOT_AVAILABLE';
      throw error;
    },
  };
}

function toolFilterGuidance(active) {
  if (!active) return '';
  return [
    'TOOL FILTER: Only tools returned by native tool discovery are available.',
    'If an intended tool is absent, inspect discovery once and use a safe listed tool that can achieve the same outcome.',
    'Do not retry or invent the hidden tool, alter the filter, or use another mechanism solely to evade it.',
    'If no listed route works, report: Human help needed — the required capability is not available in this tool profile. Next: <one concrete human action>.',
  ].join('\n');
}

module.exports = {
  FILTER_ENV,
  createMcpToolFilter,
  normalizeAllowedMcpTools,
  toolFilterGuidance,
};
