import {
  toolDefinitions as fullToolDefinitions,
  getToolDefinitions as getFullToolDefinitions,
  callTool as callFullTool
} from './mcpTools.js';
import {
  toolDefinitions as simpleToolDefinitions,
  getToolDefinitions as getSimpleToolDefinitions,
  callTool as callSimpleTool
} from './mcpToolsSimple.js';
import {
  toolDefinitions as durdrawToolDefinitions,
  getToolDefinitions as getDurdrawToolDefinitions,
  callTool as callDurdrawTool
} from './mcpDurdraw.js';

const SIMPLE_TOOLSET_KEYS = new Set(['simple', 'simplified']);
const DURDRAW_TOOLSET_KEYS = new Set(['durdraw', 'dur']);

export function getToolsetMode(value = process.env.NOTTY_MCP_TOOLSET) {
  if (typeof value !== 'string') {
    return 'full';
  }
  const normalized = value.trim().toLowerCase();
  if (SIMPLE_TOOLSET_KEYS.has(normalized)) {
    return 'simple';
  }
  if (DURDRAW_TOOLSET_KEYS.has(normalized)) {
    return 'durdraw';
  }
  return 'full';
}

export function getMcpToolset(mode = getToolsetMode()) {
  if (mode === 'simple') {
    return {
      mode,
      toolDefinitions: simpleToolDefinitions,
      getToolDefinitions: getSimpleToolDefinitions,
      callTool: callSimpleTool
    };
  }

  if (mode === 'durdraw') {
    return {
      mode,
      toolDefinitions: durdrawToolDefinitions,
      getToolDefinitions: getDurdrawToolDefinitions,
      callTool: callDurdrawTool
    };
  }

  return {
    mode,
    toolDefinitions: fullToolDefinitions,
    getToolDefinitions: getFullToolDefinitions,
    callTool: callFullTool
  };
}
