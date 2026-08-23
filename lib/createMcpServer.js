import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema
} from '@modelcontextprotocol/sdk/types.js';
import { getMcpToolset } from './mcpToolset.js';
import { logTerminalEvent, withLogContextDefaults } from './terminalLogging.js';

const DEFAULT_SERVER_OPTIONS = Object.freeze({
  name: 'node-pty-server',
  version: '1.0.0'
});

const DEFAULT_CAPABILITIES = Object.freeze({
  capabilities: {
    tools: {}
  }
});

export function createMcpServer(options = {}) {
  const identity = {
    ...DEFAULT_SERVER_OPTIONS,
    ...options
  };
  const { toolDefinitions, getToolDefinitions, callTool } = getMcpToolset();
  const resolveToolDefinitions =
    typeof getToolDefinitions === 'function' ? getToolDefinitions : () => toolDefinitions;

  const server = new Server(identity, DEFAULT_CAPABILITIES);

  server.setRequestHandler(ListToolsRequestSchema, async () =>
    withLogContextDefaults(
      {
        protocol: 'mcp',
        transport: 'stdio',
        source: 'mcpStdio'
      },
      () => {
        const activeToolDefinitions = resolveToolDefinitions();
        logTerminalEvent({
          op: 'listTools',
          count: activeToolDefinitions.length
        });
        return { tools: activeToolDefinitions };
      }
    )
  );

  server.setRequestHandler(CallToolRequestSchema, async (req) =>
    withLogContextDefaults(
      {
        protocol: 'mcp',
        transport: 'stdio',
        source: 'mcpStdio'
      },
      () => callTool(req.params.name, req.params.arguments || {})
    )
  );

  return server;
}
