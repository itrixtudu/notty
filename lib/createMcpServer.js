import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema
} from '@modelcontextprotocol/sdk/types.js';
import { getMcpToolset } from './mcpToolset.js';
import { logTerminalEvent, withLogContextDefaults } from './terminalLogging.js';
import mcpToolFilter from './mcpToolFilter.cjs';

const { createMcpToolFilter } = mcpToolFilter;

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
  const { allowedMcpTools, ...serverOptions } = options;
  const identity = {
    ...DEFAULT_SERVER_OPTIONS,
    ...serverOptions
  };
  const { toolDefinitions, getToolDefinitions, callTool } = getMcpToolset();
  const resolveToolDefinitions =
    typeof getToolDefinitions === 'function' ? getToolDefinitions : () => toolDefinitions;
  const resolveFilter = () => createMcpToolFilter(
    resolveToolDefinitions(),
    Object.hasOwn(options, 'allowedMcpTools') ? allowedMcpTools : undefined
  );

  resolveFilter();

  const server = new Server(identity, DEFAULT_CAPABILITIES);

  server.setRequestHandler(ListToolsRequestSchema, async () =>
    withLogContextDefaults(
      {
        protocol: 'mcp',
        transport: 'stdio',
        source: 'mcpStdio'
      },
      () => {
        const activeToolDefinitions = resolveFilter().definitions;
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
      () => {
        try {
          resolveFilter().assertAllowed(req.params.name);
        } catch (error) {
          if (error?.code !== 'TOOL_NOT_AVAILABLE') throw error;
          logTerminalEvent({
            op: 'callToolDenied',
            tool: req.params.name,
            code: error.code
          });
          return {
            isError: true,
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: { code: error.code, message: error.message }
              })
            }]
          };
        }
        return callTool(req.params.name, req.params.arguments || {});
      }
    )
  );

  return server;
}
