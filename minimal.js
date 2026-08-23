#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

console.error('[minimal] Starting...');

const srv = new Server({
  name: "minimal-test",
  version: "1.0.0"
}, {
  capabilities: {
    tools: {}
  }
});

console.error('[minimal] Server created');

srv.setRequestHandler(ListToolsRequestSchema, async () => {
  console.error('[minimal] ListTools called');
  return {
    tools: [
      {
        name: "health",
        description: "Health check",
        inputSchema: {
          type: "object",
          properties: {}
        }
      },
      {
        name: "info",
        description: "Get server info",
        inputSchema: {
          type: "object",
          properties: {}
        }
      }
    ]
  };
});

srv.setRequestHandler(CallToolRequestSchema, async (req) => {
  console.error('[minimal] CallTool:', req.params.name);
  
  if (req.params.name === 'health') {
    return {
      content: [{
        type: "text",
        text: "OK"
      }]
    };
  }
  
  if (req.params.name === 'info') {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          name: "minimal-test",
          version: "1.0.0",
          platform: process.platform,
          node: process.version,
          uptime: process.uptime()
        }, null, 2)
      }]
    };
  }
  
  return {
    content: [{ type: "text", text: "Unknown tool" }],
    isError: true
  };
});

console.error('[minimal] Handlers registered');

const transport = new StdioServerTransport();
console.error('[minimal] Transport created');

await srv.connect(transport);
console.error('[minimal] Connected!');
