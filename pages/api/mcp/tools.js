import { getMcpToolset } from '../../../lib/mcpToolset.js';
import { getHttpProtocol, getRequestIpInfo, logTerminalEvent, withLogContext } from '../../../lib/terminalLogging.js';

export default function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', ['GET']);
    res.status(405).end();
    return;
  }

  const { sourceIp, forwardedFor } = getRequestIpInfo(req);
  withLogContext(
    {
      protocol: 'mcp',
      transport: 'http',
      source: 'nextApiMcp',
      route: 'GET /api/mcp/tools',
      http_protocol: getHttpProtocol(req),
      source_ip: sourceIp,
      x_forwarded_for: forwardedFor
    },
    () => {
      const { toolDefinitions, getToolDefinitions } = getMcpToolset();
      const activeToolDefinitions =
        typeof getToolDefinitions === 'function' ? getToolDefinitions() : toolDefinitions;
      logTerminalEvent({
        op: 'listTools',
        count: activeToolDefinitions.length
      });
      res.status(200).json({ tools: activeToolDefinitions });
    }
  );
}
