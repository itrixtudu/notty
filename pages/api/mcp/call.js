import { getMcpToolset } from '../../../lib/mcpToolset.js';
import { getHttpProtocol, getRequestIpInfo, withLogContext } from '../../../lib/terminalLogging.js';

function withMcpContext(req, route, fn) {
  const { sourceIp, forwardedFor } = getRequestIpInfo(req);
  return withLogContext(
    {
      protocol: 'mcp',
      transport: 'http',
      source: 'nextApiMcp',
      route,
      http_protocol: getHttpProtocol(req),
      source_ip: sourceIp,
      x_forwarded_for: forwardedFor
    },
    fn
  );
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', ['POST']);
    res.status(405).end();
    return;
  }

  const { name, arguments: args } = req.body || {};
  if (typeof name !== 'string' || !name.trim()) {
    res.status(400).json({ error: 'Tool name is required' });
    return;
  }

  await withMcpContext(req, 'POST /api/mcp/call', async () => {
    const { callTool } = getMcpToolset();
    const result = await callTool(name, args || {});
    const status = result.isError ? 400 : 200;
    res.status(status).json(result);
  });
}
