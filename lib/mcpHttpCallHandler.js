export function createMcpHttpCallHandler({
  getMcpToolset,
  getHttpProtocol,
  getRequestIpInfo,
  withLogContext,
  logError = (...args) => console.error(...args)
}) {
  return async function mcpHttpCallHandler(req, res) {
    try {
      const { sourceIp, forwardedFor } = getRequestIpInfo(req);
      await withLogContext(
        {
          protocol: 'mcp',
          transport: 'http',
          source: 'mcpRouter',
          route: 'POST /mcp/call',
          http_protocol: getHttpProtocol(req),
          source_ip: sourceIp,
          x_forwarded_for: forwardedFor
        },
        async () => {
          const { name, arguments: args } = req.body || {};
          if (typeof name !== 'string' || !name.trim()) {
            res.status(400).json({ error: 'Tool name is required' });
            return;
          }

          const { callTool } = getMcpToolset();
          const result = await callTool(name, args || {});
          const status = result.isError ? 400 : 200;
          res.status(status).json(result);
        }
      );
    } catch (err) {
      logError('[mcp-http] tool call error:', err);
      if (!res.headersSent) {
        res.status(500).json({ error: err?.message || 'Tool call failed' });
      }
    }
  };
}
