import { safeRequestErrorDetails } from './safeRequestError.js';

export function isMcpTransportRequest(req) {
  const method = String(req?.method || 'GET').toUpperCase();
  const accept = String(req?.headers?.accept || '').toLowerCase();
  return method !== 'GET' || accept.includes('text/event-stream');
}

export function routeMcpTransportOrUi(req, _res, next) {
  if (!isMcpTransportRequest(req)) {
    next('router');
    return;
  }
  next();
}

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
      logError('[mcp-http] tool call error:', safeRequestErrorDetails(err));
      if (!res.headersSent) {
        res.status(500).json({ error: err?.message || 'Tool call failed' });
      }
    }
  };
}
