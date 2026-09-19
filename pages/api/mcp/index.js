import { getServerForRequest } from '../../../lib/mcpHttpServer.js';
import { getHttpProtocol, getRequestIpInfo, withLogContext } from '../../../lib/terminalLogging.js';
import { safeRequestErrorDetails } from '../../../lib/safeRequestError.js';

export const config = {
  api: {
    bodyParser: false
  }
};

export default async function handler(req, res) {
  try {
    const { sourceIp, forwardedFor } = getRequestIpInfo(req);
    await withLogContext(
      {
        protocol: 'mcp',
        transport: 'http',
        source: 'nextApiMcp',
        route: `${req.method || 'REQUEST'} /api/mcp`,
        http_protocol: getHttpProtocol(req),
        source_ip: sourceIp,
        x_forwarded_for: forwardedFor
      },
      async () => {
        // Get or create a per-client transport for concurrent attachments
        const { transport, sessionId } = await getServerForRequest(req);

        // Log session info for debugging
        console.log('[mcp-http] Handling request for session:', sessionId);

        // Set session ID in response headers for client tracking
        res.setHeader('X-Session-Id', sessionId);

        await transport.handleRequest(req, res);
      }
    );
  } catch (err) {
    console.error('[mcp-http] request failed:', safeRequestErrorDetails(err));
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          error: {
            code: -32603,
            message: err?.message || 'Internal error'
          },
          id: null
        })
      );
    }
  }
}
