import { NextResponse } from 'next/server.js';
import { resolveOriginPolicy } from './lib/corsPolicy.js';

function withCorsHeaders(response, decision) {
  if (!decision.responseOrigin) {
    return response;
  }
  response.headers.set('Access-Control-Allow-Origin', decision.responseOrigin);
  response.headers.set(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-Session-Id, MCP-Session-Id, MCP-Protocol-Version, Last-Event-ID'
  );
  response.headers.set('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  response.headers.set('Access-Control-Expose-Headers', 'X-Session-Id, MCP-Session-Id');
  if (decision.responseOrigin !== '*') {
    response.headers.append('Vary', 'Origin');
  }
  return response;
}

export function proxy(request) {
  const pathname = request.nextUrl.pathname;
  const method = request.method.toUpperCase();
  const isApiRequest = pathname.startsWith('/api/');
  const isMcpTransportRequest = pathname === '/mcp'
    && (method !== 'GET' || (request.headers.get('accept') || '').includes('text/event-stream'));

  if ((isApiRequest || isMcpTransportRequest)
    && process.env.NOTTY_INTEGRATED_SERVER !== 'true') {
    return NextResponse.json(
      {
        error: {
          code: 'INTEGRATED_SERVER_REQUIRED',
          message: 'Notty API and MCP routes require the authenticated server entrypoint'
        }
      },
      { status: 503 }
    );
  }

  let originDecision = null;
  if (isApiRequest || isMcpTransportRequest) {
    const trustedHosts = [
      process.env.NOTTY_PUBLIC_HOST,
      process.env.PUBLIC_HOST,
      process.env.NOTTY_BIND_HOST,
      process.env.NOTTY_HOST,
      process.env.BIND_HOST,
      process.env.HOST,
      process.env.NOTTY_PUBLIC_ORIGIN,
      process.env.NOTTY_TRUSTED_HOSTS
    ];
    originDecision = resolveOriginPolicy({
      origin: request.headers.get('origin'),
      host: request.headers.get('host'),
      protocol: request.nextUrl.protocol,
      allowedOrigin: process.env.ALLOWED_ORIGIN,
      publicOrigin: process.env.NOTTY_PUBLIC_ORIGIN,
      fetchSite: request.headers.get('sec-fetch-site'),
      trustedHosts
    });
    if (!originDecision.allowed) {
      return NextResponse.json(
        { error: { code: 'ORIGIN_REJECTED', message: 'Cross-origin requests are not allowed' } },
        { status: 403 }
      );
    }
    if (method === 'OPTIONS') {
      return withCorsHeaders(new NextResponse(null, { status: 204 }), originDecision);
    }
  }

  if (pathname !== '/mcp') {
    return originDecision
      ? withCorsHeaders(NextResponse.next(), originDecision)
      : NextResponse.next();
  }

  const accept = request.headers.get('accept') || '';

  const wantsStream = accept.includes('text/event-stream');
  const isNonGet = method !== 'GET';

  if (isNonGet || wantsStream) {
    const rewriteUrl = request.nextUrl.clone();
    rewriteUrl.pathname = '/api/mcp';
    const response = NextResponse.rewrite(rewriteUrl);
    return originDecision ? withCorsHeaders(response, originDecision) : response;
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/mcp', '/api/:path*']
};
