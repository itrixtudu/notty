import { resolveBrowserUrl } from './browserRequest.js';

const ENV_WS_URL = process.env.NOTTY_PUBLIC_WS_URL;

export async function resolveTerminalWsUrl(sessionId) {
  if (typeof window === 'undefined') {
    throw new Error('WebSocket resolution requires a browser context');
  }

  const target = ENV_WS_URL || window.location.href;
  const url = new URL(resolveBrowserUrl(target));
  if (url.protocol === 'https:') {
    url.protocol = 'wss:';
  } else if (url.protocol === 'http:') {
    url.protocol = 'ws:';
  }
  url.pathname = '/ws/terminals';
  url.searchParams.set('id', String(sessionId));
  return url.toString();
}
