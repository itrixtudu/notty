import { getStandaloneWsState } from '../../lib/standaloneWsServer.js';

export const config = {
  api: {
    bodyParser: false
  }
};

export default function handler(req, res) {
  let state;

  try {
    state = getStandaloneWsState();
  } catch (err) {
    res.setHeader('Cache-Control', 'no-store');
    res.status(503).json({
      ready: false,
      error: err?.message || 'Terminal WebSocket server unavailable'
    });
    return;
  }

  const forwardedProto = req.headers['x-forwarded-proto'];
  const protocol = Array.isArray(forwardedProto)
    ? forwardedProto[0]
    : forwardedProto;
  const secure = protocol === 'https';

  const headerHost =
    req.headers['x-forwarded-host'] ||
    req.headers.host ||
    (state.host && state.port ? `${state.host}:${state.port}` : undefined);

  const scheme = secure ? 'wss' : 'ws';
  const url = headerHost ? `${scheme}://${headerHost}${state.path}` : state.url;

  res.setHeader('Cache-Control', 'no-store');
  res.status(200).json({
    ready: true,
    url,
    host: state.host,
    port: state.port,
    path: state.path
  });
}
