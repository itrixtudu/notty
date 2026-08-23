#!/usr/bin/env node

import dns from 'node:dns';
import dgram from 'node:dgram';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import process from 'node:process';

const DEFAULT_TIMEOUT_MS = 1_500;
const MIN_TIMEOUT_MS = 250;
const MAX_TIMEOUT_MS = 10_000;

const BLOCKED_SOCKET_CODES = new Set([
  'EACCES',
  'EHOSTDOWN',
  'EHOSTUNREACH',
  'ENETDOWN',
  'ENETUNREACH',
  'EPERM',
  'ETIMEDOUT',
]);

const BLOCKED_DNS_CODES = new Set([
  'EACCES',
  'EAI_AGAIN',
  'ECANCELLED',
  'EDESTRUCTION',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENODATA',
  'ENOTFOUND',
  'ENOTIMP',
  'ENOTINITIALIZED',
  'EPERM',
  'EREFUSED',
  'ESERVFAIL',
  'ETIMEOUT',
]);

function usage() {
  return `Usage: node nosh-egress-containment-probe.mjs [--timeout-ms NUMBER]\n\n` +
    'Run a bounded default-deny escape probe from inside a guarded runner.\n' +
    'The program succeeds only when no DNS, TCP, HTTP(S), or direct-DNS probe\n' +
    'obtains positive evidence that traffic escaped.\n';
}

function parseTimeout(value) {
  if (!/^[1-9][0-9]*$/u.test(String(value || ''))) {
    throw new TypeError('--timeout-ms must be an integer');
  }
  const selected = Number(value);
  if (
    !Number.isSafeInteger(selected)
    || selected < MIN_TIMEOUT_MS
    || selected > MAX_TIMEOUT_MS
  ) {
    throw new TypeError(
      `--timeout-ms must be between ${MIN_TIMEOUT_MS} and ${MAX_TIMEOUT_MS}`,
    );
  }
  return selected;
}

export function parseProbeOptions(argv) {
  let timeoutMs = DEFAULT_TIMEOUT_MS;
  let timeoutSeen = false;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '-h' || argument === '--help') {
      return { help: true, timeoutMs };
    }
    if (argument === '--timeout-ms') {
      if (timeoutSeen || index + 1 >= argv.length) {
        throw new TypeError('--timeout-ms requires one value');
      }
      timeoutMs = parseTimeout(argv[index + 1]);
      timeoutSeen = true;
      index += 1;
      continue;
    }
    if (argument.startsWith('--timeout-ms=')) {
      if (timeoutSeen) {
        throw new TypeError('--timeout-ms may be supplied only once');
      }
      timeoutMs = parseTimeout(argument.slice('--timeout-ms='.length));
      timeoutSeen = true;
      continue;
    }
    throw new TypeError(`unknown option: ${argument}`);
  }
  return { help: false, timeoutMs };
}

function safeError(error) {
  const code = typeof error?.code === 'string' ? error.code : null;
  const name = typeof error?.name === 'string' ? error.name : 'Error';
  return { code, name };
}

function blockedResult(id, kind, target, detail) {
  return {
    id,
    kind,
    target,
    status: 'blocked',
    escaped: false,
    detail,
  };
}

function escapedResult(id, kind, target, detail) {
  return {
    id,
    kind,
    target,
    status: 'escaped',
    escaped: true,
    detail,
  };
}

function indeterminateResult(id, kind, target, detail) {
  return {
    id,
    kind,
    target,
    status: 'indeterminate',
    escaped: null,
    detail,
  };
}

export function tcpConnectProbe({ id, host, port, family = 4, timeoutMs }) {
  const target = family === 6 ? `[${host}]:${port}` : `${host}:${port}`;
  return new Promise((resolve) => {
    let settled = false;
    const socket = net.createConnection({ host, port, family });
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };
    const timer = setTimeout(() => {
      finish(blockedResult(id, 'tcp', target, { outcome: 'timeout' }));
    }, timeoutMs);
    socket.once('connect', () => {
      finish(escapedResult(id, 'tcp', target, { outcome: 'connected' }));
    });
    socket.once('error', (error) => {
      const selected = safeError(error);
      if (BLOCKED_SOCKET_CODES.has(selected.code)) {
        finish(blockedResult(id, 'tcp', target, {
          outcome: 'socket-error',
          ...selected,
        }));
        return;
      }
      if (selected.code === 'ECONNREFUSED' || selected.code === 'ECONNRESET') {
        finish(escapedResult(id, 'tcp', target, {
          outcome: 'network-response',
          ...selected,
        }));
        return;
      }
      finish(indeterminateResult(id, 'tcp', target, {
        outcome: 'unexpected-error',
        ...selected,
      }));
    });
  });
}

export async function systemDnsProbe({ timeoutMs }) {
  const id = 'system-dns-example';
  const target = 'example.com A';
  const resolver = new dns.promises.Resolver({
    timeout: timeoutMs,
    tries: 1,
  });
  try {
    const addresses = await resolver.resolve4('example.com');
    if (addresses.length) {
      return escapedResult(id, 'dns', target, {
        outcome: 'resolved',
        answerCount: addresses.length,
      });
    }
    return indeterminateResult(id, 'dns', target, {
      outcome: 'empty-answer',
    });
  } catch (error) {
    const selected = safeError(error);
    if (BLOCKED_DNS_CODES.has(selected.code)) {
      return blockedResult(id, 'dns', target, {
        outcome: 'resolver-error',
        ...selected,
      });
    }
    return indeterminateResult(id, 'dns', target, {
      outcome: 'unexpected-error',
      ...selected,
    });
  }
}

function dnsQuery(name, identifier = 0x4e47) {
  const labels = name.split('.');
  const encodedLabels = labels.map((label) => {
    const content = Buffer.from(label, 'ascii');
    return Buffer.concat([Buffer.from([content.length]), content]);
  });
  const header = Buffer.alloc(12);
  header.writeUInt16BE(identifier, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const question = Buffer.alloc(4);
  question.writeUInt16BE(1, 0);
  question.writeUInt16BE(1, 2);
  return Buffer.concat([...encodedLabels, Buffer.from([0]), question], 12 +
    encodedLabels.reduce((total, item) => total + item.length, 0) + 5);
}

export function udpDnsProbe({ timeoutMs }) {
  const id = 'direct-dns-udp';
  const target = '8.8.8.8:53';
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.close();
      resolve(result);
    };
    const timer = setTimeout(() => {
      finish(blockedResult(id, 'udp-dns', target, { outcome: 'timeout' }));
    }, timeoutMs);
    socket.once('message', (message) => {
      finish(escapedResult(id, 'udp-dns', target, {
        outcome: 'response',
        responseBytes: message.length,
      }));
    });
    socket.once('error', (error) => {
      const selected = safeError(error);
      if (BLOCKED_SOCKET_CODES.has(selected.code)) {
        finish(blockedResult(id, 'udp-dns', target, {
          outcome: 'socket-error',
          ...selected,
        }));
        return;
      }
      if (selected.code === 'ECONNREFUSED' || selected.code === 'ECONNRESET') {
        finish(escapedResult(id, 'udp-dns', target, {
          outcome: 'network-response',
          ...selected,
        }));
        return;
      }
      finish(indeterminateResult(id, 'udp-dns', target, {
        outcome: 'unexpected-error',
        ...selected,
      }));
    });
    socket.send(dnsQuery('example.com'), 53, '8.8.8.8', (error) => {
      if (!error) return;
      const selected = safeError(error);
      if (BLOCKED_SOCKET_CODES.has(selected.code)) {
        finish(blockedResult(id, 'udp-dns', target, {
          outcome: 'send-error',
          ...selected,
        }));
        return;
      }
      finish(indeterminateResult(id, 'udp-dns', target, {
        outcome: 'unexpected-send-error',
        ...selected,
      }));
    });
  });
}

export function udpResponseProbe({ id, host, port, payload, timeoutMs }) {
  const target = `${host}:${port}`;
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.close();
      resolve(result);
    };
    const timer = setTimeout(() => {
      finish(blockedResult(id, 'udp', target, { outcome: 'timeout' }));
    }, timeoutMs);
    socket.once('message', (message) => {
      finish(escapedResult(id, 'udp', target, {
        outcome: 'response',
        responseBytes: message.length,
      }));
    });
    socket.once('error', (error) => {
      const selected = safeError(error);
      if (BLOCKED_SOCKET_CODES.has(selected.code)) {
        finish(blockedResult(id, 'udp', target, {
          outcome: 'socket-error',
          ...selected,
        }));
        return;
      }
      if (selected.code === 'ECONNREFUSED' || selected.code === 'ECONNRESET') {
        finish(escapedResult(id, 'udp', target, {
          outcome: 'network-response',
          ...selected,
        }));
        return;
      }
      finish(indeterminateResult(id, 'udp', target, {
        outcome: 'unexpected-error',
        ...selected,
      }));
    });
    socket.send(payload, port, host, (error) => {
      if (!error) return;
      const selected = safeError(error);
      if (BLOCKED_SOCKET_CODES.has(selected.code)) {
        finish(blockedResult(id, 'udp', target, {
          outcome: 'send-error',
          ...selected,
        }));
        return;
      }
      finish(indeterminateResult(id, 'udp', target, {
        outcome: 'unexpected-send-error',
        ...selected,
      }));
    });
  });
}

function quicVersionProbePayload() {
  const payload = Buffer.alloc(1_200);
  payload[0] = 0xc0;
  payload.writeUInt32BE(0x1a2a3a4a, 1);
  payload[5] = 8;
  Buffer.from('noshdeny').copy(payload, 6);
  payload[14] = 8;
  Buffer.from('guardnet').copy(payload, 15);
  return payload;
}

export function fetchProbe({ id, url, timeoutMs }) {
  const selectedUrl = new URL(url);
  const client = selectedUrl.protocol === 'https:' ? https : http;
  return new Promise((resolve) => {
    let settled = false;
    let request;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      request?.destroy();
      resolve(result);
    };
    const timer = setTimeout(() => {
      finish(blockedResult(id, 'http', url, { outcome: 'timeout' }));
    }, timeoutMs);
    request = client.request(selectedUrl, {
      agent: false,
      headers: { connection: 'close' },
      method: 'HEAD',
      rejectUnauthorized: true,
    });
    request.once('socket', (socket) => {
      const connected = () => {
        finish(escapedResult(id, 'http', url, {
          outcome: 'connected',
        }));
      };
      if (socket.connecting) socket.once('connect', connected);
      else connected();
    });
    request.once('response', (response) => {
      response.destroy();
      finish(escapedResult(id, 'http', url, {
        outcome: 'response',
        responseStatus: response.statusCode,
      }));
    });
    request.once('error', (error) => {
      const selected = safeError(error);
      if (
        BLOCKED_SOCKET_CODES.has(selected.code)
        || BLOCKED_DNS_CODES.has(selected.code)
      ) {
        finish(blockedResult(id, 'http', url, {
          outcome: 'request-error',
          ...selected,
        }));
        return;
      }
      if (selected.code === 'ECONNREFUSED' || selected.code === 'ECONNRESET') {
        finish(escapedResult(id, 'http', url, {
          outcome: 'network-response',
          ...selected,
        }));
        return;
      }
      finish(indeterminateResult(id, 'http', url, {
        outcome: 'unexpected-error',
        ...selected,
      }));
    });
    request.end();
  });
}

export async function runContainmentProbes({ timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  parseTimeout(timeoutMs);
  const probes = await Promise.all([
    systemDnsProbe({ timeoutMs }),
    fetchProbe({ id: 'hostname-http', url: 'http://example.com/', timeoutMs }),
    fetchProbe({ id: 'hostname-https', url: 'https://example.com/', timeoutMs }),
    tcpConnectProbe({ id: 'public-http-ip', host: '1.1.1.1', port: 80, timeoutMs }),
    tcpConnectProbe({ id: 'public-https-ip', host: '1.1.1.1', port: 443, timeoutMs }),
    tcpConnectProbe({ id: 'direct-dns-tcp', host: '8.8.8.8', port: 53, timeoutMs }),
    tcpConnectProbe({ id: 'dns-over-tls', host: '1.1.1.1', port: 853, timeoutMs }),
    tcpConnectProbe({ id: 'private-rfc1918', host: '10.0.0.1', port: 80, timeoutMs }),
    tcpConnectProbe({
      id: 'link-local-metadata',
      host: '169.254.169.254',
      port: 80,
      timeoutMs,
    }),
    tcpConnectProbe({
      id: 'public-ipv6-https',
      host: '2606:4700:4700::1111',
      port: 443,
      family: 6,
      timeoutMs,
    }),
    udpDnsProbe({ timeoutMs }),
    udpResponseProbe({
      id: 'quic-udp-bypass',
      host: '1.1.1.1',
      port: 443,
      payload: quicVersionProbePayload(),
      timeoutMs,
    }),
    udpResponseProbe({
      id: 'default-deny-udp',
      host: '1.1.1.1',
      port: 12_345,
      payload: Buffer.from('nosh-default-deny-udp'),
      timeoutMs,
    }),
  ]);
  const escaped = probes.filter((probe) => probe.escaped === true);
  const indeterminate = probes.filter((probe) => probe.escaped === null);
  return {
    schemaVersion: 1,
    kind: 'NoshEgressContainmentProbeResult',
    generatedAt: new Date().toISOString(),
    timeoutMs,
    probeCount: probes.length,
    escapedCount: escaped.length,
    indeterminateCount: indeterminate.length,
    passed: escaped.length === 0 && indeterminate.length === 0,
    probes,
    limitations: [
      'This client-side result requires matching complete Guard deny-counter evidence.',
      'It proves the zero-allowlist L3/L4 smoke scope, not L7 behavior through an approved proxy.',
    ],
  };
}

async function main(argv) {
  const options = parseProbeOptions(argv);
  if (options.help) {
    process.stdout.write(usage());
    return 0;
  }
  const result = await runContainmentProbes(options);
  process.stdout.write(`${JSON.stringify(result)}\n`);
  return result.passed ? 0 : 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2))
    .then((status) => {
      process.exitCode = status;
    })
    .catch((error) => {
      process.stderr.write(`nosh-egress-containment-probe: ${error.message}\n`);
      process.exitCode = 2;
    });
}
