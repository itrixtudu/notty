import { browserFetch } from './browserRequest.js';

async function responsePayload(response) {
  return response.json().catch(() => ({}));
}

function responseError(response, payload, fallback) {
  const message = payload?.error?.message
    || payload?.error
    || response.statusText
    || fallback;
  const error = new Error(message);
  error.code = payload?.error?.code || 'terminal_spawn_failed';
  error.statusCode = response.status;
  return error;
}

export async function browserSpawnOtpRequired() {
  try {
    const response = await browserFetch('/api/spawn-otps', {
      cache: 'no-store',
      headers: { Accept: 'application/json' }
    });
    const payload = await responsePayload(response);
    if (!response.ok) {
      return true;
    }
    return payload.enabled !== false;
  } catch {
    // A failed status probe must never silently turn OTP enforcement off.
    return true;
  }
}

export async function spawnBrowserTerminal(options = {}, otp = '') {
  const source = options && typeof options === 'object' && !Array.isArray(options)
    ? options
    : {};
  const { otp: _discardedOtp, ...terminalOptions } = source;
  const value = typeof otp === 'string' ? otp.trim() : '';
  const response = await browserFetch('/api/terminals', {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      ...terminalOptions,
      ...(value ? { otp: value } : {})
    })
  });
  const payload = await responsePayload(response);
  if (!response.ok) {
    throw responseError(response, payload, 'Unable to create terminal session');
  }
  return payload;
}

function hasTerminalUuid(args) {
  return (
    typeof args?.terminal_uuid === 'string'
    && Boolean(args.terminal_uuid.trim())
  ) || (
    typeof args?.terminalUuid === 'string'
    && Boolean(args.terminalUuid.trim())
  );
}

export function mcpToolRequiresSpawnOtp(tool, args = {}) {
  const properties = tool?.inputSchema?.properties;
  if (!properties || !Object.prototype.hasOwnProperty.call(properties, 'otp')) {
    return false;
  }

  // Simplified run_command creates a terminal only when no UUID is supplied.
  // While OTP protection is enabled, numeric terminal ids are deliberately not
  // accepted as a reusable terminal reference.
  if (tool?.name === 'run_command' && hasTerminalUuid(args)) {
    return false;
  }

  return true;
}

export function prepareMcpToolArguments(tool, args = {}, otp = '') {
  const source = args && typeof args === 'object' && !Array.isArray(args)
    ? args
    : {};
  const { otp: _discardedOtp, ...toolArguments } = source;
  const value = typeof otp === 'string' ? otp.trim() : '';

  if (!mcpToolRequiresSpawnOtp(tool, toolArguments) || !value) {
    return toolArguments;
  }

  return { ...toolArguments, otp: value };
}
