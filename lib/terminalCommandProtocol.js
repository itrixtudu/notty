const OSC_PREFIX = '\x1b]6973;notty-command;';
const BEL = '\x07';
const ST = '\x1b\\';
const MAX_MARKER_LENGTH = 64 * 1024;

const ALTERNATE_SCREEN_SEQUENCES = [
  { sequence: '\x1b[?1049h', active: true },
  { sequence: '\x1b[?1049l', active: false },
  { sequence: '\x1b[?1047h', active: true },
  { sequence: '\x1b[?1047l', active: false },
  { sequence: '\x1b[?47h', active: true },
  { sequence: '\x1b[?47l', active: false }
];

export const TERMINAL_COMMAND_OSC_PREFIX = OSC_PREFIX;

function encodeHex(value) {
  return Buffer.from(String(value ?? ''), 'utf8').toString('hex');
}

function decodeHex(value) {
  if (!value) {
    return '';
  }
  if (!/^(?:[0-9a-f]{2})+$/i.test(value)) {
    return null;
  }
  return Buffer.from(value, 'hex').toString('utf8');
}

function normalizeMarkerType(value) {
  return ['prompt', 'start', 'complete'].includes(value) ? value : null;
}

export function encodeTerminalCommandMarker(event = {}, options = {}) {
  const type = normalizeMarkerType(event.type);
  if (!type) {
    throw new Error('Terminal command marker type must be prompt, start, or complete');
  }

  const commandId = String(event.commandId ?? '');
  const exitCode = event.exitCode === null || event.exitCode === undefined
    ? ''
    : String(event.exitCode);
  const nonce = String(options.nonce ?? event.nonce ?? '');
  if (!/^[A-Za-z0-9_-]{1,160}$/.test(nonce)) {
    throw new Error('Terminal command marker nonce is invalid');
  }
  const payload = [
    '2',
    nonce,
    type,
    commandId,
    exitCode,
    encodeHex(event.cwd),
    encodeHex(event.command)
  ].join(';');
  const terminator = options.terminator === 'st' ? ST : BEL;
  return `${OSC_PREFIX}${payload}${terminator}`;
}

export function parseTerminalCommandMarker(payload, options = {}) {
  const rawPayload = String(payload ?? '');
  if (rawPayload.length > MAX_MARKER_LENGTH) {
    return null;
  }
  const fields = rawPayload.split(';');
  if (fields.length !== 7 || fields[0] !== '2') {
    return null;
  }

  const nonce = fields[1];
  const expectedNonce = options.expectedNonce;
  if (
    !/^[A-Za-z0-9_-]{1,160}$/.test(nonce)
    || (typeof expectedNonce === 'string' && nonce !== expectedNonce)
  ) {
    return null;
  }

  const type = normalizeMarkerType(fields[2]);
  if (!type || !/^[A-Za-z0-9_.:-]{0,160}$/.test(fields[3])) {
    return null;
  }

  let exitCode = null;
  if (fields[4] !== '') {
    if (!/^-?\d+$/.test(fields[4])) {
      return null;
    }
    exitCode = Number.parseInt(fields[4], 10);
    if (!Number.isSafeInteger(exitCode)) {
      return null;
    }
  }

  if (type === 'complete' && exitCode === null) {
    return null;
  }
  if ((type === 'start' || type === 'complete') && !fields[3]) {
    return null;
  }

  const cwd = decodeHex(fields[5]);
  const command = decodeHex(fields[6]);
  if (cwd === null || command === null) {
    return null;
  }

  return {
    version: 2,
    type,
    commandId: fields[3] || null,
    exitCode,
    cwd: cwd || null,
    command
  };
}

function suffixPrefixLength(value, target) {
  const maxLength = Math.min(value.length, target.length - 1);
  for (let length = maxLength; length > 0; length -= 1) {
    if (value.endsWith(target.slice(0, length))) {
      return length;
    }
  }
  return 0;
}

function markerTerminatorIndex(value) {
  const belIndex = value.indexOf(BEL);
  const stIndex = value.indexOf(ST);
  if (belIndex === -1) {
    return stIndex === -1 ? null : { index: stIndex, length: ST.length };
  }
  if (stIndex === -1 || belIndex < stIndex) {
    return { index: belIndex, length: BEL.length };
  }
  return { index: stIndex, length: ST.length };
}

export function createTerminalOutputParser(options = {}) {
  const onCommandMarker = typeof options.onCommandMarker === 'function'
    ? options.onCommandMarker
    : () => {};
  const onAlternateScreen = typeof options.onAlternateScreen === 'function'
    ? options.onAlternateScreen
    : () => {};
  const markerNonce = typeof options.markerNonce === 'string'
    && /^[A-Za-z0-9_-]{1,160}$/.test(options.markerNonce)
    ? options.markerNonce
    : null;
  let markerPending = '';
  let alternatePending = '';
  let alternateScreen = false;

  const inspectAlternateScreen = (visibleData) => {
    const combined = alternatePending + visibleData;
    const matches = [];
    for (const candidate of ALTERNATE_SCREEN_SEQUENCES) {
      let index = combined.indexOf(candidate.sequence);
      while (index !== -1) {
        matches.push({ index, active: candidate.active });
        index = combined.indexOf(candidate.sequence, index + candidate.sequence.length);
      }
    }
    matches.sort((left, right) => left.index - right.index);
    for (const match of matches) {
      if (alternateScreen !== match.active) {
        alternateScreen = match.active;
        onAlternateScreen(alternateScreen);
      }
    }

    let keepLength = 0;
    for (const candidate of ALTERNATE_SCREEN_SEQUENCES) {
      keepLength = Math.max(keepLength, suffixPrefixLength(combined, candidate.sequence));
    }
    alternatePending = keepLength ? combined.slice(-keepLength) : '';
  };

  const push = (chunk) => {
    let input = markerPending + String(chunk ?? '');
    markerPending = '';
    let visible = '';

    while (input) {
      const prefixIndex = input.indexOf(OSC_PREFIX);
      if (prefixIndex === -1) {
        const keepLength = suffixPrefixLength(input, OSC_PREFIX);
        if (keepLength) {
          visible += input.slice(0, -keepLength);
          markerPending = input.slice(-keepLength);
        } else {
          visible += input;
        }
        break;
      }

      visible += input.slice(0, prefixIndex);
      const markerBody = input.slice(prefixIndex + OSC_PREFIX.length);
      const terminator = markerTerminatorIndex(markerBody);
      if (!terminator) {
        if (markerBody.length > MAX_MARKER_LENGTH) {
          visible += OSC_PREFIX;
          input = markerBody;
          continue;
        }
        markerPending = input.slice(prefixIndex);
        break;
      }

      const payload = markerBody.slice(0, terminator.index);
      const marker = markerNonce && payload.length <= MAX_MARKER_LENGTH
        ? parseTerminalCommandMarker(payload, { expectedNonce: markerNonce })
        : null;
      if (marker) {
        onCommandMarker(marker);
      }
      input = markerBody.slice(terminator.index + terminator.length);
    }

    if (visible) {
      inspectAlternateScreen(visible);
    }
    return visible;
  };

  const flush = () => {
    const remainder = markerPending;
    markerPending = '';
    if (remainder) {
      inspectAlternateScreen(remainder);
    }
    return remainder;
  };

  return {
    push,
    flush,
    getState() {
      return {
        alternateScreen,
        pendingMarkerBytes: markerPending.length
      };
    }
  };
}
