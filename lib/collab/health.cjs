'use strict';

const RATE_LIMIT_PATTERNS = Object.freeze([
  /\brate[ _-]?limit(?:ed|ing)?\b/i,
  /\btoo many requests\b/i,
  /(?:^|\D)429(?:\D|$)/,
  /\bquota (?:has been )?(?:exceeded|exhausted)\b/i,
  /\bresource exhausted\b/i,
  /\bcapacity (?:limit|exceeded|unavailable)\b/i,
  /\btemporarily overloaded\b/i,
]);

function parseRetryAt(text, now = Date.now()) {
  const source = String(text || '');
  const duration = source.match(/retry(?:ing)?\s+(?:after|in)\s+(\d+(?:\.\d+)?)\s*(ms|milliseconds?|s|sec(?:ond)?s?|m|min(?:ute)?s?)/i);
  if (duration) {
    const amount = Number(duration[1]);
    const unit = duration[2].toLowerCase();
    const multiplier = unit.startsWith('m') && !unit.startsWith('ms') ? 60_000
      : unit.startsWith('ms') ? 1
        : 1_000;
    return new Date(now + amount * multiplier).toISOString();
  }
  const absolute = source.match(/retry(?:ing)?\s+(?:at|after)\s+((?:20\d\d-\d\d-\d\d|[A-Z][a-z]{2},)[^\r\n.;]*)/i);
  if (absolute) {
    const parsed = Date.parse(absolute[1].trim());
    if (Number.isFinite(parsed) && parsed > now) return new Date(parsed).toISOString();
  }
  return '';
}

function classifyAgentHealth(text, options = {}) {
  const source = String(text || '');
  if (!source || !RATE_LIMIT_PATTERNS.some((pattern) => pattern.test(source))) return null;
  const normalized = source.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '').replace(/\s+/g, ' ').trim();
  return {
    code: 'rate-limited',
    message: 'Agent model runtime reported a rate limit.',
    source: options.source || 'automatic',
    retryAt: parseRetryAt(normalized, options.now),
    updatedAt: new Date(options.now || Date.now()).toISOString(),
  };
}

function normalizeHealthOverride(input = {}, now = Date.now()) {
  const code = input.code === null || input.code === '' || input.code === 'clear'
    ? ''
    : String(input.code || '').trim().toLowerCase();
  if (!code) {
    return {
      code: '',
      message: 'Operator cleared the rate-limit status for this session.',
      source: 'operator',
      cleared: true,
      retryAt: '',
      updatedAt: new Date(now).toISOString(),
    };
  }
  if (code !== 'rate-limited') {
    throw new Error('health code must be rate-limited or null');
  }
  const message = String(input.message || 'Operator marked this agent as rate limited.').trim();
  return {
    code,
    message: message.slice(0, 240),
    source: 'operator',
    retryAt: '',
    updatedAt: new Date(now).toISOString(),
  };
}

module.exports = {
  RATE_LIMIT_PATTERNS,
  classifyAgentHealth,
  normalizeHealthOverride,
  parseRetryAt,
};
