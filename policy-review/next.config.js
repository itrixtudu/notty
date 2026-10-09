const { isIP } = require('node:net');

const DEFAULT_ALLOWED_DEV_ORIGINS = ['localhost', '127.0.0.1', '[::1]'];
const HOST_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

const isExactHostname = value => (
  value.length <= 253
  && !/^[0-9.]+$/.test(value)
  && value.split('.').every(label => HOST_LABEL_PATTERN.test(label))
);

const configuredAllowedDevOrigins = String(process.env.NOTTY_ALLOWED_DEV_ORIGINS || '')
  .split(',')
  .map(value => value.trim().toLowerCase())
  .filter(Boolean)
  .map(value => {
    const bracketedIpv6 = value.startsWith('[') && value.endsWith(']')
      ? value.slice(1, -1)
      : null;
    if (
      isIP(value) !== 4
      && !(bracketedIpv6 && isIP(bracketedIpv6) === 6)
      && !isExactHostname(value)
    ) {
      throw new Error(
        'NOTTY_ALLOWED_DEV_ORIGINS must contain comma-separated exact hostnames or IP addresses',
      );
    }
    return value;
  });

const POLICY_REVIEW_RESPONSE_HEADERS = Object.freeze([
  { key: 'Cache-Control', value: 'no-store' },
  { key: 'Referrer-Policy', value: 'no-referrer' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
]);

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  allowedDevOrigins: [...new Set([
    ...DEFAULT_ALLOWED_DEV_ORIGINS,
    ...configuredAllowedDevOrigins,
  ])],
  async headers() {
    return ['/policy-review', '/tool-review', '/setup'].map(source => ({
      source,
      headers: POLICY_REVIEW_RESPONSE_HEADERS,
    }));
  },
  turbopack: {
    root: __dirname,
  },
};

module.exports = nextConfig;
