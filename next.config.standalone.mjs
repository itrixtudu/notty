import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const cspDirectives = [
  "default-src 'self';",
  "script-src 'self' 'unsafe-eval' blob:;",
  "style-src 'self' 'unsafe-inline';",
  "img-src 'self' data: blob:;",
  "font-src 'self' data:;",
  "connect-src 'self' ws: wss: https: blob:;",
  "worker-src 'self' blob:;",
  "frame-ancestors 'self';",
  "object-src 'none';"
].join(' ');

const polyfillEntry = './lib/polyfills/webxr.js';
const enableWebXRPolyfill = process.env.NEXT_PUBLIC_ENABLE_WEBXR_POLYFILL === 'true';

const nextConfig = {
  reactStrictMode: true,
  allowedDevOrigins: ['172.17.0.*'],
  output: 'standalone',
  transpilePackages: [
    'three',
    '@react-three/fiber',
    '@react-three/drei',
    '@react-three/xr',
    '@react-three/uikit',
    'three-mesh-ui',
    'leva'
  ],
  headers: async () => [
    {
      source: '/(.*)',
      headers: [
        {
          key: 'Content-Security-Policy',
          value: cspDirectives
        },
        {
          key: 'Permissions-Policy',
          value: 'xr-spatial-tracking=(self "https://*")'
        }
      ]
    }
  ],
  webpack: (config, { isServer }) => {
    config.module.rules.push({
      test: /\.(glsl|vs|fs|vert|frag)$/i,
      type: 'asset/source'
    });

    config.resolve.extensions = config.resolve.extensions ?? [];
    config.resolve.extensions.push('.glsl', '.vs', '.fs', '.vert', '.frag');

    if (!isServer) {
      config.resolve.fallback = {
        ...(config.resolve.fallback ?? {}),
        fs: false
      };
    }

    if (enableWebXRPolyfill) {
      const originalEntry = config.entry;

      config.entry = async () => {
        const entries = await originalEntry();

        Object.keys(entries).forEach(key => {
          if (Array.isArray(entries[key]) && !entries[key].includes(polyfillEntry)) {
            entries[key].unshift(polyfillEntry);
          }
        });

        return entries;
      };
    }

    return config;
  },
  turbopack: {
    root: __dirname
  }
};

export default nextConfig;
