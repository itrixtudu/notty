import WebXRPolyfill from 'webxr-polyfill';

const enablePolyfill = process.env.NEXT_PUBLIC_ENABLE_WEBXR_POLYFILL === 'true';

if (
  enablePolyfill &&
  typeof window !== 'undefined' &&
  typeof navigator !== 'undefined' &&
  (!('xr' in navigator) || !navigator.xr)
) {
  // eslint-disable-next-line no-new
  new WebXRPolyfill({
    allowCardboardOnDesktop: true,
    cardboardConfig: {
      SUPPORTED: true
    }
  });
}
