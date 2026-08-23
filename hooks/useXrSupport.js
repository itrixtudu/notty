import { useEffect, useMemo, useState } from 'react';

const XR_SUPPORTED_MODES = ['immersive-vr', 'immersive-ar'];
const XR_MODE_MAP = {
  'immersive-vr': 'vr',
  'immersive-ar': 'ar'
};

export default function useXrSupport() {
  const [status, setStatus] = useState({ checking: true, modes: [], error: null });

  useEffect(() => {
    let cancelled = false;

    const detectSupport = async () => {
      if (typeof window === 'undefined' || typeof navigator === 'undefined') {
        return;
      }

      try {
        if (!navigator.xr || typeof navigator.xr.isSessionSupported !== 'function') {
          if (!cancelled) {
            setStatus({ checking: false, modes: [], error: null });
          }
          return;
        }

        const results = await Promise.all(
          XR_SUPPORTED_MODES.map(async candidate => {
            try {
              const supported = await navigator.xr.isSessionSupported(candidate);
              return supported ? XR_MODE_MAP[candidate] : null;
            } catch (err) {
              console.warn(`Failed to query support for ${candidate}`, err);
              return null;
            }
          })
        );

        if (cancelled) {
          return;
        }

        const availableModes = results.filter(Boolean);
        setStatus({ checking: false, modes: availableModes, error: null });
      } catch (error) {
        if (!cancelled) {
          setStatus({ checking: false, modes: [], error });
        }
      }
    };

    detectSupport();

    return () => {
      cancelled = true;
    };
  }, []);

  return useMemo(() => status, [status]);
}
