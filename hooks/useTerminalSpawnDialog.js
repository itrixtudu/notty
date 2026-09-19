import { useCallback, useEffect, useRef, useState } from 'react';
import {
  browserSpawnOtpRequired,
  spawnBrowserTerminal
} from '../lib/browserTerminalSpawn.js';

export default function useTerminalSpawnDialog() {
  const [pending, setPending] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const resolverRef = useRef(null);
  const requestActiveRef = useRef(false);

  const finish = useCallback((value) => {
    const resolve = resolverRef.current;
    resolverRef.current = null;
    requestActiveRef.current = false;
    setPending(null);
    setSubmitting(false);
    setError('');
    resolve?.(value);
  }, []);

  const beginOtpRequest = useCallback((attempt) => {
    requestActiveRef.current = true;
    return new Promise((resolve) => {
      resolverRef.current = resolve;
      setError('');
      setPending({ attempt });
    });
  }, []);

  const requestSpawnOtp = useCallback(async (attempt) => {
    if (typeof attempt !== 'function') {
      throw new TypeError('A terminal spawn OTP request requires an attempt function.');
    }
    if (requestActiveRef.current) {
      throw new Error('A terminal spawn request is already waiting for an OTP.');
    }
    requestActiveRef.current = true;
    if (!await browserSpawnOtpRequired()) {
      try {
        return await attempt('');
      } finally {
        requestActiveRef.current = false;
      }
    }
    return beginOtpRequest(attempt);
  }, [beginOtpRequest]);

  const requestTerminalSpawn = useCallback(async (options = {}) => {
    if (requestActiveRef.current) {
      throw new Error('A terminal spawn request is already waiting for an OTP.');
    }
    requestActiveRef.current = true;
    const source = options && typeof options === 'object' && !Array.isArray(options)
      ? options
      : {};
    const { otp: _discardedOtp, ...terminalOptions } = source;

    if (!await browserSpawnOtpRequired()) {
      try {
        return await spawnBrowserTerminal(terminalOptions);
      } finally {
        requestActiveRef.current = false;
      }
    }

    return beginOtpRequest((otp) => spawnBrowserTerminal(terminalOptions, otp));
  }, [beginOtpRequest]);

  const submit = useCallback(async (otp) => {
    if (!pending || submitting) {
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      const result = await pending.attempt(otp);
      finish(result);
    } catch (spawnError) {
      setError(spawnError instanceof Error ? spawnError.message : 'Unable to create terminal session');
      setSubmitting(false);
    }
  }, [finish, pending, submitting]);

  const cancel = useCallback(() => {
    if (!submitting) {
      finish(null);
    }
  }, [finish, submitting]);

  useEffect(() => () => {
    resolverRef.current?.(null);
    resolverRef.current = null;
    requestActiveRef.current = false;
  }, []);

  return {
    requestSpawnOtp,
    requestTerminalSpawn,
    spawnDialogProps: {
      open: Boolean(pending),
      busy: submitting,
      error,
      onSubmit: submit,
      onCancel: cancel
    }
  };
}
