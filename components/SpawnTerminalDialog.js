import { useEffect, useRef, useState } from 'react';

export default function SpawnTerminalDialog({
  open,
  busy = false,
  error = '',
  title = 'Spawn terminal',
  actionLabel = 'Spawn terminal',
  onSubmit,
  onCancel
}) {
  const [otp, setOtp] = useState('');
  const inputRef = useRef(null);

  useEffect(() => {
    if (!open) {
      setOtp('');
      return undefined;
    }

    setOtp('');
    const focusTimer = window.setTimeout(() => inputRef.current?.focus(), 0);
    const handleKeyDown = (event) => {
      if (event.key === 'Escape' && !busy) {
        event.preventDefault();
        onCancel?.();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.clearTimeout(focusTimer);
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [busy, onCancel, open]);

  if (!open) {
    return null;
  }

  const handleSubmit = async (event) => {
    event.preventDefault();
    const value = otp.trim();
    if (!value || busy) {
      return;
    }
    try {
      await onSubmit?.(value);
    } finally {
      // Do not retain a submitted capability, including after a failed attempt.
      setOtp('');
    }
  };

  return (
    <div
      className="control-overlay terminal-spawn-otp-overlay"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !busy) {
          onCancel?.();
        }
      }}
    >
      <form
        className="control-panel terminal-spawn-otp-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="terminal-spawn-otp-title"
        onSubmit={handleSubmit}
      >
        <div className="control-panel-header">
          <div>
            <h2 id="terminal-spawn-otp-title">{title}</h2>
            <p>Enter a fresh one-time OTP from the local Nosh launcher.</p>
          </div>
          <button
            type="button"
            className="icon-button"
            onClick={onCancel}
            disabled={busy}
            aria-label="Cancel terminal spawn"
          >
            <span aria-hidden="true">×</span>
          </button>
        </div>
        <div className="control-panel-body">
          <label>
            One-time OTP
            <input
              ref={inputRef}
              type="text"
              inputMode="text"
              autoCapitalize="none"
              autoComplete="off"
              autoCorrect="off"
              spellCheck={false}
              value={otp}
              onChange={(event) => setOtp(event.target.value)}
              disabled={busy}
            />
          </label>
          {error ? <div className="error" role="alert">{error}</div> : null}
          <div className="row">
            <button type="submit" disabled={busy || !otp.trim()}>
              {busy ? 'Submitting…' : actionLabel}
            </button>
            <button type="button" className="secondary" onClick={onCancel} disabled={busy}>
              Cancel
            </button>
          </div>
          <p className="hint">The OTP is sent only in this spawn request and cleared after every attempt.</p>
        </div>
      </form>
    </div>
  );
}
