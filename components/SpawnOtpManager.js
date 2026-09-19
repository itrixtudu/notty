import { Fragment, useCallback, useEffect, useId, useRef, useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { browserFetch } from '../lib/browserRequest.js';
import { spawnOtpHistory } from '../lib/spawnOtpHistory.js';
import {
  formatOtpRemaining,
  otpClockNow,
  otpDisplayStatus,
  otpRemainingSeconds
} from '../lib/spawnOtpCountdown.js';

const defaultForm = {
  value: '',
  ttlSeconds: ''
};

async function jsonFetch(url, options) {
  const response = await browserFetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.error?.message || payload.error || response.statusText);
  }

  return response.json();
}

function formatTimestamp(value) {
  if (value === null || value === undefined || value === '') {
    return 'Never';
  }

  try {
    const date = new Date(value);
    return Number.isFinite(date.getTime()) ? date.toLocaleString() : 'Unknown';
  } catch {
    return 'Invalid date';
  }
}

function getStatusLabel(status) {
  if (status === 'used') {
    return 'Used';
  }
  if (status === 'expired') {
    return 'Expired';
  }
  if (status === 'revoked') {
    return 'Revoked';
  }
  return 'Available';
}

function getSourceLabel(source) {
  if (source === 'env') {
    return 'Launcher';
  }
  if (source === 'operator-cli') {
    return 'Operator CLI';
  }
  if (source === 'guard-operator') {
    return 'Guard operator';
  }
  return 'UI';
}

function OtpTable({ records, now, label }) {
  const [expanded, setExpanded] = useState(() => new Set());
  const tableId = useId();
  return (
    <div className="otp-table-scroll" role="region" aria-label={label} tabIndex={0}>
      <table className="otp-table" aria-label={label}>
        <thead>
          <tr>
            {['History', 'Record ID', 'Status', 'Remaining', 'TTL', 'Source', 'Created', 'Expires', 'Used'].map((column) => (
              <th key={column} scope="col">{column}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {records.map((otp) => {
            const status = otpDisplayStatus(otp, now);
            const historyId = `${tableId}-${otp.uuid}`;
            return (
              <Fragment key={otp.uuid}>
              <tr>
                <td><button type="button" className="secondary" aria-expanded={expanded.has(otp.uuid)}
                  aria-controls={expanded.has(otp.uuid) ? historyId : undefined}
                  aria-label={`${expanded.has(otp.uuid) ? 'Hide' : 'Show'} lifecycle history for ${otp.uuid}`}
                  onClick={() => setExpanded((current) => {
                    const next = new Set(current);
                    if (next.has(otp.uuid)) next.delete(otp.uuid); else next.add(otp.uuid);
                    return next;
                  })}>{expanded.has(otp.uuid) ? 'Hide' : 'History'}</button></td>
                <th scope="row"><code>{otp.uuid}</code></th>
                <td><span className={`otp-status otp-status-${status}`}>{getStatusLabel(status)}</span></td>
                <td className="otp-table-countdown">{formatOtpRemaining(otp, now)}</td>
                <td>{otp.ttlSeconds == null ? 'No expiry' : `${otp.ttlSeconds}s`}</td>
                <td>{getSourceLabel(otp.source)}</td>
                <td>{formatTimestamp(otp.createdAt)}</td>
                <td>{otp.expiresAt == null ? 'No expiry' : formatTimestamp(otp.expiresAt)}</td>
                <td>{otp.usedAt == null ? '—' : formatTimestamp(otp.usedAt)}</td>
              </tr>
              {expanded.has(otp.uuid) && <tr id={historyId} className="otp-history-row"><td colSpan={9}>
                <table className="otp-lifecycle-table" aria-label={`Lifecycle history for ${otp.uuid}`}>
                  <thead><tr><th scope="col">Time</th><th scope="col">Event</th><th scope="col">Details</th></tr></thead>
                  <tbody>{spawnOtpHistory(otp, now).map((entry) => <tr key={entry.event}>
                    <td>{formatTimestamp(entry.time)}</td><th scope="row">{entry.event}</th><td>{entry.details}</td>
                  </tr>)}</tbody>
                </table>
                <p className="hint">Lifecycle metadata only; terminal output and command history are not archived.</p>
              </td></tr>}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default function SpawnOtpManager({ open = false, onClose }) {
  const [dashboard, setDashboard] = useState(null);
  const [form, setForm] = useState(defaultForm);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState('');
  const [revealedOtp, setRevealedOtp] = useState(null);
  const [copyStatus, setCopyStatus] = useState('');
  const [now, setNow] = useState(() => Date.now());
  const reconcilingRef = useRef(new Set());
  const dialogRef = useRef(null);
  const clockRef = useRef(null);
  const requestRevisionRef = useRef(0);
  const creatingRef = useRef(false);
  const acceptDashboard = useCallback((data) => {
    clockRef.current = { serverTime: data.serverTime, elapsedAt: performance.now() };
    setNow(otpClockNow(clockRef.current, performance.now()));
    setDashboard(data);
    setLoading(false);
  }, []);

  useEffect(() => {
    setCopyStatus('');
  }, [revealedOtp]);

  const copyOtp = async () => {
    if (!revealedOtp?.value) return;
    try {
      if (window.isSecureContext && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(revealedOtp.value);
      } else {
        // HTTP container addresses may not expose the Clipboard API.
        const previousFocus = document.activeElement;
        const input = document.createElement('textarea');
        input.value = revealedOtp.value;
        input.style.position = 'fixed';
        input.style.opacity = '0';
        dialogRef.current.appendChild(input);
        try {
          input.select();
          if (!document.execCommand('copy')) throw new Error('Copy failed');
        } finally {
          input.value = '';
          input.remove();
          previousFocus?.focus();
        }
      }
      setCopyStatus('Copied');
    } catch {
      setCopyStatus('Unable to copy automatically. Select the code and copy it manually.');
    }
  };

  const loadOtps = useCallback(async ({ quiet = false, clearReveal = true } = {}) => {
    if (quiet && creatingRef.current) return false;
    const revision = ++requestRevisionRef.current;
    if (!quiet) {
      setLoading(true);
    }
    setError('');
    if (clearReveal) {
      setRevealedOtp(null);
    }
    try {
      const data = await jsonFetch('/api/spawn-otps');
      if (revision !== requestRevisionRef.current) return false;
      acceptDashboard(data);
      return true;
    } catch (err) {
      if (revision === requestRevisionRef.current) setError(err.message);
      return false;
    } finally {
      if (revision === requestRevisionRef.current) {
        setLoading(false);
      }
    }
  }, [acceptDashboard]);

  useEffect(() => {
    if (!open) {
      setRevealedOtp(null);
      setForm(defaultForm);
      return undefined;
    }
    loadOtps();
    const poll = window.setInterval(() => {
      loadOtps({ quiet: true, clearReveal: false });
    }, 15_000);
    return () => {
      window.clearInterval(poll);
      requestRevisionRef.current += 1;
    };
  }, [loadOtps, open]);

  useEffect(() => {
    if (!open) return undefined;
    const updateClock = () => setNow(otpClockNow(clockRef.current, performance.now()));
    const timer = window.setInterval(updateClock, 1_000);
    const handleVisibility = () => {
      if (document.visibilityState === 'visible') {
        updateClock();
        loadOtps({ quiet: true, clearReveal: false });
      }
    };
    document.addEventListener('visibilitychange', handleVisibility);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener('visibilitychange', handleVisibility);
    };
  }, [loadOtps, open]);

  useEffect(() => {
    if (!open) {
      return undefined;
    }
    const previouslyFocused = document.activeElement;
    dialogRef.current?.focus();
    const handleKeydown = (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onClose?.();
        return;
      }
      if (event.key !== 'Tab' || !dialogRef.current) {
        return;
      }
      const focusable = Array.from(dialogRef.current.querySelectorAll(
        'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      )).filter((element) => element.getClientRects().length > 0);
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!first || !last) {
        event.preventDefault();
        dialogRef.current.focus();
      } else if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener('keydown', handleKeydown);
    return () => {
      window.removeEventListener('keydown', handleKeydown);
      if (previouslyFocused instanceof HTMLElement && previouslyFocused.isConnected) {
        window.requestAnimationFrame(() => previouslyFocused.focus());
      }
    };
  }, [onClose, open]);

  const updateForm = useCallback((field, value) => {
    setForm((current) => ({ ...current, [field]: value }));
  }, []);

  const handleCreate = useCallback(async (event) => {
    event.preventDefault();
    if (creatingRef.current) {
      return;
    }

    setCreating(true);
    creatingRef.current = true;
    const revision = ++requestRevisionRef.current;
    setError('');
    try {
      const payload = {};
      if (form.value.trim()) {
        payload.value = form.value.trim();
      }
      if (form.ttlSeconds.trim()) {
        payload.ttlSeconds = Number(form.ttlSeconds);
      }

      const data = await jsonFetch('/api/spawn-otps', {
        method: 'POST',
        body: JSON.stringify(payload)
      });

      if (revision !== requestRevisionRef.current) return;
      acceptDashboard(data.dashboard);
      setRevealedOtp(data.otp);
      setForm(defaultForm);
    } catch (err) {
      if (revision === requestRevisionRef.current) setError(err.message);
    } finally {
      creatingRef.current = false;
      setCreating(false);
    }
  }, [acceptDashboard, creating, form]);

  const available = dashboard?.available || [];
  const history = dashboard?.history || [];
  const used = history.filter((otp) => otp.status === 'used');
  const expired = history.filter((otp) => otp.status === 'expired');
  const revoked = history.filter((otp) => otp.status === 'revoked');
  const defaultTtlSeconds = dashboard?.defaultTtlSeconds ?? null;
  const summaryLabel = loading
    ? 'Loading OTP state'
    : dashboard?.enabled
      ? `${available.length} available`
      : 'OTP protection idle';

  useEffect(() => {
    if (!open) return;
    const availableIds = new Set(available.map((otp) => otp.uuid));
    for (const id of reconcilingRef.current) {
      if (!availableIds.has(id)) reconcilingRef.current.delete(id);
    }
    const expiredIds = available
      .filter((otp) => otpRemainingSeconds(otp, now) === 0)
      .map((otp) => otp.uuid)
      .filter((uuid) => !reconcilingRef.current.has(uuid));
    if (!expiredIds.length) {
      return;
    }
    expiredIds.forEach((uuid) => reconcilingRef.current.add(uuid));
    loadOtps({ quiet: true, clearReveal: false }).then((success) => {
      if (!success) {
        expiredIds.forEach((uuid) => reconcilingRef.current.delete(uuid));
      }
    });
  }, [available, loadOtps, now, open]);

  return (
    <>
      {open && (
        <div
          className="control-overlay otp-manager-overlay"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) {
              onClose?.();
            }
          }}
        >
          <section
            ref={dialogRef}
            className="control-panel otp-manager-panel"
            role="dialog"
            aria-modal="true"
            aria-labelledby="otp-manager-title"
            tabIndex={-1}
          >
            <div className="control-panel-header">
              <div>
                <h2 id="otp-manager-title">Spawn OTP Management</h2>
                <p>Issue and review one-time terminal-spawn capabilities.</p>
              </div>
              <button
                type="button"
                className="icon-button"
                onClick={onClose}
                aria-label="Close OTP management"
              >
                <span aria-hidden="true">×</span>
              </button>
            </div>
            <div className="control-panel-body">
    <section className="card">
      <div className="card-header">
        <div>
          <h3>OTP Tokens</h3>
          <p>Issue single-use terminal spawn OTPs and review available tokens, used tokens, TTLs, and UUIDs.</p>
        </div>
        <button type="button" className="secondary" onClick={() => loadOtps()} disabled={loading || creating}
          title="Reload token status from the server; this also dismisses any newly revealed code">
          {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      {dashboard?.mintingEnabled === true ? (
        <form className="otp-create-form" onSubmit={handleCreate}>
          <label>
            OTP Value
            <input
              type="text"
              autoCapitalize="none"
              autoComplete="off"
              autoCorrect="off"
              spellCheck={false}
              placeholder="Leave blank to auto-generate"
              value={form.value}
              onChange={(event) => updateForm('value', event.target.value)}
            />
          </label>

          <div className="row">
            <label>
              TTL Seconds
              <input
                type="number"
                min="1"
                step="1"
                placeholder={
                  defaultTtlSeconds === null
                    ? 'No default expiry'
                    : `${defaultTtlSeconds}`
                }
                value={form.ttlSeconds}
                onChange={(event) => updateForm('ttlSeconds', event.target.value)}
              />
            </label>
            <button type="submit" disabled={creating}>
              {creating ? 'Creating…' : 'Create OTP'}
            </button>
          </div>
        </form>
      ) : dashboard ? (
        <p className="hint">
          {dashboard.enabled
            ? 'HTTP OTP minting is disabled in OTP-only mode. Use the launcher OTP or run nosh auth otp locally.'
            : 'Terminal spawn OTP enforcement is disabled for this server.'}
        </p>
      ) : null}

      {revealedOtp?.value && (
        <div className="otp-create-form" role="status">
          <strong>New OTP — shown once</strong>
          <div className="otp-copy-row">
            <code className="otp-entry-value">{revealedOtp.value}</code>
            <button
              type="button"
              className="secondary"
              onClick={copyOtp}
              aria-label={copyStatus === 'Copied' ? 'OTP copied' : 'Copy OTP code'}
              title={copyStatus === 'Copied' ? 'Copied' : 'Copy OTP code'}
            >
              {copyStatus === 'Copied'
                ? <Check size={18} aria-hidden="true" />
                : <Copy size={18} aria-hidden="true" />}
            </button>
          </div>
          <span role="status">{copyStatus}</span>
          <button type="button" className="secondary" onClick={() => setRevealedOtp(null)}>
            Dismiss
          </button>
        </div>
      )}

      <div className="otp-summary">
        <span className={`otp-pill ${dashboard?.enabled ? 'otp-pill-active' : 'otp-pill-idle'}`}>
          {summaryLabel}
        </span>
        <span className="status-note">{used.length} used</span>
        <span className="status-note">{expired.length} expired</span>
        <span className="status-note">{revoked.length} revoked</span>
        <span className="status-note">
          Default TTL {defaultTtlSeconds === null ? 'disabled' : `${defaultTtlSeconds}s`}
        </span>
      </div>

      <p className="hint">
        Tokens are single-use. Values are shown only when created; dashboard entries expose UUIDs and lifecycle timestamps, never reusable plaintext.
      </p>

      {error && (
        <div className="error" role="alert">
          {error}
        </div>
      )}

      <div className="otp-section">
        <div className="otp-section-header">
          <h4>Available Tokens</h4>
          <span>{available.length}</span>
        </div>
        {available.length ? (
          <OtpTable records={available} now={now} label="Available OTP tokens" />
        ) : (
          <p className="hint">No unused OTPs are currently available.</p>
        )}
      </div>

      <div className="otp-section">
        <div className="otp-section-header">
          <h4>Used, Expired, And Revoked Tokens</h4>
          <span>{history.length}</span>
        </div>
        {history.length ? (
          <OtpTable records={history} now={now} label="OTP token history" />
        ) : (
          <p className="hint">Used, expired, and revoked OTP records will appear here as their lifecycle changes.</p>
        )}
      </div>
    </section>
            </div>
          </section>
        </div>
      )}
    </>
  );
}
