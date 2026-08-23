import { useCallback, useEffect, useState } from 'react';
import { browserFetch } from '../lib/browserRequest.js';

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
    throw new Error(payload.error || response.statusText);
  }

  return response.json();
}

function formatTimestamp(value) {
  if (!value) {
    return 'Never';
  }

  try {
    return new Date(value).toLocaleString();
  } catch {
    return 'Invalid date';
  }
}

function formatTtl(otp) {
  if (otp.ttlSeconds === null) {
    return 'No expiry';
  }
  if (otp.status === 'available') {
    return `${otp.ttlSeconds}s (${otp.remainingSeconds}s left)`;
  }
  return `${otp.ttlSeconds}s`;
}

function getStatusLabel(status) {
  if (status === 'used') {
    return 'Used';
  }
  if (status === 'expired') {
    return 'Expired';
  }
  return 'Available';
}

function OtpEntry({ otp }) {
  return (
    <article className={`otp-entry otp-entry-${otp.status}`}>
      <div className="otp-entry-header">
        <div className="otp-entry-value-block">
          <span className="otp-entry-label">OTP Value</span>
          <code className="otp-entry-value">{otp.value}</code>
        </div>
        <span className={`otp-status otp-status-${otp.status}`}>{getStatusLabel(otp.status)}</span>
      </div>

      <dl className="otp-entry-grid">
        <div>
          <dt>UUID</dt>
          <dd>{otp.uuid}</dd>
        </div>
        <div>
          <dt>TTL</dt>
          <dd>{formatTtl(otp)}</dd>
        </div>
        <div>
          <dt>Created</dt>
          <dd>{formatTimestamp(otp.createdAt)}</dd>
        </div>
        <div>
          <dt>Source</dt>
          <dd>{otp.source === 'env' ? 'Environment' : 'UI'}</dd>
        </div>
        <div>
          <dt>Used</dt>
          <dd>{formatTimestamp(otp.usedAt)}</dd>
        </div>
        <div>
          <dt>Expires</dt>
          <dd>{otp.expiresAt ? formatTimestamp(otp.expiresAt) : 'No expiry'}</dd>
        </div>
      </dl>
    </article>
  );
}

export default function SpawnOtpManager() {
  const [dashboard, setDashboard] = useState(null);
  const [form, setForm] = useState(defaultForm);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState('');

  const loadOtps = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await jsonFetch('/api/spawn-otps');
      setDashboard(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadOtps();
  }, [loadOtps]);

  const updateForm = useCallback((field, value) => {
    setForm((current) => ({ ...current, [field]: value }));
  }, []);

  const handleCreate = useCallback(async (event) => {
    event.preventDefault();
    if (creating) {
      return;
    }

    setCreating(true);
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

      setDashboard(data.dashboard);
      setForm(defaultForm);
    } catch (err) {
      setError(err.message);
    } finally {
      setCreating(false);
    }
  }, [creating, form]);

  const available = dashboard?.available || [];
  const history = dashboard?.history || [];
  const used = history.filter((otp) => otp.status === 'used');
  const expired = history.filter((otp) => otp.status === 'expired');
  const defaultTtlSeconds = dashboard?.defaultTtlSeconds ?? null;
  const summaryLabel = loading
    ? 'Loading OTP state'
    : dashboard?.enabled
      ? `${available.length} available`
      : 'OTP protection idle';

  return (
    <section className="card">
      <div className="card-header">
        <div>
          <h3>Spawn OTP Management</h3>
          <p>Issue single-use MCP spawn OTPs and review available tokens, used tokens, TTLs, and UUIDs.</p>
        </div>
        <button type="button" className="secondary" onClick={loadOtps} disabled={loading}>
          {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      <form className="otp-create-form" onSubmit={handleCreate}>
        <label>
          OTP Value
          <input
            type="text"
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

      <div className="otp-summary">
        <span className={`otp-pill ${dashboard?.enabled ? 'otp-pill-active' : 'otp-pill-idle'}`}>
          {summaryLabel}
        </span>
        <span className="status-note">{used.length} used</span>
        <span className="status-note">{expired.length} expired</span>
        <span className="status-note">
          Default TTL {defaultTtlSeconds === null ? 'disabled' : `${defaultTtlSeconds}s`}
        </span>
      </div>

      <p className="hint">
        Tokens are single-use. Used or expired entries remain visible here so you can track UUIDs, TTLs, and timestamps after the next spawn attempt.
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
          <div className="otp-entry-list">
            {available.map((otp) => (
              <OtpEntry key={otp.uuid} otp={otp} />
            ))}
          </div>
        ) : (
          <p className="hint">No unused OTPs are currently available.</p>
        )}
      </div>

      <div className="otp-section">
        <div className="otp-section-header">
          <h4>Used And Expired Tokens</h4>
          <span>{history.length}</span>
        </div>
        {history.length ? (
          <div className="otp-entry-list">
            {history.map((otp) => (
              <OtpEntry key={otp.uuid} otp={otp} />
            ))}
          </div>
        ) : (
          <p className="hint">Used and expired OTPs will appear here after a token is consumed or times out.</p>
        )}
      </div>
    </section>
  );
}
