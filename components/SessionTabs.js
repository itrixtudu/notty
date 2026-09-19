import { useEffect, useRef, useState } from 'react';
import { formatOtpRemaining } from '../lib/spawnOtpCountdown.js';
import styles from '../styles/Terminal.module.css';
import {
  getActiveSessionTabIndex,
  getNextSessionTabIndex
} from './sessionTabsModel.js';

export default function SessionTabs({
  sessions,
  activeSessionId,
  onSelect,
  onClose,
  onRenew,
  renewing = false,
  closingSessionIds = new Set()
}) {
  const tabRefs = useRef(new Map());
  const [now, setNow] = useState(() => Date.now());
  const clockRef = useRef({ offset: 0 });
  useEffect(() => {
    const serverTime = sessions.find((session) => Number.isFinite(session.serverTime))?.serverTime;
    clockRef.current.offset = serverTime == null ? 0 : serverTime - Date.now();
    setNow(Date.now() + clockRef.current.offset);
  }, [sessions]);
  useEffect(() => {
    const tick = () => setNow(Date.now() + clockRef.current.offset);
    const timer = window.setInterval(tick, 1000);
    document.addEventListener('visibilitychange', tick);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener('visibilitychange', tick);
    };
  }, []);
  const activeIndex = getActiveSessionTabIndex(sessions, activeSessionId);
  const focusableIndex = activeIndex >= 0 ? activeIndex : 0;

  useEffect(() => {
    if (activeSessionId == null) {
      return;
    }
    tabRefs.current.get(activeSessionId)?.scrollIntoView({
      block: 'nearest',
      inline: 'nearest'
    });
  }, [activeSessionId, sessions]);

  const handleKeyDown = (event, currentIndex) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
      return;
    }

    event.preventDefault();
    const nextIndex = getNextSessionTabIndex(currentIndex, sessions.length, event.key);
    const nextSession = sessions[nextIndex];
    if (!nextSession) {
      return;
    }

    onSelect(nextSession.id);
    window.requestAnimationFrame(() => tabRefs.current.get(nextSession.id)?.focus());
  };

  const handleClose = async (event, sessionId) => {
    event.preventDefault();
    event.stopPropagation();
    const result = await onClose?.(sessionId);
    if (result?.closed && result.nextSessionId != null) {
      window.requestAnimationFrame(() => tabRefs.current.get(result.nextSessionId)?.focus());
    }
  };

  return (
    <div className={styles.sessionTabs} role="tablist" aria-label="Terminal sessions">
      {sessions.length ? sessions.map((session, index) => {
        const isActive = session.id === activeSessionId;
        const access = session.inputAccess;
        const expiresAt = access?.expiresAt;
        const duration = expiresAt - access?.createdAt;
        const progress = expiresAt == null ? 100
          : Math.max(0, Math.min(100, duration > 0 ? (expiresAt - now) / duration * 100 : 0));
        const label = expiresAt != null && now >= expiresAt
          ? 'Expired' : formatOtpRemaining({ expiresAt, status: 'available' }, now);
        return (
          <div
            key={session.id}
            className={`${styles.sessionTabItem}${isActive ? ` ${styles.sessionTabItemActive}` : ''}`}
            role="presentation"
            style={{ '--tab-time-left': `${progress}%` }}
          >
            <button
              ref={(node) => {
                if (node) {
                  tabRefs.current.set(session.id, node);
                } else {
                  tabRefs.current.delete(session.id);
                }
              }}
              type="button"
              className={`${styles.sessionTab}${isActive ? ` ${styles.sessionTabActive}` : ''}`}
              role="tab"
              aria-selected={isActive}
              tabIndex={index === focusableIndex ? 0 : -1}
              title={session.cwd || '~'}
              aria-label={`Terminal #${session.id}, ${session.shell}, ${label}`}
              onClick={() => onSelect(session.id)}
              onKeyDown={(event) => handleKeyDown(event, index)}
            >
              <span className={styles.sessionTabStatus} aria-hidden="true" />
              <span className={styles.sessionTabLabel}>{label}</span>
            </button>
            <button
              type="button"
              className={styles.sessionTabClose}
              aria-label={`Close terminal #${session.id}`}
              title={`Close terminal #${session.id} and terminate its session`}
              disabled={closingSessionIds.has(session.id)}
              onClick={(event) => handleClose(event, session.id)}
            >
              <span aria-hidden="true">×</span>
            </button>
            {access && onRenew && (
              <button
                type="button"
                className={styles.sessionTabClose}
                title={`Renew terminal #${session.id} access with a fresh OTP`}
                aria-label={`Renew terminal #${session.id} access`}
                disabled={renewing}
                onClick={() => onRenew(session.id)}
              >
                <span aria-hidden="true">↻</span>
              </button>
            )}
          </div>
        );
      }) : (
        <span className={styles.sessionTabsEmpty}>No sessions</span>
      )}
    </div>
  );
}
