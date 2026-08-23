import { useEffect, useRef } from 'react';
import styles from '../styles/Terminal.module.css';
import {
  getActiveSessionTabIndex,
  getNextSessionTabIndex
} from './sessionTabsModel.js';

export default function SessionTabs({ sessions, activeSessionId, onSelect }) {
  const tabRefs = useRef(new Map());
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

  return (
    <div className={styles.sessionTabs} role="tablist" aria-label="Terminal sessions">
      {sessions.length ? sessions.map((session, index) => {
        const isActive = session.id === activeSessionId;
        return (
          <button
            key={session.id}
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
            onClick={() => onSelect(session.id)}
            onKeyDown={(event) => handleKeyDown(event, index)}
          >
            <span className={styles.sessionTabStatus} aria-hidden="true" />
            <span className={styles.sessionTabLabel}>#{session.id} · {session.shell}</span>
          </button>
        );
      }) : (
        <span className={styles.sessionTabsEmpty}>No sessions</span>
      )}
    </div>
  );
}
