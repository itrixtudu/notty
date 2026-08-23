export function getActiveSessionTabIndex(sessions, activeSessionId) {
  if (!Array.isArray(sessions) || activeSessionId == null) {
    return -1;
  }
  return sessions.findIndex((session) => session.id === activeSessionId);
}

export function getNextSessionTabIndex(currentIndex, sessionCount, key) {
  if (!Number.isInteger(sessionCount) || sessionCount <= 0) {
    return -1;
  }

  const safeIndex = Number.isInteger(currentIndex) && currentIndex >= 0 && currentIndex < sessionCount
    ? currentIndex
    : 0;

  if (key === 'ArrowRight') {
    return (safeIndex + 1) % sessionCount;
  }
  if (key === 'ArrowLeft') {
    return (safeIndex - 1 + sessionCount) % sessionCount;
  }
  if (key === 'Home') {
    return 0;
  }
  if (key === 'End') {
    return sessionCount - 1;
  }
  return safeIndex;
}
