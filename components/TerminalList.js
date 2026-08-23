export default function TerminalList({
  sessions,
  selectedId,
  onSelect,
  onRefresh
}) {
  return (
    <div className="card">
      <div className="card-header">
        <h3>Sessions</h3>
        <div className="row">
          <span>{sessions.length} active</span>
          <button type="button" onClick={onRefresh}>
            Refresh
          </button>
        </div>
      </div>
      <ul className="session-list">
        {sessions.map((session) => (
          <li key={session.id}>
            <button
              className={session.id === selectedId ? 'selected' : ''}
              type="button"
              onClick={() => onSelect(session.id)}
            >
              <div className="session-title">
                #{session.id} · {session.shell}
              </div>
              <div className="session-meta">
                {session.cols}×{session.rows} · {session.cwd || '~'}
              </div>
            </button>
          </li>
        ))}
        {!sessions.length && (
          <li className="empty">No sessions yet. Create one to get started.</li>
        )}
      </ul>
    </div>
  );
}
