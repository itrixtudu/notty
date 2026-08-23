import dynamic from 'next/dynamic';

const XtermRenderer = dynamic(() => import('./XtermRenderer.js'), {
  ssr: false,
  loading: () => (
    <div className="terminal-shell terminal-shell-empty">
      <div className="terminal-placeholder">
        <h2>Loading xterm.js...</h2>
      </div>
    </div>
  )
});

export default function TerminalConsole({ sessionId }) {
  return <XtermRenderer sessionId={sessionId} />;
}
