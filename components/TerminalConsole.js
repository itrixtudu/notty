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

export default function TerminalConsole({
  sessionId,
  fullViewport = false,
  showPlaceholder = true,
  showChrome = true,
  onNewTerminal,
  title,
  subtitle,
  compact = false,
  autoFocus = true,
  updateDocumentTitle = true,
  onConnectionStatus,
  onSelectionChange,
  headerActions,
  copyControls = false,
  transcriptControl = false
}) {
  return (
    <XtermRenderer
      sessionId={sessionId}
      fullViewport={fullViewport}
      showPlaceholder={showPlaceholder}
      showChrome={showChrome}
      onNewTerminal={onNewTerminal}
      title={title}
      subtitle={subtitle}
      compact={compact}
      autoFocus={autoFocus}
      updateDocumentTitle={updateDocumentTitle}
      onConnectionStatus={onConnectionStatus}
      onSelectionChange={onSelectionChange}
      headerActions={headerActions}
      copyControls={copyControls}
      transcriptControl={transcriptControl}
    />
  );
}
