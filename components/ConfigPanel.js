import { useState } from 'react';

export default function ConfigPanel() {
  const [shortcutsOpen, setShortcutsOpen] = useState(false);

  return (
    <div className="card">
      <div className="card-header">
        <h3>Terminal Settings</h3>
        <p>Configure terminal appearance. Rendering now always uses xterm.js.</p>
      </div>

      <div className="row">
        <label>
          Rendering Engine
          <input type="text" value="xterm.js" disabled />
        </label>
      </div>

      <p className="hint">
        xterm.js provides a full-featured terminal with WebGL acceleration and addons like fit and web links.
      </p>

      <div className="row">
        <label>
          Font Family
          <select disabled>
            <option>Coming Soon</option>
          </select>
        </label>
        <label>
          Font Size
          <input type="number" min="8" max="32" disabled />
        </label>
      </div>
      <label>
        Theme
        <select disabled>
          <option>Light</option>
          <option>Dark</option>
        </select>
      </label>
      <p className="hint">
        Font and theme controls will be enabled in a future update.
      </p>

      <div className="row">
        <button
          type="button"
          className="secondary"
          aria-expanded={shortcutsOpen}
          onClick={() => setShortcutsOpen((current) => !current)}
        >
          Keyboard Shortcuts
        </button>
      </div>
      {shortcutsOpen && (
        <div className="shortcut-list">
          <div className="shortcut-row">
            <span className="shortcut-key">Ctrl+Shift+→</span>
            <span>Spawn a new terminal session.</span>
          </div>
          <div className="shortcut-row">
            <span className="shortcut-key">Ctrl+Shift+↑</span>
            <span>Toggle fullscreen terminal view (WebGL).</span>
          </div>
          <div className="shortcut-row">
            <span className="shortcut-key">Ctrl+Shift+↓</span>
            <span>Exit focus/zoomed view (WebGL).</span>
          </div>
        </div>
      )}
    </div>
  );
}
