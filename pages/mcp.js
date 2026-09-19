import { useEffect, useMemo, useState } from 'react';
import SpawnTerminalDialog from '../components/SpawnTerminalDialog.js';
import useTerminalSpawnDialog from '../hooks/useTerminalSpawnDialog.js';
import {
  mcpToolRequiresSpawnOtp,
  prepareMcpToolArguments
} from '../lib/browserTerminalSpawn.js';
import { browserFetch } from '../lib/browserRequest.js';

export default function McpPage() {
  const [tools, setTools] = useState([]);
  const [selectedToolName, setSelectedToolName] = useState('');
  const [argsText, setArgsText] = useState('{}');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { requestSpawnOtp, spawnDialogProps } = useTerminalSpawnDialog();

  useEffect(() => {
    let cancelled = false;
    async function loadTools() {
      try {
        const response = await browserFetch('/api/mcp/tools');
        if (!response.ok) {
          throw new Error('Failed to load tool metadata');
        }
        const data = await response.json();
        if (!cancelled) {
          setTools(data.tools || []);
          setSelectedToolName((data.tools && data.tools[0]?.name) || '');
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || 'Unable to load tools');
        }
      }
    }
    loadTools();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!selectedToolName) {
      setArgsText('{}');
      return;
    }
    const next = tools.find((tool) => tool.name === selectedToolName);
    if (!next) {
      setArgsText('{}');
      return;
    }
    const placeholder = next.inputSchema?.properties || {};
    const defaults = buildDefaults(placeholder);
    setArgsText(JSON.stringify(defaults, null, 2));
  }, [selectedToolName, tools]);

  const selectedTool = useMemo(
    () => tools.find((tool) => tool.name === selectedToolName),
    [tools, selectedToolName]
  );

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!selectedToolName) return;
    setLoading(true);
    setError('');
    setResult(null);

    let args;
    try {
      args = argsText.trim() ? JSON.parse(argsText) : {};
    } catch (err) {
      setError(`Invalid JSON: ${err.message}`);
      setLoading(false);
      return;
    }

    const invokeTool = async (toolArguments) => {
      const response = await browserFetch('/api/mcp/call', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: selectedToolName, arguments: toolArguments })
      });

      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw getToolCallError(data);
      }
      return data;
    };

    try {
      const toolArguments = prepareMcpToolArguments(selectedTool, args);
      if (
        args
        && typeof args === 'object'
        && Object.prototype.hasOwnProperty.call(args, 'otp')
      ) {
        setArgsText(JSON.stringify(toolArguments, null, 2));
      }

      const data = mcpToolRequiresSpawnOtp(selectedTool, toolArguments)
        ? await requestSpawnOtp((otp) => invokeTool(
            prepareMcpToolArguments(selectedTool, toolArguments, otp)
          ))
        : await invokeTool(toolArguments);
      if (data) {
        setResult(data);
      }
    } catch (err) {
      setError(err.message || 'Tool call failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="page">
      <header>
        <h1>MCP Terminal Tools</h1>
        <p>Inspect the local MCP tool surface and exercise calls directly from the browser.</p>
      </header>

      <section className="card">
        <div className="card-header">
          <h3>How this page works</h3>
        </div>
        <p>
          The stdio MCP server still lives in <code>server.js</code>. Run it with <code>npm start</code> or
          switch to SSE via <code>MCP_TRANSPORT=sse</code>. This dashboard only mirrors the tool metadata
          and routes calls through the shared PTY manager, so you can sanity-check requests without leaving
          the UI.
        </p>
        <p className="hint">
          The dedicated terminal WebSocket now shares the primary <code>PORT</code> (default{' '}
          <code>3000</code>; override with <code>PORT</code> or <code>NOTTY_PUBLIC_WS_URL</code>). MCP itself
          still speaks stdio/SSE and is separate from that socket.
        </p>
      </section>

      {error && (
        <div className="error" role="alert">
          {error}
        </div>
      )}

      <div className="layout">
        <div className="stack">
          <div className="card">
            <div className="card-header">
              <h3>Registered Tools</h3>
              <p>{tools.length ? `${tools.length} available` : 'Loading...'}</p>
            </div>
            {tools.length === 0 ? (
              <p>No tools registered. Check that the MCP server imported <code>lib/mcpTools.js</code>.</p>
            ) : (
              <ul className="session-list">
                {tools.map((tool) => (
                  <li key={tool.name}>
                    <button
                      type="button"
                      className={tool.name === selectedToolName ? 'selected' : ''}
                      onClick={() => setSelectedToolName(tool.name)}
                    >
                      <div className="session-title">{tool.name}</div>
                      <div className="session-meta">{tool.description}</div>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Call Tool</h3>
              {selectedTool && (
                <p>
                  {selectedTool.description}
                  {selectedTool.inputSchema?.properties && (
                    <>
                      {' '}
                      <code>{JSON.stringify(Object.keys(selectedTool.inputSchema.properties))}</code>
                    </>
                  )}
                </p>
              )}
            </div>
            <select
              value={selectedToolName}
              onChange={(event) => setSelectedToolName(event.target.value)}
            >
              {tools.map((tool) => (
                <option key={tool.name} value={tool.name}>
                  {tool.name}
                </option>
              ))}
            </select>
          </div>
          <form onSubmit={handleSubmit} className="stack">
            <label>
              Arguments (JSON)
              <textarea
                value={argsText}
                onChange={(event) => setArgsText(event.target.value)}
                rows={10}
                spellCheck={false}
              />
            </label>
            <div className="row">
              <button type="submit" disabled={!selectedToolName || loading}>
                {loading ? 'Calling...' : 'Call Tool'}
              </button>
            </div>
            {selectedTool?.inputSchema?.properties?.otp && (
              <p className="hint">
                Spawn OTPs are entered in a separate one-time dialog and are never retained in this JSON field.
              </p>
            )}
          </form>
          {result && (
            <div>
              <h4>Result</h4>
              <pre>{formatResult(result)}</pre>
            </div>
          )}
        </div>
      </div>
      <SpawnTerminalDialog {...spawnDialogProps} />
    </main>
  );
}

function buildDefaults(properties) {
  const out = {};
  for (const [key, value] of Object.entries(properties)) {
    if (key === 'otp') {
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(value, 'default')) {
      out[key] = value.default;
    } else {
      out[key] = null;
    }
  }
  return out;
}

function getToolCallError(payload) {
  const text = payload?.content?.[0]?.text;
  let code = '';
  let message = typeof payload?.error === 'string'
    ? payload.error
    : payload?.error?.message;

  if (typeof text === 'string' && text.trim()) {
    try {
      const parsed = JSON.parse(text);
      code = parsed?.error?.code || '';
      message = parsed?.error?.message || message || text;
    } catch {
      message = text;
    }
  }

  const error = new Error(message || 'Tool call failed');
  if (code) {
    error.code = code;
  }
  return error;
}

function formatResult(result) {
  if (!result) return '';
  const text = result.content?.[0]?.text;
  if (typeof text === 'string') {
    return text;
  }
  return JSON.stringify(result, null, 2);
}
