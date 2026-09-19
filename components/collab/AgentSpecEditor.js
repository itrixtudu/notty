import { useId, useMemo, useRef } from 'react';
import styles from '../../styles/Collab.module.css';
import { Pencil, Plus, X } from 'lucide-react';
import {
  AGENT_BACKENDS,
  AGENT_HARNESSES,
  displayModelName,
  formatAgentModel,
  isCompatibleAgentBackend,
  normalizeAgentSpec,
  thinkOptionsFor
} from './configModel.js';

function entriesFrom(value) {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== 'object') return [];
  if (Array.isArray(value.models)) return value.models;
  return Object.entries(value).flatMap(([id, entry]) => {
    if (['status', 'error', 'stale', 'updatedAt', 'source'].includes(id)) return [];
    if (Array.isArray(entry)) return entry;
    if (entry && typeof entry === 'object' && Array.isArray(entry.models)) {
      return entry.models;
    }
    return [{ id, ...(entry && typeof entry === 'object' ? entry : { description: entry }) }];
  });
}

function catalogSources(catalog, harness, backend) {
  const root = catalog?.catalog || catalog?.models || catalog;
  if (Array.isArray(root)) {
    const targets = root.filter((entry) => (
      entry
      && typeof entry === 'object'
      && String(entry.harness || entry.agent || '').toLowerCase() === harness
      && String(entry.backend || 'default').toLowerCase() === backend
    ));
    return targets.length ? targets.map((entry) => entry.models || entry) : [root];
  }
  if (!root || typeof root !== 'object') return [root];
  const sources = [
    root[`${harness}:${backend}`],
    root[`${harness}.${backend}`],
    root?.[harness]?.[backend]
  ];
  if (backend === 'ollama') sources.push(root.ollama);
  if (backend === 'default') sources.push(root[harness]);
  return sources;
}

export function modelOptionsFromCatalogs(catalogs, harness, backend) {
  const seen = new Set();
  const options = [];
  for (const catalog of catalogs) {
    for (const source of catalogSources(catalog, harness, backend)) {
      for (const entry of entriesFrom(source)) {
        const entryHarness = String(entry?.harness || entry?.agent || '').toLowerCase();
        const entryBackend = String(entry?.backend || '').toLowerCase();
        const entryRuntime = String(entry?.runtime || '').toLowerCase();
        if (entryHarness && entryHarness !== harness) continue;
        if (entryBackend && entryBackend !== backend) continue;
        if (entryRuntime && ![harness, backend].includes(entryRuntime)) continue;
        const id = String(
          typeof entry === 'string'
            ? entry
            : entry?.id || entry?.model || entry?.name || ''
        ).trim();
        if (!id || seen.has(id)) continue;
        seen.add(id);
        options.push({
          id,
          label: typeof entry === 'object'
            ? String(entry.description || entry.label || '').trim()
            : ''
        });
      }
    }
  }
  return options;
}

export default function AgentSpecEditor({
  agents,
  prompts,
  modelCatalog,
  launchCatalog,
  onChange,
  onEditPrompt,
  onCreatePrompt,
  sectionLabel = 'Roster',
  maxRows = Infinity
}) {
  const rows = agents.map(normalizeAgentSpec);
  const rowKeysRef = useRef([]);
  const nextRowKeyRef = useRef(1);
  const promptById = Object.fromEntries((prompts || []).map((prompt) => [prompt.id, prompt]));
  const modelOptionsByTuple = useMemo(() => Object.fromEntries(
    AGENT_HARNESSES.flatMap(({ id: harness }) => AGENT_BACKENDS.map(({ id: backend }) => [
      `${harness}:${backend}`,
      isCompatibleAgentBackend(harness, backend)
        ? modelOptionsFromCatalogs([launchCatalog, modelCatalog], harness, backend)
        : []
    ]))
  ), [launchCatalog, modelCatalog]);
  const modelListId = `collab-models-${useId().replace(/[^A-Za-z0-9_-]/g, '')}`;

  while (rowKeysRef.current.length < rows.length) {
    rowKeysRef.current.push(`agent-row-${nextRowKeyRef.current}`);
    nextRowKeyRef.current += 1;
  }
  if (rowKeysRef.current.length > rows.length) {
    rowKeysRef.current.length = rows.length;
  }

  const replaceRow = (index, nextRow) => {
    onChange(rows.map((row, rowIndex) => rowIndex === index ? nextRow : row));
  };

  const updateRow = (index, field, value) => {
    const current = rows[index];
    let next = { ...current, [field]: value };
    if (field === 'harness' && value !== 'codex') {
      next.backend = 'default';
    }
    if (field === 'harness' || field === 'backend') {
      const options = thinkOptionsFor(next.harness, next.backend);
      if (!options.includes(next.think)) next.think = options[0] ?? '';
    }
    replaceRow(index, next);
  };

  const removeRow = (index) => {
    rowKeysRef.current.splice(index, 1);
    onChange(rows.filter((_, rowIndex) => rowIndex !== index));
  };

  const addRow = () => {
    rowKeysRef.current.push(`agent-row-${nextRowKeyRef.current}`);
    nextRowKeyRef.current += 1;
    if (rows.length >= maxRows) return;
    onChange([
      ...rows,
      {
        prompt: prompts?.[0]?.id || 'coder',
        harness: 'codex',
        backend: 'default',
        model: '',
        think: ''
      }
    ]);
  };

  return (
    <div className={styles.agentEditor}>
      <div className={styles.sectionHeading}>
        <span>{sectionLabel}</span>
        <div className={styles.headingActions}>
          {onCreatePrompt && (
            <button type="button" className={styles.textCommand} onClick={onCreatePrompt}>
              <Plus size={13} aria-hidden="true" /> New role
            </button>
          )}
          {rows.length < maxRows && (
            <button type="button" className={styles.iconCommand} onClick={addRow} title="Add agent">
              <Plus size={15} aria-hidden="true" />
              <span className={styles.srOnly}>Add agent</span>
            </button>
          )}
        </div>
      </div>
      <div className={styles.agentRows}>
        {rows.map((agent, index) => {
          const prompt = promptById[agent.prompt];
          const tuple = `${agent.harness}:${agent.backend}`;
          const modelOptions = modelOptionsByTuple[tuple] || [];
          const runtimeModelListId = `${modelListId}-${agent.harness}-${agent.backend}`;
          const thinkOptions = thinkOptionsFor(agent.harness, agent.backend);
          return (
            <div className={styles.agentRow} key={rowKeysRef.current[index]}>
              <label className={styles.roleField}>
                <span>Role</span>
                <span className={styles.inputWithAction}>
                  <select value={agent.prompt} onChange={(event) => updateRow(index, 'prompt', event.target.value)}>
                    {!promptById[agent.prompt] && agent.prompt && (
                      <option value={agent.prompt}>{agent.prompt}</option>
                    )}
                    {(prompts || []).map((option) => (
                      <option value={option.id} key={option.id}>{option.label || option.id}</option>
                    ))}
                  </select>
                  {onEditPrompt && agent.prompt && (
                    <button
                      type="button"
                      className={styles.inlineIcon}
                      onClick={() => onEditPrompt(agent.prompt)}
                      aria-label={`Edit ${prompt?.label || agent.prompt} role`}
                      title="Quick edit role"
                    >
                      <Pencil size={12} aria-hidden="true" />
                    </button>
                  )}
                </span>
              </label>
              <label>
                <span>Agent</span>
                <select
                  value={agent.harness}
                  onChange={(event) => updateRow(index, 'harness', event.target.value)}
                >
                  {agent.harness && !AGENT_HARNESSES.some(({ id }) => id === agent.harness) && (
                    <option value={agent.harness}>{agent.harness} (unsupported)</option>
                  )}
                  {AGENT_HARNESSES.map((option) => (
                    <option value={option.id} key={option.id}>{option.label}</option>
                  ))}
                </select>
              </label>
              <label>
                <span>Runtime</span>
                <select
                  value={agent.backend}
                  onChange={(event) => updateRow(index, 'backend', event.target.value)}
                >
                  {AGENT_BACKENDS.filter((option) => (
                    isCompatibleAgentBackend(agent.harness, option.id)
                  )).map((option) => (
                    <option value={option.id} key={option.id}>{option.label}</option>
                  ))}
                </select>
              </label>
              <label className={styles.modelField}>
                <span>Model</span>
                <input
                  value={agent.model}
                  onChange={(event) => updateRow(index, 'model', event.target.value)}
                  placeholder="Custom or catalog model"
                  list={modelOptions.length ? runtimeModelListId : undefined}
                  autoComplete="off"
                />
              </label>
              <label>
                <span>Think</span>
                <select
                  value={agent.think}
                  onChange={(event) => updateRow(index, 'think', event.target.value)}
                >
                  {!thinkOptions.includes(agent.think) && agent.think && (
                    <option value={agent.think}>{agent.think} (unsupported)</option>
                  )}
                  {thinkOptions.map((think) => (
                    <option value={think} key={think || 'default'}>{think || 'Default'}</option>
                  ))}
                </select>
              </label>
              <button
                type="button"
                className={styles.removeAgent}
                onClick={() => removeRow(index)}
                aria-label={`Remove ${prompt?.label || agent.prompt || `agent ${index + 1}`}`}
                title="Remove agent"
              >
                <X size={14} aria-hidden="true" />
              </button>
              <div className={styles.agentSpec}>
                <strong>{formatAgentModel(agent)}</strong>
                {agent.backend === 'ollama' && <span>via Ollama</span>}
                <span>Think {agent.think || 'Default'}</span>
                {agent.harness === 'agy' && agent.model !== displayModelName(agent) && (
                  <span className={styles.rawModel} title="Raw launch model ID">ID: {agent.model}</span>
                )}
              </div>
            </div>
          );
        })}
        {!rows.length && <div className={styles.emptyRow}>No agents</div>}
      </div>
      {Object.entries(modelOptionsByTuple).map(([tuple, modelOptions]) => (
        modelOptions.length > 0 && (
          <datalist id={`${modelListId}-${tuple.replace(':', '-')}`} key={tuple}>
            {modelOptions.map((model) => (
              <option value={model.id} key={model.id}>{model.label}</option>
            ))}
          </datalist>
        )
      ))}
    </div>
  );
}
