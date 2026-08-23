import { useEffect, useMemo, useState } from 'react';
import AgentSpecEditor from './AgentSpecEditor.js';
import {
  createAgentDocument,
  createPromptDocument,
  createTemplateDocument,
  formatAgentModel,
  isCompatibleAgentBackend,
  isPromptReferenced,
  normalizeAgentSpec,
  resolveLaunchAgents,
  scopeHasPrompt,
  scopeHasTemplate,
  thinkOptionsFor
} from './configModel.js';
import styles from '../../styles/Collab.module.css';

function templateToDraft(template) {
  return {
    ...createTemplateDocument(template),
    id: template.id,
    agents: (template.agents || []).map(normalizeAgentSpec),
    coordinatorSpec: template.coordinatorSpec
      ? normalizeAgentSpec(template.coordinatorSpec)
      : null
  };
}

function sourceLabel(source) {
  if (source === 'workspace') return 'workspace';
  if (source === 'user') return 'user';
  return 'built-in';
}

function entryFromScope(config, scope, collection, id) {
  const entries = config?.documents?.[scope]?.[collection];
  if (Array.isArray(entries)) return entries.find((entry) => entry.id === id) || null;
  if (entries && Object.hasOwn(entries, id)) return entries[id];
  return null;
}

function scopedTemplate(config, scope, template) {
  const override = entryFromScope(config, scope, 'templates', template.id);
  return override ? { ...override, id: template.id } : template;
}

function scopedPrompt(config, scope, prompt) {
  const override = entryFromScope(config, scope, 'prompts', prompt.id);
  return override ? { ...override, id: prompt.id } : prompt;
}

function lowerScopeHasPrompt(config, scope, promptId) {
  const lowerScopes = scope === 'workspace' ? ['user', 'builtin'] : ['builtin'];
  return lowerScopes.some((candidate) => (
    scopeHasPrompt(config?.documents?.[candidate], promptId)
  ));
}

function validAgentDocument(agent) {
  return Boolean(
    agent.prompt
    && agent.harness
    && agent.backend
    && agent.model
    && isCompatibleAgentBackend(agent.harness, agent.backend)
    && thinkOptionsFor(agent.harness, agent.backend).includes(agent.think)
  );
}

function catalogState(launchCatalog, modelCatalog) {
  if (!launchCatalog) {
    return modelCatalog ? { status: 'ready', message: 'Legacy model catalog' } : { status: 'empty' };
  }
  if (Array.isArray(launchCatalog)) {
    const errors = launchCatalog.filter((entry) => entry.status === 'error');
    const ready = launchCatalog.filter((entry) => entry.status === 'ready');
    const loading = launchCatalog.some((entry) => entry.status === 'loading');
    if (loading) return { status: 'loading', message: 'Refreshing launch targets' };
    if (errors.length === launchCatalog.length) {
      return { status: 'error', message: errors[0]?.error || 'All launch targets unavailable' };
    }
    if (errors.length) {
      return { status: 'stale', message: `${errors.length} launch target${errors.length === 1 ? '' : 's'} unavailable` };
    }
    if (!ready.length) return { status: 'empty', message: 'No catalog models found; custom hosted IDs are allowed' };
    return { status: 'ready', message: `${ready.length} launch targets refreshed` };
  }
  if (launchCatalog.error) {
    return {
      status: launchCatalog.stale ? 'stale' : 'error',
      message: launchCatalog.error.message || launchCatalog.error
    };
  }
  return {
    status: launchCatalog.status || (launchCatalog.stale ? 'stale' : 'ready'),
    message: launchCatalog.message || launchCatalog.updatedAt || ''
  };
}

function promptDraft(prompt = {}) {
  return {
    id: prompt.id || '',
    ...createPromptDocument(prompt)
  };
}

function PromptLibrary({
  config,
  scope,
  onChangeScope,
  selectedPromptId,
  onSelectPrompt,
  creatingPrompt,
  onCreatePrompt,
  onSavePrompt,
  onRemovePrompt,
  busy
}) {
  const prompts = config.prompts || [];
  const resolved = prompts.find((prompt) => prompt.id === selectedPromptId) || prompts[0] || null;
  const [draft, setDraft] = useState(() => promptDraft(resolved || {}));
  const [error, setError] = useState('');

  useEffect(() => {
    if (creatingPrompt) {
      setDraft(promptDraft());
      setError('');
      return;
    }
    if (!resolved) return;
    setDraft(promptDraft(scopedPrompt(config, scope, resolved)));
    setError('');
  }, [
    creatingPrompt,
    resolved?.id,
    scope,
    config?.revisions?.user,
    config?.revisions?.workspace
  ]);

  const save = async (event) => {
    event.preventDefault();
    const id = draft.id.trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9.-]*$/.test(id)) {
      setError('Role ID must use letters, numbers, dots, or hyphens.');
      return;
    }
    if (!draft.label.trim() || !draft.role.trim() || !draft.instructions.trim()) {
      setError('Label, role, and instructions are required.');
      return;
    }
    setError('');
    const saved = await onSavePrompt(scope, id, draft);
    if (saved !== false) onSelectPrompt(id);
  };

  const current = creatingPrompt ? null : resolved;
  const hasOverride = current ? scopeHasPrompt(config.documents?.[scope], current.id) : false;
  const referenced = current ? isPromptReferenced(config.templates, current.id) : false;
  const hasLowerDefinition = current
    ? lowerScopeHasPrompt(config, scope, current.id)
    : false;
  const removalBlocked = referenced && !hasLowerDefinition;

  return (
    <div className={styles.promptLibrary}>
      <aside className={styles.promptList} aria-label="Prompt library roles">
        <button
          type="button"
          className={`${styles.promptItem}${creatingPrompt ? ` ${styles.promptItemActive}` : ''}`}
          onClick={onCreatePrompt}
        >
          + New role
        </button>
        {prompts.map((prompt) => (
          <button
            type="button"
            className={`${styles.promptItem}${!creatingPrompt && prompt.id === resolved?.id ? ` ${styles.promptItemActive}` : ''}`}
            onClick={() => onSelectPrompt(prompt.id)}
            key={prompt.id}
          >
            <strong>{prompt.label || prompt.id}</strong>
            <span>{prompt.role || prompt.id} · {sourceLabel(prompt.source)}</span>
          </button>
        ))}
      </aside>

      <form className={styles.promptForm} onSubmit={save}>
        <div className={styles.editorToolbar}>
          <label>
            <span>Write to</span>
            <select value={scope} onChange={(event) => onChangeScope(event.target.value)}>
              <option value="user">User config</option>
              <option value="workspace">Workspace config</option>
            </select>
          </label>
          <span className={styles.overrideState}>
            {hasOverride ? `${scope} override` : `copy to ${scope}`}
          </span>
          {hasOverride && current && (
            <button
              type="button"
              className={styles.secondaryCommand}
              onClick={() => onRemovePrompt(scope, current.id)}
              disabled={busy || removalBlocked}
              title={removalBlocked
                ? 'Referenced roles need a lower-scope definition before removal'
                : 'Remove this override and reveal the lower-scope role'}
            >
              Remove override
            </button>
          )}
        </div>
        <div className={styles.promptGrid}>
          <label>
            <span>Reusable ID</span>
            <input
              value={draft.id}
              onChange={(event) => setDraft((value) => ({ ...value, id: event.target.value }))}
              disabled={!creatingPrompt}
              placeholder="observer"
            />
          </label>
          <label>
            <span>Label</span>
            <input
              value={draft.label}
              onChange={(event) => setDraft((value) => ({ ...value, label: event.target.value }))}
              placeholder="Observer"
            />
          </label>
          <label>
            <span>Role</span>
            <input
              value={draft.role}
              onChange={(event) => setDraft((value) => ({ ...value, role: event.target.value }))}
              placeholder="observer"
            />
          </label>
          <label>
            <span>Identity seed</span>
            <input
              value={draft.identity}
              onChange={(event) => setDraft((value) => ({ ...value, identity: event.target.value }))}
              placeholder={draft.id || 'observer'}
            />
          </label>
          <label className={styles.checkField}>
            <input
              type="checkbox"
              checked={draft.coordinatorCapable}
              onChange={(event) => setDraft((value) => ({
                ...value,
                coordinatorCapable: event.target.checked
              }))}
            />
            <span>Coordinator capable</span>
          </label>
          <label className={styles.promptInstructions}>
            <span>Instructions</span>
            <textarea
              value={draft.instructions}
              onChange={(event) => setDraft((value) => ({ ...value, instructions: event.target.value }))}
              placeholder="Describe this role's responsibilities and boundaries."
            />
          </label>
        </div>
        {removalBlocked && hasOverride && (
          <div className={styles.inlineNotice}>
            This role is referenced by a profile and has no lower-scope definition.
          </div>
        )}
        {error && <div className={styles.formError} role="alert">{error}</div>}
        <div className={styles.editorActions}>
          <span>Saving writes the role and existing profile document atomically.</span>
          <button type="submit" disabled={busy}>
            {busy ? 'Saving…' : hasOverride ? 'Save role override' : 'Save role'}
          </button>
        </div>
      </form>
    </div>
  );
}

export default function CollabLaunchpad({
  config,
  selectedTemplateId,
  onSelectTemplate,
  onLaunch,
  onSaveTemplate,
  onRemoveOverride,
  onSavePrompt,
  onRemovePrompt,
  onRefreshCatalog,
  modelCatalog,
  launchCatalog,
  busy
}) {
  const templates = config?.templates || [];
  const selected = templates.find((template) => template.id === selectedTemplateId)
    || templates[0]
    || null;
  const [panel, setPanel] = useState('launch');
  const [task, setTask] = useState('');
  const [channel, setChannel] = useState('');
  const [coordinatorMode, setCoordinatorMode] = useState('human');
  const [scope, setScope] = useState('user');
  const [draft, setDraft] = useState(() => selected ? templateToDraft(selected) : null);
  const [validationError, setValidationError] = useState('');
  const [selectedPromptId, setSelectedPromptId] = useState(config?.prompts?.[0]?.id || '');
  const [creatingPrompt, setCreatingPrompt] = useState(false);

  useEffect(() => {
    if (!selected) return;
    const nextScope = selected.source === 'workspace' ? 'workspace' : 'user';
    setCoordinatorMode(selected.defaultCoordinatorMode || 'human');
    setChannel(selected.channel || 'lobby');
    setScope(nextScope);
    setDraft(templateToDraft(scopedTemplate(config, nextScope, selected)));
    setValidationError('');
  }, [
    selected?.id,
    selected?.source,
    config?.revisions?.user,
    config?.revisions?.workspace
  ]);

  const parsedAgents = useMemo(() => (
    resolveLaunchAgents(selected, coordinatorMode, config?.prompts)
  ), [selected, coordinatorMode, config?.prompts]);

  const launch = async (event) => {
    event.preventDefault();
    if (!selected) return;
    if (!parsedAgents.length) {
      setValidationError(
        coordinatorMode === 'human'
          ? 'Human coordination removes coordinator roles; add at least one worker before launch.'
          : 'This profile has no launchable agents.'
      );
      return;
    }
    if (
      coordinatorMode === 'agent'
      && parsedAgents.filter((agent) => agent.coordinatorCapable).length !== 1
    ) {
      setValidationError('Agent coordination requires exactly one coordinator-capable role.');
      return;
    }
    setValidationError('');
    await onLaunch({
      templateId: selected.id,
      coordinatorMode,
      task: task.trim() || undefined,
      channel: channel.trim() || undefined
    });
  };

  const saveTemplate = async (event) => {
    event.preventDefault();
    const normalizedAgents = (draft?.agents || []).map(createAgentDocument);
    const normalizedCoordinator = draft?.coordinatorSpec
      ? createAgentDocument(draft.coordinatorSpec)
      : null;
    if (!draft?.label?.trim()) {
      setValidationError('Template label is required.');
      return;
    }
    if (!normalizedAgents.length || normalizedAgents.some((agent) => !validAgentDocument(agent))) {
      setValidationError('Each row needs a compatible role, agent, runtime, model, and Think level.');
      return;
    }
    if (normalizedCoordinator && !validAgentDocument(normalizedCoordinator)) {
      setValidationError('The coordinator fallback needs a compatible role, agent, runtime, model, and Think level.');
      return;
    }
    const promptById = new Map((config.prompts || []).map((prompt) => [prompt.id, prompt]));
    const coordinatorCount = normalizedAgents.filter((agent) => (
      promptById.get(agent.prompt)?.coordinatorCapable
    )).length;
    const fallbackCoordinator = normalizedCoordinator
      ? Boolean(promptById.get(normalizedCoordinator.prompt)?.coordinatorCapable)
      : false;
    if (normalizedCoordinator && !fallbackCoordinator) {
      setValidationError('The coordinator fallback role must be coordinator capable.');
      return;
    }
    if (
      draft.defaultCoordinatorMode === 'agent'
      && (coordinatorCount > 1 || (coordinatorCount === 0 && !fallbackCoordinator))
    ) {
      setValidationError('Agent coordination requires exactly one coordinator-capable role or fallback.');
      return;
    }

    setValidationError('');
    const requiredNoshProfiles = draft.requiredNoshProfilesText == null
      ? (draft.requiredNoshProfiles || [])
      : String(draft.requiredNoshProfilesText)
          .split(',')
          .map((profile) => profile.trim())
          .filter(Boolean);
    await onSaveTemplate(scope, draft.id, {
      ...draft,
      agents: normalizedAgents,
      coordinatorSpec: normalizedCoordinator || undefined,
      requiredNoshProfiles
    });
  };

  const editDraft = (field, value) => {
    setDraft((current) => ({ ...current, [field]: value }));
  };

  const changeScope = (nextScope) => {
    setScope(nextScope);
    if (selected) setDraft(templateToDraft(scopedTemplate(config, nextScope, selected)));
    setValidationError('');
  };

  const editPrompt = (promptId) => {
    setSelectedPromptId(promptId);
    setCreatingPrompt(false);
    setPanel('roles');
  };

  const createPrompt = () => {
    setCreatingPrompt(true);
    setPanel('roles');
  };

  if (!selected) {
    return <div className={styles.emptyState}>No collaboration templates are configured.</div>;
  }

  const scopeDocument = config.documents?.[scope];
  const hasOverride = scopeHasTemplate(scopeDocument, selected.id);
  const requiredProfiles = selected.requiredNoshProfiles || [];
  const catalog = catalogState(launchCatalog, modelCatalog);

  return (
    <div className={styles.launchpad}>
      <aside className={styles.templateRail} aria-label="Collaboration templates">
        <div className={styles.railHeader}>
          <span>Profiles</span>
          <span className={styles.count}>{templates.length}</span>
        </div>
        <div className={styles.templateList}>
          {templates.map((template) => (
            <button
              type="button"
              className={`${styles.templateItem}${template.id === selected.id ? ` ${styles.templateItemActive}` : ''}`}
              aria-pressed={template.id === selected.id}
              onClick={() => onSelectTemplate(template.id)}
              key={template.id}
            >
              <span className={styles.templateItemTop}>
                <strong>{template.label || template.id}</strong>
                <span className={`${styles.sourceBadge} ${styles[`source_${['user', 'workspace'].includes(template.source) ? template.source : 'builtin'}`]}`}>
                  {sourceLabel(template.source)}
                </span>
              </span>
              <span>{template.agents?.length || 0} agents · {template.layout || 'grid'}</span>
            </button>
          ))}
        </div>
      </aside>

      <section className={styles.profilePanel}>
        <div className={styles.profileHeader}>
          <div>
            <h2>{selected.label || selected.id}</h2>
            <p>{selected.description || selected.id}</p>
          </div>
          <div className={styles.segmented} aria-label="Profile action">
            {[
              ['launch', 'Launch'],
              ['edit', 'Template'],
              ['roles', 'Roles']
            ].map(([id, label]) => (
              <button
                type="button"
                className={panel === id ? styles.segmentActive : ''}
                onClick={() => setPanel(id)}
                aria-pressed={panel === id}
                key={id}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        {panel === 'launch' && (
          <form className={styles.launchForm} onSubmit={launch}>
            <div className={styles.agentPreview}>
              <div className={styles.previewHeader}>
                <span>Role</span>
                <span>Agent + Model</span>
                <span>Think</span>
                <span>Identity</span>
              </div>
              {parsedAgents.map((agent, index) => (
                <div className={styles.previewRow} key={`${agent.prompt}-${agent.harness}-${agent.model}-${index}`}>
                  <strong>{agent.label || agent.role || agent.prompt}</strong>
                  <span className={styles.agentModelCell}>
                    <strong>{formatAgentModel(agent)}</strong>
                    {agent.backend === 'ollama' && <small>via Ollama</small>}
                  </span>
                  <span>{agent.think || 'Default'}</span>
                  <code>{agent.identity || agent.prompt}</code>
                </div>
              ))}
              {!parsedAgents.length && (
                <div className={styles.previewEmpty}>No workers remain in this coordinator mode.</div>
              )}
            </div>

            <div className={styles.launchFields}>
              <label className={styles.taskField}>
                <span>Task</span>
                <textarea
                  value={task}
                  onChange={(event) => setTask(event.target.value)}
                  placeholder="Optional kickoff task"
                />
              </label>
              <div className={styles.launchOptions}>
                <fieldset>
                  <legend>Coordinator</legend>
                  <div className={styles.segmentedControl}>
                    <label className={coordinatorMode === 'human' ? styles.selectedOption : ''}>
                      <input
                        type="radio"
                        name="coordinatorMode"
                        value="human"
                        checked={coordinatorMode === 'human'}
                        onChange={() => setCoordinatorMode('human')}
                      />
                      Human
                    </label>
                    <label className={coordinatorMode === 'agent' ? styles.selectedOption : ''}>
                      <input
                        type="radio"
                        name="coordinatorMode"
                        value="agent"
                        checked={coordinatorMode === 'agent'}
                        onChange={() => setCoordinatorMode('agent')}
                      />
                      Agent
                    </label>
                  </div>
                </fieldset>
                <label>
                  <span>Channel</span>
                  <input value={channel} onChange={(event) => setChannel(event.target.value)} />
                </label>
                <div className={styles.requirements}>
                  <span>Nosh</span>
                  <strong>{requiredProfiles.length ? requiredProfiles.join(', ') : 'none'}</strong>
                </div>
                {validationError && <div className={styles.formError} role="alert">{validationError}</div>}
                <button type="submit" className={styles.launchButton} disabled={busy || !parsedAgents.length}>
                  {busy ? 'Launching…' : 'Launch profile'}
                </button>
              </div>
            </div>
          </form>
        )}

        {panel === 'edit' && (
          <form className={styles.editorForm} onSubmit={saveTemplate}>
            <div className={styles.editorToolbar}>
              <label>
                <span>Write to</span>
                <select value={scope} onChange={(event) => changeScope(event.target.value)}>
                  <option value="user">User config</option>
                  <option value="workspace">Workspace config</option>
                </select>
              </label>
              <span className={styles.overrideState}>
                {hasOverride ? `${scope} override` : `copy to ${scope}`}
              </span>
              {hasOverride && (
                <button
                  type="button"
                  className={styles.secondaryCommand}
                  onClick={() => onRemoveOverride(scope, selected.id)}
                  disabled={busy}
                >
                  Remove override
                </button>
              )}
            </div>

            <div className={`${styles.catalogStatus} ${styles[`catalog_${catalog.status}`]}`} role="status">
              <span>Model catalog: {catalog.status}{catalog.message ? ` · ${catalog.message}` : ''}</span>
              {onRefreshCatalog && (
                <button type="button" onClick={onRefreshCatalog} disabled={busy}>Retry / refresh</button>
              )}
            </div>

            <div className={styles.editorGrid}>
              <label>
                <span>Label</span>
                <input value={draft?.label || ''} onChange={(event) => editDraft('label', event.target.value)} />
              </label>
              <label>
                <span>Layout</span>
                <select value={draft?.layout || 'grid'} onChange={(event) => editDraft('layout', event.target.value)}>
                  {(config.layouts || []).map((layout) => (
                    <option value={layout.id} key={layout.id}>{layout.label || layout.id}</option>
                  ))}
                </select>
              </label>
              <label>
                <span>Channel</span>
                <input value={draft?.channel || ''} onChange={(event) => editDraft('channel', event.target.value)} />
              </label>
              <label>
                <span>Default coordinator</span>
                <select
                  value={draft?.defaultCoordinatorMode || 'human'}
                  onChange={(event) => editDraft('defaultCoordinatorMode', event.target.value)}
                >
                  <option value="human">Human</option>
                  <option value="agent">Agent</option>
                </select>
              </label>
              <label className={styles.wideField}>
                <span>Description</span>
                <input value={draft?.description || ''} onChange={(event) => editDraft('description', event.target.value)} />
              </label>
              <label>
                <span>Required Nosh profiles</span>
                <input
                  value={draft?.requiredNoshProfilesText ?? (draft?.requiredNoshProfiles || []).join(', ')}
                  onChange={(event) => editDraft('requiredNoshProfilesText', event.target.value)}
                  placeholder="agents, python"
                />
              </label>
            </div>

            <AgentSpecEditor
              agents={draft?.agents || []}
              prompts={config.prompts || []}
              modelCatalog={modelCatalog}
              launchCatalog={launchCatalog}
              onChange={(agents) => editDraft('agents', agents)}
              onEditPrompt={editPrompt}
              onCreatePrompt={createPrompt}
            />

            <AgentSpecEditor
              sectionLabel="Coordinator fallback"
              maxRows={1}
              agents={draft?.coordinatorSpec ? [draft.coordinatorSpec] : []}
              prompts={config.prompts || []}
              modelCatalog={modelCatalog}
              launchCatalog={launchCatalog}
              onChange={(agents) => editDraft('coordinatorSpec', agents[0] || null)}
              onEditPrompt={editPrompt}
            />

            {validationError && <div className={styles.formError} role="alert">{validationError}</div>}
            <div className={styles.editorActions}>
              <span>{sourceLabel(selected.source)} source remains unchanged until save</span>
              <button type="submit" disabled={busy}>
                {busy ? 'Saving…' : hasOverride ? 'Save override' : 'Create override'}
              </button>
            </div>
          </form>
        )}

        {panel === 'roles' && (
          <PromptLibrary
            config={config}
            scope={scope}
            onChangeScope={changeScope}
            selectedPromptId={selectedPromptId}
            onSelectPrompt={(promptId) => {
              setSelectedPromptId(promptId);
              setCreatingPrompt(false);
            }}
            creatingPrompt={creatingPrompt}
            onCreatePrompt={() => setCreatingPrompt(true)}
            onSavePrompt={onSavePrompt}
            onRemovePrompt={onRemovePrompt}
            busy={busy}
          />
        )}
      </section>
    </div>
  );
}
