#!/usr/bin/env node
'use strict';

const { randomUUID } = require('crypto');
const childProcess = require('child_process');
const fs = require('fs');
const http = require('http');
const path = require('path');
const process = require('process');

const {
    COLLAB_SESSION_MCP_SERVER,
    buildLaunchCommand,
    createConfigStore,
    createEventHub,
    createLaunchCatalog,
    createSessionManager,
    defaultAgySafetyArgs,
    defaultClaudeSafetyArgs,
    defaultCodexPermissionMode,
    defaultCodexSafetyArgs,
    modelReasoningConfig,
    mcpTransportFor,
    normalizeAgentRuntime,
    normalizeAgentThink,
    normalizeLaunchTarget,
    prepareOllamaCodexProvider,
    removeOllamaModelCatalog,
} = require('./lib/collab/index.cjs');
const { createIrcTerminalUi } = require('./lib/collab/terminal-ui.cjs');
const { createTelemetryStore } = require('./lib/collab/telemetry.cjs');
const {
    childEnvironmentAssignments,
    sanitizeChildEnvironment,
} = require('./lib/childEnvironment.cjs');

function readEarlyCliOption(name) {
    const prefix = `--${name}=`;
    for (let index = 2; index < process.argv.length; index += 1) {
        const token = process.argv[index];
        if (token.startsWith(prefix)) {
            return token.slice(prefix.length);
        }
        if (token === `--${name}` && process.argv[index + 1] && !process.argv[index + 1].startsWith('--')) {
            return process.argv[index + 1];
        }
    }
    return '';
}

const APP_ROOT = path.resolve(__dirname);
const WORKSPACE_ROOT = path.resolve(readEarlyCliOption('workdir') || process.env.NOTTY_WORKDIR || process.cwd());
const ROOT = WORKSPACE_ROOT;
const AGENTS_DIR = path.join(ROOT, 'agents');
const ACTIVE_DIR = path.join(AGENTS_DIR, 'active');
const MSGS_DIR = path.join(AGENTS_DIR, 'msgs');
const COLLAB_DIR = path.join(ROOT, 'collab', 'intragent');
const CHANNELS_DIR = path.join(COLLAB_DIR, 'channels');
const MANAGED_AGENTS_PATH = path.join(COLLAB_DIR, 'managed_agents.json');
const MESSAGE_FEEDBACK_PATH = path.join(COLLAB_DIR, 'message_feedback.jsonl');
const CONFIG_STORE = createConfigStore({ appRoot: APP_ROOT, workspaceRoot: WORKSPACE_ROOT });
const EVENT_HUB = createEventHub();
const LAUNCH_CATALOG = createLaunchCatalog({
    appRoot: APP_ROOT,
    environment: sanitizeChildEnvironment(process.env),
});
let SESSION_MANAGER = null;
const TELEMETRY_STORE = createTelemetryStore({
    feedbackPath: MESSAGE_FEEDBACK_PATH,
    eventHub: EVENT_HUB,
    getSession: () => SESSION_MANAGER ? SESSION_MANAGER.getSession() : null,
    findMessage: findChannelMessage,
    forEachMessage: forEachStoredChannelMessage,
});
const MAX_JSON_BODY_BYTES = 1024 * 1024;
const MAX_CHANNEL_RECORD_BYTES = MAX_JSON_BODY_BYTES + (64 * 1024);
const MAX_CHANNEL_READ_BYTES = MAX_CHANNEL_RECORD_BYTES;
const IRC_STYLE_RESET = '\x1b[0m';
const IRC_STYLE_TIME = '\x1b[1;33m';
const IRC_STYLE_CHANNEL = '\x1b[1;36m';
const IRC_STYLE_USER = '\x1b[1;32m';
const IRC_STYLE_DEST = '\x1b[1;35m';
const IRC_STYLE_CODE = '\x1b[1;34m';
const IRC_STYLE_HEADING = '\x1b[1;34m';
const IRC_STYLE_BOLD = '\x1b[1m';
const IRC_STYLE_MAGENTA = '\x1b[1;35m';
const IRC_STYLE_KIND_JOIN = '\x1b[1;32m';
const IRC_STYLE_KIND_MESSAGE = '\x1b[1;31m';
const IRC_STYLE_PROMPT_USER = '\x1b[1;93m';
const IRC_STYLE_PROMPT_CHANNEL = '\x1b[1;96m';
const IRC_GLYPH = {
    coordinator: '⚙',
    scout: '🔍',
    coder: '✎',
    tester: '🧪',
    logger: '📝',
    human: '👤',
};
const IRC_ROLE_COLOR = {
    coordinator: IRC_STYLE_CHANNEL,
    scout: IRC_STYLE_TIME,
    coder: IRC_STYLE_MAGENTA,
    tester: IRC_STYLE_KIND_JOIN,
    logger: IRC_STYLE_CODE,
    human: '\x1b[97m',
};

ensureDir(MSGS_DIR);
ensureDir(CHANNELS_DIR);

const REGISTERED_MCP_AGENTS = new Map();
const PENDING_AGENT_WORK = new Map();

function clearDirectoryFiles(dirPath) {
    if (!fs.existsSync(dirPath)) {
        return 0;
    }

    let removed = 0;
    for (const name of fs.readdirSync(dirPath)) {
        const fullPath = path.join(dirPath, name);
        const stat = fs.statSync(fullPath);
        if (!stat.isFile()) {
            continue;
        }
        fs.unlinkSync(fullPath);
        removed += 1;
    }
    return removed;
}

function clearFileIfPresent(filePath) {
    if (!fs.existsSync(filePath)) {
        return 0;
    }

    const stat = fs.statSync(filePath);
    if (!stat.isFile()) {
        return 0;
    }

    fs.unlinkSync(filePath);
    return 1;
}

function resetCollabRuntimeState() {
    REGISTERED_MCP_AGENTS.clear();
    PENDING_AGENT_WORK.clear();

    return {
        active: clearDirectoryFiles(ACTIVE_DIR),
        msgs: clearDirectoryFiles(MSGS_DIR),
        channels: clearDirectoryFiles(CHANNELS_DIR),
        managed_agents: clearFileIfPresent(MANAGED_AGENTS_PATH),
        feedback: TELEMETRY_STORE.clear(),
    };
}

function readManagedAgents() {
    if (!fs.existsSync(MANAGED_AGENTS_PATH)) {
        return {};
    }

    const parsed = safeJson(fs.readFileSync(MANAGED_AGENTS_PATH, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return {};
    }

    return parsed;
}

function writeManagedAgents(data) {
    ensureDir(path.dirname(MANAGED_AGENTS_PATH));
    const temporary = `${MANAGED_AGENTS_PATH}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
    fs.renameSync(temporary, MANAGED_AGENTS_PATH);
}

function tmuxSessionExists(target) {
    const cleanTarget = sanitize(target, '');
    if (!cleanTarget) {
        return false;
    }

    const result = childProcess.spawnSync('tmux', ['has-session', '-t', cleanTarget], {
        stdio: 'ignore',
    });

    return result.status === 0;
}

function getRegisteredAgentSessions(agent) {
    const cleanAgent = sanitize(agent, '');
    if (!cleanAgent) {
        return [];
    }

    return Array.from(REGISTERED_MCP_AGENTS.values()).filter((entry) => entry && entry.agent === cleanAgent);
}

function describeManagedAgentEntry(agent) {
    const managed = getManagedAgentEntry(agent);
    if (!managed) {
        return null;
    }

    const sessions = getRegisteredAgentSessions(managed.agent);
    const pending = getPendingSummary(managed.agent);
    const tmuxAlive = tmuxSessionExists(managed.target);
    const status = sessions.length === 0
        ? 'unregistered'
        : sessions.every((entry) => entry.status !== 'busy')
            ? 'idle'
            : 'busy';

    return {
        agent: managed.agent,
        target: managed.target,
        timestamp: managed.added_at || '',
        role: managed.role || managed.agent,
        harness: managed.harness || (managed.runtime === 'ollama' ? 'codex' : managed.runtime || 'codex'),
        backend: managed.backend || (managed.runtime === 'ollama' ? 'ollama' : 'default'),
        runtime: managed.runtime || 'codex',
        model: managed.model || '',
        think: managed.think || '',
        session_id: managed.session_id || '',
        runtime_session_id: managed.runtime_session_id || '',
        permission_mode: managed.permission_mode || '',
        tmux_alive: tmuxAlive,
        registered: sessions.length > 0,
        sessions: sessions.length,
        status,
        pending,
    };
}

function formatManagedAgentRow(row) {
    const parts = [
        row.agent,
        row.target,
        row.tmux_alive ? 'tmux:up' : 'tmux:down',
        row.registered ? `mcp:${row.status}` : 'mcp:unregistered',
        `runtime:${row.runtime || 'codex'}`,
    ];
    if (row.model) {
        parts.push(`model:${row.model}`);
    }
    if (row.think) {
        parts.push(`think:${row.think}`);
    }
    const pendingText = formatPendingSummary(row.pending);
    if (pendingText) {
        parts.push(`pending:${pendingText}`);
    }
    if (row.timestamp) {
        parts.push(row.timestamp);
    }
    return parts.join('\t');
}

function listManagedAgentRows() {
    return Object.keys(readManagedAgents())
        .sort((left, right) => left.localeCompare(right))
        .map((agent) => describeManagedAgentEntry(agent))
        .filter(Boolean);
}

function getManagedAgentNudge(row) {
    if (!row || !row.tmux_alive) {
        return null;
    }

    if (row.registered) {
        if (row.status !== 'idle') {
            return null;
        }

        return {
            kind: 'claim',
            body: 'Call the collab MCP tool claim_pending once. Read indicated messages and act only on explicit assignments. If there is no assignment, end your turn silently; do not report ready/idle or poll again.',
        };
    }

    return {
        kind: 'bootstrap',
        body: `Use the configured collab MCP service, set your nickname to ${row.agent}, set_status("idle"), and call claim_pending() once. Read indicated messages and act only on explicit assignments. Otherwise end silently. If MCP is unavailable, report one failure and stop; do not explore or debug the service.`,
    };
}

function normalizeManagedCommand(parts) {
    if (!Array.isArray(parts)) {
        return ['codex'];
    }

    const clean = parts.map((part) => String(part)).filter((part) => part.length > 0);
    return clean.length > 0 ? clean : ['codex'];
}

function appendManagedBootstrap(command, runtime, prompt) {
    if (!prompt) {
        return command;
    }
    return runtime === 'agy'
        ? [...command, '--prompt-interactive', prompt]
        : [...command, prompt];
}

function rejectAgentSpawnOtp(input = {}) {
    const keys = ['spawnOtp', 'spawn_otp', 'spawn-otp', 'otp'];
    const key = keys.find((name) => Object.prototype.hasOwnProperty.call(input, name));
    if (
        key
        && input[key] !== undefined
        && input[key] !== null
        && input[key] !== ''
    ) {
        throw new Error(
            'Agent OTP delivery is not supported; enter a spawn OTP directly in each terminal-spawn request.',
        );
    }
}

function resolveLaunchTargetInput(input = {}, fallback = {}) {
    const source = input && typeof input === 'object' ? input : {};
    const base = fallback && typeof fallback === 'object' ? fallback : {};
    const hasRuntime = Object.prototype.hasOwnProperty.call(source, 'runtime')
        && source.runtime !== undefined
        && source.runtime !== null
        && String(source.runtime).trim();
    const target = normalizeLaunchTarget({
        ...base,
        ...(hasRuntime ? { runtime: source.runtime } : {}),
        ...(source.harness ? { harness: source.harness } : {}),
        ...(source.backend ? { backend: source.backend } : {}),
    });
    if (hasRuntime && (source.harness || source.backend)) {
        const legacy = normalizeLaunchTarget({ runtime: source.runtime });
        if (legacy.harness !== target.harness || legacy.backend !== target.backend) {
            throw new Error('--runtime conflicts with --harness/--backend');
        }
    }
    return target;
}

function buildCreateAgentBootstrapPrompt(options) {
    const agent = sanitize(options.agent, 'agent');
    const role = sanitize(options.role, agent) || agent;
    const channel = resolveChannelName({
        channel: options.channel,
        defaultChannel: 'lobby',
    }, 'lobby');
    const mcpUrl = String(options.mcp_url || options.mcpUrl || 'http://127.0.0.1:1337/mcp').trim() || 'http://127.0.0.1:1337/mcp';

    return [
        `You are the ${role} agent for this tmux session.`,
        `Use the collab MCP service at ${mcpUrl}.`,
        `Your coordination channel is ${channel}. Use set_nickname() to set your nickname to ${agent}, then call set_status("idle") and wait for explicit instructions or a Notty pending-work nudge.`,
        'Do not call claim_pending(), read_messages(), or send_message() during startup. Do not poll, announce readiness, or invent work.',
    ].filter(Boolean).join(' ');
}

function createManagedAgent(options = {}) {
    const agent = sanitize(options.agent, '');
    if (!agent) {
        throw new Error('create-agent requires --agent');
    }

    const target = sanitize(options.target || agent, agent);
    const role = sanitize(options.role || agent, agent);
    const launchTarget = resolveLaunchTargetInput(options);
    const { harness, backend, runtime } = launchTarget;
    const think = normalizeAgentThink(options.think, launchTarget);
    rejectAgentSpawnOtp(options);
    if (runtime === 'ollama' && !String(options.model || '').trim()) {
        throw new Error('ollama agents require a model');
    }
    const channel = resolveChannelName({
        channel: options.channel,
        defaultChannel: 'lobby',
    }, 'lobby');
    const mcpUrl = String(options.mcp_url || options.mcpUrl || 'http://127.0.0.1:1337/mcp').trim() || 'http://127.0.0.1:1337/mcp';
    const workdir = path.resolve(String(options.workdir || ROOT));
    const childEnvironment = sanitizeChildEnvironment(process.env);
    if (getManagedAgentEntry(agent)) {
        throw new Error(`managed agent already exists: ${agent}`);
    }
    if (tmuxSessionExists(target)) {
        throw new Error(`tmux session already exists: ${target}`);
    }
    const bootstrapPrompt = buildCreateAgentBootstrapPrompt({
        agent,
        role,
        channel,
        mcpUrl,
    });
    const explicitCommand = Array.isArray(options.command)
        ? options.command
        : Array.isArray(options._)
            ? options._
            : [];
    const ollamaProvider = explicitCommand.length === 0 && backend === 'ollama'
        ? prepareOllamaCodexProvider({
            model: String(options.model || ''),
            endpoint: options.ollamaEndpoint || options.ollamaHost,
            environment: childEnvironment,
            curlBin: options.curlBin || process.env.CURL_BIN,
            timeoutMs: options.ollamaTimeoutMs,
            runtimeDir: options.ollamaRuntimeDir,
            isolationKey: `standalone:${workdir}:${target}`,
        })
        : null;
    let runtimeSessionId = String(options.runtimeSessionId || options.runtime_session_id || '').trim();
    if (!runtimeSessionId && harness === 'claude') {
        runtimeSessionId = randomUUID();
    }
    const cleanupPreparedCatalog = (error) => {
        if (!ollamaProvider?.catalogPath) return;
        try {
            removeOllamaModelCatalog(ollamaProvider.catalogPath, {
                runtimeDir: options.ollamaRuntimeDir,
                environment: childEnvironment,
            });
        } catch (cleanupError) {
            error.ollamaCatalogPath = ollamaProvider.catalogPath;
            error.ollamaCatalogCleanupError = cleanupError;
        }
    };
    let launchCommand;
    try {
        launchCommand = explicitCommand.length > 0
            ? appendManagedBootstrap(
                normalizeManagedCommand(explicitCommand),
                harness,
                bootstrapPrompt,
            )
            : buildLaunchCommand({
                identity: agent,
                harness,
                backend,
                model: String(options.model || ''),
                think,
            }, {
                prompt: bootstrapPrompt,
                resumeSessionId: options.resume ? runtimeSessionId : '',
                newSessionId: !options.resume && harness === 'claude' ? runtimeSessionId : '',
                mcpUrl,
                mcpServerName: COLLAB_SESSION_MCP_SERVER,
                codexBin: options.codexBin || process.env.CODEX_BIN || 'codex',
                agyBin: options.agyBin || process.env.AGY_BIN || 'agy',
                claudeBin: options.claudeBin || process.env.CLAUDE_BIN || 'claude',
                codexArgs: defaultCodexSafetyArgs(childEnvironment),
                agyArgs: defaultAgySafetyArgs(childEnvironment),
                claudeArgs: defaultClaudeSafetyArgs(childEnvironment),
                ollamaProviderArgs: ollamaProvider?.args,
                environment: childEnvironment,
            });
    } catch (error) {
        cleanupPreparedCatalog(error);
        throw error;
    }

    const created = childProcess.spawnSync(
        'tmux',
        [
            'new-session',
            '-d',
            '-c',
            workdir,
            '-s',
            target,
            '--',
            'env',
            '-i',
            ...childEnvironmentAssignments(childEnvironment),
            `MYID=${agent}`,
            `COLLAB_AGENT_ID=${agent}`,
            `COLLAB_CHANNEL=${channel}`,
            `COLLAB_MCP_URL=${mcpUrl}`,
            `COLLAB_ROLE=${role}`,
            `COLLAB_HARNESS=${harness}`,
            `COLLAB_BACKEND=${backend}`,
            `COLLAB_RUNTIME=${runtime}`,
            `COLLAB_MODEL=${String(options.model || '')}`,
            `COLLAB_THINK=${think}`,
            ...launchCommand,
        ],
        {
            encoding: 'utf8',
            env: childEnvironment,
        },
    );

    if (created.error) {
        if (!tmuxSessionExists(target)) {
            cleanupPreparedCatalog(created.error);
        } else if (ollamaProvider?.catalogPath) {
            created.error.ollamaCatalogPath = ollamaProvider.catalogPath;
        }
        throw created.error;
    }
    if (created.status !== 0) {
        const error = new Error((created.stderr || created.stdout || `tmux new-session failed (${created.status})`).trim());
        if (!tmuxSessionExists(target)) {
            cleanupPreparedCatalog(error);
        } else if (ollamaProvider?.catalogPath) {
            error.ollamaCatalogPath = ollamaProvider.catalogPath;
        }
        throw error;
    }

    let entry = null;
    try {
        if (bootstrapPrompt) {
            sleepMs(200);
        }
        if (!tmuxSessionExists(target)) {
            throw new Error(`tmux session did not stay alive: ${target}`);
        }
        entry = addManagedAgent(agent, target, {
            role,
            harness,
            backend,
            runtime,
            model: options.model,
            think,
            runtimeSessionId,
            permissionMode: Object.hasOwn(options, 'permissionMode')
                ? options.permissionMode
                : '',
        });
    } catch (error) {
        if (entry) {
            removeManagedAgent(agent);
        }
        if (tmuxSessionExists(target)) {
            childProcess.spawnSync('tmux', ['kill-session', '-t', target], { stdio: 'ignore' });
        }
        if (!tmuxSessionExists(target)) {
            cleanupPreparedCatalog(error);
        } else if (ollamaProvider?.catalogPath) {
            error.ollamaCatalogPath = ollamaProvider.catalogPath;
        }
        throw error;
    }

    return {
        agent: entry.agent,
        target: entry.target,
        role,
        harness,
        backend,
        runtime,
        model: String(options.model || ''),
        think,
        channel,
        mcp_url: mcpUrl,
        workdir,
        command: launchCommand,
    };
}

function createManagedAgentCommand(options) {
    const created = createManagedAgent(options);
    process.stdout.write(
        `agent=${created.agent}\ttarget=${created.target}\trole=${created.role}\truntime=${created.runtime}\tmodel=${created.model || 'default'}\tthink=${created.think || 'default'}\tchannel=${created.channel}\tcommand=${created.command.join(' ')}\n`,
    );
}

function listManagedAgentsStatusCommand() {
    const rows = listManagedAgentRows();
    const text = rows.length > 0
        ? rows.map((row) => formatManagedAgentRow(row)).join('\n')
        : 'no managed agents';
    process.stdout.write(`${text}\n`);
}

function getManagedAgentEntry(agent) {
    const cleanAgent = sanitize(agent, '');
    if (!cleanAgent) {
        return null;
    }

    const data = readManagedAgents();
    const entry = data[cleanAgent];
    if (!entry || typeof entry !== 'object') {
        return null;
    }
    const launchTarget = resolveLaunchTargetInput(entry);

    return {
        agent: cleanAgent,
        target: sanitize(entry.target || cleanAgent, cleanAgent),
        added_at: entry.added_at || '',
        role: sanitize(entry.role, ''),
        ...launchTarget,
        model: String(entry.model || ''),
        think: normalizeAgentThink(entry.think || '', launchTarget),
        session_id: String(entry.session_id || ''),
        runtime_session_id: String(entry.runtime_session_id || ''),
        permission_mode: String(entry.permission_mode || ''),
    };
}

function listManagedAgentEntries() {
    const data = readManagedAgents();
    return Object.keys(data)
        .sort()
        .map((agent) => getManagedAgentEntry(agent))
        .filter(Boolean);
}

function addManagedAgent(agent, target, metadata = {}) {
    const cleanAgent = sanitize(agent, '');
    const cleanTarget = sanitize(target || cleanAgent, cleanAgent);
    if (!cleanAgent || !cleanTarget) {
        fail('managed agent requires agent id');
    }

    const data = readManagedAgents();
    const current = data[cleanAgent] || {};
    const launchTarget = resolveLaunchTargetInput(metadata, current);
    const { harness, backend, runtime } = launchTarget;
    const thinkInput = Object.hasOwn(metadata, 'think') ? metadata.think : current.think || '';
    const think = normalizeAgentThink(thinkInput, launchTarget);
    const runtimeSessionId = Object.hasOwn(metadata, 'runtimeSessionId')
        ? metadata.runtimeSessionId
        : Object.hasOwn(metadata, 'runtime_session_id')
            ? metadata.runtime_session_id
            : current.runtime_session_id || '';
    const permissionMode = Object.hasOwn(metadata, 'permissionMode')
        ? metadata.permissionMode
        : Object.hasOwn(metadata, 'permission_mode')
            ? metadata.permission_mode
            : current.permission_mode || '';
    data[cleanAgent] = {
        ...current,
        target: cleanTarget,
        added_at: current.added_at || new Date().toISOString(),
        role: sanitize(metadata.role || current.role, ''),
        harness,
        backend,
        runtime,
        model: String(metadata.model || current.model || ''),
        think,
        session_id: String(metadata.sessionId || metadata.session_id || current.session_id || ''),
        runtime_session_id: String(runtimeSessionId || ''),
        permission_mode: String(permissionMode || ''),
    };
    writeManagedAgents(data);
    return getManagedAgentEntry(cleanAgent);
}

function removeManagedAgent(agent) {
    const cleanAgent = sanitize(agent, '');
    if (!cleanAgent) {
        fail('managed agent requires agent id');
    }

    const data = readManagedAgents();
    if (!(cleanAgent in data)) {
        return false;
    }

    delete data[cleanAgent];
    writeManagedAgents(data);
    return true;
}

function registerMcpAgentSession(sessionId, agent) {
    const cleanSessionId = sanitize(sessionId, '');
    const cleanAgent = sanitize(agent, '');
    if (!cleanSessionId || !cleanAgent) {
        return;
    }

    const now = new Date().toISOString();
    const current = REGISTERED_MCP_AGENTS.get(cleanSessionId) || {
        connectedAt: now,
        status: 'idle',
        statusUpdatedAt: now,
    };

    if (current.agent && current.agent !== cleanAgent) {
        EVENT_HUB.emit('agent.registration', {
            agent: current.agent,
            sessionId: cleanSessionId,
            registered: false,
        });
    }

    REGISTERED_MCP_AGENTS.set(cleanSessionId, {
        ...current,
        sessionId: cleanSessionId,
        agent: cleanAgent,
        updatedAt: now,
    });
    EVENT_HUB.emit('agent.registration', {
        agent: cleanAgent,
        sessionId: cleanSessionId,
        registered: true,
    });
}

function unregisterMcpAgentSession(sessionId) {
    const cleanSessionId = sanitize(sessionId, '');
    if (!cleanSessionId) {
        return;
    }

    const current = REGISTERED_MCP_AGENTS.get(cleanSessionId);
    REGISTERED_MCP_AGENTS.delete(cleanSessionId);
    if (current) {
        EVENT_HUB.emit('agent.registration', {
            agent: current.agent,
            sessionId: cleanSessionId,
            registered: false,
        });
    }
}

function clearAgentRuntime(agent) {
    const cleanAgent = sanitize(agent, '');
    if (!cleanAgent) {
        return;
    }
    for (const [sessionId, entry] of REGISTERED_MCP_AGENTS) {
        if (entry && entry.agent === cleanAgent) {
            REGISTERED_MCP_AGENTS.delete(sessionId);
            EVENT_HUB.emit('agent.registration', {
                agent: cleanAgent,
                sessionId,
                registered: false,
            });
        }
    }
    PENDING_AGENT_WORK.delete(cleanAgent);
    EVENT_HUB.emit('agent.pending', { agent: cleanAgent, pending: getPendingSummary(cleanAgent) });
}

function setMcpAgentSessionStatus(sessionId, agent, status) {
    const cleanSessionId = sanitize(sessionId, '');
    const cleanAgent = sanitize(agent, '');
    const cleanStatus = String(status || '').trim().toLowerCase();
    if (!cleanSessionId || (cleanStatus !== 'busy' && cleanStatus !== 'idle')) {
        return '';
    }

    const now = new Date().toISOString();
    const current = REGISTERED_MCP_AGENTS.get(cleanSessionId);

    if (!current) {
        if (!cleanAgent) {
            return '';
        }

        REGISTERED_MCP_AGENTS.set(cleanSessionId, {
            sessionId: cleanSessionId,
            agent: cleanAgent,
            connectedAt: now,
            updatedAt: now,
            status: cleanStatus,
            statusUpdatedAt: now,
        });
        if (cleanStatus === 'idle') {
            nudgeManagedAgentIfNeeded(cleanAgent);
        }
        EVENT_HUB.emit('agent.status', { agent: cleanAgent, status: cleanStatus });
        return cleanStatus;
    }

    const nextAgent = cleanAgent || current.agent;
    REGISTERED_MCP_AGENTS.set(cleanSessionId, {
        ...current,
        agent: nextAgent,
        updatedAt: now,
        status: cleanStatus,
        statusUpdatedAt: now,
    });
    if (cleanStatus === 'idle') {
        nudgeManagedAgentIfNeeded(nextAgent);
    }
    EVENT_HUB.emit('agent.status', { agent: nextAgent, status: cleanStatus });
    return cleanStatus;
}

function listRegisteredAgentIds() {
    return Array.from(new Set(
        Array.from(REGISTERED_MCP_AGENTS.values())
            .map((entry) => entry && entry.agent ? entry.agent : '')
            .filter(Boolean),
    )).sort();
}

function getOrCreatePendingAgentWork(agent) {
    const cleanAgent = sanitize(agent, '');
    if (!cleanAgent) {
        return null;
    }

    const current = PENDING_AGENT_WORK.get(cleanAgent);
    if (current) {
        return current;
    }

    const created = {
        directCount: 0,
        channels: new Set(),
        updatedAt: '',
        nudgeKey: '',
    };
    PENDING_AGENT_WORK.set(cleanAgent, created);
    return created;
}

function markPendingDirectForAgent(agent) {
    const pending = getOrCreatePendingAgentWork(agent);
    if (!pending) {
        return;
    }

    pending.directCount += 1;
    pending.updatedAt = new Date().toISOString();
    pending.nudgeKey = '';
    EVENT_HUB.emit('agent.pending', { agent: sanitize(agent, ''), pending: getPendingSummary(agent) });
}

function markPendingChannelForAgent(agent, channel) {
    const pending = getOrCreatePendingAgentWork(agent);
    const cleanChannel = sanitize(channel, '');
    if (!pending || !cleanChannel) {
        return;
    }

    pending.channels.add(cleanChannel);
    pending.updatedAt = new Date().toISOString();
    pending.nudgeKey = '';
    EVENT_HUB.emit('agent.pending', { agent: sanitize(agent, ''), pending: getPendingSummary(agent) });
}

function isRegisteredAgentIdle(agent) {
    const cleanAgent = sanitize(agent, '');
    if (!cleanAgent) {
        return false;
    }

    const sessions = Array.from(REGISTERED_MCP_AGENTS.values()).filter((entry) => entry && entry.agent === cleanAgent);
    if (sessions.length === 0) {
        return false;
    }

    return sessions.every((entry) => entry.status !== 'busy');
}

function getPendingSummaryKey(summary) {
    return `d:${summary.directCount}|c:${summary.channels.join(',')}`;
}

function nudgeManagedAgentIfNeeded(agent) {
    const row = describeManagedAgentEntry(agent);
    if (!row) {
        return false;
    }

    const summary = row.pending;
    if (summary.directCount === 0 && summary.channels.length === 0) {
        return false;
    }

    const nudge = getManagedAgentNudge(row);
    if (!nudge) {
        return false;
    }

    const pending = getOrCreatePendingAgentWork(row.agent);
    const nextKey = `${nudge.kind}|${getPendingSummaryKey(summary)}`;
    if (!pending || pending.nudgeKey === nextKey) {
        return false;
    }

    try {
        tmuxSendKeys({
            target: row.target,
            body: nudge.body,
            enter: true,
            delay_ms: 200,
            fatal: false,
            quiet: true,
            _: [],
        });
        pending.nudgeKey = nextKey;
        return true;
    } catch (_error) {
        return false;
    }
}

function getPendingSummary(agent) {
    const cleanAgent = sanitize(agent, '');
    const pending = cleanAgent ? PENDING_AGENT_WORK.get(cleanAgent) : null;
    const channels = pending ? Array.from(pending.channels).sort() : [];
    return {
        directCount: pending ? pending.directCount : 0,
        channels,
        updatedAt: pending ? pending.updatedAt : '',
    };
}

function formatPendingSummary(summary) {
    const parts = [];
    if (summary.directCount > 0) {
        parts.push(`direct=${summary.directCount}`);
    }
    if (summary.channels.length > 0) {
        parts.push(`channels=${summary.channels.join(',')}`);
    }
    return parts.join(',');
}

function buildPendingInstructions(summary) {
    const instructions = [];
    if (summary.directCount > 0) {
        instructions.push('check messages on collab');
    }
    for (const channel of summary.channels) {
        instructions.push(`check ${channel} channel on collab`);
    }
    return instructions;
}

function claimPendingForAgent(agent) {
    const cleanAgent = sanitize(agent, '');
    const summary = getPendingSummary(cleanAgent);
    const payload = {
        agent: cleanAgent,
        direct_count: summary.directCount,
        channels: summary.channels,
        has_pending: summary.directCount > 0 || summary.channels.length > 0,
        next: buildPendingInstructions(summary),
        updated_at: summary.updatedAt || '',
    };

    if (cleanAgent) {
        PENDING_AGENT_WORK.delete(cleanAgent);
        EVENT_HUB.emit('agent.pending', { agent: cleanAgent, pending: getPendingSummary(cleanAgent) });
    }

    return payload;
}

function shouldFanoutChannelPending(record) {
    if (record?.author_type === 'human') return true;
    const sender = sanitize(record && record.agent_id, '');
    if (!sender) {
        return false;
    }

    const session = SESSION_MANAGER ? SESSION_MANAGER.getSession() : null;
    const sessionAgent = session && Array.isArray(session.agents)
        ? session.agents.find((agent) => agent && agent.identity === sender)
        : null;
    if (sessionAgent && sessionAgent.coordinatorCapable) {
        return true;
    }

    return session ? false : !getManagedAgentEntry(sender);
}

function markPendingForRecord(record) {
    if (!record || record.kind !== 'message') {
        return;
    }

    const sender = sanitize(record.agent_id, '');
    const recipient = sanitize(record.to || 'all', 'all');

    if (recipient && recipient !== 'all') {
        if (recipient === sender) {
            return;
        }

        markPendingDirectForAgent(recipient);
        nudgeManagedAgentIfNeeded(recipient);
        return;
    }

    if (!shouldFanoutChannelPending(record)) {
        return;
    }

    const recipients = new Set();
    for (const agent of listRegisteredAgentIds()) {
        if (agent !== sender) {
            recipients.add(agent);
        }
    }
    for (const row of listManagedAgentRows()) {
        if (row.agent !== sender) {
            recipients.add(row.agent);
        }
    }

    for (const agent of recipients) {
        markPendingChannelForAgent(agent, record.channel || 'lobby');
        nudgeManagedAgentIfNeeded(agent);
    }
}

function listRegisteredMcpAgentEntries() {
    const grouped = new Map();

    for (const entry of REGISTERED_MCP_AGENTS.values()) {
        if (!entry || !entry.agent) {
            continue;
        }

        const current = grouped.get(entry.agent);
        if (!current) {
            grouped.set(entry.agent, {
                agent: entry.agent,
                status: entry.status === 'busy' ? 'busy' : 'idle',
                lock: 'mcp',
                timestamp: entry.updatedAt || entry.connectedAt || '-',
                sessions: 1,
            });
            continue;
        }

        current.sessions += 1;
        if (entry.status === 'busy') {
            current.status = 'busy';
        }
        if ((entry.updatedAt || '') > (current.timestamp || '')) {
            current.timestamp = entry.updatedAt;
        }
    }

    return Array.from(grouped.values())
        .sort((left, right) => left.agent.localeCompare(right.agent))
        .map((row) => {
            const pending = getPendingSummary(row.agent);
            const stateParts = [row.status];
            if (row.sessions > 1) {
                stateParts.push(`sessions:${row.sessions}`);
            }
            const pendingText = formatPendingSummary(pending);
            if (pendingText) {
                stateParts.push(`pending:${pendingText}`);
            }
            return {
                agent: row.agent,
                state: stateParts.join(' '),
                lock: row.lock,
                timestamp: row.timestamp,
            };
        });
}

function listKnownAgentEntries() {
    const merged = new Map();

    for (const row of listActiveAgentEntries()) {
        merged.set(row.agent, { ...row });
    }

    for (const row of listRegisteredMcpAgentEntries()) {
        const current = merged.get(row.agent);
        if (!current) {
            merged.set(row.agent, { ...row });
            continue;
        }

        merged.set(row.agent, {
            agent: row.agent,
            state: `${current.state} mcp:${row.state}`,
            lock: current.lock || row.lock,
            timestamp: (row.timestamp || '') > (current.timestamp || '') ? row.timestamp : current.timestamp,
        });
    }

    return Array.from(merged.values()).sort((left, right) => left.agent.localeCompare(right.agent));
}

function normalizeChannelName(value, fallback = 'lobby') {
    const raw = String(value || '').trim().replace(/^#+/, '');
    if (!raw) {
        return fallback;
    }
    return sanitize(raw, fallback);
}

function resolveTmuxTarget(input) {
    const target = input && (input.target || input.session)
        ? String(input.target || input.session).trim()
        : '';
    if (!target) {
        fail('tmux target is required (--target coder:0.0 or --session coder)');
    }
    return target;
}

function runTmux(args, fatal = true) {
    const result = childProcess.spawnSync('tmux', args, {
        encoding: 'utf8',
    });

    if (result.error) {
        if (!fatal) {
            throw result.error;
        }
        fail(result.error.message || String(result.error));
    }

    if (result.status !== 0) {
        const message = (result.stderr || result.stdout || `tmux ${args.join(' ')} failed`).trim();
        if (!fatal) {
            throw new Error(message);
        }
        fail(message);
    }

    return result.stdout || '';
}

function sleepMs(ms) {
    const delay = toNonNegativeInt(ms, 0);
    if (delay <= 0) {
        return;
    }

    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delay);
}

const args = process.argv.slice(2);
const command = args[0] || 'watch';
const opts = parseArgs(args.slice(1));
const REMOTE_CLI_COMMANDS = new Set([
    'send',
    'msg',
    'join',
    'create-agent',
    'resume-agent',
    'add-agent',
    'remove-agent',
    'managed-agents',
    'agents',
    'who',
    'channels',
    'list',
    'tmux-send',
    'tmux-read',
]);

main().catch((error) => {
    process.stderr.write(`${error && error.message ? error.message : String(error)}\n`);
    process.exitCode = 1;
});

async function main() {
    const standalone = toBoolean(opts.standalone, false)
        || toBoolean(process.env.NOTTY_COLLAB_STANDALONE, false);

    if (!standalone && command === 'mirror') {
        return await startRemoteMirror(opts);
    }

    if (!standalone && REMOTE_CLI_COMMANDS.has(command)) {
        if (toBoolean(opts.fresh, false)) {
            fail('--fresh is not valid for daemon-backed commands; stop the active session or use --standalone explicitly');
        }
        return await runRemoteCliCommand(command, opts);
    }

    if (command === 'irc' && !standalone) {
        if (toBoolean(opts.fresh, false)) {
            fail('--fresh is not valid for a daemon-backed IRC client; use --standalone explicitly for legacy local mode');
        }
        return await startRemoteIrc({
            ...opts,
            server: resolveRemoteDaemonUrl(opts),
        });
    }

    if (command === 'mcp' && !standalone && toBoolean(opts.fresh, false)) {
        fail('--fresh is not valid for a daemon-backed MCP proxy; use --standalone explicitly for legacy local mode');
    }

    if (toBoolean(opts.fresh, false) && (command === 'irc' || command === 'mcp')) {
        const cleared = resetCollabRuntimeState();
        process.stdout.write(
            `fresh start: cleared active=${cleared.active} msgs=${cleared.msgs} channels=${cleared.channels} managed_agents=${cleared.managed_agents} feedback=${cleared.feedback}\n`,
        );
    }

    switch (command) {
        case 'msg':
        case 'send':
            return sendMessage(opts);
        case 'create-agent':
            return createAgentScriptCommand(opts);
        case 'resume-agent':
            return resumeAgentScriptCommand(opts);
        case 'add-agent':
            return addManagedAgentCommand(opts);
        case 'remove-agent':
            return removeManagedAgentCommand(opts);
        case 'managed-agents':
            return listManagedAgentsStatusCommand();
        case 'tail':
            return tailChannel(opts);
        case 'watch':
            return watchBus(opts);
        case 'mirror':
            return mirrorBus(opts);
        case 'join':
            return joinChannel(opts);
        case 'agents':
            return listAgents();
        case 'who':
            return listParticipants(opts);
        case 'channels':
        case 'list':
            return listChannels();
        case 'tmux-send':
            return tmuxSendKeys(opts);
        case 'tmux-read':
            return tmuxReadPane(opts);
        case 'irc':
            return startIrc(opts);
        case 'daemon': {
            const daemonHost = resolveListenHost(opts.ip, '127.0.0.1');
            if (daemonHost !== '127.0.0.1' && daemonHost !== '::1' && daemonHost !== 'localhost') {
                fail('collab daemon only listens on a loopback address');
            }
            return await startMcpServer({ ...opts, transport: 'sse' });
        }
        case 'mcp':
            return await startMcpServer(opts);
        case 'help':
        default:
            printHelp();
    }
}

function resolveRemoteDaemonUrl(input = {}) {
    const value = String(
        input.server
        || input.url
        || input['mcp-url']
        || input.mcp_url
        || defaultAgentMcpUrl(),
    ).trim();
    const parsed = new URL(value);
    if (parsed.protocol !== 'http:') {
        fail('collab daemon URL must use http://');
    }
    return parsed.origin;
}

function remoteCommandInput(input = {}) {
    const body = { ...input };
    delete body.server;
    delete body.url;
    delete body.standalone;
    delete body.fresh;
    return body;
}

function printRemoteCommandResult(commandName, result) {
    if (commandName === 'send' || commandName === 'msg' || commandName === 'join') {
        process.stdout.write(`${formatRecord(result)}\n`);
        return;
    }
    if (commandName === 'tmux-read') {
        process.stdout.write(`${String(result || '').replace(/\n?$/, '\n')}`);
        return;
    }
    if (commandName === 'tmux-send') {
        process.stdout.write(`${result}\n`);
        return;
    }
    if (commandName === 'managed-agents') {
        const rows = Array.isArray(result) ? result : [];
        process.stdout.write(`${rows.length > 0 ? rows.map(formatManagedAgentRow).join('\n') : 'no managed agents'}\n`);
        return;
    }
    if (commandName === 'agents') {
        const rows = Array.isArray(result) ? result : [];
        process.stdout.write(`${rows.length > 0
            ? rows.map((row) => `${row.agent}\t${row.state}\t${row.lock}\t${row.timestamp}`).join('\n')
            : 'no active agents'}\n`);
        return;
    }
    if (commandName === 'who') {
        const rows = Array.isArray(result?.participants) ? result.participants : [];
        process.stdout.write(`${rows.length > 0
            ? rows.map((row) => `${row.agent}\t${row.status}\t${row.lock}\tlast_msg:${row.lastMsg}`).join('\n')
            : `no participants in #${result?.channel || 'lobby'}`}\n`);
        return;
    }
    if (commandName === 'channels' || commandName === 'list') {
        const rows = Array.isArray(result) ? result : [];
        process.stdout.write(`${rows.length > 0
            ? rows.map((row) => `${row.channel}\t${row.bytes} bytes\t${row.updatedAt}`).join('\n')
            : 'no channels yet'}\n`);
        return;
    }
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

async function runRemoteCliCommand(commandName, input) {
    const response = await requestRemoteJson(
        resolveRemoteDaemonUrl(input),
        'POST',
        `/admin/v1/commands/${encodeURIComponent(commandName)}`,
        remoteCommandInput(input),
    );
    printRemoteCommandResult(commandName, response.result);
    return response.result;
}

function parseArgs(argv) {
    const parsed = { _: [] };

    for (let i = 0; i < argv.length; i += 1) {
        const token = argv[i];
        if (token === '--') {
            parsed._.push(...argv.slice(i + 1));
            break;
        }
        if (!token.startsWith('--')) {
            parsed._.push(token);
            continue;
        }

        const eqIndex = token.indexOf('=');
        if (eqIndex !== -1) {
            const key = token.slice(2, eqIndex);
            const value = token.slice(eqIndex + 1);
            parsed[key] = value;
            continue;
        }

        const key = token.slice(2);
        const next = argv[i + 1];
        if (!next || next.startsWith('--')) {
            parsed[key] = true;
            continue;
        }

        parsed[key] = next;
        i += 1;
    }

    return parsed;
}

function tokenizeCommandLine(value) {
    const tokens = [];
    let token = '';
    let quote = '';
    let escaped = false;
    let started = false;

    for (const character of String(value || '')) {
        if (escaped) {
            token += character;
            escaped = false;
            started = true;
            continue;
        }
        if (character === '\\') {
            escaped = true;
            started = true;
            continue;
        }
        if (quote) {
            if (character === quote) {
                quote = '';
            } else {
                token += character;
            }
            started = true;
            continue;
        }
        if (character === '"' || character === "'") {
            quote = character;
            started = true;
            continue;
        }
        if (/\s/.test(character)) {
            if (started) {
                tokens.push(token);
                token = '';
                started = false;
            }
            continue;
        }
        token += character;
        started = true;
    }

    if (quote) {
        throw new Error(`unterminated ${quote === '"' ? 'double' : 'single'} quote`);
    }
    if (escaped) {
        throw new Error('command cannot end with an escape character');
    }
    if (started) {
        tokens.push(token);
    }
    return tokens;
}

function parseIrcCreateAgentArgs(argv) {
    const input = parseArgs(Array.isArray(argv) ? argv : []);
    for (const name of ['agent', 'name', 'id', 'role', 'runtime', 'harness', 'backend', 'model']) {
        if (!Object.prototype.hasOwnProperty.call(input, name)) {
            continue;
        }
        if (typeof input[name] !== 'string' || !input[name].trim()) {
            throw new Error(`--${name} requires a value`);
        }
    }

    const explicitRole = input.role || '';
    const agent = sanitize(
        input.agent || input.name || input.id || input._[0] || explicitRole,
        '',
    );
    if (!agent) {
        throw new Error('usage: /create_agent <agent> [role] or /create_agent --role <role>');
    }

    const launchTarget = resolveLaunchTargetInput(input);
    const { harness, backend, runtime } = launchTarget;
    const model = typeof input.model === 'string' ? input.model.trim() : '';
    const think = normalizeAgentThink(input.think, launchTarget);
    rejectAgentSpawnOtp(input);
    if (runtime === 'ollama' && !model) {
        throw new Error('/create_agent --runtime ollama requires --model');
    }

    return {
        agent,
        role: sanitize(explicitRole || input._[1] || agent, agent),
        harness,
        backend,
        runtime,
        model,
        think,
    };
}

function resolveDefaultAgentId(fallback) {
    return sanitize(process.env.COLLAB_AGENT_ID || process.env.MYID || process.env.USER, fallback);
}

function resolveAgentId(input, fallback) {
    const source = input || {};
    return sanitize(source.agent || source.defaultAgent || process.env.COLLAB_AGENT_ID || process.env.MYID || process.env.USER, fallback);
}

function resolveChannelName(input, fallback) {
    const source = input || {};
    return normalizeChannelName(source.channel || source.defaultChannel, fallback);
}

function resolveListenHost(value, fallback) {
    const host = String(value || fallback || '').trim();
    return host || fallback;
}

function formatUrlHost(value) {
    const host = String(value || '').trim();
    return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
}

function sendMessage(input) {
    const agentId = resolveAgentId(input, 'agent');
    const channel = resolveChannelName(input, 'lobby');
    const to = input.to ? String(input.to).trim() : 'all';
    const body = input.body
        ? String(input.body)
        : Array.isArray(input._)
            ? input._.join(' ').trim()
            : '';
    const kind = sanitize(input.kind, 'message');

    if (!body) {
        fail('send requires --body "..." (or trailing text).');
    }

    const record = TELEMETRY_STORE.stamp({
        id: randomUUID(),
        timestamp: new Date().toISOString(),
        kind,
        agent_id: agentId,
        channel,
        to,
        body,
    }, { authorType: input.authorType });

    const result = writeRecord(record);
    markPendingForRecord(record);
    EVENT_HUB.emit('channel.message', record);

    if (!input.quiet) {
        process.stdout.write(`${formatRecord(record)}\n`);
        process.stdout.write(`${result.channelPath}\n`);
        process.stdout.write(`${result.msgPath}\n`);
    }

    return record;
}

function writeRecord(record) {
    const channelPath = path.join(CHANNELS_DIR, `${record.channel}.jsonl`);
    const serialized = JSON.stringify(record);
    const serializedBytes = Buffer.byteLength(serialized, 'utf8') + 1;
    if (serializedBytes > MAX_CHANNEL_RECORD_BYTES) {
        const error = new Error(`channel message exceeds ${MAX_CHANNEL_RECORD_BYTES} bytes`);
        error.statusCode = 413;
        throw error;
    }
    fs.appendFileSync(channelPath, `${serialized}\n`, 'utf8');

    const suffix = `${Math.floor(Date.now() / 1000)}.${String(process.hrtime.bigint()).slice(-9)}`;
    const msgPath = path.join(MSGS_DIR, `${record.agent_id}.${suffix}.msg`);
    const msgBody = [
        `agent_id: ${record.agent_id}`,
        `timestamp: ${record.timestamp}`,
        `kind: ${record.kind || 'message'}`,
        `to: ${record.to}`,
        `channel: ${record.channel}`,
        `body: ${record.body}`,
        '',
    ].join('\n');

    fs.writeFileSync(msgPath, msgBody, 'utf8');

    return { channelPath, msgPath };
}

function tailChannel(input) {
    const channel = normalizeChannelName(input.channel, 'lobby');
    const lines = toPositiveInt(input.lines || input.limit, 20);
    const follow = Boolean(input.follow);
    const channelPath = path.join(CHANNELS_DIR, `${channel}.jsonl`);

    if (!fs.existsSync(channelPath)) {
        if (!follow) {
            process.stdout.write(`channel not found: ${channel}\n`);
            return;
        }
        fs.writeFileSync(channelPath, '', 'utf8');
    }

    printRecent(channelPath, lines);

    if (!follow) {
        return;
    }

    process.stdout.write(`following #${channel} (Ctrl+C to exit)\n`);
    let offset = fs.statSync(channelPath).size;

    const timer = setInterval(() => {
        let size = 0;

        try {
            size = fs.statSync(channelPath).size;
        } catch (error) {
            return;
        }

        if (size < offset) {
            offset = 0;
        }

        if (size === offset) {
            return;
        }

        const batch = readChannelLineBatch(channelPath, offset, size);
        offset = batch.cursor;

        for (const entry of batch.entries) {
            const parsed = safeJson(entry.line);
            process.stdout.write(parsed ? `${formatRecord(parsed)}\n` : `[raw] ${entry.line}\n`);
        }
    }, 400);

    process.on('SIGINT', () => {
        clearInterval(timer);
        process.stdout.write('\n');
        process.exit(0);
    });
}

function watchBus(input) {
    const lines = toPositiveInt(input.lines || input.limit, 20);
    const follow = toBoolean(input.follow, true);
    const allChannels = toBoolean(input['all-channels'], !input.channel);
    const requestedChannels = parseChannelList(input.channel);
    const toFilter = input.to ? String(input.to).trim() : '';
    const agentFilter = input.agent ? sanitize(input.agent, '') : '';
    const createMissing = follow && !allChannels;

    const describeScope = () => {
        if (allChannels) {
            return 'all channels';
        }
        return requestedChannels.length > 0
            ? `channels=${requestedChannels.join(',')}`
            : 'channel=lobby';
    };

    const readSources = () => resolveChannelSources({
        allChannels,
        requestedChannels,
        createMissing,
    });

    const matches = (record) => matchesWatchFilters(record, { toFilter, agentFilter });
    const printRecords = (records) => {
        const ordered = records.sort(sortRecordsByTimestamp);
        for (const record of ordered) {
            if (matches(record)) {
                process.stdout.write(`${formatRecord(record)}\n`);
            }
        }
    };

    const initialSources = readSources();
    const recentRecords = readRecentFromSources(initialSources, lines).slice(-lines);

    if (recentRecords.length === 0) {
        process.stdout.write(`watch: no recent messages in ${describeScope()}\n`);
    } else {
        printRecords(recentRecords);
    }

    if (!follow) {
        return;
    }

    const offsets = new Map();
    seedSourceOffsets(offsets, initialSources);
    process.stdout.write(`watching ${describeScope()} (Ctrl+C to exit)\n`);

    const timer = setInterval(() => {
        const sources = readSources();
        seedSourceOffsets(offsets, sources);
        const delta = readSourceDeltas(sources, offsets);
        if (delta.length > 0) {
            printRecords(delta);
        }
    }, 400);

    process.on('SIGINT', () => {
        clearInterval(timer);
        process.stdout.write('\n');
        process.exit(0);
    });
}

function mirrorBus(input) {
    const recipient = sanitize(input.to || input.user || 'kross', 'kross');
    const targetChannel = sanitize(input['target-channel'] || 'lobby', 'lobby');
    const sourceArg = input['source-channel'] || input.channel;
    const requestedChannels = parseChannelList(sourceArg);
    const allChannels = toBoolean(input['all-channels'], requestedChannels.length === 0);
    const follow = toBoolean(input.follow, true);
    const replayLines = toNonNegativeInt(input['replay-lines'], 0);
    const mirrorAgent = sanitize(input.agent || process.env.COLLAB_AGENT_ID || process.env.MYID || 'collab', 'collab');
    const dryRun = Boolean(input['dry-run']);
    const createMissing = follow && !allChannels;

    const describeScope = () => {
        if (allChannels) {
            return 'all channels';
        }
        return requestedChannels.length > 0
            ? `channels=${requestedChannels.join(',')}`
            : 'channel=lobby';
    };

    const readSources = () => resolveChannelSources({
        allChannels,
        requestedChannels,
        createMissing,
    });

    process.stdout.write(
        `mirror: ${describeScope()} -> #${targetChannel} to=${recipient} as ${mirrorAgent}${dryRun ? ' (dry-run)' : ''}\n`,
    );

    const emitMirror = (record) => {
        if (!shouldMirrorRecord(record, { recipient, targetChannel, mirrorAgent })) {
            return;
        }

        const mirrorRecord = {
            timestamp: new Date().toISOString(),
            kind: 'mirror',
            agent_id: mirrorAgent,
            channel: targetChannel,
            to: recipient,
            body: formatMirrorBody(record),
            source_channel: record.channel || 'lobby',
            source_agent: record.agent_id || 'unknown',
            source_to: record.to || 'all',
            source_kind: record.kind || 'message',
            source_timestamp: record.timestamp || '-',
        };

        if (dryRun) {
            process.stdout.write(`[dry-run] ${formatRecord(mirrorRecord)}\n`);
            return;
        }

        const persistedMirror = TELEMETRY_STORE.stamp(mirrorRecord, { authorType: 'mirror' });
        const result = writeRecord(persistedMirror);
        process.stdout.write(`${formatRecord(persistedMirror)}\n`);
        process.stdout.write(`${result.channelPath}\n`);
    };

    const initialSources = readSources();

    if (replayLines > 0) {
        const replay = readRecentFromSources(initialSources, replayLines).slice(-replayLines);
        for (const record of replay.sort(sortRecordsByTimestamp)) {
            emitMirror(record);
        }
    }

    if (!follow) {
        return;
    }

    const offsets = new Map();
    seedSourceOffsets(offsets, initialSources);
    process.stdout.write('mirroring live traffic (Ctrl+C to exit)\n');

    const timer = setInterval(() => {
        const sources = readSources();
        seedSourceOffsets(offsets, sources);
        const delta = readSourceDeltas(sources, offsets).sort(sortRecordsByTimestamp);
        for (const record of delta) {
            emitMirror(record);
        }
    }, 400);

    process.on('SIGINT', () => {
        clearInterval(timer);
        process.stdout.write('\n');
        process.exit(0);
    });
}

function joinChannel(input) {
    const channel = normalizeChannelName(input.channel, 'lobby');
    const body = input.body ? String(input.body) : `joined #${channel}`;

    sendMessage({
        ...input,
        channel,
        to: 'all',
        body,
        kind: 'join',
    });
}

function writeStdoutLine(text) {
    process.stdout.write(`${text}\n`);
}

function listAgents(writeLine = writeStdoutLine) {
    const rows = listKnownAgentEntries();

    if (rows.length === 0) {
        writeLine('no active agents');
        return;
    }

    for (const row of rows) {
        writeLine(`${row.agent}\t${row.state}\t${row.lock}\t${row.timestamp}`);
    }
}

function listChannels(writeLine = writeStdoutLine) {
    const files = fs.readdirSync(CHANNELS_DIR).filter((name) => name.endsWith('.jsonl')).sort();

    if (files.length === 0) {
        writeLine('no channels yet');
        return;
    }

    for (const file of files) {
        const channel = file.replace(/\.jsonl$/, '');
        const fullPath = path.join(CHANNELS_DIR, file);
        const stat = fs.statSync(fullPath);
        writeLine(`${channel}\t${stat.size} bytes\t${stat.mtime.toISOString()}`);
    }
}

function listParticipants(input, writeLine = writeStdoutLine) {
    const channel = normalizeChannelName(input.channel, 'lobby');
    const rows = listParticipantsRows(channel);

    if (rows.length === 0) {
        writeLine(`no participants in #${channel}`);
        return;
    }

    for (const row of rows) {
        writeLine(`${row.agent}\t${row.status}\t${row.lock}\tlast_msg:${row.lastMsg}`);
    }
}

function addManagedAgentCommand(input) {
    const agent = resolveAgentId(input, '');
    const target = sanitize(input.target || input.session || agent, agent);
    const entry = addManagedAgent(agent, target, {
        role: input.role,
        harness: input.harness,
        backend: input.backend,
        runtime: input.runtime,
        model: input.model,
        think: input.think,
    });
    process.stdout.write(`${entry.agent}\t${entry.target}\t${entry.added_at}\n`);
}

function removeManagedAgentCommand(input) {
    const agent = resolveAgentId(input, '');
    const removed = removeManagedAgent(agent);
    process.stdout.write(removed ? `removed ${agent}\n` : `not found ${agent}\n`);
}

function listManagedAgentsCommand(writeLine = writeStdoutLine) {
    const rows = listManagedAgentEntries();
    if (rows.length === 0) {
        writeLine('no managed agents');
        return;
    }

    for (const row of rows) {
        writeLine(`${row.agent}\t${row.target}\t${row.added_at}`);
    }
}

function defaultAgentMcpUrl() {
    return String(process.env.COLLAB_MCP_URL || 'http://127.0.0.1:1337/mcp').trim() || 'http://127.0.0.1:1337/mcp';
}

function agentMcpUrlForRuntime(runtime, value = '') {
    const launchTarget = runtime && typeof runtime === 'object'
        ? normalizeLaunchTarget(runtime)
        : normalizeLaunchTarget({ runtime });
    const configured = String(value || defaultAgentMcpUrl()).trim() || defaultAgentMcpUrl();
    if (mcpTransportFor(launchTarget) !== 'sse') {
        return configured;
    }
    try {
        const parsed = new URL(configured);
        if (!parsed.pathname || parsed.pathname === '/' || parsed.pathname === '/mcp') {
            parsed.pathname = '/sse';
        }
        return parsed.toString();
    } catch (_error) {
        return configured;
    }
}

function runAgentLauncherScript(scriptName, args, options = {}) {
    const scriptPath = path.join(APP_ROOT, 'agents', 'bin', scriptName);
    rejectAgentSpawnOtp(options);
    const launchTarget = resolveLaunchTargetInput(options);
    const env = {
        ...sanitizeChildEnvironment(process.env),
        NOTTY_COLLAB_STANDALONE: '1',
        COLLAB_CHANNEL: normalizeChannelName(options.channel, 'lobby'),
        COLLAB_MCP_URL: String(options.mcpUrl || options.mcp_url || defaultAgentMcpUrl()).trim() || defaultAgentMcpUrl(),
        COLLAB_HARNESS: launchTarget.harness,
        COLLAB_BACKEND: launchTarget.backend,
        COLLAB_RUNTIME: launchTarget.runtime,
        COLLAB_MODEL: String(options.model || ''),
        COLLAB_THINK: String(options.think || ''),
    };
    const role = sanitize(options.role, '');
    if (role) {
        env.COLLAB_ROLE = role;
    }

    const result = childProcess.spawnSync(scriptPath, args, {
        cwd: ROOT,
        env,
        encoding: 'utf8',
    });

    if (result.error) {
        throw result.error;
    }

    if (result.status !== 0) {
        throw new Error((result.stderr || result.stdout || `${scriptName} failed (${result.status})`).trim());
    }

    return (result.stdout || '').trim();
}

function createAgentScriptCommand(input) {
    const agent = sanitize(input.agent || input.name || input.id || input._[0], '');
    if (!agent) {
        fail('create-agent requires --agent');
    }
    if (Object.hasOwn(input, 'model') && typeof input.model !== 'string') {
        fail('create-agent --model requires a value');
    }

    const role = sanitize(input.role || input._[1] || agent, agent);
    const launchTarget = resolveLaunchTargetInput(input);
    const { harness, backend, runtime } = launchTarget;
    const model = typeof input.model === 'string' ? input.model.trim() : '';
    const think = normalizeAgentThink(input.think, launchTarget);
    rejectAgentSpawnOtp(input);
    if (runtime === 'ollama' && !model) {
        fail('create-agent --runtime ollama requires --model');
    }
    const args = [
        '--agent', agent,
        '--role', role,
        '--harness', harness,
        '--backend', backend,
    ];
    if (model) {
        args.push('--model', model);
    }
    if (think) {
        args.push('--think', think);
    }
    const output = runAgentLauncherScript('create_agent.sh', args, {
        channel: input.channel,
        mcpUrl: agentMcpUrlForRuntime(
            launchTarget,
            harness === 'agy'
                ? input['sse-url'] || input.sse_url || input['mcp-url'] || input.mcp_url
                : input['mcp-url'] || input.mcp_url,
        ),
        role,
        harness,
        backend,
        runtime,
        model,
        think,
    });
    process.stdout.write(`${output}\n`);
}

function resolveResumeAgentInput(input) {
    const agent = sanitize(input.agent || input.name || input.id || input._[0], '');
    const sessionId = String(input['session-id'] || input.session_id || input.sessionId || input._[1] || '').trim();
    const role = sanitize(input.role || input._[2] || agent, agent);
    if (!agent || !sessionId) {
        fail('resume-agent requires --agent and --session-id');
    }
    for (const name of ['runtime', 'harness', 'backend', 'model']) {
        if (Object.hasOwn(input, name) && typeof input[name] !== 'string') {
            fail(`resume-agent --${name} requires a value`);
        }
    }
    const launchTarget = resolveLaunchTargetInput(input);
    const { harness, backend, runtime } = launchTarget;
    const model = String(input.model || '').trim();
    const think = normalizeAgentThink(input.think, launchTarget);
    if (backend === 'ollama' && !model) {
        fail('resume-agent --backend ollama requires --model');
    }
    return { agent, sessionId, role, launchTarget, harness, backend, runtime, model, think };
}

function resumeAgentScriptCommand(input) {
    const {
        agent,
        sessionId,
        role,
        launchTarget,
        harness,
        backend,
        runtime,
        model,
        think,
    } = resolveResumeAgentInput(input);
    const args = [
        '--agent', agent,
        '--session-id', sessionId,
        '--role', role,
        '--harness', harness,
        '--backend', backend,
    ];
    if (model) args.push('--model', model);
    if (think) args.push('--think', think);
    const configuredMcpUrl = harness === 'agy'
        ? input['sse-url'] || input.sse_url || input['mcp-url'] || input.mcp_url
        : input['mcp-url'] || input.mcp_url;
    const output = runAgentLauncherScript('resume_agent.sh', args, {
        channel: input.channel,
        mcpUrl: agentMcpUrlForRuntime(launchTarget, configuredMcpUrl),
        role,
        harness,
        backend,
        runtime,
        model,
        think,
    });
    process.stdout.write(`${output}\n`);
}

function tmuxSendKeys(input) {
    const target = resolveTmuxTarget(input);
    const text = input.body ? String(input.body) : input.text ? String(input.text) : input._.join(' ').trim();
    const enter = toBoolean(input.enter, false);
    const delayMs = toNonNegativeInt(input['delay-ms'] || input.delay_ms, enter ? 200 : 0);
    const fatal = input.fatal !== false;

    if (text) {
        runTmux(['send-keys', '-t', target, text], fatal);
    }

    if (enter) {
        sleepMs(delayMs);
        runTmux(['send-keys', '-t', target, 'C-m'], fatal);
    }

    if (!input.quiet) {
        process.stdout.write(`${target}\n`);
    }
    return target;
}

function tmuxReadPane(input) {
    const target = resolveTmuxTarget(input);
    const lines = toPositiveInt(input.lines || input.limit, 80);
    const output = runTmux(['capture-pane', '-pt', target], input.fatal !== false);
    const tail = output.split('\n').slice(-lines).join('\n');
    if (!input.quiet) {
        process.stdout.write(`${tail}\n`);
    }
    return tail;
}

function formatMcpSseStatus(info, defaults) {
    return `mcp listening: http://${formatUrlHost(info.host)}:${info.port}${info.mcpPath} (sse ${info.ssePath}, post ${info.messagesPath}) default_agent=${defaults.agent} default_channel=${defaults.channel}`;
}

function writeJsonResponse(res, statusCode, payload) {
    res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(payload));
}

function writeMcpError(res, statusCode, message) {
    writeJsonResponse(res, statusCode, {
        jsonrpc: '2.0',
        error: {
            code: statusCode >= 500 ? -32603 : -32000,
            message,
        },
        id: null,
    });
}

async function readJsonBody(req, options = {}) {
    const maxBytes = toPositiveInt(options.maxBytes, MAX_JSON_BODY_BYTES);
    return await new Promise((resolve, reject) => {
        const chunks = [];
        let totalBytes = 0;
        let settled = false;

        const rejectOnce = (error) => {
            if (settled) {
                return;
            }
            settled = true;
            reject(error);
        };

        req.on('data', (chunk) => {
            if (settled) {
                return;
            }
            totalBytes += chunk.length;
            if (totalBytes > maxBytes) {
                const error = new Error(`request body exceeds ${maxBytes} bytes`);
                error.statusCode = 413;
                rejectOnce(error);
                return;
            }
            chunks.push(chunk);
        });

        req.on('end', () => {
            if (settled) {
                return;
            }
            settled = true;
            if (chunks.length === 0) {
                resolve(undefined);
                return;
            }

            const raw = Buffer.concat(chunks).toString('utf8').trim();
            if (!raw) {
                resolve(undefined);
                return;
            }

            try {
                resolve(JSON.parse(raw));
            } catch (error) {
                const invalidJson = new Error(`invalid JSON body: ${error.message}`);
                invalidJson.statusCode = 400;
                reject(invalidJson);
            }
        });

        req.on('error', rejectOnce);
    });
}

function requirePlainObject(value, label = 'request body') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        const error = new Error(`${label} must be a JSON object`);
        error.statusCode = 400;
        throw error;
    }
    return value;
}

async function requestRemoteJson(serverUrl, method, pathname, body) {
    const target = new URL(pathname, `${String(serverUrl).replace(/\/+$/, '')}/`);
    if (target.protocol !== 'http:') {
        throw new Error('remote collab IRC currently requires an http:// loopback server URL');
    }
    return await new Promise((resolve, reject) => {
        const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
        const req = http.request(target, {
            method,
            headers: payload ? {
                'Content-Type': 'application/json',
                'Content-Length': payload.length,
            } : {},
        }, (res) => {
            const chunks = [];
            res.on('data', (chunk) => chunks.push(chunk));
            res.on('end', () => {
                const raw = Buffer.concat(chunks).toString('utf8');
                let parsed = null;
                try {
                    parsed = raw ? JSON.parse(raw) : null;
                } catch (_error) {
                    reject(new Error(`collab daemon returned invalid JSON (${res.statusCode})`));
                    return;
                }
                if ((res.statusCode || 500) >= 400) {
                    reject(new Error(parsed && parsed.error && parsed.error.message
                        ? parsed.error.message
                        : `collab daemon request failed (${res.statusCode})`));
                    return;
                }
                resolve(parsed);
            });
        });
        req.on('error', reject);
        if (payload) {
            req.write(payload);
        }
        req.end();
    });
}

async function startRemoteMirror(input) {
    const serverUrl = resolveRemoteDaemonUrl(input);
    const recipient = sanitize(input.to || input.user || 'kross', 'kross');
    const targetChannel = sanitize(input['target-channel'] || 'lobby', 'lobby');
    const sourceArg = input['source-channel'] || input.channel;
    const requestedChannels = parseChannelList(sourceArg);
    const allChannels = toBoolean(input['all-channels'], requestedChannels.length === 0);
    const follow = toBoolean(input.follow, true);
    const replayLines = Math.min(toNonNegativeInt(input['replay-lines'], 0), 500);
    const mirrorAgent = sanitize(input.agent || process.env.COLLAB_AGENT_ID || process.env.MYID || 'collab', 'collab');
    const dryRun = Boolean(input['dry-run']);
    const cursors = new Map();
    let polling = false;
    let lastError = '';

    const channelNames = async () => {
        if (!allChannels) {
            return requestedChannels.length > 0 ? requestedChannels : ['lobby'];
        }
        const bootstrap = await requestRemoteJson(serverUrl, 'GET', '/admin/v1/bootstrap');
        return dedupeAndSortChannels(bootstrap.channels || []);
    };
    const emitMirror = async (record) => {
        if (!shouldMirrorRecord(record, { recipient, targetChannel, mirrorAgent })) {
            return;
        }
        const body = formatMirrorBody(record);
        if (dryRun) {
            process.stdout.write(`[dry-run] ${formatRecord({
                timestamp: new Date().toISOString(),
                kind: 'message',
                agent_id: mirrorAgent,
                channel: targetChannel,
                to: recipient,
                body,
            })}\n`);
            return;
        }
        const response = await requestRemoteJson(
            serverUrl,
            'POST',
            `/admin/v1/channels/${encodeURIComponent(targetChannel)}/messages`,
            { agent: mirrorAgent, to: recipient, body, kind: 'mirror' },
        );
        if (response.message) {
            process.stdout.write(`${formatRecord(response.message)}\n`);
        }
    };
    const seedChannel = async (channel, replay) => {
        const response = await requestRemoteJson(
            serverUrl,
            'GET',
            `/admin/v1/channels/${encodeURIComponent(channel)}/messages?limit=${replay > 0 ? replay : 1}`,
        );
        cursors.set(channel, Number.isInteger(response.cursor) ? response.cursor : 0);
        if (replay > 0) {
            for (const record of response.messages || []) {
                await emitMirror(record);
            }
        }
    };
    const poll = async () => {
        if (polling) {
            return;
        }
        polling = true;
        try {
            const channels = await channelNames();
            for (const channel of channels) {
                if (!cursors.has(channel)) {
                    cursors.set(channel, 0);
                }
                let cursor = cursors.get(channel);
                for (let page = 0; page < 20; page += 1) {
                    const response = await requestRemoteJson(
                        serverUrl,
                        'GET',
                        `/admin/v1/channels/${encodeURIComponent(channel)}/messages?limit=500&cursor=${cursor}`,
                    );
                    const nextCursor = Number.isInteger(response.cursor) ? response.cursor : cursor;
                    for (const record of response.messages || []) {
                        await emitMirror(record);
                    }
                    cursors.set(channel, nextCursor);
                    if (nextCursor === cursor || (response.messages || []).length < 500) {
                        break;
                    }
                    cursor = nextCursor;
                }
            }
            lastError = '';
        } catch (error) {
            const message = error.message || String(error);
            if (message !== lastError) {
                process.stderr.write(`[collab] mirror: ${message}\n`);
                lastError = message;
            }
        } finally {
            polling = false;
        }
    };

    const initialChannels = await channelNames();
    process.stdout.write(
        `mirror: ${allChannels ? 'all channels' : `channels=${initialChannels.join(',')}`} -> #${targetChannel} to=${recipient} as ${mirrorAgent}${dryRun ? ' (dry-run)' : ''}\n`,
    );
    for (const channel of initialChannels) {
        await seedChannel(channel, replayLines);
    }
    if (!follow) {
        return;
    }
    const timer = setInterval(() => void poll(), 500);
    process.on('SIGINT', () => {
        clearInterval(timer);
        process.stdout.write('\n');
        process.exit(0);
    });
}

async function startRemoteIrc(input) {
    const serverUrl = String(input.server || input.url || '').trim();
    let agent = sanitize(input.agent || 'kross', 'kross');
    let channel = normalizeChannelName(input.channel, 'lobby');
    let to = input.to ? String(input.to).trim() : 'all';
    const replayLines = Math.min(toPositiveInt(input.lines || input.limit, 50), 500);
    const seen = new Set();
    let polling = false;
    let lastError = '';
    let messageCursor = null;

    const terminalUi = createIrcTerminalUi({
        input: process.stdin,
        output: process.stdout,
        prompt: () => {
            const target = to === 'all' ? '' : `->${to}`;
            const roleMeta = getIrcRoleMeta(agent);
            return `${roleMeta.glyph} ${IRC_STYLE_PROMPT_USER}${agent}${IRC_STYLE_RESET}@${IRC_STYLE_PROMPT_CHANNEL}#${channel}${IRC_STYLE_RESET}${target}> `;
        },
    });
    const rl = terminalUi.readline;
    const renderPrompt = () => terminalUi.prompt();
    const writeLine = (text) => terminalUi.write(text);
    const recordKey = (record) => record.id || JSON.stringify([
        record.timestamp || '', record.kind || '', record.agent_id || '', record.channel || '', record.to || '', record.body || '',
    ]);
    const fetchMessages = async (showExisting = false) => {
        if (polling) {
            return;
        }
        polling = true;
        try {
            const cursorQuery = messageCursor === null ? '' : `&cursor=${encodeURIComponent(messageCursor)}`;
            const response = await requestRemoteJson(
                serverUrl,
                'GET',
                `/admin/v1/channels/${encodeURIComponent(channel)}/messages?limit=${replayLines}${cursorQuery}`,
            );
            for (const record of response.messages || []) {
                const key = recordKey(record);
                if (!seen.has(key)) {
                    seen.add(key);
                    if (showExisting || terminalUi.isPromptVisible()) {
                        writeLine(formatRecord(record, { ircMode: true, includeDate: true }));
                    }
                }
            }
            messageCursor = Number.isInteger(response.cursor) ? response.cursor : messageCursor;
            lastError = '';
        } catch (error) {
            const message = error.message || String(error);
            if (message !== lastError) {
                writeLine(`[collab] ${message}`);
                lastError = message;
            }
        } finally {
            polling = false;
        }
    };
    const sendRemote = async (body) => {
        const response = await requestRemoteJson(
            serverUrl,
            'POST',
            `/admin/v1/channels/${encodeURIComponent(channel)}/messages`,
            { agent, to, body, kind: 'message' },
        );
        const record = response.message;
        if (record) {
            seen.add(recordKey(record));
            writeLine(formatRecord(record, { ircMode: true, includeDate: true }));
        }
    };

    const bootstrap = await requestRemoteJson(serverUrl, 'GET', '/admin/v1/bootstrap');
    if (!bootstrap.daemon || bootstrap.daemon.marker !== 'notty-collab-daemon') {
        throw new Error('server is not a compatible collab daemon');
    }
    writeLine(`collab irc client: server=${serverUrl} agent=${agent} channel=#${channel} to=${to}`);
    writeLine('type /help for commands');
    await fetchMessages(true);
    const timer = setInterval(() => void fetchMessages(false), 500);

    rl.on('line', (line) => {
        const raw = String(line || '').trim();
        if (!raw) {
            renderPrompt();
            return;
        }
        if (!raw.startsWith('/')) {
            void sendRemote(raw).catch((error) => writeLine(`[collab] ${error.message}`));
            return;
        }
        let parts;
        try {
            parts = tokenizeCommandLine(raw.slice(1));
        } catch (error) {
            writeLine(`[collab] ${error.message || String(error)}`);
            return;
        }
        const sub = String(parts.shift() || '').toLowerCase();
        if (sub === 'help') {
            writeLine('/create_agent <id> --role <role> [--harness codex|agy|claude] [--backend default|ollama] [--model "model"] [--think level]  launch agent\n/resume_agent <id> <session_id> [--harness codex|agy|claude] [--backend default|ollama] [--model "model"] [--think level]  resume agent\n/join <channel>  switch channel\n/to <agent|all>  set target\n/all  set target to all\n/nick <name>  change nickname\n/tail  replay recent messages\n/say <text>  send message\n/status  show daemon status\n/quit  exit');
            return;
        }
        if (sub === 'create_agent') {
            let createInput;
            try {
                createInput = parseIrcCreateAgentArgs(parts);
            } catch (error) {
                writeLine(`[collab] ${error.message || String(error)}`);
                return;
            }
            void requestRemoteJson(
                serverUrl,
                'POST',
                '/admin/v1/commands/create-agent',
                { ...createInput, channel },
            )
                .then((response) => {
                    const result = response.result || {};
                    writeLine(`agent=${result.agent || createInput.agent} target=${result.target || createInput.agent} runtime=${result.runtime || createInput.runtime} model=${result.model || createInput.model || '(default)'} think=${result.think || createInput.think || '(default)'}`);
                })
                .catch((error) => writeLine(`[collab] ${error.message || String(error)}`));
            return;
        }
        if (sub === 'resume_agent') {
            let resumeInput;
            try {
                resumeInput = resolveResumeAgentInput(parseArgs(parts));
            } catch (error) {
                writeLine(`[collab] ${error.message || String(error)}`);
                return;
            }
            void requestRemoteJson(
                serverUrl,
                'POST',
                '/admin/v1/commands/resume-agent',
                {
                    agent: resumeInput.agent,
                    sessionId: resumeInput.sessionId,
                    role: resumeInput.role,
                    harness: resumeInput.harness,
                    backend: resumeInput.backend,
                    model: resumeInput.model,
                    think: resumeInput.think,
                    channel,
                },
            )
                .then((response) => {
                    const result = response.result || {};
                    writeLine(`agent=${result.agent || resumeInput.agent} target=${result.target || resumeInput.agent} harness=${result.harness || resumeInput.harness} model=${result.model || resumeInput.model || '(default)'} think=${result.think || resumeInput.think || '(default)'}`);
                })
                .catch((error) => writeLine(`[collab] ${error.message || String(error)}`));
            return;
        }
        if (sub === 'join') {
            channel = normalizeChannelName(parts[0], channel);
            seen.clear();
            messageCursor = null;
            void fetchMessages(true);
            renderPrompt();
            return;
        }
        if (sub === 'to') {
            to = parts[0] || 'all';
            renderPrompt();
            return;
        }
        if (sub === 'all') {
            to = 'all';
            renderPrompt();
            return;
        }
        if (sub === 'nick') {
            agent = sanitize(parts[0], agent);
            renderPrompt();
            return;
        }
        if (sub === 'tail') {
            seen.clear();
            messageCursor = null;
            void fetchMessages(true);
            renderPrompt();
            return;
        }
        if (sub === 'say') {
            const body = parts.join(' ');
            if (body) {
                void sendRemote(body).catch((error) => writeLine(`[collab] ${error.message}`));
            } else {
                renderPrompt();
            }
            return;
        }
        if (sub === 'status' || sub === 'mcp') {
            void requestRemoteJson(serverUrl, 'GET', '/admin/v1/bootstrap')
                .then((value) => writeLine(`daemon=${value.service.status} workspace=${value.workspaceRoot}`))
                .catch((error) => writeLine(`[collab] ${error.message}`));
            return;
        }
        if (sub === 'quit' || sub === 'exit') {
            rl.close();
            return;
        }
        writeLine(`unknown command: /${sub}`);
    });
    rl.on('close', () => {
        terminalUi.setPromptVisible(false);
        clearInterval(timer);
        writeLine('bye');
        process.exit(0);
    });
    terminalUi.setPromptVisible(true);
    renderPrompt();
}

async function startIrc(input) {
    if (input.server || input.url) {
        return await startRemoteIrc(input);
    }
    let agent = sanitize(input.agent || 'kross', 'kross');
    let channel = normalizeChannelName(input.channel, 'lobby');
    let to = input.to ? String(input.to).trim() : 'all';
    const follow = toBoolean(input.follow, true);
    const replayLines = toPositiveInt(input.lines || input.limit, 20);
    const seenLocal = new Set();
    let watchPath = '';
    let watchOffset = 0;
    let watchTimer = null;
    let mcpSse = null;
    const sseHost = resolveListenHost(input.ip, '127.0.0.1');
    const ssePort = toPositiveInt(input.port, 1337);

    const terminalUi = createIrcTerminalUi({
        input: process.stdin,
        output: process.stdout,
        prompt: () => {
            const target = to === 'all' ? '' : `->${to}`;
            const roleMeta = getIrcRoleMeta(agent);
            return `${roleMeta.glyph} ${IRC_STYLE_PROMPT_USER}${agent}${IRC_STYLE_RESET}@${IRC_STYLE_PROMPT_CHANNEL}#${channel}${IRC_STYLE_RESET}${target}> `;
        },
    });
    const rl = terminalUi.readline;
    const renderPrompt = () => terminalUi.prompt();
    const writeIrcLine = (text) => terminalUi.write(text);

    writeIrcLine(`collab irc mode: agent=${agent} channel=#${channel} to=${to} follow=${follow ? 'on' : 'off'}`);
    writeIrcLine('type /help for commands');

    const recordKey = (record) => JSON.stringify([
        record.timestamp || '',
        record.kind || '',
        record.agent_id || '',
        record.channel || '',
        record.to || '',
        record.body || '',
    ]);

    let lastIrcDateKey = '';
    const formatIrcRecord = (record) => {
        const timestamp = splitTimestampParts(record && record.timestamp);
        const includeDate = timestamp.dateKey !== '' && timestamp.dateKey !== lastIrcDateKey;
        if (timestamp.dateKey !== '') {
            lastIrcDateKey = timestamp.dateKey;
        }
        return formatRecord(record, { ircMode: true, includeDate });
    };

    const syncWatchSource = (showRecent) => {
        const nextPath = path.join(CHANNELS_DIR, `${channel}.jsonl`);
        if (!fs.existsSync(nextPath)) {
            fs.writeFileSync(nextPath, '', 'utf8');
        }

        const changed = nextPath !== watchPath;
        watchPath = nextPath;

        if (showRecent && replayLines > 0) {
            printRecent(watchPath, replayLines, formatIrcRecord, writeIrcLine);
        }

        if (changed || showRecent) {
            watchOffset = fs.statSync(watchPath).size;
        }
    };

    const emitLocalRecord = (record) => {
        seenLocal.add(recordKey(record));
        writeIrcLine(formatIrcRecord(record));
    };

    const pollChannel = () => {
        syncWatchSource(false);

        let size = 0;
        try {
            size = fs.statSync(watchPath).size;
        } catch (error) {
            return;
        }

        if (size < watchOffset) {
            watchOffset = 0;
        }

        if (size === watchOffset) {
            return;
        }

        const batch = readChannelLineBatch(watchPath, watchOffset, size);
        watchOffset = batch.cursor;

        for (const entry of batch.entries) {
            const parsed = safeJson(entry.line);
            if (!parsed) {
                writeIrcLine(`[raw] ${entry.line}`);
                continue;
            }

            const key = recordKey(parsed);
            if (seenLocal.has(key)) {
                seenLocal.delete(key);
                continue;
            }

            writeIrcLine(formatIrcRecord(parsed));
        }
    };

    const announceJoin = () => {
        const joined = sendMessage({
            agent,
            channel,
            to: 'all',
            body: `joined #${channel}`,
            kind: 'join',
            quiet: true,
        });
        seenLocal.add(recordKey(joined));
    };

    const printIrcHelp = () => {
        writeIrcLine([
            '/help            show commands',
            '/create_agent <id> [role] [--harness codex|agy|claude] [--backend default|ollama] [--model "model"] [--think level]  launch an agent',
            '/create_agent --role <role> [--harness codex|agy|claude] [--backend default|ollama]  use the role as the agent id',
            '/resume_agent <id> <session_id> [--harness codex|agy|claude] [--backend default|ollama] [--model "model"] [--think level]  resume an agent',
            '/add_agent <id> [target]  register a tmux-managed agent for idle nudges',
            '/remove_agent <id>        remove a tmux-managed agent registration',
            '/managed          list tmux-managed agent registrations',
            '/join <channel>  switch channel',
            '/mcp             print MCP SSE listener status',
            '/to <agent|all>  set direct message target',
            '/all             set target to all',
            '/nick <name>     change agent id',
            '/who [channel]   list channel participants',
            '/channels        list channels',
            '/agents          list active agents',
            '/tail [lines]    print recent messages in current channel',
            '/tail does not change live follow; irc follows current channel by default',
            '/say <text>      send message',
            '/quit            exit irc mode',
        ].join('\n'));
    };

    try {
        mcpSse = await startMcpSseBridge({
            ip: sseHost,
            port: ssePort,
            getDefaultAgent: () => agent,
            getDefaultChannel: () => channel,
            logLine: writeIrcLine,
        });
        writeIrcLine(formatMcpSseStatus(mcpSse, { agent, channel }));
    } catch (error) {
        writeIrcLine(`[mcp] unable to start SSE listener on ${sseHost}:${ssePort}: ${error.message}`);
    }

    syncWatchSource(true);
    announceJoin();

    if (follow) {
        writeIrcLine(`watching #${channel} live (Ctrl+C to exit)`);
        watchTimer = setInterval(pollChannel, 400);
    }

    rl.on('line', (line) => {
        const raw = String(line || '').trim();

        if (!raw) {
            renderPrompt();
            return;
        }

        if (raw.startsWith('/')) {
            let parts;
            try {
                parts = tokenizeCommandLine(raw.slice(1));
            } catch (error) {
                writeIrcLine(error.message || String(error));
                return;
            }
            const sub = (parts[0] || '').toLowerCase();
            const rest = parts.slice(1);

            if (sub === 'help') {
                printIrcHelp();
                return;
            }

            if (sub === 'create_agent') {
                try {
                    const {
                        agent: createdAgent,
                        role,
                        runtime,
                        model,
                        think,
                    } = parseIrcCreateAgentArgs(rest);
                    const args = ['--agent', createdAgent, '--role', role, '--runtime', runtime];
                    if (model) {
                        args.push('--model', model);
                    }
                    if (think) {
                        args.push('--think', think);
                    }
                    const configuredMcpUrl = runtime === 'agy'
                        ? input['sse-url'] || input.sse_url || input['mcp-url'] || input.mcp_url
                        : input['mcp-url'] || input.mcp_url;
                    const listenerMcpUrl = mcpSse
                        ? `http://${formatUrlHost(mcpSse.host)}:${mcpSse.port}${runtime === 'agy' ? mcpSse.ssePath : mcpSse.mcpPath}`
                        : defaultAgentMcpUrl();
                    const output = runAgentLauncherScript('create_agent.sh', args, {
                        channel,
                        role,
                        runtime,
                        model,
                        think,
                        mcpUrl: agentMcpUrlForRuntime(runtime, configuredMcpUrl || listenerMcpUrl),
                    });
                    writeIrcLine(output);
                } catch (error) {
                    writeIrcLine(error.message || String(error));
                }
                return;
            }

            if (sub === 'resume_agent') {
                try {
                    const resumeInput = resolveResumeAgentInput(parseArgs(rest));
                    const args = [
                        '--agent', resumeInput.agent,
                        '--session-id', resumeInput.sessionId,
                        '--role', resumeInput.role,
                        '--harness', resumeInput.harness,
                        '--backend', resumeInput.backend,
                    ];
                    if (resumeInput.model) args.push('--model', resumeInput.model);
                    if (resumeInput.think) args.push('--think', resumeInput.think);
                    const configuredMcpUrl = resumeInput.harness === 'agy'
                        ? input['sse-url'] || input.sse_url || input['mcp-url'] || input.mcp_url
                        : input['mcp-url'] || input.mcp_url;
                    const listenerMcpUrl = mcpSse
                        ? `http://${formatUrlHost(mcpSse.host)}:${mcpSse.port}${
                            resumeInput.harness === 'agy' ? mcpSse.ssePath : mcpSse.mcpPath
                        }`
                        : defaultAgentMcpUrl();
                    const output = runAgentLauncherScript('resume_agent.sh', args, {
                        channel,
                        role: resumeInput.role,
                        harness: resumeInput.harness,
                        backend: resumeInput.backend,
                        runtime: resumeInput.runtime,
                        model: resumeInput.model,
                        think: resumeInput.think,
                        mcpUrl: agentMcpUrlForRuntime(
                            resumeInput.launchTarget,
                            configuredMcpUrl || listenerMcpUrl,
                        ),
                    });
                    writeIrcLine(output);
                } catch (error) {
                    writeIrcLine(error.message || String(error));
                }
                return;
            }

            if (sub === 'add_agent') {
                const managedAgent = sanitize(rest[0], '');
                if (!managedAgent) {
                    writeIrcLine('usage: /add_agent <agent> [target]');
                } else {
                    const entry = addManagedAgent(managedAgent, sanitize(rest[1] || managedAgent, managedAgent));
                    writeIrcLine(`managed agent ${entry.agent} -> ${entry.target}`);
                }
                return;
            }

            if (sub === 'remove_agent') {
                const managedAgent = sanitize(rest[0], '');
                if (!managedAgent) {
                    writeIrcLine('usage: /remove_agent <agent>');
                } else {
                    const removed = removeManagedAgent(managedAgent);
                    writeIrcLine(removed ? `removed ${managedAgent}` : `not found ${managedAgent}`);
                }
                return;
            }

            if (sub === 'managed') {
                listManagedAgentsCommand(writeIrcLine);
                return;
            }

            if (sub === 'mcp') {
                if (mcpSse) {
                    writeIrcLine(formatMcpSseStatus(mcpSse, { agent, channel }));
                } else {
                    writeIrcLine(`[mcp] unavailable on ${sseHost}:${ssePort}`);
                }
                return;
            }

            if (sub === 'join') {
                const nextChannel = normalizeChannelName(rest[0], channel);
                channel = nextChannel;
                syncWatchSource(true);
                announceJoin();
                writeIrcLine(`joined #${channel}`);
                return;
            }

            if (sub === 'to') {
                to = rest[0] ? String(rest[0]).trim() : 'all';
                writeIrcLine(`target=${to}`);
                return;
            }

            if (sub === 'all') {
                to = 'all';
                writeIrcLine('target=all');
                return;
            }

            if (sub === 'nick') {
                agent = sanitize(rest[0], agent);
                writeIrcLine(`nick=${agent}`);
                return;
            }

            if (sub === 'who') {
                listParticipants({ channel: rest[0] || channel }, writeIrcLine);
                return;
            }

            if (sub === 'channels') {
                listChannels(writeIrcLine);
                return;
            }

            if (sub === 'agents') {
                listAgents(writeIrcLine);
                return;
            }

            if (sub === 'tail') {
                const lines = toPositiveInt(rest[0], 20);
                const channelPath = path.join(CHANNELS_DIR, `${channel}.jsonl`);
                if (!fs.existsSync(channelPath)) {
                    writeIrcLine(`channel not found: ${channel}`);
                } else {
                    printRecent(channelPath, lines, formatIrcRecord, writeIrcLine);
                }
                return;
            }

            if (sub === 'say') {
                const body = rest.join(' ');
                if (!body) {
                    writeIrcLine('usage: /say <text>');
                } else {
                    const sent = sendMessage({
                        agent,
                        channel,
                        to,
                        body,
                        kind: 'message',
                        quiet: true,
                    });
                    emitLocalRecord(sent);
                    return;
                }
                return;
            }

            if (sub === 'quit' || sub === 'exit') {
                rl.close();
                return;
            }

            writeIrcLine(`unknown command: /${sub}`);
            return;
        }

        const sent = sendMessage({
            agent,
            channel,
            to,
            body: raw,
            kind: 'message',
            quiet: true,
        });
        emitLocalRecord(sent);
    });

    rl.on('close', () => {
        terminalUi.setPromptVisible(false);
        if (watchTimer) {
            clearInterval(watchTimer);
        }

        const finalize = async () => {
            if (mcpSse) {
                await mcpSse.close();
            }

            writeIrcLine('bye');
            process.exit(0);
        };

        void finalize();
    });

    terminalUi.setPromptVisible(true);
    renderPrompt();
}

async function loadMcpSdk() {
    let Client;
    let Server;
    let StdioServerTransport;
    let SSEServerTransport;
    let StreamableHTTPServerTransport;
    let ListToolsRequestSchema;
    let CallToolRequestSchema;
    let isInitializeRequest;
    let StreamableHTTPClientTransport;

    try {
        ({ Client } = await import('@modelcontextprotocol/sdk/client/index.js'));
        ({ StreamableHTTPClientTransport } = await import('@modelcontextprotocol/sdk/client/streamableHttp.js'));
        ({ Server } = await import('@modelcontextprotocol/sdk/server/index.js'));
        ({ StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js'));
        ({ SSEServerTransport } = await import('@modelcontextprotocol/sdk/server/sse.js'));
        ({ StreamableHTTPServerTransport } = await import('@modelcontextprotocol/sdk/server/streamableHttp.js'));
        ({ ListToolsRequestSchema, CallToolRequestSchema, isInitializeRequest } = await import('@modelcontextprotocol/sdk/types.js'));
    } catch (error) {
        fail('mcp mode requires @modelcontextprotocol/sdk to be installed.');
    }

    return {
        Client,
        Server,
        StdioServerTransport,
        SSEServerTransport,
        StreamableHTTPServerTransport,
        ListToolsRequestSchema,
        CallToolRequestSchema,
        isInitializeRequest,
        StreamableHTTPClientTransport,
    };
}

function createMcpServer(sdk, options) {
    const {
        Server,
        ListToolsRequestSchema,
        CallToolRequestSchema,
    } = sdk;
    const getDefaultAgent = typeof options.getDefaultAgent === 'function'
        ? options.getDefaultAgent
        : () => options.defaultAgent || resolveDefaultAgentId('agent');
    const getDefaultChannel = typeof options.getDefaultChannel === 'function'
        ? options.getDefaultChannel
        : () => options.defaultChannel || 'lobby';
    const getSessionId = typeof options.getSessionId === 'function'
        ? options.getSessionId
        : () => '';
    const registerAgent = typeof options.registerAgent === 'function'
        ? options.registerAgent
        : () => {};
    const listAgentRows = typeof options.listAgentRows === 'function'
        ? options.listAgentRows
        : () => listKnownAgentEntries();

    const server = new Server(
        {
            name: 'collab',
            version: '1.0.0',
        },
        {
            capabilities: {
                tools: {},
            },
        },
    );
    let mcpAgent = sanitize(getDefaultAgent(), 'agent');
    const mcpTmuxTarget = (params) => require('./lib/collab/tmux-target.cjs').resolveCollabTmuxTarget(
        params.target || params.session || mcpAgent,
        SESSION_MANAGER ? SESSION_MANAGER.getSession() : null,
        readManagedAgents(),
    );

    server.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: [
            {
                name: 'send_message',
                description: 'Send a message to a channel. Uses the current MCP nickname when agent is omitted.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        agent: { type: 'string' },
                        channel: { type: 'string', default: 'lobby' },
                        to: { type: 'string', default: 'all' },
                        body: { type: 'string' },
                    },
                    required: ['body'],
                },
            },
            {
                name: 'set_nickname',
                description: 'Set the default MCP nickname used by future send_message calls.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        nickname: { type: 'string' },
                    },
                    required: ['nickname'],
                },
            },
            {
                name: 'tmux_send',
                description: 'Send text and optional Enter to a tmux session/pane. Defaults to the current MCP nickname when target/session is omitted.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        target: { type: 'string' },
                        session: { type: 'string' },
                        body: { type: 'string' },
                        enter: { type: 'boolean', default: false },
                        delay_ms: { type: 'number', default: 200 },
                    },
                },
            },
            {
                name: 'tmux_read',
                description: 'Read recent content from a tmux session/pane. Defaults to the current MCP nickname when target/session is omitted.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        target: { type: 'string' },
                        session: { type: 'string' },
                        lines: { type: 'number', default: 80 },
                    },
                },
            },
            {
                name: 'set_status',
                description: 'Set the current registered agent runtime status.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        status: { type: 'string', enum: ['busy', 'idle'] },
                    },
                    required: ['status'],
                },
            },
            {
                name: 'read_messages',
                description: 'Read recent messages from a channel.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        channel: { type: 'string', default: 'lobby' },
                        limit: { type: 'number', default: 20 },
                    },
                },
            },
            {
                name: 'claim_pending',
                description: 'Claim and clear any pending direct or channel work for the current registered agent.',
                inputSchema: { type: 'object', properties: {} },
            },
            {
                name: 'list_agents',
                description: 'List active intent agents plus registered MCP agents and their runtime status.',
                inputSchema: { type: 'object', properties: {} },
            },
            {
                name: 'list_channels',
                description: 'List channels from collab/intragent/channels.',
                inputSchema: { type: 'object', properties: {} },
            },
            {
                name: 'list_participants',
                description: 'List participants observed in a channel log.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        channel: { type: 'string', default: 'lobby' },
                    },
                },
            },
        ],
    }));

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
        const name = request.params.name;
        const params = request.params.arguments || {};

        if (name === 'send_message') {
            const sent = sendMessage({
                agent: params.agent || mcpAgent,
                channel: params.channel || getDefaultChannel(),
                to: params.to,
                body: params.body,
                quiet: true,
            });
            return { content: [{ type: 'text', text: formatRecord(sent) }] };
        }

        if (name === 'set_nickname') {
            const nickname = sanitize(params.nickname, '');
            if (!nickname) {
                throw new Error('set_nickname requires nickname');
            }

            mcpAgent = nickname;
            registerAgent(getSessionId(), mcpAgent);
            nudgeManagedAgentIfNeeded(mcpAgent);
            return { content: [{ type: 'text', text: `nickname=${mcpAgent}` }] };
        }

        if (name === 'tmux_send') {
            const target = tmuxSendKeys({
                target: mcpTmuxTarget(params),
                body: params.body,
                enter: params.enter,
                delay_ms: params.delay_ms,
                quiet: true,
                _: [],
            });
            return { content: [{ type: 'text', text: `target=${target}` }] };
        }

        if (name === 'tmux_read') {
            const text = tmuxReadPane({
                target: mcpTmuxTarget(params),
                lines: params.lines,
                quiet: true,
            });
            return { content: [{ type: 'text', text }] };
        }

        if (name === 'set_status') {
            const status = String(params.status || '').trim().toLowerCase();
            if (status !== 'busy' && status !== 'idle') {
                throw new Error('set_status requires status=busy|idle');
            }

            const nextStatus = setMcpAgentSessionStatus(getSessionId(), mcpAgent, status);
            if (!nextStatus) {
                throw new Error('set_status requires a registered MCP session');
            }

            if (nextStatus === 'idle') {
                nudgeManagedAgentIfNeeded(mcpAgent);
            }
            return { content: [{ type: 'text', text: `status=${nextStatus}` }] };
        }

        if (name === 'read_messages') {
            const channel = resolveChannelName({
                channel: params.channel,
                defaultChannel: getDefaultChannel(),
            }, 'lobby');
            const limit = toPositiveInt(params.limit, 20);
            const entries = readChannelEntries(channel, limit);
            const text = entries.length > 0
                ? entries.map((entry) => formatRecord(entry)).join('\n')
                : `channel #${channel} is empty`;
            return { content: [{ type: 'text', text }] };
        }

        if (name === 'claim_pending') {
            const payload = claimPendingForAgent(mcpAgent);
            return { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }] };
        }

        if (name === 'list_agents') {
            const rows = listAgentRows();
            const text = rows.length > 0
                ? rows.map((row) => `${row.agent}\t${row.state}\t${row.lock}\t${row.timestamp}`).join('\n')
                : 'no active agents';
            return { content: [{ type: 'text', text }] };
        }

        if (name === 'list_channels') {
            const files = fs.readdirSync(CHANNELS_DIR).filter((file) => file.endsWith('.jsonl')).sort();
            const text = files.length > 0
                ? files.map((file) => file.replace(/\.jsonl$/, '')).join('\n')
                : 'no channels yet';
            return { content: [{ type: 'text', text }] };
        }

        if (name === 'list_participants') {
            const channel = resolveChannelName({
                channel: params.channel,
                defaultChannel: getDefaultChannel(),
            }, 'lobby');
            const rows = listParticipantsRows(channel);
            const text = rows.length > 0
                ? rows.map((row) => `${row.agent}\t${row.status}\t${row.lock}\tlast_msg:${row.lastMsg}`).join('\n')
                : `no participants in #${channel}`;
            return { content: [{ type: 'text', text }] };
        }

        throw new Error(`Tool not found: ${name}`);
    });

    return server;
}

function getConfigResponse() {
    const config = CONFIG_STORE.load();
    return {
        ...config.summary,
        documents: config.documents,
        paths: config.paths,
    };
}

function collabMcpUrl(context) {
    const host = formatUrlHost(context.host);
    return `http://${host}:${context.port}${context.mcpPath}`;
}

function collabSseUrl(context) {
    const host = formatUrlHost(context.host);
    return `http://${host}:${context.port}${context.ssePath}`;
}

function handleAdminCommand(commandName, rawInput, context) {
    const input = requirePlainObject(rawInput || {}, 'command body');
    const positional = Array.isArray(input._) ? input._.map(String) : [];
    try {
        switch (commandName) {
            case 'send':
            case 'msg':
                return sendMessage({ ...input, quiet: true, _: positional });
            case 'join': {
                const channel = normalizeChannelName(input.channel, 'lobby');
                return sendMessage({
                    ...input,
                    channel,
                    to: 'all',
                    body: input.body ? String(input.body) : `joined #${channel}`,
                    kind: 'join',
                    quiet: true,
                    _: positional,
                });
            }
            case 'add-agent': {
                const agent = sanitize(input.agent || input.name || input.id || positional[0], '');
                const target = sanitize(input.target || input.session || agent, agent);
                return addManagedAgent(agent, target, {
                    role: input.role,
                    harness: input.harness,
                    backend: input.backend,
                    runtime: input.runtime,
                    model: input.model,
                    think: input.think,
                });
            }
            case 'remove-agent': {
                const agent = sanitize(input.agent || input.name || input.id || positional[0], '');
                return { agent, removed: removeManagedAgent(agent) };
            }
            case 'managed-agents':
                return listManagedAgentRows();
            case 'agents':
                return listKnownAgentEntries();
            case 'who': {
                const channel = normalizeChannelName(input.channel, 'lobby');
                return { channel, participants: listParticipantsRows(channel) };
            }
            case 'channels':
            case 'list':
                return listChannelStatusRows();
            case 'tmux-send':
                return tmuxSendKeys({ ...input, quiet: true, _: positional });
            case 'tmux-read':
                return tmuxReadPane({ ...input, quiet: true, _: positional });
            case 'create-agent': {
                const agent = sanitize(input.agent || input.name || input.id || positional[0], '');
                if (!agent) {
                    fail('create-agent requires --agent');
                }
                const role = sanitize(input.role || positional[1] || agent, agent);
                for (const name of ['runtime', 'harness', 'backend']) {
                    if (Object.hasOwn(input, name) && typeof input[name] !== 'string') {
                        fail(`create-agent --${name} requires a value`);
                    }
                }
                if (Object.hasOwn(input, 'model') && typeof input.model !== 'string') {
                    fail('create-agent --model requires a value');
                }
                const launchTarget = resolveLaunchTargetInput(input);
                const { harness, backend, runtime } = launchTarget;
                const model = String(input.model || '').trim();
                const think = normalizeAgentThink(input.think, launchTarget);
                rejectAgentSpawnOtp(input);
                if (runtime === 'ollama' && !model) {
                    fail('create-agent --runtime ollama requires --model');
                }
                const mcpUrl = mcpTransportFor(launchTarget) === 'sse'
                    ? collabSseUrl(context)
                    : collabMcpUrl(context);
                return createManagedAgent({
                    agent,
                    target: input.target,
                    role,
                    harness,
                    backend,
                    model,
                    think,
                    runtimeSessionId: '',
                    permissionMode: harness === 'codex' ? defaultCodexPermissionMode(process.env) : '',
                    channel: input.channel,
                    mcpUrl,
                    workdir: WORKSPACE_ROOT,
                    codexBin: input['codex-bin'],
                    agyBin: input['agy-bin'],
                    claudeBin: input['claude-bin'],
                    curlBin: input['curl-bin'],
                    ollamaEndpoint: input['ollama-endpoint'] || input['ollama-host'],
                    ollamaRuntimeDir: input['ollama-runtime-dir'],
                });
            }
            case 'resume-agent': {
                const agent = sanitize(input.agent || input.name || input.id || positional[0], '');
                const resumeId = String(input['session-id'] || input.session_id || input.sessionId || positional[1] || '').trim();
                if (!agent || !resumeId) {
                    fail('resume-agent requires --agent and --session-id');
                }
                const role = sanitize(input.role || positional[2] || agent, agent);
                for (const name of ['runtime', 'harness', 'backend']) {
                    if (Object.hasOwn(input, name) && typeof input[name] !== 'string') {
                        fail(`resume-agent --${name} requires a value`);
                    }
                }
                if (Object.hasOwn(input, 'model') && typeof input.model !== 'string') {
                    fail('resume-agent --model requires a value');
                }
                const launchTarget = resolveLaunchTargetInput(input);
                const { harness, backend, runtime } = launchTarget;
                const model = String(input.model || '').trim();
                const think = normalizeAgentThink(input.think, launchTarget);
                if (runtime === 'ollama' && !model) {
                    fail('resume-agent --runtime ollama requires --model');
                }
                const mcpUrl = mcpTransportFor(launchTarget) === 'sse'
                    ? collabSseUrl(context)
                    : collabMcpUrl(context);
                return createManagedAgent({
                    agent,
                    target: input.target,
                    role,
                    harness,
                    backend,
                    model,
                    think,
                    runtimeSessionId: resumeId,
                    permissionMode: harness === 'codex' ? defaultCodexPermissionMode(process.env) : '',
                    channel: input.channel,
                    mcpUrl,
                    workdir: WORKSPACE_ROOT,
                    resume: true,
                    codexBin: input['codex-bin'],
                    agyBin: input['agy-bin'],
                    claudeBin: input['claude-bin'],
                    curlBin: input['curl-bin'],
                    ollamaEndpoint: input['ollama-endpoint'] || input['ollama-host'],
                    ollamaRuntimeDir: input['ollama-runtime-dir'],
                });
            }
            default: {
                const error = new Error(`unsupported daemon command: ${commandName}`);
                error.statusCode = 404;
                throw error;
            }
        }
    } catch (error) {
        if (!Number.isInteger(error.statusCode)) {
            error.statusCode = 422;
        }
        throw error;
    }
}

function writeAdminError(res, error) {
    const statusCode = Number.isInteger(error && error.statusCode) ? error.statusCode : 500;
    const payload = {
        error: {
            code: statusCode,
            message: error && error.message ? error.message : String(error),
        },
    };
    if (error && error.currentRevision) {
        payload.error.currentRevision = error.currentRevision;
    }
    writeJsonResponse(res, statusCode, payload);
}

function isLoopbackAddress(value) {
    const address = String(value || '').split('%', 1)[0].toLowerCase();
    return address === '::1'
        || address === '::ffff:127.0.0.1'
        || /^127(?:\.\d{1,3}){3}$/.test(address);
}

function validateAdminRequest(req, requestUrl) {
    if (!isLoopbackAddress(req.socket && req.socket.remoteAddress)) {
        const error = new Error('collab admin API requires a loopback client');
        error.statusCode = 403;
        throw error;
    }
    const hostname = requestUrl.hostname;
    if (!['127.0.0.1', 'localhost', '[::1]'].includes(hostname)) {
        const error = new Error('collab admin API requires a loopback Host header');
        error.statusCode = 403;
        throw error;
    }

    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
        return;
    }
    const contentType = String(req.headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
    if (contentType !== 'application/json') {
        const error = new Error('collab admin mutations require application/json');
        error.statusCode = 415;
        throw error;
    }
    const fetchSite = String(req.headers['sec-fetch-site'] || '').trim().toLowerCase();
    if (fetchSite === 'cross-site') {
        const error = new Error('cross-site collab admin mutations are not allowed');
        error.statusCode = 403;
        throw error;
    }
    const origin = String(req.headers.origin || '').trim();
    if (origin) {
        let originUrl;
        try {
            originUrl = new URL(origin);
        } catch (_error) {
            const error = new Error('invalid request Origin');
            error.statusCode = 403;
            throw error;
        }
        if (originUrl.host !== requestUrl.host) {
            const error = new Error('cross-origin collab admin mutations are not allowed');
            error.statusCode = 403;
            throw error;
        }
    }
}

function basicAuthUsername(headerValue) {
    const header = Array.isArray(headerValue) ? headerValue[0] : headerValue;
    const match = String(header || '').match(/^Basic\s+([^\s]+)$/i);
    if (!match) {
        return '';
    }
    try {
        const decoded = Buffer.from(match[1], 'base64').toString('utf8');
        const separator = decoded.indexOf(':');
        return String(separator === -1 ? decoded : decoded.slice(0, separator)).trim();
    } catch (_error) {
        return '';
    }
}

function resolveAdminOperator(req) {
    const forwarded = Array.isArray(req.headers['x-notty-collab-operator'])
        ? req.headers['x-notty-collab-operator'][0]
        : req.headers['x-notty-collab-operator'];
    const basicAuthEnabled = ['1', 'true', 'yes', 'on'].includes(
        String(process.env.NOTTY_BASIC_AUTH_ENABLED || '').trim().toLowerCase(),
    );
    return String(
        forwarded
        || (basicAuthEnabled ? basicAuthUsername(req.headers.authorization) : '')
        || process.env.NOTTY_COLLAB_OPERATOR
        || 'operator',
    ).trim() || 'operator';
}

async function handleAdminRequest(req, res, requestUrl, context) {
    const pathname = requestUrl.pathname;
    if (!pathname.startsWith('/admin/v1/')) {
        return false;
    }

    try {
        validateAdminRequest(req, requestUrl);
        if (req.method === 'GET' && pathname === '/admin/v1/bootstrap') {
            const config = CONFIG_STORE.load();
            const session = SESSION_MANAGER.getSession();
            const launchCatalog = LAUNCH_CATALOG.read();
            writeJsonResponse(res, 200, {
                apiVersion: 'v1',
                daemon: {
                    marker: 'notty-collab-daemon',
                    version: 1,
                    pid: process.pid,
                },
                service: {
                    name: 'collab',
                    status: 'ready',
                    host: context.host,
                    port: context.port,
                    mcpPath: context.mcpPath,
                    ssePath: context.ssePath,
                    messagesPath: context.messagesPath,
                },
                workspaceRoot: WORKSPACE_ROOT,
                paths: {
                    appRoot: APP_ROOT,
                    workspaceRoot: WORKSPACE_ROOT,
                },
                config: config.summary,
                launchCatalog,
                modelCatalog: LAUNCH_CATALOG.legacy(),
                tasks: SESSION_MANAGER.tasks(),
                session,
                channels: listChannelNames(),
            });
            return true;
        }

        if (req.method === 'POST' && pathname === '/admin/v1/catalog/refresh') {
            await readJsonBody(req);
            LAUNCH_CATALOG.invalidate();
            const launchCatalog = LAUNCH_CATALOG.read({ refresh: true });
            const modelCatalog = LAUNCH_CATALOG.legacy();
            EVENT_HUB.emit('catalog.changed', { launchCatalog });
            writeJsonResponse(res, 200, { launchCatalog, modelCatalog });
            return true;
        }

        if (pathname === '/admin/v1/tasks') {
            if (req.method === 'GET') writeJsonResponse(res, 200, SESSION_MANAGER.tasks());
            else if (req.method === 'POST') {
                const body = requirePlainObject(await readJsonBody(req));
                writeJsonResponse(res, 201, SESSION_MANAGER.createTask(body.name));
            } else if (req.method === 'PATCH') {
                writeJsonResponse(res, 200, SESSION_MANAGER.taskSettings(requirePlainObject(await readJsonBody(req))));
            } else writeJsonResponse(res, 405, { error: 'Method not allowed' });
            return true;
        }

        if (req.method === 'GET' && pathname === '/admin/v1/config') {
            writeJsonResponse(res, 200, getConfigResponse());
            return true;
        }

        const configMatch = pathname.match(/^\/admin\/v1\/config\/(user|workspace)$/);
        if (req.method === 'PUT' && configMatch) {
            const body = requirePlainObject(await readJsonBody(req));
            if (!body || !body.document) {
                const error = new Error('request body must contain revision and document');
                error.statusCode = 400;
                throw error;
            }
            try {
                CONFIG_STORE.write(configMatch[1], body.revision, body.document);
            } catch (error) {
                if (!Number.isInteger(error.statusCode)) {
                    error.statusCode = 422;
                }
                throw error;
            }
            const response = getConfigResponse();
            EVENT_HUB.emit('config.changed', {
                scope: configMatch[1],
                revision: response.revisions[configMatch[1]],
            });
            writeJsonResponse(res, 200, response);
            return true;
        }

        if (pathname === '/admin/v1/session') {
            if (req.method === 'GET') {
                writeJsonResponse(res, 200, { session: SESSION_MANAGER.getSession() });
                return true;
            }
            if (req.method === 'POST') {
                const body = requirePlainObject(await readJsonBody(req));
                writeJsonResponse(res, 201, { session: await SESSION_MANAGER.launchTask(body) });
                return true;
            }
            if (req.method === 'PATCH') {
                const body = requirePlainObject(await readJsonBody(req));
                writeJsonResponse(res, 200, { session: SESSION_MANAGER.patch(body) });
                return true;
            }
            if (req.method === 'DELETE') {
                const result = SESSION_MANAGER.stop();
                writeJsonResponse(res, 200, { session: null, result });
                return true;
            }
        }

        const retryMatch = pathname.match(/^\/admin\/v1\/session\/agents\/([^/]+)\/retry$/);
        if (req.method === 'POST' && retryMatch) {
            const agentId = decodeURIComponent(retryMatch[1]);
            writeJsonResponse(res, 200, { session: await SESSION_MANAGER.retryTask(agentId) });
            return true;
        }

        const healthMatch = pathname.match(/^\/admin\/v1\/session\/agents\/([^/]+)\/health$/);
        if (req.method === 'PUT' && healthMatch) {
            const agentId = decodeURIComponent(healthMatch[1]);
            const body = requirePlainObject(await readJsonBody(req));
            writeJsonResponse(res, 200, {
                session: SESSION_MANAGER.setAgentHealth(agentId, body),
            });
            return true;
        }

        const permissionModeMatch = pathname.match(
            /^\/admin\/v1\/session\/agents\/([^/]+)\/permission-mode$/,
        );
        if (req.method === 'POST' && permissionModeMatch) {
            const agentId = decodeURIComponent(permissionModeMatch[1]);
            const body = requirePlainObject(await readJsonBody(req));
            writeJsonResponse(res, 200, {
                session: await SESSION_MANAGER.relaunch(agentId, body),
            });
            return true;
        }

        const commandMatch = pathname.match(/^\/admin\/v1\/commands\/([^/]+)$/);
        if (req.method === 'POST' && commandMatch) {
            const commandName = decodeURIComponent(commandMatch[1]);
            const result = handleAdminCommand(commandName, await readJsonBody(req), context);
            writeJsonResponse(res, 200, { result });
            return true;
        }

        if (req.method === 'GET' && pathname === '/admin/v1/stats') {
            writeJsonResponse(
                res,
                200,
                TELEMETRY_STORE.stats(requestUrl.searchParams.get('scope') || 'session'),
            );
            return true;
        }

        const feedbackMatch = pathname.match(
            /^\/admin\/v1\/channels\/([^/]+)\/messages\/([^/]+)\/feedback$/,
        );
        if (req.method === 'PUT' && feedbackMatch) {
            const channel = normalizeChannelName(decodeURIComponent(feedbackMatch[1]), 'lobby');
            const messageId = decodeURIComponent(feedbackMatch[2]);
            const body = requirePlainObject(await readJsonBody(req));
            if (!Object.prototype.hasOwnProperty.call(body, 'rating')) {
                const error = new Error('request body must contain rating');
                error.statusCode = 400;
                throw error;
            }
            writeJsonResponse(res, 200, TELEMETRY_STORE.rate({
                channel,
                messageId,
                operator: resolveAdminOperator(req),
                rating: body.rating,
            }));
            return true;
        }

        const channelMatch = pathname.match(/^\/admin\/v1\/channels\/([^/]+)\/messages$/);
        if (channelMatch && (req.method === 'GET' || req.method === 'POST')) {
            const channel = normalizeChannelName(decodeURIComponent(channelMatch[1]), 'lobby');
            if (req.method === 'GET') {
                const limit = Math.min(toPositiveInt(requestUrl.searchParams.get('limit'), 100), 500);
                const rawCursor = requestUrl.searchParams.get('cursor');
                let cursor = null;
                if (rawCursor !== null) {
                    cursor = Number.parseInt(rawCursor, 10);
                    if (!Number.isSafeInteger(cursor) || cursor < 0) {
                        const error = new Error('cursor must be a non-negative integer');
                        error.statusCode = 400;
                        throw error;
                    }
                }
                const page = readChannelPage(channel, limit, cursor);
                writeJsonResponse(res, 200, {
                    channel,
                    ...page,
                    messages: TELEMETRY_STORE.enrich(
                        page.messages,
                        resolveAdminOperator(req),
                    ),
                });
                return true;
            }
            const body = requirePlainObject(await readJsonBody(req));
            if (!body || !String(body.body || '').trim()) {
                const error = new Error('request body must contain a non-empty body');
                error.statusCode = 400;
                throw error;
            }
            const message = sendMessage({
                agent: body.agent || 'operator',
                channel,
                to: body.to || 'all',
                body: String(body.body),
                kind: body.kind === 'mirror' ? 'mirror' : 'message',
                authorType: body.kind === 'mirror' ? 'mirror' : 'human',
                quiet: true,
                _: [],
            });
            writeJsonResponse(res, 201, { message });
            return true;
        }

        if (req.method === 'GET' && pathname === '/admin/v1/events') {
            EVENT_HUB.attach(req, res);
            return true;
        }

        writeJsonResponse(res, 404, { error: { code: 404, message: 'Admin endpoint not found' } });
        return true;
    } catch (error) {
        writeAdminError(res, error);
        return true;
    }
}

async function startMcpSseBridge(input) {
    const sdk = await loadMcpSdk();
    const host = resolveListenHost(input.ip, '127.0.0.1');
    const port = toPositiveInt(input.port, 1337);
    const mcpPath = input.mcpPath ? String(input.mcpPath).trim() : '/mcp';
    const ssePath = input.ssePath ? String(input.ssePath).trim() : '/sse';
    const messagesPath = input.messagesPath ? String(input.messagesPath).trim() : '/messages';
    const logLine = typeof input.logLine === 'function'
        ? input.logLine
        : (text) => process.stdout.write(`${text}\n`);
    CONFIG_STORE.load();
    SESSION_MANAGER = createSessionManager({
        appRoot: APP_ROOT,
        workspaceRoot: WORKSPACE_ROOT,
        configStore: CONFIG_STORE,
        eventHub: EVENT_HUB,
        mcpUrl: `http://${formatUrlHost(host)}:${port}${mcpPath}`,
        sseUrl: `http://${formatUrlHost(host)}:${port}${ssePath}`,
        describeAgent: describeManagedAgentEntry,
        addManagedAgent,
        removeManagedAgent,
        clearAgentRuntime,
        listLegacyManagedAgents: listManagedAgentRows,
        postMessage: (message) => sendMessage({ ...message, authorType: 'human' }),
    });
    SESSION_MANAGER.reconcile();
    const reconciliationTimer = setInterval(() => {
        try {
            SESSION_MANAGER.reconcile();
        } catch (error) {
            logLine(`[collab] session reconciliation failed: ${error.message || String(error)}`);
        }
    }, 1000);
    reconciliationTimer.unref();
    const transports = new Map();
    const httpServer = http.createServer(async (req, res) => {
        const requestUrl = new URL(
            req.url || '/',
            `http://${req.headers.host || `${formatUrlHost(host)}:${port}`}`,
        );

        if (await handleAdminRequest(req, res, requestUrl, {
            host,
            port,
            mcpPath,
            ssePath,
            messagesPath,
        })) {
            return;
        }

        if (requestUrl.pathname === mcpPath &&
            (req.method === 'GET' || req.method === 'POST' || req.method === 'DELETE')) {
            try {
                const sessionHeader = req.headers['mcp-session-id'];
                const sessionId = Array.isArray(sessionHeader) ? sessionHeader[0] : sessionHeader || '';
                const parsedBody = req.method === 'POST' ? await readJsonBody(req) : undefined;
                let transport = null;

                if (sessionId) {
                    const entry = transports.get(sessionId);
                    if (!entry) {
                        writeMcpError(res, 400, 'Bad Request: No valid session ID provided');
                        return;
                    }
                    if (!(entry.transport instanceof sdk.StreamableHTTPServerTransport)) {
                        writeMcpError(res, 400, 'Bad Request: Session exists but uses a different transport protocol');
                        return;
                    }
                    transport = entry.transport;
                } else {
                    if (req.method !== 'POST' || !sdk.isInitializeRequest(parsedBody)) {
                        writeMcpError(res, 400, 'Bad Request: No valid session ID provided');
                        return;
                    }

                    let entry = null;
                    transport = new sdk.StreamableHTTPServerTransport({
                        sessionIdGenerator: () => randomUUID(),
                        onsessioninitialized: (newSessionId) => {
                            transports.set(newSessionId, entry);
                        },
                    });

                    const server = createMcpServer(sdk, {
                        getDefaultAgent: input.getDefaultAgent,
                        getDefaultChannel: input.getDefaultChannel,
                        getSessionId: () => transport.sessionId || '',
                        registerAgent: registerMcpAgentSession,
                        listAgentRows: listKnownAgentEntries,
                    });
                    entry = { transport, server };

                    transport.onclose = () => {
                        const closedSessionId = transport.sessionId;
                        if (closedSessionId) {
                            unregisterMcpAgentSession(closedSessionId);
                            transports.delete(closedSessionId);
                        }
                    };

                    await server.connect(transport);
                    logLine('[mcp] streamable HTTP client initialized');
                }

                await transport.handleRequest(req, res, parsedBody);
                return;
            } catch (error) {
                if (!res.headersSent) {
                    writeMcpError(res, 500, 'Internal server error');
                }
                logLine(`[mcp] streamable http error: ${error.message}`);
                return;
            }
        }

        if (req.method === 'GET' && requestUrl.pathname === ssePath) {
            try {
                const transport = new sdk.SSEServerTransport(messagesPath, res);
                const sessionId = transport.sessionId;
                const server = createMcpServer(sdk, {
                    getDefaultAgent: input.getDefaultAgent,
                    getDefaultChannel: input.getDefaultChannel,
                    getSessionId: () => transport.sessionId || sessionId,
                    registerAgent: registerMcpAgentSession,
                    listAgentRows: listKnownAgentEntries,
                });
                transports.set(sessionId, { transport, server });
                transport.onclose = () => {
                    unregisterMcpAgentSession(sessionId);
                    transports.delete(sessionId);
                };
                await server.connect(transport);
                logLine(`[mcp] sse client connected session=${sessionId}`);
                return;
            } catch (error) {
                if (!res.headersSent) {
                    res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
                    res.end('Error establishing SSE stream');
                }
                logLine(`[mcp] sse stream error: ${error.message}`);
                return;
            }
        }

        if (req.method === 'POST' && requestUrl.pathname === messagesPath) {
            const sessionId = requestUrl.searchParams.get('sessionId');
            if (!sessionId) {
                res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
                res.end('Missing sessionId parameter');
                return;
            }

            const entry = transports.get(sessionId);
            if (!entry) {
                res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
                res.end('Session not found');
                return;
            }

            try {
                await entry.transport.handlePostMessage(req, res);
            } catch (error) {
                if (!res.headersSent) {
                    res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
                    res.end('Error handling request');
                }
                logLine(`[mcp] sse message error: ${error.message}`);
            }
            return;
        }

        if (req.method === 'GET' && requestUrl.pathname === '/') {
            const status = {
                name: 'collab',
                transport: 'streamable-http+sse',
                host,
                port,
                mcp_path: mcpPath,
                sse_path: ssePath,
                messages_path: messagesPath,
                default_agent: sanitize(
                    typeof input.getDefaultAgent === 'function' ? input.getDefaultAgent() : resolveDefaultAgentId('agent'),
                    'agent',
                ),
                default_channel: sanitize(
                    typeof input.getDefaultChannel === 'function' ? input.getDefaultChannel() : 'lobby',
                    'lobby',
                ),
                sessions: transports.size,
            };
            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify(status, null, 2));
            return;
        }

        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Not found');
    });

    return await new Promise((resolve, reject) => {
        let settled = false;
        const finishError = (error) => {
            if (settled) {
                logLine(`[mcp] sse listener error: ${error.message}`);
                return;
            }

            settled = true;
            clearInterval(reconciliationTimer);
            reject(error);
        };

        httpServer.once('error', finishError);
        httpServer.listen(port, host, () => {
            if (settled) {
                return;
            }

            settled = true;
            httpServer.off('error', finishError);
            httpServer.on('error', (error) => {
                logLine(`[mcp] sse listener error: ${error.message}`);
            });
            resolve({
                host,
                port,
                mcpPath,
                ssePath,
                messagesPath,
                async close() {
                    clearInterval(reconciliationTimer);
                    for (const entry of transports.values()) {
                        await entry.transport.close();
                    }
                    transports.clear();
                    await new Promise((done) => httpServer.close(done));
                },
            });
        });
    });
}

function resolveRemoteMcpUrl(input = {}) {
    const value = String(input.server || input.url || input['mcp-url'] || input.mcp_url || defaultAgentMcpUrl()).trim();
    const parsed = new URL(value);
    if (parsed.pathname === '/' || parsed.pathname === '') {
        parsed.pathname = '/mcp';
    }
    return parsed;
}

async function startMcpStdioProxy(sdk, input = {}) {
    let client = null;
    let remoteTransport = null;
    try {
        client = new sdk.Client({ name: 'collab-stdio-proxy', version: '1.0.0' });
        remoteTransport = new sdk.StreamableHTTPClientTransport(resolveRemoteMcpUrl(input));
        await client.connect(remoteTransport, { timeout: 1000 });
        await client.callTool({
            name: 'set_nickname',
            arguments: { nickname: sanitize(input.agent || resolveDefaultAgentId('agent'), 'agent') },
        }, undefined, { timeout: 1000 });
    } catch (error) {
        if (remoteTransport) {
            try {
                await remoteTransport.close();
            } catch (_closeError) {
                // Preserve the original connection failure.
            }
        }
        throw new Error(`unable to connect stdio MCP proxy to collab daemon: ${error.message || String(error)}`);
    }

    const server = new sdk.Server(
        { name: 'collab', version: '1.0.0' },
        { capabilities: { tools: {} } },
    );
    server.setRequestHandler(sdk.ListToolsRequestSchema, async (request) => {
        return await client.listTools(request.params || {});
    });
    server.setRequestHandler(sdk.CallToolRequestSchema, async (request) => {
        return await client.callTool(request.params);
    });
    const transport = new sdk.StdioServerTransport();
    await server.connect(transport);
    return true;
}

async function startMcpServer(input = {}) {
    if (input.transport === 'sse' || toBoolean(input.sse, false)) {
        const bridge = await startMcpSseBridge(input);
        process.stdout.write(`${formatMcpSseStatus(bridge, {
            agent: sanitize(
                typeof input.getDefaultAgent === 'function' ? input.getDefaultAgent() : input.agent || resolveDefaultAgentId('agent'),
                'agent',
            ),
            channel: sanitize(
                typeof input.getDefaultChannel === 'function' ? input.getDefaultChannel() : input.channel || 'lobby',
                'lobby',
            ),
        })}\n`);
        return;
    }

    const sdk = await loadMcpSdk();
    const standalone = toBoolean(input.standalone, false)
        || toBoolean(process.env.NOTTY_COLLAB_STANDALONE, false);
    if (!standalone) {
        await startMcpStdioProxy(sdk, input);
        return;
    }
    const server = createMcpServer(sdk, {
        defaultAgent: input.agent || resolveDefaultAgentId('agent'),
        defaultChannel: input.channel || 'lobby',
    });
    const transport = new sdk.StdioServerTransport();
    await server.connect(transport);
}

function listActiveAgentEntries() {
    if (!fs.existsSync(ACTIVE_DIR)) {
        return [];
    }

    const files = fs.readdirSync(ACTIVE_DIR).filter((name) => name.endsWith('.intent')).sort();
    const rows = [];

    for (const name of files) {
        const raw = fs.readFileSync(path.join(ACTIVE_DIR, name), 'utf8');
        const fields = parseFlatFields(raw);

        rows.push({
            agent: fields.agent_id || name.replace(/\.intent$/, ''),
            state: fields.state || 'unknown',
            lock: fields.lock || '-',
            timestamp: fields.timestamp || '-',
        });
    }

    return rows;
}

function readBoundedFileRange(filePath, startOffset, endOffset) {
    const start = Number.isSafeInteger(startOffset) && startOffset >= 0 ? startOffset : 0;
    const end = Number.isSafeInteger(endOffset) && endOffset > start ? endOffset : start;
    const length = Math.min(end - start, MAX_CHANNEL_READ_BYTES);
    if (length <= 0) {
        return { chunk: Buffer.alloc(0), endOffset: start };
    }

    const chunk = Buffer.alloc(length);
    const fd = fs.openSync(filePath, 'r');
    let bytesRead = 0;
    try {
        while (bytesRead < chunk.length) {
            const count = fs.readSync(
                fd,
                chunk,
                bytesRead,
                chunk.length - bytesRead,
                start + bytesRead,
            );
            if (count === 0) {
                break;
            }
            bytesRead += count;
        }
    } finally {
        fs.closeSync(fd);
    }

    return {
        chunk: bytesRead === chunk.length ? chunk : chunk.subarray(0, bytesRead),
        endOffset: start + bytesRead,
    };
}

function readChannelLineBatch(filePath, startOffset, endOffset) {
    const { chunk, endOffset: readEnd } = readBoundedFileRange(filePath, startOffset, endOffset);
    const entries = [];
    let lineStart = 0;
    while (lineStart < chunk.length) {
        const newline = chunk.indexOf(0x0a, lineStart);
        if (newline === -1) {
            break;
        }
        entries.push({
            line: chunk.subarray(lineStart, newline).toString('utf8'),
            cursor: startOffset + newline + 1,
        });
        lineStart = newline + 1;
    }

    if (entries.length > 0) {
        return { entries, cursor: entries[entries.length - 1].cursor };
    }

    // A record larger than the read window must not permanently stall a follower.
    // Skip this window only when more of the snapshotted file remains; an unfinished
    // record at EOF stays pending until its terminating newline is appended.
    const cursor = readEnd > startOffset && readEnd < endOffset ? readEnd : startOffset;
    return { entries, cursor };
}

function readRecentChannelLines(filePath, limit) {
    const size = fs.statSync(filePath).size;
    if (size === 0) {
        return [];
    }

    // Reserve one byte to determine whether the bounded tail starts on a record
    // boundary, avoiding the accidental parsing of a truncated JSON prefix.
    const contentStart = Math.max(0, size - (MAX_CHANNEL_READ_BYTES - 1));
    const readStart = contentStart > 0 ? contentStart - 1 : 0;
    const { chunk } = readBoundedFileRange(filePath, readStart, size);
    let lineStart = 0;
    if (readStart > 0) {
        if (chunk[0] === 0x0a) {
            lineStart = 1;
        } else {
            const firstNewline = chunk.indexOf(0x0a, 1);
            if (firstNewline === -1) {
                return [];
            }
            lineStart = firstNewline + 1;
        }
    }

    return chunk.subarray(lineStart).toString('utf8').split('\n').filter(Boolean).slice(-limit);
}

function forEachChannelLine(filePath, visit) {
    const size = fs.statSync(filePath).size;
    let offset = 0;
    while (offset < size) {
        const batch = readChannelLineBatch(filePath, offset, size);
        for (const entry of batch.entries) {
            visit(entry.line);
        }
        if (batch.cursor <= offset) {
            break;
        }
        offset = batch.cursor;
    }
}

function findChannelMessage(channel, messageId) {
    const cleanChannel = normalizeChannelName(channel, 'lobby');
    const cleanMessageId = String(messageId || '').trim();
    if (!cleanMessageId) {
        return null;
    }
    const channelPath = path.join(CHANNELS_DIR, `${cleanChannel}.jsonl`);
    if (!fs.existsSync(channelPath)) {
        return null;
    }
    let match = null;
    forEachChannelLine(channelPath, (line) => {
        if (match) {
            return;
        }
        const record = safeJson(line);
        if (record && record.id === cleanMessageId && record.channel === cleanChannel) {
            match = record;
        }
    });
    return match;
}

function forEachStoredChannelMessage(visit) {
    for (const channel of listChannelNames()) {
        const channelPath = path.join(CHANNELS_DIR, `${channel}.jsonl`);
        try {
            forEachChannelLine(channelPath, (line) => {
                const record = safeJson(line);
                if (record) {
                    visit(record);
                }
            });
        } catch (error) {
            if (error && error.code !== 'ENOENT') {
                throw error;
            }
        }
    }
}

function listParticipantsRows(channel) {
    const channelPath = path.join(CHANNELS_DIR, `${channel}.jsonl`);
    if (!fs.existsSync(channelPath)) {
        return [];
    }

    const participants = new Map();
    forEachChannelLine(channelPath, (line) => {
        const parsed = safeJson(line);
        if (!parsed || !parsed.agent_id) {
            return;
        }
        participants.set(parsed.agent_id, parsed.timestamp || '-');
    });

    const activeMap = new Map(listActiveAgentEntries().map((row) => [row.agent, row]));
    return Array.from(participants.keys()).sort().map((agent) => {
        const active = activeMap.get(agent);
        return {
            agent,
            status: active ? active.state : 'offline',
            lock: active ? active.lock : '-',
            lastMsg: participants.get(agent),
        };
    });
}

function resolveChannelSources(options) {
    const allChannels = Boolean(options && options.allChannels);
    const requestedChannels = Array.isArray(options && options.requestedChannels)
        ? options.requestedChannels
        : [];
    const createMissing = Boolean(options && options.createMissing);

    const channelNames = allChannels
        ? listChannelNames()
        : dedupeAndSortChannels(requestedChannels.length > 0 ? requestedChannels : ['lobby']);
    const sources = [];

    for (const channel of channelNames) {
        const filePath = path.join(CHANNELS_DIR, `${channel}.jsonl`);
        if (!fs.existsSync(filePath) && createMissing) {
            fs.writeFileSync(filePath, '', 'utf8');
        }
        if (fs.existsSync(filePath)) {
            sources.push({ channel, filePath });
        }
    }

    return sources;
}

function listChannelNames() {
    if (!fs.existsSync(CHANNELS_DIR)) {
        return [];
    }

    return fs.readdirSync(CHANNELS_DIR)
        .filter((name) => name.endsWith('.jsonl'))
        .map((name) => name.replace(/\.jsonl$/, ''))
        .filter(Boolean)
        .sort();
}

function listChannelStatusRows() {
    return listChannelNames().map((channel) => {
        const stat = fs.statSync(path.join(CHANNELS_DIR, `${channel}.jsonl`));
        return {
            channel,
            bytes: stat.size,
            updatedAt: stat.mtime.toISOString(),
        };
    });
}

function readRecentFromSources(sources, lines) {
    const records = [];

    for (const source of sources) {
        if (!fs.existsSync(source.filePath)) {
            continue;
        }

        const entries = readRecentChannelLines(source.filePath, lines);
        for (const line of entries) {
            const record = parseChannelLine(line, source.channel);
            if (record) {
                records.push(record);
            }
        }
    }

    return records.sort(sortRecordsByTimestamp);
}

function seedSourceOffsets(offsets, sources) {
    const activePaths = new Set();

    for (const source of sources) {
        activePaths.add(source.filePath);
        if (!offsets.has(source.filePath)) {
            const size = fs.existsSync(source.filePath) ? fs.statSync(source.filePath).size : 0;
            offsets.set(source.filePath, size);
        }
    }

    for (const filePath of Array.from(offsets.keys())) {
        if (!activePaths.has(filePath)) {
            offsets.delete(filePath);
        }
    }
}

function readSourceDeltas(sources, offsets) {
    const records = [];

    for (const source of sources) {
        let currentSize = 0;
        try {
            currentSize = fs.statSync(source.filePath).size;
        } catch (error) {
            offsets.delete(source.filePath);
            continue;
        }

        const previousSize = offsets.has(source.filePath) ? offsets.get(source.filePath) : currentSize;
        if (currentSize < previousSize) {
            offsets.set(source.filePath, 0);
        }

        const startOffset = offsets.has(source.filePath) ? offsets.get(source.filePath) : 0;
        if (currentSize === startOffset) {
            continue;
        }

        const batch = readChannelLineBatch(source.filePath, startOffset, currentSize);
        offsets.set(source.filePath, batch.cursor);

        for (const entry of batch.entries) {
            const record = parseChannelLine(entry.line, source.channel);
            if (record) {
                records.push(record);
            }
        }
    }

    return records;
}

function parseChannelLine(line, fallbackChannel) {
    const parsed = safeJson(line);
    if (!parsed) {
        return null;
    }
    return normalizeRecord(parsed, fallbackChannel);
}

function normalizeRecord(record, fallbackChannel) {
    return {
        id: record.id || '',
        timestamp: record.timestamp || '-',
        kind: record.kind || 'message',
        agent_id: record.agent_id || 'unknown',
        channel: normalizeChannelName(record.channel || fallbackChannel || 'lobby', 'lobby'),
        to: record.to || 'all',
        body: record.body || '',
    };
}

function sortRecordsByTimestamp(left, right) {
    const leftScore = timestampScore(left && left.timestamp);
    const rightScore = timestampScore(right && right.timestamp);
    if (leftScore !== rightScore) {
        return leftScore - rightScore;
    }
    return 0;
}

function timestampScore(value) {
    const score = Date.parse(value || '');
    if (Number.isFinite(score)) {
        return score;
    }
    return 0;
}

function matchesWatchFilters(record, filters) {
    if (!record) {
        return false;
    }

    if (filters.agentFilter && record.agent_id !== filters.agentFilter) {
        return false;
    }

    if (filters.toFilter) {
        return record.to === 'all' || record.to === filters.toFilter;
    }

    return true;
}

function shouldMirrorRecord(record, options) {
    if (!record || !record.body) {
        return false;
    }

    if (record.kind === 'mirror' && record.agent_id === options.mirrorAgent) {
        return false;
    }

    if (record.channel === options.targetChannel && (record.to === 'all' || record.to === options.recipient)) {
        return false;
    }

    return true;
}

function formatMirrorBody(record) {
    const sourceChannel = record.channel || 'lobby';
    const sourceAgent = record.agent_id || 'unknown';
    const sourceTo = record.to || 'all';
    const sourceKind = record.kind || 'message';
    const sourceBody = record.body || '';
    return `[src #${sourceChannel} ${sourceAgent} -> ${sourceTo} (${sourceKind})] ${sourceBody}`;
}

function readChannelEntries(channel, limit) {
    const channelPath = path.join(CHANNELS_DIR, `${channel}.jsonl`);
    if (!fs.existsSync(channelPath)) {
        return [];
    }

    const entries = [];
    const lines = readRecentChannelLines(channelPath, limit);

    for (const line of lines) {
        const parsed = safeJson(line);
        if (parsed) {
            entries.push(parsed);
        }
    }

    return entries;
}

function readChannelPage(channel, limit, cursor = null) {
    const channelPath = path.join(CHANNELS_DIR, `${channel}.jsonl`);
    if (!fs.existsSync(channelPath)) {
        return { messages: [], cursor: 0 };
    }
    const size = fs.statSync(channelPath).size;
    if (cursor === null) {
        return { messages: readChannelEntries(channel, limit), cursor: size };
    }
    const start = cursor > size ? 0 : cursor;
    if (start === size) {
        return { messages: [], cursor: size };
    }
    const batch = readChannelLineBatch(channelPath, start, size);
    const messages = [];
    let nextCursor = batch.entries.length === 0 ? batch.cursor : start;
    for (const entry of batch.entries) {
        nextCursor = entry.cursor;
        const parsed = entry.line ? safeJson(entry.line) : null;
        if (parsed) {
            messages.push(parsed);
        }
        if (messages.length >= limit) {
            break;
        }
    }
    return { messages, cursor: nextCursor };
}

function printRecent(channelPath, lines, formatEntry = formatRecord, writeLine = writeStdoutLine) {
    const entries = readRecentChannelLines(channelPath, lines);

    if (entries.length === 0) {
        writeLine('channel is empty');
        return;
    }

    for (const line of entries) {
        const parsed = safeJson(line);
        writeLine(parsed ? formatEntry(parsed) : `[raw] ${line}`);
    }
}

function parseFlatFields(raw) {
    const out = {};

    for (const line of raw.split('\n')) {
        const idx = line.indexOf(':');
        if (idx <= 0) {
            continue;
        }

        const key = line.slice(0, idx).trim();
        const value = line.slice(idx + 1).trim();
        if (key) {
            out[key] = value;
        }
    }

    return out;
}

function safeJson(line) {
    try {
        return JSON.parse(line);
    } catch (error) {
        return null;
    }
}

function splitTimestampParts(value) {
    const text = value ? String(value) : '-';
    const match = text.match(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/);

    if (!match) {
        return {
            dateKey: '',
            dateTime: text,
            time: text,
        };
    }

    return {
        dateKey: match[1],
        dateTime: `${match[1]} ${match[2]}`,
        time: match[2],
    };
}

function formatRecord(record, options = {}) {
    const time = record.timestamp || '-';
    const channel = record.channel || 'lobby';
    const from = record.agent_id || 'unknown';
    const to = record.to || 'all';
    const body = record.body || '';
    const kind = record.kind || 'message';
    if (options.ircMode) {
        const timestamp = splitTimestampParts(record.timestamp);
        const renderedTime = options.includeDate ? timestamp.dateTime : timestamp.time;
        const highlightedBody = colorizeMarkdownBody(body);
        const roleMeta = getIrcRoleMeta(from);
        if (kind === 'join') {
            return `${roleMeta.glyph} ${IRC_STYLE_TIME}[${renderedTime}]${IRC_STYLE_RESET} ${roleMeta.color}${from}${IRC_STYLE_RESET} joined ${IRC_STYLE_CHANNEL}#${channel}${IRC_STYLE_RESET}`;
        }
        if (kind === 'message' && (!to || to === 'all')) {
            return `${roleMeta.glyph} ${IRC_STYLE_TIME}[${renderedTime}]${IRC_STYLE_RESET} ${roleMeta.color}${from}${IRC_STYLE_RESET}: ${highlightedBody}`;
        }
        if (kind === 'message') {
            return `${roleMeta.glyph} ${IRC_STYLE_TIME}[${renderedTime}]${IRC_STYLE_RESET} ${roleMeta.color}${from}${IRC_STYLE_RESET} to ${IRC_STYLE_DEST}${to}${IRC_STYLE_RESET}: ${highlightedBody}`;
        }
        if (!to || to === 'all') {
            return `${roleMeta.glyph} ${IRC_STYLE_TIME}[${renderedTime}]${IRC_STYLE_RESET} ${roleMeta.color}${from}${IRC_STYLE_RESET} ${kind}: ${highlightedBody}`;
        }
        return `${roleMeta.glyph} ${IRC_STYLE_TIME}[${renderedTime}]${IRC_STYLE_RESET} ${roleMeta.color}${from}${IRC_STYLE_RESET} ${kind} ${IRC_STYLE_DEST}${to}${IRC_STYLE_RESET}: ${highlightedBody}`;
    }
    return `[${time}] #${channel} ${from} -> ${to} (${kind}): ${body}`;
}

function getIrcRoleMeta(agent) {
    const role = resolveIrcRole(agent);
    const glyph = IRC_GLYPH[role] || '•';
    const color = IRC_ROLE_COLOR[role] || '\x1b[1;37m';
    return {
        color,
        glyph: `${color}${glyph}${IRC_STYLE_RESET}`,
    };
}

function resolveIrcRole(agent) {
    const candidate = String(agent || '').toLowerCase();

    if (candidate in IRC_GLYPH) {
        return candidate;
    }

    if (candidate === 'codex' || candidate === 'ai' || candidate.includes('bot')) {
        return 'coder';
    }

    if (candidate === 'kross' || candidate === 'human') {
        return 'human';
    }

    return '';
}

function formatIrcKindStyle(kind) {
    switch (String(kind || '').toLowerCase()) {
        case 'join':
            return IRC_STYLE_KIND_JOIN;
        case 'message':
            return IRC_STYLE_KIND_MESSAGE;
        default:
            return IRC_STYLE_BOLD;
    }
}

function colorizeMarkdownBody(body) {
    if (!body) {
        return body;
    }

    const codeFragments = [];
    const protectedBody = body.replace(/```[\s\S]*?```|`[^`\n]+`/g, (match) => {
        const token = `__IRC_CODE_${codeFragments.length}__`;
        codeFragments.push(`${IRC_STYLE_CODE}${match}${IRC_STYLE_RESET}`);
        return token;
    });

    let markdownBody = protectedBody
        .replace(/^#{1,6}\s+(.+)$/gm, `${IRC_STYLE_HEADING}$&${IRC_STYLE_RESET}`)
        .replace(/\*\*([^*\n]+)\*\*/g, (match, content) => `${IRC_STYLE_BOLD}${content}${IRC_STYLE_RESET}`);

    for (let i = 0; i < codeFragments.length; i += 1) {
        markdownBody = markdownBody.replace(`__IRC_CODE_${i}__`, codeFragments[i]);
    }

    return markdownBody;
}

function sanitize(value, fallback) {
    const raw = String(value || fallback || '').trim();
    const clean = raw.replace(/[^A-Za-z0-9._-]/g, '_');
    return clean || fallback;
}

function parseChannelList(value) {
    if (value === undefined || value === null) {
        return [];
    }

    const tokens = String(value)
        .split(',')
        .map((item) => sanitize(item, ''))
        .filter(Boolean);
    return dedupeAndSortChannels(tokens);
}

function dedupeAndSortChannels(channels) {
    return Array.from(new Set(channels)).sort();
}

function toPositiveInt(value, fallback) {
    const parsed = Number.parseInt(String(value || ''), 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function toNonNegativeInt(value, fallback) {
    const parsed = Number.parseInt(String(value || ''), 10);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function toBoolean(value, fallback) {
    if (value === undefined || value === null) {
        return fallback;
    }

    if (typeof value === 'boolean') {
        return value;
    }

    const raw = String(value).trim().toLowerCase();
    if (raw === '') {
        return true;
    }

    if (['1', 'true', 'yes', 'y', 'on'].includes(raw)) {
        return true;
    }

    if (['0', 'false', 'no', 'n', 'off'].includes(raw)) {
        return false;
    }

    return fallback;
}

function ensureDir(dir) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
}

function fail(message) {
    throw new Error(String(message));
}

function printHelp() {
    process.stdout.write('collab.cjs - intragent bus + cross-channel watch/mirror\n\n');
    process.stdout.write('usage:\n');
    process.stdout.write('  node collab.cjs send --agent codex --channel lobby --to all --body "ready"\n');
    process.stdout.write('  node collab.cjs create-agent --agent coder [--role planner] [--harness codex|agy|claude] [--backend default|ollama] [--model "model"] [--think level]\n');
    process.stdout.write('  node collab.cjs resume-agent --agent coder --session-id <id> [--harness codex|agy|claude] [--backend default|ollama] [--model "model"] [--think level]\n');
    process.stdout.write('  node collab.cjs add-agent --agent coder [--target coder]\n');
    process.stdout.write('  node collab.cjs remove-agent --agent coder\n');
    process.stdout.write('  node collab.cjs managed-agents\n');
    process.stdout.write('  node collab.cjs watch --all-channels --follow\n');
    process.stdout.write('  node collab.cjs mirror --all-channels --target-channel lobby --to kross --follow\n');
    process.stdout.write('  node collab.cjs tail --channel lobby --lines 20 [--follow]\n');
    process.stdout.write('  node collab.cjs join --agent codex --channel lobby\n');
    process.stdout.write('  node collab.cjs who --channel lobby\n');
    process.stdout.write('  node collab.cjs irc --agent kross --channel lobby [--server http://127.0.0.1:1337]\n');
    process.stdout.write('  node collab.cjs irc --server http://127.0.0.1:1337 --agent kross --channel lobby\n');
    process.stdout.write('  node collab.cjs agents\n');
    process.stdout.write('  node collab.cjs channels\n');
    process.stdout.write('  node collab.cjs tmux-send --session coder --body "wake up" --enter --delay-ms 200\n');
    process.stdout.write('  node collab.cjs tmux-read --session coder --lines 40\n');
    process.stdout.write('  node collab.cjs mcp [--server http://127.0.0.1:1337]\n');
    process.stdout.write('  node collab.cjs mcp --transport sse --ip 127.0.0.1 --port 1337\n');
    process.stdout.write('  node collab.cjs daemon --ip 127.0.0.1 --port 1337\n');
    process.stdout.write('  node collab.cjs irc --standalone --channel lobby --ip 127.0.0.1 --port 1337 --fresh\n');
    process.stdout.write('\nnotes:\n');
    process.stdout.write('  use channel names like lobby, not #lobby\n');
    process.stdout.write('  mutating commands, irc, and stdio mcp use the loopback daemon by default; --standalone explicitly enables legacy local behavior\n');
    process.stdout.write('  --fresh is available only with --standalone and clears legacy active, message, channel, managed-agent, and feedback runtime files\n');
    process.stdout.write('  Codex, Agy, and Claude are agent harnesses; default and Ollama are model backends; Ollama currently requires Codex\n');
    process.stdout.write('  create-agent launches Codex/default by default; legacy --runtime codex|agy|ollama|claude aliases remain accepted\n');
    process.stdout.write('  --think sets Codex reasoning effort or Agy/Claude --effort; bare --think selects high where supported\n');
    process.stdout.write('  Codex and Claude use the /mcp Streamable HTTP endpoint; Agy uses /sse; Codex via Ollama also uses /mcp\n');
    process.stdout.write('  Nosh defaults Codex to full access; set NOTTY_COLLAB_UNSANDBOXED=false to force workspace-write\n');
    process.stdout.write('  Agy and Claude stay sandboxed by the Nosh default; explicit NOTTY_COLLAB_UNSANDBOXED=true unsandboxes all agents\n');
    process.stdout.write('  daemon hosts MCP plus the /admin/v1 HTTP orchestration API; --server selects a loopback daemon URL\n');
    process.stdout.write('  add-agent registers a tmux session for idle-time claim_pending nudges\n');
}
