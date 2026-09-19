'use strict';

const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { thinkLevelsFor } = require('./launch.cjs');
const { queryOllamaTags } = require('./ollama.cjs');
const { sanitizeChildEnvironment } = require('../childEnvironment.cjs');

const READY_TTL_MS = 30_000;
const ERROR_TTL_MS = 5_000;

function parseCodexModels(text) {
  return String(text || '')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .map((line) => {
      const match = line.match(/^(\S+)(?:\s+(.*))?$/);
      return match ? { id: match[1], description: String(match[2] || '').trim() } : null;
    })
    .filter(Boolean);
}

function parseLineModels(text, headerPattern = null) {
  return String(text || '')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !(headerPattern && headerPattern.test(line)))
    .map((line) => ({ id: line.split(/\s+/, 1)[0], description: '' }))
    .filter((entry) => entry.id);
}

function parseAgyModels(text) {
  return String(text || '')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !/^available models:?$/i.test(line))
    .map((id) => ({ id, description: '' }));
}

function parseOllamaModels(models) {
  return (Array.isArray(models) ? models : [])
    .map((entry) => {
      const id = String(entry?.name || entry?.model || '').trim();
      const details = entry?.details && typeof entry.details === 'object' ? entry.details : {};
      const description = [details.parameter_size, details.quantization_level]
        .map((value) => String(value || '').trim())
        .filter(Boolean)
        .join(' · ');
      return id ? { id, description } : null;
    })
    .filter(Boolean);
}

function catalogKey(harness, backend = 'default') {
  return `${harness}:${backend}`;
}

function createLaunchCatalog(options = {}) {
  const appRoot = path.resolve(options.appRoot || path.join(__dirname, '..', '..'));
  const environment = sanitizeChildEnvironment(options.environment || process.env);
  const spawnSync = options.spawnSync || childProcess.spawnSync;
  const now = options.now || Date.now;
  const cache = new Map();

  function record(target, values = {}) {
    const models = Array.isArray(values.models) ? values.models : [];
    const status = values.status || (models.length ? 'ready' : 'empty');
    return {
      harness: target.harness,
      backend: target.backend,
      status,
      available: status !== 'error',
      error: String(values.error || ''),
      refreshedAt: new Date(now()).toISOString(),
      models,
      thinkMode: 'explicit',
      thinkLevels: [...thinkLevelsFor(target)],
    };
  }

  function commandModels(target, command, args, parse) {
    const result = spawnSync(command, args, {
      encoding: 'utf8',
      timeout: 5000,
      maxBuffer: 256 * 1024,
      env: environment,
    });
    if (result.error || result.status !== 0) {
      return record(target, {
        status: 'error',
        error: result.error?.message
          || String(result.stderr || result.stdout || `${command} exited ${result.status}`).trim(),
      });
    }
    return record(target, { models: parse(result.stdout) });
  }

  function loadTarget(target) {
    if (target.harness === 'codex' && target.backend === 'default') {
      const catalogPath = path.join(appRoot, 'agents', 'bin', 'codex.models');
      if (!fs.existsSync(catalogPath)) {
        return record(target, { status: 'error', error: `model catalog not found: ${catalogPath}` });
      }
      return record(target, { models: parseCodexModels(fs.readFileSync(catalogPath, 'utf8')) });
    }
    if (target.harness === 'agy') {
      return commandModels(
        target,
        String(environment.AGY_BIN || 'agy'),
        ['models'],
        parseAgyModels,
      );
    }
    if (target.harness === 'claude') {
      const result = spawnSync(String(environment.CLAUDE_BIN || 'claude'), ['--version'], {
        encoding: 'utf8',
        timeout: 5000,
        maxBuffer: 64 * 1024,
        env: environment,
      });
      if (result.error || result.status !== 0) {
        return record(target, {
          status: 'error',
          error: result.error?.message
            || String(result.stderr || result.stdout || 'claude is unavailable').trim(),
        });
      }
      return record(target, {
        models: [
          { id: 'sonnet', description: 'Latest hosted Sonnet alias.' },
          { id: 'opus', description: 'Latest hosted Opus alias.' },
        ],
      });
    }
    try {
      const result = queryOllamaTags({
        endpoint: options.ollamaEndpoint,
        environment,
        spawnSync,
        curlBin: options.curlBin,
        timeoutMs: options.ollamaTimeoutMs,
      });
      return record(target, { models: parseOllamaModels(result.models) });
    } catch (error) {
      return record(target, { status: 'error', error: error.message || String(error) });
    }
  }

  function getTarget(harness, backend = 'default', optionsForRead = {}) {
    const key = catalogKey(harness, backend);
    const cached = cache.get(key);
    if (!optionsForRead.refresh && cached && cached.expiresAt > now()) return cached.value;
    const value = loadTarget({ harness, backend });
    cache.set(key, {
      value,
      expiresAt: now() + (value.status === 'error' ? ERROR_TTL_MS : READY_TTL_MS),
    });
    return value;
  }

  function read(optionsForRead = {}) {
    const targets = [
      ['codex', 'default'],
      ['codex', 'ollama'],
      ['agy', 'default'],
      ['claude', 'default'],
    ];
    return targets.map(([harness, backend]) => getTarget(
      harness,
      backend,
      optionsForRead,
    ));
  }

  function legacy(optionsForRead = {}) {
    const entries = read(optionsForRead);
    const byKey = new Map(entries.map((entry) => [catalogKey(entry.harness, entry.backend), entry.models]));
    return {
      codex: byKey.get('codex:default') || [],
      agy: byKey.get('agy:default') || [],
      ollama: byKey.get('codex:ollama') || [],
      claude: byKey.get('claude:default') || [],
    };
  }

  function invalidate() {
    cache.clear();
  }

  return { getTarget, invalidate, legacy, read };
}

module.exports = {
  ERROR_TTL_MS,
  READY_TTL_MS,
  catalogKey,
  createLaunchCatalog,
  parseAgyModels,
  parseCodexModels,
  parseLineModels,
  parseOllamaModels,
};
