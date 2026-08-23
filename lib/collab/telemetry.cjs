'use strict';

const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const MESSAGE_SCHEMA_VERSION = 2;
const FEEDBACK_SCHEMA_VERSION = 1;
const VALID_RATINGS = new Set(['helpful', 'unhelpful']);

function cleanText(value, fallback = '') {
  const text = String(value ?? '').trim();
  return text || fallback;
}

function normalizeLegacyRuntime(value) {
  const runtime = cleanText(value, 'codex').toLowerCase();
  if (runtime === 'ollama') {
    return { harness: 'codex', backend: 'ollama' };
  }
  if (runtime === 'agy') {
    return { harness: 'agy', backend: 'default' };
  }
  if (runtime === 'claude') {
    return { harness: 'claude', backend: 'default' };
  }
  return { harness: 'codex', backend: 'default' };
}

function canonicalAgentSnapshot(agent = {}) {
  const legacy = normalizeLegacyRuntime(agent.runtime);
  return {
    role: cleanText(agent.role || agent.prompt || agent.identity || agent.id, 'agent'),
    harness: cleanText(agent.harness, legacy.harness).toLowerCase(),
    backend: cleanText(agent.backend, legacy.backend).toLowerCase(),
    model: cleanText(agent.model),
    think: cleanText(agent.think).toLowerCase(),
  };
}

function matchSessionAgent(session, agentId) {
  const cleanAgentId = cleanText(agentId);
  if (!session || !cleanAgentId || !Array.isArray(session.agents)) {
    return null;
  }
  return session.agents.find((agent) => cleanText(agent?.identity) === cleanAgentId)
    || session.agents.find((agent) => cleanText(agent?.id) === cleanAgentId)
    || null;
}

function stampChannelRecord(record, options = {}) {
  const source = record && typeof record === 'object' ? record : {};
  const explicitAuthorType = cleanText(options.authorType).toLowerCase();
  const session = options.session || null;
  const matchedAgent = explicitAuthorType === 'human'
    || explicitAuthorType === 'system'
    || explicitAuthorType === 'mirror'
      ? null
      : matchSessionAgent(session, source.agent_id);
  const authorType = explicitAuthorType || (matchedAgent ? 'agent' : 'unknown');

  return {
    ...source,
    schema_version: MESSAGE_SCHEMA_VERSION,
    session_id: matchedAgent ? cleanText(session?.id) || null : null,
    session_agent_id: matchedAgent
      ? cleanText(matchedAgent.id || matchedAgent.identity) || null
      : null,
    author_type: authorType,
    author_snapshot: matchedAgent ? canonicalAgentSnapshot(matchedAgent) : null,
  };
}

function isAttributedAgentMessage(message) {
  return Boolean(
    message
    && message.schema_version >= MESSAGE_SCHEMA_VERSION
    && message.kind === 'message'
    && message.author_type === 'agent'
    && cleanText(message.id)
    && cleanText(message.session_id)
    && cleanText(message.session_agent_id)
    && message.author_snapshot
    && typeof message.author_snapshot === 'object',
  );
}

function normalizeRating(value) {
  if (value === null || value === undefined || value === '' || value === 'clear') {
    return null;
  }
  const rating = cleanText(value).toLowerCase();
  if (!VALID_RATINGS.has(rating)) {
    const error = new Error('rating must be helpful, unhelpful, or null');
    error.statusCode = 400;
    throw error;
  }
  return rating;
}

function validateOperator(value) {
  const operator = cleanText(value, 'operator');
  if (operator.length > 128 || /[\r\n\0]/.test(operator)) {
    const error = new Error('operator identity is invalid');
    error.statusCode = 400;
    throw error;
  }
  return operator;
}

function emptyFeedback(viewerRating = null) {
  return {
    helpful: 0,
    unhelpful: 0,
    rated: 0,
    helpfulRatio: null,
    helpfulPercentage: null,
    viewerRating,
    operatorVote: viewerRating,
  };
}

function summarizeFeedback(messageId, operator, ratings) {
  const summary = emptyFeedback();
  for (const [key, rating] of ratings) {
    const separator = key.indexOf('\0');
    if (separator === -1 || key.slice(separator + 1) !== messageId) {
      continue;
    }
    if (rating === 'helpful') {
      summary.helpful += 1;
    } else if (rating === 'unhelpful') {
      summary.unhelpful += 1;
    }
    if (key.slice(0, separator) === operator) {
      summary.viewerRating = rating;
      summary.operatorVote = rating;
    }
  }
  summary.rated = summary.helpful + summary.unhelpful;
  summary.helpfulRatio = summary.rated > 0 ? summary.helpful / summary.rated : null;
  summary.helpfulPercentage = summary.helpfulRatio === null
    ? null
    : summary.helpfulRatio * 100;
  return summary;
}

function readFeedbackState(feedbackPath) {
  const ratings = new Map();
  if (!fs.existsSync(feedbackPath)) {
    return ratings;
  }
  const lines = fs.readFileSync(feedbackPath, 'utf8').split('\n');
  for (const line of lines) {
    if (!line) continue;
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }
    const operator = cleanText(entry?.operator);
    const messageId = cleanText(entry?.message_id);
    if (!operator || !messageId) continue;
    const key = `${operator}\0${messageId}`;
    if (entry.tombstone === true || entry.rating === null || entry.vote === null) {
      ratings.delete(key);
      continue;
    }
    const rating = cleanText(entry.rating || entry.vote).toLowerCase();
    if (VALID_RATINGS.has(rating)) {
      ratings.set(key, rating);
    }
  }
  return ratings;
}

function appendJsonLine(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify(value)}\n`, 'utf8');
}

function addFeedbackCounts(target, summary) {
  target.helpful += summary.helpful;
  target.unhelpful += summary.unhelpful;
  target.rated += summary.rated;
}

function finishCounts(target) {
  target.helpfulRatio = target.rated > 0 ? target.helpful / target.rated : null;
  target.helpfulPercentage = target.helpfulRatio === null
    ? null
    : target.helpfulRatio * 100;
  return target;
}

function statsRowFor(message, includeSessionAgent) {
  const snapshot = canonicalAgentSnapshot(message.author_snapshot);
  const keyParts = [
    ...(includeSessionAgent ? [cleanText(message.session_agent_id)] : []),
    snapshot.role,
    snapshot.harness,
    snapshot.backend,
    snapshot.model,
    snapshot.think,
  ];
  return {
    key: JSON.stringify(keyParts),
    role: snapshot.role,
    harness: snapshot.harness,
    agent: snapshot.harness,
    backend: snapshot.backend,
    runtime: snapshot.backend === 'ollama' ? 'ollama' : snapshot.harness,
    model: snapshot.model,
    think: snapshot.think,
    sessionAgentId: cleanText(message.session_agent_id) || null,
    session_agent_id: cleanText(message.session_agent_id) || null,
    agentId: cleanText(message.session_agent_id) || null,
    sessionAgentIds: new Set(cleanText(message.session_agent_id)
      ? [cleanText(message.session_agent_id)]
      : []),
    messages: 0,
    helpful: 0,
    unhelpful: 0,
    rated: 0,
    helpfulRatio: null,
    helpfulPercentage: null,
  };
}

function createTelemetryStore(options = {}) {
  const feedbackPath = path.resolve(options.feedbackPath || 'message_feedback.jsonl');
  const getSession = typeof options.getSession === 'function' ? options.getSession : () => null;
  const findMessage = typeof options.findMessage === 'function' ? options.findMessage : () => null;
  const forEachMessage = typeof options.forEachMessage === 'function'
    ? options.forEachMessage
    : () => {};
  const eventHub = options.eventHub || null;

  function stamp(record, stampOptions = {}) {
    return stampChannelRecord(record, {
      ...stampOptions,
      session: stampOptions.session === undefined ? getSession() : stampOptions.session,
    });
  }

  function enrich(messages, operatorValue) {
    const operator = validateOperator(operatorValue);
    const ratings = readFeedbackState(feedbackPath);
    return (Array.isArray(messages) ? messages : []).map((message) => ({
      ...message,
      feedback: summarizeFeedback(cleanText(message?.id), operator, ratings),
    }));
  }

  function rate({ channel, messageId, operator: operatorValue, rating: ratingValue }) {
    const operator = validateOperator(operatorValue);
    const message = findMessage(cleanText(channel), cleanText(messageId));
    if (!message) {
      const error = new Error('message not found');
      error.statusCode = 404;
      throw error;
    }
    if (!isAttributedAgentMessage(message)) {
      const error = new Error('feedback is available only for attributed agent messages');
      error.statusCode = 422;
      throw error;
    }

    const rating = normalizeRating(ratingValue);
    const ratings = readFeedbackState(feedbackPath);
    const key = `${operator}\0${message.id}`;
    const previousRating = ratings.get(key) || null;
    if (previousRating === rating) {
      return {
        changed: false,
        messageId: message.id,
        channel: message.channel,
        rating,
        feedback: summarizeFeedback(message.id, operator, ratings),
      };
    }

    const record = {
      schema_version: FEEDBACK_SCHEMA_VERSION,
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      message_id: message.id,
      channel: message.channel,
      operator,
      rating,
      ...(rating === null ? { tombstone: true } : {}),
    };
    appendJsonLine(feedbackPath, record);
    if (rating === null) {
      ratings.delete(key);
    } else {
      ratings.set(key, rating);
    }
    const result = {
      changed: true,
      messageId: message.id,
      channel: message.channel,
      rating,
      feedback: summarizeFeedback(message.id, operator, ratings),
    };
    eventHub?.emit?.('message.feedback', result);
    return result;
  }

  function stats(scopeValue = 'session') {
    const scope = cleanText(scopeValue, 'session').toLowerCase();
    if (scope !== 'session' && scope !== 'lifetime') {
      const error = new Error('scope must be session or lifetime');
      error.statusCode = 400;
      throw error;
    }
    const sessionId = scope === 'session' ? cleanText(getSession()?.id) : '';
    const ratings = readFeedbackState(feedbackPath);
    const rows = new Map();
    const totals = {
      messages: 0,
      helpful: 0,
      unhelpful: 0,
      rated: 0,
      helpfulRatio: null,
      helpfulPercentage: null,
    };
    const seen = new Set();

    forEachMessage((message) => {
      if (!isAttributedAgentMessage(message) || seen.has(message.id)) return;
      seen.add(message.id);
      if (scope === 'session' && (!sessionId || message.session_id !== sessionId)) return;
      const prototype = statsRowFor(message, scope === 'session');
      let row = rows.get(prototype.key);
      if (!row) {
        row = prototype;
        rows.set(row.key, row);
      } else if (prototype.sessionAgentId) {
        row.sessionAgentIds.add(prototype.sessionAgentId);
        if (row.sessionAgentId !== prototype.sessionAgentId) {
          row.sessionAgentId = null;
        }
      }
      const feedback = summarizeFeedback(message.id, '', ratings);
      row.messages += 1;
      totals.messages += 1;
      addFeedbackCounts(row, feedback);
      addFeedbackCounts(totals, feedback);
    });

    const outputRows = Array.from(rows.values()).map((row) => finishCounts({
      ...row,
      sessionAgentIds: Array.from(row.sessionAgentIds).sort(),
    })).sort((left, right) => (
      left.role.localeCompare(right.role)
      || left.harness.localeCompare(right.harness)
      || left.model.localeCompare(right.model)
      || left.think.localeCompare(right.think)
    ));

    return {
      scope,
      sessionId: sessionId || null,
      rows: outputRows,
      totals: finishCounts(totals),
    };
  }

  function clear() {
    if (!fs.existsSync(feedbackPath)) return 0;
    fs.unlinkSync(feedbackPath);
    return 1;
  }

  return {
    feedbackPath,
    stamp,
    enrich,
    rate,
    stats,
    clear,
    readFeedbackState: () => readFeedbackState(feedbackPath),
  };
}

module.exports = {
  FEEDBACK_SCHEMA_VERSION,
  MESSAGE_SCHEMA_VERSION,
  canonicalAgentSnapshot,
  createTelemetryStore,
  isAttributedAgentMessage,
  normalizeRating,
  stampChannelRecord,
};
