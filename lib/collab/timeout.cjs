function timeoutPolicy(choice = {}) {
  const timeoutSeconds = choice.timeoutSeconds === undefined ? 3600 : choice.timeoutSeconds;
  const terminateOnExpire = choice.terminateOnExpire === undefined ? true : choice.terminateOnExpire;
  if (!Number.isSafeInteger(timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > 604800
    || typeof terminateOnExpire !== 'boolean') {
    throw Object.assign(new Error('Timeout must be 1–604800 seconds and terminateOnExpire must be boolean'), { statusCode: 422 });
  }
  return { timeoutSeconds, terminateOnExpire };
}

function enforceAgentDeadline(agent, session, controls, now = Date.now()) {
  if (session.recovered || !Number.isFinite(agent.expiresAt) || now < agent.expiresAt
    || !agent.terminateOnExpire) return agent;
  if (agent.status === 'stopped' && agent.error === 'Terminated on expiry.') return agent;
  const present = controls.present(agent.tmuxTarget);
  if (present && !controls.owned(agent.tmuxTarget, session.id)) return agent;
  if (present) controls.stop(agent.tmuxTarget);
  if (controls.present(agent.tmuxTarget)) {
    return { ...agent, status: 'stop-failed', error: 'Timeout reached; terminal termination has not completed.' };
  }
  controls.clear(agent.identity);
  return { ...agent, status: 'stopped', error: 'Terminated on expiry.', tmuxAlive: false,
    tmuxPresent: false, tmuxOwned: false };
}

module.exports = { timeoutPolicy, enforceAgentDeadline };
