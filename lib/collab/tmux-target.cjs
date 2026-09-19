'use strict';

function resolveCollabTmuxTarget(requested, session, managed = {}) {
  const target = String(requested || '').trim();
  if (!target) throw new Error('tmux target is required');
  if (session) {
    const matches = (session.agents || []).filter((agent) => (
      [agent.id, agent.identity, agent.tmuxTarget].includes(target)
    ));
    if (matches.length === 1 && matches[0].tmuxTarget) return matches[0].tmuxTarget;
    if (matches.length > 1) throw new Error('Ambiguous collaboration agent target');
    if (target.replace(/^#/, '') === session.channel) {
      throw new Error('Channels are not tmux panes. Use read_messages to read the channel, claim_pending to claim work, and send_message to reply.');
    }
    throw new Error('Unknown collaboration agent target; use an exact agent identity from list_agents');
  }
  return Object.hasOwn(managed, target) ? managed[target].target || target : target;
}

module.exports = { resolveCollabTmuxTarget };
