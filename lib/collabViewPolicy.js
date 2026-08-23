export function isAgentViewEligible(session, agent) {
  if (!agent || agent.tmuxAlive !== true) {
    return false;
  }
  return session?.recovered === true ? true : agent.tmuxOwned === true;
}
