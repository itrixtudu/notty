import { getActiveSessions, cleanupSession } from '../../../lib/mcpHttpServer.js';

export default function handler(req, res) {
  if (req.method === 'GET') {
    const sessions = getActiveSessions(req);
    res.status(200).json({ sessions, count: sessions.length });
  } else if (req.method === 'DELETE') {
    // Clean up a specific session
    const { sessionId } = req.query;
    if (!sessionId) {
      res.status(400).json({ error: 'sessionId is required' });
      return;
    }

    const success = cleanupSession(sessionId, req);
    if (success) {
      res.status(200).json({ message: 'Session cleaned up', sessionId });
    } else {
      res.status(404).json({ error: 'Session not found', sessionId });
    }
  } else {
    res.setHeader('Allow', ['GET', 'DELETE']);
    res.status(405).end();
  }
}
