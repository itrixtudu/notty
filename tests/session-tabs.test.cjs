const assert = require('node:assert/strict');
const test = require('node:test');

test('session tabs derive the active tab from the focused pane session', async () => {
  const { getActiveSessionTabIndex } = await import('../components/sessionTabsModel.js');
  const sessions = [{ id: 12 }, { id: 24 }, { id: 36 }];

  assert.equal(getActiveSessionTabIndex(sessions, 24), 1);
  assert.equal(getActiveSessionTabIndex(sessions, 99), -1);
  assert.equal(getActiveSessionTabIndex([], 24), -1);
  assert.equal(getActiveSessionTabIndex(sessions, null), -1);
});

test('session tab navigation wraps in both directions', async () => {
  const { getNextSessionTabIndex } = await import('../components/sessionTabsModel.js');

  assert.equal(getNextSessionTabIndex(2, 3, 'ArrowRight'), 0);
  assert.equal(getNextSessionTabIndex(0, 3, 'ArrowLeft'), 2);
  assert.equal(getNextSessionTabIndex(1, 3, 'ArrowRight'), 2);
  assert.equal(getNextSessionTabIndex(1, 3, 'ArrowLeft'), 0);
});

test('session tab navigation supports boundary keys and empty lists', async () => {
  const { getNextSessionTabIndex } = await import('../components/sessionTabsModel.js');

  assert.equal(getNextSessionTabIndex(2, 4, 'Home'), 0);
  assert.equal(getNextSessionTabIndex(0, 4, 'End'), 3);
  assert.equal(getNextSessionTabIndex(-1, 4, 'ArrowRight'), 1);
  assert.equal(getNextSessionTabIndex(0, 0, 'ArrowRight'), -1);
});
