'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

test('splits assign a distinct terminal session to the new pane', async (t) => {
  const { createInitialLayout, splitPane } = await import('../lib/terminalLayout.js');

  for (const direction of ['horizontal', 'vertical']) {
    await t.test(direction, () => {
      const layout = splitPane(
        createInitialLayout(101),
        'pane-1',
        'pane-2',
        direction,
        202
      );

      assert.equal(layout.type, 'split');
      assert.equal(layout.direction, direction);
      assert.equal(layout.children[0].sessionId, 101);
      assert.equal(layout.children[1].sessionId, 202);
      assert.notEqual(layout.children[0].sessionId, layout.children[1].sessionId);
    });
  }
});

test('a split without a created session never mirrors the source pane', async () => {
  const { createInitialLayout, splitPane } = await import('../lib/terminalLayout.js');
  const layout = splitPane(
    createInitialLayout(101),
    'pane-1',
    'pane-2',
    'vertical'
  );

  assert.equal(layout.children[0].sessionId, 101);
  assert.equal(layout.children[1].sessionId, null);
});

test('nested splits preserve unrelated terminal sessions', async () => {
  const { createInitialLayout, splitPane } = await import('../lib/terminalLayout.js');
  const firstSplit = splitPane(
    createInitialLayout(101),
    'pane-1',
    'pane-2',
    'vertical',
    202
  );
  const nestedSplit = splitPane(
    firstSplit,
    'pane-2',
    'pane-3',
    'horizontal',
    303
  );

  assert.equal(nestedSplit.children[0].sessionId, 101);
  assert.equal(nestedSplit.children[1].children[0].sessionId, 202);
  assert.equal(nestedSplit.children[1].children[1].sessionId, 303);
});

test('initial layout metadata cannot override reserved pane fields', async () => {
  const { createInitialLayout } = await import('../lib/terminalLayout.js');
  const layout = createInitialLayout(101, {
    type: 'split',
    id: 'override',
    sessionId: 999,
    label: 'Primary'
  });

  assert.deepEqual(layout, {
    type: 'leaf',
    id: 'pane-1',
    sessionId: 101,
    label: 'Primary'
  });
});

test('first pane lookup tolerates an empty or missing layout', async () => {
  const { getFirstPane } = await import('../lib/terminalLayout.js');

  assert.equal(getFirstPane(null), null);
  assert.equal(getFirstPane({ type: 'split', children: [] }), null);
});

test('pane ratios produce flex styles and invalid ratios fall back', async () => {
  const { getPaneStyle } = await import('../lib/terminalLayout.js');
  const layout = { ratios: [2, 0, Number.NaN] };

  assert.deepEqual(getPaneStyle(layout, 0), { flex: '2 1 0' });
  assert.equal(getPaneStyle(layout, 1), undefined);
  assert.equal(getPaneStyle(layout, 2), undefined);
  assert.equal(getPaneStyle({}, 0), undefined);
});

test('split ratios can resize a nested split without changing its parent', async () => {
  const {
    createInitialLayout,
    splitPane,
    updateSplitRatios
  } = await import('../lib/terminalLayout.js');
  const firstSplit = splitPane(
    createInitialLayout(101),
    'pane-1',
    'pane-2',
    'vertical',
    202
  );
  const layout = splitPane(
    firstSplit,
    'pane-2',
    'pane-3',
    'horizontal',
    303
  );
  const nestedSplitId = layout.children[1].id;
  const resized = updateSplitRatios(layout, nestedSplitId, [0.5, 1.5]);

  assert.deepEqual(resized.ratios, [1, 1]);
  assert.deepEqual(resized.children[1].ratios, [0.5, 1.5]);
  assert.equal(resized.children[0], layout.children[0]);
});

test('split ratio updates reject missing, non-positive, and mismatched values', async () => {
  const {
    createInitialLayout,
    splitPane,
    updateSplitRatios
  } = await import('../lib/terminalLayout.js');
  const layout = splitPane(
    createInitialLayout(101),
    'pane-1',
    'pane-2',
    'vertical',
    202
  );

  assert.equal(updateSplitRatios(layout, 'missing-split', [0.5, 1.5]), layout);
  assert.equal(updateSplitRatios(layout, layout.id, [0, 2]), layout);
  assert.equal(updateSplitRatios(layout, layout.id, [1]), layout);
});

test('splitting an unknown pane is a no-op', async () => {
  const { createInitialLayout, splitPane } = await import('../lib/terminalLayout.js');
  const layout = createInitialLayout(101);

  assert.equal(splitPane(layout, 'missing-pane', 'pane-2', 'vertical', 202), layout);
});
