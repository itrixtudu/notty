export function createInitialLayout(sessionId = null, metadata = {}) {
  return {
    ...metadata,
    type: 'leaf',
    id: 'pane-1',
    sessionId
  };
}

export function updatePane(layout, paneId, updater) {
  if (layout.type === 'leaf') {
    return layout.id === paneId ? updater(layout) : layout;
  }

  return {
    ...layout,
    children: layout.children.map((child) => updatePane(child, paneId, updater))
  };
}

export function hasPane(layout, paneId) {
  if (layout.type === 'leaf') {
    return layout.id === paneId;
  }
  return layout.children.some((child) => hasPane(child, paneId));
}

export function getPane(layout, paneId) {
  if (layout.type === 'leaf') {
    return layout.id === paneId ? layout : null;
  }

  for (const child of layout.children) {
    const found = getPane(child, paneId);
    if (found) {
      return found;
    }
  }
  return null;
}

export function getFirstPane(layout) {
  if (!layout) {
    return null;
  }
  if (layout.type === 'leaf') {
    return layout;
  }
  return layout.children?.length ? getFirstPane(layout.children[0]) : null;
}

export function pruneSessionFromLayout(layout, sessionId) {
  if (layout.type === 'leaf') {
    return layout.sessionId === sessionId ? { ...layout, sessionId: null } : layout;
  }

  return {
    ...layout,
    children: layout.children.map((child) => pruneSessionFromLayout(child, sessionId))
  };
}

export function splitPane(layout, paneId, newPaneId, direction, newSessionId = null) {
  return updatePane(layout, paneId, (pane) => ({
    type: 'split',
    id: `split-${newPaneId}`,
    direction,
    ratios: [1, 1],
    children: [
      pane,
      { type: 'leaf', id: newPaneId, sessionId: newSessionId }
    ]
  }));
}

export function updateSplitRatios(layout, splitId, ratios) {
  if (!layout || layout.type === 'leaf') {
    return layout;
  }

  if (layout.id === splitId) {
    const validRatios = Array.isArray(ratios)
      && ratios.length === layout.children.length
      && ratios.every((ratio) => Number.isFinite(ratio) && ratio > 0);
    return validRatios ? { ...layout, ratios } : layout;
  }

  let changed = false;
  const children = layout.children.map((child) => {
    const nextChild = updateSplitRatios(child, splitId, ratios);
    changed ||= nextChild !== child;
    return nextChild;
  });

  return changed ? { ...layout, children } : layout;
}

export function getPaneStyle(layout, index) {
  const ratio = layout.ratios?.[index];
  return Number.isFinite(ratio) && ratio > 0
    ? { flex: `${ratio} 1 0` }
    : undefined;
}
