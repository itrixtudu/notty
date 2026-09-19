export function buildChatLayout(ids, columns = 2, mode = 'grid', ratios = {}) {
  const leaf = (id) => ({ type: 'leaf', id });
  const split = (id, direction, children) => children.length === 1 ? children[0] : ({
    type: 'split', id, direction, children, ratios: ratios[id]
  });
  const grid = (items, count) => {
    const rows = [];
    for (let i = 0; i < items.length; i += count) {
      const group = items.slice(i, i + count);
      rows.push(split(`row:${group.join('|')}`, 'vertical', group.map(leaf)));
    }
    return split(`rows:${items.join('|')}:${count}`, 'horizontal', rows);
  };
  if (!ids.length) return null;
  if (!columns && ['lead-grid', 'pair'].includes(mode) && ids.length > 1) {
    return split(`monitor:${ids.join('|')}`, 'vertical', [leaf(ids[0]), grid(ids.slice(1), 2)]);
  }
  return grid(ids, Math.max(1, Math.min(4, columns || (ids.length <= 4 ? 2 : 3))));
}
