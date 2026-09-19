'use strict';

// Only the rendered buffer is available here, never hidden CLI conversation state.
function terminalSnapshot(buffer, maxLines = 10000, maxBytes = 1024 * 1024) {
  const encoder = new TextEncoder();
  const lines = [];
  let bytes = 0;
  let truncated = buffer.length > maxLines;
  for (let index = buffer.length - 1; index >= Math.max(0, buffer.length - maxLines); index -= 1) {
    const text = buffer.getLine(index)?.translateToString(true) || '';
    const size = encoder.encode(text).length + 1;
    if (bytes + size > maxBytes) { truncated = true; break; }
    lines.push(text);
    bytes += size;
  }
  return { text: lines.reverse().join('\n'), truncated };
}

function terminalSnapshotStyle(options, screenHeight, rows) {
  // xterm's measured cell height includes font metrics, not just fontSize.
  const measuredLineHeight = Number.isFinite(screenHeight) && screenHeight > 0
    && Number.isInteger(rows) && rows > 0 ? screenHeight / rows : null;
  return {
    fontFamily: options.fontFamily,
    fontSize: `${options.fontSize}px`,
    fontWeight: options.fontWeight || 'normal',
    fontStyle: 'normal',
    lineHeight: measuredLineHeight ? `${measuredLineHeight}px` : options.lineHeight || 1,
    letterSpacing: `${options.letterSpacing || 0}px`,
    fontVariantLigatures: 'none',
  };
}

module.exports = { terminalSnapshot, terminalSnapshotStyle };
