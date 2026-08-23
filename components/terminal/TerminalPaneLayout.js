import { Fragment, useEffect, useRef, useState } from 'react';
import TerminalConsole from '../TerminalConsole.js';
import { getPaneStyle } from '../../lib/terminalLayout.js';

const MIN_COLUMN_SIZE = 160;
const MIN_ROW_SIZE = 120;
const KEYBOARD_RESIZE_STEP = 24;

function getRenderedDirection(splitElement, fallbackDirection) {
  if (typeof window === 'undefined' || !splitElement) {
    return fallbackDirection;
  }
  return window.getComputedStyle(splitElement).flexDirection === 'column'
    ? 'horizontal'
    : 'vertical';
}

function getAdjacentGeometry(divider, fallbackDirection) {
  const firstPane = divider?.previousElementSibling;
  const secondPane = divider?.nextElementSibling;
  const splitElement = divider?.parentElement;
  if (!firstPane || !secondPane || !splitElement) {
    return null;
  }

  const direction = getRenderedDirection(splitElement, fallbackDirection);
  const firstRect = firstPane.getBoundingClientRect();
  const secondRect = secondPane.getBoundingClientRect();
  const dividerRect = divider.getBoundingClientRect();
  const vertical = direction === 'vertical';
  const start = vertical ? firstRect.left : firstRect.top;
  const dividerSize = vertical ? dividerRect.width : dividerRect.height;
  const usableSize = (vertical ? secondRect.right : secondRect.bottom) - start - dividerSize;

  return {
    direction,
    start,
    dividerSize,
    usableSize,
    firstSize: vertical ? firstRect.width : firstRect.height
  };
}

function resizeAdjacentPanes({
  geometry,
  firstSize,
  index,
  ratios,
  onResize
}) {
  if (!geometry || geometry.usableSize <= 0) {
    return;
  }

  const minimum = Math.min(
    geometry.direction === 'vertical' ? MIN_COLUMN_SIZE : MIN_ROW_SIZE,
    geometry.usableSize / 2
  );
  const nextFirstSize = Math.min(
    Math.max(firstSize, minimum),
    geometry.usableSize - minimum
  );
  const pairRatio = ratios[index] + ratios[index + 1];
  const nextRatios = [...ratios];
  nextRatios[index] = pairRatio * (nextFirstSize / geometry.usableSize);
  nextRatios[index + 1] = pairRatio - nextRatios[index];
  onResize(nextRatios);
}

function TerminalSplitResizer({
  direction,
  index,
  ratios,
  splitId,
  onResizeSplit
}) {
  const [resizing, setResizing] = useState(false);
  const cleanupRef = useRef(null);
  const pairRatio = ratios[index] + ratios[index + 1];
  const percentage = Math.round((ratios[index] / pairRatio) * 100);

  useEffect(() => () => cleanupRef.current?.(), []);

  const handlePointerDown = (event) => {
    if (event.button !== 0 || !onResizeSplit || typeof window === 'undefined') {
      return;
    }

    const divider = event.currentTarget;
    const geometry = getAdjacentGeometry(divider, direction);
    if (!geometry) {
      return;
    }

    event.preventDefault();
    cleanupRef.current?.();
    divider.setPointerCapture?.(event.pointerId);
    setResizing(true);

    const previousBodyCursor = document.body.style.cursor;
    const previousBodyUserSelect = document.body.style.userSelect;
    document.body.style.cursor = geometry.direction === 'vertical' ? 'col-resize' : 'row-resize';
    document.body.style.userSelect = 'none';

    const updateFromPointer = (moveEvent) => {
      moveEvent.preventDefault();
      const pointerPosition = geometry.direction === 'vertical'
        ? moveEvent.clientX
        : moveEvent.clientY;
      resizeAdjacentPanes({
        geometry,
        firstSize: pointerPosition - geometry.start - (geometry.dividerSize / 2),
        index,
        ratios,
        onResize: (nextRatios) => onResizeSplit(splitId, nextRatios)
      });
    };
    const stopResize = () => {
      setResizing(false);
      document.body.style.cursor = previousBodyCursor;
      document.body.style.userSelect = previousBodyUserSelect;
      window.removeEventListener('pointermove', updateFromPointer);
      window.removeEventListener('pointerup', stopResize);
      window.removeEventListener('pointercancel', stopResize);
      cleanupRef.current = null;
    };

    cleanupRef.current = stopResize;
    window.addEventListener('pointermove', updateFromPointer);
    window.addEventListener('pointerup', stopResize);
    window.addEventListener('pointercancel', stopResize);
  };

  const handleKeyDown = (event) => {
    if (!onResizeSplit) {
      return;
    }

    const geometry = getAdjacentGeometry(event.currentTarget, direction);
    if (!geometry) {
      return;
    }

    const step = event.shiftKey ? 80 : KEYBOARD_RESIZE_STEP;
    let nextFirstSize = geometry.firstSize;
    if (
      (geometry.direction === 'vertical' && event.key === 'ArrowLeft')
      || (geometry.direction === 'horizontal' && event.key === 'ArrowUp')
    ) {
      nextFirstSize -= step;
    } else if (
      (geometry.direction === 'vertical' && event.key === 'ArrowRight')
      || (geometry.direction === 'horizontal' && event.key === 'ArrowDown')
    ) {
      nextFirstSize += step;
    } else if (event.key === 'Home') {
      nextFirstSize = 0;
    } else if (event.key === 'End') {
      nextFirstSize = geometry.usableSize;
    } else {
      return;
    }

    event.preventDefault();
    resizeAdjacentPanes({
      geometry,
      firstSize: nextFirstSize,
      index,
      ratios,
      onResize: (nextRatios) => onResizeSplit(splitId, nextRatios)
    });
  };

  return (
    <button
      type="button"
      className={`terminal-split-resizer terminal-split-resizer-${direction}${resizing ? ' terminal-split-resizer-active' : ''}`}
      aria-label={`Resize ${direction === 'vertical' ? 'terminal columns' : 'terminal rows'}`}
      aria-orientation={direction === 'vertical' ? 'vertical' : 'horizontal'}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={percentage}
      onPointerDown={handlePointerDown}
      onKeyDown={handleKeyDown}
      role="separator"
    />
  );
}

export default function TerminalPaneLayout({
  layout,
  activePaneId,
  onActivatePane,
  onNewTerminal,
  onResizeSplit,
  renderPane
}) {
  if (layout.type === 'leaf') {
    const isActive = layout.id === activePaneId;
    const content = renderPane
      ? renderPane(layout, isActive)
      : <TerminalConsole sessionId={layout.sessionId} onNewTerminal={onNewTerminal} />;

    return (
      <div
        className={`terminal-pane${isActive ? ' terminal-pane-active' : ''}`}
        onPointerDown={() => onActivatePane?.(layout.id)}
        onFocusCapture={() => onActivatePane?.(layout.id)}
        data-pane-id={layout.id}
      >
        {content}
      </div>
    );
  }

  const ratios = layout.children.map((child, index) => {
    const ratio = layout.ratios?.[index];
    return Number.isFinite(ratio) && ratio > 0 ? ratio : 1;
  });

  return (
    <div className={`terminal-split terminal-split-${layout.direction}`}>
      {layout.children.map((child, index) => (
        <Fragment key={child.id}>
          <div className="terminal-split-child" style={getPaneStyle(layout, index)}>
            <TerminalPaneLayout
              layout={child}
              activePaneId={activePaneId}
              onActivatePane={onActivatePane}
              onNewTerminal={onNewTerminal}
              onResizeSplit={onResizeSplit}
              renderPane={renderPane}
            />
          </div>
          {index < layout.children.length - 1 && (
            <TerminalSplitResizer
              direction={layout.direction}
              index={index}
              ratios={ratios}
              splitId={layout.id}
              onResizeSplit={onResizeSplit}
            />
          )}
        </Fragment>
      ))}
    </div>
  );
}
