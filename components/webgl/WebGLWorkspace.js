import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { Text } from '@react-three/drei';
import { Color, Euler, Quaternion, Vector3 } from 'three';
import SpatialTerminal from '../xr/terminals/SpatialTerminal.js';
import SpawnTerminalDialog from '../SpawnTerminalDialog.js';
import useXRTerminal from '../../hooks/useXRTerminal.js';
import useTerminalSpawnDialog from '../../hooks/useTerminalSpawnDialog.js';
import { browserFetch } from '../../lib/browserRequest.js';

const PLACEHOLDER_SESSION = {
  id: null,
  shell: 'No terminal sessions yet',
  cwd: ''
};

const CAMERA_BASE_POSITION = new Vector3(0, 1.55, 1.9);
const CAMERA_DEFAULT_LOOK_AT = new Vector3(0, 1.35, -1.8);

const TERMINAL_BASE_HEIGHT = 1.4;
const CAMERA_FOCUS_DISTANCE = 0.95;
const CAMERA_FOCUS_HEIGHT_OFFSET = 0.04;
const FULLSCREEN_TERMINAL_DISTANCE = 0.85;
const SPLIT_LAYOUT_WIDTH = 3.4;
const SPLIT_LAYOUT_HEIGHT = 1.9;
const SPLIT_LAYOUT_GAP = 0.08;
const SPLIT_LAYOUT_Z = -1.65;
const LAYOUT_CAROUSEL = 'carousel';
const LAYOUT_SPLIT = 'split';

const easeInOutQuad = t => (t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t);

const WEBGL_SCANLINES_STORAGE_KEY = 'notty:webglScanlines';

function resolveWebglDebugFlag() {
  if (typeof window === 'undefined') {
    return false;
  }

  try {
    const params = new URLSearchParams(window.location.search);
    if (params.get('debugWebgl') === '1') {
      return true;
    }
    if (window.localStorage?.getItem('notty:debugWebgl') === '1') {
      return true;
    }
  } catch {
    // ignore
  }

  return false;
}

function resolveWebglScanlinesFlag() {
  if (typeof window === 'undefined') {
    return true;
  }

  try {
    const stored = window.localStorage?.getItem(WEBGL_SCANLINES_STORAGE_KEY);
    if (stored === '0') {
      return false;
    }
    if (stored === '1') {
      return true;
    }
  } catch {
    // ignore
  }

  return true;
}

function useJsonFetch() {
  return useCallback(async (url, options = {}) => {
    const response = await browserFetch(url, {
      headers: { 'Content-Type': 'application/json' },
      ...options
    });

    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.error || response.statusText);
    }

    return response.json();
  }, []);
}

function isEditableTarget(target) {
  if (!target || typeof target !== 'object') {
    return false;
  }

  const node = target;
  const tag = typeof node.tagName === 'string' ? node.tagName.toLowerCase() : '';
  if (tag === 'input' || tag === 'textarea' || tag === 'select') {
    return true;
  }

  if (node.isContentEditable) {
    return true;
  }

  const role = typeof node.getAttribute === 'function' ? node.getAttribute('role') : '';
  return role === 'textbox' || role === 'combobox';
}

function isWithinEditableTarget(target) {
  const node = target && typeof target === 'object' ? target : null;
  if (!node || typeof node.closest !== 'function') {
    return isEditableTarget(target);
  }

  if (node.closest('input,textarea,select,[contenteditable="true"],[role="textbox"],[role="combobox"]')) {
    return true;
  }

  const label = node.closest('label');
  if (label && typeof label.querySelector === 'function') {
    if (label.querySelector('input,textarea,select')) {
      return true;
    }
  }

  return false;
}

function formatColsRowsSpec(cols, rows) {
  const safeCols = Number.isFinite(cols) ? Math.max(10, Math.floor(cols)) : 80;
  const safeRows = Number.isFinite(rows) ? Math.max(5, Math.floor(rows)) : 24;
  return `${safeCols}x${safeRows}`;
}

function parseColsRowsSpec(value) {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (!raw) {
    return null;
  }

  const match = raw.match(/^(\d+)\s*(?:x|×|,|\s)\s*(\d+)$/i);
  if (!match) {
    return null;
  }

  const cols = Number(match[1]);
  const rows = Number(match[2]);
  if (!Number.isFinite(cols) || !Number.isFinite(rows)) {
    return null;
  }

  return { cols, rows };
}

function clampColsRows(cols, rows) {
  const safeCols = Math.max(10, Math.min(600, Math.floor(cols)));
  const safeRows = Math.max(5, Math.min(240, Math.floor(rows)));
  return { cols: safeCols, rows: safeRows };
}

function createSplitLeaf(sessionId) {
  return { type: 'leaf', sessionId };
}

function isSplitLeaf(node) {
  return Boolean(node && node.type === 'leaf');
}

function isSplitBranch(node) {
  return Boolean(node && node.type === 'split');
}

function getSplitLeafIds(node, ids = []) {
  if (!node) {
    return ids;
  }
  if (isSplitLeaf(node)) {
    if (node.sessionId != null) {
      ids.push(node.sessionId);
    }
    return ids;
  }
  if (isSplitBranch(node)) {
    getSplitLeafIds(node.first, ids);
    getSplitLeafIds(node.second, ids);
  }
  return ids;
}

function ensureSplitRoot(root, fallbackSessionId) {
  if (root) {
    return root;
  }
  if (fallbackSessionId == null) {
    return null;
  }
  return createSplitLeaf(fallbackSessionId);
}

function pruneSplitTree(node, liveSessionIds) {
  if (!node) {
    return null;
  }
  if (isSplitLeaf(node)) {
    return liveSessionIds.has(node.sessionId) ? node : null;
  }
  if (!isSplitBranch(node)) {
    return null;
  }

  const first = pruneSplitTree(node.first, liveSessionIds);
  const second = pruneSplitTree(node.second, liveSessionIds);
  if (first && second) {
    return {
      ...node,
      first,
      second
    };
  }
  return first ?? second;
}

function replaceSplitLeaf(node, targetSessionId, replacement) {
  if (!node) {
    return replacement;
  }
  if (isSplitLeaf(node)) {
    return node.sessionId === targetSessionId ? replacement : node;
  }
  if (!isSplitBranch(node)) {
    return node;
  }
  return {
    ...node,
    first: replaceSplitLeaf(node.first, targetSessionId, replacement),
    second: replaceSplitLeaf(node.second, targetSessionId, replacement)
  };
}

function splitSessionInTree(root, targetSessionId, newSessionId, direction) {
  const targetLeaf = createSplitLeaf(targetSessionId);
  const splitNode = {
    type: 'split',
    direction,
    ratio: 0.5,
    first: targetLeaf,
    second: createSplitLeaf(newSessionId)
  };

  if (!root) {
    return splitNode;
  }

  const leafIds = getSplitLeafIds(root);
  if (!leafIds.includes(targetSessionId)) {
    return {
      type: 'split',
      direction,
      ratio: 0.5,
      first: root,
      second: createSplitLeaf(newSessionId)
    };
  }

  return replaceSplitLeaf(root, targetSessionId, splitNode);
}

function buildSplitPanes(node, rect, panes = []) {
  if (!node) {
    return panes;
  }
  if (isSplitLeaf(node)) {
    panes.push({ sessionId: node.sessionId, rect });
    return panes;
  }
  if (!isSplitBranch(node)) {
    return panes;
  }

  const ratio = Number.isFinite(node.ratio) ? Math.min(0.85, Math.max(0.15, node.ratio)) : 0.5;
  if (node.direction === 'vertical') {
    const availableWidth = Math.max(0.4, rect.width - SPLIT_LAYOUT_GAP);
    const firstWidth = availableWidth * ratio;
    const secondWidth = availableWidth - firstWidth;
    const firstRect = {
      x: rect.x - rect.width / 2 + firstWidth / 2,
      y: rect.y,
      width: firstWidth,
      height: rect.height
    };
    const secondRect = {
      x: rect.x + rect.width / 2 - secondWidth / 2,
      y: rect.y,
      width: secondWidth,
      height: rect.height
    };
    buildSplitPanes(node.first, firstRect, panes);
    buildSplitPanes(node.second, secondRect, panes);
    return panes;
  }

  const availableHeight = Math.max(0.4, rect.height - SPLIT_LAYOUT_GAP);
  const firstHeight = availableHeight * ratio;
  const secondHeight = availableHeight - firstHeight;
  const firstRect = {
    x: rect.x,
    y: rect.y + rect.height / 2 - firstHeight / 2,
    width: rect.width,
    height: firstHeight
  };
  const secondRect = {
    x: rect.x,
    y: rect.y - rect.height / 2 + secondHeight / 2,
    width: rect.width,
    height: secondHeight
  };
  buildSplitPanes(node.first, firstRect, panes);
  buildSplitPanes(node.second, secondRect, panes);
  return panes;
}

function translateKey(event) {
  const { key, ctrlKey, altKey, metaKey } = event;

  if (metaKey) {
    return null;
  }

  if (key === 'Escape') {
    return '\u001b';
  }

  if (key === 'Enter') {
    return '\r';
  }

  if (key === 'Backspace') {
    return '\u007f';
  }

  if (key === 'Tab') {
    return '\t';
  }

  if (key === 'ArrowUp') {
    return '\u001b[A';
  }

  if (key === 'ArrowDown') {
    return '\u001b[B';
  }

  if (key === 'ArrowLeft') {
    return '\u001b[D';
  }

  if (key === 'ArrowRight') {
    return '\u001b[C';
  }

  if (key === 'Delete') {
    return '\u001b[3~';
  }

  if (key === 'Home') {
    return '\u001b[H';
  }

  if (key === 'End') {
    return '\u001b[F';
  }

  if (key === 'PageUp') {
    return '\u001b[5~';
  }

  if (key === 'PageDown') {
    return '\u001b[6~';
  }

  if (ctrlKey && key.length === 1) {
    const upper = key.toUpperCase();
    const code = upper.charCodeAt(0);

    if (code >= 64 && code <= 95) {
      return String.fromCharCode(code - 64);
    }

    if (upper === ' ') {
      return '\u0000';
    }

    return null;
  }

  if (altKey && key.length === 1) {
    return `\u001b${key}`;
  }

  if (key.length === 1) {
    return key;
  }

  return null;
}

function focusKeyboardNode(node) {
  if (!node || typeof node.focus !== 'function') {
    return;
  }

  const focus = () => {
    node.value = '';
    try {
      node.focus({ preventScroll: true });
    } catch {
      node.focus();
    }
  };

  focus();

  if (typeof window === 'undefined') {
    return;
  }

  window.requestAnimationFrame?.(() => {
    if (typeof document !== 'undefined' && document.activeElement !== node) {
      focus();
    }
  });
  window.setTimeout(() => {
    if (typeof document !== 'undefined' && document.activeElement !== node) {
      focus();
    }
  }, 80);
}

function useTerminalKeyCapture({
  enabled,
  captureRef,
  onCreate,
  onExitFocus,
  onSplitVertical,
  onSplitHorizontal,
  onToggleFullscreen,
  sendInput
}) {
  const enabledRef = useRef(enabled);
  const sendRef = useRef(sendInput);
  const createRef = useRef(onCreate);
  const exitRef = useRef(onExitFocus);
  const splitVerticalRef = useRef(onSplitVertical);
  const splitHorizontalRef = useRef(onSplitHorizontal);
  const toggleFullscreenRef = useRef(onToggleFullscreen);

  useLayoutEffect(() => {
    enabledRef.current = enabled;
    const node = captureRef.current;
    if (!node) {
      return;
    }
    if (!enabled) {
      node.value = '';
      node.blur?.();
      return;
    }

    focusKeyboardNode(node);
  }, [enabled, captureRef]);

  useEffect(() => {
    sendRef.current = sendInput;
  }, [sendInput]);

  useEffect(() => {
    createRef.current = onCreate;
  }, [onCreate]);

  useEffect(() => {
    exitRef.current = onExitFocus;
  }, [onExitFocus]);

  useEffect(() => {
    splitVerticalRef.current = onSplitVertical;
  }, [onSplitVertical]);

  useEffect(() => {
    splitHorizontalRef.current = onSplitHorizontal;
  }, [onSplitHorizontal]);

  useEffect(() => {
    toggleFullscreenRef.current = onToggleFullscreen;
  }, [onToggleFullscreen]);

  useEffect(() => {
    const node = captureRef.current;
    if (!node) {
      return;
    }

    const focusCapture = () => {
      if (!enabledRef.current) {
        return;
      }
      if (typeof document !== 'undefined' && document.activeElement === node) {
        return;
      }
      focusKeyboardNode(node);
    };

    if (enabledRef.current) {
      focusCapture();
    }

    const handlePointerDown = (event) => {
      if (!enabledRef.current) {
        return;
      }
      if (event.target && typeof event.target === 'object' && typeof event.target.closest === 'function') {
        if (event.target.closest('.webgl-overlay')) {
          return;
        }
      }
      if (isWithinEditableTarget(event.target)) {
        return;
      }
      focusCapture();
    };

    window.addEventListener('pointerdown', handlePointerDown);
    return () => window.removeEventListener('pointerdown', handlePointerDown);
  }, [captureRef]);

  useEffect(() => {
    const node = captureRef.current;
    if (!node) {
      return;
    }

    const flushText = () => {
      if (!enabledRef.current) {
        node.value = '';
        return;
      }
      const value = node.value;
      if (!value) {
        return;
      }
      node.value = '';
      sendRef.current?.(value);
    };

    const handleKeyDown = (event) => {
      if (!enabledRef.current) {
        return;
      }

      if (
        event.ctrlKey
        && event.shiftKey
        && !event.altKey
        && !event.metaKey
        && event.key === 'ArrowUp'
      ) {
        if (event.repeat) {
          return;
        }
        event.preventDefault();
        event.stopPropagation();
        toggleFullscreenRef.current?.();
        return;
      }

      if (
        event.ctrlKey
        && event.shiftKey
        && !event.altKey
        && !event.metaKey
        && event.key === 'ArrowDown'
      ) {
        if (event.repeat) {
          return;
        }
        event.preventDefault();
        event.stopPropagation();
        splitHorizontalRef.current?.();
        return;
      }

      if (
        event.ctrlKey
        && event.shiftKey
        && !event.altKey
        && !event.metaKey
        && event.key === 'ArrowRight'
      ) {
        if (event.repeat) {
          return;
        }
        event.preventDefault();
        event.stopPropagation();
        splitVerticalRef.current?.();
        return;
      }

      if (
        event.ctrlKey
        && !event.altKey
        && !event.metaKey
        && event.key === 'ArrowDown'
      ) {
        if (event.repeat) {
          return;
        }
        event.preventDefault();
        event.stopPropagation();
        exitRef.current?.();
        return;
      }

      const isAltGraph = typeof event.getModifierState === 'function' && event.getModifierState('AltGraph');

      if (
        event.altKey
        && !event.ctrlKey
        && !event.shiftKey
        && !event.metaKey
        && !isAltGraph
        && event.key.toLowerCase() === 'n'
      ) {
        if (event.repeat) {
          return;
        }
        event.preventDefault();
        event.stopPropagation();
        createRef.current?.();
        return;
      }

      const isPlainTextKey = (
        event.key.length === 1
        && !event.ctrlKey
        && !event.altKey
        && !event.metaKey
        && !isAltGraph
      );

      if (isPlainTextKey) {
        return;
      }

      const hasModifier = (event.ctrlKey || event.altKey) && !isAltGraph;
      const isSpecialKey = (
        event.key === 'Enter'
        || event.key === 'Backspace'
        || event.key === 'Tab'
        || event.key === 'Escape'
        || event.key === 'ArrowUp'
        || event.key === 'ArrowDown'
        || event.key === 'ArrowLeft'
        || event.key === 'ArrowRight'
        || event.key === 'Delete'
        || event.key === 'Home'
        || event.key === 'End'
        || event.key === 'PageUp'
        || event.key === 'PageDown'
      );

      if (!hasModifier && !isSpecialKey) {
        return;
      }

      const data = translateKey(event);
      if (!data) {
        return;
      }
      event.preventDefault();
      sendRef.current?.(data);
    };

    node.addEventListener('input', flushText);
    node.addEventListener('compositionend', flushText);
    node.addEventListener('keydown', handleKeyDown);
    return () => {
      node.removeEventListener('input', flushText);
      node.removeEventListener('compositionend', flushText);
      node.removeEventListener('keydown', handleKeyDown);
    };
  }, [captureRef]);
}

function useNavigation({ enabled, onStep, onEnter }) {
  const enabledRef = useRef(enabled);
  const stepRef = useRef(onStep);
  const enterRef = useRef(onEnter);

  useEffect(() => {
    enabledRef.current = enabled;
  }, [enabled]);

  useEffect(() => {
    stepRef.current = onStep;
  }, [onStep]);

  useEffect(() => {
    enterRef.current = onEnter;
  }, [onEnter]);

  useEffect(() => {
    const handleKeyDown = event => {
      if (isEditableTarget(event.target)) {
        return;
      }

      if (!enabledRef.current) {
        return;
      }

      if (event.ctrlKey || event.shiftKey || event.altKey || event.metaKey) {
        return;
      }

      if (event.key === 'Enter') {
        if (event.repeat) {
          return;
        }
        event.preventDefault();
        enterRef.current?.();
        return;
      }

      if (event.key === 'ArrowLeft') {
        event.preventDefault();
        stepRef.current?.(-1);
        return;
      }

      if (event.key === 'ArrowRight') {
        event.preventDefault();
        stepRef.current?.(1);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);
}

function FocusCamera({ focusTarget }) {
  const { camera } = useThree();
  const animationRef = useRef({
    startTime: 0,
    duration: 0,
    startPosition: new Vector3().copy(CAMERA_BASE_POSITION),
    startLookAt: new Vector3().copy(CAMERA_DEFAULT_LOOK_AT),
    targetPosition: new Vector3().copy(CAMERA_BASE_POSITION),
    targetLookAt: new Vector3().copy(CAMERA_DEFAULT_LOOK_AT),
  });

  useEffect(() => {
    const now = Date.now();

    const anim = animationRef.current;
    anim.startTime = now;
    anim.duration = focusTarget ? 700 : 650;
    anim.startPosition.copy(camera.position);
    anim.startLookAt.copy(anim.targetLookAt);
    if (focusTarget?.cameraPosition && focusTarget?.lookAt) {
      anim.targetPosition.set(
        focusTarget.cameraPosition[0],
        focusTarget.cameraPosition[1],
        focusTarget.cameraPosition[2]
      );
      anim.targetLookAt.set(
        focusTarget.lookAt[0],
        focusTarget.lookAt[1],
        focusTarget.lookAt[2]
      );
    } else {
      anim.targetPosition.copy(CAMERA_BASE_POSITION);
      anim.targetLookAt.copy(CAMERA_DEFAULT_LOOK_AT);
    }
  }, [focusTarget, camera]);

  useFrame(() => {
    const anim = animationRef.current;
    const now = Date.now();
    const elapsed = now - anim.startTime;
    const progress = Math.min(elapsed / anim.duration, 1);
    const easedProgress = easeInOutQuad(progress);

    camera.position.lerpVectors(anim.startPosition, anim.targetPosition, easedProgress);
    const nextLookAt = new Vector3().lerpVectors(anim.startLookAt, anim.targetLookAt, easedProgress);
    camera.lookAt(nextLookAt);

    if (progress === 1) {
      anim.startTime = 0;
    }
  });

  return null;
}

function FullscreenTerminalOverlay({ enabled, texture, onFocusInput }) {
  const groupRef = useRef(null);
  const backgroundRef = useRef(null);
  const terminalRef = useRef(null);
  const { camera, size } = useThree();

  useFrame(() => {
    if (!enabled) {
      return;
    }

    const group = groupRef.current;
    const background = backgroundRef.current;
    const terminal = terminalRef.current;
    if (!group || !background || !terminal) {
      return;
    }

    const distance = Math.max(Number(camera.near) + 0.02, FULLSCREEN_TERMINAL_DISTANCE);
    group.position.copy(camera.position);
    group.quaternion.copy(camera.quaternion);

    const pixelAspect = size.width > 0 && size.height > 0 ? size.width / size.height : 1;
    const fov = camera.isPerspectiveCamera ? camera.fov : 60;
    const viewportHeight = 2 * Math.tan((fov * Math.PI) / 360) * distance;
    const viewportWidth = viewportHeight * pixelAspect;

    background.position.set(0, 0, -distance);
    background.scale.set(viewportWidth, viewportHeight, 1);

    const image = texture?.image;
    const texWidth = Number(image?.width ?? image?.videoWidth ?? 0);
    const texHeight = Number(image?.height ?? image?.videoHeight ?? 0);
    const textureAspect = texHeight > 0 ? texWidth / texHeight : pixelAspect;

    let planeWidth = viewportWidth;
    let planeHeight = viewportHeight;
    if (pixelAspect > textureAspect) {
      planeWidth = viewportHeight * textureAspect;
    } else if (pixelAspect < textureAspect) {
      planeHeight = viewportWidth / textureAspect;
    }

    terminal.position.set(0, 0, -distance + 0.001);
    terminal.scale.set(planeWidth, planeHeight, 1);
  });

  if (!enabled) {
    return null;
  }

  return (
    <group ref={groupRef}>
      <mesh
        ref={backgroundRef}
        frustumCulled={false}
        renderOrder={9998}
        onPointerDown={(event) => {
          event.stopPropagation();
          onFocusInput?.();
        }}
      >
        <planeGeometry args={[1, 1]} />
        <meshBasicMaterial color="#000000" toneMapped={false} depthTest={false} depthWrite={false} />
      </mesh>
      <mesh
        ref={terminalRef}
        frustumCulled={false}
        renderOrder={9999}
        onPointerDown={(event) => {
          event.stopPropagation();
          onFocusInput?.();
        }}
      >
        <planeGeometry args={[1, 1]} />
        {texture ? (
          <meshBasicMaterial map={texture} toneMapped={false} depthTest={false} depthWrite={false} />
        ) : (
          <meshBasicMaterial color="#05070f" toneMapped={false} depthTest={false} depthWrite={false} />
        )}
      </mesh>
    </group>
  );
}

function SessionCarousel({
  sessions,
  activeIndex,
  onSessionFocus,
  onSessionBlur,
  onSelect,
  focusedSessionId,
  manualResizeSessions,
  debugWebgl,
  scanlinesEnabled,
  sceneHidden = false,
  onCreate,
  onKill,
  creating,
  killing,
  errorMessage,
  onFocusedTransform,
  onTerminalTexture
}) {
  const carouselRef = useRef();
  const rotationRef = useRef(0);
  const targetRotationRef = useRef(0);
  const sessionGroupRefs = useRef(new Map());
  const lastTransformRef = useRef(null);

  const total = sessions.length;
  const angleStep = total > 0 ? (Math.PI * 2) / total : Math.PI * 2;
  const radius = 2.25;
  const baseHeight = TERMINAL_BASE_HEIGHT;

  useEffect(() => {
    if (total <= 0) {
      targetRotationRef.current = 0;
      return;
    }

    const baseRotation = -activeIndex * angleStep;
    const currentRotation = rotationRef.current;
    const twoPi = Math.PI * 2;
    const offset = Math.round((currentRotation - baseRotation) / twoPi) * twoPi;
    targetRotationRef.current = baseRotation + offset;
  }, [activeIndex, angleStep, total]);

  useFrame((_, delta) => {
    if (sceneHidden) {
      return;
    }

    const current = rotationRef.current;
    const target = targetRotationRef.current;
    if (Math.abs(target - current) > 1e-4) {
      const smoothing = 1 - Math.exp(-delta * 4.2);
      const next = current + (target - current) * smoothing;
      rotationRef.current = next;
      if (carouselRef.current) {
        carouselRef.current.rotation.y = next;
      }
    }

    if (focusedSessionId == null || !onFocusedTransform) {
      return;
    }

    const node = sessionGroupRefs.current.get(focusedSessionId);
    if (!node) {
      return;
    }

    const panelPosition = new Vector3(0, baseHeight, 0);
    node.localToWorld(panelPosition);
    const quaternion = new Quaternion();
    node.getWorldQuaternion(quaternion);
    const euler = new Euler().setFromQuaternion(quaternion, 'YXZ');
    const forward = new Vector3(0, 0, 1).applyQuaternion(quaternion).normalize();
    const payload = {
      sessionId: focusedSessionId,
      position: [panelPosition.x, panelPosition.y, panelPosition.z],
      rotation: [euler.x, euler.y, euler.z],
      forward: [forward.x, forward.y, forward.z]
    };
    const previous = lastTransformRef.current;
    if (
      !previous ||
      previous.sessionId !== payload.sessionId ||
      Math.abs(previous.position[0] - payload.position[0]) > 1e-3 ||
      Math.abs(previous.position[1] - payload.position[1]) > 1e-3 ||
      Math.abs(previous.position[2] - payload.position[2]) > 1e-3 ||
      Math.abs(previous.rotation[0] - payload.rotation[0]) > 1e-3 ||
      Math.abs(previous.rotation[1] - payload.rotation[1]) > 1e-3 ||
      Math.abs(previous.rotation[2] - payload.rotation[2]) > 1e-3
    ) {
      lastTransformRef.current = payload;
      onFocusedTransform(payload);
    }
  });

  const displaySessions = sessions.length ? sessions : [PLACEHOLDER_SESSION];
  const displayCount = displaySessions.length;
  const displayStep = displayCount > 0 ? (Math.PI * 2) / displayCount : Math.PI * 2;

  useEffect(() => {
    if (focusedSessionId == null) {
      lastTransformRef.current = null;
      onFocusedTransform?.(null);
    }
  }, [focusedSessionId, onFocusedTransform]);

  return (
    <>
      <group ref={carouselRef} visible={!sceneHidden}>
        {displaySessions.map((session, index) => {
          const baseAngle = index * displayStep + Math.PI;
          const position = [
            Math.sin(baseAngle) * radius,
            0,
            Math.cos(baseAngle) * radius
          ];
          const rotation = [0, baseAngle - Math.PI, 0];
          const terminalId = session.id != null ? `webgl-${session.id}` : `placeholder-${index}`;
          const title = session.id != null ? `Session ${session.id} · ${session.shell}` : session.shell;
          const isFocused = focusedSessionId === session.id;
          const isActive = sessions.length ? index === activeIndex : true;
          const holographicEnabled = Boolean(scanlinesEnabled) && (isActive || isFocused);
          const resizeMode = session.id != null && manualResizeSessions?.has(session.id) ? 'follow' : 'push';

          const refCallback = node => {
            if (session.id == null) {
              return;
            }
            if (node) {
              sessionGroupRefs.current.set(session.id, node);
            } else {
              sessionGroupRefs.current.delete(session.id);
            }
          };

          return (
            <group key={terminalId} position={position} rotation={rotation} ref={refCallback}>
              <SpatialTerminal
                sessionId={session.id ?? undefined}
                terminalId={terminalId}
                title={title}
                position={[0, baseHeight, 0]}
                rotation={[0, 0, 0]}
                size={[1.28, 0.8]}
                quality="balanced"
                resizeMode={resizeMode}
                matchTextureAspect
                showStatusLine={Boolean(debugWebgl)}
                holographic={holographicEnabled}
                inputActive={isFocused}
                onTexture={(texture) => {
                  if (session.id != null) {
                    onTerminalTexture?.(session.id, texture);
                  }
                }}
                onFocus={() => {
                  if (session.id != null) {
                    onSelect(index);
                  }
                }}
                onActivate={() => {
                  if (session.id != null) {
                    onSelect(index);
                    onSessionFocus(session);
                  }
                }}
                onBlur={() => {
                  if (session.id != null) {
                    onSessionBlur(session);
                  }
                }}
              />
            </group>
          );
        })}
      </group>

      <group position={[0, 0.15, -1.2]} visible={!sceneHidden}>
        <ControlCube
          position={[-0.6, 0, 0]}
          color={creating ? '#1e3a8a' : '#2563eb'}
          label={creating ? 'Spawning…' : 'New Session'}
          onClick={onCreate}
          disabled={creating}
        />
        <ControlCube
          position={[0.6, 0, 0]}
          color={killing ? '#7f1d1d' : '#dc2626'}
          label={killing ? 'Terminating…' : 'Kill Session'}
          onClick={onKill}
          disabled={killing || !sessions.length || !sessions[activeIndex]?.id}
        />
      </group>

      <group visible={!sceneHidden}>
        <EnvironmentElements />
      </group>

      {!sceneHidden && errorMessage ? (
        <Text position={[0, 2.45, -1.9]} fontSize={0.18} color="#fca5a5" anchorX="center" anchorY="middle">
          {errorMessage}
        </Text>
      ) : null}
    </>
  );
}

function SessionSplitLayout({
  sessions,
  splitRoot,
  activeSessionId,
  onSessionFocus,
  onSessionBlur,
  onSelectSession,
  focusedSessionId,
  manualResizeSessions,
  debugWebgl,
  scanlinesEnabled,
  sceneHidden = false,
  onCreate,
  onKill,
  creating,
  killing,
  errorMessage,
  onFocusedTransform,
  onTerminalTexture
}) {
  const paneGroupRefs = useRef(new Map());
  const lastTransformRef = useRef(null);
  const baseHeight = TERMINAL_BASE_HEIGHT;
  const sessionMap = useMemo(() => {
    const next = new Map();
    sessions.forEach((session) => {
      if (session.id != null) {
        next.set(session.id, session);
      }
    });
    return next;
  }, [sessions]);
  const panes = useMemo(() => {
    const rect = {
      x: 0,
      y: 0,
      width: SPLIT_LAYOUT_WIDTH,
      height: SPLIT_LAYOUT_HEIGHT
    };
    return buildSplitPanes(splitRoot, rect).filter((pane) => sessionMap.has(pane.sessionId));
  }, [splitRoot, sessionMap]);

  useFrame(() => {
    if (sceneHidden) {
      return;
    }

    if (focusedSessionId == null || !onFocusedTransform) {
      return;
    }

    const node = paneGroupRefs.current.get(focusedSessionId);
    if (!node) {
      return;
    }

    const panelPosition = new Vector3(0, 0, 0);
    node.localToWorld(panelPosition);
    const quaternion = new Quaternion();
    node.getWorldQuaternion(quaternion);
    const euler = new Euler().setFromQuaternion(quaternion, 'YXZ');
    const forward = new Vector3(0, 0, 1).applyQuaternion(quaternion).normalize();
    const payload = {
      sessionId: focusedSessionId,
      position: [panelPosition.x, panelPosition.y, panelPosition.z],
      rotation: [euler.x, euler.y, euler.z],
      forward: [forward.x, forward.y, forward.z]
    };
    const previous = lastTransformRef.current;
    if (
      !previous ||
      previous.sessionId !== payload.sessionId ||
      Math.abs(previous.position[0] - payload.position[0]) > 1e-3 ||
      Math.abs(previous.position[1] - payload.position[1]) > 1e-3 ||
      Math.abs(previous.position[2] - payload.position[2]) > 1e-3 ||
      Math.abs(previous.rotation[0] - payload.rotation[0]) > 1e-3 ||
      Math.abs(previous.rotation[1] - payload.rotation[1]) > 1e-3 ||
      Math.abs(previous.rotation[2] - payload.rotation[2]) > 1e-3
    ) {
      lastTransformRef.current = payload;
      onFocusedTransform(payload);
    }
  });

  useEffect(() => {
    if (focusedSessionId == null) {
      lastTransformRef.current = null;
      onFocusedTransform?.(null);
    }
  }, [focusedSessionId, onFocusedTransform]);

  return (
    <>
      <group visible={!sceneHidden}>
        {panes.map((pane) => {
          const session = sessionMap.get(pane.sessionId);
          if (!session) {
            return null;
          }

          const terminalId = `webgl-split-${session.id}`;
          const title = `Session ${session.id} · ${session.shell}`;
          const isFocused = focusedSessionId === session.id;
          const isActive = activeSessionId === session.id;
          const holographicEnabled = Boolean(scanlinesEnabled) && (isActive || isFocused);
          const resizeMode = manualResizeSessions?.has(session.id) ? 'follow' : 'push';
          const size = [
            Math.max(0.6, pane.rect.width),
            Math.max(0.4, pane.rect.height)
          ];
          const position = [
            pane.rect.x,
            baseHeight + pane.rect.y,
            SPLIT_LAYOUT_Z
          ];

          const refCallback = node => {
            if (node) {
              paneGroupRefs.current.set(session.id, node);
            } else {
              paneGroupRefs.current.delete(session.id);
            }
          };

          const selectAndFocus = () => {
            onSelectSession(session.id);
            onSessionFocus(session);
          };

          return (
            <group key={terminalId} position={position} rotation={[0, 0, 0]} ref={refCallback}>
              <SpatialTerminal
                sessionId={session.id}
                terminalId={terminalId}
                title={title}
                position={[0, 0, 0]}
                rotation={[0, 0, 0]}
                size={size}
                quality="balanced"
                resizeMode={resizeMode}
                matchTextureAspect={false}
                showStatusLine={Boolean(debugWebgl)}
                holographic={holographicEnabled}
                inputActive={isFocused}
                onTexture={(texture) => onTerminalTexture?.(session.id, texture)}
                onFocus={selectAndFocus}
                onActivate={selectAndFocus}
                onBlur={() => onSessionBlur(session)}
              />
            </group>
          );
        })}
      </group>

      <group position={[0, 0.15, -1.2]} visible={!sceneHidden}>
        <ControlCube
          position={[-0.6, 0, 0]}
          color={creating ? '#1e3a8a' : '#2563eb'}
          label={creating ? 'Spawning...' : 'New Session'}
          onClick={onCreate}
          disabled={creating}
        />
        <ControlCube
          position={[0.6, 0, 0]}
          color={killing ? '#7f1d1d' : '#dc2626'}
          label={killing ? 'Terminating...' : 'Kill Session'}
          onClick={onKill}
          disabled={killing || activeSessionId == null}
        />
      </group>

      <group visible={!sceneHidden}>
        <EnvironmentElements />
      </group>

      {!sceneHidden && errorMessage ? (
        <Text position={[0, 2.45, -1.9]} fontSize={0.18} color="#fca5a5" anchorX="center" anchorY="middle">
          {errorMessage}
        </Text>
      ) : null}
    </>
  );
}

function ControlCube({ position, color, label, onClick, disabled }) {
  const [hovered, setHovered] = useState(false);
  const handleClick = useCallback(() => {
    if (!disabled && typeof onClick === 'function') {
      onClick();
    }
  }, [disabled, onClick]);

  return (
    <group position={position}>
      <mesh
        onPointerDown={handleClick}
        onPointerOver={() => {
          if (!disabled) {
            setHovered(true);
          }
        }}
        onPointerOut={() => setHovered(false)}
      >
        <boxGeometry args={[0.32, 0.32, 0.32]} />
        <meshStandardMaterial
          color={new Color(disabled ? '#334155' : hovered ? new Color(color).offsetHSL(0, 0, 0.1) : color)}
          metalness={0.2}
          roughness={0.4}
        />
      </mesh>
      <Text position={[0, -0.28, 0]} fontSize={0.12} color="#dbeafe" anchorX="center" anchorY="top">
        {label}
      </Text>
    </group>
  );
}

function EnvironmentElements() {
  return (
    <group>
      <ambientLight intensity={0.4} />
      <directionalLight position={[3, 6, 2]} intensity={1.1} castShadow />
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.01, 0]} receiveShadow>
        <circleGeometry args={[6, 64]} />
        <meshStandardMaterial color="#0b1120" roughness={0.9} metalness={0.05} />
      </mesh>
      <gridHelper args={[8, 32, '#1e293b', '#0f172a']} position={[0, -0.009, 0]} />
    </group>
  );
}

export default function WebGLWorkspace() {
  const jsonFetch = useJsonFetch();
  const { requestTerminalSpawn, spawnDialogProps } = useTerminalSpawnDialog();
  const [debugWebgl] = useState(() => resolveWebglDebugFlag());
  const [scanlinesEnabled, setScanlinesEnabled] = useState(() => resolveWebglScanlinesFlag());
  const debugLog = useCallback((...args) => {
    if (debugWebgl) {
      console.log(...args);
    }
  }, [debugWebgl]);
  const [sessions, setSessions] = useState([]);
  const [activeIndex, setActiveIndex] = useState(0);
  const [layoutMode, setLayoutMode] = useState(LAYOUT_CAROUSEL);
  const [splitRoot, setSplitRoot] = useState(null);
  const [focusedSessionId, setFocusedSessionId] = useState(null);
  const [focusTransform, setFocusTransform] = useState(null);
  const [manualResizeSessions, setManualResizeSessions] = useState(() => new Set());
  const [resizeSpec, setResizeSpec] = useState('');
  const [resizeDirty, setResizeDirty] = useState(false);
  const [controlMessage, setControlMessage] = useState('');
  const [controlsCollapsed, setControlsCollapsed] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [fullscreenTerminalSessionId, setFullscreenTerminalSessionId] = useState(null);
  const [fullscreenTerminalTexture, setFullscreenTerminalTexture] = useState(null);
  const terminalTexturesRef = useRef(new Map());
  const controlsCollapsedBeforeFullscreenRef = useRef(false);
  const controlsCollapsedAutoRef = useRef(false);
  const keyCaptureRef = useRef(null);
  const pendingInputRef = useRef('');
  const [creating, setCreating] = useState(false);
  const [killing, setKilling] = useState(false);
  const [error, setError] = useState(null);
  const focusLockRef = useRef(false);
  const requestKeyboardCapture = useCallback(() => {
    const node = keyCaptureRef.current;
    focusKeyboardNode(node);

    if (typeof window === 'undefined') {
      return;
    }

    window.requestAnimationFrame?.(() => focusKeyboardNode(node));
    window.setTimeout(() => focusKeyboardNode(node), 0);
    window.setTimeout(() => focusKeyboardNode(node), 160);
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }

    try {
      window.localStorage?.setItem(WEBGL_SCANLINES_STORAGE_KEY, scanlinesEnabled ? '1' : '0');
    } catch {
      // ignore
    }
  }, [scanlinesEnabled]);

  const handleTerminalTexture = useCallback((sessionId, texture) => {
    if (sessionId == null) {
      return;
    }

    const map = terminalTexturesRef.current;
    if (texture) {
      map.set(sessionId, texture);
    } else {
      map.delete(sessionId);
    }

    if (sessionId === fullscreenTerminalSessionId) {
      setFullscreenTerminalTexture(texture ?? null);
    }
  }, [fullscreenTerminalSessionId]);

  useEffect(() => {
    if (fullscreenTerminalSessionId == null) {
      setFullscreenTerminalTexture(null);
      return;
    }

    setFullscreenTerminalTexture(terminalTexturesRef.current.get(fullscreenTerminalSessionId) ?? null);
  }, [fullscreenTerminalSessionId]);

  useEffect(() => {
    if (fullscreenTerminalSessionId == null) {
      return;
    }

    if (sessions.some(session => session.id === fullscreenTerminalSessionId)) {
      return;
    }

    setFullscreenTerminalSessionId(null);
  }, [sessions, fullscreenTerminalSessionId]);

  const isTerminalFullscreen = fullscreenTerminalSessionId != null;

  useEffect(() => {
    if (focusedSessionId == null && !isTerminalFullscreen) {
      return;
    }
    requestKeyboardCapture();
  }, [focusedSessionId, isTerminalFullscreen, requestKeyboardCapture]);

  useEffect(() => {
    if (isTerminalFullscreen) {
      controlsCollapsedBeforeFullscreenRef.current = controlsCollapsed;
      controlsCollapsedAutoRef.current = true;
      if (!controlsCollapsed) {
        setControlsCollapsed(true);
      }
      return;
    }

    if (!controlsCollapsedAutoRef.current) {
      return;
    }

    controlsCollapsedAutoRef.current = false;
    if (controlsCollapsed) {
      setControlsCollapsed(controlsCollapsedBeforeFullscreenRef.current);
    }
  }, [isTerminalFullscreen]);

  const loadSessions = useCallback(async () => {
    try {
      const data = await jsonFetch('/api/terminals');
      const list = Array.isArray(data.sessions) ? data.sessions : [];
      setSessions(list);
      setActiveIndex(prev => {
        if (list.length === 0) {
          return 0;
        }
        if (prev >= list.length) {
          return 0;
        }
        return prev;
      });
      setError(null);
      return list;
    } catch (err) {
      setError(err.message);
      return [];
    }
  }, [jsonFetch]);

  useEffect(() => {
    loadSessions();
  }, [loadSessions]);

  useEffect(() => {
    if (focusedSessionId == null) {
      return;
    }
    if (sessions.some(session => session.id === focusedSessionId)) {
      return;
    }
    debugLog('[webgl] focused session disappeared', { focusedSessionId });
    setFocusedSessionId(null);
  }, [sessions, focusedSessionId, debugLog]);

  const activeSession = sessions.length ? sessions[Math.min(activeIndex, sessions.length - 1)] : null;
  const activeSessionId = activeSession?.id ?? null;
  const splitLeafIds = useMemo(() => getSplitLeafIds(splitRoot), [splitRoot]);
  const splitFallbackSessionId = useMemo(() => {
    if (focusedSessionId != null && sessions.some(session => session.id === focusedSessionId)) {
      return focusedSessionId;
    }
    if (activeSessionId != null && splitLeafIds.includes(activeSessionId)) {
      return activeSessionId;
    }
    const splitLiveSessionId = splitLeafIds.find(sessionId => sessions.some(session => session.id === sessionId));
    return splitLiveSessionId ?? activeSessionId ?? sessions[0]?.id ?? null;
  }, [focusedSessionId, sessions, activeSessionId, splitLeafIds]);
  const effectiveSplitRoot = useMemo(
    () => ensureSplitRoot(splitRoot, splitFallbackSessionId),
    [splitRoot, splitFallbackSessionId]
  );
  const targetSession = focusedSessionId != null
    ? sessions.find(session => session.id === focusedSessionId) ?? activeSession
    : activeSession;
  const targetSessionId = targetSession?.id ?? null;
  const targetSessionLabel = focusedSessionId != null ? 'Focused' : 'Active';
  const manualResizeLocked = targetSessionId != null && manualResizeSessions.has(targetSessionId);

  useEffect(() => {
    setManualResizeSessions((previous) => {
      if (!previous.size) {
        return previous;
      }

      const liveIds = new Set(sessions.map(session => session.id));
      let changed = false;
      const next = new Set();
      previous.forEach((sessionId) => {
        if (liveIds.has(sessionId)) {
          next.add(sessionId);
        } else {
          changed = true;
        }
      });
      return changed ? next : previous;
    });
  }, [sessions]);

  useEffect(() => {
    const liveIds = new Set(sessions.map(session => session.id));
    setSplitRoot(previous => pruneSplitTree(previous, liveIds));
  }, [sessions]);

  useEffect(() => {
    if (layoutMode !== LAYOUT_SPLIT) {
      return;
    }
    if (sessions.length || splitRoot) {
      return;
    }
    setLayoutMode(LAYOUT_CAROUSEL);
  }, [layoutMode, sessions.length, splitRoot]);

  useEffect(() => {
    debugLog('[webgl] state', {
      sessions: sessions.map(session => session.id),
      activeIndex,
      activeSessionId: activeSession?.id ?? null,
      focusedSessionId
    });
  }, [debugLog, sessions, activeIndex, activeSession?.id, focusedSessionId]);

  const {
    status: controlStatus,
    statusNote: controlStatusNote,
    dimensions: controlDimensions,
    isConnected: isControlConnected,
    sendInput: sendInputRaw,
    sendResize: sendResizeRaw,
    reconnect: reconnectControl
  } = useXRTerminal({
    sessionId: targetSessionId ?? undefined,
    autoConnect: targetSessionId != null
  });

  const sendInput = useCallback((data) => {
    if (data === '\r' || data === '\u001b') {
      debugLog('[webgl] sendInput', { focusedSessionId, data });
    }
    const ok = sendInputRaw(data);
    if (ok) {
      return true;
    }

    pendingInputRef.current = (pendingInputRef.current + data).slice(-4096);
    reconnectControl().catch(() => {});
    return false;
  }, [sendInputRaw, debugLog, focusedSessionId, reconnectControl]);

  const flushPendingInput = useCallback(() => {
    const pending = pendingInputRef.current;
    if (!pending) {
      return;
    }
    const ok = sendInputRaw(pending);
    if (ok) {
      pendingInputRef.current = '';
    }
  }, [sendInputRaw]);

  useEffect(() => {
    setControlMessage('');
    setResizeDirty(false);
    pendingInputRef.current = '';

    if (targetSessionId == null) {
      setResizeSpec('');
      return;
    }

    const cols = Number.isFinite(targetSession?.cols) ? targetSession.cols : controlDimensions.cols;
    const rows = Number.isFinite(targetSession?.rows) ? targetSession.rows : controlDimensions.rows;
    setResizeSpec(formatColsRowsSpec(cols, rows));
  }, [targetSessionId]);

  useEffect(() => {
    if (targetSessionId == null) {
      return;
    }
    if (resizeDirty) {
      return;
    }
    setResizeSpec(formatColsRowsSpec(controlDimensions.cols, controlDimensions.rows));
  }, [targetSessionId, controlDimensions.cols, controlDimensions.rows, resizeDirty]);

  useEffect(() => {
    if (isControlConnected) {
      flushPendingInput();
    }
  }, [isControlConnected, flushPendingInput]);

  const handleApplyResize = useCallback(async () => {
    if (targetSessionId == null) {
      setControlMessage('No session selected.');
      return;
    }

    const parsed = parseColsRowsSpec(resizeSpec);
    if (!parsed) {
      setControlMessage('Enter a size like 120x40.');
      return;
    }

    const { cols, rows } = clampColsRows(parsed.cols, parsed.rows);
    setResizeSpec(formatColsRowsSpec(cols, rows));
    setResizeDirty(false);
    setControlMessage('');

    setManualResizeSessions((previous) => {
      if (previous.has(targetSessionId)) {
        return previous;
      }
      const next = new Set(previous);
      next.add(targetSessionId);
      return next;
    });

    if (!isControlConnected) {
      await reconnectControl().catch(() => {});
    }

    const ok = sendResizeRaw(cols, rows);
    if (!ok) {
      setControlMessage('Resize failed (not connected yet).');
    }
  }, [targetSessionId, resizeSpec, isControlConnected, reconnectControl, sendResizeRaw]);

  const handleAutoFit = useCallback(() => {
    if (targetSessionId == null) {
      return;
    }
    setControlMessage('');
    setManualResizeSessions((previous) => {
      if (!previous.has(targetSessionId)) {
        return previous;
      }
      const next = new Set(previous);
      next.delete(targetSessionId);
      return next;
    });
  }, [targetSessionId]);

  const handleResetTerminal = useCallback(async () => {
    if (targetSessionId == null) {
      setControlMessage('No session selected.');
      return;
    }

    setControlMessage('');
    if (!isControlConnected) {
      await reconnectControl().catch(() => {});
    }

    const ok = sendInputRaw('reset\r');
    if (!ok) {
      setControlMessage('Reset failed (not connected yet).');
    }
  }, [targetSessionId, isControlConnected, reconnectControl, sendInputRaw]);

  const handleFocusedTransformUpdate = useCallback(transform => {
    if (!transform) {
      setFocusTransform(null);
      return;
    }
    setFocusTransform(current => {
      if (!transform || transform.sessionId !== focusedSessionId) {
        return current;
      }
      if (!current) {
        return transform;
      }
      if (current.sessionId !== transform.sessionId) {
        return transform;
      }
      const positionChanged =
        Math.abs(current.position[0] - transform.position[0]) > 1e-3 ||
        Math.abs(current.position[1] - transform.position[1]) > 1e-3 ||
        Math.abs(current.position[2] - transform.position[2]) > 1e-3;
      const rotationChanged =
        Math.abs(current.rotation[0] - transform.rotation[0]) > 1e-3 ||
        Math.abs(current.rotation[1] - transform.rotation[1]) > 1e-3 ||
        Math.abs(current.rotation[2] - transform.rotation[2]) > 1e-3;
      const forwardChanged =
        !current.forward ||
        !transform.forward ||
        Math.abs(current.forward[0] - transform.forward[0]) > 1e-3 ||
        Math.abs(current.forward[1] - transform.forward[1]) > 1e-3 ||
        Math.abs(current.forward[2] - transform.forward[2]) > 1e-3;
      if (positionChanged || rotationChanged || forwardChanged) {
        return transform;
      }
      return current;
    });
  }, [focusedSessionId]);

  useEffect(() => {
    if (focusedSessionId == null) {
      setFocusTransform(null);
    }
  }, [focusedSessionId]);

  const focusTarget = useMemo(() => {
    if (!focusTransform) {
      return null;
    }
    const position = focusTransform.position;
    const forward = focusTransform.forward;
    if (!position || position.length !== 3) {
      return null;
    }
    const center = new Vector3(position[0], position[1], position[2]);
    const direction = forward && forward.length === 3
      ? new Vector3(forward[0], forward[1], forward[2])
      : new Vector3(0, 0, 1);
    if (direction.lengthSq() === 0) {
      direction.set(0, 0, 1);
    }
    direction.normalize();
    const cameraPosition = center.clone().add(direction.clone().multiplyScalar(CAMERA_FOCUS_DISTANCE));
    cameraPosition.y += CAMERA_FOCUS_HEIGHT_OFFSET;
    const lookAt = center.clone();
    return {
      cameraPosition: [cameraPosition.x, cameraPosition.y, cameraPosition.z],
      lookAt: [lookAt.x, lookAt.y, lookAt.z]
    };
  }, [focusTransform]);

  useNavigation({
    enabled: focusedSessionId == null && layoutMode === LAYOUT_CAROUSEL,
    onStep: direction => {
      if (!sessions.length) {
        return;
      }
      setActiveIndex(prev => {
        const next = (prev + direction + sessions.length) % sessions.length;
        return next;
      });
    },
    onEnter: () => {
      if (focusedSessionId != null) {
        return;
      }
      const session = activeSession;
      if (session?.id != null) {
        debugLog('[webgl] enter focus', { activeIndex, sessionId: session.id });
        if (typeof document !== 'undefined') {
          document.activeElement?.blur?.();
        }
        setFocusedSessionId(session.id);
        requestKeyboardCapture();
      }
    }
  });

  const spawnTerminalSession = useCallback(async () => {
    if (creating) {
      return null;
    }
    setCreating(true);
    try {
      const data = await requestTerminalSpawn({});
      if (!data) {
        return null;
      }
      const list = await loadSessions();
      if (data?.session?.id && Array.isArray(list)) {
        let index = list.findIndex(session => session.id === data.session.id);
        if (index < 0 && list.length) {
          index = list.length - 1;
        }
        if (index >= 0) {
          setActiveIndex(index);
          setFocusedSessionId(data.session.id);
          requestKeyboardCapture();
        }
      }
      return {
        session: data?.session ?? null,
        list,
        index: data?.session?.id && Array.isArray(list)
          ? list.findIndex(session => session.id === data.session.id)
          : -1
      };
    } catch (err) {
      setError(err.message);
      return null;
    } finally {
      setCreating(false);
    }
  }, [creating, loadSessions, requestKeyboardCapture, requestTerminalSpawn]);

  const resolveSplitTargetSessionId = useCallback(() => {
    if (focusedSessionId != null && sessions.some(session => session.id === focusedSessionId)) {
      return focusedSessionId;
    }
    if (activeSession?.id != null) {
      return activeSession.id;
    }
    return sessions[0]?.id ?? null;
  }, [focusedSessionId, sessions, activeSession?.id]);

  const handleSplit = useCallback(async (direction) => {
    const targetSessionId = resolveSplitTargetSessionId();
    const result = await spawnTerminalSession();
    const newSessionId = result?.session?.id ?? null;
    if (newSessionId == null) {
      return;
    }

    setLayoutMode(LAYOUT_SPLIT);
    setControlMessage('');
    if (targetSessionId == null) {
      setSplitRoot(createSplitLeaf(newSessionId));
      return;
    }

    setSplitRoot(previous => {
      const root = ensureSplitRoot(previous, targetSessionId);
      return splitSessionInTree(root, targetSessionId, newSessionId, direction);
    });
  }, [resolveSplitTargetSessionId, spawnTerminalSession]);

  const handleSplitVertical = useCallback(() => {
    handleSplit('vertical');
  }, [handleSplit]);

  const handleSplitHorizontal = useCallback(() => {
    handleSplit('horizontal');
  }, [handleSplit]);

  const handleCreate = useCallback(async () => {
    await spawnTerminalSession();
  }, [spawnTerminalSession]);

  const handleCreateForActiveLayout = useCallback(() => {
    if (layoutMode === LAYOUT_SPLIT) {
      handleSplitVertical();
      return;
    }
    handleCreate();
  }, [layoutMode, handleSplitVertical, handleCreate]);

  const handleKill = useCallback(async () => {
    if (killing) {
      return;
    }
    const session = targetSession;
    if (session?.id == null) {
      return;
    }
    setKilling(true);
    try {
      await browserFetch(`/api/terminals/${session.id}`, { method: 'DELETE' });
      setFocusedSessionId(current => (current === session.id ? null : current));
      await loadSessions();
    } catch (err) {
      setError(err.message);
    } finally {
      setKilling(false);
    }
  }, [killing, targetSession, loadSessions]);

  const handleToggleTerminalFullscreen = useCallback(() => {
    if (fullscreenTerminalSessionId != null) {
      setControlMessage('');
      setFullscreenTerminalSessionId(null);
      return;
    }

    const candidateSessionId = focusedSessionId ?? activeSession?.id ?? null;
    if (candidateSessionId == null) {
      setControlMessage('No session selected.');
      return;
    }

    setControlMessage('');
    setFullscreenTerminalSessionId(candidateSessionId);
    requestKeyboardCapture();

    if (focusedSessionId == null) {
      debugLog('[webgl] enter focus (fullscreen)', { sessionId: candidateSessionId });
      if (typeof document !== 'undefined') {
        document.activeElement?.blur?.();
      }
      setFocusedSessionId(candidateSessionId);
      requestKeyboardCapture();
    }
  }, [fullscreenTerminalSessionId, focusedSessionId, activeSession?.id, debugLog, requestKeyboardCapture]);

  const handleExitFocus = useCallback(() => {
    if (focusedSessionId == null && fullscreenTerminalSessionId == null) {
      return;
    }

    debugLog('[webgl] exit focus', { focusedSessionId });
    setFullscreenTerminalSessionId(null);
    setFocusedSessionId(null);
  }, [focusedSessionId, fullscreenTerminalSessionId, debugLog]);

  useTerminalKeyCapture({
    enabled: focusedSessionId != null,
    captureRef: keyCaptureRef,
    onCreate: handleCreateForActiveLayout,
    onExitFocus: handleExitFocus,
    onSplitVertical: handleSplitVertical,
    onSplitHorizontal: handleSplitHorizontal,
    onToggleFullscreen: handleToggleTerminalFullscreen,
    sendInput
  });

  useEffect(() => {
    const handleKeyDown = (event) => {
      if (isEditableTarget(event.target)) {
        return;
      }
      const isAltGraph = typeof event.getModifierState === 'function' && event.getModifierState('AltGraph');

      if (
        event.altKey
        && !event.ctrlKey
        && !event.shiftKey
        && !event.metaKey
        && !isAltGraph
        && event.key.toLowerCase() === 'n'
      ) {
        if (event.repeat) {
          return;
        }
        event.preventDefault();
        handleCreateForActiveLayout();
        return;
      }

      if (
        event.ctrlKey
        && event.shiftKey
        && !event.altKey
        && !event.metaKey
        && event.key === 'ArrowDown'
      ) {
        if (event.repeat) {
          return;
        }
        event.preventDefault();
        handleSplitHorizontal();
        return;
      }

      if (
        event.ctrlKey
        && event.shiftKey
        && !event.altKey
        && !event.metaKey
        && event.key === 'ArrowUp'
      ) {
        if (event.repeat) {
          return;
        }
        event.preventDefault();
        handleToggleTerminalFullscreen();
        return;
      }

      if (
        event.ctrlKey
        && event.shiftKey
        && !event.altKey
        && !event.metaKey
        && event.key === 'ArrowRight'
      ) {
        if (event.repeat) {
          return;
        }
        event.preventDefault();
        handleSplitVertical();
        return;
      }

      if (
        event.ctrlKey
        && !event.shiftKey
        && !event.altKey
        && !event.metaKey
        && event.key === 'ArrowDown'
      ) {
        if (event.repeat) {
          return;
        }
        event.preventDefault();
        handleExitFocus();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleCreateForActiveLayout, handleSplitVertical, handleSplitHorizontal, handleToggleTerminalFullscreen, handleExitFocus]);

  const handleSessionFocus = useCallback(session => {
    debugLog('[webgl] onSessionFocus', { sessionId: session?.id ?? null, focusLock: focusLockRef.current });
    if (focusLockRef.current) {
      return;
    }

    const index = sessions.findIndex(item => item.id === session.id);
    if (index >= 0) {
      setActiveIndex(index);
    }
    if (session.id != null) {
      debugLog('[webgl] focus set (pointer)', { sessionId: session.id, index });
      if (typeof document !== 'undefined') {
        document.activeElement?.blur?.();
      }
      setFocusedSessionId(session.id);
      requestKeyboardCapture();
      focusLockRef.current = true;
      setTimeout(() => {
        focusLockRef.current = false;
      }, 1000);
    }
  }, [sessions, debugLog, requestKeyboardCapture]);

  const handleSessionBlur = useCallback(session => {
    setFocusedSessionId(current => {
      debugLog('[webgl] onSessionBlur', { sessionId: session?.id ?? null, current });
      return current === session.id ? null : current;
    });
  }, [debugLog]);

  const handleSelect = useCallback(index => {
    setActiveIndex(index);
  }, []);

  const handleSelectSessionId = useCallback(sessionId => {
    const index = sessions.findIndex(session => session.id === sessionId);
    if (index >= 0) {
      setActiveIndex(index);
    }
  }, [sessions]);

  const handleShowCarouselLayout = useCallback(() => {
    setLayoutMode(LAYOUT_CAROUSEL);
    setControlMessage('');
  }, []);

  const handleShowSplitLayout = useCallback(() => {
    const fallbackSessionId = splitFallbackSessionId ?? activeSessionId ?? sessions[0]?.id ?? null;
    if (fallbackSessionId == null) {
      setControlMessage('Create a session before switching to split layout.');
      return;
    }
    setSplitRoot(previous => ensureSplitRoot(previous, fallbackSessionId));
    setLayoutMode(LAYOUT_SPLIT);
    setControlMessage('');
  }, [splitFallbackSessionId, activeSessionId, sessions]);

  const controlDimsLabel = targetSessionId != null ? `${controlDimensions.cols}×${controlDimensions.rows}` : '—';
  const isSplitLayout = layoutMode === LAYOUT_SPLIT;

  return (
    <div className="webgl-page">
      <Canvas
        shadows
        camera={{ position: [CAMERA_BASE_POSITION.x, CAMERA_BASE_POSITION.y, CAMERA_BASE_POSITION.z], fov: 62, near: 0.1, far: 50 }}
        dpr={[1, 1.5]}
      >
        <color attach="background" args={[0.02, 0.04, 0.1]} />
        <FocusCamera focusTarget={focusTarget} />
        {isSplitLayout ? (
          <SessionSplitLayout
            sessions={sessions}
            splitRoot={effectiveSplitRoot}
            activeSessionId={targetSessionId}
            onSessionFocus={handleSessionFocus}
            onSessionBlur={handleSessionBlur}
            onSelectSession={handleSelectSessionId}
            focusedSessionId={focusedSessionId}
            manualResizeSessions={manualResizeSessions}
            debugWebgl={debugWebgl}
            scanlinesEnabled={scanlinesEnabled}
            sceneHidden={isTerminalFullscreen}
            onCreate={handleCreateForActiveLayout}
            onKill={handleKill}
            creating={creating}
            killing={killing}
            errorMessage={error}
            onFocusedTransform={handleFocusedTransformUpdate}
            onTerminalTexture={handleTerminalTexture}
          />
        ) : (
          <SessionCarousel
            sessions={sessions}
            activeIndex={Math.min(activeIndex, Math.max(sessions.length - 1, 0))}
            onSessionFocus={handleSessionFocus}
            onSessionBlur={handleSessionBlur}
            onSelect={handleSelect}
            focusedSessionId={focusedSessionId}
            manualResizeSessions={manualResizeSessions}
            debugWebgl={debugWebgl}
            scanlinesEnabled={scanlinesEnabled}
            sceneHidden={isTerminalFullscreen}
            onCreate={handleCreate}
            onKill={handleKill}
            creating={creating}
            killing={killing}
            errorMessage={error}
            onFocusedTransform={handleFocusedTransformUpdate}
            onTerminalTexture={handleTerminalTexture}
          />
        )}
        <FullscreenTerminalOverlay
          enabled={isTerminalFullscreen}
          texture={fullscreenTerminalTexture}
          onFocusInput={requestKeyboardCapture}
        />
      </Canvas>

      <textarea
        ref={keyCaptureRef}
        className="webgl-key-capture"
        aria-label="Terminal keyboard input capture"
        autoCapitalize="none"
        autoComplete="off"
        autoCorrect="off"
        spellCheck={false}
        tabIndex={-1}
      />

      <div className="webgl-overlay">
        <div
          className={`webgl-controls${controlsCollapsed ? ' collapsed' : ''}`}
          role="region"
          aria-label="Terminal controls"
        >
          <div className="webgl-controls-header">
            <div className="webgl-controls-title">Terminal controls</div>
            <button
              type="button"
              className="webgl-controls-toggle secondary"
              aria-expanded={!controlsCollapsed}
              aria-label={controlsCollapsed ? 'Show terminal controls' : 'Hide terminal controls'}
              onClick={() => setControlsCollapsed(current => !current)}
            >
              {controlsCollapsed ? '▸' : '▾'}
            </button>
          </div>

          <div className="webgl-controls-body">
            <div className="webgl-controls-meta">
              <span>{targetSessionLabel} session:</span>
              <strong>{targetSessionId != null ? `#${targetSessionId}` : '—'}</strong>
              <span className="webgl-controls-dims">{controlDimsLabel}</span>
            </div>

            <form
              className="webgl-controls-form"
              onSubmit={(event) => {
                event.preventDefault();
                handleApplyResize();
              }}
            >
              <label>
                Cols×Rows
                <input
                  inputMode="numeric"
                  autoComplete="off"
                  value={resizeSpec}
                  placeholder="120x40"
                  onChange={(event) => {
                    setResizeSpec(event.target.value);
                    setResizeDirty(true);
                  }}
                  disabled={targetSessionId == null}
                  aria-label="Terminal size in columns by rows"
                />
              </label>
              <div className="webgl-controls-actions">
                <button type="submit" disabled={targetSessionId == null}>
                  Resize
                </button>
                <button
                  type="button"
                  onClick={handleAutoFit}
                  disabled={targetSessionId == null || !manualResizeLocked}
                  className="secondary"
                >
                  Auto fit
                </button>
              </div>
            </form>

            <div className="webgl-controls-actions">
              <button type="button" onClick={handleResetTerminal} disabled={targetSessionId == null}>
                Reset
              </button>
              <button
                type="button"
                className="danger"
                onClick={handleKill}
                disabled={killing || !targetSession?.id}
              >
                Kill
              </button>
            </div>

            <div className="webgl-controls-actions">
              <button
                type="button"
                className="secondary"
                aria-pressed={scanlinesEnabled}
                onClick={() => setScanlinesEnabled(current => !current)}
                title="Toggle the terminal scanline shader"
              >
                Scanlines: {scanlinesEnabled ? 'On' : 'Off'}
              </button>
            </div>

            <div className="webgl-controls-actions">
              <button
                type="button"
                className="secondary"
                aria-pressed={layoutMode === LAYOUT_CAROUSEL}
                onClick={handleShowCarouselLayout}
              >
                Carousel
              </button>
              <button
                type="button"
                className="secondary"
                aria-pressed={layoutMode === LAYOUT_SPLIT}
                onClick={handleShowSplitLayout}
                disabled={!sessions.length}
              >
                Split
              </button>
            </div>

	            <div className="webgl-controls-actions">
	              <button
	                type="button"
	                className="secondary"
	                aria-pressed={isTerminalFullscreen}
	                onMouseDown={(event) => {
	                  event.preventDefault();
	                }}
	                onClick={handleToggleTerminalFullscreen}
	                disabled={targetSessionId == null && !isTerminalFullscreen}
	                title="Toggle fullscreen terminal view (Ctrl+Shift+↑)"
	              >
	                {isTerminalFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
	              </button>
            </div>

            {controlMessage ? (
              <div className="webgl-controls-message" role="status">
                {controlMessage}
              </div>
            ) : null}

            <div className="webgl-controls-actions">
              <button
                type="button"
                className="secondary"
                aria-expanded={shortcutsOpen}
                onClick={() => setShortcutsOpen((current) => !current)}
              >
                Keyboard Shortcuts
              </button>
            </div>
            {shortcutsOpen && (
              <div className="shortcut-list shortcut-list--webgl">
                <div className="shortcut-row">
                  <span className="webgl-controls-shortcut">Alt+N</span>
                  <span>Create a new terminal session.</span>
                </div>
                <div className="shortcut-row">
                  <span className="webgl-controls-shortcut">Ctrl+Shift+→</span>
                  <span>Split the active pane vertically.</span>
                </div>
                <div className="shortcut-row">
                  <span className="webgl-controls-shortcut">Ctrl+Shift+↑</span>
                  <span>Toggle terminal fullscreen view.</span>
                </div>
                <div className="shortcut-row">
                  <span className="webgl-controls-shortcut">Ctrl+Shift+↓</span>
                  <span>Split the active pane horizontally.</span>
                </div>
                <div className="shortcut-row">
                  <span className="webgl-controls-shortcut">Ctrl+↓</span>
                  <span>Exit focus/zoomed view (legacy).</span>
                </div>
              </div>
            )}

            <div className="webgl-controls-connection">
              <span className={`status status-${controlStatus}`}>{controlStatus}</span>
              {controlStatusNote ? <span className="status-note">{controlStatusNote}</span> : null}
            </div>
          </div>
        </div>
      </div>
      <SpawnTerminalDialog {...spawnDialogProps} />
    </div>
  );
}
