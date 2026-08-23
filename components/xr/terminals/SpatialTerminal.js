import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Color, CanvasTexture, LinearFilter, SRGBColorSpace } from 'three';
import { RoundedBox, Text, shaderMaterial } from '@react-three/drei';
import { extend, useFrame, useThree } from '@react-three/fiber';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { WebglAddon } from '@xterm/addon-webgl';
import useXRTerminal from '../../../hooks/useXRTerminal.js';
import { shouldDeferCanvasReadback, waitForCanvasReadbackInput } from '../../../lib/canvasReadbackGate.js';
import useSpatialStore from '../../../lib/stores/spatialStore.js';

const RimGlowMaterial = shaderMaterial(
  {
    color: new Color('#4f9bff'),
    intensity: 1,
    thickness: 1.4
  },
  `varying vec3 vNormal;
   varying vec3 vWorldPosition;
   void main() {
     vNormal = normalize(normalMatrix * normal);
     vec4 worldPosition = modelMatrix * vec4(position, 1.0);
     vWorldPosition = worldPosition.xyz;
     gl_Position = projectionMatrix * viewMatrix * worldPosition;
   }`,
  `uniform vec3 color;
   uniform float intensity;
   uniform float thickness;
   varying vec3 vNormal;
   varying vec3 vWorldPosition;
   void main() {
     vec3 viewDir = normalize(cameraPosition - vWorldPosition);
     float rim = pow(1.0 - max(dot(vNormal, viewDir), 0.0), thickness);
     vec3 finalColor = color * rim * intensity;
     gl_FragColor = vec4(finalColor, rim * intensity);
   }`
);

const HolographicTerminalMaterial = shaderMaterial(
  {
    map: null,
    time: 0,
    color: new Color('#4ff3ff'),
    blendStrength: 0.4
  },
  `varying vec2 vUv;
   void main() {
     vUv = uv;
     gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
   }`,
  `uniform sampler2D map;
   uniform float time;
   uniform vec3 color;
   uniform float blendStrength;
   varying vec2 vUv;
   float hash(vec2 p) {
     return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453);
   }
   void main() {
     vec4 base = texture2D(map, vUv);
     float scan = sin((vUv.y + time * 0.12) * 140.0) * 0.08 + 0.92;
     float noise = hash(vUv * time * 60.0);
     vec3 holo = mix(base.rgb, color, blendStrength * 0.55 + noise * 0.08);
     float alpha = base.a * (0.88 + noise * 0.12);
     gl_FragColor = vec4(holo * scan, alpha);
   }`
);

extend({ RimGlowMaterial, HolographicTerminalMaterial });

const MAX_BUFFER_LENGTH = 200000;
const HANDLE_DIRECTIONS = [
  [1, 1],
  [-1, 1],
  [-1, -1],
  [1, -1]
];

function createRenderer(mode, options = {}) {
  if (mode === 'performance') {
    return new PerformanceRenderer();
  }
  return new XtermTextureRenderer({
    enableWebgl: true,
    onDimensions: options.onDimensions,
    maxTextureSize: options.maxTextureSize
  });
}

function useTerminalRenderer(mode, options = {}) {
  const rendererRef = useRef(null);
  const pendingPixelSizeRef = useRef(null);
  const pendingDimensionsRef = useRef(null);
  const cursorActiveRef = useRef(false);
  const [texture, setTexture] = useState(null);
  const [canvasReadbackReady, setCanvasReadbackReady] = useState(() => (
    typeof window !== 'undefined' && !shouldDeferCanvasReadback(window)
  ));

  useEffect(() => {
    if (typeof window === 'undefined') {
      return undefined;
    }

    if (mode === 'performance' || !shouldDeferCanvasReadback(window)) {
      setCanvasReadbackReady(true);
      return undefined;
    }

    setCanvasReadbackReady(false);
    return waitForCanvasReadbackInput(() => {
      setCanvasReadbackReady(true);
    }, window);
  }, [mode]);

  useEffect(() => {
    if (
      typeof window === 'undefined' ||
      !canvasReadbackReady ||
      (mode !== 'performance' && shouldDeferCanvasReadback(window))
    ) {
      setTexture(null);
      return () => {};
    }

    const renderer = createRenderer(mode, options);
    rendererRef.current = renderer;
    renderer.setCursorActive?.(cursorActiveRef.current);

    if (pendingPixelSizeRef.current) {
      renderer.setPixelSize(...pendingPixelSizeRef.current);
    }
    if (pendingDimensionsRef.current) {
      renderer.setDimensions(pendingDimensionsRef.current.cols, pendingDimensionsRef.current.rows);
    }

    setTexture(renderer.getTexture());

    return () => {
      renderer.dispose();
      rendererRef.current = null;
      setTexture(null);
    };
  }, [mode, canvasReadbackReady]);

  const write = useCallback((chunk) => {
    rendererRef.current?.write(chunk);
  }, []);

  const refresh = useCallback((snapshot) => {
    rendererRef.current?.refresh(snapshot);
  }, []);

  const setPixelSize = useCallback((width, height) => {
    pendingPixelSizeRef.current = [width, height];
    rendererRef.current?.setPixelSize(width, height);
  }, []);

  const setDimensions = useCallback((cols, rows) => {
    pendingDimensionsRef.current = { cols, rows };
    rendererRef.current?.setDimensions(cols, rows);
  }, []);

  const setCursorActive = useCallback((active) => {
    cursorActiveRef.current = Boolean(active);
    rendererRef.current?.setCursorActive?.(cursorActiveRef.current);
  }, []);

  return {
    texture,
    write,
    refresh,
    setPixelSize,
    setDimensions,
    setCursorActive,
    canvasReadbackReady
  };
}

class XtermTextureRenderer {
  constructor({ enableWebgl, onDimensions, maxTextureSize }) {
    this.enableWebgl = enableWebgl;
    this.onDimensions = typeof onDimensions === 'function' ? onDimensions : null;
    this.maxTextureSize = Number.isFinite(maxTextureSize) ? Math.floor(maxTextureSize) : null;
    this.container = null;
    this.terminal = null;
    this.fitAddon = null;
    this.webglAddon = null;
    this.texture = null;
    this.canvas = null;
    this.textureCanvas = null;
    this.mirrorCanvas = null;
    this.mirrorCtx = null;
    this.webglCanvasContext = null;
    this.webglCanvasContextCanvas = null;
    this.detectedWebglMaxSize = null;
    this.lastMirrorSize = { width: 0, height: 0 };
    this.resizeDisposable = null;
    this.renderDisposable = null;
    this.updateHandle = null;
    this.pendingPixelSize = null;
    this.pendingDimensions = null;
    this.ready = false;
    this.init();
  }

  init() {
    if (typeof window === 'undefined') {
      return;
    }

    this.container = document.createElement('div');
    this.container.className = 'xr-terminal-offscreen';
    Object.assign(this.container.style, {
      position: 'fixed',
      top: '0',
      left: '0',
      width: '1024px',
      height: '640px',
      opacity: '0',
      pointerEvents: 'none',
      overflow: 'hidden',
      zIndex: '-1'
    });
    document.body.appendChild(this.container);

    const terminal = new Terminal({
      cursorBlink: true,
      cursorInactiveStyle: 'outline',
      fontFamily: 'JetBrains Mono, Fira Code, Consolas, Monaco, monospace',
      fontSize: 15,
      theme: {
        background: '#05070f',
        foreground: '#c5c8c6',
        cursor: '#c5c8c6',
        black: '#1d1f21',
        red: '#cc6666',
        green: '#b5bd68',
        yellow: '#f0c674',
        blue: '#81a2be',
        magenta: '#b294bb',
        cyan: '#8abeb7',
        white: '#c5c8c6',
        brightBlack: '#969896',
        brightRed: '#cc6666',
        brightGreen: '#b5bd68',
        brightYellow: '#f0c674',
        brightBlue: '#81a2be',
        brightMagenta: '#b294bb',
        brightCyan: '#8abeb7',
        brightWhite: '#ffffff'
      },
      scrollback: 2000,
      allowTransparency: true,
      convertEol: false
    });

    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();
    terminal.loadAddon(fitAddon);
    terminal.loadAddon(webLinksAddon);

    if (this.enableWebgl) {
      try {
        const webglAddon = new WebglAddon(true);
        webglAddon.onContextLoss(() => {
          webglAddon.dispose();
        });
        terminal.loadAddon(webglAddon);
        this.webglAddon = webglAddon;
      } catch (err) {
        console.warn('[SpatialTerminal] WebGL addon unavailable:', err.message);
      }
    }

    terminal.open(this.container);
    if (typeof terminal.onResize === 'function') {
      this.resizeDisposable = terminal.onResize(({ cols, rows }) => {
        this.emitDimensions(cols, rows);
      });
    }
    if (typeof terminal.onRender === 'function') {
      this.renderDisposable = terminal.onRender(() => {
        this.scheduleUpdate();
      });
    }
    this.terminal = terminal;
    this.fitAddon = fitAddon;
    this.fitAddon.fit();
    this.captureTexture();
    this.emitDimensions();
    this.ready = true;

    if (this.pendingPixelSize) {
      this.setPixelSize(...this.pendingPixelSize);
      this.pendingPixelSize = null;
    }

    if (this.pendingDimensions) {
      this.setDimensions(this.pendingDimensions.cols, this.pendingDimensions.rows);
      this.pendingDimensions = null;
    }
  }

  resolveTerminalCanvas() {
    if (!this.container) {
      return null;
    }

    const canvases = Array.from(this.container.querySelectorAll('canvas'));
    if (!canvases.length) {
      return null;
    }

    if (!this.enableWebgl) {
      return canvases[0];
    }

    const nonLayerCanvas = canvases.find((canvas) => {
      const classes = Array.from(canvas.classList ?? []);
      return !classes.some((name) => name.startsWith('xterm-') && name.endsWith('-layer'));
    });

    return nonLayerCanvas || canvases[canvases.length - 1];
  }

  resolveWebglContext(canvas) {
    if (!canvas || typeof canvas.getContext !== 'function') {
      return null;
    }

    if (this.webglCanvasContextCanvas === canvas) {
      return this.webglCanvasContext;
    }

    let context = null;
    try {
      context =
        canvas.getContext('webgl2', { preserveDrawingBuffer: true }) ||
        canvas.getContext('webgl', { preserveDrawingBuffer: true }) ||
        canvas.getContext('experimental-webgl', { preserveDrawingBuffer: true });
    } catch {
      context = null;
    }

    this.webglCanvasContext = context;
    this.webglCanvasContextCanvas = canvas;
    return context;
  }

  getMaxWebglSize(canvas) {
    if (Number.isFinite(this.maxTextureSize) && this.maxTextureSize > 0) {
      return this.maxTextureSize;
    }

    if (Number.isFinite(this.detectedWebglMaxSize) && this.detectedWebglMaxSize > 0) {
      return this.detectedWebglMaxSize;
    }

    const gl = this.resolveWebglContext(canvas);
    if (!gl || typeof gl.getParameter !== 'function') {
      return null;
    }

    let maxTexture = null;
    let maxRenderbuffer = null;
    try {
      maxTexture = gl.getParameter(gl.MAX_TEXTURE_SIZE);
      maxRenderbuffer = gl.getParameter(gl.MAX_RENDERBUFFER_SIZE);
    } catch {
      maxTexture = null;
      maxRenderbuffer = null;
    }

    const candidates = [maxTexture, maxRenderbuffer].filter((value) => Number.isFinite(value) && value > 0);
    if (!candidates.length) {
      return null;
    }

    const resolved = Math.floor(Math.min(...candidates));
    this.detectedWebglMaxSize = resolved;
    return resolved;
  }

  getCanvasSourceSize(canvas) {
    const fallback = getCanvasDimensions(canvas);
    const gl = this.resolveWebglContext(canvas);
    if (!gl || typeof gl.drawingBufferWidth !== 'number' || typeof gl.drawingBufferHeight !== 'number') {
      return fallback;
    }

    const width = Math.floor(gl.drawingBufferWidth) || fallback.width;
    const height = Math.floor(gl.drawingBufferHeight) || fallback.height;
    return { width, height };
  }

  clampToMaxSize(width, height, maxSize) {
    const safeWidth = Math.max(1, Math.floor(width));
    const safeHeight = Math.max(1, Math.floor(height));
    if (!Number.isFinite(maxSize) || maxSize <= 0) {
      return { width: safeWidth, height: safeHeight };
    }

    const limit = Math.floor(maxSize);
    if (safeWidth <= limit && safeHeight <= limit) {
      return { width: safeWidth, height: safeHeight };
    }

    const scale = Math.min(limit / safeWidth, limit / safeHeight);
    return {
      width: Math.max(1, Math.floor(safeWidth * scale)),
      height: Math.max(1, Math.floor(safeHeight * scale))
    };
  }

  captureTexture() {
    if (!this.container) {
      return;
    }

    const canvas = this.resolveTerminalCanvas();
    if (!canvas) {
      return;
    }
    this.canvas = canvas;

    if (this.enableWebgl) {
      this.ensureMirrorCanvas(canvas);
    }

    const targetCanvas = this.enableWebgl && this.mirrorCanvas ? this.mirrorCanvas : canvas;

    if (!this.texture) {
      this.texture = new CanvasTexture(targetCanvas);
      this.texture.colorSpace = SRGBColorSpace;
      this.texture.minFilter = LinearFilter;
      this.texture.magFilter = LinearFilter;
    } else if (this.texture.image !== targetCanvas) {
      this.texture.dispose();
      this.texture.image = targetCanvas;
      this.texture.needsUpdate = true;
    }

    this.textureCanvas = targetCanvas;
    this.texture.needsUpdate = true;
    this.scheduleUpdate();
  }

  ensureMirrorCanvas(sourceCanvas) {
    if (!this.enableWebgl || typeof document === 'undefined') {
      return;
    }

    if (!this.mirrorCanvas) {
      const nextCanvas = document.createElement('canvas');
      nextCanvas.width = 1;
      nextCanvas.height = 1;
      const nextCtx = nextCanvas.getContext('2d');
      if (!nextCtx) {
        return;
      }
      this.mirrorCanvas = nextCanvas;
      this.mirrorCtx = nextCtx;
      if (this.texture && this.texture.image !== nextCanvas) {
        this.texture.image = nextCanvas;
        this.texture.needsUpdate = true;
      }
      return;
    }

    const { width: sourceWidth, height: sourceHeight } = this.getCanvasSourceSize(sourceCanvas);
    if (!sourceWidth || !sourceHeight) {
      return;
    }

    const maxSize = this.getMaxWebglSize(sourceCanvas);
    const { width, height } = this.clampToMaxSize(sourceWidth, sourceHeight, maxSize);

    if (this.mirrorCanvas.width !== width || this.mirrorCanvas.height !== height) {
      const nextCanvas = document.createElement('canvas');
      nextCanvas.width = width;
      nextCanvas.height = height;
      const nextCtx = nextCanvas.getContext('2d');
      if (!nextCtx) {
        return;
      }
      this.mirrorCanvas = nextCanvas;
      this.mirrorCtx = nextCtx;
      if (this.texture && this.texture.image !== nextCanvas) {
        this.texture.dispose();
        this.texture.image = nextCanvas;
        this.texture.needsUpdate = true;
      }
      this.lastMirrorSize = { width, height };
    }
  }

  copyWebglToMirror() {
    if (!this.enableWebgl || !this.canvas) {
      return;
    }

    this.ensureMirrorCanvas(this.canvas);

    if (!this.mirrorCanvas || !this.mirrorCtx) {
      return;
    }

    const { width: sourceWidth, height: sourceHeight } = this.getCanvasSourceSize(this.canvas);
    const targetWidth = Number(this.mirrorCanvas.width) || 0;
    const targetHeight = Number(this.mirrorCanvas.height) || 0;
    if (!sourceWidth || !sourceHeight || !targetWidth || !targetHeight) {
      return;
    }

    this.mirrorCtx.setTransform(1, 0, 0, 1, 0, 0);
    this.mirrorCtx.clearRect(0, 0, targetWidth, targetHeight);
    try {
      this.mirrorCtx.drawImage(this.canvas, 0, 0, sourceWidth, sourceHeight, 0, 0, targetWidth, targetHeight);
    } catch (err) {
      // Ignore transient drawImage failures (e.g. context loss); next frame will retry.
    }
  }

  scheduleUpdate() {
    if (this.updateHandle) {
      return;
    }
    this.updateHandle = requestAnimationFrame(() => {
      this.updateHandle = null;
      if (this.enableWebgl) {
        this.copyWebglToMirror();
      }
      if (this.texture) {
        this.texture.needsUpdate = true;
      }
    });
  }

  setPixelSize(width, height) {
    if (!this.ready) {
      this.pendingPixelSize = [width, height];
      return;
    }

    const requestedWidth = Math.max(128, Math.floor(width));
    const requestedHeight = Math.max(96, Math.floor(height));

    const dpr = typeof window !== 'undefined' ? window.devicePixelRatio || 1 : 1;
    const maxSize = this.getMaxWebglSize(this.canvas);
    const maxCss = Number.isFinite(maxSize) && maxSize > 0 ? Math.floor((maxSize - 2) / dpr) : null;
    const clampScale = maxCss
      ? Math.min(1, maxCss / requestedWidth, maxCss / requestedHeight)
      : 1;
    const safeWidth = Math.max(128, Math.floor(requestedWidth * clampScale));
    const safeHeight = Math.max(96, Math.floor(requestedHeight * clampScale));

    if (this.container) {
      this.container.style.width = `${safeWidth}px`;
      this.container.style.height = `${safeHeight}px`;
    }
    this.fitAddon?.fit();
    this.emitDimensions();
    this.captureTexture();
    this.scheduleUpdate();
  }

  setDimensions(cols, rows) {
    if (!Number.isFinite(cols) || !Number.isFinite(rows)) {
      return;
    }

    if (!this.ready) {
      this.pendingDimensions = { cols, rows };
      return;
    }

    this.terminal?.resize(cols, rows);
    this.emitDimensions(cols, rows);
    this.scheduleUpdate();
  }

  setCursorActive(active) {
    if (!this.terminal) {
      return;
    }
    this.terminal.options.cursorInactiveStyle = active ? 'block' : 'outline';
    this.terminal.refresh(this.terminal.buffer.active.cursorY, this.terminal.buffer.active.cursorY);
    this.scheduleUpdate();
  }

  write(chunk) {
    if (!chunk || !this.ready) {
      return;
    }
    this.terminal?.write(chunk);
    this.scheduleUpdate();
  }

  refresh(snapshot) {
    if (!this.ready) {
      return;
    }
    this.terminal?.reset();
    if (snapshot) {
      this.terminal?.write(snapshot);
    }
    this.scheduleUpdate();
  }

  getTexture() {
    return this.texture;
  }

  dispose() {
    if (this.updateHandle) {
      cancelAnimationFrame(this.updateHandle);
      this.updateHandle = null;
    }

    const terminal = this.terminal;
    const container = this.container;
    this.terminal = null;

    const disposeTerminal = () => {
      terminal?.dispose();
      if (container && container.parentNode) {
        container.parentNode.removeChild(container);
      }
    };

    if (terminal && typeof window !== 'undefined') {
      setTimeout(() => disposeTerminal(), 0);
    } else {
      disposeTerminal();
    }

    if (this.texture) {
      this.texture.dispose();
      this.texture = null;
    }

    this.textureCanvas = null;
    this.mirrorCanvas = null;
    this.mirrorCtx = null;

    if (this.resizeDisposable) {
      this.resizeDisposable.dispose?.();
      this.resizeDisposable = null;
    }

    if (this.renderDisposable) {
      this.renderDisposable.dispose?.();
      this.renderDisposable = null;
    }

    this.container = null;
    this.fitAddon = null;
    this.webglAddon = null;
    this.canvas = null;
  }

  emitDimensions(cols = this.terminal?.cols, rows = this.terminal?.rows) {
    if (!this.onDimensions) {
      return;
    }
    const nextCols = Number.isFinite(cols) ? cols : undefined;
    const nextRows = Number.isFinite(rows) ? rows : undefined;
    if (nextCols == null || nextRows == null) {
      return;
    }
    this.onDimensions({ cols: nextCols, rows: nextRows });
  }
}

class PerformanceRenderer {
  constructor() {
    if (typeof document === 'undefined') {
      this.canvas = null;
      this.ctx = null;
      this.texture = null;
      return;
    }

    this.canvas = document.createElement('canvas');
    this.ctx = this.canvas.getContext('2d');
    this.texture = new CanvasTexture(this.canvas);
    this.texture.colorSpace = SRGBColorSpace;
    this.texture.minFilter = LinearFilter;
    this.texture.magFilter = LinearFilter;
    this.buffer = '';
    this.cols = 80;
    this.rows = 24;
    this.cursorActive = false;
  }

  setPixelSize(width, height) {
    if (!this.canvas || !this.ctx) {
      return;
    }

    const safeWidth = Math.max(128, Math.floor(width));
    const safeHeight = Math.max(96, Math.floor(height));
    this.canvas.width = safeWidth;
    this.canvas.height = safeHeight;
    this.render();
  }

  setDimensions(cols, rows) {
    if (Number.isFinite(cols)) {
      this.cols = cols;
    }
    if (Number.isFinite(rows)) {
      this.rows = rows;
    }
    this.render();
  }

  write(chunk) {
    if (!chunk) {
      return;
    }
    this.buffer = trimBuffer(this.buffer + chunk);
    this.render();
  }

  refresh(snapshot) {
    this.buffer = snapshot ?? '';
    this.render();
  }

  setCursorActive(active) {
    this.cursorActive = Boolean(active);
    this.render();
  }

  render() {
    if (!this.ctx || !this.canvas) {
      return;
    }

    const ctx = this.ctx;
    ctx.fillStyle = '#05070f';
    ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);

    const lines = extractVisibleLines(this.buffer, this.rows);
    const fontSize = Math.max(12, this.canvas.height / (this.rows + 3));
    const lineHeight = fontSize * 1.2;

    ctx.font = `${fontSize}px 'JetBrains Mono', 'Fira Code', monospace`;
    ctx.textBaseline = 'top';
    ctx.fillStyle = '#c5c8c6';

    const startY = Math.max(6, this.canvas.height - lineHeight * lines.length - 8);
    lines.forEach((line, index) => {
      ctx.fillText(line, 8, startY + index * lineHeight);
    });

    if (this.cursorActive) {
      const line = lines[lines.length - 1] ?? '';
      const cursorX = Math.min(this.canvas.width - 12, 8 + ctx.measureText(line).width);
      const cursorY = startY + Math.max(0, lines.length - 1) * lineHeight;
      ctx.fillStyle = '#c5c8c6';
      ctx.fillRect(cursorX, cursorY + 2, Math.max(8, fontSize * 0.55), Math.max(12, lineHeight - 4));
    }

    if (this.texture) {
      this.texture.needsUpdate = true;
    }
  }

  getTexture() {
    return this.texture;
  }

  dispose() {
    if (this.texture) {
      this.texture.dispose();
      this.texture = null;
    }
    this.ctx = null;
    this.canvas = null;
  }
}

function getCanvasDimensions(canvas) {
  if (!canvas) {
    return { width: 0, height: 0 };
  }
  const width = Number(canvas.width) || canvas.clientWidth || canvas.offsetWidth || 0;
  const height = Number(canvas.height) || canvas.clientHeight || canvas.offsetHeight || 0;
  return { width, height };
}

function trimBuffer(buffer) {
  if (buffer.length <= MAX_BUFFER_LENGTH) {
    return buffer;
  }
  return buffer.slice(buffer.length - MAX_BUFFER_LENGTH);
}

const ANSI_SEQUENCE_REGEX = /\u001b\[[0-9;]*[A-Za-z]/g;
const OSC_SEQUENCE_REGEX = /\u001b\].*?\u0007/g;
const OSC_TITLE_REGEX = /\u001b\](?:0|2);([^\u0007\u001b]*)(?:\u0007|\u001b\\)/g;
const OSC_TITLE_SEARCH_WINDOW = 512;

function stripAnsi(input = '') {
  return input.replace(OSC_SEQUENCE_REGEX, '').replace(ANSI_SEQUENCE_REGEX, '');
}

function extractVisibleLines(buffer, maxRows) {
  const normalized = stripAnsi(buffer).replace(/\r(?!\n)/g, '');
  const rawLines = normalized.split(/\r?\n/);
  return rawLines.slice(-maxRows);
}

const DEFAULT_SIZE = [1.2, 0.75];

export default function SpatialTerminal({
  sessionId,
  title = `Session ${sessionId}`,
  terminalId = sessionId,
  size = DEFAULT_SIZE,
  position,
  rotation,
  scale,
  quality = 'auto',
  resizeMode = 'push',
  matchTextureAspect = false,
  showStatusLine = true,
  holographic = false,
  inputActive = false,
  onFocus,
  onBlur,
  onActivate,
  onResize,
  onTexture
}) {
  const planeRef = useRef(null);
  const holographicRef = useRef(null);
  const glowRef = useRef(null);
  const draggingRef = useRef(null);
  const outputBufferRef = useRef('');
  const measuredDimensionsHandlerRef = useRef(null);
  const pendingMeasuredDimensionsRef = useRef(null);
  const lastSentResizeRef = useRef({ cols: 80, rows: 24 });
  const lastRequestedPixelSizeRef = useRef({ width: 0, height: 0 });
  const cellSizeEstimateRef = useRef({ width: 8, height: 16 });
  const [surfaceSize, setSurfaceSize] = useState(size);
  const [hovered, setHovered] = useState(false);
  const [deviceTier, setDeviceTier] = useState('mid');
  const [qualityPreference, setQualityPreference] = useState(quality ?? 'auto');
  const [qualityMode, setQualityMode] = useState(quality === 'auto' ? 'high' : quality);
  const [oscTitle, setOscTitle] = useState('');
  const [remoteDimensions, setRemoteDimensions] = useState({ cols: 80, rows: 24 });

  const resolvedPosition = useMemo(() => position ?? [0, 1.4, -1.6], [position]);
  const resolvedRotation = useMemo(() => rotation ?? [0, 0, 0], [rotation]);
  const resolvedScale = useMemo(() => scale ?? [1, 1, 1], [scale]);

  useEffect(() => {
    setSurfaceSize((currentSize) => {
      const nextWidth = Array.isArray(size) && Number.isFinite(size[0]) ? size[0] : DEFAULT_SIZE[0];
      const nextHeight = Array.isArray(size) && Number.isFinite(size[1]) ? size[1] : DEFAULT_SIZE[1];
      const nextSize = [nextWidth, nextHeight];
      if (
        Array.isArray(currentSize) &&
        currentSize.length === 2 &&
        currentSize[0] === nextWidth &&
        currentSize[1] === nextHeight
      ) {
        return currentSize;
      }
      return nextSize;
    });
  }, [Array.isArray(size) ? size[0] : undefined, Array.isArray(size) ? size[1] : undefined]);

  useEffect(() => {
    setQualityPreference(quality ?? 'auto');
    if (quality !== 'auto') {
      setQualityMode(quality);
    }
  }, [quality]);

  useEffect(() => {
    lastSentResizeRef.current = { cols: 0, rows: 0 };
  }, [sessionId]);

  useEffect(() => {
    setOscTitle('');
  }, [sessionId, title]);

  useEffect(() => {
    if (typeof navigator === 'undefined') {
      return;
    }

    const cores = navigator.hardwareConcurrency ?? 4;
    if (cores >= 8) {
      setDeviceTier('high');
    } else if (cores >= 4) {
      setDeviceTier('mid');
    } else {
      setDeviceTier('low');
    }
  }, []);

  const relayMeasuredDimensions = useCallback((payload) => {
    if (measuredDimensionsHandlerRef.current) {
      measuredDimensionsHandlerRef.current(payload);
      return;
    }
    pendingMeasuredDimensionsRef.current = payload;
  }, []);

  const threeRenderer = useThree((state) => state.gl);
  const maxTextureSize = useMemo(() => {
    const ctx = threeRenderer?.getContext?.();
    if (!ctx || typeof ctx.getParameter !== 'function') {
      return undefined;
    }
    try {
      const maxTexture = ctx.getParameter(ctx.MAX_TEXTURE_SIZE);
      const maxRenderbuffer = ctx.getParameter(ctx.MAX_RENDERBUFFER_SIZE);
      const candidates = [maxTexture, maxRenderbuffer].filter((value) => Number.isFinite(value) && value > 0);
      return candidates.length ? Math.floor(Math.min(...candidates)) : undefined;
    } catch {
      return undefined;
    }
  }, [threeRenderer]);

  const rendererOptions = useMemo(() => ({
    onDimensions: relayMeasuredDimensions,
    maxTextureSize
  }), [relayMeasuredDimensions, maxTextureSize]);

  const {
    texture,
    write,
    refresh,
    setPixelSize,
    setDimensions: setRendererDimensions,
    setCursorActive,
    canvasReadbackReady
  } = useTerminalRenderer(qualityMode, rendererOptions);
  const textureHandlerRef = useRef(onTexture);

  useEffect(() => {
    textureHandlerRef.current = onTexture;
  }, [onTexture]);

  useEffect(() => {
    if (typeof onTexture === 'function') {
      onTexture(texture);
    }
  }, [texture, onTexture]);

  useEffect(() => {
    setCursorActive(inputActive);
  }, [inputActive, setCursorActive]);

  useEffect(() => () => {
    const handler = textureHandlerRef.current;
    if (typeof handler === 'function') {
      handler(null);
    }
  }, []);

  const fpsSamplesRef = useRef([]);
  const fpsAverageRef = useRef(60);
  const lastAspectCorrectionAtRef = useRef(0);
  const lastActivateClickAtRef = useRef(0);

  useFrame((_, delta) => {
    const fps = 1 / Math.max(delta, 1e-6);
    const samples = fpsSamplesRef.current;
    samples.push(fps);
    if (samples.length > 90) {
      samples.shift();
    }
    const total = samples.reduce((acc, value) => acc + value, 0);
    fpsAverageRef.current = samples.length ? total / samples.length : fps;

    if (holographicRef.current) {
      holographicRef.current.time += delta;
    }

    if (glowRef.current) {
      glowRef.current.intensity = hovered ? 1.4 : 1.0;
    }

    if (matchTextureAspect && texture?.image) {
      const { width, height } = getCanvasDimensions(texture.image);
      if (width > 0 && height > 0) {
        const now = Date.now();
        if (now - lastAspectCorrectionAtRef.current > 250 && !draggingRef.current) {
          const [surfaceWidth, surfaceHeight] = surfaceSize;
          if (surfaceWidth > 0 && surfaceHeight > 0) {
            const desiredHeight = Math.max(0.4, surfaceWidth / (width / height));
            const deltaHeight = Math.abs(desiredHeight - surfaceHeight);
            const relative = deltaHeight / surfaceHeight;
            if (relative > 0.02) {
              lastAspectCorrectionAtRef.current = now;
              setSurfaceSize([surfaceWidth, desiredHeight]);
            }
          }
        }
      }
    }
  });

  const terminalCount = useSpatialStore((state) => Object.keys(state.terminals).length);
  const registerTerminal = useSpatialStore((state) => state.registerTerminal);
  const unregisterTerminal = useSpatialStore((state) => state.unregisterTerminal);
  const setActiveTerminal = useSpatialStore((state) => state.setActiveTerminal);
  const activeTerminalId = useSpatialStore((state) => state.activeTerminalId);
  const isActive = activeTerminalId === terminalId;
  const wasActiveRef = useRef(null);

  useEffect(() => {
    if (!terminalId) {
      return () => {};
    }
    registerTerminal(terminalId, {
      position: resolvedPosition,
      rotation: resolvedRotation,
      scale: resolvedScale
    });
    return () => unregisterTerminal(terminalId);
  }, [
    terminalId,
    resolvedPosition,
    resolvedRotation,
    resolvedScale,
    registerTerminal,
    unregisterTerminal
  ]);

  useEffect(() => {
    const wasActive = wasActiveRef.current;
    wasActiveRef.current = isActive;

    if (wasActive == null) {
      if (isActive && typeof onFocus === 'function') {
        onFocus();
      }
      return;
    }

    if (!wasActive && isActive && typeof onFocus === 'function') {
      onFocus();
    }

    if (wasActive && !isActive && typeof onBlur === 'function') {
      onBlur();
    }
  }, [isActive, onBlur, onFocus]);

  useEffect(() => {
    if (qualityPreference !== 'auto') {
      setQualityMode(qualityPreference);
      return () => {};
    }

    const interval = setInterval(() => {
      const avgFps = fpsAverageRef.current;
      let target = 'high';

      if (avgFps < 50 || terminalCount > 3 || deviceTier === 'mid') {
        target = 'balanced';
      }

      if (avgFps < 40 || terminalCount > 4 || deviceTier === 'low') {
        target = 'performance';
      }

      setQualityMode((current) => (current === target ? current : target));
    }, 1500);

    return () => clearInterval(interval);
  }, [qualityPreference, terminalCount, deviceTier]);

  const appendOutput = useCallback((chunk) => {
    if (!chunk) {
      return;
    }
    outputBufferRef.current = trimBuffer(outputBufferRef.current + chunk);
    const searchWindow = outputBufferRef.current.slice(-OSC_TITLE_SEARCH_WINDOW);
    let match = null;
    for (const entry of searchWindow.matchAll(OSC_TITLE_REGEX)) {
      match = entry;
    }
    if (match && match[1]) {
      setOscTitle(match[1].trim());
    }
    write(chunk);
  }, [write]);

  const applyPixelSize = useCallback((width, height) => {
    lastRequestedPixelSizeRef.current = { width, height };
    setPixelSize(width, height);
  }, [setPixelSize]);

  const { status, statusNote, sendInput, sendResize, dimensions } = useXRTerminal({
    sessionId,
    onOutput: appendOutput,
    onSession: (session) => {
      if (!session) {
        return;
      }
      if (!sessionId) {
        return;
      }
      const cols = Number.isFinite(session.cols) ? session.cols : remoteDimensions.cols;
      const rows = Number.isFinite(session.rows) ? session.rows : remoteDimensions.rows;
      setRemoteDimensions((prev) => {
        if (prev.cols === cols && prev.rows === rows) {
          return prev;
        }
        return { cols, rows };
      });
      setRendererDimensions(cols, rows);
      lastSentResizeRef.current = { cols, rows };
    },
    onExit: (info) => {
      appendOutput(`\n[process exited code=${info?.exitCode ?? '0'}]\n`);
    },
    onError: (error) => {
      const message = error?.message ?? String(error ?? 'network error');
      appendOutput(`\n[ws error] ${message}\n`);
    },
    onServerError: (message) => {
      if (message) {
        appendOutput(`\n[error] ${message}\n`);
      }
    }
  });

  const handleRendererDimensions = useCallback(({ cols, rows }) => {
    if (!Number.isFinite(cols) || !Number.isFinite(rows)) {
      return;
    }
    const safeCols = Math.max(10, Math.floor(cols));
    const safeRows = Math.max(5, Math.floor(rows));
    const lastPixelSize = lastRequestedPixelSizeRef.current;
    if (lastPixelSize.width > 0 && lastPixelSize.height > 0 && safeCols > 0 && safeRows > 0) {
      const nextCellWidth = lastPixelSize.width / safeCols;
      const nextCellHeight = lastPixelSize.height / safeRows;
      if (Number.isFinite(nextCellWidth) && Number.isFinite(nextCellHeight)) {
        cellSizeEstimateRef.current = {
          width: Math.min(64, Math.max(4, nextCellWidth)),
          height: Math.min(64, Math.max(6, nextCellHeight))
        };
      }
    }

    if (resizeMode === 'follow') {
      return;
    }

    setRemoteDimensions((prev) => {
      if (prev.cols === safeCols && prev.rows === safeRows) {
        return prev;
      }
      return { cols: safeCols, rows: safeRows };
    });
    if (!sessionId) {
      return;
    }
    const previous = lastSentResizeRef.current;
    if (previous.cols === safeCols && previous.rows === safeRows) {
      return;
    }
    lastSentResizeRef.current = { cols: safeCols, rows: safeRows };
    sendResize(safeCols, safeRows);
    if (typeof onResize === 'function') {
      const [width, height] = surfaceSize;
      onResize({ cols: safeCols, rows: safeRows, width, height });
    }
  }, [resizeMode, sessionId, sendResize, onResize, surfaceSize]);

  useEffect(() => {
    measuredDimensionsHandlerRef.current = handleRendererDimensions;
    if (pendingMeasuredDimensionsRef.current) {
      handleRendererDimensions(pendingMeasuredDimensionsRef.current);
      pendingMeasuredDimensionsRef.current = null;
    }
  }, [handleRendererDimensions]);

  useEffect(() => {
    if (resizeMode === 'follow') {
      return;
    }
    if (!sessionId) {
      return;
    }
    if (!Number.isFinite(remoteDimensions.cols) || !Number.isFinite(remoteDimensions.rows)) {
      return;
    }
    handleRendererDimensions({ cols: remoteDimensions.cols, rows: remoteDimensions.rows });
  }, [resizeMode, sessionId, remoteDimensions.cols, remoteDimensions.rows, handleRendererDimensions]);

  useEffect(() => {
    if (!dimensions) {
      return;
    }
    if (!sessionId) {
      return;
    }
    const cols = Number.isFinite(dimensions.cols) ? dimensions.cols : lastSentResizeRef.current.cols;
    const rows = Number.isFinite(dimensions.rows) ? dimensions.rows : lastSentResizeRef.current.rows;
    setRemoteDimensions((prev) => {
      if (prev.cols === cols && prev.rows === rows) {
        return prev;
      }
      return { cols, rows };
    });
    setRendererDimensions(cols, rows);
    const previous = lastSentResizeRef.current;
    if (previous.cols !== cols || previous.rows !== rows) {
      lastSentResizeRef.current = { cols, rows };
      if (typeof onResize === 'function') {
        const [width, height] = surfaceSize;
        onResize({ cols, rows, width, height });
      }
    }
  }, [dimensions, sessionId, setRendererDimensions, onResize, surfaceSize]);

  useEffect(() => {
    if (!texture) {
      return;
    }
    refresh(outputBufferRef.current);
  }, [texture, refresh]);

  useEffect(() => {
    if (resizeMode !== 'follow') {
      return;
    }
    if (!Number.isFinite(remoteDimensions.cols) || !Number.isFinite(remoteDimensions.rows)) {
      return;
    }
    const cellSize = cellSizeEstimateRef.current;
    const widthPx = Math.max(256, Math.round(remoteDimensions.cols * cellSize.width));
    const heightPx = Math.max(192, Math.round(remoteDimensions.rows * cellSize.height));
    applyPixelSize(widthPx, heightPx);
    setRendererDimensions(remoteDimensions.cols, remoteDimensions.rows);
  }, [resizeMode, remoteDimensions.cols, remoteDimensions.rows, applyPixelSize, setRendererDimensions]);

  useEffect(() => {
    if (resizeMode === 'follow') {
      return;
    }
    const [width, height] = surfaceSize;
    const pxPerMeter = qualityMode === 'high' ? 1024 : qualityMode === 'balanced' ? 820 : 640;
    const widthPx = Math.max(256, Math.round(width * pxPerMeter));
    const heightPx = Math.max(192, Math.round(height * pxPerMeter));
    applyPixelSize(widthPx, heightPx);
  }, [resizeMode, surfaceSize, qualityMode, applyPixelSize]);

  useEffect(() => {
    if (qualityMode !== 'performance') {
      return;
    }
    if (resizeMode === 'follow') {
      return;
    }
    const [width, height] = surfaceSize;
    const cols = Math.max(40, Math.round(width * 90));
    const rows = Math.max(16, Math.round(height * 45));
    setRemoteDimensions((prev) => {
      if (prev.cols === cols && prev.rows === rows) {
        return prev;
      }
      return { cols, rows };
    });
    setRendererDimensions(cols, rows);
    if (!sessionId) {
      return;
    }
    lastSentResizeRef.current = { cols, rows };
    sendResize(cols, rows);
    if (typeof onResize === 'function') {
      onResize({ cols, rows, width, height });
    }
  }, [resizeMode, surfaceSize, qualityMode, sessionId, setRendererDimensions, sendResize, onResize]);

  const handleSurfacePointerDown = useCallback((event) => {
    event.stopPropagation();
    setActiveTerminal(terminalId);

    if (typeof onActivate === 'function') {
      const clickCount = event?.detail ?? event?.nativeEvent?.detail;
      if (Number.isFinite(clickCount) && clickCount >= 2) {
        lastActivateClickAtRef.current = 0;
        onActivate();
        return;
      }

      const now = Date.now();
      const last = lastActivateClickAtRef.current;
      lastActivateClickAtRef.current = now;
      if (last && now - last < 450) {
        lastActivateClickAtRef.current = 0;
        onActivate();
      }
    }
  }, [setActiveTerminal, terminalId, onActivate]);

  const handlePointerOver = useCallback((event) => {
    event.stopPropagation();
    setHovered(true);
  }, []);

  const handlePointerOut = useCallback(() => {
    setHovered(false);
  }, []);

  const handleHandlePointerDown = useCallback((event, direction) => {
    event.stopPropagation();
    event.target.setPointerCapture?.(event.pointerId);
    const plane = planeRef.current;
    if (!plane) {
      return;
    }
    const localPoint = plane.worldToLocal(event.point.clone());
    draggingRef.current = {
      pointerId: event.pointerId,
      direction,
      initialPoint: localPoint,
      initialSize: { width: surfaceSize[0], height: surfaceSize[1] }
    };
    setActiveTerminal(terminalId);
  }, [surfaceSize, setActiveTerminal, terminalId]);

  const handleHandlePointerMove = useCallback((event) => {
    const drag = draggingRef.current;
    if (!drag || drag.pointerId !== event.pointerId) {
      return;
    }
    const plane = planeRef.current;
    if (!plane) {
      return;
    }
    const localPoint = plane.worldToLocal(event.point.clone());
    const dx = localPoint.x - drag.initialPoint.x;
    const dy = localPoint.y - drag.initialPoint.y;
    const widthDelta = drag.direction[0] === 0 ? 0 : dx * drag.direction[0] * 2;
    const heightDelta = drag.direction[1] === 0 ? 0 : dy * drag.direction[1] * 2;
    const nextWidth = Math.max(0.6, drag.initialSize.width + widthDelta);
    const nextHeight = Math.max(0.4, drag.initialSize.height + heightDelta);
    setSurfaceSize([nextWidth, nextHeight]);
  }, []);

  const handleHandlePointerUp = useCallback((event) => {
    const drag = draggingRef.current;
    if (!drag || drag.pointerId !== event.pointerId) {
      return;
    }
    draggingRef.current = null;
    event.target.releasePointerCapture?.(event.pointerId);
  }, []);

  const [surfaceWidth, surfaceHeight] = surfaceSize;
  const frameDepth = 0.05;
  const framePadding = 0.12;
  const displayStatus = canvasReadbackReady ? status : 'waiting';
  const displayStatusNote = canvasReadbackReady ? statusNote : 'user input required';

  const handleDirections = useMemo(() => HANDLE_DIRECTIONS, []);

  return (
    <group position={position} rotation={rotation} scale={scale}>
      <mesh position={[0, -surfaceHeight * 0.6, -0.05]} rotation={[-Math.PI / 2, 0, 0]} receiveShadow>
        <planeGeometry args={[surfaceWidth * 1.6, surfaceWidth * 1.6]} />
        <shadowMaterial opacity={0.25} />
      </mesh>

      <RoundedBox args={[surfaceWidth + framePadding, surfaceHeight + framePadding, frameDepth]} radius={0.14} smoothness={4} castShadow>
        <meshPhysicalMaterial
          color={new Color('#1a233c')}
          transparent
          opacity={0.18}
          metalness={0.2}
          roughness={0.05}
          transmission={0.95}
          thickness={0.45}
        />
      </RoundedBox>

      <mesh
        ref={planeRef}
        position={[0, 0, frameDepth * 0.5 + 0.002]}
        onPointerDown={handleSurfacePointerDown}
        onPointerOver={handlePointerOver}
        onPointerOut={handlePointerOut}
      >
        <planeGeometry args={[surfaceWidth, surfaceHeight]} />
        {texture ? (
          holographic ? (
            <holographicTerminalMaterial
              ref={holographicRef}
              map={texture}
              transparent
              toneMapped={false}
            />
          ) : (
            <meshBasicMaterial map={texture} toneMapped={false} transparent />
          )
        ) : (
          <meshBasicMaterial color="#05070f" />
        )}
      </mesh>

      {isActive && (
        <mesh position={[0, 0, frameDepth * 0.5 + 0.015]}>
          <planeGeometry args={[surfaceWidth * 1.05, surfaceHeight * 1.05]} />
          <rimGlowMaterial ref={glowRef} color={new Color('#4f9bff')} transparent depthWrite={false} />
        </mesh>
      )}

      <RoundedBox args={[surfaceWidth, 0.14, 0.02]} position={[0, surfaceHeight / 2 + 0.1, 0.04]} radius={0.06} smoothness={3}>
        <meshStandardMaterial color={isActive ? '#24335b' : '#18203a'} transparent opacity={0.9} />
      </RoundedBox>

      <Text position={[0, surfaceHeight / 2 + 0.1, 0.07]} fontSize={0.09} color="#d6e7ff" anchorX="center" anchorY="middle">
        {oscTitle || title}
      </Text>
      {showStatusLine ? (
        <Text position={[0, surfaceHeight / 2 - 0.02, 0.07]} fontSize={0.045} color="#8fb2ff" anchorX="center" anchorY="middle">
          {displayStatus}
          {displayStatusNote ? ` · ${displayStatusNote}` : ''} · {remoteDimensions.cols}×{remoteDimensions.rows} · {qualityMode}
        </Text>
      ) : null}

      {handleDirections.map((direction, index) => (
        <mesh
          key={`handle-${direction[0]}-${direction[1]}`}
          position={[direction[0] * surfaceWidth * 0.5, direction[1] * surfaceHeight * 0.5, frameDepth * 0.6]}
          onPointerDown={(event) => handleHandlePointerDown(event, direction)}
          onPointerMove={handleHandlePointerMove}
          onPointerUp={handleHandlePointerUp}
          onPointerOut={handleHandlePointerUp}
        >
          <sphereGeometry args={[0.045, 16, 16]} />
          <meshStandardMaterial color={isActive ? '#5ea5ff' : '#324166'} emissive={isActive ? '#1d4d89' : '#111826'} emissiveIntensity={0.4} />
        </mesh>
      ))}
    </group>
  );
}
