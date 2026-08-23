import { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebglAddon } from '@xterm/addon-webgl';
import {
  primeCanvasReadback,
  shouldDeferCanvasReadback,
  waitForCanvasReadbackInput
} from '../../lib/canvasReadbackGate.js';
import { resolveTerminalWsUrl } from '../../lib/terminalWs.js';

const vertexShaderSource = `
  attribute vec2 aPosition;
  attribute vec2 aTexCoord;
  varying vec2 vTexCoord;
  uniform vec2 uScale;
  void main() {
    vTexCoord = aTexCoord;
    gl_Position = vec4(aPosition * uScale, 0.0, 1.0);
  }
`;

const fragmentShaderSource = `
  precision mediump float;
  varying vec2 vTexCoord;
  uniform sampler2D uTexture;
  void main() {
    vec4 tex = texture2D(uTexture, vTexCoord);
    gl_FragColor = vec4(tex.rgb, 1.0);
  }
`;

function compileShader(gl, type, source) {
  const shader = gl.createShader(type);
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    console.error('[basicgl] shader compile error:', gl.getShaderInfoLog(shader));
    gl.deleteShader(shader);
    return null;
  }
  return shader;
}

function createProgram(gl) {
  const vertexShader = compileShader(gl, gl.VERTEX_SHADER, vertexShaderSource);
  const fragmentShader = compileShader(gl, gl.FRAGMENT_SHADER, fragmentShaderSource);
  if (!vertexShader || !fragmentShader) {
    return null;
  }

  const program = gl.createProgram();
  gl.attachShader(program, vertexShader);
  gl.attachShader(program, fragmentShader);
  gl.linkProgram(program);

  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    console.error('[basicgl] program link error:', gl.getProgramInfoLog(program));
    gl.deleteProgram(program);
    return null;
  }

  gl.deleteShader(vertexShader);
  gl.deleteShader(fragmentShader);

  return program;
}

function resizeCanvas(canvas) {
  const { clientWidth, clientHeight } = canvas;
  const dpr = window.devicePixelRatio || 1;
  const width = Math.floor(clientWidth * dpr);
  const height = Math.floor(clientHeight * dpr);

  if (canvas.width !== width || canvas.height !== height) {
    canvas.width = width;
    canvas.height = height;
    return true;
  }

  return false;
}

function draw(gl, programInfo, buffers, texture, scaleX = 1, scaleY = 1) {
  gl.useProgram(programInfo.program);

  gl.bindBuffer(gl.ARRAY_BUFFER, buffers.position);
  gl.enableVertexAttribArray(programInfo.attribLocations.position);
  gl.vertexAttribPointer(programInfo.attribLocations.position, 2, gl.FLOAT, false, 0, 0);

  gl.bindBuffer(gl.ARRAY_BUFFER, buffers.texCoord);
  gl.enableVertexAttribArray(programInfo.attribLocations.texCoord);
  gl.vertexAttribPointer(programInfo.attribLocations.texCoord, 2, gl.FLOAT, false, 0, 0);

  gl.activeTexture(gl.TEXTURE0);
  gl.bindTexture(gl.TEXTURE_2D, texture);
  gl.uniform1i(programInfo.uniformLocations.texture, 0);
  gl.uniform2f(programInfo.uniformLocations.scale, scaleX, scaleY);

  gl.clearColor(0, 0, 0, 1);
  gl.clear(gl.COLOR_BUFFER_BIT);
  gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
}

export default function BasicGLViewer({ sessionId = 1 }) {
  const canvasRef = useRef(null);
  const debugPreviewRef = useRef(null);
  const [status, setStatus] = useState('idle');
  const [statusNote, setStatusNote] = useState('');
  const [canvasReadbackReady, setCanvasReadbackReady] = useState(() => (
    typeof window !== 'undefined' && !shouldDeferCanvasReadback(window)
  ));

  useEffect(() => {
    if (typeof window === 'undefined') {
      return undefined;
    }

    if (!shouldDeferCanvasReadback(window)) {
      setCanvasReadbackReady(true);
      return undefined;
    }

    setCanvasReadbackReady(false);
    setStatus('waiting');
    setStatusNote('user input required');
    return waitForCanvasReadbackInput(() => {
      setCanvasReadbackReady(true);
      setStatus('idle');
      setStatusNote('');
    }, window);
  }, [sessionId]);

  useEffect(() => {
    if (!canvasReadbackReady) return () => {};

    const canvas = canvasRef.current;
    if (!canvas) return () => {};

    const debugEnabled = new URLSearchParams(window.location.search).has('debug');
    if (debugPreviewRef.current) {
      debugPreviewRef.current.style.display = debugEnabled ? 'block' : 'none';
    }

    const gl = canvas.getContext('webgl');
    if (!gl) {
      console.error('[basicgl] Unable to initialize WebGL.');
      setStatus('error');
      setStatusNote('webgl unavailable');
      return () => {};
    }

    const program = createProgram(gl);
    if (!program) {
      setStatus('error');
      setStatusNote('shader error');
      return () => {};
    }

    const positionBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([
        -1, -1,
        1, -1,
        -1, 1,
        1, 1,
      ]),
      gl.STATIC_DRAW
    );

    const texCoordBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, texCoordBuffer);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([
        0, 1,
        1, 1,
        0, 0,
        1, 0,
      ]),
      gl.STATIC_DRAW
    );

    const programInfo = {
      program,
      attribLocations: {
        position: gl.getAttribLocation(program, 'aPosition'),
        texCoord: gl.getAttribLocation(program, 'aTexCoord'),
      },
      uniformLocations: {
        texture: gl.getUniformLocation(program, 'uTexture'),
        scale: gl.getUniformLocation(program, 'uScale'),
      },
    };

    const texture = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, texture);
    gl.texImage2D(
      gl.TEXTURE_2D,
      0,
      gl.RGBA,
      1,
      1,
      0,
      gl.RGBA,
      gl.UNSIGNED_BYTE,
      new Uint8Array([0, 0, 0, 255])
    );
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);

    const offscreen = document.createElement('div');
    offscreen.className = 'basicgl-xterm-offscreen';
    Object.assign(offscreen.style, {
      position: 'fixed',
      top: '0',
      left: '0',
      width: '1024px',
      height: '640px',
      pointerEvents: 'none',
      overflow: 'hidden',
      zIndex: '0'
    });
    document.body.appendChild(offscreen);

    const terminal = new Terminal({
      cursorBlink: false,
      fontSize: 14,
      fontFamily: 'JetBrains Mono, Fira Code, Consolas, Monaco, monospace',
      theme: {
        background: '#0a0e14',
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
        brightWhite: '#ffffff',
      },
      scrollback: 10000,
      allowTransparency: false,
      convertEol: false,
    });

    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    console.log('[basicgl] opening xterm (offscreen size)', {
      width: offscreen.clientWidth,
      height: offscreen.clientHeight
    });
    terminal.open(offscreen);
    console.log('[basicgl] xterm opened', {
      cols: terminal.cols,
      rows: terminal.rows,
      hasElement: Boolean(terminal.element)
    });

    let webglAddon = null;
    try {
      webglAddon = new WebglAddon(true);
      webglAddon.onContextLoss(() => {
        console.warn('[basicgl] xterm webgl context lost');
        webglAddon.dispose();
      });
      terminal.loadAddon(webglAddon);
      console.log('[basicgl] xterm webgl addon loaded');
    } catch (err) {
      console.warn('[basicgl] xterm webgl addon failed to load:', err?.message ?? err);
      setStatus('error');
      setStatusNote('xterm webgl addon failed');
    }

    fitAddon.fit();
    terminal.refresh(0, Math.max(0, terminal.rows - 1));

    let sourceCanvas = null;
    const mirrorCanvas = document.createElement('canvas');
    const mirrorCtx = mirrorCanvas.getContext('2d');
    if (debugEnabled && debugPreviewRef.current && mirrorCtx) {
      mirrorCanvas.style.width = '320px';
      mirrorCanvas.style.height = 'auto';
      mirrorCanvas.style.display = 'block';
      debugPreviewRef.current.appendChild(mirrorCanvas);
    }

    const classifyCanvas = (candidate) => {
      if (!candidate) {
        return { isWebgl: false, isWebgl2: false };
      }

      let webgl2 = false;
      let webgl = false;
      try {
        webgl2 = Boolean(candidate.getContext && candidate.getContext('webgl2'));
      } catch {
        webgl2 = false;
      }

      if (!webgl2) {
        try {
          webgl = Boolean(candidate.getContext && candidate.getContext('webgl'));
        } catch {
          webgl = false;
        }
      }

      return { isWebgl: webgl2 || webgl, isWebgl2: webgl2 };
    };

    const findSourceCanvas = () => {
      const textLayer = offscreen.querySelector('canvas.xterm-text-layer');
      if (textLayer) {
        if (sourceCanvas !== textLayer) {
          sourceCanvas = textLayer;
          console.log('[basicgl] xterm canvas found', {
            className: sourceCanvas.className,
            width: sourceCanvas.width,
            height: sourceCanvas.height,
            kind: 'text-layer'
          });
        }
        return textLayer;
      }

      const canvases = Array.from(offscreen.querySelectorAll('.xterm-screen canvas, canvas'));
      if (!canvases.length) {
        return null;
      }

      const webglCanvas = canvases.find((candidate) => classifyCanvas(candidate).isWebgl);
      const preferred =
        webglCanvas
        || canvases.find((candidate) => !candidate.classList.contains('xterm-link-layer'))
        || canvases[canvases.length - 1];

      if (!preferred) {
        return null;
      }

      if (sourceCanvas !== preferred) {
        sourceCanvas = preferred;
        const flags = classifyCanvas(sourceCanvas);
        console.log('[basicgl] xterm canvas found', {
          className: sourceCanvas.className,
          width: sourceCanvas.width,
          height: sourceCanvas.height,
          kind: flags.isWebgl2 ? 'webgl2' : flags.isWebgl ? 'webgl' : 'canvas-2d'
        });
      }
      return preferred;
    };

    if (!findSourceCanvas()) {
      console.warn('[basicgl] xterm canvas not found yet (will retry).');
    }

    const missingCanvasTimer = setTimeout(() => {
      if (sourceCanvas) {
        return;
      }
      const canvases = Array.from(offscreen.querySelectorAll('canvas')).map((canvasNode) => ({
        className: canvasNode.className,
        width: canvasNode.width,
        height: canvasNode.height,
        ...classifyCanvas(canvasNode)
      }));
      console.warn('[basicgl] still no xterm canvas after 1s', {
        canvases,
        offscreenChildren: offscreen.children.length
      });
    }, 1000);

    const mutationObserver = new MutationObserver(() => {
      findSourceCanvas();
    });
    mutationObserver.observe(offscreen, { childList: true, subtree: true });

    let ws = null;
    let raf = 0;
    let active = true;
    let firstOutputLogged = false;
    let renderEvents = 0;
    const renderDisposable = terminal.onRender(({ start, end }) => {
      renderEvents += 1;
      if (renderEvents <= 5) {
        console.log('[basicgl] xterm rendered', { start, end });
      }
    });

    const connect = async () => {
      try {
        setStatus('connecting');
        setStatusNote('');

        const wsUrl = await resolveTerminalWsUrl(sessionId);
        console.log('[basicgl] ws connecting', wsUrl);
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          if (!active) return;
          setStatus('connected');
          setStatusNote('');
          console.log('[basicgl] ws open');
          try {
            ws.send(JSON.stringify({ type: 'resize', cols: terminal.cols, rows: terminal.rows }));
          } catch {
            // ignore
          }
        };

        ws.onclose = (event) => {
          if (!active) return;
          const detail = `code=${event.code}${event.reason ? ` reason=${event.reason}` : ''}`;
          setStatus(event.wasClean ? 'closed' : 'error');
          setStatusNote(detail);
          console.log('[basicgl] ws close', detail);
        };

        ws.onerror = () => {
          if (!active) return;
          setStatus('error');
          setStatusNote('network error');
          console.log('[basicgl] ws error');
        };

        ws.onmessage = (event) => {
          if (!active) return;
          let message;
          try {
            message = JSON.parse(event.data);
          } catch (err) {
            terminal.writeln(`\r\n[parse error] ${err.message}`);
            return;
          }

          if (message.type === 'output') {
            terminal.write(message.data, () => {
              terminal.refresh(0, Math.max(0, terminal.rows - 1));
            });
            if (!firstOutputLogged) {
              firstOutputLogged = true;
              console.log('[basicgl] first ws output', { length: message.data?.length ?? 0 });
            }
            return;
          }

          if (message.type === 'session') {
            return;
          }

          if (message.type === 'exit') {
            terminal.writeln(`\r\n[process exited code=${message.info?.exitCode}]`);
            setStatus('closed');
            setStatusNote(`code=${message.info?.exitCode ?? '0'}`);
            return;
          }

          if (message.type === 'error') {
            terminal.writeln(`\r\n[error] ${message.error}`);
          }
        };
      } catch (err) {
        setStatus('error');
        setStatusNote(err.message ?? 'unknown error');
        terminal.writeln(`\r\n[ws error] ${err.message}`);
      }
    };

    connect();

    let firstUploadLogged = false;
    let probeLogged = false;
    let textureWidth = 0;
    let textureHeight = 0;
    let glErrorLogged = false;
    const render = () => {
      if (!active) return;
      if (resizeCanvas(canvas)) {
        gl.viewport(0, 0, canvas.width, canvas.height);
      }

      if (!sourceCanvas || !sourceCanvas.isConnected) {
        findSourceCanvas();
      }

      const uploadCanvas = sourceCanvas && mirrorCtx ? mirrorCanvas : sourceCanvas;

      if (sourceCanvas && mirrorCtx) {
        const width = sourceCanvas.width;
        const height = sourceCanvas.height;
        if (width && height) {
          if (mirrorCanvas.width !== width || mirrorCanvas.height !== height) {
            mirrorCanvas.width = width;
            mirrorCanvas.height = height;
          }
          mirrorCtx.setTransform(1, 0, 0, 1, 0, 0);
          mirrorCtx.clearRect(0, 0, width, height);
          mirrorCtx.drawImage(sourceCanvas, 0, 0, width, height, 0, 0, width, height);
        }
      }

      if (uploadCanvas && uploadCanvas.width && uploadCanvas.height) {
        gl.bindTexture(gl.TEXTURE_2D, texture);
        if (uploadCanvas.width !== textureWidth || uploadCanvas.height !== textureHeight) {
          gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, uploadCanvas);
          textureWidth = uploadCanvas.width;
          textureHeight = uploadCanvas.height;
        } else {
          gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0, gl.RGBA, gl.UNSIGNED_BYTE, uploadCanvas);
        }
        if (!glErrorLogged) {
          const error = gl.getError();
          if (error !== gl.NO_ERROR) {
            glErrorLogged = true;
            console.warn('[basicgl] gl error after upload', { error });
          }
        }
        if (!firstUploadLogged) {
          firstUploadLogged = true;
          console.log('[basicgl] first texture upload', {
            width: uploadCanvas.width,
            height: uploadCanvas.height,
            source: uploadCanvas === mirrorCanvas ? 'mirror' : 'direct'
          });
        }
        if (firstOutputLogged && !probeLogged && mirrorCtx && uploadCanvas === mirrorCanvas) {
          probeLogged = true;
          try {
            const midX = Math.max(0, Math.floor(mirrorCanvas.width / 2));
            const midY = Math.max(0, Math.floor(mirrorCanvas.height / 2));
            const sample = mirrorCtx.getImageData(midX, midY, 1, 1).data;
            console.log('[basicgl] mirror probe', { x: midX, y: midY, rgba: Array.from(sample) });
          } catch (err) {
            console.warn('[basicgl] mirror probe failed', err?.message ?? err);
          }
        }
      }

      const viewportAspect = canvas.width > 0 && canvas.height > 0 ? canvas.width / canvas.height : 1;
      const contentWidth = uploadCanvas?.width || textureWidth || 0;
      const contentHeight = uploadCanvas?.height || textureHeight || 0;
      const contentAspect = contentHeight > 0 ? contentWidth / contentHeight : viewportAspect;

      let scaleX = 1;
      let scaleY = 1;
      if (viewportAspect > contentAspect) {
        scaleX = contentAspect / viewportAspect;
      } else if (viewportAspect < contentAspect) {
        scaleY = viewportAspect / contentAspect;
      }

      draw(
        gl,
        programInfo,
        { position: positionBuffer, texCoord: texCoordBuffer },
        texture,
        scaleX,
        scaleY
      );
      raf = requestAnimationFrame(render);
    };

    raf = requestAnimationFrame(render);

    return () => {
      active = false;
      if (raf) cancelAnimationFrame(raf);
      clearTimeout(missingCanvasTimer);
      mutationObserver.disconnect();
      renderDisposable.dispose?.();
      if (ws) {
        try {
          ws.close(1000);
        } catch {
          // ignore
        }
      }
      console.log('[basicgl] cleanup (deferring xterm dispose)');
      setTimeout(() => {
        terminal.dispose();
        if (offscreen.parentNode) {
          offscreen.parentNode.removeChild(offscreen);
        }
      }, 0);
      gl.deleteTexture(texture);
      gl.deleteBuffer(positionBuffer);
      gl.deleteBuffer(texCoordBuffer);
      gl.deleteProgram(program);
    };
  }, [sessionId, canvasReadbackReady]);

  return (
    <div className="basicgl-page">
      <canvas ref={canvasRef} className="basicgl-canvas" />
      <div className="basicgl-hud">
        <div className="basicgl-title">/basicgl · session {sessionId}</div>
        <div className="basicgl-status">
          {status}
          {statusNote ? ` (${statusNote})` : ''}
        </div>
      </div>
      {!canvasReadbackReady && (
        <button
          type="button"
          className="basicgl-start"
          onClick={() => {
            if (primeCanvasReadback(window)) {
              setCanvasReadbackReady(true);
            }
          }}
        >
          Start terminal
        </button>
      )}
      <div ref={debugPreviewRef} className="basicgl-debug" />
      <style jsx>{`
        .basicgl-page {
          position: fixed;
          inset: 0;
          background: #000;
          z-index: 1;
        }

        .basicgl-canvas {
          width: 100%;
          height: 100%;
          display: block;
        }

        .basicgl-hud {
          position: absolute;
          top: 12px;
          left: 12px;
          padding: 10px 12px;
          border-radius: 10px;
          background: rgba(2, 6, 23, 0.72);
          border: 1px solid rgba(148, 163, 184, 0.35);
          color: rgba(226, 232, 240, 0.9);
          font: 13px/1.35 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono',
            'Courier New', monospace;
          pointer-events: none;
          z-index: 2;
        }

        .basicgl-title {
          color: #f8fafc;
          font-weight: 600;
        }

        .basicgl-start {
          position: absolute;
          left: 50%;
          top: 50%;
          transform: translate(-50%, -50%);
          z-index: 3;
          pointer-events: auto;
        }

        .basicgl-debug {
          display: none;
          position: absolute;
          left: 12px;
          bottom: 12px;
          border-radius: 10px;
          overflow: hidden;
          border: 1px solid rgba(148, 163, 184, 0.35);
          background: rgba(2, 6, 23, 0.72);
          pointer-events: none;
          z-index: 2;
        }
      `}</style>
    </div>
  );
}
