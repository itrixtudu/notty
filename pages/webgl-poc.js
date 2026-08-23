import { useEffect, useRef } from 'react';

const vertexShaderSource = `
  attribute vec2 aPosition;
  attribute vec2 aTexCoord;
  varying vec2 vTexCoord;
  void main() {
    vTexCoord = aTexCoord;
    gl_Position = vec4(aPosition, 0.0, 1.0);
  }
`;

const fragmentShaderSource = `
  precision mediump float;
  varying vec2 vTexCoord;
  uniform sampler2D uTexture;
  void main() {
    gl_FragColor = texture2D(uTexture, vTexCoord);
  }
`;

function compileShader(gl, type, source) {
  const shader = gl.createShader(type);
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    console.error('Shader compile error:', gl.getShaderInfoLog(shader));
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
    console.error('Program link error:', gl.getProgramInfoLog(program));
    gl.deleteProgram(program);
    return null;
  }

  gl.deleteShader(vertexShader);
  gl.deleteShader(fragmentShader);

  return program;
}

function createTextTexture(gl) {
  const textCanvas = document.createElement('canvas');
  textCanvas.width = 1024;
  textCanvas.height = 512;
  const ctx = textCanvas.getContext('2d');

  ctx.fillStyle = '#0d0d0d';
  ctx.fillRect(0, 0, textCanvas.width, textCanvas.height);
  ctx.font = '24px "Fira Code", "Source Code Pro", monospace';
  ctx.textBaseline = 'top';
  ctx.fillStyle = '#39ff14';

  const lines = [
    'lorem ipsum dolor sit amet, consectetur adipiscing elit.',
    'sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.',
    'ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi.',
    'aliquip ex ea commodo consequat. duis aute irure dolor in reprehenderit.',
    'in voluptate velit esse cillum dolore eu fugiat nulla pariatur.',
    'excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia.',
    'deserunt mollit anim id est laborum. — fake terminal output ready.',
  ];

  const lineHeight = 32;
  const startY = 32;
  lines.forEach((line, index) => {
    const y = startY + index * lineHeight;
    ctx.fillText(line, 32, y);
  });

  const texture = gl.createTexture();
  gl.bindTexture(gl.TEXTURE_2D, texture);
  gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, textCanvas);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);

  return texture;
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

function draw(gl, programInfo, buffers, texture) {
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

  gl.clearColor(0, 0, 0, 1);
  gl.clear(gl.COLOR_BUFFER_BIT);
  gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
}

function WebglPocPage() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return () => {};

    const gl = canvas.getContext('webgl');
    if (!gl) {
      console.error('Unable to initialize WebGL.');
      return () => {};
    }

    const program = createProgram(gl);
    if (!program) {
      return () => {};
    }

    const positionBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
    const positions = new Float32Array([
      -1, -1,
      1, -1,
      -1, 1,
      1, 1,
    ]);
    gl.bufferData(gl.ARRAY_BUFFER, positions, gl.STATIC_DRAW);

    const texCoordBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, texCoordBuffer);
    const texCoords = new Float32Array([
      0, 1,
      1, 1,
      0, 0,
      1, 0,
    ]);
    gl.bufferData(gl.ARRAY_BUFFER, texCoords, gl.STATIC_DRAW);

    const programInfo = {
      program,
      attribLocations: {
        position: gl.getAttribLocation(program, 'aPosition'),
        texCoord: gl.getAttribLocation(program, 'aTexCoord'),
      },
      uniformLocations: {
        texture: gl.getUniformLocation(program, 'uTexture'),
      },
    };

    const texture = createTextTexture(gl);

    function render() {
      if (resizeCanvas(canvas)) {
        gl.viewport(0, 0, canvas.width, canvas.height);
      }
      draw(gl, programInfo, { position: positionBuffer, texCoord: texCoordBuffer }, texture);
    }

    render();
    window.addEventListener('resize', render);

    return () => {
      window.removeEventListener('resize', render);
      gl.deleteTexture(texture);
      gl.deleteBuffer(positionBuffer);
      gl.deleteBuffer(texCoordBuffer);
      gl.deleteProgram(program);
    };
  }, []);

  return (
    <div className="webgl-poc">
      <div className="header">
        <h1>WebGL Fake Terminal</h1>
        <p>
          A completely isolated proof-of-concept that simply renders static text onto a WebGL
          texture. No sockets, no REST calls, just pixels.
        </p>
      </div>
      <div className="terminal-wrapper">
        <canvas ref={canvasRef} className="terminal-canvas" />
      </div>
      <style jsx>{`
        .webgl-poc {
          min-height: 100vh;
          background: radial-gradient(circle at top, #0f172a, #020617);
          color: #e0f2fe;
          padding: 2rem;
          font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        }

        .header {
          max-width: 720px;
          margin: 0 auto 2rem auto;
          text-align: center;
        }

        .header h1 {
          font-size: 2.5rem;
          margin-bottom: 0.75rem;
        }

        .header p {
          color: #94a3b8;
          line-height: 1.5;
        }

        .terminal-wrapper {
          max-width: 960px;
          margin: 0 auto;
          background: rgba(15, 23, 42, 0.8);
          border-radius: 1rem;
          padding: 1rem;
          box-shadow: 0 10px 40px rgba(2, 6, 23, 0.6);
        }

        .terminal-canvas {
          width: 100%;
          height: 540px;
          display: block;
          border-radius: 0.5rem;
          border: 1px solid rgba(148, 163, 184, 0.4);
          background: black;
        }

        @media (max-width: 768px) {
          .terminal-canvas {
            height: 360px;
          }
        }
      `}</style>
    </div>
  );
}

export default WebglPocPage;
