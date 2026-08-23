const INPUT_EVENTS = ['pointerdown', 'mousedown', 'touchstart', 'keydown'];
let firefoxCanvasReadbackPrimed = false;

export function isFirefoxBrowser(win = globalThis.window) {
  const userAgent = win?.navigator?.userAgent ?? '';
  return /\bFirefox\//.test(userAgent);
}

export function primeCanvasReadback(win = globalThis.window) {
  if (!isFirefoxBrowser(win) || firefoxCanvasReadbackPrimed) {
    return true;
  }

  try {
    const canvas = win.document.createElement('canvas');
    canvas.width = 1;
    canvas.height = 1;
    const context = canvas.getContext('2d', { willReadFrequently: true });
    context?.getImageData(0, 0, 1, 1);
    firefoxCanvasReadbackPrimed = true;
    return true;
  } catch {
    return false;
  }
}

export function shouldDeferCanvasReadback(win = globalThis.window) {
  return Boolean(isFirefoxBrowser(win) && !firefoxCanvasReadbackPrimed);
}

export function waitForCanvasReadbackInput(callback, win = globalThis.window) {
  if (!win?.document || typeof callback !== 'function') {
    return () => {};
  }

  let active = true;
  const cleanup = () => {
    if (!active) {
      return;
    }
    active = false;
    for (const eventName of INPUT_EVENTS) {
      win.document.removeEventListener(eventName, handleInput, true);
    }
  };
  const handleInput = () => {
    const primed = primeCanvasReadback(win);
    if (!primed && shouldDeferCanvasReadback(win)) {
      return;
    }
    cleanup();
    callback();
  };

  for (const eventName of INPUT_EVENTS) {
    win.document.addEventListener(eventName, handleInput, {
      capture: true,
      passive: true
    });
  }

  return cleanup;
}
