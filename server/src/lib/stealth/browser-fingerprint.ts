/**
 * Browser Fingerprint Hardening
 * Injected into every Playwright context via addInitScript().
 * Covers the vectors that bot-detection systems (Cloudflare, DataDome,
 * Akamai Bot Manager) probe first: webdriver flag, chrome runtime object,
 * navigator properties, WebGL vendor strings, and permissions API.
 */

/** Realistic Windows/macOS Chrome user-agents (rotate per session). */
export const STEALTH_USER_AGENTS: string[] = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
];

export function getRandomUserAgent(): string {
  return STEALTH_USER_AGENTS[Math.floor(Math.random() * STEALTH_USER_AGENTS.length)];
}

/** Chromium launch args that suppress automation signals. */
export function getBrowserLaunchArgs(): string[] {
  return [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    // Core: remove the AutomationControlled feature flag (sets navigator.webdriver)
    '--disable-blink-features=AutomationControlled',
    // Suppress infobar ("Chrome is being controlled by automated test software")
    '--disable-infobars',
    // Don't expose Chrome DevTools remote debugging port in headers
    '--no-first-run',
    '--no-default-browser-check',
    // Disable extension warnings that appear in headless logs
    '--disable-extensions',
    // Realistic window size matching the viewport
    '--window-size=1280,800',
    '--start-maximized',
    // Disable background throttling so timing feels consistent
    '--disable-backgrounding-occluded-windows',
    '--disable-background-timer-throttling',
  ];
}

/**
 * JavaScript init script injected before any page code runs.
 * Uses Object.defineProperty so that target-page JS cannot overwrite it.
 *
 * Detection vectors covered:
 *  1. navigator.webdriver (most common check)
 *  2. window.chrome runtime object (missing in headless = bot)
 *  3. navigator.plugins (empty in headless = bot)
 *  4. navigator.languages (empty array = bot)
 *  5. navigator.hardwareConcurrency + deviceMemory (unrealistic values = bot)
 *  6. WebGL vendor/renderer strings (default headless strings are on deny-lists)
 *  7. navigator.permissions.query for notifications ('denied' in headless = bot)
 *  8. screen.colorDepth / pixelDepth (1-bit in some headless envs)
 *  9. Iframe contentWindow.navigator.webdriver (bypass via frames)
 * 10. window.outerWidth/Height (0 in headless = bot)
 */
export function getFingerprintInitScript(): string {
  return `
(function () {
  'use strict';

  // ── 1. navigator.webdriver ────────────────────────────────────────────────
  // The single most-checked property. Delete it entirely so it returns
  // undefined rather than false, which is what real Chrome does.
  try {
    Object.defineProperty(navigator, 'webdriver', {
      get: () => undefined,
      configurable: true,
    });
  } catch (_) {}

  // ── 2. window.chrome runtime object ──────────────────────────────────────
  // Headless Chromium ships without window.chrome; its absence is a flag.
  if (!window.chrome) {
    const chrome = {
      app: {
        isInstalled: false,
        InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
        RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' },
        getDetails: function() {},
        getIsInstalled: function() {},
        installState: function() {},
      },
      runtime: {
        OnInstalledReason: {
          CHROME_UPDATE: 'chrome_update', INSTALL: 'install',
          SHARED_MODULE_UPDATE: 'shared_module_update', UPDATE: 'update',
        },
        OnRestartRequiredReason: {
          APP_UPDATE: 'app_update', OS_UPDATE: 'os_update', PERIODIC: 'periodic',
        },
        PlatformArch: { ARM: 'arm', X86_32: 'x86-32', X86_64: 'x86-64' },
        PlatformNaclArch: { ARM: 'arm', X86_32: 'x86-32', X86_64: 'x86-64' },
        PlatformOs: {
          ANDROID: 'android', CROS: 'cros', LINUX: 'linux',
          MAC: 'mac', OPENBSD: 'openbsd', WIN: 'win',
        },
        RequestUpdateCheckStatus: {
          NO_UPDATE: 'no_update', THROTTLED: 'throttled', UPDATE_AVAILABLE: 'update_available',
        },
        id: undefined,
        connect: function() {},
        sendMessage: function() {},
      },
      csi: function() {},
      loadTimes: function() {
        return {
          commitLoadTime: Date.now() / 1000 - Math.random(),
          connectionInfo: 'h2',
          finishDocumentLoadTime: Date.now() / 1000,
          finishLoadTime: Date.now() / 1000,
          firstPaintAfterLoadTime: 0,
          firstPaintTime: Date.now() / 1000 - Math.random() * 0.2,
          navigationType: 'Other',
          npnNegotiatedProtocol: 'h2',
          requestTime: Date.now() / 1000 - Math.random() * 0.5,
          startLoadTime: Date.now() / 1000 - Math.random() * 0.5,
          wasAlternateProtocolAvailable: false,
          wasFetchedViaSpdy: true,
          wasNpnNegotiated: true,
        };
      },
    };
    try {
      window.chrome = chrome;
    } catch (_) {}
  }

  // ── 3. navigator.plugins ──────────────────────────────────────────────────
  // Headless has 0 plugins; real Chrome has at least 3 (PDF viewer, NaCl, etc.)
  const fakePlugins = [
    {
      name: 'Chrome PDF Plugin',
      description: 'Portable Document Format',
      filename: 'internal-pdf-viewer',
      length: 1,
    },
    {
      name: 'Chrome PDF Viewer',
      description: '',
      filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai',
      length: 1,
    },
    {
      name: 'Native Client',
      description: '',
      filename: 'internal-nacl-plugin',
      length: 2,
    },
  ];
  try {
    Object.defineProperty(navigator, 'plugins', {
      get: () => {
        const arr = [...fakePlugins];
        arr.item = (i) => arr[i] || null;
        arr.namedItem = (n) => arr.find(p => p.name === n) || null;
        arr.refresh = () => {};
        return arr;
      },
      configurable: true,
    });
  } catch (_) {}

  // ── 4. navigator.languages ────────────────────────────────────────────────
  try {
    Object.defineProperty(navigator, 'languages', {
      get: () => ['en-US', 'en'],
      configurable: true,
    });
  } catch (_) {}

  // ── 5. navigator.hardwareConcurrency + deviceMemory ───────────────────────
  const hc = [4, 8, 8, 16][Math.floor(Math.random() * 4)]; // bias toward 8
  try {
    Object.defineProperty(navigator, 'hardwareConcurrency', {
      get: () => hc, configurable: true,
    });
  } catch (_) {}
  try {
    const dm = [4, 8][Math.floor(Math.random() * 2)];
    Object.defineProperty(navigator, 'deviceMemory', {
      get: () => dm, configurable: true,
    });
  } catch (_) {}

  // ── 6. WebGL vendor/renderer strings ──────────────────────────────────────
  // Default headless renderer strings ("Google SwiftShader" etc.) are on block-lists.
  const spoofWebGL = (ctxProto) => {
    const orig = ctxProto.getParameter;
    ctxProto.getParameter = function(param) {
      // UNMASKED_VENDOR_WEBGL = 37445, UNMASKED_RENDERER_WEBGL = 37446
      if (param === 37445) return 'Intel Inc.';
      if (param === 37446) return 'Intel Iris OpenGL Engine';
      return orig.call(this, param);
    };
  };
  try { spoofWebGL(WebGLRenderingContext.prototype); } catch (_) {}
  try { spoofWebGL(WebGL2RenderingContext.prototype); } catch (_) {}

  // ── 7. Permissions API (notifications) ────────────────────────────────────
  // Headless returns 'denied' for notification permission; real Chrome 'default'.
  if (navigator.permissions && navigator.permissions.query) {
    const origQuery = navigator.permissions.query.bind(navigator.permissions);
    navigator.permissions.query = (params) => {
      if (params && params.name === 'notifications') {
        return Promise.resolve({ state: 'default', onchange: null });
      }
      return origQuery(params);
    };
  }

  // ── 8. screen.colorDepth / pixelDepth ────────────────────────────────────
  try {
    Object.defineProperty(screen, 'colorDepth', { get: () => 24, configurable: true });
    Object.defineProperty(screen, 'pixelDepth', { get: () => 24, configurable: true });
  } catch (_) {}

  // ── 9. window.outerWidth / outerHeight ───────────────────────────────────
  // Headless leaves these at 0; real Chrome matches window size.
  try {
    if (window.outerWidth === 0) {
      Object.defineProperty(window, 'outerWidth', { get: () => 1280, configurable: true });
    }
    if (window.outerHeight === 0) {
      Object.defineProperty(window, 'outerHeight', { get: () => 800, configurable: true });
    }
  } catch (_) {}

  // ── 10. iframe webdriver propagation ──────────────────────────────────────
  // Some detectors create an iframe and check its navigator.webdriver.
  // Override HTMLIFrameElement.contentWindow getter to patch child frames.
  try {
    const origContentWindow = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow');
    if (origContentWindow) {
      Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
        get: function() {
          const win = origContentWindow.get.call(this);
          if (win && win.navigator) {
            try {
              Object.defineProperty(win.navigator, 'webdriver', {
                get: () => undefined, configurable: true,
              });
            } catch (_) {}
          }
          return win;
        },
        configurable: true,
      });
    }
  } catch (_) {}

  // ── 11. Canvas fingerprinting noise ──────────────────────────────────────
  // Override toDataURL to add ±1 imperceptible pixel noise on small canvases
  // (fingerprint canvases are typically ≤400×150). Saves/restores original
  // pixel data so the visible canvas is unchanged.
  try {
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(type, quality) {
      if (this.width > 0 && this.height > 0 && this.width <= 400 && this.height <= 200) {
        const ctx = this.getContext('2d');
        if (ctx) {
          const saved = ctx.getImageData(0, 0, this.width, this.height);
          const noisy = ctx.createImageData(saved);
          noisy.data.set(saved.data);
          for (let i = 0; i < noisy.data.length; i += 4) {
            if (Math.random() < 0.05) noisy.data[i] = Math.min(255, noisy.data[i] + 1);
          }
          ctx.putImageData(noisy, 0, 0);
          const result = origToDataURL.call(this, type, quality);
          ctx.putImageData(saved, 0, 0);
          return result;
        }
      }
      return origToDataURL.call(this, type, quality);
    };
  } catch (_) {}

  // ── 12. AudioContext fingerprinting ──────────────────────────────────────
  // Patch OfflineAudioContext.startRendering() to inject sub-noise into the
  // rendered audio buffer, breaking timing-based headless detection.
  try {
    const OrigOfflineAC = window.OfflineAudioContext;
    if (OrigOfflineAC) {
      const PatchedOfflineAC = function(...args) {
        const ctx = new OrigOfflineAC(...args);
        const origStart = ctx.startRendering.bind(ctx);
        ctx.startRendering = async function() {
          const buffer = await origStart();
          for (let ch = 0; ch < buffer.numberOfChannels; ch++) {
            const data = buffer.getChannelData(ch);
            for (let i = 0; i < data.length; i++) {
              data[i] += (Math.random() - 0.5) * 1e-7;
            }
          }
          return buffer;
        };
        return ctx;
      };
      PatchedOfflineAC.prototype = OrigOfflineAC.prototype;
      Object.setPrototypeOf(PatchedOfflineAC, OrigOfflineAC);
      window.OfflineAudioContext = PatchedOfflineAC;
    }
  } catch (_) {}

  // ── 13. WebRTC local IP leak prevention ──────────────────────────────────
  // Intercept RTCPeerConnection to suppress host candidates that would
  // reveal the real local IP address through STUN/TURN ICE gathering.
  try {
    const OrigRTC = window.RTCPeerConnection;
    if (OrigRTC) {
      const localIpPattern = /(\s)(192\.168|10\.\d+|172\.(1[6-9]|2\d|3[01])|169\.254)\.\d+\.\d+(\s|$)/;
      const PatchedRTC = function(config, constraints) {
        const pc = new OrigRTC(config, constraints);
        const origSetLocalDesc = pc.setLocalDescription.bind(pc);
        pc.setLocalDescription = function(desc) {
          if (desc && desc.sdp) {
            desc = { ...desc, sdp: desc.sdp.replace(localIpPattern, ' 0.0.0.0 ') };
          }
          return origSetLocalDesc(desc);
        };
        return pc;
      };
      PatchedRTC.prototype = OrigRTC.prototype;
      Object.setPrototypeOf(PatchedRTC, OrigRTC);
      window.RTCPeerConnection = PatchedRTC;
    }
  } catch (_) {}

  // ── 14. Battery API ───────────────────────────────────────────────────────
  // Headless returns undefined or unrealistic values; spoof a normal laptop.
  try {
    if (navigator.getBattery) {
      Object.defineProperty(navigator, 'getBattery', {
        value: () => Promise.resolve({
          charging: true,
          chargingTime: 0,
          dischargingTime: Infinity,
          level: 1.0,
          onchargingchange: null,
          onchargingtimechange: null,
          ondischargingtimechange: null,
          onlevelchange: null,
          addEventListener: () => {},
          removeEventListener: () => {},
          dispatchEvent: () => false,
        }),
        configurable: true,
        writable: true,
      });
    }
  } catch (_) {}

  // ── 15. Network Information API ───────────────────────────────────────────
  // navigator.connection is undefined in headless; add a realistic value.
  try {
    if (!navigator.connection) {
      Object.defineProperty(navigator, 'connection', {
        get: () => ({
          downlink: 10,
          downlinkMax: Infinity,
          effectiveType: '4g',
          onchange: null,
          rtt: 50,
          saveData: false,
          type: 'wifi',
          addEventListener: () => {},
          removeEventListener: () => {},
          dispatchEvent: () => false,
        }),
        configurable: true,
      });
    }
  } catch (_) {}

})();
`;
}
