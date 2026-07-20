/**
 * Playwright Worker
 * Runs browser replay in an isolated worker thread so Playwright's page
 * lifecycle never blocks the main event loop during concurrent verifications.
 *
 * Protocol (all messages are JSON-serialisable):
 *   Main → Worker  { type: 'init' }
 *   Worker → Main  { type: 'ready' }
 *
 *   Main → Worker  { type: 'replay', id: string, result: SerializedSolverResult }
 *   Worker → Main  { type: 'result', id: string, data: ReplayResult }
 *                | { type: 'error',  id: string, message: string }
 *
 *   Main → Worker  { type: 'close' }
 *   Worker → Main  { type: 'closed' }
 */
import { parentPort } from 'worker_threads';
import { chromium, Browser, BrowserContext } from 'playwright';
import { getBrowserLaunchArgs, getFingerprintInitScript, getRandomUserAgent } from '../lib/stealth/browser-fingerprint';
import { installScopeRoute } from '../lib/net/scoped-browser-route';

interface SerializedSolverResult {
  taskId: string;
  endpoint: string;
  vulnClass: string;
  payload: string;
  found: boolean;
  confidence: number;
  request?: string;
  /** This specific replay's program — the context is shared across the
   *  worker's whole lifetime, so scope MUST be resolved per-replay via a
   *  fresh page-level route, never cached from an earlier call. */
  programId?: number;
}

interface ReplayResult {
  confirmed: boolean;
  screenshot?: string;
  consoleAlerts: string[];
  networkRequests: string[];
}

let browser: Browser | null = null;
let context: BrowserContext | null = null;

async function initBrowser(): Promise<void> {
  if (browser) return;
  browser = await chromium.launch({ headless: true, args: getBrowserLaunchArgs() });
  context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    userAgent: getRandomUserAgent(),
    locale: 'en-US',
    timezoneId: 'America/New_York',
    geolocation: { latitude: 40.7128, longitude: -74.0060 },
    colorScheme: 'light',
    reducedMotion: 'no-preference',
    permissions: [],
    extraHTTPHeaders: { 'Accept-Language': 'en-US,en;q=0.9', 'Sec-Ch-Ua-Mobile': '?0' },
  });
  await context.addInitScript(getFingerprintInitScript());
}

async function replay(result: SerializedSolverResult): Promise<ReplayResult> {
  if (!browser || !context) {
    return { confirmed: false, consoleAlerts: [], networkRequests: [] };
  }

  const page = await context.newPage();
  // Browser-native egress chokepoint, bound to THIS replay's programId. A
  // fresh page is created per replay() call (confirmed above), so a
  // page-level route here cannot leak scope between replays for different
  // programs sharing this worker's one long-lived context.
  await installScopeRoute(page, result.programId);
  const consoleAlerts: string[] = [];
  const networkRequests: string[] = [];

  // Execution oracle: resolves the first time injected JS actually runs (sentinel
  // callback or a dialog sink). This is proof of execution — distinct from the
  // payload merely being present in the DOM, which proves nothing about XSS.
  let executed = false;
  let resolveExecution!: (source: string) => void;
  const executionSignal = new Promise<string>(resolve => { resolveExecution = resolve; });
  const markExecuted = (source: string) => {
    if (executed) return;
    executed = true;
    consoleAlerts.push(`XSS_EXECUTED:${source}`);
    resolveExecution(source);
  };

  try {
    // Sentinel binding: any payload that calls window.__xssOracle() proves execution.
    await page.exposeFunction('__xssOracle', () => markExecuted('sentinel'));
    // Bridge the classic dialog sinks into the sentinel so legacy alert(1)-style
    // payloads still register as execution without blocking on a native dialog.
    await page.addInitScript(() => {
      const w = globalThis as unknown as Record<string, unknown> & { __xssOracle?: () => void };
      const fire = () => { try { w.__xssOracle?.(); } catch { /* ignore */ } };
      w.alert = () => fire();
      w.confirm = () => { fire(); return true; };
      w.prompt = () => { fire(); return ''; };
      w.print = () => fire();
    });

    page.on('console', msg => {
      if (msg.type() === 'warning' || msg.type() === 'error' || msg.text().includes('alert')) {
        consoleAlerts.push(msg.text());
      }
    });
    page.on('dialog', async dialog => {
      consoleAlerts.push(`DIALOG:${dialog.type()}:${dialog.message()}`);
      markExecuted('dialog');
      await dialog.accept();
    });
    page.on('request', req => {
      if (req.url().includes('169.254') || req.url().includes('localhost')) {
        networkRequests.push(req.url());
      }
    });

    const url = result.request || `${result.endpoint}?q=${encodeURIComponent(result.payload)}`;
    // 'load' (not domcontentloaded) so subresource error handlers — <img onerror=…>
    // and friends — have actually fired by the time goto resolves.
    await page.goto(url, { timeout: 15000, waitUntil: 'load' });

    const bodyText = ((await page.textContent('body').catch(() => '')) ?? '').toLowerCase();
    const captchaInText = bodyText.includes('captcha') ||
      bodyText.includes('verify you are human') || bodyText.includes('are you a robot');
    const captchaSelectors = [
      '[data-sitekey]', 'iframe[src*="recaptcha"]', 'iframe[src*="hcaptcha"]',
      '.cf-challenge-running', '#challenge-running',
    ];
    const captchaElFound = (await Promise.all(
      captchaSelectors.map(sel => page.$(sel).then(el => el !== null).catch(() => false))
    )).some(Boolean);

    if (captchaInText || captchaElFound) {
      return { confirmed: false, consoleAlerts: ['CAPTCHA_DETECTED'], networkRequests: [] };
    }

    // For XSS, await the execution signal against a bounded deadline instead of
    // sleeping a fixed interval and snapshotting — event-driven on actual execution,
    // so the DCL/subresource timing race disappears. If the payload ran during load,
    // executionSignal is already resolved and this returns immediately.
    let xssExecuted = false;
    if (result.vulnClass === 'xss') {
      const EXEC_DEADLINE_MS = 4000;
      const outcome = await Promise.race([
        executionSignal.then(() => 'executed' as const),
        page.waitForTimeout(EXEC_DEADLINE_MS).then(() => 'timeout' as const),
      ]);
      xssExecuted = outcome === 'executed';
    } else {
      await page.waitForTimeout(2000);
    }

    const screenshotBuffer = await page.screenshot({ type: 'png' });
    const screenshot = screenshotBuffer.toString('base64');

    let confirmed = false;
    if (result.vulnClass === 'xss') {
      // Execution-only oracle. Presence of the payload in the DOM is NOT confirmation —
      // it conflates reflection with execution and is wrong in both directions.
      confirmed = xssExecuted;
    } else if (result.vulnClass === 'ssrf') {
      confirmed = networkRequests.length > 0;
    } else if (result.vulnClass === 'open_redirect') {
      const currentUrl = page.url();
      confirmed = currentUrl.includes('evil.com') || !currentUrl.includes(new URL(result.endpoint).hostname);
    } else {
      confirmed = false; // L3 not applicable for this vuln class; verdict uses L2/L4
    }

    return { confirmed, screenshot, consoleAlerts, networkRequests };
  } catch (err) {
    return { confirmed: false, consoleAlerts, networkRequests };
  } finally {
    await page.close();
  }
}

parentPort?.on('message', async (msg: any) => {
  if (msg.type === 'init') {
    try {
      await initBrowser();
      parentPort?.postMessage({ type: 'ready' });
    } catch (err) {
      // A failed launch must NOT report ready — the main thread's init handshake
      // (VerifierAgent.ts) treats 'ready' as "Layer 3 is live," so faking it here
      // let a browser that never launched silently reject every XSS finding as if
      // a real replay had tested and disproved it.
      parentPort?.postMessage({ type: 'error', id: 'init', message: String(err) });
    }
  } else if (msg.type === 'replay') {
    try {
      const data = await replay(msg.result as SerializedSolverResult);
      parentPort?.postMessage({ type: 'result', id: msg.id, data });
    } catch (err) {
      parentPort?.postMessage({ type: 'error', id: msg.id, message: String(err) });
    }
  } else if (msg.type === 'close') {
    if (browser) {
      await browser.close().catch(() => {});
      browser = null;
      context = null;
    }
    parentPort?.postMessage({ type: 'closed' });
    process.exit(0);
  }
});
