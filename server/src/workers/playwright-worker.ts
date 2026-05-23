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

interface SerializedSolverResult {
  taskId: string;
  endpoint: string;
  vulnClass: string;
  payload: string;
  found: boolean;
  confidence: number;
  request?: string;
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
  const consoleAlerts: string[] = [];
  const networkRequests: string[] = [];

  try {
    page.on('console', msg => {
      if (msg.type() === 'warning' || msg.type() === 'error' || msg.text().includes('alert')) {
        consoleAlerts.push(msg.text());
      }
    });
    page.on('dialog', async dialog => {
      consoleAlerts.push(`DIALOG:${dialog.type()}:${dialog.message()}`);
      await dialog.accept();
    });
    page.on('request', req => {
      if (req.url().includes('169.254') || req.url().includes('localhost')) {
        networkRequests.push(req.url());
      }
    });

    const url = result.request || `${result.endpoint}?q=${encodeURIComponent(result.payload)}`;
    await page.goto(url, { timeout: 15000, waitUntil: 'domcontentloaded' });

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

    await page.waitForTimeout(2000);
    const screenshotBuffer = await page.screenshot({ type: 'png' });
    const screenshot = screenshotBuffer.toString('base64');

    let confirmed = false;
    if (result.vulnClass === 'xss') {
      confirmed = consoleAlerts.some(a => a.includes('DIALOG:alert') || a.includes('alert('));
      if (!confirmed) {
        const content = await page.content();
        confirmed = content.includes(result.payload);
      }
    } else if (result.vulnClass === 'ssrf') {
      confirmed = networkRequests.length > 0;
    } else if (result.vulnClass === 'open_redirect') {
      const currentUrl = page.url();
      confirmed = currentUrl.includes('evil.com') || !currentUrl.includes(new URL(result.endpoint).hostname);
    } else {
      confirmed = result.found;
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
      parentPort?.postMessage({ type: 'ready' }); // still signal ready; replay will return empty
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
