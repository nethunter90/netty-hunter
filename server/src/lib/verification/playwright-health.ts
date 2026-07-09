/**
 * Startup Playwright health check — launches a real Chromium instance
 * independently of VerifierAgent's worker, so a broken browser (missing
 * binary, missing system deps, sandbox/permission issue) shows up loudly
 * in the startup log instead of being discovered mid-hunt when Layer 3
 * silently goes offline.
 */
import { chromium, type Browser } from "playwright";
import { getBrowserLaunchArgs } from "../stealth/browser-fingerprint";

const HEALTH_CHECK_TIMEOUT_MS = 15_000;

export async function checkPlaywrightHealth(): Promise<{ ok: boolean; error?: string }> {
  let browser: Browser | null = null;
  try {
    browser = await Promise.race([
      chromium.launch({ headless: true, args: getBrowserLaunchArgs() }),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`Launch timed out after ${HEALTH_CHECK_TIMEOUT_MS / 1000}s`)), HEALTH_CHECK_TIMEOUT_MS)
      ),
    ]);
    const page = await browser.newPage();
    await page.goto("about:blank");
    await page.close();
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
}
