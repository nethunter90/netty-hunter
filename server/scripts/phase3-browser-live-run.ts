/**
 * Phase 3 live-path verification — browser-native egress, closing the YELLOW
 * from the two prior handoffs. Real Chromium, real local HTTP servers, real
 * DB-backed ScopeGuard (program id 1149).
 *
 * Cases:
 *  1. direct out-of-scope navigation -> blocked
 *  2. in-scope page referencing an out-of-scope <script src> -> blocked, page still loads
 *  3. NAVIGATION that server-redirects to the excluded host -> blocked AT THE HOP
 *     (the exact case that broke under route.continue() in Phase 1 — re-proven here
 *     as part of the final live run, not just the isolated unit test)
 *  4. rendering fidelity for an in-scope page reconstructed via route.fetch/fulfill:
 *     status, content-type, a custom response header, AND Set-Cookie survive, and the
 *     cookie is actually sent back on a subsequent same-context request.
 *
 * Run: npx tsx scripts/phase3-browser-live-run.ts
 */
import "dotenv/config";
import { readFileSync } from "fs";
import { chromium } from "playwright";
import { installScopeRoute } from "../src/lib/net/scoped-browser-route";

const PROGRAM_ID = 1149;
const EXCLUDED_LOG = "/tmp/claude-1000/-home-kali-Desktop-netty-hunter/9c701b6a-e045-44b9-b400-855c6f8eb116/scratchpad/browser_excluded_access.log";

function excludedHits(): string[] {
  try {
    return readFileSync(EXCLUDED_LOG, "utf-8").split("\n").filter(l => l.trim().length > 0);
  } catch {
    return [];
  }
}

async function main() {
  const browser = await chromium.launch({ headless: true, args: ["--no-sandbox", "--disable-setuid-sandbox"] });
  let pass = true;

  try {
    console.log("=== CASE 1: direct out-of-scope navigation -> BLOCKED ===");
    {
      const context = await browser.newContext();
      const page = await context.newPage();
      await installScopeRoute(page, PROGRAM_ID);
      try {
        await page.goto("http://127.0.0.1:9992/", { timeout: 8000 });
        console.log("RESULT: unexpectedly ALLOWED");
        pass = false;
      } catch (err) {
        console.log(`RESULT: blocked — ${(err as Error).message}`);
      }
      console.log(`Excluded-host hits: ${excludedHits().length} (must be 0)`);
      if (excludedHits().length !== 0) pass = false;
      await context.close();
    }

    console.log("\n=== CASE 2: in-scope page referencing an out-of-scope <script src> -> page loads, script blocked ===");
    {
      const context = await browser.newContext();
      const page = await context.newPage();
      await installScopeRoute(page, PROGRAM_ID);
      const resp = await page.goto("http://localhost:9991/spa-page", { timeout: 8000 });
      console.log(`RESULT: page loaded, status=${resp?.status()}`);
      await page.waitForTimeout(500);
      console.log(`Excluded-host hits: ${excludedHits().length} (must be 0)`);
      if (excludedHits().length !== 0) pass = false;
      await context.close();
    }

    console.log("\n=== CASE 3: navigation that SERVER-REDIRECTS to the excluded host -> BLOCKED AT THE HOP ===");
    console.log("(this is the exact case that silently broke under route.continue() in Phase 1)");
    {
      const context = await browser.newContext();
      const page = await context.newPage();
      await installScopeRoute(page, PROGRAM_ID);
      try {
        await page.goto("http://localhost:9991/redirect-away", { timeout: 8000 });
        console.log("RESULT: unexpectedly ALLOWED — the redirect target was reached");
        pass = false;
      } catch (err) {
        console.log(`RESULT: blocked at the redirect hop — ${(err as Error).message}`);
      }
      console.log(`Excluded-host hits: ${excludedHits().length} (must still be 0)`);
      if (excludedHits().length !== 0) pass = false;
      await context.close();
    }

    console.log("\n=== CASE 4: rendering fidelity through the route.fetch/fulfill reconstruction ===");
    {
      const context = await browser.newContext();
      const page = await context.newPage();
      await installScopeRoute(page, PROGRAM_ID);

      const resp = await page.goto("http://localhost:9991/set-cookie", { timeout: 8000 });
      const status = resp?.status();
      const contentType = resp?.headers()["content-type"];
      const customHeader = resp?.headers()["x-fidelity-marker"];
      const bodyText = await page.textContent("body").catch(() => "");
      console.log(`status=${status}, content-type="${contentType}", x-fidelity-marker="${customHeader}", body="${bodyText}"`);

      const statusOk = status === 200;
      const contentTypeOk = (contentType ?? "").includes("text/html");
      const headerOk = customHeader === "custom-response-header-value";
      const bodyOk = (bodyText ?? "").includes("cookie set");
      console.log(`status preserved: ${statusOk}, content-type preserved: ${contentTypeOk}, custom header preserved: ${headerOk}, body preserved: ${bodyOk}`);
      if (!statusOk || !contentTypeOk || !headerOk || !bodyOk) pass = false;

      // The real test: did the browser's cookie jar actually get the Set-Cookie,
      // and does it resend it automatically on the NEXT request in this context —
      // proving Set-Cookie survived route.fulfill(), not just that the page rendered.
      const resp2 = await page.goto("http://localhost:9991/check-cookie", { timeout: 8000 });
      const bodyText2 = await page.textContent("body").catch(() => "");
      console.log(`Follow-up request (relies on browser's own cookie jar): status=${resp2?.status()}, body="${bodyText2}"`);
      const cookieSurvived = (bodyText2 ?? "").includes("cookie-received: True") || (bodyText2 ?? "").includes("cookie-received: true");
      console.log(cookieSurvived
        ? "PASS — Set-Cookie survived the route.fetch/fulfill reconstruction and the browser resent it correctly"
        : "FAIL — the cookie did NOT survive the proxy reconstruction — this is the fidelity bug class to watch for");
      if (!cookieSurvived) pass = false;

      await context.close();
    }
  } finally {
    await browser.close();
  }

  console.log("\n=== FINAL ===");
  console.log(`Total excluded-host hits across the whole run: ${excludedHits().length}`);
  console.log(pass ? "ALL CASES PASS" : "AT LEAST ONE CASE FAILED — see above");
  process.exit(pass ? 0 : 1);
}

main().catch(err => {
  console.error("Harness error:", err);
  process.exit(1);
});
