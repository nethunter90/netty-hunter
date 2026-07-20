/**
 * Phase 1 adversarial test set — browser-native (Playwright) egress chokepoint.
 * Real Chromium, real local HTTP servers, real DB-backed ScopeGuard. Cases 1-6
 * per the browser-egress handoff.
 *
 * Run: npx tsx scripts/phase1-browser-lure-tests.ts
 */
import "dotenv/config";
import { readFileSync } from "fs";
import { chromium } from "playwright";
import { installScopeRoute } from "../src/lib/net/scoped-browser-route";

const PROGRAM_A = 1147; // scope=["localhost:9991"], outOfScope=["127.0.0.1:9992"]
const NONEXISTENT_PROGRAM = 999999; // valid positive int, no such DB row — real internal throw

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
    console.log("=== TEST 1: in-scope navigation → ALLOWED ===");
    {
      const context = await browser.newContext();
      const page = await context.newPage();
      await installScopeRoute(page, PROGRAM_A);
      try {
        const resp = await page.goto("http://localhost:9991/", { timeout: 8000 });
        console.log(`RESULT: navigation succeeded, status=${resp?.status()}`);
      } catch (err) {
        console.log(`RESULT: unexpectedly BLOCKED — ${(err as Error).message}`);
        pass = false;
      }
      await context.close();
    }

    console.log("\n=== TEST 2: out-of-scope navigation → ABORTED ===");
    {
      const context = await browser.newContext();
      const page = await context.newPage();
      await installScopeRoute(page, PROGRAM_A);
      try {
        await page.goto("http://127.0.0.1:9992/", { timeout: 8000 });
        console.log("RESULT: unexpectedly ALLOWED — navigation succeeded");
        pass = false;
      } catch (err) {
        console.log(`RESULT: navigation aborted as expected — ${(err as Error).message}`);
      }
      console.log(`Excluded-host hits so far: ${excludedHits().length} (must be 0)`);
      if (excludedHits().length !== 0) pass = false;
      await context.close();
    }

    console.log("\n=== TEST 3: in-scope page referencing an out-of-scope <script src> → page loads, script aborted ===");
    {
      const context = await browser.newContext();
      const page = await context.newPage();
      await installScopeRoute(page, PROGRAM_A);
      const consoleErrors: string[] = [];
      page.on("console", msg => { if (msg.type() === "error") consoleErrors.push(msg.text()); });
      try {
        const resp = await page.goto("http://localhost:9991/spa-page", { timeout: 8000 });
        console.log(`RESULT: page navigation succeeded, status=${resp?.status()}`);
      } catch (err) {
        console.log(`RESULT: unexpectedly BLOCKED at navigation — ${(err as Error).message}`);
        pass = false;
      }
      await page.waitForTimeout(500); // let the aborted script request settle
      console.log(`Excluded-host hits after script-src page load: ${excludedHits().length} (must be 0 — the script fetch must have been aborted, not the page navigation)`);
      if (excludedHits().length !== 0) pass = false;
      await context.close();
    }

    console.log("\n=== TEST 4: navigation that server-redirects to an out-of-scope host → ABORTED at the hop ===");
    {
      const context = await browser.newContext();
      const page = await context.newPage();
      await installScopeRoute(page, PROGRAM_A);
      try {
        await page.goto("http://localhost:9991/redirect-away", { timeout: 8000 });
        console.log("RESULT: unexpectedly ALLOWED — navigation to the redirect target succeeded");
        pass = false;
      } catch (err) {
        console.log(`RESULT: aborted as expected — ${(err as Error).message}`);
      }
      console.log(`Excluded-host hits after redirect test: ${excludedHits().length} (must still be 0)`);
      if (excludedHits().length !== 0) pass = false;
      await context.close();
    }

    console.log("\n=== TEST 5: ScopeGuard throws internally (nonexistent programId) → fail CLOSED ===");
    {
      const context = await browser.newContext();
      const page = await context.newPage();
      await installScopeRoute(page, NONEXISTENT_PROGRAM);
      try {
        await page.goto("http://localhost:9991/", { timeout: 8000 });
        console.log("RESULT: unexpectedly ALLOWED despite guard error");
        pass = false;
      } catch (err) {
        console.log(`RESULT: aborted (fail-closed) as expected — ${(err as Error).message}`);
      }
      await context.close();
    }

    console.log("\n=== TEST 6a: offensive route modification LANDS on the dispatched request after falling back to the scope route ===");
    {
      const context = await browser.newContext();
      const page = await context.newPage();
      await installScopeRoute(page, PROGRAM_A); // registered FIRST — runs LAST, has final say
      // Emulates LogicExploitAgent's intercept_request tool exactly: registered
      // SECOND (after the scope route), modifies a header, then falls back.
      await page.route("**/echo-header", async (route) => {
        const req = route.request();
        const headers = { ...req.headers(), "x-netty-marker": "OFFENSIVE_MODIFICATION_APPLIED" };
        await route.fallback({ headers });
      });
      const resp = await page.goto("http://localhost:9991/echo-header", { timeout: 8000 });
      const body = await page.textContent("body").catch(() => "");
      console.log(`RESULT: status=${resp?.status()}, body="${body}"`);
      const modificationLanded = (body ?? "").includes("OFFENSIVE_MODIFICATION_APPLIED");
      console.log(modificationLanded
        ? "PASS — the offensive header modification reached the server (fallback() chain intact)"
        : "FAIL — the offensive modification did NOT reach the server — fallback() chain broken");
      if (!modificationLanded) pass = false;
      await context.close();
    }

    console.log("\n=== TEST 6b: same offensive route installed, but target is OUT of scope → scope route still wins (abort) ===");
    {
      const context = await browser.newContext();
      const page = await context.newPage();
      await installScopeRoute(page, PROGRAM_A);
      await page.route("**/*", async (route) => {
        const req = route.request();
        const headers = { ...req.headers(), "x-netty-marker": "OFFENSIVE_MODIFICATION_APPLIED" };
        await route.fallback({ headers });
      });
      try {
        await page.goto("http://127.0.0.1:9992/", { timeout: 8000 });
        console.log("RESULT: unexpectedly ALLOWED — offensive route clobbered the scope route");
        pass = false;
      } catch (err) {
        console.log(`RESULT: still aborted despite the offensive route being installed — ${(err as Error).message}`);
      }
      console.log(`Excluded-host hits after test 6b: ${excludedHits().length} (must still be 0 — proves scope has final say over an offensive modify-and-fallback route)`);
      if (excludedHits().length !== 0) pass = false;
      await context.close();
    }
  } finally {
    await browser.close();
  }

  console.log("\n=== FINAL ===");
  console.log(`Total excluded-host hits across the whole run: ${excludedHits().length}`);
  console.log(pass ? "ALL TESTS PASS" : "AT LEAST ONE TEST FAILED — see above");
  process.exit(pass ? 0 : 1);
}

main().catch(err => {
  console.error("Harness error:", err);
  process.exit(1);
});
