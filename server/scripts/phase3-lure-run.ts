/**
 * Phase 3 live-path verification — intentional out-of-scope lure.
 *
 * Real network traffic, real DB-backed scope (program id 1146: "Phase3 Lure
 * Test", scope=["localhost:9991"], outOfScope=["127.0.0.1:9992"]), real
 * ScopeGuard/scopedHttp code (imported directly, not mocked). Two real local
 * HTTP servers: 9991 (in-scope) and 9992 (excluded — logs every hit it
 * receives to excluded_access.log so containment failures are independently
 * observable, not self-reported by the guard).
 *
 * Run: npx tsx scripts/phase3-lure-run.ts
 */
import "dotenv/config";
import { readFileSync } from "fs";
import { scopedHttp, OutOfScopeError } from "../src/lib/net/scoped-http";
import { HunterEngine } from "../src/agents/HunterEngine";
import { deepCrawl } from "../src/lib/tools/js-spa-crawler";

const PROGRAM_ID = 1146;
const EXCLUDED_LOG = "/tmp/claude-1000/-home-kali-Desktop-netty-hunter/9c701b6a-e045-44b9-b400-855c6f8eb116/scratchpad/excluded_access.log";

function excludedHitCount(): number {
  try {
    return readFileSync(EXCLUDED_LOG, "utf-8").split("\n").filter(l => l.trim().length > 0).length;
  } catch {
    return 0;
  }
}

async function main() {
  console.log("=== TEST 1: direct request to in-scope host → must be ALLOWED ===");
  try {
    const resp = await scopedHttp.get("http://localhost:9991/", {}, PROGRAM_ID);
    console.log(`RESULT: allowed, status=${resp.status}, body=${JSON.stringify(resp.data)}`);
  } catch (err) {
    console.log(`RESULT: unexpectedly BLOCKED — ${(err as Error).message}`);
  }

  console.log("\n=== TEST 2: direct request to the EXCLUDED host → must be BLOCKED ===");
  try {
    const resp = await scopedHttp.get("http://127.0.0.1:9992/", {}, PROGRAM_ID);
    console.log(`RESULT: unexpectedly ALLOWED — status=${resp.status}`);
  } catch (err) {
    if (err instanceof OutOfScopeError) {
      console.log(`RESULT: blocked as OutOfScopeError — reason: ${err.reason}`);
    } else {
      console.log(`RESULT: blocked, but wrong error type — ${(err as Error).message}`);
    }
  }
  console.log(`Excluded-host hit count so far: ${excludedHitCount()} (must be 0)`);

  console.log("\n=== TEST 3: request to in-scope host that REDIRECTS to the excluded host → must be BLOCKED AT THE HOP ===");
  try {
    const resp = await scopedHttp.get("http://localhost:9991/redirect-away", { validateStatus: () => true }, PROGRAM_ID);
    console.log(`RESULT: unexpectedly ALLOWED — status=${resp.status}`);
  } catch (err) {
    if (err instanceof OutOfScopeError) {
      console.log(`RESULT: blocked as OutOfScopeError — reason: ${err.reason}`);
    } else {
      console.log(`RESULT: blocked, but wrong error type — ${(err as Error).message}`);
    }
  }
  console.log(`Excluded-host hit count after redirect test: ${excludedHitCount()} (must still be 0)`);

  console.log("\n=== TEST 4a: HunterEngine.probeDeserialize() with scraped content referencing the excluded absolute URL ===");
  console.log("(HunterEngine.ts:3689-3691 — new URL(match[2], baseUrl))");
  const engine = new HunterEngine() as unknown as {
    state: { observations: unknown[]; programId: number; targetUrl: string };
    probeDeserialize(baseUrl: string): Promise<{ found: boolean; output: string; endpoint: string; flagValues: string[]; duration: number }>;
    authHeaders: Record<string, string>;
  };
  const scrapedPage = await scopedHttp.get("http://localhost:9991/scrape-target", {}, PROGRAM_ID);
  engine.state = {
    observations: [{ rawOutput: String(scrapedPage.data) }],
    programId: PROGRAM_ID,
    targetUrl: "http://localhost:9991/",
  };
  engine.authHeaders = {};
  const result = await engine.probeDeserialize("http://localhost:9991/");
  console.log(`RESULT: probeDeserialize returned found=${result.found}`);
  console.log(`Excluded-host hit count after probeDeserialize: ${excludedHitCount()} (0 expected either way — see the finding-correction note below)`);
  console.log(
    "NOTE: empirically verified (scripts output, separate from this run) that this regex's own prefix " +
    "(`[^\"'/\\s]*`, which excludes '/') structurally prevents match[2] from ever resolving to a genuinely " +
    "absolute, off-origin http(s) URL for realistic scraped content — the earliest '/' before the pattern " +
    "word always gets consumed as the delimiter, stripping any 'http://' or '//' prefix. The originally " +
    "flagged leak at this exact regex is corrected: not realistically reachable. scopedHttp migration here " +
    "still stands as defense-in-depth regardless."
  );

  console.log("\n=== TEST 4b: js-spa-crawler regexFallbackCrawl — a genuinely absolute <script src> is the realistic version of this leak ===");
  console.log("(js-spa-crawler.ts resolveScriptUrl(): new URL(src, pageUrl), where src comes verbatim from <script src=\"...\"> with NO slash-exclusion constraint)");
  const crawlResult = await deepCrawl("http://localhost:9991/spa-page", { maxDepth: 0, maxPages: 1, programId: PROGRAM_ID });
  console.log(`RESULT: deepCrawl completed — jsFilesScanned=${crawlResult.jsFilesScanned}, endpointsFound=${crawlResult.endpointsFound.length}`);
  console.log(`Excluded-host hit count after deepCrawl: ${excludedHitCount()} (must still be 0 — the absolute script src must have been blocked before dispatch)`);

  console.log("\n=== FINAL: total excluded-host hits across the entire run ===");
  const total = excludedHitCount();
  console.log(`Total hits: ${total}`);
  console.log(total === 0 ? "PASS — zero out-of-scope requests left the machine" : "FAIL — containment breach, see excluded_access.log");
  process.exit(total === 0 ? 0 : 1);
}

main().catch(err => {
  console.error("Harness error:", err);
  process.exit(1);
});
