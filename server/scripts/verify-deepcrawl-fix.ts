/**
 * In-situ verification for the deepCrawl SPA-route fix (2026-07-03).
 *
 * Runs the REAL deepCrawl() against the live sentprime instance and reports
 * pagesVisited, discovered routes, and whether any of the two independently-
 * planted answer-key surfaces (the original 15-item list's terminal/binary/
 * team/api-key endpoints, and the newly-shared 8-item wifi/desktop-agent
 * list) show up anywhere in the discovered endpoint/route set.
 *
 * Run: npx tsx scripts/verify-deepcrawl-fix.ts
 */
import { deepCrawl } from "../src/lib/tools/js-spa-crawler";

const TARGET = "http://localhost:5000";

// Kali-Web-IDE's actual 8-item answer key (confirmed 2026-07-03) — auth
// bypass, unauthenticated wifi attack endpoints, OS command injection via
// wifi interface param, path traversal via BSSID, unauthenticated/unvalidated
// websocket wifi controls, insecure capture storage, unsanitized projectDir
// in the build orchestrator, prompt/command injection in claudeBuild.
const ANSWER_KEY_SIGNALS = [
  "isAuthenticated", "wifi/interfaces", "wifi/monitor", "wifi/scan", "wifi/captures",
  "airmon-ng", "airodump-ng", "aireplay-ng", "wifi-captures",
  "autonomousBuild", "build-orchestrator", "projectDir", "claudeBuild",
  "dangerously-skip-permissions",
];

async function main() {
  console.log(`Running deepCrawl against ${TARGET} (maxDepth:2, maxPages:20 — same config HunterEngine uses)...\n`);
  const start = Date.now();
  const result = await deepCrawl(TARGET, { maxDepth: 2, maxPages: 20 });
  const ms = Date.now() - start;

  console.log(`Done in ${ms}ms`);
  console.log(`pagesVisited: ${result.pagesVisited}`);
  console.log(`endpointsFound: ${result.endpointsFound.length}`);
  console.log(`siteMap:`);
  for (const s of result.siteMap) {
    console.log(`  depth=${s.depth} linksFound=${s.linksFound}  ${s.url}`);
  }

  console.log(`\n=== Answer-key signal check ===`);
  const allText = JSON.stringify(result.endpointsFound) + JSON.stringify(result.siteMap);
  let anyHit = false;
  for (const sig of ANSWER_KEY_SIGNALS) {
    const hit = allText.toLowerCase().includes(sig.toLowerCase());
    if (hit) anyHit = true;
    console.log(`  ${hit ? "✅ FOUND" : "  absent"}: ${sig}`);
  }

  console.log(anyHit
    ? "\n✅ At least one previously-invisible answer-key surface is now discoverable."
    : "\n❌ Still nothing — the SPA-route extraction alone did not surface these paths. See notes below.");
}

main().catch(err => {
  console.error("Verification failed:", err);
  process.exit(1);
});
