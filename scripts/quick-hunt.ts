/**
 * quick-hunt.ts — minimal end-to-end smoke test for HunterEngine.
 * Creates throwaway DB records, runs one hunt loop, prints what happened.
 * Run: cd server && npx tsx ../scripts/quick-hunt.ts [targetUrl]
 */
import "dotenv/config";
import { db } from "../server/src/db";
import { programs, campaigns, targets } from "../server/src/db/schema";
import { HunterEngine } from "../server/src/agents/HunterEngine";

const TARGET = process.argv[2] ?? "http://localhost:3001";

async function main() {
  console.log(`\n[quick-hunt] target: ${TARGET}`);
  console.log("[quick-hunt] creating throwaway program + campaign...");

  const [prog] = await db.insert(programs).values({
    name: "quick-hunt-smoke-test",
    platform: "hackerone",
    programHandle: "smoke-test",
    active: true,
    scope: [`*.${new URL(TARGET).hostname}`],
    outOfScope: [],
    maxPayout: 0,
    minPayout: 0,
  }).returning();

  const [camp] = await db.insert(campaigns).values({
    programId: prog.id,
    name: "quick-hunt-smoke",
    goal: "smoke test — confirm hunt loop completes",
    status: "running",
    huntMode: "forward",
    strategy: {},
    budget: { maxRequests: 50, maxTime: 120 },
    startedAt: new Date(),
  }).returning();

  const [tgt] = await db.insert(targets).values({
    programId: prog.id,
    url: TARGET,
    type: "web",
    status: "scanning",
  }).returning();

  console.log(`[quick-hunt] program=${prog.id} campaign=${camp.id} target=${tgt.id}`);
  console.log("[quick-hunt] starting hunt (max 2 iterations, 50 requests, 2 min)...\n");

  const engine = new HunterEngine();
  const events: string[] = [];

  const stamp = () => `[${((Date.now()-started)/1000).toFixed(1)}s]`;
  engine.on("hunt:phase",         d => { const msg = `  ${stamp()} PHASE       ${d.phase} (iter ${d.iteration})`; console.log(msg); events.push(msg); });
  engine.on("hunt:observations",  d => { const msg = `  ${stamp()} OBSERVE     ${d.count} observations`; console.log(msg); events.push(msg); });
  engine.on("hunt:hypotheses",    d => { const msg = `  ${stamp()} HYPOTHESIZE ${d.hypotheses?.length ?? 0} hypotheses`; console.log(msg); events.push(msg); });
  engine.on("hunt:probing",       d => { const msg = `  ${stamp()} PROBE       ${d.tool} → ${d.endpoint}`; console.log(msg); events.push(msg); });
  engine.on("hunt:probe_result",  d => { const msg = `  ${stamp()} RESULT      success=${d.success} (${d.duration}ms)`; console.log(msg); events.push(msg); });
  engine.on("hunt:finding_confirmed", d => { const msg = `  ${stamp()} FINDING *** ${d.finding?.vulnType} confidence=${d.finding?.confidence}`; console.log(msg); events.push(msg); });
  engine.on("hunt:error",         d => { const msg = `  ${stamp()} ERROR       ${d.error}`; console.error(msg); events.push(msg); });
  // Extra verbosity for diagnosing hangs
  ["hunt:secrets_found","hunt:ws_vulns","hunt:bucket_exposed","hunt:proto_pollution",
   "hunt:host_header","hunt:crlf","hunt:cookie_flags","hunt:params_discovered",
   "hunt:oauth_vulns","hunt:mass_assignment","hunt:business_logic","hunt:2fa_bypass",
   "hunt:jwt_vulns","hunt:open_redirect","hunt:xxe_found","hunt:graphql_schema",
   "hunt:cve_seeded","hunt:changes_detected",
  ].forEach(ev => engine.on(ev, () => console.log(`  ${stamp()} EVENT       ${ev}`)));

  const started = Date.now();

  await new Promise<void>((resolve) => {
    const timeout = setTimeout(() => {
      console.log(`\n[quick-hunt] TIMEOUT (8min) — hunt did not complete`);
      resolve();
    }, 480_000);

    engine.once("hunt:complete", d => {
      clearTimeout(timeout);
      console.log(`\n[quick-hunt] COMPLETE — findings=${d.findings} iterations=${d.iterations} elapsed=${((Date.now()-started)/1000).toFixed(1)}s`);
      resolve();
    });
    engine.once("hunt:error", () => { clearTimeout(timeout); resolve(); });

    engine.startHunt({
      targetUrl: TARGET,
      programId: prog.id,
      campaignId: camp.id,
      targetId: tgt.id,
      maxIterations: 2,
      budget: { maxRequests: 50, maxTime: 120 },
    }).catch(err => {
      console.error("[quick-hunt] startHunt threw:", err.message);
      clearTimeout(timeout);
      resolve();
    });
  });

  console.log(`\n[quick-hunt] summary: ${events.length} events emitted`);
  const phases = events.filter(e => e.includes("PHASE"));
  console.log(`[quick-hunt] phases reached: ${phases.map(e => e.trim().split(/\s+/)[1]).join(" → ")}`);
  process.exit(0);
}

main().catch(err => {
  console.error("[quick-hunt] fatal:", err.message);
  process.exit(1);
});
