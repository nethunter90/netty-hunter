/**
 * UI trust fix #1 (pause visibility) — Part A: capture the REAL hunt:paused
 * payload the engine emits for both dimensions (budget, auth), against the
 * real Phase-A program (1181), so the frontend fix can be proven against the
 * actual wire contract rather than an assumed shape.
 *
 * This deliberately pre-sets the pause flags rather than exhausting a real
 * LLM budget or dropping a real auth session — HOW the engine reaches
 * budgetPaused/authPaused is already proven live elsewhere (handoff C's
 * budget-escapee-live-proof.ts, blocker #2's auth-expiry-proof.ts). This
 * proof is scoped to what happens FROM there: the emit shape a UI consumer
 * has to parse correctly.
 *
 * Run: npx tsx scripts/pause-payload-capture-proof.ts
 */
import "dotenv/config";
import { pool, db } from "../src/db";
import { programs } from "../src/db/schema";
import { eq } from "drizzle-orm";
import { HunterEngine } from "../src/agents/HunterEngine";

const PROGRAM_ID = 1181;

async function capturePause(setup: (engine: HunterEngine) => void): Promise<Record<string, unknown>> {
  const engine = new HunterEngine();
  (engine as unknown as { state: Record<string, unknown> }).state = {
    sessionId: `pause-capture-${Math.random().toString(36).slice(2)}`,
    targetUrl: "http://localhost:8081/",
    programId: PROGRAM_ID,
    phase: "probe",
    observations: [],
    hypotheses: [],
    probes: [],
    confirmedFindings: [],
    iteration: 2,
    maxIterations: 5,
    budget: { maxRequests: 100, requestsMade: 5, maxTime: 3600, elapsed: 0 },
    corpusEnrichment: false,
    proxyEnabled: false,
    wafBypassEnabled: false,
    automatedScanningEnabled: false,
    discoveredEndpoints: [],
  };
  setup(engine);

  const captured: Record<string, unknown>[] = [];
  engine.on("hunt:paused", (payload: Record<string, unknown>) => captured.push(payload));

  await (engine as unknown as { runLoop: () => Promise<void> }).runLoop();

  if (captured.length !== 1) {
    throw new Error(`Expected exactly one hunt:paused emit, got ${captured.length}`);
  }
  return captured[0];
}

async function main() {
  const [program] = await db.select().from(programs).where(eq(programs.id, PROGRAM_ID)).limit(1);
  if (!program) {
    console.error(`Program ${PROGRAM_ID} not found.`);
    process.exit(1);
  }

  console.log("=== Capturing real hunt:paused payload — BUDGET dimension ===");
  const budgetPayload = await capturePause(engine => {
    (engine as unknown as { budgetPaused: boolean }).budgetPaused = true;
    (engine as unknown as { budgetPausedReason: string }).budgetPausedReason = "call_count";
  });
  console.log(JSON.stringify(budgetPayload, null, 2));

  console.log("\n=== Capturing real hunt:paused payload — AUTH dimension ===");
  const authPayload = await capturePause(engine => {
    (engine as unknown as { authPaused: boolean }).authPaused = true;
    (engine as unknown as { authPausedReason: string }).authPausedReason = "Liveness re-check failed 3 consecutive times (401/403 on a proven-authenticated baseline)";
  });
  console.log(JSON.stringify(authPayload, null, 2));

  // Assertions the frontend fix depends on: the discriminator (budgetDimension
  // present iff budget-dimension pause) and a non-empty human-readable reason.
  let failures = 0;
  const assert = (cond: boolean, label: string) => {
    if (cond) console.log(`  PASS  ${label}`);
    else { failures++; console.log(`  FAIL  ${label}`); }
  };
  console.log("\n=== Wire-contract assertions ===");
  assert(budgetPayload.budgetDimension !== undefined, "budget pause payload carries budgetDimension");
  assert(authPayload.budgetDimension === undefined, "auth pause payload does NOT carry budgetDimension (the discriminator the fix relies on)");
  assert(typeof budgetPayload.reason === "string" && (budgetPayload.reason as string).length > 0, "budget pause payload carries a non-empty reason string");
  assert(typeof authPayload.reason === "string" && (authPayload.reason as string).length > 0, "auth pause payload carries a non-empty reason string");
  assert(typeof authPayload.authReason === "string" && (authPayload.authReason as string).length > 0, "auth pause payload carries authReason with the specific drop cause");

  console.log(failures === 0 ? "\nALL CHECKS PASSED\n" : `\n${failures} CHECK(S) FAILED\n`);

  // Write the two real captured payloads to disk so Part B (the frontend
  // store/bridge proof) consumes REAL server output, not hand-written fixtures.
  const fs = await import("fs");
  fs.writeFileSync(
    "/tmp/claude-1000/-home-kali-Desktop-netty-hunter/84c279e1-2636-4556-879a-b16357627749/scratchpad/pause-payloads.json",
    JSON.stringify({ budgetPayload, authPayload }, null, 2)
  );

  await pool.end();
  process.exit(failures === 0 ? 0 : 1);
}

main().catch(async err => { console.error(err); await pool.end().catch(() => {}); process.exit(1); });
