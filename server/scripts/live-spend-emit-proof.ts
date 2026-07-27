/**
 * UI trust fix #6 (live cost during a run) -- proof.
 *
 * Records two real calls' worth of spend into ClaudeClient's ledger for a
 * session, then runs the real runLoop() iteration-top code path (via a
 * one-iteration engine configured to hit maxIterations=1 immediately after
 * the spend emit) and captures the real hunt:spend_update payload, checking
 * it matches ClaudeClient.getSpend()/getCallCount() for that session exactly
 * -- not a reimplementation.
 *
 * Run: npx tsx scripts/live-spend-emit-proof.ts
 */
import "dotenv/config";
import { pool, db } from "../src/db";
import { programs } from "../src/db/schema";
import { eq } from "drizzle-orm";
import { HunterEngine } from "../src/agents/HunterEngine";
import { ClaudeClient } from "../src/lib/claude-client";

const PROGRAM_ID = 1181;

let failures = 0;
function assert(cond: boolean, label: string): void {
  if (cond) console.log(`  PASS  ${label}`);
  else { failures++; console.log(`  FAIL  ${label}`); }
}

async function main() {
  const [program] = await db.select().from(programs).where(eq(programs.id, PROGRAM_ID)).limit(1);
  if (!program) { console.error(`Program ${PROGRAM_ID} not found.`); process.exit(1); }

  const sessionId = `live-spend-proof-${Math.random().toString(36).slice(2)}`;

  // Seed two fake usage records directly into the real ClaudeClient ledger --
  // recordSpend is private, so use the same recordExternalCall() path the
  // Claude-bridge subprocess spend accounting uses (a real, exported entry
  // point into the same ledger), then confirm getSpend/getCallCount reflect it.
  ClaudeClient.recordExternalCall(sessionId, 1200, 400, "claude-sonnet-5");
  ClaudeClient.recordExternalCall(sessionId, 800, 250, "claude-sonnet-5");

  const groundTruthSpend = ClaudeClient.getSpend(sessionId);
  const groundTruthCalls = ClaudeClient.getCallCount(sessionId);
  console.log("Ground truth from ClaudeClient ledger:", { costUsd: groundTruthSpend.costUsd, callCount: groundTruthCalls });
  assert(groundTruthCalls === 2, `ledger shows 2 calls recorded (got ${groundTruthCalls})`);
  assert(groundTruthSpend.costUsd > 0, `ledger shows nonzero cost (got ${groundTruthSpend.costUsd})`);

  const engine = new HunterEngine();
  (engine as unknown as { state: Record<string, unknown> }).state = {
    sessionId,
    targetUrl: "http://localhost:8081/",
    programId: PROGRAM_ID,
    phase: "observe",
    observations: [],
    hypotheses: [],
    probes: [],
    confirmedFindings: [],
    iteration: 0,
    // maxIterations: 1 -- the while-loop condition (iteration < maxIterations)
    // is false on entry, so runLoop() exits immediately WITHOUT reaching the
    // per-iteration body where the spend_update emit lives. Set to 1 so the
    // FIRST iteration's top-of-loop block (where hunt:phase/hunt:spend_update
    // are emitted) runs, then the loop naturally exits after iteration 1.
    maxIterations: 1,
    budget: { maxRequests: 100, requestsMade: 0, maxTime: 3600, elapsed: 0 },
    corpusEnrichment: false,
    proxyEnabled: false,
    wafBypassEnabled: false,
    automatedScanningEnabled: false,
    discoveredEndpoints: [],
  };

  const captured: Record<string, unknown>[] = [];
  engine.on("hunt:spend_update", (payload: Record<string, unknown>) => captured.push(payload));
  // The spend_update emit sits at the TOP of the loop body, synchronously
  // before the observe()/hypothesize()/probe()/update() dispatch -- so it's
  // enqueued well before the (slow, real-network) OBSERVE phase finishes.
  // Don't await full completion (OBSERVE against a real target takes many
  // seconds of paced requests) -- start the loop, give it a moment to reach
  // the emit, then abort so the background work doesn't run past this proof.
  const runPromise = (engine as unknown as { runLoop: () => Promise<void> }).runLoop().catch(() => {});
  await new Promise(r => setTimeout(r, 300));
  (engine as unknown as { aborted: boolean }).aborted = true;

  assert(captured.length >= 1, `hunt:spend_update fired at least once during the loop (got ${captured.length})`);
  if (captured.length >= 1) {
    const payload = captured[0];
    assert(payload.sessionId === sessionId, `payload carries the correct sessionId`);
    assert(payload.costUsd === groundTruthSpend.costUsd, `payload.costUsd (${payload.costUsd}) exactly matches ClaudeClient.getSpend().costUsd (${groundTruthSpend.costUsd}) -- reads the live ledger, not a snapshot`);
    assert(payload.callCount === groundTruthCalls, `payload.callCount (${payload.callCount}) exactly matches ClaudeClient.getCallCount() (${groundTruthCalls})`);
  }

  // Now record a THIRD call and re-run to prove it climbs (not a one-shot).
  ClaudeClient.recordExternalCall(sessionId, 500, 150, "claude-sonnet-5");
  const secondGroundTruth = ClaudeClient.getSpend(sessionId);
  const secondGroundTruthCalls = ClaudeClient.getCallCount(sessionId);
  assert(secondGroundTruthCalls === 3, `ledger now shows 3 calls after a third recorded call (got ${secondGroundTruthCalls})`);
  assert(secondGroundTruth.costUsd > groundTruthSpend.costUsd, `ledger cost climbed after the third call (${groundTruthSpend.costUsd} -> ${secondGroundTruth.costUsd})`);

  (engine as unknown as { state: { iteration: number; maxIterations: number }; aborted: boolean }).state.iteration = 0;
  (engine as unknown as { state: { maxIterations: number } }).state.maxIterations = 1;
  (engine as unknown as { aborted: boolean }).aborted = false;
  captured.length = 0;
  const runPromise2 = (engine as unknown as { runLoop: () => Promise<void> }).runLoop().catch(() => {});
  await new Promise(r => setTimeout(r, 300));
  (engine as unknown as { aborted: boolean }).aborted = true;
  assert(captured.length >= 1 && captured[0].costUsd === secondGroundTruth.costUsd,
    `second emit reflects the climbed total (got ${captured[0]?.costUsd}, expected ${secondGroundTruth.costUsd}) -- confirms this is a LIVE read each iteration, not cached at engine construction`);

  console.log(failures === 0 ? "\nALL CHECKS PASSED\n" : `\n${failures} CHECK(S) FAILED\n`);
  await pool.end();
  // Background OBSERVE work from both runLoop() invocations may still be
  // in flight (real paced HTTP probes) -- this proof only needs the emit,
  // already captured above, so exit rather than waiting it out.
  process.exit(failures === 0 ? 0 : 1);
}

main().catch(async err => { console.error(err); await pool.end().catch(() => {}); process.exit(1); });
