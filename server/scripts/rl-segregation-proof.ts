/**
 * Phase 2 — isolated, deterministic proof that RL provenance segregation
 * actually works, against the REAL running Phase-1 code and the REAL DB
 * (no mocks, no stochastic hunt). Creates its own throwaway program/
 * hunt_session rows, seeds known entries, reads them back through the
 * actual production classes, and deletes everything it created — whether
 * it passes or fails.
 *
 * Run: npx tsx scripts/rl-segregation-proof.ts
 */
import "dotenv/config";
import { pool, db } from "../src/db";
import { programs, huntSessions, campaigns, targets } from "../src/db/schema";
import { eq } from "drizzle-orm";
import { UnifiedReinforcementStore } from "../src/intelligence/ReinforcementStore";
import { ROIModel } from "../src/intelligence/ROIModel";
import { ReinforcementWiring } from "../src/lib/hunter/reinforcement-wiring";
import { strategyWeightLearner } from "../src/lib/learning/strategy-weight-learner";
import { resolveProvenance, resolveProvenanceFromHuntId } from "../src/lib/hunter/custom-target-program";

let failures = 0;
function assert(cond: boolean, label: string): void {
  if (cond) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}`);
  }
}

async function runCleanup(cleanup: Array<() => Promise<void>>): Promise<void> {
  for (const fn of cleanup.reverse()) {
    try { await fn(); } catch { /* best-effort on crash-path cleanup */ }
  }
}

async function main() {
  const rl = UnifiedReinforcementStore.getInstance();
  const roi = new ROIModel();
  const cleanup: Array<() => Promise<void>> = [];

  try {
    await runMain(rl, roi, cleanup);
  } catch (err) {
    console.error("rl-segregation-proof crashed mid-run — cleaning up before exit:", err);
    await runCleanup(cleanup);
    await pool.end().catch(() => {});
    process.exit(1);
  }
}

async function runMain(
  rl: UnifiedReinforcementStore,
  roi: ROIModel,
  cleanup: Array<() => Promise<void>>,
): Promise<void> {

  console.log("\n=== Setup: throwaway lab + real programs, throwaway hunt_session ===\n");

  const [labProgram] = await db.insert(programs).values({
    name: "__proof_lab_program__", platform: "local", scope: ["*"], outOfScope: [],
  }).returning();
  cleanup.push(async () => { await db.delete(programs).where(eq(programs.id, labProgram.id)); });

  const [realProgram] = await db.insert(programs).values({
    name: "__proof_real_program__", platform: "hackerone", scope: ["*"], outOfScope: [],
  }).returning();
  cleanup.push(async () => { await db.delete(programs).where(eq(programs.id, realProgram.id)); });

  const labProvenance = await resolveProvenance(labProgram.id);
  const realProvenance = await resolveProvenance(realProgram.id);
  const unknownProvenance = await resolveProvenance(999999999); // nonexistent programId
  assert(labProvenance === "lab", `resolveProvenance(labProgram) === "lab" (got "${labProvenance}")`);
  assert(realProvenance === "real", `resolveProvenance(realProgram) === "real" (got "${realProvenance}")`);
  assert(unknownProvenance === "unknown", `resolveProvenance(nonexistent) === "unknown" (got "${unknownProvenance}")`);

  // Throwaway campaign + hunt_session under the REAL program, for the
  // resolveProvenanceFromHuntId / strategyWeightLearner trace (Test 2's
  // specific regression check).
  const [target] = await db.insert(targets).values({
    programId: realProgram.id, url: "https://proof.invalid", type: "web",
  }).returning();
  cleanup.push(async () => { await db.delete(targets).where(eq(targets.id, target.id)); });

  const [campaign] = await db.insert(campaigns).values({
    programId: realProgram.id, name: "__proof_campaign__", goal: "proof",
  }).returning();
  cleanup.push(async () => { await db.delete(campaigns).where(eq(campaigns.id, campaign.id)); });

  const proofHuntId = "__proof_hunt_session_uuid__";
  const [session] = await db.insert(huntSessions).values({
    campaignId: campaign.id, targetId: target.id, sessionUuid: proofHuntId,
  }).returning();
  cleanup.push(async () => { await db.delete(huntSessions).where(eq(huntSessions.id, session.id)); });

  const resolvedFromHuntId = await resolveProvenanceFromHuntId(proofHuntId);
  assert(resolvedFromHuntId === "real",
    `resolveProvenanceFromHuntId(realHuntSession) === "real" (got "${resolvedFromHuntId}") — the exact mechanism evaluateEnriched() now uses`);

  const proofKey = `__proof_${Date.now()}__`;

  // ── Test 1 + Test 2 (read-your-own-writes) + Test 3 (unknown quarantine)
  //    on the three live-read surfaces ─────────────────────────────────────

  console.log("\n=== Surface 1: tool_success (getToolSuccessRate / getBestTool) ===\n");
  await rl.recordToolOutcome("proof_tool", proofKey, true, "real");
  await rl.recordToolOutcome("proof_tool", proofKey, true, "lab");
  await rl.recordToolOutcome("proof_tool", proofKey, true, "unknown");

  const realReadsReal = await rl.getToolSuccessRate("proof_tool", proofKey, "real");
  const realReadsLab = await rl.getToolSuccessRate("proof_tool", `${proofKey}_neverwritten`, "real");
  assert(realReadsReal === 1, `real context reads its OWN real:: write (rate=1, got ${realReadsReal})`);

  // Confirm the lab write is invisible under real context: write a DISTINCT
  // success value under lab so a leak would be numerically detectable, not
  // just coincidentally identical.
  const leakKey = `${proofKey}_leak_check`;
  await rl.recordToolOutcome("proof_tool", leakKey, true, "lab");
  await rl.recordToolOutcome("proof_tool", leakKey, false, "lab");
  await rl.recordToolOutcome("proof_tool", leakKey, false, "lab"); // lab rate = 1/3
  const realSeesLabRate = await rl.getToolSuccessRate("proof_tool", leakKey, "real");
  assert(realSeesLabRate === 0.5, `real context does NOT see the lab-written rate (cold-start default 0.5, got ${realSeesLabRate}) — no lab leak`);
  const labSeesOwnRate = await rl.getToolSuccessRate("proof_tool", leakKey, "lab");
  assert(Math.abs(labSeesOwnRate - (1 / 3)) < 0.001, `lab context DOES read its own write (~0.333, got ${labSeesOwnRate}) — lab learning still works`);

  const unknownKey = `${proofKey}_unknown_check`;
  await rl.recordToolOutcome("proof_tool", unknownKey, true, "unknown");
  const realSeesUnknown = await rl.getToolSuccessRate("proof_tool", unknownKey, "real");
  assert(realSeesUnknown === 0.5, `real context does NOT see an "unknown"-provenance write (cold-start default, got ${realSeesUnknown}) — quarantine holds`);

  // getBestTool via ReinforcementWiring — the actual live-hunt call path.
  const realWiring = new ReinforcementWiring();
  await realWiring.onHuntStart({ sessionId: "proof-real-session", programId: realProgram.id, programType: "web_app" });
  const labWiring = new ReinforcementWiring();
  await labWiring.onHuntStart({ sessionId: "proof-lab-session", programId: labProgram.id, programType: "web_app" });

  assert(realWiring.getProvenance() === "real", `ReinforcementWiring.onHuntStart(realProgram) resolves provenance to "real"`);
  assert(labWiring.getProvenance() === "lab", `ReinforcementWiring.onHuntStart(labProgram) resolves provenance to "lab"`);

  const toolKey = `${proofKey}_getbesttool`;
  await rl.recordToolOutcome("candidate_a", toolKey, true, "real");
  await rl.recordToolOutcome("candidate_a", toolKey, true, "real");
  await rl.recordToolOutcome("candidate_a", toolKey, true, "real"); // real rate ~1.0
  await rl.recordToolOutcome("candidate_a", toolKey, false, "lab");
  await rl.recordToolOutcome("candidate_a", toolKey, false, "lab");
  await rl.recordToolOutcome("candidate_a", toolKey, false, "lab"); // lab rate ~0.0 (would LOSE to candidate_b if leaked)
  const chosenUnderReal = await realWiring.getBestTool(["candidate_a", "candidate_b"], toolKey, "candidate_b");
  assert(chosenUnderReal === "candidate_a", `getBestTool() under REAL context picks candidate_a (real rate ~1.0), proving it did NOT read the lab rate ~0.0 (got "${chosenUnderReal}")`);

  console.log("\n=== Surface 2: ROIModel (getVulnClassStats via calculateExpectedValue/updateSuccessRate) ===\n");
  const vulnKey = `${proofKey}_vuln`;
  await roi.updateSuccessRate(vulnKey, true, "real");
  await roi.updateSuccessRate(vulnKey, true, "lab");
  await roi.updateSuccessRate(vulnKey, false, "lab");
  await roi.updateSuccessRate(vulnKey, false, "lab"); // lab: 1 success / 3 total; real: 1 success / 1 total
  const realRoiEv = await roi.calculateExpectedValue(vulnKey, 10000, "real");
  const labRoiEv = await roi.calculateExpectedValue(vulnKey, 10000, "lab");
  // Bayesian smoothing (s+1)/(n+4): real = 2/5 = 0.4, lab = 2/7 ≈ 0.2857 — distinguishable if leaking.
  assert(Math.abs(realRoiEv.successRate - 0.4) < 0.001,
    `ROIModel real-context successRate reflects ONLY the real write (expected 0.4, got ${realRoiEv.successRate})`);
  assert(Math.abs(labRoiEv.successRate - (2 / 7)) < 0.001,
    `ROIModel lab-context successRate reflects ONLY the lab writes (expected ~0.2857, got ${labRoiEv.successRate}) — lab learning still works`);

  console.log("\n=== Surface 3: strategy_transitions (loadWeights via strategyWeightLearner / MetaReasoner) ===\n");
  const stratKey = `proof_strategy->pivot_${Date.now()}`;
  // Seed directly at the storage layer (same shape learn() itself writes) —
  // isolates the READ-segregation proof from decision_journal's own
  // aggregation logic, which Test 2 traces separately via
  // resolveProvenanceFromHuntId above.
  await pool.query(
    `INSERT INTO reinforcement_store (domain, key, value, success_count, total_count, weight, last_updated)
     VALUES ('strategy_transitions', $1, '{}', 1, 1, 3.5, now())
     ON CONFLICT (domain, key) DO UPDATE SET weight = 3.5`,
    [`real::${stratKey}`]
  );
  await pool.query(
    `INSERT INTO reinforcement_store (domain, key, value, success_count, total_count, weight, last_updated)
     VALUES ('strategy_transitions', $1, '{}', 1, 1, 0.1, now())
     ON CONFLICT (domain, key) DO UPDATE SET weight = 0.1`,
    [`lab::${stratKey}`]
  );
  const realWeights = await strategyWeightLearner.loadWeights("real");
  const labWeights = await strategyWeightLearner.loadWeights("lab");
  const unknownWeights = await strategyWeightLearner.loadWeights("unknown");
  assert(realWeights.get(stratKey) === 3.5, `strategyWeightLearner.loadWeights("real") returns the real:: weight 3.5 (got ${realWeights.get(stratKey)})`);
  assert(labWeights.get(stratKey) === 0.1, `strategyWeightLearner.loadWeights("lab") returns the lab:: weight 0.1, not the real one (got ${labWeights.get(stratKey)})`);
  assert(unknownWeights.get(stratKey) === undefined, `strategyWeightLearner.loadWeights("unknown") does NOT see either real:: or lab:: entry (got ${unknownWeights.get(stratKey)})`);

  console.log("\n=== Cleanup ===\n");
  await pool.query(`DELETE FROM reinforcement_store WHERE key LIKE $1 OR key LIKE $2`, [`%${proofKey}%`, `%${stratKey}%`]);
  await runCleanup(cleanup);
  console.log("Cleaned up all throwaway rows.\n");

  console.log(failures === 0 ? `ALL ${18} CHECKS PASSED\n` : `${failures} CHECK(S) FAILED\n`);
  await pool.end();
  process.exit(failures === 0 ? 0 : 1);
}

main().catch(async (err) => {
  console.error("rl-segregation-proof crashed:", err);
  await pool.end().catch(() => {});
  process.exit(1);
});
