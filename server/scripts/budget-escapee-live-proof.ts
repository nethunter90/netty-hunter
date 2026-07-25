/**
 * Handoff C, Phase 2 — targeted live proof that demonstrate() and
 * synthesizeChainedAttack() respect the hunt LLM budget cap.
 *
 * The full-hunt proof (a real capped hunt against the lab target,
 * MAX_LLM_CALLS_PER_HUNT=2) already shows the shared cap mechanism works
 * end-to-end — hypothesize() hits the cap, the hunt pauses cleanly
 * (paused_budget, checkpoint saved with the real spend). But that hunt
 * paused with confirmedFindings=0, before ever reaching demonstrate() (only
 * fires post-confirmation) or synthesizeChainedAttack() (needs 1+ confirmed
 * findings) — gambling on a longer/more expensive hunt to organically time
 * budget exhaustion into those exact two call sites isn't worth it when
 * they can be exercised directly and precisely instead.
 *
 * This script: pre-exhausts the dollar budget for a real sessionId, then
 * calls demonstrate() and synthesizeChainedAttack() against that same
 * sessionId, and proves via ClaudeClient.getCallCount() that NEITHER makes
 * a real API call once exhausted — they fall back / no-op instead of
 * bypassing the cap.
 *
 * Run: npx tsx scripts/budget-escapee-live-proof.ts
 */
import "dotenv/config";
import { ClaudeClient } from "../src/lib/claude-client";
import { postExploitAgent } from "../src/agents/PostExploitAgent";
import { HunterEngine } from "../src/agents/HunterEngine";

const SESSION_ID = "budget-escapee-proof-" + Date.now();

async function main() {
  console.log(`[escapee-proof] session key: ${SESSION_ID}`);

  // MAX_LLM_CALLS_PER_HUNT (call-count cap, not the dollar cap) must be set
  // via the process environment BEFORE this module is ever imported — it's
  // read into a `private static readonly` field at class-definition time
  // (parseInt(process.env.MAX_LLM_CALLS_PER_HUNT || "150", 10)), so setting
  // process.env here, after import, has no effect (confirmed live: the
  // first version of this script tried exactly that with the dollar cap and
  // both "escapees" made real calls because the budget was never actually
  // exhausted — a bug in the proof script, not in ClaudeClient). Run this
  // script as `MAX_LLM_CALLS_PER_HUNT=1 npx tsx scripts/...`.
  if (process.env.MAX_LLM_CALLS_PER_HUNT !== "1") {
    console.error('[escapee-proof] Run with MAX_LLM_CALLS_PER_HUNT=1 set BEFORE the process starts, e.g.:\n  MAX_LLM_CALLS_PER_HUNT=1 npx tsx scripts/budget-escapee-live-proof.ts');
    process.exit(1);
  }
  // Burn the one allowed call so the cap is genuinely exhausted for this session.
  await ClaudeClient.oneShot("terse", "Say hi.", SESSION_ID).catch(() => {});
  const before = ClaudeClient.getSpend(SESSION_ID);
  console.log(`[escapee-proof] pre-exhausted spend for session: costUsd=${before.costUsd} callCount=${before.callCount} exhausted=${ClaudeClient.budgetExhaustionReason(SESSION_ID)}`);

  // ── demonstrate() / narrate() ────────────────────────────────────────────
  const callCountBeforeDemonstrate = ClaudeClient.getCallCount(SESSION_ID);
  const assessment = await postExploitAgent.demonstrate(
    {
      findingId: "escapee-proof-finding",
      sessionId: SESSION_ID,
      vulnClass: "security_headers",
      targetUrl: "http://localhost:8081",
      programId: -1,
      confidence: 0.9,
    },
    "medium",
    5.0,
  );
  const callCountAfterDemonstrate = ClaudeClient.getCallCount(SESSION_ID);
  const usedFallback = assessment.businessImpact.includes("could leverage this to compromise confidentiality, integrity, or availability");
  console.log(`[escapee-proof] demonstrate(): callCount ${callCountBeforeDemonstrate} -> ${callCountAfterDemonstrate} (no increase = no real LLM call attempted)`);
  console.log(`[escapee-proof] demonstrate(): businessImpact used deterministic fallback template: ${usedFallback}`);
  console.log(`[escapee-proof] demonstrate(): businessImpact = "${assessment.businessImpact}"`);

  // ── synthesizeChainedAttack() (private method on HunterEngine) ──────────
  const engine = new HunterEngine() as unknown as {
    state: { sessionId: string; confirmedFindings: unknown[] };
    lastSynthesisCount: number;
    synthesizeChainedAttack: () => Promise<void>;
  };
  engine.state = {
    sessionId: SESSION_ID,
    confirmedFindings: [
      { hypothesis: { vulnClass: "xss", targetUrl: "http://localhost:8081", reasoning: "test" }, severity: "medium", exploitPayload: "test" },
      { hypothesis: { vulnClass: "idor", targetUrl: "http://localhost:8081", reasoning: "test" }, severity: "high", exploitPayload: "test" },
    ],
  };
  engine.lastSynthesisCount = 0;

  const callCountBeforeSynthesis = ClaudeClient.getCallCount(SESSION_ID);
  let synthesisThrew = false;
  try {
    await engine.synthesizeChainedAttack();
  } catch (err) {
    synthesisThrew = true;
    console.log(`[escapee-proof] synthesizeChainedAttack() threw (unexpected — should no-op, not throw): ${String(err)}`);
  }
  const callCountAfterSynthesis = ClaudeClient.getCallCount(SESSION_ID);
  console.log(`[escapee-proof] synthesizeChainedAttack(): callCount ${callCountBeforeSynthesis} -> ${callCountAfterSynthesis} (no increase = no real LLM call attempted), threw=${synthesisThrew}`);

  const demonstratePassed = callCountAfterDemonstrate === callCountBeforeDemonstrate;
  const synthesisPassed = callCountAfterSynthesis === callCountBeforeSynthesis && !synthesisThrew;
  console.log(`\n[escapee-proof] RESULT: demonstrate() respects exhausted budget = ${demonstratePassed}`);
  console.log(`[escapee-proof] RESULT: synthesizeChainedAttack() respects exhausted budget = ${synthesisPassed}`);
  process.exit(demonstratePassed && synthesisPassed ? 0 : 1);
}

main().catch(err => {
  console.error("[escapee-proof] failed:", err);
  process.exit(1);
});
