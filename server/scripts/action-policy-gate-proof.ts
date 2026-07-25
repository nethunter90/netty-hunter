/**
 * Phase 2 — isolated, deterministic proof for the behavioral-rules
 * enforcement handoff (readiness blocker #3), against the REAL running
 * Phase-1 code (no mocks for the gate itself). Creates its own throwaway
 * real/lab program rows and deletes everything it created.
 *
 * Run: npx tsx scripts/action-policy-gate-proof.ts
 */
import "dotenv/config";
import { pool, db } from "../src/db";
import { programs } from "../src/db/schema";
import { eq } from "drizzle-orm";
import {
  checkAutomatedScanningAuthorization, checkFuzzingAuthorization, runProgramPreflight,
} from "../src/agents/ActionPolicyGate";
import { dispatchTool, ToolPolicyBlockedError } from "../src/lib/net/dispatch-tool";
import { HunterEngine } from "../src/agents/HunterEngine";

let failures = 0;
function assert(cond: boolean, label: string): void {
  if (cond) console.log(`  PASS  ${label}`);
  else { failures++; console.log(`  FAIL  ${label}`); }
}

async function main() {
  const cleanup: Array<() => Promise<void>> = [];

  const [realProgram] = await db.insert(programs).values({
    name: "__policy_proof_real__", platform: "hackerone", scope: ["*"], outOfScope: [],
  }).returning();
  cleanup.push(async () => { await db.delete(programs).where(eq(programs.id, realProgram.id)); });

  const [labProgram] = await db.insert(programs).values({
    name: "__policy_proof_lab__", platform: "local", scope: ["*"], outOfScope: [],
  }).returning();
  cleanup.push(async () => { await db.delete(programs).where(eq(programs.id, labProgram.id)); });

  try {
    await runTests(realProgram.id, labProgram.id);
  } catch (err) {
    console.error("action-policy-gate-proof crashed mid-run:", err);
    failures++;
  }

  for (const fn of cleanup.reverse()) { try { await fn(); } catch { /* best-effort */ } }
  console.log(failures === 0 ? "\nALL CHECKS PASSED\n" : `\n${failures} CHECK(S) FAILED\n`);
  await pool.end();
  process.exit(failures === 0 ? 0 : 1);
}

async function runTests(realId: number, labId: number) {
  const url = "http://127.0.0.1:1"; // unreachable, safe — never actually connects

  console.log("\n=== Test 1: fail-closed + surfaced (real, unspecified policy) ===\n");
  {
    const scan = await checkAutomatedScanningAuthorization(url, realId);
    const fuzz = await checkFuzzingAuthorization(url, realId);
    assert(scan.allowed === false, `real program, unspecified automatedScanningPolicy -> BLOCKED (got allowed=${scan.allowed})`);
    assert(fuzz.allowed === false, `real program, unspecified fuzzingPolicy -> BLOCKED (got allowed=${fuzz.allowed})`);
    assert(!!scan.reason && !!fuzz.reason, `both blocks carry a named reason, not a silent false (scan="${scan.reason}", fuzz="${fuzz.reason}")`);

    // dispatchTool() itself — proves the block is real at the actual exec
    // chokepoint, not just at the standalone auth functions.
    let threw: unknown = null;
    try {
      await dispatchTool({ tool: "nuclei", target: "https://example.com/", args: ["-u", "{url}"], programId: realId });
    } catch (err) { threw = err; }
    assert(threw instanceof ToolPolicyBlockedError, `dispatchTool({tool:"nuclei"}) on the real+unspecified program throws ToolPolicyBlockedError (before ever spawning) — got ${threw?.constructor?.name}`);
  }

  console.log("\n=== Test 2: both directions — real+allowed runs, LAB runs unaffected ===\n");
  {
    await db.update(programs).set({ automatedScanningPolicy: "allowed", fuzzingPolicy: "allowed" }).where(eq(programs.id, realId));

    const scanAllowed = await checkAutomatedScanningAuthorization(url, realId);
    const fuzzAllowed = await checkFuzzingAuthorization(url, realId);
    assert(scanAllowed.allowed === true, `real program with explicit "allowed" -> permitted (got ${scanAllowed.allowed})`);
    assert(fuzzAllowed.allowed === true, `real program with explicit "allowed" -> permitted (got ${fuzzAllowed.allowed})`);

    // LAB program — policy left at the default "unspecified" the whole time,
    // NEVER explicitly set to "allowed". This is the load-bearing assertion:
    // lab must run unaffected purely from being lab, not from also being
    // configured.
    const labScan = await checkAutomatedScanningAuthorization(url, labId);
    const labFuzz = await checkFuzzingAuthorization(url, labId);
    assert(labScan.allowed === true, `LAB program, policy still "unspecified" -> STILL permitted (got ${labScan.allowed}) — the fail-closed-for-real change did not fail-close lab`);
    assert(labFuzz.allowed === true, `LAB program, policy still "unspecified" -> STILL permitted (got ${labFuzz.allowed})`);

    // dispatchTool() past the gate for both — confirm neither throws
    // ToolPolicyBlockedError specifically (a network/timeout error from the
    // unreachable target is expected and fine; that's proof it got PAST the
    // gate to a real execution attempt, which is exactly what we're proving).
    for (const [label, programId] of [["real+allowed", realId], ["lab", labId]] as const) {
      let threw: unknown = null;
      try {
        await dispatchTool({ tool: "nuclei", target: url, args: ["-u", "{url}", "-timeout", "1"], programId, timeoutMs: 3000 });
      } catch (err) { threw = err; }
      assert(!(threw instanceof ToolPolicyBlockedError), `dispatchTool({tool:"nuclei"}) for ${label} is NOT blocked by policy (got ${threw?.constructor?.name ?? "no error"} — anything but ToolPolicyBlockedError proves it passed the gate)`);
    }
  }

  console.log("\n=== Test 3: no policy-blocked retry storm (runTool() itself doesn't loop) ===\n");
  {
    const engine = new HunterEngine();
    (engine as unknown as { state: { programId: number; sessionId: string; targetUrl: string } }).state =
      { programId: realId, sessionId: "__policy_proof__", targetUrl: "https://example.com" } as never;
    await db.update(programs).set({ automatedScanningPolicy: "unspecified" }).where(eq(programs.id, realId));

    const t0 = Date.now();
    const result1 = await (engine as unknown as { runTool: (t: string, u: string) => Promise<Record<string, unknown>> })
      .runTool("nuclei", "https://example.com/");
    const elapsed1 = Date.now() - t0;
    assert(result1.policyBlocked === true, `runTool("nuclei") on a policy-blocked real program returns {policyBlocked:true} (got ${JSON.stringify(result1)})`);
    assert(elapsed1 < 2000, `the block returns fast (<2s, got ${elapsed1}ms) — no internal retry/backoff loop inside runTool() itself for a policy block`);

    const t1 = Date.now();
    const result2 = await (engine as unknown as { runTool: (t: string, u: string) => Promise<Record<string, unknown>> })
      .runTool("nuclei", "https://example.com/");
    const elapsed2 = Date.now() - t1;
    assert(result2.policyBlocked === true && elapsed2 < 2000, `a second call independently returns the same fast block (got policyBlocked=${result2.policyBlocked}, ${elapsed2}ms) — each call is a single check, not an accumulating retry loop`);
  }

  console.log("\n=== Test 4: pre-flight decision logic — real+unspecified warns, lab and real+decided stay silent ===\n");
  {
    const realProgramRow = { platform: "hackerone", wafBypassPolicy: "unspecified", exploitationToolsPolicy: "unspecified", automatedScanningPolicy: "unspecified", fuzzingPolicy: "unspecified", authConfig: null };
    const warnings = runProgramPreflight(realProgramRow);
    assert(warnings.length === 4, `real program, all 4 policies unspecified -> 4 warnings (got ${warnings.length}: ${warnings.map(w => w.code).join(",")})`);

    const decidedRow = { ...realProgramRow, wafBypassPolicy: "disallowed", exploitationToolsPolicy: "allowed", automatedScanningPolicy: "allowed", fuzzingPolicy: "disallowed" };
    const decidedWarnings = runProgramPreflight(decidedRow);
    assert(decidedWarnings.length === 0, `real program, all 4 policies EXPLICITLY decided (allowed or disallowed) -> silent, 0 warnings (got ${decidedWarnings.length}) — Amendment 2 holds`);

    const labRow = { platform: "local", wafBypassPolicy: "unspecified", exploitationToolsPolicy: "unspecified", automatedScanningPolicy: "unspecified", fuzzingPolicy: "unspecified", authConfig: null };
    const labWarnings = runProgramPreflight(labRow);
    assert(labWarnings.length === 0, `LAB program, all unspecified -> still silent, 0 warnings (got ${labWarnings.length}) — lab needs no reminder`);

    console.log("  NOTE: wiring at the two entry points (CampaignOrchestrator.ts:371-378, HunterEngine.ts:1073-1083) is verified by direct code citation in the Phase 1 report, not re-invoked live here (startHunt()/layer1_governance() are full launch paths with recon/tool-loading side effects well beyond the pre-flight itself) — this test proves the DECISION function completely.");
  }
}

main().catch(async err => { console.error(err); await pool.end().catch(() => {}); process.exit(1); });
