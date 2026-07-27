/**
 * Scope-binding handoff, Fix 1 — isolated, deterministic proof against the
 * REAL running code and REAL DB (no mocks). Exercises the exact scenario
 * the audit found broken: a hunt launched via the platform's own documented
 * default path (`programId: -1`) must resolve `isLab` correctly and have
 * the restricted-action policy gate actually fire for a non-lab target,
 * while the one seeded practice-lab target keeps running unaffected.
 *
 * Creates its own throwaway rows and deletes everything it created.
 *
 * Run: npx tsx scripts/islab-unification-proof.ts
 */
import "dotenv/config";
import { pool, db } from "../src/db";
import { programs } from "../src/db/schema";
import { eq, and } from "drizzle-orm";
import { resolveCustomTargetProgram, isCrossCampaignEligible } from "../src/lib/hunter/custom-target-program";
import { checkWafBypassAuthorization } from "../src/agents/WAFBypass";

let failures = 0;
function assert(cond: boolean, label: string): void {
  if (cond) console.log(`  PASS  ${label}`);
  else { failures++; console.log(`  FAIL  ${label}`); }
}

async function main() {
  const cleanup: Array<() => Promise<void>> = [];
  try {
    await runTests(cleanup);
  } catch (err) {
    console.error("islab-unification-proof crashed mid-run:", err);
    failures++;
  }
  for (const fn of cleanup.reverse()) { try { await fn(); } catch { /* best-effort */ } }
  console.log(failures === 0 ? "\nALL CHECKS PASSED\n" : `\n${failures} CHECK(S) FAILED\n`);
  await pool.end();
  process.exit(failures === 0 ? 0 : 1);
}

async function runTests(cleanup: Array<() => Promise<void>>) {
  const realHost = `islab-proof-real-${Date.now()}.example.test`;
  const realTargetUrl = `https://${realHost}/`;
  const labTargetUrl = "http://localhost:3000/"; // the one seeded practice-lab target (lab-profiles.ts)

  console.log("\n=== Test 1: the documented `-1` default path, pointed at a REAL (non-lab) host ===\n");
  {
    const realProgramId = await resolveCustomTargetProgram(realTargetUrl);
    cleanup.push(async () => { await db.delete(programs).where(eq(programs.id, realProgramId)); });

    const [row] = await db.select().from(programs).where(eq(programs.id, realProgramId)).limit(1);
    assert(row.isLab === false, `resolveCustomTargetProgram(real host) -> isLab === false (got ${row.isLab})`);
    assert(isCrossCampaignEligible(row) === true, `isCrossCampaignEligible(row) === true for the resolved real program`);

    // The load-bearing assertion: the policy gate actually FIRES on this
    // -1-resolved id, denying an unauthorized restricted action — this is
    // exactly the path the audit found auto-permitted via platform:"local".
    const waf = await checkWafBypassAuthorization(realTargetUrl, realProgramId);
    assert(waf.allowed === false, `checkWafBypassAuthorization() on the -1-resolved REAL program, unspecified wafBypassPolicy -> DENIED (got allowed=${waf.allowed})`);
    assert(!!waf.reason, `denial carries a reason, not a silent false (got "${waf.reason}")`);
  }

  console.log("\n=== Test 2: lab still runs everything (the seeded practice-lab target) ===\n");
  {
    const labProgramId = await resolveCustomTargetProgram(labTargetUrl);
    // Do NOT clean up the seeded lab program row itself — it's a shared,
    // reusable row across every -1 launch to localhost:3000, not a
    // throwaway. We only assert its state here.

    const [row] = await db.select().from(programs).where(eq(programs.id, labProgramId)).limit(1);
    assert(row.isLab === true, `resolveCustomTargetProgram(localhost:3000) -> isLab === true (got ${row.isLab})`);
    assert(isCrossCampaignEligible(row) === false, `isCrossCampaignEligible(row) === false for the lab program`);

    // wafBypassPolicy deliberately left at its default "unspecified" the
    // whole time — proving lab permits from BEING lab, not from also being
    // configured (mirrors action-policy-gate-proof.ts's Test 2 discipline).
    const waf = await checkWafBypassAuthorization(labTargetUrl, labProgramId);
    assert(waf.allowed === true, `checkWafBypassAuthorization() on the LAB program, policy still "unspecified" -> STILL permitted (got allowed=${waf.allowed}) — the real-path fail-closed fix did not fail-close lab`);
  }

  console.log("\n=== Test 3: exactly one row has isLab=true, confirmed from the DB ===\n");
  {
    const labRows = await db.select().from(programs).where(eq(programs.isLab, true));
    assert(labRows.length === 1, `exactly one program row has isLab=true (got ${labRows.length}: ${labRows.map(r => r.name).join(", ")})`);
    assert(labRows[0]?.name === "Custom: localhost:3000", `the one isLab=true row is the seeded practice-lab target (got "${labRows[0]?.name}")`);
  }

  console.log("\n=== Test 4: a second real custom-target host does NOT collide with the lab or with each other ===\n");
  {
    const otherRealHost = `islab-proof-real2-${Date.now()}.example.test`;
    const otherRealProgramId = await resolveCustomTargetProgram(`https://${otherRealHost}/`);
    cleanup.push(async () => { await db.delete(programs).where(eq(programs.id, otherRealProgramId)); });
    const [row] = await db.select().from(programs).where(eq(programs.id, otherRealProgramId)).limit(1);
    assert(row.isLab === false, `a second, distinct real host also resolves isLab === false (got ${row.isLab})`);

    const labRowsAfter = await db.select().from(programs).where(eq(programs.isLab, true));
    assert(labRowsAfter.length === 1, `still exactly one isLab=true row after a second real launch (got ${labRowsAfter.length}) — no cross-contamination`);
  }
}

main().catch(async err => { console.error(err); await pool.end().catch(() => {}); process.exit(1); });
