/**
 * Blocker #4, Go-Live Protocol v2 — Phase A addendum. Deliberately forces
 * selection of a policy-gated tool (nuclei, automated scanning) via
 * hypothesis.toolHint against the REAL Phase-A dry-run program (id 1181,
 * platform "hackerone", automatedScanningPolicy left at its default
 * "unspecified") and proves two things live, against the actual probe()
 * loop — not a synthetic unit test of the gate in isolation (that already
 * exists: action-policy-gate-proof.ts Test 3, which proves runTool() alone
 * doesn't retry-storm on a block):
 *
 *   1. The gated hypothesis is blocked (policyBlocked:true, no subprocess
 *      ever spawned) rather than silently allowed on programId 1181.
 *   2. A second, benign hypothesis in the SAME probe() call is still
 *      processed normally — the loop does not derail, abort, or skip
 *      subsequent hypotheses because one was policy-blocked.
 *
 * Run: npx tsx scripts/phase-a-addendum-policy-continue-proof.ts
 */
import "dotenv/config";
import { pool, db } from "../src/db";
import { programs } from "../src/db/schema";
import { eq } from "drizzle-orm";
import { HunterEngine, type Hypothesis } from "../src/agents/HunterEngine";

const PROGRAM_ID = 1181;
const TARGET_URL = "http://localhost:8081/";

let failures = 0;
function assert(cond: boolean, label: string): void {
  if (cond) console.log(`  PASS  ${label}`);
  else { failures++; console.log(`  FAIL  ${label}`); }
}

async function main() {
  const [program] = await db.select().from(programs).where(eq(programs.id, PROGRAM_ID)).limit(1);
  if (!program) {
    console.error(`Program ${PROGRAM_ID} not found — expected the Phase A dry-run program to still exist.`);
    process.exit(1);
  }
  console.log(`Program ${PROGRAM_ID}: platform=${program.platform}, automatedScanningPolicy=${program.automatedScanningPolicy ?? "unspecified"}`);
  assert(
    !program.automatedScanningPolicy || program.automatedScanningPolicy === "unspecified",
    "precondition: automatedScanningPolicy is still unspecified on program 1181 (the exact fail-closed case Phase A needs to prove)"
  );

  const engine = new HunterEngine();
  const now = new Date().toISOString();

  const gated: Hypothesis = {
    id: "phase-a-addendum-gated", vulnClass: "security_misconfig", targetUrl: TARGET_URL,
    reasoning: "Phase A addendum — forced nuclei selection via toolHint to exercise the automated-scanning policy gate on a real program with unspecified policy.",
    confidence: 0.6, priority: 9, evidence: [], status: "pending", createdAt: now,
    toolHint: "nuclei",
  };
  const benign: Hypothesis = {
    id: "phase-a-addendum-benign", vulnClass: "security_headers", targetUrl: TARGET_URL,
    reasoning: "Phase A addendum — control hypothesis using an ungated tool, to prove the loop keeps going past the blocked one.",
    confidence: 0.6, priority: 9, evidence: [], status: "pending", createdAt: now,
    toolHint: "curl_probe",
  };

  (engine as unknown as { state: Record<string, unknown> }).state = {
    sessionId: "phase-a-addendum-proof",
    targetUrl: TARGET_URL,
    programId: PROGRAM_ID,
    phase: "probe",
    observations: [],
    hypotheses: [gated, benign],
    probes: [],
    confirmedFindings: [],
    iteration: 1,
    maxIterations: 5,
    budget: { maxRequests: 100, requestsMade: 0, maxTime: 3600, elapsed: 0 },
    corpusEnrichment: false,
    proxyEnabled: false,
    wafBypassEnabled: false,
    automatedScanningEnabled: false,
    discoveredEndpoints: [],
  };

  let threw: unknown = null;
  try {
    await (engine as unknown as { probe: () => Promise<void> }).probe();
  } catch (err) {
    threw = err;
  }
  assert(threw === null, `probe() completes without throwing, even though one of its two hypotheses is policy-blocked (got ${threw ? String(threw) : "no error"})`);

  const probes = (engine as unknown as { state: { probes: Array<Record<string, unknown>> } }).state.probes;
  console.log(`\nstate.probes recorded: ${probes.length}`);
  for (const p of probes) console.log(`  - hypothesisId=${p.hypothesisId} tool=${p.tool} success=${p.success}`);

  const gatedProbe = probes.find(p => p.hypothesisId === gated.id);
  const benignProbe = probes.find(p => p.hypothesisId === benign.id);

  assert(!!gatedProbe, "the gated (nuclei) hypothesis produced a probe result — it was reached and processed, not silently dropped");
  assert(gatedProbe?.tool === "nuclei", `the gated probe actually used the forced toolHint, not a fallback (got tool=${gatedProbe?.tool})`);
  assert(gatedProbe?.success === false, `the gated probe is recorded as unsuccessful (policy-blocked, not a real scan result) — got success=${gatedProbe?.success}`);
  assert(
    typeof gatedProbe?.parsed === "object" && (gatedProbe?.parsed as Record<string, unknown>)?.policyBlocked === true,
    `the gated probe's parsed result carries policyBlocked:true from runTool() (got parsed=${JSON.stringify(gatedProbe?.parsed)})`
  );
  assert(gatedProbe?.command === "", `no command/subprocess was ever built for the blocked tool (got command=${JSON.stringify(gatedProbe?.command)})`);

  assert(!!benignProbe, "the benign (curl_probe) hypothesis, which comes AFTER the blocked one in the same pending list, still produced a probe result");
  assert(benignProbe?.tool === "curl_probe", `the benign probe used its own forced toolHint, unaffected by the prior block (got tool=${benignProbe?.tool})`);
  assert(
    !(typeof benignProbe?.parsed === "object" && (benignProbe?.parsed as Record<string, unknown>)?.policyBlocked === true),
    "the benign probe was NOT policy-blocked (curl_probe isn't gated) — confirms the block is per-tool, not a hunt-wide latch"
  );

  console.log(failures === 0 ? "\nALL CHECKS PASSED — policy block fires on the forced tool, and the loop continues to the next hypothesis in the same probe() call.\n" : `\n${failures} CHECK(S) FAILED\n`);
  await pool.end();
  process.exit(failures === 0 ? 0 : 1);
}

main().catch(async err => { console.error(err); await pool.end().catch(() => {}); process.exit(1); });
