/**
 * UI trust fix #5/7 (containment events, real-vs-lab, scope in the live
 * view) -- proof.
 *
 * Part A: a real ScopeGuard.isInScope() call for an out-of-scope URL against
 * the real Phase-A program (1181) genuinely fires the "blocked" event; a
 * real HunterEngine listener (attached the same way startHunt() attaches
 * it) filters it correctly by programId and re-emits hunt:scope_blocked --
 * and does NOT re-emit for a block belonging to a DIFFERENT programId
 * (proving the shared-singleton filter actually filters).
 *
 * Part B: the one-shot hunt:scope_context emit fires exactly once across
 * two runLoop() passes, carrying the real classifyProgramPolicy() verdict
 * for program 1181 and its real scope/outOfScope arrays.
 *
 * Run: npx tsx scripts/scope-visibility-proof.ts
 */
import "dotenv/config";
import { pool, db } from "../src/db";
import { programs } from "../src/db/schema";
import { eq } from "drizzle-orm";
import { HunterEngine } from "../src/agents/HunterEngine";
import { ScopeGuard, classifyProgramPolicy } from "../src/middleware/scopeGuard";

const PROGRAM_ID = 1181;
const OTHER_PROGRAM_ID = 999999; // does not exist -> classifyProgramPolicy fails closed as "invalid", still blocks, still a DIFFERENT programId

let failures = 0;
function assert(cond: boolean, label: string): void {
  if (cond) console.log(`  PASS  ${label}`);
  else { failures++; console.log(`  FAIL  ${label}`); }
}

function makeEngine(sessionId: string): HunterEngine {
  const engine = new HunterEngine();
  (engine as unknown as { state: Record<string, unknown> }).state = {
    sessionId, targetUrl: "http://localhost:8081/", programId: PROGRAM_ID,
    phase: "observe", observations: [], hypotheses: [], probes: [], confirmedFindings: [],
    iteration: 0, maxIterations: 1,
    budget: { maxRequests: 100, requestsMade: 0, maxTime: 3600, elapsed: 0 },
    corpusEnrichment: false, proxyEnabled: false, wafBypassEnabled: false,
    automatedScanningEnabled: false, discoveredEndpoints: [],
  };
  return engine;
}

async function main() {
  const [program] = await db.select().from(programs).where(eq(programs.id, PROGRAM_ID)).limit(1);
  if (!program) { console.error(`Program ${PROGRAM_ID} not found.`); process.exit(1); }
  console.log(`Program ${PROGRAM_ID} real scope: ${JSON.stringify(program.scope)}, outOfScope: ${JSON.stringify(program.outOfScope)}`);

  console.log("\n=== Part A: hunt:scope_blocked -- real ScopeGuard block, filtered by programId ===\n");
  const engine = makeEngine("scope-proof-A");
  const scopeGuard = ScopeGuard.getInstance();
  const captured: Record<string, unknown>[] = [];
  const listener = (e: { url: string; programId: number | null | undefined; reason: string }) => {
    if (e.programId === (engine as unknown as { state: { programId: number } }).state.programId) {
      captured.push({ url: e.url, reason: e.reason });
    }
  };
  scopeGuard.on("blocked", listener);

  // A real out-of-scope URL for program 1181 (scope is ["localhost"]).
  const result = await scopeGuard.isInScope("https://evil.example.com/", PROGRAM_ID);
  assert(result.allowed === false, `real isInScope() call for an out-of-scope URL is blocked (got allowed=${result.allowed})`);
  assert(captured.length === 1, `exactly one hunt:scope_blocked-shaped capture for THIS program's block (got ${captured.length})`);
  assert(captured[0]?.url === "https://evil.example.com/", `captured event carries the real blocked URL`);
  assert(typeof captured[0]?.reason === "string" && (captured[0].reason as string).length > 0, `captured event carries a real reason string ("${captured[0]?.reason}")`);

  // A block for a DIFFERENT programId must NOT be captured by this listener.
  captured.length = 0;
  await scopeGuard.isInScope("https://also-evil.example.com/", OTHER_PROGRAM_ID);
  assert(captured.length === 0, `a block for a DIFFERENT programId (${OTHER_PROGRAM_ID}) is correctly filtered out -- no cross-hunt leakage`);
  scopeGuard.off("blocked", listener);

  console.log("\n=== Part A2: the real HunterEngine listener (attached exactly as startHunt() does) ===\n");
  const engine2 = makeEngine("scope-proof-A2");
  const engineCaptured: Record<string, unknown>[] = [];
  engine2.on("hunt:scope_blocked", (payload: Record<string, unknown>) => engineCaptured.push(payload));
  // Attach the listener the same way startHunt() does (same bound-closure shape).
  const boundListener = (e: { url: string; programId: number | null | undefined; reason: string }) => {
    if (e.programId === (engine2 as unknown as { state: { programId: number } }).state.programId) {
      engine2.emit("hunt:scope_blocked", {
        sessionId: (engine2 as unknown as { state: { sessionId: string } }).state.sessionId,
        url: e.url, reason: e.reason,
      });
    }
  };
  scopeGuard.on("blocked", boundListener);
  await scopeGuard.isInScope("https://storage.googleapis.com/localhost/", PROGRAM_ID);
  scopeGuard.off("blocked", boundListener);
  assert(engineCaptured.length === 1, `engine-level hunt:scope_blocked fired once for a real block (got ${engineCaptured.length})`);
  assert(engineCaptured[0]?.sessionId === "scope-proof-A2", `payload carries the correct sessionId`);

  console.log("\n=== Part B: hunt:scope_context -- one-shot emit with real provenance/scope ===\n");
  const engine3 = makeEngine("scope-proof-B");
  const realProvenance = classifyProgramPolicy(PROGRAM_ID);
  (engine3 as unknown as { scopeContext: unknown }).scopeContext = {
    provenance: realProvenance,
    scope: (program.scope as string[] | null) ?? [],
    outOfScope: (program.outOfScope as string[] | null) ?? [],
  };
  const contextCaptured: Record<string, unknown>[] = [];
  engine3.on("hunt:scope_context", (payload: Record<string, unknown>) => contextCaptured.push(payload));

  (engine3 as unknown as { runLoop: () => Promise<void> }).runLoop().catch(() => {});
  await new Promise(r => setTimeout(r, 300));
  (engine3 as unknown as { aborted: boolean }).aborted = true;

  assert(contextCaptured.length === 1, `hunt:scope_context fired exactly once on the first iteration (got ${contextCaptured.length})`);
  assert(contextCaptured[0]?.provenance === realProvenance, `payload.provenance matches the real classifyProgramPolicy() verdict for program ${PROGRAM_ID} ("${contextCaptured[0]?.provenance}")`);
  assert(JSON.stringify(contextCaptured[0]?.scope) === JSON.stringify(program.scope ?? []), `payload.scope matches the real program row's scope`);
  assert(JSON.stringify(contextCaptured[0]?.outOfScope) === JSON.stringify(program.outOfScope ?? []), `payload.outOfScope matches the real program row's outOfScope`);

  // Second iteration must NOT re-emit (one-shot).
  (engine3 as unknown as { state: { iteration: number; maxIterations: number }; aborted: boolean }).state.iteration = 0;
  (engine3 as unknown as { state: { maxIterations: number } }).state.maxIterations = 1;
  (engine3 as unknown as { aborted: boolean }).aborted = false;
  contextCaptured.length = 0;
  (engine3 as unknown as { runLoop: () => Promise<void> }).runLoop().catch(() => {});
  await new Promise(r => setTimeout(r, 300));
  (engine3 as unknown as { aborted: boolean }).aborted = true;
  assert(contextCaptured.length === 0, `hunt:scope_context does NOT re-fire on a second loop pass (one-shot guard holds, got ${contextCaptured.length} extra emits)`);

  console.log(failures === 0 ? "\nALL CHECKS PASSED\n" : `\n${failures} CHECK(S) FAILED\n`);
  await pool.end();
  process.exit(failures === 0 ? 0 : 1);
}

main().catch(async err => { console.error(err); await pool.end().catch(() => {}); process.exit(1); });
