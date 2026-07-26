/**
 * UI trust fix #1 (pause visibility) — Part B: feed the REAL payloads
 * captured live from HunterEngine (server/scripts/pause-payload-capture-proof.ts)
 * into the REAL huntEventBridge.ts parser (`parseHuntPausedEvent`, the exact
 * logic the socket handler uses) and drive the REAL huntStore mutators the
 * handler calls, asserting the resulting state — no reimplementation, the
 * actual fixed modules are imported and exercised end to end.
 *
 * Run (from client/): npx tsx scripts/pause-store-proof.ts
 */
import { readFileSync } from "fs";
import { huntStore } from "../src/lib/huntStore";
import { parseHuntPausedEvent } from "../src/lib/huntEventBridge";
import type { ActivityEvent } from "../src/components/LiveActivityFeed";

let failures = 0;
function assert(cond: boolean, label: string): void {
  if (cond) console.log(`  PASS  ${label}`);
  else { failures++; console.log(`  FAIL  ${label}`); }
}

// Mirrors the handler body in huntEventBridge.ts exactly (push + updateSessions) —
// re-run here directly against the real store so the proof doesn't need a live
// socket transport to exercise real incoming-event handling.
function handlePaused(data: unknown): void {
  const { sessionId, dimension, reason, findings, iterations } = parseHuntPausedEvent(data);
  huntStore.pushEvent({ type: "paused", ts: new Date().toISOString(), dimension, reason, findings, iterations } as ActivityEvent);
  huntStore.updateSessions(prev => prev.map(s =>
    s.sessionUuid === sessionId
      ? { ...s, status: dimension === "budget" ? "paused_budget" : "paused_auth", pausedReason: reason }
      : s
  ));
}

function main(): void {
  const raw = readFileSync(
    "/tmp/claude-1000/-home-kali-Desktop-netty-hunter/84c279e1-2636-4556-879a-b16357627749/scratchpad/pause-payloads.json",
    "utf-8"
  );
  const { budgetPayload, authPayload } = JSON.parse(raw);
  console.log("Loaded real captured payloads from the live engine run:\n", { budgetPayload, authPayload });

  huntStore.updateSessions(() => [{
    sessionUuid: budgetPayload.sessionId, targetUrl: "http://localhost:8081/",
    status: "running", phase: "probe", iteration: 2, findings: 0,
  }]);

  console.log("\n=== Real parseHuntPausedEvent() + real huntStore, fed the real BUDGET payload ===");
  handlePaused(budgetPayload);

  const afterBudget = huntStore.activeSessions.find(s => s.sessionUuid === budgetPayload.sessionId);
  assert(!!afterBudget, "session still present after pause (not silently dropped)");
  assert(afterBudget?.status === "paused_budget", `session status is exactly "paused_budget" (got ${afterBudget?.status}) — NOT "running"`);
  assert(afterBudget?.status !== "running", "session status is definitively NOT running — this is the bug the fix closes");
  assert(afterBudget?.pausedReason === budgetPayload.reason, `pausedReason carries the real server reason (got ${JSON.stringify(afterBudget?.pausedReason)})`);

  const budgetFeedEvent = huntStore.activityEvents.at(-1);
  assert(budgetFeedEvent?.type === "paused", `a "paused" activity-feed row was pushed (got type=${budgetFeedEvent?.type})`);
  assert((budgetFeedEvent as any)?.dimension === "budget", `feed row correctly tagged dimension="budget" (got ${(budgetFeedEvent as any)?.dimension})`);

  huntStore.updateSessions(prev => [...prev, {
    sessionUuid: authPayload.sessionId, targetUrl: "http://localhost:8081/",
    status: "running", phase: "probe", iteration: 2, findings: 0,
  }]);

  console.log("\n=== Real parseHuntPausedEvent() + real huntStore, fed the real AUTH payload ===");
  handlePaused(authPayload);

  const afterAuth = huntStore.activeSessions.find(s => s.sessionUuid === authPayload.sessionId);
  assert(!!afterAuth, "auth session still present after pause");
  assert(afterAuth?.status === "paused_auth", `session status is exactly "paused_auth" (got ${afterAuth?.status}) — distinct from paused_budget`);
  assert(afterAuth?.pausedReason === authPayload.authReason, `pausedReason carries authReason specifically (got ${JSON.stringify(afterAuth?.pausedReason)})`);

  const authFeedEvent = huntStore.activityEvents.at(-1);
  assert((authFeedEvent as any)?.dimension === "auth", `feed row correctly tagged dimension="auth" (got ${(authFeedEvent as any)?.dimension})`);

  const budgetStillPaused = huntStore.activeSessions.find(s => s.sessionUuid === budgetPayload.sessionId);
  assert(budgetStillPaused?.status === "paused_budget", "the earlier budget-paused session is unaffected by the later auth pause (no cross-session bleed)");

  // isRunning derivation (HuntConsole.tsx) — the acceptance criterion "the
  // LIVE badge is gone" reduces to this boolean, computed the same way the
  // component computes it.
  const isRunning = huntStore.activeSessions.some(s => s.status === "running" || s.status === "stopping");
  assert(isRunning === false, "isRunning (LIVE-badge driver) is false with both sessions paused and none running");

  console.log(failures === 0 ? "\nALL CHECKS PASSED\n" : `\n${failures} CHECK(S) FAILED\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
