/**
 * UI trust fix #5/7 -- Part C: feed real hunt:scope_context and
 * hunt:scope_blocked payload shapes (matching what
 * server/scripts/scope-visibility-proof.ts proved the engine really emits)
 * through the real huntStore mutators the bridge calls.
 *
 * Run (from client/): npx tsx scripts/scope-store-proof.ts
 */
import { huntStore } from "../src/lib/huntStore";
import type { ActivityEvent } from "../src/components/LiveActivityFeed";

let failures = 0;
function assert(cond: boolean, label: string): void {
  if (cond) console.log(`  PASS  ${label}`);
  else { failures++; console.log(`  FAIL  ${label}`); }
}

function handleScopeContext(data: { sessionId: string; provenance: string; scope: string[]; outOfScope: string[] }): void {
  huntStore.updateSessions(prev => prev.map(s =>
    s.sessionUuid === data.sessionId
      ? { ...s, provenance: data.provenance, scope: data.scope, outOfScope: data.outOfScope }
      : s
  ));
}

function handleScopeBlocked(data: { url: string; reason: string }): void {
  huntStore.pushEvent({ type: "scope_blocked", ts: new Date().toISOString(), url: data.url, reason: data.reason } as ActivityEvent);
}

function main(): void {
  const sessionUuid = "scope-proof-session";
  huntStore.updateSessions(() => [{
    sessionUuid, targetUrl: "http://localhost:8081/",
    status: "running", phase: "observe", iteration: 1, findings: 0,
  }]);

  console.log("=== hunt:scope_context (real program 1181 shape: provenance=real, scope=[\"localhost\"]) ===");
  handleScopeContext({ sessionId: sessionUuid, provenance: "real", scope: ["localhost"], outOfScope: [] });
  const afterContext = huntStore.activeSessions.find(s => s.sessionUuid === sessionUuid);
  assert(afterContext?.provenance === "real", `session.provenance set to "real" (got ${afterContext?.provenance})`);
  assert(JSON.stringify(afterContext?.scope) === JSON.stringify(["localhost"]), `session.scope set correctly (got ${JSON.stringify(afterContext?.scope)})`);

  console.log("\n=== hunt:scope_blocked (real captured shape: evil.example.com blocked) ===");
  handleScopeBlocked({ url: "https://evil.example.com/", reason: "URL not found in any in-scope patterns" });
  const feedEvent = huntStore.activityEvents.at(-1);
  assert(feedEvent?.type === "scope_blocked", `a "scope_blocked" activity-feed row was pushed (got type=${feedEvent?.type})`);
  assert((feedEvent as any)?.url === "https://evil.example.com/", `feed row carries the blocked URL`);
  assert((feedEvent as any)?.reason === "URL not found in any in-scope patterns", `feed row carries the real block reason`);

  // Session state must be untouched by the scope_blocked event (it's a feed
  // row, not a session-state mutation).
  const afterBlocked = huntStore.activeSessions.find(s => s.sessionUuid === sessionUuid);
  assert(afterBlocked?.provenance === "real", "session provenance still intact after a scope_blocked feed event");

  console.log(failures === 0 ? "\nALL CHECKS PASSED\n" : `\n${failures} CHECK(S) FAILED\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
