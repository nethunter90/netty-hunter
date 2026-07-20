import { describe, test, expect } from "vitest";
import fs from "fs";
import path from "path";
import { normalizeVulnClass } from "../lib/vuln-taxonomy";

/**
 * Phase 2 — deterministic routing-reproduction validation for the taxonomy
 * fix, per the coverage-gap/taxonomy handoff's rule: "validate by routing
 * reproduction, not by re-running the full hunt." This proves the #4 fix
 * end-to-end WITHOUT spinning up a real hunt (no DB, no Playwright, no
 * Anthropic calls) — attributable and fast.
 *
 * The routing decision itself lives deep inside HunterEngine.probe(), which
 * isn't practically unit-testable in isolation (it's entangled with live
 * scopedHttp/Playwright/DB state). Instead of mocking all of that, this test
 * extracts the ACTUAL routing-gate literal array from the source file (same
 * technique as the drift guard) and composes it with normalizeVulnClass() —
 * together these two real artifacts deterministically prove the routing
 * outcome for any input, with zero behavioral assumptions.
 *
 * Claim being proven: "#4 now routes to LogicExploitAgent, proven
 * deterministically" — NOT "#4 now converts to a finding." Whether
 * LogicExploitAgent can actually confirm a checkout-bypass once dispatched is
 * a separate, unbuilt question (the checkout-probe wall this fix doesn't
 * touch) — this test makes no claim about that.
 */

const SERVER_SRC = path.resolve(__dirname, "..");

function getRoutingAllowlist(): string[] {
  const src = fs.readFileSync(path.join(SERVER_SRC, "agents/HunterEngine.ts"), "utf-8");
  const m = src.match(
    /\["business_logic", "race_condition", "idor", "auth_bypass"\]\.includes\(hypothesis\.vulnClass\)/
  );
  if (!m) throw new Error("LogicExploitAgent routing gate not found at its known location — source moved, update this test");
  const literals = m[0].match(/"[a-z0-9_]+"/g) ?? [];
  return literals.map((l) => l.slice(1, -1));
}

/** Simulates what HunterEngine.ts:2679 actually evaluates, using the real
 *  extracted allowlist — not a re-typed copy. */
function routesToLogicExploitAgent(vulnClass: string): boolean {
  return getRoutingAllowlist().includes(vulnClass);
}

describe("taxonomy fix — routing reproduction (deterministic, no hunt required)", () => {
  test("BEFORE the fix, raw 'authentication_bypass' would NOT have routed (regression anchor)", () => {
    // This documents the original #4 bug precisely: the raw, un-normalized
    // string never matches the routing gate's canonical-only allowlist.
    expect(routesToLogicExploitAgent("authentication_bypass")).toBe(false);
  });

  test("AFTER the fix, a chain-synthesis 'authentication_bypass' hypothesis routes to LogicExploitAgent", () => {
    // This is the exact input that broke #4: chain-synthesis emitted this
    // raw string as next_hypothesis.vulnClass. The ingestion fix
    // (HunterEngine.ts's synthesizeChainedAttack()) now runs every
    // next_hypothesis.vulnClass through normalizeVulnClass() before the
    // hypothesis is ever pushed to state.hypotheses — so by the time the
    // routing gate sees it, it's already canonical.
    const raw = "authentication_bypass";
    const normalized = normalizeVulnClass(raw);
    expect(normalized).toBe("auth_bypass");
    expect(routesToLogicExploitAgent(normalized!)).toBe(true);
  });

  test("the sibling drift found in the census also now routes correctly", () => {
    const cases: Array<[string, string]> = [
      ["authorization_bypass", "auth_bypass"],
    ];
    for (const [raw, expectedCanonical] of cases) {
      const normalized = normalizeVulnClass(raw);
      expect(normalized).toBe(expectedCanonical);
      expect(routesToLogicExploitAgent(normalized!)).toBe(true);
    }
  });

  test("the other three routing-eligible classes still route (no regression from the fix)", () => {
    for (const vc of ["business_logic", "race_condition", "idor"]) {
      expect(normalizeVulnClass(vc)).toBe(vc);
      expect(routesToLogicExploitAgent(vc)).toBe(true);
    }
  });

  test("fail-loud path: a genuinely unrecognized class does not silently route anywhere, and is discardable pre-routing", () => {
    // Mirrors what HunterEngine.ts's ingestion code now does: if
    // normalizeVulnClass() returns null, the hypothesis is discarded (with a
    // logged warning) BEFORE it ever reaches a routing decision — it never
    // gets the chance to silently fall through to the nuclei/generic
    // fallback the way "authentication_bypass" used to.
    const raw = "lateral_movement"; // real example from the DB census — chain-synthesis impact-label leakage
    const normalized = normalizeVulnClass(raw);
    expect(normalized).toBeNull();
    // No routing call is made at all for a null-normalized hypothesis in the
    // real ingestion code (see HunterEngine.ts synthesizeChainedAttack()'s
    // `if (!vulnClass) { logger.warn(...); }` branch) — asserting the
    // precondition (null) is what makes that discard path reachable.
  });

  test("the ingestion source actually contains the discard-on-null guard (not just this test's assumption)", () => {
    const src = fs.readFileSync(
      path.join(SERVER_SRC, "agents/HunterEngine.ts"),
      "utf-8"
    );
    expect(src).toContain('logger.warn("[HunterEngine] Discarding hypothesis — unrecognized vulnClass"');
    expect(src).toContain(
      'logger.warn("[HunterEngine] Chain synthesis — discarding next_hypothesis with unrecognized vulnClass"'
    );
  });
});
