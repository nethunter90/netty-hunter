/**
 * EffortScaler regression tests (2026-07-03, post-benchmark fix).
 *
 * A real sentprime hunt launched with a generic goal string scored
 * "trivial" — before any crawling happened — which excluded rce/auth_bypass/
 * idor from focusVulnClasses entirely. The target had 3 RCE endpoints, an
 * IDOR→account-takeover chain, and an auth-bypass middleware; none of them
 * were ever hypothesized because the classifier judged complexity purely
 * from the launch string, with no floor against excluding high-severity
 * classes and no path to revise the judgment once real signal existed.
 *
 * These are the "cheap teeth": if a future change to effort-scaling.ts
 * reintroduces either failure mode, these tests catch it before a real hunt
 * silently narrows itself away from the classes that matter most.
 */
import { describe, it, expect } from "vitest";
import { effortScaler, isHigherTier } from "../lib/intelligence/effort-scaling";

const SENTPRIME_TARGET_URL = "http://localhost:5000";
const SENTPRIME_GENERIC_GOAL = "Hunt for vulnerabilities on http://localhost:5000";

// A representative slice of what a real crawl of sentprime's actual feature
// panels would surface — the endpoints this exact benchmark run never
// discovered because deepCrawl's shallow pass never reached them.
const SENTPRIME_DEEP_CRAWL_ENDPOINTS = [
  "/api/terminal-bridge/execute",
  "/api/tools/binary-analyze",
  "/api/team/members",
  "/api/user/api-key/generate",
  "/api/agent/tools",
  "/api/proxy/forward",
  "/api/diagnostics",
  "/api/download/source",
  "/api/ui-state/state",
  "/api/ui-state/patterns",
  "/api/mission-control/agents",
  "/api/governance/stats",
];

describe("EffortScaler — high-severity floor (handoff: never gate these away pre-observation)", () => {
  it("the exact sentprime launch (generic goal string, no crawl signal) still includes rce/auth_bypass/idor", () => {
    // This is the literal input that scored "trivial" in the real benchmark run.
    const profile = effortScaler.analyze(SENTPRIME_TARGET_URL, SENTPRIME_GENERIC_GOAL);
    expect(profile.complexity).toBe("trivial"); // the string genuinely doesn't trigger any keyword — that's fine
    // ...but the floor must hold regardless of how badly the string-only guess undershoots.
    expect(profile.focusVulnClasses).toContain("rce");
    expect(profile.focusVulnClasses).toContain("auth_bypass");
    expect(profile.focusVulnClasses).toContain("idor");
  });

  it("every complexity tier includes the floor, not just trivial", () => {
    const goalsByExpectedTier: Array<[string, string]> = [
      [SENTPRIME_TARGET_URL, ""], // trivial
      ["http://x/api", "search query filter"], // some tier above trivial
      ["http://x/admin/api/auth/login", "payment billing checkout upload serialize webhook"], // high tier
    ];
    for (const [url, goal] of goalsByExpectedTier) {
      const profile = effortScaler.analyze(url, goal);
      expect(profile.focusVulnClasses).toContain("rce");
      expect(profile.focusVulnClasses).toContain("auth_bypass");
      expect(profile.focusVulnClasses).toContain("idor");
    }
  });
});

describe("EffortScaler — post-crawl rescale (handoff: classify from observed signal, not the launch string)", () => {
  it("the same generic sentprime launch scores ABOVE trivial once real crawl signal is provided", () => {
    const provisional = effortScaler.analyze(SENTPRIME_TARGET_URL, SENTPRIME_GENERIC_GOAL);
    expect(provisional.complexity).toBe("trivial");

    const rescaled = effortScaler.analyze(SENTPRIME_TARGET_URL, SENTPRIME_GENERIC_GOAL, SENTPRIME_DEEP_CRAWL_ENDPOINTS);
    expect(isHigherTier(rescaled.complexity, provisional.complexity)).toBe(true);
    // High-severity endpoint keywords (terminal/admin/proxy/binary/diagnostics)
    // should be enough to clear at least "moderate", ideally higher.
    expect(["moderate", "complex", "expert"]).toContain(rescaled.complexity);
  });

  it("a large discovered surface alone (no specific keyword matches) still raises the tier", () => {
    const manyGenericEndpoints = Array.from({ length: 50 }, (_, i) => `/api/resource${i}`);
    const provisional = effortScaler.analyze(SENTPRIME_TARGET_URL, SENTPRIME_GENERIC_GOAL);
    const rescaled = effortScaler.analyze(SENTPRIME_TARGET_URL, SENTPRIME_GENERIC_GOAL, manyGenericEndpoints);
    expect(isHigherTier(rescaled.complexity, provisional.complexity)).toBe(true);
  });

  it("a small, unremarkable discovered surface does not spuriously escalate the tier", () => {
    const fewBenignEndpoints = ["/api/health", "/api/version"];
    const provisional = effortScaler.analyze(SENTPRIME_TARGET_URL, SENTPRIME_GENERIC_GOAL);
    const rescaled = effortScaler.analyze(SENTPRIME_TARGET_URL, SENTPRIME_GENERIC_GOAL, fewBenignEndpoints);
    expect(rescaled.complexity).toBe(provisional.complexity);
  });

  it("rce is actually IN focus (not just present via the floor) once command-surface endpoints are observed", () => {
    const rescaled = effortScaler.analyze(SENTPRIME_TARGET_URL, SENTPRIME_GENERIC_GOAL, SENTPRIME_DEEP_CRAWL_ENDPOINTS);
    expect(rescaled.rationale).toMatch(/command_surface|privileged_endpoint|agent_surface/);
  });
});

describe("isHigherTier ordering", () => {
  it("orders tiers correctly", () => {
    expect(isHigherTier("expert", "trivial")).toBe(true);
    expect(isHigherTier("trivial", "expert")).toBe(false);
    expect(isHigherTier("moderate", "moderate")).toBe(false);
    expect(isHigherTier("complex", "moderate")).toBe(true);
  });
});
