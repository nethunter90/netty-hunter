/**
 * EffortScaler — analyzes a hunt target at startup and recommends
 * probe budget, iteration limit, and token allocation.
 *
 * Prevents over-spending on simple targets and under-spending on hard ones.
 */

import type { Complexity } from "./failure-prediction";

export interface EffortProfile {
  complexity: Complexity;
  probeLimit: number;
  iterationLimit: number;
  parallelProbes: number;
  focusVulnClasses: string[];
  rationale: string;
}

interface ComplexityFactor {
  name: string;
  weight: number;
  matched: boolean;
}

const COMPLEXITY_PATTERNS: Array<{ pattern: RegExp; factor: string; weight: number }> = [
  { pattern: /api|graphql|rest/i,                   factor: "api_surface",     weight: 1.2 },
  { pattern: /auth|login|oauth|sso|jwt/i,           factor: "auth_layer",      weight: 1.3 },
  { pattern: /admin|dashboard|internal/i,           factor: "privileged_area", weight: 1.4 },
  { pattern: /upload|file|attachment|blob/i,        factor: "file_handling",   weight: 1.2 },
  { pattern: /serial|deserializ|pickle|marshal/i,   factor: "serialization",   weight: 1.5 },
  { pattern: /webhook|callback|redirect/i,          factor: "async_surface",   weight: 1.2 },
  { pattern: /search|query|filter|sort/i,           factor: "input_surface",   weight: 1.1 },
  { pattern: /payment|billing|stripe|checkout/i,    factor: "financial",       weight: 1.6 },
  { pattern: /flag|ctf|challenge|level/i,           factor: "ctf_target",      weight: 1.3 },
];

const PROFILES: Record<Complexity, Omit<EffortProfile, "complexity" | "focusVulnClasses" | "rationale">> = {
  trivial:  { probeLimit: 30,  iterationLimit: 5,  parallelProbes: 2 },
  simple:   { probeLimit: 60,  iterationLimit: 8,  parallelProbes: 3 },
  moderate: { probeLimit: 100, iterationLimit: 12, parallelProbes: 4 },
  complex:  { probeLimit: 160, iterationLimit: 18, parallelProbes: 6 },
  expert:   { probeLimit: 240, iterationLimit: 25, parallelProbes: 8 },
};

// handoff (2026-07-03, post-benchmark): a real sentprime hunt scored "trivial"
// purely from a generic launch string ("Hunt for vulnerabilities on
// http://localhost:5000"), which excluded rce/auth_bypass/idor from
// focusVulnClasses entirely — before any crawling happened, on a target that
// turned out to have RCE endpoints, an IDOR→takeover chain, and an
// auth-bypass middleware. No tier may ever exclude these three high-severity
// classes, regardless of what the string/crawl signal says — classifiers fail
// silently, so this is an unconditional floor, not a tunable default.
const HIGH_SEVERITY_FLOOR = ["rce", "auth_bypass", "idor"];

function withFloor(classes: string[]): string[] {
  return Array.from(new Set([...classes, ...HIGH_SEVERITY_FLOOR]));
}

const VULN_CLASS_BY_COMPLEXITY: Record<Complexity, string[]> = {
  trivial:  withFloor(["xss", "sqli", "info_disclosure", "security_headers"]),
  simple:   withFloor(["xss", "sqli", "idor", "cors", "open_redirect", "info_disclosure"]),
  moderate: withFloor(["sqli", "ssrf", "idor", "auth_bypass", "xxe", "xss", "lfi"]),
  complex:  withFloor(["rce", "ssrf", "sqli", "auth_bypass", "deserialization", "ssti", "xxe"]),
  expert:   withFloor(["rce", "deserialization", "prototype_pollution", "race_condition", "ssti", "sqli"]),
};

// Route-name keywords that mark a genuinely higher-value/higher-risk surface
// than the generic launch string could ever convey — these are checked
// against ACTUAL discovered endpoint paths (post-crawl), not the target URL.
// Each match is a strong signal: a target exposing an admin/terminal/proxy/
// binary-analysis surface is never "trivial", no matter how it was launched.
const ENDPOINT_SIGNAL_PATTERNS: Array<{ pattern: RegExp; factor: string; weight: number }> = [
  { pattern: /terminal|shell|execute|command/i,        factor: "command_surface",   weight: 2.0 },
  { pattern: /admin|team\/members|api-?key|privileged/i, factor: "privileged_endpoint", weight: 1.8 },
  { pattern: /proxy|agent\/(tools|ai)/i,                factor: "agent_surface",     weight: 1.6 },
  { pattern: /binary|hexdump|wireless|audit/i,          factor: "offensive_tooling", weight: 1.6 },
  { pattern: /diagnostics|download\/source|debug/i,     factor: "diagnostic_surface", weight: 1.4 },
];

class EffortScaler {
  /**
   * @param discoveredEndpoints Optional list of endpoint paths/URLs observed
   *   by an actual crawl (e.g. deepCrawl's endpointsFound) — when provided,
   *   these carry MORE weight than the launch string, since they reflect what
   *   the target actually exposes rather than how the operator phrased the
   *   goal. Callers should re-invoke analyze() with this once available
   *   (post-observe) and only ever escalate the effort profile, never
   *   downgrade it, from whatever the pre-crawl provisional call produced.
   */
  analyze(targetUrl: string, goal: string, discoveredEndpoints?: string[]): EffortProfile {
    const combined = `${targetUrl} ${goal}`.toLowerCase();
    const factors: ComplexityFactor[] = [];

    let totalWeight = 1.0;
    for (const { pattern, factor, weight } of COMPLEXITY_PATTERNS) {
      const matched = pattern.test(combined);
      factors.push({ name: factor, weight, matched });
      if (matched) totalWeight *= weight;
    }

    if (discoveredEndpoints && discoveredEndpoints.length > 0) {
      const endpointText = discoveredEndpoints.join(" ").toLowerCase();
      for (const { pattern, factor, weight } of ENDPOINT_SIGNAL_PATTERNS) {
        const matched = pattern.test(endpointText);
        factors.push({ name: factor, weight, matched });
        if (matched) totalWeight *= weight;
      }
      // A large discovered surface is itself a complexity signal, independent
      // of any specific keyword match — a 60-endpoint app isn't trivial.
      if (discoveredEndpoints.length > 40) totalWeight *= 1.6;
      else if (discoveredEndpoints.length > 15) totalWeight *= 1.3;
    }

    // Map total weight to complexity tier
    let complexity: Complexity;
    if (totalWeight < 1.2)      complexity = "trivial";
    else if (totalWeight < 1.5) complexity = "simple";
    else if (totalWeight < 2.2) complexity = "moderate";
    else if (totalWeight < 3.5) complexity = "complex";
    else                        complexity = "expert";

    const matchedFactors = factors.filter(f => f.matched).map(f => f.name);
    const profile = PROFILES[complexity];

    return {
      complexity,
      ...profile,
      focusVulnClasses: VULN_CLASS_BY_COMPLEXITY[complexity],
      rationale: matchedFactors.length > 0
        ? `${complexity} target — factors: ${matchedFactors.join(", ")} (weight=${totalWeight.toFixed(2)})`
        : `${complexity} target — no specific complexity factors detected`,
    };
  }
}

// Ordering used to decide whether a rescale is an upgrade — never allow a
// post-crawl rescale to DOWNGRADE the provisional pre-crawl profile (under-
// provisioning was the failure mode being fixed; over-provisioning is cheap).
const TIER_ORDER: Complexity[] = ["trivial", "simple", "moderate", "complex", "expert"];
export function isHigherTier(a: Complexity, b: Complexity): boolean {
  return TIER_ORDER.indexOf(a) > TIER_ORDER.indexOf(b);
}

export const effortScaler = new EffortScaler();
