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

const VULN_CLASS_BY_COMPLEXITY: Record<Complexity, string[]> = {
  trivial:  ["xss", "sqli", "info_disclosure", "security_headers"],
  simple:   ["xss", "sqli", "idor", "cors", "open_redirect", "info_disclosure"],
  moderate: ["sqli", "ssrf", "idor", "auth_bypass", "xxe", "xss", "lfi"],
  complex:  ["rce", "ssrf", "sqli", "auth_bypass", "deserialization", "ssti", "xxe"],
  expert:   ["rce", "deserialization", "prototype_pollution", "race_condition", "ssti", "sqli"],
};

class EffortScaler {
  analyze(targetUrl: string, goal: string): EffortProfile {
    const combined = `${targetUrl} ${goal}`.toLowerCase();
    const factors: ComplexityFactor[] = [];

    let totalWeight = 1.0;
    for (const { pattern, factor, weight } of COMPLEXITY_PATTERNS) {
      const matched = pattern.test(combined);
      factors.push({ name: factor, weight, matched });
      if (matched) totalWeight *= weight;
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

export const effortScaler = new EffortScaler();
