import { describe, test, expect } from "vitest";
import fs from "fs";
import path from "path";
import { CANONICAL_VULN_CLASSES } from "../lib/vuln-taxonomy";

/**
 * Anti-drift guard (Phase 1, taxonomy census follow-up).
 *
 * Scope and honesty note: this guard catches a DIFFERENT bug class than
 * normalizeVulnClass() does. The original #4 bug — a chain-synthesis LLM call
 * emitting "authentication_bypass" — was a RUNTIME value from unconstrained
 * free text; no static scan of the source tree could ever have caught it,
 * because the literal string never appears anywhere in the source. That's
 * exactly why normalize() lives at the two LLM ingestion points instead of
 * being "solved" here.
 *
 * What this guard DOES catch: a future HARDCODED typo in one of the static
 * vulnClass vocabularies below (e.g. someone adding "buisness_logic" to
 * HIGH_SEVERITY_FLOOR, or a new probesFor() case keyed on a class that isn't
 * in the canonical list). That's a real, adjacent failure mode the census
 * surfaced was possible (multiple independent hardcoded lists, no shared
 * source of truth) — this is the compile-time-adjacent check for it.
 *
 * Implementation note: these constants are intentionally module-private in
 * their source files (not exported), so this test parses the literal arrays
 * out of the raw source text rather than importing them. That's a conscious
 * trade — it keeps internal implementation details private while still
 * giving the guard real teeth, at the cost of the regexes needing to be kept
 * in sync if a boundary's declaration shape changes materially.
 */

const CANONICAL = new Set<string>(CANONICAL_VULN_CLASSES);
const SERVER_SRC = path.resolve(__dirname, "..");

function readSource(relPath: string): string {
  return fs.readFileSync(path.join(SERVER_SRC, relPath), "utf-8");
}

function extractQuotedLiterals(block: string): string[] {
  const matches = block.match(/"[a-z0-9_]+"/g) ?? [];
  return matches.map((m) => m.slice(1, -1));
}

describe("vuln-taxonomy anti-drift guard — hardcoded boundary vocabularies", () => {
  test("HunterEngine.ts LogicExploitAgent routing gate is all-canonical", () => {
    const src = readSource("agents/HunterEngine.ts");
    const m = src.match(
      /\["business_logic", "race_condition", "idor", "auth_bypass"\]\.includes\(hypothesis\.vulnClass\)/
    );
    expect(m).not.toBeNull();
    const literals = extractQuotedLiterals(m![0]);
    expect(literals.length).toBeGreaterThan(0);
    for (const lit of literals) {
      expect(CANONICAL.has(lit)).toBe(true);
    }
  });

  test("effort-scaling.ts HIGH_SEVERITY_FLOOR and VULN_CLASS_BY_COMPLEXITY are all-canonical", () => {
    const src = readSource("lib/intelligence/effort-scaling.ts");

    const floorMatch = src.match(/const HIGH_SEVERITY_FLOOR = \[[^\]]+\]/);
    expect(floorMatch).not.toBeNull();
    for (const lit of extractQuotedLiterals(floorMatch![0])) {
      expect(CANONICAL.has(lit)).toBe(true);
    }

    const tiersMatch = src.match(
      /const VULN_CLASS_BY_COMPLEXITY: Record<Complexity, string\[\]> = \{[\s\S]*?\n\};/
    );
    expect(tiersMatch).not.toBeNull();
    const literals = extractQuotedLiterals(tiersMatch![0]);
    expect(literals.length).toBeGreaterThan(0);
    for (const lit of literals) {
      expect(CANONICAL.has(lit)).toBe(true);
    }
  });

  test("PostExploitAgent.ts NOT_DEMONSTRABLE keys are all-canonical", () => {
    const src = readSource("agents/PostExploitAgent.ts");
    const m = src.match(
      /NOT_DEMONSTRABLE: Readonly<Record<string, string>> = \{[\s\S]*?\n  \};/
    );
    expect(m).not.toBeNull();
    // Keys only — values are free-text reasons, not vulnClass values.
    const keyMatches = m![0].match(/^\s*([a-z0-9_]+):\s*"/gm) ?? [];
    const keys = keyMatches.map((k) => k.trim().replace(/:\s*"$/, ""));
    expect(keys.length).toBeGreaterThan(0);
    for (const key of keys) {
      expect(CANONICAL.has(key)).toBe(true);
    }
  });

  test("SELF_CONFIRMED_SOURCES entries correspond to producers whose vulnClass is canonical", () => {
    // This set is keyed on prober SOURCE names, not vulnClass values directly —
    // guarded instead by the completeness test in vuln-taxonomy.test.ts, which
    // checks every known producer literal (crlf_injection, mass_assignment,
    // etc.) normalizes. Documented here so the boundary isn't silently unguarded.
    const src = readSource("agents/HunterEngine.ts");
    const m = src.match(/const SELF_CONFIRMED_SOURCES = new Set\(\[[^\]]+\]\)/);
    expect(m).not.toBeNull();
    expect(extractQuotedLiterals(m![0]).length).toBeGreaterThan(0);
  });
});
