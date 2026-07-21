import { describe, test, expect } from "vitest";
import fs from "fs";
import path from "path";

/**
 * Leak C Phase 3b — deterministic selection-reproduction test, re-run against
 * the real session-143 fixture with the Phase 3a effective-confidence lift
 * added on top of the Phase 1 parity floor.
 *
 * Fixture columns (fixtures/leak-c-session-143-hypotheses.tsv):
 *   id | vulnClass | priority | confidence | createdAt | evidence_sources | has_success_probe
 * has_success_probe is a real bool_or() over hunt_sessions.probes for that
 * hypothesisId — i.e. this models effectiveConfidence's actual gating
 * condition (SELF_CONFIRMED evidence AND a real success:true probe already
 * recorded), not an approximation.
 */

const SELF_CONFIRMED_SOURCES = new Set([
  "race_condition_detector", "cookie_flag_checker", "host_header_probe", "oauth_probe",
  "mass_assignment_probe", "two_factor_bypass_probe", "jwt_confusion_probe",
  "prototype_pollution_probe", "cloud_bucket_probe", "websocket_probe",
  "open_redirect_chain_probe", "blind_xxe_probe", "crlf_probe", "deserialization_prober",
  "file_upload_webshell_prober", "blind_command_injection_prober",
]);

interface HypRow {
  id: string;
  vulnClass: string;
  priority: number;
  confidence: number;
  createdAt: number;
  isSelfConfirmed: boolean;
  hasSuccessProbe: boolean;
}

function loadFixture(): HypRow[] {
  const tsvPath = path.resolve(__dirname, "fixtures/leak-c-session-143-hypotheses.tsv");
  const raw = fs.readFileSync(tsvPath, "utf-8");
  return raw
    .trim()
    .split("\n")
    .map((line) => {
      const [id, vulnClass, priority, confidence, createdAt, sources, hasSuccess] = line.split("|");
      const srcs = (sources ?? "").split(",").filter(Boolean);
      return {
        id,
        vulnClass,
        priority: Number(priority) || 0,
        confidence: Number(confidence) || 0,
        createdAt: Number(createdAt) || 0,
        isSelfConfirmed: srcs.some((s) => SELF_CONFIRMED_SOURCES.has(s)),
        hasSuccessProbe: hasSuccess === "t",
      };
    });
}

/** Mirrors HunterEngine.ts's blendConfidence() exactly: 0.4/0.6 weighted
 *  blend against a successRate of 1.0 for a single successful probe
 *  (the fixture only tracks whether a matching probe SUCCEEDED, matching
 *  effectiveConfidence()'s own filter of `p.success` — real per-hunt probe
 *  counts for a hypothesis are consistently 1 in the traced case). */
function blendConfidence(baseConfidence: number): number {
  const successRate = 1.0;
  return Math.min(0.99, baseConfidence * 0.4 + successRate * 0.6);
}

/** Phase 1: priority floor to parity (9) for SELF_CONFIRMED evidence. */
function effectivePriority(h: HypRow): number {
  return h.isSelfConfirmed ? Math.max(h.priority, 9) : h.priority;
}

/** Phase 3a: preview update()'s confidence blend for ranking ONLY, gated on
 *  a real success:true probe already in hand — mirrors HunterEngine.ts's
 *  effectiveConfidence() precisely. */
function effectiveConfidence(h: HypRow): number {
  if (!h.isSelfConfirmed || !h.hasSuccessProbe) return h.confidence;
  return blendConfidence(h.confidence);
}

function oldScore(h: HypRow): number {
  return h.priority * h.confidence;
}

function phase1Score(h: HypRow): number {
  return effectivePriority(h) * h.confidence;
}

function phase3Score(h: HypRow): number {
  return effectivePriority(h) * effectiveConfidence(h);
}

function top8(rows: HypRow[], scoreFn: (h: HypRow) => number): HypRow[] {
  return [...rows].sort((a, b) => scoreFn(b) - scoreFn(a)).slice(0, 8);
}

const TARGET_ID = "b985752e-9800-44a5-832e-7ce9381b6c1f"; // the traced #7 mass_assignment hypothesis

describe("Leak C Phase 3b — deterministic selection reproduction (session 143, real data)", () => {
  const all = loadFixture();
  const target = all.find((h) => h.id === TARGET_ID)!;
  const contemporaries = all.filter((h) => h.createdAt <= target.createdAt);

  test("fixture + target sanity", () => {
    expect(target).toBeDefined();
    expect(target.isSelfConfirmed).toBe(true);
    expect(target.hasSuccessProbe).toBe(true);
    expect(target.confidence).toBe(0.6);
    expect(contemporaries.length).toBeGreaterThan(0);
    expect(contemporaries.length).toBeLessThan(all.length);
  });

  test("effectiveConfidence(target) matches the hand-computed blend (0.6*0.4 + 1.0*0.6 = 0.84)", () => {
    expect(effectiveConfidence(target)).toBeCloseTo(0.84, 5);
  });

  test("OLD ranking: target does not make top-8 (starvation baseline)", () => {
    expect(top8(contemporaries, oldScore).some((h) => h.id === TARGET_ID)).toBe(false);
  });

  test("PHASE 1 (parity floor only): target still does not make top-8 (matches the prior STOP-gate finding)", () => {
    expect(top8(contemporaries, phase1Score).some((h) => h.id === TARGET_ID)).toBe(false);
  });

  test("PHASE 3 (parity floor + confidence-blend preview): does target make top-8?", () => {
    const result = top8(contemporaries, phase3Score);
    const seated = result.some((h) => h.id === TARGET_ID);
    const rank = [...contemporaries].sort((a, b) => phase3Score(b) - phase3Score(a))
      .findIndex((h) => h.id === TARGET_ID);

    // Print the full ranking context regardless of outcome — this is the
    // number the handoff asks to report either way.
    // eslint-disable-next-line no-console
    console.log(
      "PHASE 3 rank (0-indexed):", rank, "of", contemporaries.length,
      "| seated in top8:", seated,
      "\ntop8:", top8(contemporaries, phase3Score).map((h) => ({
        id: h.id.slice(0, 8), vc: h.vulnClass,
        effPriority: effectivePriority(h), effConfidence: Number(effectiveConfidence(h).toFixed(3)),
        score: Number(phase3Score(h).toFixed(3)),
      }))
    );

    expect(seated).toBe(true);
  });
});
