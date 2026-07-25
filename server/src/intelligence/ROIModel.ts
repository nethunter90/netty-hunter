/**
 * ROI Model
 * Calculates expected value per vulnerability type.
 * Auto-tunes confidence thresholds based on historical performance.
 *
 * PROVENANCE (2026-07-23 readiness handoff): this class used to read/write
 * the RL table directly via raw db.select/insert/update calls under
 * domain "tool_success", key=vulnClass — a second, undocumented writer into
 * the same domain UnifiedReinforcementStore.recordToolOutcome() uses (with a
 * different key shape: bare vulnClass here vs "tool:vulnClass" there — they
 * don't collide, but they were both unsegregated by lab/real). That bypass is
 * now closed: every read/write here goes through
 * UnifiedReinforcementStore.getVulnClassStats()/recordVulnClassOutcome(),
 * which prefixes the key by provenance exactly like every other RL consumer.
 * Every public method that touches the store now requires a `provenance`
 * argument — callers must resolve it via resolveProvenance()
 * (lib/hunter/custom-target-program.ts) or reuse an already-resolved value
 * (e.g. HunterEngine's own ReinforcementWiring.getProvenance()).
 */
import { db } from "../db";
import { programs } from "../db/schema";
import { eq } from "drizzle-orm";
import { UnifiedReinforcementStore, Provenance } from "./ReinforcementStore";

// Average bug bounty payouts by severity/type (USD) – industry averages
const BASE_PAYOUTS: Record<string, number> = {
  rce: 8000,
  sqli: 4000,
  ssrf: 3500,
  auth_bypass: 5000,
  xxe: 3000,
  lfi: 2000,
  idor: 2500,
  xss: 1200,
  csrf: 800,
  open_redirect: 500,
  cors: 700,
  info_disclosure: 400,
  misconfig: 600,
  exposed_admin: 1500,
  subdomain_takeover: 2000,
  rate_limit_bypass: 500,
  business_logic: 3000,
  security_headers: 200,
};

export interface VulnROI {
  vulnClass: string;
  basePayout: number;
  adjustedPayout: number;
  expectedValue: number;
  huntingCost: number;     // time * hourly rate
  roi: number;             // (ev - cost) / cost
  confidenceThreshold: number; // auto-tuned minimum confidence to pursue
  successRate: number;
}

export class ROIModel {
  private readonly HOURLY_RATE = 150; // $150/hr equivalent
  private readonly rl = UnifiedReinforcementStore.getInstance();

  async calculateExpectedValue(
    vulnClass: string,
    programMaxPayout: number,
    provenance: Provenance,
    programId?: number,
  ): Promise<VulnROI> {
    // Fetch program-specific historical payout & success rate when programId is provided
    let programAvgPayout: number | null = null;
    let programSuccessRate: number | null = null;

    if (programId) {
      const [prog] = await db.select({
        avgPayout: programs.avgPayout,
        successRate: programs.successRate,
      }).from(programs).where(eq(programs.id, programId)).limit(1);

      if (prog) {
        programAvgPayout = prog.avgPayout;
        programSuccessRate = prog.successRate;
      }
    }

    // Blend: 60% global base payout, 40% program historical average (when available)
    const globalBase = Math.min(BASE_PAYOUTS[vulnClass] || 1000, programMaxPayout);
    const basePayout = programAvgPayout && programAvgPayout > 0
      ? Math.round(globalBase * 0.6 + programAvgPayout * 0.4)
      : globalBase;

    // Fetch historical success rate from reinforcement store — provenance-gated,
    // see module docstring.
    const { successCount: s, totalCount: n } = await this.rl.getVulnClassStats(vulnClass, provenance);

    // Bayesian smoothing with Beta(1,3) prior (mean=0.25): (successes+1)/(total+4).
    // At 0 observations → 0.25; at 5 failed attempts → 1/9 ≈ 0.11 (graceful, not 0.0).
    // The prior dissolves naturally as data accumulates — no cliff edge at the 5-attempt boundary.
    const rlRate = (s + 1) / (n + 4);

    // Blend: 70% RL store rate, 30% program-specific historical rate (when available)
    const successRate = programSuccessRate && programSuccessRate > 0
      ? rlRate * 0.7 + programSuccessRate * 0.3
      : rlRate;

    const adjustedPayout = basePayout * this.getSeverityMultiplier(vulnClass);
    const ev = adjustedPayout * successRate;
    const huntingCost = this.estimateHuntingTime(vulnClass) * this.HOURLY_RATE;
    const roi = huntingCost > 0 ? (ev - huntingCost) / huntingCost : 0;

    // Auto-tune confidence threshold: higher EV = lower threshold (worth pursuing even uncertain leads)
    const confidenceThreshold = Math.max(0.15, Math.min(0.7, 0.6 - (ev / 10000)));

    return {
      vulnClass,
      basePayout,
      adjustedPayout,
      expectedValue: Math.round(ev * 100) / 100,
      huntingCost: Math.round(huntingCost * 100) / 100,
      roi: Math.round(roi * 100) / 100,
      confidenceThreshold,
      successRate,
    };
  }

  async rankVulnClasses(programMaxPayout: number, provenance: Provenance, programId?: number): Promise<VulnROI[]> {
    const classes = Object.keys(BASE_PAYOUTS);
    const rois = await Promise.all(
      classes.map(vc => this.calculateExpectedValue(vc, programMaxPayout, provenance, programId))
    );
    rois.sort((a, b) => b.expectedValue - a.expectedValue);
    return rois;
  }

  async updateSuccessRate(vulnClass: string, found: boolean, provenance: Provenance): Promise<void> {
    await this.rl.recordVulnClassOutcome(vulnClass, found, provenance);
  }

  private getSeverityMultiplier(vulnClass: string): number {
    const multipliers: Record<string, number> = {
      rce: 1.5, sqli: 1.2, ssrf: 1.1, auth_bypass: 1.3, xxe: 1.1,
      lfi: 1.0, idor: 1.0, xss: 0.9, csrf: 0.8, open_redirect: 0.7,
    };
    return multipliers[vulnClass] || 1.0;
  }

  private estimateHuntingTime(vulnClass: string): number {
    // Hours to hunt for this vuln class
    const times: Record<string, number> = {
      rce: 8, sqli: 3, ssrf: 4, auth_bypass: 6, xxe: 5,
      lfi: 3, idor: 2, xss: 2, csrf: 1, open_redirect: 0.5,
      security_headers: 0.25, info_disclosure: 1, misconfig: 2,
    };
    return times[vulnClass] || 2;
  }
}

export default ROIModel;
