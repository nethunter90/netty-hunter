/**
 * Target Selection Intelligence
 * Pre-hunt program scoring and ranking based on metadata, ROI, and — where a
 * program has been synced with real HackerOne data — actual per-asset scope
 * richness (asset type, bounty eligibility, severity ceiling) and program
 * state (paying vs. VDP-only), instead of just a flat payout number and
 * scope-array length.
 *
 * Deliberately does NOT penalize a program for lacking RCE-chain-friendly
 * surface — there is no separate "RCE fit" scoring term. A program whose
 * scope can't plausibly yield an RCE chain still scores well if it pays,
 * has real bounty-eligible assets, and an uncapped severity ceiling; the
 * only place asset type matters is the general assetTestabilityScore below
 * (can this engine test it AT ALL), which is one weighted factor among many,
 * not a gate.
 */
import { db } from "../db";
import { programs, findings, campaigns } from "../db/schema";
import { eq, desc, sql } from "drizzle-orm";
import logger from "../utils/logger";
import type { ProgramMetadata, ScopeAsset } from "../lib/bounty-intelligence/program-fetcher";

export interface ProgramScore {
  programId: number;
  name: string;
  platform: string;
  roiScore: number;
  successProbability: number;
  avgPayout: number;
  responseTime: number;
  competitionLevel: "low" | "medium" | "high";
  rank: number;
  factors: Record<string, number>;
  /** Human-readable reasons behind the score, for a recommendation UI —
   *  not just an opaque number. */
  notes: string[];
}

// Asset types this engine can actually generate HTTP-based probes against.
// Mobile/hardware/other assets are real in-scope targets, just not ones
// this platform's web-focused hunt loop can test.
const WEB_TESTABLE_TYPES = new Set<ScopeAsset["type"]>(["url", "domain", "wildcard", "api"]);
// Severity ceilings that meaningfully cap what a finding there can be worth —
// "low"/"none"/"informational" mean even a real bug is unlikely to be a
// serious report. Undefined/other values are treated as uncapped.
const LOW_SEVERITY_CAPS = new Set(["none", "low", "informational"]);

export class TargetSelectionIntelligence {
  async scorePrograms(): Promise<ProgramScore[]> {
    const allPrograms = await db.select().from(programs).where(eq(programs.active, true));
    const scores: ProgramScore[] = [];

    for (const prog of allPrograms) {
      const score = await this.scoreProgram(prog.id, prog);
      scores.push(score);
    }

    // Rank by ROI score
    scores.sort((a, b) => b.roiScore - a.roiScore);
    scores.forEach((s, i) => { s.rank = i + 1; });

    logger.info("Target Selection: Programs ranked", { count: scores.length });
    return scores;
  }

  private async scoreProgram(
    programId: number,
    prog: typeof programs.$inferSelect
  ): Promise<ProgramScore> {
    // Fetch historical data
    const huntCount = await db.select({ count: sql<number>`count(*)` })
      .from(campaigns).where(eq(campaigns.programId, programId));
    const findingCount = await db.select({ count: sql<number>`count(*)` })
      .from(findings)
      .innerJoin(campaigns, eq(findings.campaignId, campaigns.id))
      .where(eq(campaigns.programId, programId));

    const hunts = Number(huntCount[0]?.count || 0);
    const finds = Number(findingCount[0]?.count || 0);

    const metadata = (prog.metadata as ProgramMetadata) || {};
    const inScopeAssets = metadata.scopeAssets?.inScope;
    const notes: string[] = [];

    // ── Real-scope-derived factors — neutral (0.5) default when a program
    // has no scopeAssets data (manually created, non-HackerOne, or synced
    // before this feature existed) so it isn't unfairly punished for lacking
    // data it was never given a chance to have. ──────────────────────────
    let assetTestabilityScore = 0.5;
    let bountyEligibleScore = 0.5;
    let severityCeilingScore = 0.5;

    if (inScopeAssets && inScopeAssets.length > 0) {
      const testable = inScopeAssets.filter(a => WEB_TESTABLE_TYPES.has(a.type)).length;
      assetTestabilityScore = testable / inScopeAssets.length;
      if (assetTestabilityScore < 0.5) {
        notes.push(`Only ${testable}/${inScopeAssets.length} in-scope assets are web-testable (rest are mobile/hardware/other)`);
      }

      const eligible = inScopeAssets.filter(a => a.eligible !== false).length;
      bountyEligibleScore = eligible / inScopeAssets.length;
      if (bountyEligibleScore < 1) {
        notes.push(`${inScopeAssets.length - eligible}/${inScopeAssets.length} in-scope assets are not bounty-eligible`);
      }

      const uncapped = inScopeAssets.filter(a => !a.maxSeverity || !LOW_SEVERITY_CAPS.has(a.maxSeverity.toLowerCase())).length;
      severityCeilingScore = uncapped / inScopeAssets.length;
      if (severityCeilingScore < 0.5) {
        notes.push(`Most in-scope assets cap severity at low/none — findings there are unlikely to pay well even if real`);
      }
    }

    // offersBounties undefined (unknown) defaults mildly optimistic rather
    // than penalizing — most tracked programs on these platforms do pay.
    // A CONFIRMED false (VDP-only) is scored down but never to zero — still
    // worth hunting for CVE credit/reputation, just not for money.
    const payingProgramScore = metadata.offersBounties === false ? 0.3 : metadata.offersBounties === true ? 1 : 0.7;
    if (metadata.offersBounties === false) notes.push("VDP-only — no monetary bounty, still worth hunting for CVE credit");

    // Scoring factors (0-1 each)
    const factors: Record<string, number> = {
      // Payout potential (normalized to $10k max)
      payoutScore: Math.min(1, (prog.maxPayout || 0) / 10000),

      // Response time (faster = better; normalize to 24h target)
      responseTimeScore: Math.max(0, 1 - ((prog.responseTime || 168) / 168)),

      // Historical success rate
      successRateScore: prog.successRate || (hunts > 0 ? finds / hunts : 0.3),

      // Scope breadth (wider = more opportunities; inferred from scope array length)
      scopeBreadthScore: Math.min(1, ((prog.scope as string[]).length || 1) / 10),

      // Program age / maturity (newer programs have fewer hunters)
      noiseScore: hunts < 5 ? 0.8 : Math.max(0, 1 - (hunts / 50)),

      // Platform reputation
      platformScore: { hackerone: 0.9, bugcrowd: 0.85, intigriti: 0.8, synack: 0.95, yeswehack: 0.75 }[prog.platform] || 0.5,

      // Real per-asset scope data (neutral default when absent — see above)
      assetTestabilityScore,
      bountyEligibleScore,
      severityCeilingScore,
      payingProgramScore,
    };

    const weights = {
      payoutScore: 0.20,
      responseTimeScore: 0.10,
      successRateScore: 0.15,
      scopeBreadthScore: 0.05,
      noiseScore: 0.05,
      platformScore: 0.05,
      assetTestabilityScore: 0.15,
      bountyEligibleScore: 0.10,
      severityCeilingScore: 0.10,
      payingProgramScore: 0.05,
    };

    const roiScore = Object.entries(factors).reduce((sum, [k, v]) => {
      return sum + v * (weights[k as keyof typeof weights] || 0);
    }, 0);

    const competition = hunts > 20 ? "high" : hunts > 5 ? "medium" : "low";

    if (!inScopeAssets) notes.push("No per-asset scope data — sync from HackerOne for a more precise score");

    return {
      programId,
      name: prog.name,
      platform: prog.platform,
      roiScore: Math.round(roiScore * 100) / 100,
      successProbability: factors.successRateScore,
      avgPayout: prog.avgPayout || 0,
      responseTime: prog.responseTime || 0,
      competitionLevel: competition,
      rank: 0,
      factors,
      notes,
    };
  }

  async recommendNextTarget(excludeProgramIds: number[] = []): Promise<ProgramScore | null> {
    const scores = await this.scorePrograms();
    return scores.find(s => !excludeProgramIds.includes(s.programId)) || null;
  }
}

export default TargetSelectionIntelligence;
