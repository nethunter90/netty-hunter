/**
 * Target Selection Intelligence
 * Pre-hunt program scoring and ranking based on metadata and ROI.
 */
import { db } from "../db";
import { programs, findings, campaigns } from "../db/schema";
import { eq, desc, sql } from "drizzle-orm";
import logger from "../utils/logger";

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
}

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
    };

    const weights = {
      payoutScore: 0.3,
      responseTimeScore: 0.15,
      successRateScore: 0.25,
      scopeBreadthScore: 0.1,
      noiseScore: 0.1,
      platformScore: 0.1,
    };

    const roiScore = Object.entries(factors).reduce((sum, [k, v]) => {
      return sum + v * (weights[k as keyof typeof weights] || 0);
    }, 0);

    const competition = hunts > 20 ? "high" : hunts > 5 ? "medium" : "low";

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
    };
  }

  async recommendNextTarget(excludeProgramIds: number[] = []): Promise<ProgramScore | null> {
    const scores = await this.scorePrograms();
    return scores.find(s => !excludeProgramIds.includes(s.programId)) || null;
  }
}

export default TargetSelectionIntelligence;
