/**
 * Autonomy Maturity Tracking System
 * Tracks genuine autonomy maturity after 50+ hunts.
 * Includes: Brier snapshots, reinforcement noise detection,
 * Composite Autonomy Maturity Score (CAMS), Per-Domain Autonomy Gating.
 *
 * 6 Operational Domains:
 * 1. Hypothesis Generation
 * 2. Tool Selection
 * 3. Scope Adherence
 * 4. False Positive Rate
 * 5. Exploit Chain Depth
 * 6. Reporting Quality
 */
import { db } from "../db";
import { autonomyMetrics } from "../db/schema";
import { desc } from "drizzle-orm";
import { UnifiedReinforcementStore } from "./ReinforcementStore";
import logger from "../utils/logger";

export type AutonomyDomain =
  | "hypothesis_generation"
  | "tool_selection"
  | "scope_adherence"
  | "false_positive_rate"
  | "exploit_chain_depth"
  | "reporting_quality";

export interface DomainScore {
  domain: AutonomyDomain;
  score: number;             // 0-1
  trend: "improving" | "stable" | "declining";
  maturityLevel: "nascent" | "developing" | "competent" | "proficient" | "expert";
  regressionDetected: boolean;
  lastUpdated: Date;
}

export interface AutonomyMaturityReport {
  huntNumber: number;
  compositeScore: number;       // CAMS: 0-100
  maturityLevel: string;
  domainScores: Record<AutonomyDomain, DomainScore>;
  brierScore: number;
  reinforcementNoise: number;
  regressionFlags: string[];
  recommendations: string[];
  readyForFullAutonomy: boolean;
}

export class AutonomyMaturityTracker {
  private static instance: AutonomyMaturityTracker;
  private rlStore = UnifiedReinforcementStore.getInstance();
  private huntCount = 0;

  private domainHistory: Map<AutonomyDomain, number[]> = new Map();

  static getInstance(): AutonomyMaturityTracker {
    if (!AutonomyMaturityTracker.instance) {
      AutonomyMaturityTracker.instance = new AutonomyMaturityTracker();
    }
    return AutonomyMaturityTracker.instance;
  }

  async recordHuntOutcome(data: {
    hypothesesGenerated: number;
    hypothesesCorrect: number;
    toolsSelected: number;
    toolsCorrect: number;
    outOfScopeAttempts: number;
    falsePositives: number;
    confirmedFindings: number;
    chainDepth: number;
    reportQualityScore: number; // 0-1
  }): Promise<AutonomyMaturityReport> {
    this.huntCount++;

    // Compute domain scores
    const domainRawScores: Record<AutonomyDomain, number> = {
      hypothesis_generation: data.hypothesesGenerated > 0
        ? data.hypothesesCorrect / data.hypothesesGenerated
        : 0,
      tool_selection: data.toolsSelected > 0
        ? data.toolsCorrect / data.toolsSelected
        : 0.5,
      scope_adherence: Math.max(0, 1 - (data.outOfScopeAttempts * 0.1)),
      false_positive_rate: data.confirmedFindings + data.falsePositives > 0
        ? data.confirmedFindings / (data.confirmedFindings + data.falsePositives)
        : 0.5,
      exploit_chain_depth: Math.min(1, data.chainDepth / 5),
      reporting_quality: data.reportQualityScore,
    };

    // Update domain history for trend analysis
    for (const [domain, score] of Object.entries(domainRawScores)) {
      const history = this.domainHistory.get(domain as AutonomyDomain) || [];
      history.push(score);
      if (history.length > 10) history.shift();
      this.domainHistory.set(domain as AutonomyDomain, history);
    }

    // Build domain score objects with trend analysis
    const domainScores: Record<AutonomyDomain, DomainScore> = {} as Record<AutonomyDomain, DomainScore>;
    for (const [domain, score] of Object.entries(domainRawScores)) {
      const history = this.domainHistory.get(domain as AutonomyDomain) || [score];
      const trend = this.computeTrend(history);
      const regressionDetected = trend === "declining" && score < 0.5;

      domainScores[domain as AutonomyDomain] = {
        domain: domain as AutonomyDomain,
        score,
        trend,
        maturityLevel: this.scoreToMaturity(score),
        regressionDetected,
        lastUpdated: new Date(),
      };
    }

    // Composite Autonomy Maturity Score (CAMS)
    const domainWeights: Record<AutonomyDomain, number> = {
      hypothesis_generation: 0.25,
      tool_selection: 0.20,
      scope_adherence: 0.20,
      false_positive_rate: 0.20,
      exploit_chain_depth: 0.10,
      reporting_quality: 0.05,
    };

    const compositeScore = Math.round(
      Object.entries(domainScores).reduce((sum, [domain, ds]) => {
        return sum + ds.score * (domainWeights[domain as AutonomyDomain] || 0);
      }, 0) * 100
    );

    // Brier score for calibration quality
    const brierScore = await this.rlStore.computeBrierScore();

    // Reinforcement noise detection
    const rlStats = await this.rlStore.getStats();
    const avgSuccessRates = Object.values(rlStats).map(s => s.avgSuccessRate);
    const noise = this.computeVariance(avgSuccessRates);

    const regressionFlags = Object.entries(domainScores)
      .filter(([, ds]) => ds.regressionDetected)
      .map(([domain]) => `Regression in ${domain}`);

    const recommendations = this.generateRecommendations(domainScores, compositeScore);
    const readyForFullAutonomy = compositeScore >= 75 && this.huntCount >= 50 && regressionFlags.length === 0;

    const report: AutonomyMaturityReport = {
      huntNumber: this.huntCount,
      compositeScore,
      maturityLevel: this.camsToLabel(compositeScore),
      domainScores,
      brierScore,
      reinforcementNoise: noise,
      regressionFlags,
      recommendations,
      readyForFullAutonomy,
    };

    // Persist to DB
    await db.insert(autonomyMetrics).values({
      huntNumber: this.huntCount,
      compositeScore,
      domainScores: domainScores as unknown as Record<string, unknown>,
      brierSnapshot: brierScore,
      reinforcementNoise: noise,
      regressionDetected: regressionFlags.length > 0,
      metadata: report as unknown as Record<string, unknown>,
    });

    logger.info("Autonomy Maturity recorded", {
      huntNumber: this.huntCount,
      compositeScore,
      maturityLevel: report.maturityLevel,
    });

    return report;
  }

  async getLatestReport(): Promise<AutonomyMaturityReport | null> {
    const [latest] = await db.select().from(autonomyMetrics)
      .orderBy(desc(autonomyMetrics.recordedAt))
      .limit(1);

    if (!latest) return null;
    return latest.metadata as unknown as AutonomyMaturityReport;
  }

  async getProgressHistory(limit: number = 20): Promise<Array<{ huntNumber: number; compositeScore: number; recordedAt: Date }>> {
    const records = await db.select({
      huntNumber: autonomyMetrics.huntNumber,
      compositeScore: autonomyMetrics.compositeScore,
      recordedAt: autonomyMetrics.recordedAt,
    }).from(autonomyMetrics)
      .orderBy(desc(autonomyMetrics.recordedAt))
      .limit(limit);

    return records.reverse();
  }

  private computeTrend(history: number[]): "improving" | "stable" | "declining" {
    if (history.length < 3) return "stable";
    const recent = history.slice(-3);
    const avg = recent.reduce((a, b) => a + b, 0) / recent.length;
    const older = history.slice(-6, -3);
    const olderAvg = older.length > 0 ? older.reduce((a, b) => a + b, 0) / older.length : avg;

    if (avg - olderAvg > 0.05) return "improving";
    if (olderAvg - avg > 0.05) return "declining";
    return "stable";
  }

  private computeVariance(values: number[]): number {
    if (values.length === 0) return 0;
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    return values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / values.length;
  }

  private scoreToMaturity(score: number): DomainScore["maturityLevel"] {
    if (score >= 0.9) return "expert";
    if (score >= 0.75) return "proficient";
    if (score >= 0.55) return "competent";
    if (score >= 0.35) return "developing";
    return "nascent";
  }

  private camsToLabel(score: number): string {
    if (score >= 90) return "Expert Autonomy";
    if (score >= 75) return "Proficient Autonomy";
    if (score >= 55) return "Competent Autonomy";
    if (score >= 35) return "Developing Autonomy";
    return "Nascent Autonomy";
  }

  private generateRecommendations(
    domainScores: Record<AutonomyDomain, DomainScore>,
    compositeScore: number
  ): string[] {
    const recs: string[] = [];

    if (domainScores.hypothesis_generation.score < 0.5) {
      recs.push("Improve hypothesis quality: add more static analysis patterns to seed generation");
    }
    if (domainScores.false_positive_rate.score < 0.6) {
      recs.push("Reduce false positives: strengthen Layer 3 browser validation gate");
    }
    if (domainScores.scope_adherence.score < 0.9) {
      recs.push("Critical: Scope violations detected – review ScopeGuard configuration");
    }
    if (domainScores.tool_selection.score < 0.6) {
      recs.push("Improve tool selection: update Framework-Vuln Matrix with more data");
    }
    if (compositeScore < 50) {
      recs.push("System needs more hunts to calibrate – manual oversight recommended");
    }

    return recs;
  }
}

export default AutonomyMaturityTracker;
