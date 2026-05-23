/**
 * ReinforcementStore — lib/hunter adapter
 *
 * Extends UnifiedReinforcementStore with richer read APIs:
 * tool profiles, framework-vuln matrix, program/platform rankings,
 * confidence calibration, and exploration stats.
 */
import { UnifiedReinforcementStore } from '../../intelligence/ReinforcementStore';
import { db } from '../../db';
import { reinforcementStore as rlTable } from '../../db/schema';
import { eq } from 'drizzle-orm';

export interface ToolProfile {
  tool: string;
  totalAttempts: number;
  successRate: number;
  byVulnClass: Record<string, { attempts: number; successRate: number }>;
  rank: number;
}

export interface FrameworkVulnProfile {
  framework: string;
  vulnClasses: Array<{ vulnClass: string; rate: number; attempts: number }>;
  topVuln: string;
}

export interface PlatformRankEntry {
  platform: string;
  avgSuccessRate: number;
  entries: number;
  rank: number;
}

export interface ProgramTypeProfile {
  programType: string;
  topStrategies: Array<{ strategy: string; successRate: number }>;
}

export interface CalibrationReport {
  brierScore: number;
  totalBuckets: number;
  wellCalibrated: boolean;
  byVulnClass: Record<string, { avgBias: number; buckets: number }>;
  message: string;
}

export interface ExplorationStats {
  totalExplored: number;
  uniquePatterns: number;
  hotspots: Array<{ pattern: string; count: number }>;
  coldAreas: string[];
}

export interface RLSnapshot {
  toolProfiles: ToolProfile[];
  frameworkVulnProfiles: FrameworkVulnProfile[];
  platformRanking: PlatformRankEntry[];
  calibration: CalibrationReport;
  explorationStats: ExplorationStats;
  capturedAt: number;
}

// ── Adapter ───────────────────────────────────────────────────────────────────

class ReinforcementStoreAdapter {
  private readonly rl = UnifiedReinforcementStore.getInstance();

  async getSnapshot(): Promise<RLSnapshot> {
    const [tools, frameworks, platforms, calibration, exploration] = await Promise.all([
      this.getAllToolProfiles(),
      this.getAllFrameworkVulnProfiles(),
      this.getPlatformRanking(),
      this.getCalibration(),
      this.getExplorationStats(),
    ]);
    return { toolProfiles: tools, frameworkVulnProfiles: frameworks, platformRanking: platforms, calibration, explorationStats: exploration, capturedAt: Date.now() };
  }

  async getAllToolProfiles(): Promise<ToolProfile[]> {
    const entries = await db.select().from(rlTable).where(eq(rlTable.domain, 'tool_success'));

    const toolMap: Record<string, { total: number; success: number; byVulnClass: Record<string, { attempts: number; success: number }> }> = {};

    for (const e of entries) {
      const [tool, vulnClass] = e.key.split(':');
      if (!toolMap[tool]) toolMap[tool] = { total: 0, success: 0, byVulnClass: {} };
      toolMap[tool].total  += e.totalCount || 0;
      toolMap[tool].success += e.successCount || 0;
      if (vulnClass) {
        toolMap[tool].byVulnClass[vulnClass] = {
          attempts:    e.totalCount   || 0,
          success:     e.successCount || 0,
        };
      }
    }

    const profiles: ToolProfile[] = Object.entries(toolMap)
      .map(([tool, data]) => ({
        tool,
        totalAttempts: data.total,
        successRate:   data.total > 0 ? Math.round((data.success / data.total) * 100) / 100 : 0,
        byVulnClass:   Object.fromEntries(
          Object.entries(data.byVulnClass).map(([vc, d]) => [
            vc,
            { attempts: d.attempts, successRate: d.attempts > 0 ? Math.round((d.success / d.attempts) * 100) / 100 : 0 },
          ])
        ),
        rank: 0,
      }))
      .sort((a, b) => b.successRate - a.successRate);

    profiles.forEach((p, i) => { p.rank = i + 1; });
    return profiles;
  }

  async getToolProfile(tool: string): Promise<ToolProfile | null> {
    const profiles = await this.getAllToolProfiles();
    return profiles.find(p => p.tool === tool) ?? null;
  }

  async getToolRecommendation(context: Record<string, unknown>, epsilon = 0.15): Promise<string[]> {
    const profiles = await this.getAllToolProfiles();
    const vulnClass = context.vulnClass as string | undefined;

    let results: string[];
    if (vulnClass) {
      results = profiles
        .filter(p => p.byVulnClass[vulnClass]?.successRate > 0.3)
        .sort((a, b) => (b.byVulnClass[vulnClass]?.successRate ?? 0) - (a.byVulnClass[vulnClass]?.successRate ?? 0))
        .slice(0, 5)
        .map(p => p.tool);
    } else {
      results = profiles.slice(0, 5).map(p => p.tool);
    }

    // Epsilon-greedy: occasionally swap the last slot for an underexplored tool
    // so novel techniques get tried before RL history labels them as "unlikely".
    if (Math.random() < epsilon) {
      const underexplored = profiles.filter(p => {
        const attempts = vulnClass ? (p.byVulnClass[vulnClass]?.attempts ?? 0) : 0;
        return attempts < 10 && !results.includes(p.tool);
      });
      if (underexplored.length > 0) {
        const pick = underexplored[Math.floor(Math.random() * underexplored.length)];
        results = [...results.slice(0, 4), pick.tool];
      }
    }

    return results;
  }

  async getAllFrameworkVulnProfiles(): Promise<FrameworkVulnProfile[]> {
    const entries = await db.select().from(rlTable).where(eq(rlTable.domain, 'framework_vuln'));

    const fwMap: Record<string, Array<{ vulnClass: string; rate: number; attempts: number }>> = {};
    for (const e of entries) {
      const [framework, vulnClass] = e.key.split(':');
      if (!fwMap[framework]) fwMap[framework] = [];
      const rate = (e.totalCount || 0) > 0 ? (e.successCount || 0) / (e.totalCount || 1) : 0;
      fwMap[framework].push({ vulnClass, rate: Math.round(rate * 100) / 100, attempts: e.totalCount || 0 });
    }

    return Object.entries(fwMap).map(([framework, vulnClasses]) => {
      const sorted = [...vulnClasses].sort((a, b) => b.rate - a.rate);
      return { framework, vulnClasses: sorted, topVuln: sorted[0]?.vulnClass ?? 'unknown' };
    });
  }

  async getFrameworkPriorities(framework: string): Promise<string[]> {
    const vulns = await this.rl.getVulnsForFramework(framework);
    return vulns.map(v => v.vulnClass);
  }

  async getPlatformRanking(): Promise<PlatformRankEntry[]> {
    const entries = await db.select().from(rlTable).where(eq(rlTable.domain, 'program_type'));

    const platformMap: Record<string, { total: number; success: number }> = {};

    for (const e of entries) {
      // key format: "programType:strategy" — we use programType as platform proxy
      const [platform] = e.key.split(':');
      if (!platformMap[platform]) platformMap[platform] = { total: 0, success: 0 };
      platformMap[platform].total  += e.totalCount   || 0;
      platformMap[platform].success += e.successCount || 0;
    }

    const ranking: PlatformRankEntry[] = Object.entries(platformMap)
      .map(([platform, data]) => ({
        platform,
        avgSuccessRate: data.total > 0 ? Math.round((data.success / data.total) * 100) / 100 : 0,
        entries:        data.total,
        rank:           0,
      }))
      .sort((a, b) => b.avgSuccessRate - a.avgSuccessRate);

    ranking.forEach((r, i) => { r.rank = i + 1; });
    return ranking;
  }

  async getAllProgramTypeProfiles(): Promise<ProgramTypeProfile[]> {
    const entries = await db.select().from(rlTable).where(eq(rlTable.domain, 'program_type'));

    const typeMap: Record<string, Array<{ strategy: string; successRate: number }>> = {};
    for (const e of entries) {
      const [programType, strategy] = e.key.split(':');
      if (!typeMap[programType]) typeMap[programType] = [];
      const rate = (e.totalCount || 0) > 0 ? (e.successCount || 0) / (e.totalCount || 1) : 0;
      typeMap[programType].push({ strategy, successRate: Math.round(rate * 100) / 100 });
    }

    return Object.entries(typeMap).map(([programType, strategies]) => ({
      programType,
      topStrategies: strategies.sort((a, b) => b.successRate - a.successRate).slice(0, 5),
    }));
  }

  async getCalibration(): Promise<CalibrationReport> {
    const brierScore = await this.rl.computeBrierScore();
    const entries = await db.select().from(rlTable).where(eq(rlTable.domain, 'confidence_calibration'));

    const byVulnClass: Record<string, { biasSum: number; buckets: number }> = {};
    for (const e of entries) {
      const [vulnClass, bucketStr] = e.key.split(':');
      const predicted = Number(bucketStr) || 0;
      const actual = (e.totalCount || 0) > 0 ? (e.successCount || 0) / (e.totalCount || 1) : 0;
      const bias = Math.abs(predicted - actual);
      if (!byVulnClass[vulnClass]) byVulnClass[vulnClass] = { biasSum: 0, buckets: 0 };
      byVulnClass[vulnClass].biasSum  += bias;
      byVulnClass[vulnClass].buckets  += 1;
    }

    const byVulnClassOut: Record<string, { avgBias: number; buckets: number }> = {};
    for (const [vc, data] of Object.entries(byVulnClass)) {
      byVulnClassOut[vc] = {
        avgBias: data.buckets > 0 ? Math.round((data.biasSum / data.buckets) * 100) / 100 : 0,
        buckets: data.buckets,
      };
    }

    const wellCalibrated = brierScore < 0.15;

    return {
      brierScore: Math.round(brierScore * 1000) / 1000,
      totalBuckets: entries.length,
      wellCalibrated,
      byVulnClass: byVulnClassOut,
      message: wellCalibrated
        ? 'Confidence calibration is good (Brier < 0.15)'
        : brierScore < 0.25
          ? 'Calibration is moderate — more data needed'
          : 'Poor calibration — confidence estimates are unreliable',
    };
  }

  calibrateConfidence(rawConfidence: number): number {
    // Platt scaling approximation: push confidence toward center slightly
    const adjusted = 0.1 + rawConfidence * 0.8;
    return Math.round(Math.max(0, Math.min(1, adjusted)) * 100) / 100;
  }

  async getExplorationStats(): Promise<ExplorationStats> {
    const entries = await db.select().from(rlTable).where(eq(rlTable.domain, 'exploration'));

    const patternCounts: Record<string, number> = {};
    for (const e of entries) {
      patternCounts[e.key] = (patternCounts[e.key] || 0) + 1;
    }

    const hotspots = Object.entries(patternCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([pattern, count]) => ({ pattern, count }));

    const all = Object.entries(patternCounts);
    const coldAreas = all
      .filter(([, c]) => c <= 1)
      .slice(0, 10)
      .map(([pattern]) => pattern);

    return {
      totalExplored:   entries.length,
      uniquePatterns:  all.length,
      hotspots,
      coldAreas,
    };
  }

  // Delegates
  recordToolOutcome(tool: string, vulnClass: string, success: boolean) {
    return this.rl.recordToolOutcome(tool, vulnClass, success);
  }
  recordFrameworkVuln(framework: string, vulnClass: string, found: boolean) {
    return this.rl.recordFrameworkVuln(framework, vulnClass, found);
  }
  recordConfidenceCalibration(vulnClass: string, confidence: number, found: boolean) {
    return this.rl.recordConfidenceCalibration(vulnClass, confidence, found);
  }
  computeBrierScore() {
    return this.rl.computeBrierScore();
  }
}

export const reinforcementStore = new ReinforcementStoreAdapter();
