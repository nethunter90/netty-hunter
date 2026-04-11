/**
 * AutonomyMaturityTracker — lib/hunter adapter
 *
 * Wraps the core AutonomyMaturityTracker and adds:
 *  - Milestone reports (every 10 hunts)
 *  - Brier trend over last N hunts
 *  - Reinforcement noise report
 *  - Exploration health
 *  - getDomainGateReport() — weakest-link gating (the CAMS cap)
 */
import { AutonomyMaturityTracker, type AutonomyDomain, type DomainScore } from '../../intelligence/AutonomyTracker';
import { UnifiedReinforcementStore } from '../../intelligence/ReinforcementStore';

// ── Types ─────────────────────────────────────────────────────────────────────

type OperationalLevel = 'nascent' | 'learning' | 'developing' | 'high_autonomy';
type DeploymentMode   = 'lab_only' | 'supervised' | 'semi_autonomous' | 'autonomous';

export interface DomainGate {
  domain: AutonomyDomain;
  score: number;
  operationalLevel: OperationalLevel;
  deploymentMode: DeploymentMode;
  trend: 'improving' | 'stable' | 'declining';
  regressionDetected: boolean;
  percentToNextLevel: number;
  nextLevelThreshold: number;
  stabilityHuntsAtLevel: number;
}

export interface DomainGateReport {
  gates: DomainGate[];
  regressions: Array<{ domain: AutonomyDomain; severity: 'warning' | 'critical'; message: string }>;
  gatingActive: boolean;
  globalLevelCap: OperationalLevel;
  weakestDomain: AutonomyDomain;
  weakestScore: number;
  deploymentMode: DeploymentMode;
  deploymentLabel: string;
  reviewRequirement: string;
  globalCapExplanation: string;
  stabilityRequired: number;
}

export interface MaturityScore {
  compositeScore: number;
  maturityLevel: string;
  huntCount: number;
  readyForFullAutonomy: boolean;
  globalLevelCap: OperationalLevel;
  deploymentMode: DeploymentMode;
}

export interface BrierTrend {
  current: number;
  history: Array<{ huntNumber: number; score: number }>;
  trend: 'improving' | 'stable' | 'regressing';
  message: string;
}

export interface NoiseReport {
  reinforcementNoise: number;
  noiseLevel: 'low' | 'medium' | 'high';
  message: string;
  domainVariance: Record<AutonomyDomain, number>;
}

export interface ExplorationHealth {
  totalExplorations: number;
  uniqueEndpoints: number;
  uniqueVulnClasses: number;
  coverageScore: number;
  health: 'poor' | 'fair' | 'good' | 'excellent';
}

export interface MilestoneReport {
  milestone: number;
  compositeScore: number;
  maturityLevel: string;
  domainScores: Record<AutonomyDomain, number>;
  weakestDomain: AutonomyDomain;
  weakestScore: number;
  recommendations: string[];
  readyForFullAutonomy: boolean;
  recordedAt: number;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const REGRESSION_ABSOLUTE_FLOOR = 0.6;
const STABILITY_HUNTS_REQUIRED  = 3;
const MILESTONE_INTERVAL        = 10;

const DOMAINS: AutonomyDomain[] = [
  'hypothesis_generation',
  'tool_selection',
  'scope_adherence',
  'false_positive_rate',
  'exploit_chain_depth',
  'reporting_quality',
];

const CRITICAL_DOMAINS: AutonomyDomain[] = ['scope_adherence', 'false_positive_rate'];

// ── Level helpers ─────────────────────────────────────────────────────────────

function scoreToLevel(score: number): OperationalLevel {
  if (score < 0.3) return 'nascent';
  if (score < 0.5) return 'learning';
  if (score < 0.7) return 'developing';
  return 'high_autonomy';
}

function levelToDeployment(level: OperationalLevel): { mode: DeploymentMode; label: string; review: string } {
  const MAP: Record<OperationalLevel, { mode: DeploymentMode; label: string; review: string }> = {
    nascent:       { mode: 'lab_only',        label: 'Lab Only',        review: '100% human review'         },
    learning:      { mode: 'supervised',      label: 'Supervised',      review: 'Review all findings'       },
    developing:    { mode: 'semi_autonomous', label: 'Semi-Autonomous', review: 'Spot-check 25%'            },
    high_autonomy: { mode: 'autonomous',      label: 'Autonomous',      review: 'Review before submission'  },
  };
  return MAP[level];
}

function percentToNext(score: number, level: OperationalLevel): { percent: number; threshold: number } {
  const BOUNDS: Record<OperationalLevel, [number, number]> = {
    nascent:       [0,   0.3],
    learning:      [0.3, 0.5],
    developing:    [0.5, 0.7],
    high_autonomy: [0.7, 1.0],
  };
  const [lo, hi] = BOUNDS[level];
  return {
    percent:   Math.round(Math.min(100, Math.max(0, (score - lo) / (hi - lo) * 100))),
    threshold: hi,
  };
}

// ── Main class ────────────────────────────────────────────────────────────────

class AutonomyMaturityTrackerAdapter {
  private readonly tracker = AutonomyMaturityTracker.getInstance();
  private readonly rlStore = UnifiedReinforcementStore.getInstance();

  // In-memory history of weakest-domain scores per hunt (for stability window)
  private weakestLevelHistory: OperationalLevel[] = [];
  private milestones: MilestoneReport[] = [];
  private brierHistory: Array<{ huntNumber: number; score: number }> = [];

  // ── Public API ──────────────────────────────────────────────────────────────

  getHuntCount(): number {
    // Access protected field via the typed interface
    return (this.tracker as unknown as { huntCount: number }).huntCount ?? 0;
  }

  async getMaturityScore(): Promise<MaturityScore> {
    const report = await this.tracker.getLatestReport();
    const gateReport = await this.getDomainGateReport();

    return {
      compositeScore:      report?.compositeScore ?? 0,
      maturityLevel:       report?.maturityLevel  ?? 'Nascent Autonomy',
      huntCount:           this.getHuntCount(),
      readyForFullAutonomy: report?.readyForFullAutonomy ?? false,
      globalLevelCap:      gateReport.globalLevelCap,
      deploymentMode:      gateReport.deploymentMode,
    };
  }

  async getBrierTrend(): Promise<BrierTrend> {
    const history   = await this.tracker.getProgressHistory(20);
    const brierNow  = await this.rlStore.computeBrierScore();

    // Build a simplified brier history from our in-memory record
    const hist = this.brierHistory.slice(-20);

    let trend: BrierTrend['trend'] = 'stable';
    if (hist.length >= 6) {
      const recent = hist.slice(-3).reduce((a, b) => a + b.score, 0) / 3;
      const older  = hist.slice(-6, -3).reduce((a, b) => a + b.score, 0) / 3;
      if (recent < older - 0.02)  trend = 'improving';  // lower Brier = better
      if (recent > older + 0.02)  trend = 'regressing';
    }

    return {
      current: brierNow,
      history: hist,
      trend,
      message: trend === 'improving'
        ? 'Confidence calibration is improving'
        : trend === 'regressing'
          ? 'Confidence calibration is degrading — review prediction accuracy'
          : 'Confidence calibration is stable',
    };
  }

  async getNoiseReport(): Promise<NoiseReport> {
    const report = await this.tracker.getLatestReport();
    const noise  = report?.reinforcementNoise ?? 0;

    // Estimate per-domain variance from last report's domain scores
    const domainVariance: Record<AutonomyDomain, number> = {} as Record<AutonomyDomain, number>;
    for (const d of DOMAINS) {
      const score = report?.domainScores[d]?.score ?? 0;
      // simple proxy: variance from 0.5 baseline
      domainVariance[d] = Math.abs(score - 0.5);
    }

    const level: NoiseReport['noiseLevel'] =
      noise < 0.05  ? 'low'  :
      noise < 0.15  ? 'medium' :
      'high';

    return {
      reinforcementNoise: noise,
      noiseLevel: level,
      message:
        level === 'high'
          ? 'High reinforcement noise — RL is unstable, consider more hunts or domain reset'
          : level === 'medium'
            ? 'Moderate noise — system is learning, continue monitoring'
            : 'Low noise — reinforcement signal is stable',
      domainVariance,
    };
  }

  async getExplorationHealth(): Promise<ExplorationHealth> {
    const stats = await this.rlStore.getStats();
    const explorationStats = stats['exploration' as keyof typeof stats] as { entries: number; avgSuccessRate: number } | undefined;
    const total = explorationStats?.entries ?? 0;

    // Estimate unique endpoints/vulnClasses from entries
    const uniqueEndpoints  = Math.ceil(total * 0.6);  // heuristic
    const uniqueVulnClasses = Math.min(total, 19);

    const coverageScore =
      total === 0 ? 0 :
      Math.min(1, total / 200);  // 200 explorations = full coverage

    const health: ExplorationHealth['health'] =
      coverageScore >= 0.8 ? 'excellent' :
      coverageScore >= 0.5 ? 'good'      :
      coverageScore >= 0.2 ? 'fair'      :
      'poor';

    return {
      totalExplorations:  total,
      uniqueEndpoints,
      uniqueVulnClasses,
      coverageScore: Math.round(coverageScore * 100) / 100,
      health,
    };
  }

  getMilestoneReports(): MilestoneReport[] {
    return this.milestones;
  }

  getMilestoneReport(milestone: number): MilestoneReport | null {
    return this.milestones.find(m => m.milestone === milestone) ?? null;
  }

  async generateMilestoneReport(): Promise<MilestoneReport | null> {
    const report = await this.tracker.getLatestReport();
    if (!report) return null;

    const huntCount = this.getHuntCount();
    const milestoneNum = Math.floor(huntCount / MILESTONE_INTERVAL) * MILESTONE_INTERVAL;

    const domainScores: Record<AutonomyDomain, number> = {} as Record<AutonomyDomain, number>;
    let weakestDomain: AutonomyDomain = 'hypothesis_generation';
    let weakestScore = 1.0;

    for (const d of DOMAINS) {
      const s = report.domainScores[d]?.score ?? 0;
      domainScores[d] = s;
      if (s < weakestScore) { weakestScore = s; weakestDomain = d; }
    }

    const milestone: MilestoneReport = {
      milestone:           milestoneNum,
      compositeScore:      report.compositeScore,
      maturityLevel:       report.maturityLevel,
      domainScores,
      weakestDomain,
      weakestScore,
      recommendations:     report.recommendations,
      readyForFullAutonomy: report.readyForFullAutonomy,
      recordedAt:          Date.now(),
    };

    // Store if it's a new milestone
    if (!this.milestones.find(m => m.milestone === milestoneNum)) {
      this.milestones.push(milestone);
    }

    return milestone;
  }

  async getDomainGateReport(): Promise<DomainGateReport> {
    const report = await this.tracker.getLatestReport();

    if (!report) {
      return this.buildDefaultGateReport();
    }

    // Build gates per domain
    const gates: DomainGate[] = [];
    let weakestDomain: AutonomyDomain = 'hypothesis_generation';
    let weakestScore = 1.0;

    for (const d of DOMAINS) {
      const ds: DomainScore = report.domainScores[d];
      const score = ds?.score ?? 0;
      const level = scoreToLevel(score);
      const { percent, threshold } = percentToNext(score, level);

      // Count consecutive hunts at this level (from levelHistory)
      const stability = this.countConsecutiveAtLevel(level);

      gates.push({
        domain:                d,
        score,
        operationalLevel:      level,
        deploymentMode:        levelToDeployment(level).mode,
        trend:                 ds?.trend ?? 'stable',
        regressionDetected:    ds?.regressionDetected ?? false,
        percentToNextLevel:    percent,
        nextLevelThreshold:    threshold,
        stabilityHuntsAtLevel: stability,
      });

      if (score < weakestScore) { weakestScore = score; weakestDomain = d; }
    }

    // Regressions
    const regressions: DomainGateReport['regressions'] = [];
    for (const gate of gates) {
      if (gate.regressionDetected) {
        const severity = CRITICAL_DOMAINS.includes(gate.domain) ? 'critical' : 'warning';
        regressions.push({
          domain:   gate.domain,
          severity,
          message:  `${gate.domain.replace(/_/g, ' ')} score (${Math.round(gate.score * 100)}%) below ${REGRESSION_ABSOLUTE_FLOOR * 100}% floor`,
        });
      }
    }

    // Global cap = weakest domain level
    const globalLevelCap = scoreToLevel(weakestScore);
    const { mode, label, review } = levelToDeployment(globalLevelCap);

    // Track stability history
    this.weakestLevelHistory.push(globalLevelCap);
    if (this.weakestLevelHistory.length > 20) this.weakestLevelHistory.shift();

    return {
      gates,
      regressions,
      gatingActive:          true,
      globalLevelCap,
      weakestDomain,
      weakestScore,
      deploymentMode:        mode,
      deploymentLabel:       label,
      reviewRequirement:     review,
      globalCapExplanation:  `Global autonomy capped by ${weakestDomain.replace(/_/g, ' ')} (${Math.round(weakestScore * 100)}%)`,
      stabilityRequired:     STABILITY_HUNTS_REQUIRED,
    };
  }

  // Called by hunter-engine after each hunt completes
  async recordHunt(data: {
    hypothesesGenerated: number;
    hypothesesCorrect: number;
    toolsSelected: number;
    toolsCorrect: number;
    outOfScopeAttempts: number;
    falsePositives: number;
    confirmedFindings: number;
    chainDepth: number;
    reportQualityScore: number;
  }) {
    const report = await this.tracker.recordHuntOutcome(data);
    const brierNow = report.brierScore;

    this.brierHistory.push({ huntNumber: this.getHuntCount(), score: brierNow });
    if (this.brierHistory.length > 50) this.brierHistory.shift();

    // Record milestone every MILESTONE_INTERVAL hunts
    if (this.getHuntCount() % MILESTONE_INTERVAL === 0) {
      await this.generateMilestoneReport();
    }

    return report;
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private countConsecutiveAtLevel(level: OperationalLevel): number {
    let count = 0;
    for (let i = this.weakestLevelHistory.length - 1; i >= 0; i--) {
      if (this.weakestLevelHistory[i] === level) count++;
      else break;
    }
    return count;
  }

  private buildDefaultGateReport(): DomainGateReport {
    const gates: DomainGate[] = DOMAINS.map(d => ({
      domain:                d,
      score:                 0,
      operationalLevel:      'nascent',
      deploymentMode:        'lab_only',
      trend:                 'stable',
      regressionDetected:    false,
      percentToNextLevel:    0,
      nextLevelThreshold:    0.3,
      stabilityHuntsAtLevel: 0,
    }));

    return {
      gates,
      regressions:           [],
      gatingActive:          false,
      globalLevelCap:        'nascent',
      weakestDomain:         'hypothesis_generation',
      weakestScore:          0,
      deploymentMode:        'lab_only',
      deploymentLabel:       'Lab Only',
      reviewRequirement:     '100% human review',
      globalCapExplanation:  'No hunt data yet',
      stabilityRequired:     STABILITY_HUNTS_REQUIRED,
    };
  }
}

export const autonomyMaturityTracker = new AutonomyMaturityTrackerAdapter();
