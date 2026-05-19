import { stealthLogger } from './stealth-logger';

export interface SessionMetrics {
  toolsDeferred: number;
  timingDelays: number;
  detectionEvents: number;
  modeChanges: number;
  platformCompliance: boolean;
}

export interface ScoreResult {
  baseScore: number;
  stealthBonus: number;
  deferralBonus: number;
  detectionPenalty: number;
  complianceBonus: number;
  finalScore: number;
  breakdown: string[];
}

interface TrainingStats {
  sessionsScored: number;
  avgScore: number;
  modeDistribution: Record<string, number>;
}

const MODE_BONUSES: Record<string, number> = {
  ultrastealth: 0.25,
  stealth: 0.15,
  aggressive: 0,
};

const DEFERRAL_POINTS_PER_TOOL = 2;
const MAX_DEFERRAL_TOOLS = 5;
const MAX_DEFERRAL_BONUS = DEFERRAL_POINTS_PER_TOOL * MAX_DEFERRAL_TOOLS;
const MAX_DETECTION_PENALTY = 50;
const COMPLIANCE_BONUS = 5;

class TrainingIntegration {
  private metrics: SessionMetrics;
  private currentMode: string;
  private totalScored: number;
  private scoreSum: number;
  private modeDistribution: Record<string, number>;

  constructor() {
    this.metrics = this.defaultMetrics();
    this.currentMode = 'stealth';
    this.totalScored = 0;
    this.scoreSum = 0;
    this.modeDistribution = {};
  }

  private defaultMetrics(): SessionMetrics {
    return {
      toolsDeferred: 0,
      timingDelays: 0,
      detectionEvents: 0,
      modeChanges: 0,
      platformCompliance: true,
    };
  }

  calculateScore(baseScore: number, sessionMetrics: SessionMetrics): ScoreResult {
    const breakdown: string[] = [];

    const bonusRate = MODE_BONUSES[this.currentMode] ?? 0;
    const stealthBonus = Math.round(baseScore * bonusRate * 100) / 100;
    breakdown.push(`Stealth mode (${this.currentMode}): +${(bonusRate * 100).toFixed(0)}% = +${stealthBonus}`);

    const effectiveDeferred = Math.min(sessionMetrics.toolsDeferred, MAX_DEFERRAL_TOOLS);
    const deferralBonus = effectiveDeferred * DEFERRAL_POINTS_PER_TOOL;
    breakdown.push(`Deferred tools (${effectiveDeferred}/${MAX_DEFERRAL_TOOLS}): +${deferralBonus} pts`);

    const detectionRisk = sessionMetrics.detectionEvents > 0
      ? Math.min(sessionMetrics.detectionEvents * 10, 100)
      : 0;
    const rawPenalty = (detectionRisk / 100) * 20 + (sessionMetrics.detectionEvents * 3);
    const detectionPenalty = Math.min(rawPenalty, MAX_DETECTION_PENALTY);
    breakdown.push(`Detection penalty (risk=${detectionRisk}%, events=${sessionMetrics.detectionEvents}): -${detectionPenalty.toFixed(1)}`);

    const complianceBonus = sessionMetrics.platformCompliance ? COMPLIANCE_BONUS : 0;
    breakdown.push(`Platform compliance: ${sessionMetrics.platformCompliance ? `+${COMPLIANCE_BONUS}` : '+0'}`);

    const finalScore = Math.round((baseScore + stealthBonus + deferralBonus - detectionPenalty + complianceBonus) * 100) / 100;
    breakdown.push(`Final score: ${finalScore}`);

    this.totalScored++;
    this.scoreSum += finalScore;
    this.modeDistribution[this.currentMode] = (this.modeDistribution[this.currentMode] || 0) + 1;

    stealthLogger.log('auto_adjustment', {
      type: 'training_score',
      baseScore,
      stealthBonus,
      deferralBonus,
      detectionPenalty,
      complianceBonus,
      finalScore,
      mode: this.currentMode,
    });

    return {
      baseScore,
      stealthBonus,
      deferralBonus,
      detectionPenalty,
      complianceBonus,
      finalScore,
      breakdown,
    };
  }

  recordToolDeferral(): void {
    this.metrics.toolsDeferred++;
    stealthLogger.log('tool_deferral', { toolsDeferred: this.metrics.toolsDeferred });
  }

  recordTimingDelay(ms: number): void {
    this.metrics.timingDelays += ms;
    stealthLogger.log('timing_adjustment', { delayMs: ms, totalDelays: this.metrics.timingDelays });
  }

  recordDetectionEvent(): void {
    this.metrics.detectionEvents++;
    stealthLogger.log('alert', { detectionEvents: this.metrics.detectionEvents });
  }

  recordModeChange(): void {
    this.metrics.modeChanges++;
    stealthLogger.log('mode_change', { modeChanges: this.metrics.modeChanges, currentMode: this.currentMode });
  }

  setPlatformCompliance(compliant: boolean): void {
    this.metrics.platformCompliance = compliant;
    stealthLogger.log('platform_rule', { compliant });
  }

  setStealthMode(mode: string): void {
    this.currentMode = mode;
    this.recordModeChange();
  }

  getSessionMetrics(): SessionMetrics {
    return { ...this.metrics };
  }

  resetSession(): void {
    this.metrics = this.defaultMetrics();
    this.currentMode = 'stealth';
  }

  getStats(): TrainingStats {
    return {
      sessionsScored: this.totalScored,
      avgScore: this.totalScored > 0 ? Math.round((this.scoreSum / this.totalScored) * 100) / 100 : 0,
      modeDistribution: { ...this.modeDistribution },
    };
  }
}

export const trainingIntegration = new TrainingIntegration();
