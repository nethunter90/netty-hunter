/**
 * Timing Engine
 * Decay-aware probe scheduler. Wraps TemporalDecayEngine to provide per-probe
 * timing recommendations with jitter and adaptive rate limiting.
 */
import { DefenderModelState, temporalDecay } from '../hunter/temporal-decay';

export interface TimingRecommendation {
  waitMs: number;
  rationale: string;
  inDecayWindow: boolean;
  estimatedAnomalyScore: number;
}

// Block rate thresholds that trigger a recovery pause
const RECOVERY_THRESHOLDS: Record<string, number> = {
  passive:     0.10,
  balanced:    0.25,
  aggressive:  0.50,
};

export class TimingEngine {
  /**
   * Get how long to wait before the next probe.
   * Returns 0 if it is safe to probe immediately.
   */
  getRecommendation(
    sessionId: string,
    domain: string,
    vendor: string,
    stealthMode: 'passive' | 'balanced' | 'aggressive' = 'balanced'
  ): TimingRecommendation {
    const state = temporalDecay.getDecayState(sessionId, domain, vendor);
    const baseWait = state.recommendedWaitMs;

    // Passive mode adds extra safety margin (1.5×)
    const modeMultiplier = stealthMode === 'passive' ? 1.5
      : stealthMode === 'aggressive' ? 0.7
      : 1.0;

    const waitMs = this.applyJitter(Math.ceil(baseWait * modeMultiplier));

    let rationale: string;
    if (state.inRecoveryWindow) {
      rationale = `recovery-wait: anomaly=${state.estimatedAnomalyScore.toFixed(2)}, clean=${state.cleanRequestsSince} requests`;
    } else if (baseWait > 0) {
      rationale = `decay-window: ${Math.round(baseWait / 1000)}s until anomaly < 0.2`;
    } else {
      rationale = 'clear: anomaly score below threshold';
    }

    return {
      waitMs,
      rationale,
      inDecayWindow: state.estimatedAnomalyScore > 0.2,
      estimatedAnomalyScore: state.estimatedAnomalyScore,
    };
  }

  /**
   * Add ±factor jitter to a base wait time to avoid automaton periodicity detection.
   * factor=0.2 means ±20% random variation.
   */
  applyJitter(baseMs: number, factor: number = 0.2): number {
    if (baseMs === 0) return 0;
    const jitter = baseMs * factor * (Math.random() * 2 - 1);
    return Math.max(0, Math.round(baseMs + jitter));
  }

  /**
   * Returns true if the recent block rate exceeds the threshold for the current
   * stealth mode, meaning we should pause and let the baseline recover.
   */
  shouldPauseForRecovery(
    recentBlockRate: number,
    stealthMode: 'passive' | 'balanced' | 'aggressive' = 'balanced',
    vendor: string = 'generic'
  ): boolean {
    const threshold = RECOVERY_THRESHOLDS[stealthMode] ?? 0.25;
    // More lenient for vendors with fast decay (e.g. aws_waf)
    const vendorModifier = vendor === 'aws_waf' ? 1.5 : 1.0;
    return recentBlockRate > threshold * vendorModifier;
  }

  /**
   * Compute adaptive request rate (requests per minute) based on current anomaly score.
   * Higher anomaly → slower rate.
   */
  adaptiveRateLimit(state: DefenderModelState): number {
    const maxRpm = 30;
    const minRpm = 2;
    // Linear interpolation: at anomaly=0 → maxRpm, at anomaly=1 → minRpm
    return Math.round(maxRpm - (maxRpm - minRpm) * state.estimatedAnomalyScore);
  }
}
