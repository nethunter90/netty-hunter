/**
 * Temporal Decay Engine
 * Models how AI-powered WAF/bot-management systems decay their anomaly memory
 * over time, and schedules probes to exploit those decay windows.
 *
 * Vendor parameters are reverse-engineered estimates based on public research
 * on Cloudflare Bot Management, Akamai Bot Manager, AWS WAF ML rules, and Imperva.
 */
import { EvasionAttempt, TemporalAnalysis, TemporalPhase } from './types';
import logger from '../../utils/logger';

export interface VendorDecayParameters {
  vendor: string;
  sessionWindowMs: number;       // sliding observation window length
  anomalyHalfLifeMs: number;     // how quickly one anomaly event loses weight
  baselineUpdateRate: number;    // 0–1, how fast clean traffic shifts the baseline
  recoveryCleanRequests: number; // benign requests needed to wash one anomaly
  adaptiveThresholds: boolean;   // does this vendor scale thresholds with traffic vol?
}

export interface DefenderModelState {
  domain: string;
  estimatedAnomalyScore: number;  // 0–1 (0 = invisible to WAF, 1 = flagged)
  lastProbeAt: number;
  cleanRequestsSince: number;
  decayProgress: number;          // 0–1, fraction of anomaly weight that has decayed
  recommendedWaitMs: number;
  inRecoveryWindow: boolean;
}

export interface ScheduledProbe {
  probeId: string;
  executeAt: number;   // absolute ms timestamp
  delayMs: number;     // wait from previous probe
  rationale: string;
}

export interface WarmupPlan {
  domain: string;
  requestCount: number;
  intervalMs: number;
  paths: string[];
  estimatedMs: number;
}

// ── Vendor Profiles ────────────────────────────────────────────────────────────

const VENDOR_PARAMS: Record<string, VendorDecayParameters> = {
  cloudflare: {
    vendor: 'cloudflare',
    sessionWindowMs: 3_600_000,   // 1 hour
    anomalyHalfLifeMs: 600_000,   // 10 min half-life
    baselineUpdateRate: 0.05,
    recoveryCleanRequests: 20,
    adaptiveThresholds: true,
  },
  akamai: {
    vendor: 'akamai',
    sessionWindowMs: 1_800_000,   // 30 min
    anomalyHalfLifeMs: 900_000,   // 15 min half-life
    baselineUpdateRate: 0.03,
    recoveryCleanRequests: 30,
    adaptiveThresholds: true,
  },
  aws_waf: {
    vendor: 'aws_waf',
    sessionWindowMs: 300_000,     // 5 min (rule-group window)
    anomalyHalfLifeMs: 180_000,   // 3 min half-life
    baselineUpdateRate: 0.10,
    recoveryCleanRequests: 10,
    adaptiveThresholds: false,
  },
  imperva: {
    vendor: 'imperva',
    sessionWindowMs: 7_200_000,   // 2 hours
    anomalyHalfLifeMs: 1_800_000, // 30 min half-life
    baselineUpdateRate: 0.02,
    recoveryCleanRequests: 50,
    adaptiveThresholds: true,
  },
  f5_big_ip: {
    vendor: 'f5_big_ip',
    sessionWindowMs: 3_600_000,
    anomalyHalfLifeMs: 1_200_000,
    baselineUpdateRate: 0.04,
    recoveryCleanRequests: 25,
    adaptiveThresholds: false,
  },
  generic: {
    vendor: 'generic',
    sessionWindowMs: 1_800_000,
    anomalyHalfLifeMs: 600_000,
    baselineUpdateRate: 0.05,
    recoveryCleanRequests: 20,
    adaptiveThresholds: false,
  },
};

function getParams(vendor: string): VendorDecayParameters {
  return VENDOR_PARAMS[vendor] ?? VENDOR_PARAMS.generic;
}

// ── Defender Decay Model ───────────────────────────────────────────────────────

export class DefenderDecayModel {
  /**
   * Estimate the current defender model state from probe history.
   * Applies exponential decay to each blocking event and sums residual anomaly scores.
   */
  estimateState(domain: string, vendor: string, history: EvasionAttempt[]): DefenderModelState {
    const params = getParams(vendor);
    const now = Date.now();
    const windowStart = now - params.sessionWindowMs;
    const recent = history.filter(h => h.attemptedAt >= windowStart);

    let anomalyScore = 0;
    let lastProbeAt = 0;
    let cleanRequestsSince = 0;

    for (const attempt of recent) {
      if (attempt.attemptedAt > lastProbeAt) lastProbeAt = attempt.attemptedAt;
      if (!attempt.succeeded) {
        // Blocked probe — adds anomaly weight, then decays exponentially
        const ageMs = now - attempt.attemptedAt;
        const decayedWeight = Math.exp(-ageMs * Math.LN2 / params.anomalyHalfLifeMs);
        anomalyScore = Math.min(1, anomalyScore + decayedWeight);
      } else {
        cleanRequestsSince++;
        // Clean requests reduce anomaly score
        anomalyScore = Math.max(0, anomalyScore - params.baselineUpdateRate);
      }
    }

    const decayProgress = lastProbeAt > 0
      ? Math.min(1, (now - lastProbeAt) / params.anomalyHalfLifeMs)
      : 1;

    const inRecoveryWindow = anomalyScore > 0.3 &&
      cleanRequestsSince < params.recoveryCleanRequests;

    const recommendedWaitMs = this.recommendWaitTime(
      { domain, estimatedAnomalyScore: anomalyScore, lastProbeAt, cleanRequestsSince,
        decayProgress, recommendedWaitMs: 0, inRecoveryWindow },
      vendor
    );

    return {
      domain,
      estimatedAnomalyScore: anomalyScore,
      lastProbeAt,
      cleanRequestsSince,
      decayProgress,
      recommendedWaitMs,
      inRecoveryWindow,
    };
  }

  /**
   * Compute how long to wait before the next probe so anomaly score drops below 0.2.
   */
  recommendWaitTime(state: DefenderModelState, vendor: string): number {
    const params = getParams(vendor);
    const target = 0.2;
    const current = state.estimatedAnomalyScore;
    if (current <= target) return 0;

    // Solve: current * exp(-t * ln2 / halfLife) = target  →  t = halfLife * ln(current/target) / ln2
    const waitMs = params.anomalyHalfLifeMs * Math.log(current / target) / Math.LN2;

    // If adaptive thresholds, add buffer for threshold re-calibration
    const buffer = params.adaptiveThresholds ? params.anomalyHalfLifeMs * 0.25 : 0;
    return Math.ceil(waitMs + buffer);
  }

  /** Returns when the anomaly will have decayed below threshold (absolute ms timestamp). */
  predictDecayCompletion(state: DefenderModelState, vendor: string): number {
    return Date.now() + this.recommendWaitTime(state, vendor);
  }

  /** Benign requests needed to wash the current anomaly score below safe threshold. */
  cleanRequestsNeeded(currentBlockRate: number, vendor: string): number {
    const params = getParams(vendor);
    if (currentBlockRate <= 0.1) return 0;
    return Math.ceil(params.recoveryCleanRequests * currentBlockRate);
  }

  /** Build a warmup plan to establish a normal baseline before probing. */
  buildWarmupPlan(domain: string, vendor: string): WarmupPlan {
    const params = getParams(vendor);
    const count = params.recoveryCleanRequests;
    const intervalMs = Math.floor(params.sessionWindowMs / (count * 2));

    const defaultPaths = ['/', '/about', '/contact', '/faq', '/sitemap.xml',
      '/robots.txt', '/login', '/search?q=test', '/api/health', '/terms'];

    return {
      domain,
      requestCount: count,
      intervalMs,
      paths: defaultPaths.slice(0, Math.min(count, defaultPaths.length)),
      estimatedMs: count * intervalMs,
    };
  }
}

// ── Temporal Decay Engine (singleton) ─────────────────────────────────────────

export class TemporalDecayEngine {
  private static instance: TemporalDecayEngine;
  private readonly model = new DefenderDecayModel();
  // keyed by `${sessionId}:${domain}`
  private readonly history = new Map<string, EvasionAttempt[]>();

  private constructor() {}

  static getInstance(): TemporalDecayEngine {
    if (!TemporalDecayEngine.instance) {
      TemporalDecayEngine.instance = new TemporalDecayEngine();
    }
    return TemporalDecayEngine.instance;
  }

  private key(sessionId: string, domain: string): string {
    return `${sessionId}:${domain}`;
  }

  recordAttempt(sessionId: string, attempt: EvasionAttempt): void {
    const domain = attempt.category; // category field carries domain in evasion context
    const k = this.key(sessionId, domain);
    if (!this.history.has(k)) this.history.set(k, []);
    const arr = this.history.get(k)!;
    arr.push(attempt);
    // Cap per-key history to prevent unbounded growth for long-running sessions
    if (arr.length > 500) arr.splice(0, arr.length - 500);
    // Evict stale sessions lazily when the Map grows large
    if (this.history.size > 200) this.evictStale();
    logger.debug('[TemporalDecay] recorded attempt', {
      sessionId, domain, succeeded: attempt.succeeded, technique: attempt.technique,
    });
  }

  private evictStale(): void {
    const cutoff = Date.now() - 2 * 60 * 60 * 1000; // 2-hour TTL per session:domain key
    for (const [k, arr] of this.history) {
      const latest = arr.length > 0 ? arr[arr.length - 1].attemptedAt : 0;
      if (latest < cutoff) this.history.delete(k);
    }
  }

  /** Analyse temporal phase transitions for a session/domain pair. */
  analyzeSession(sessionId: string, domain: string): TemporalAnalysis {
    const k = this.key(sessionId, domain);
    const history = this.history.get(k) ?? [];

    if (history.length === 0) {
      return { phases: [], currentPhase: null, transitionPattern: 'no_data',
               predictedNextPhase: null, phaseTransitions: [] };
    }

    // Bucket into 5-minute windows and compute block rate per window
    const bucketMs = 5 * 60 * 1000;
    const buckets = new Map<number, { blocked: number; total: number }>();
    for (const h of history) {
      const bucket = Math.floor(h.attemptedAt / bucketMs) * bucketMs;
      if (!buckets.has(bucket)) buckets.set(bucket, { blocked: 0, total: 0 });
      const b = buckets.get(bucket)!;
      b.total++;
      if (!h.succeeded) b.blocked++;
    }

    const sorted = [...buckets.entries()].sort((a, b) => a[0] - b[0]);
    const phases: TemporalPhase[] = sorted.map(([ts, b], i) => ({
      name: `window_${i + 1}`,
      startedAt: ts,
      endedAt: ts + bucketMs,
      blockRate: b.total > 0 ? b.blocked / b.total : 0,
      requestCount: b.total,
    }));

    // Detect trend across last 3 phases
    const recent = phases.slice(-3);
    let transitionPattern: TemporalAnalysis['transitionPattern'] = 'stable';
    if (recent.length >= 2) {
      const first = recent[0].blockRate;
      const last = recent[recent.length - 1].blockRate;
      if (last > first + 0.15) transitionPattern = 'escalating';
      else if (last < first - 0.15) transitionPattern = 'de-escalating';
    }

    const phaseTransitions: Array<{ from: string; to: string; at: number }> = [];
    for (let i = 1; i < phases.length; i++) {
      if (Math.abs(phases[i].blockRate - phases[i - 1].blockRate) > 0.2) {
        phaseTransitions.push({
          from: phases[i - 1].name,
          to: phases[i].name,
          at: phases[i].startedAt,
        });
      }
    }

    const currentPhase = phases.length > 0 ? phases[phases.length - 1].name : null;
    const predictedNextPhase = transitionPattern === 'escalating'
      ? 'high_block' : transitionPattern === 'de-escalating' ? 'recovery' : 'stable';

    return { phases, currentPhase, transitionPattern, predictedNextPhase, phaseTransitions };
  }

  /** Absolute ms timestamp of when it is safe to fire the next probe. */
  getNextProbeTime(sessionId: string, domain: string, vendor: string): number {
    const k = this.key(sessionId, domain);
    const history = this.history.get(k) ?? [];
    const state = this.model.estimateState(domain, vendor, history);
    return Date.now() + state.recommendedWaitMs;
  }

  /** Build an ordered schedule for multiple probes, spacing them around decay windows. */
  generateSchedule(sessionId: string, domain: string, vendor: string, probeIds: string[]): ScheduledProbe[] {
    const params = getParams(vendor);
    const k = this.key(sessionId, domain);
    const history = this.history.get(k) ?? [];
    const baseState = this.model.estimateState(domain, vendor, history);

    const scheduled: ScheduledProbe[] = [];
    let cursor = Date.now() + baseState.recommendedWaitMs;

    for (let i = 0; i < probeIds.length; i++) {
      const delayMs = i === 0
        ? baseState.recommendedWaitMs
        : Math.ceil(params.anomalyHalfLifeMs * 0.5); // half-life spacing between probes

      scheduled.push({
        probeId: probeIds[i],
        executeAt: cursor,
        delayMs,
        rationale: i === 0
          ? (baseState.inRecoveryWindow ? 'post-recovery-wait' : 'decay-window-exploit')
          : 'inter-probe-spacing',
      });
      cursor += delayMs;
    }

    return scheduled;
  }

  getWarmupPlan(domain: string, vendor: string): WarmupPlan {
    return this.model.buildWarmupPlan(domain, vendor);
  }

  getDecayState(sessionId: string, domain: string, vendor: string): DefenderModelState {
    const k = this.key(sessionId, domain);
    const history = this.history.get(k) ?? [];
    return this.model.estimateState(domain, vendor, history);
  }
}

export const temporalDecay = TemporalDecayEngine.getInstance();
