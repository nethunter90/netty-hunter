/**
 * Stealth Coordinator
 * Orchestrates all stealth modules: timing (decay-aware), behavioral mimicry,
 * AI WAF evasion, session warmup, and traffic normalization.
 */
import { StealthMode } from '../hunter/types';
import { temporalDecay, WarmupPlan } from '../hunter/temporal-decay';
import { BehavioralMimicry, MimicrySession } from './behavioral-mimicry';
import { AIWAFEvasion, AIEvasionVariant } from './ai-waf-evasion';
import { TimingEngine, TimingRecommendation } from './timing-engine';
import { SessionWarmup, WarmupResult } from './session-warmup';
import { TrafficNormalizer } from './traffic-normalizer';
import logger from '../../utils/logger';

export { BehavioralMimicry, MimicrySession } from './behavioral-mimicry';
export { AIWAFEvasion, AIEvasionVariant } from './ai-waf-evasion';
export { TimingEngine, TimingRecommendation } from './timing-engine';
export { SessionWarmup, WarmupResult } from './session-warmup';
export { TrafficNormalizer } from './traffic-normalizer';

export interface StealthContext {
  sessionId: string;
  domain: string;
  vendor: string;       // from WAFDetector result
  stealthMode: StealthMode;
}

export interface PreparedProbe {
  url: string;
  headers: Record<string, string>;
  delayMs: number;
  rationale: string;
  aiVariants: AIEvasionVariant[];
  normalizationScore: number;
}

// ── Stealth Coordinator (singleton) ───────────────────────────────────────────

export class StealthCoordinator {
  private static instance: StealthCoordinator;
  private readonly mimicry = new BehavioralMimicry();
  private readonly aiEvasion = new AIWAFEvasion();
  private readonly timing = new TimingEngine();
  private readonly warmup = new SessionWarmup();
  private readonly normalizer = new TrafficNormalizer();

  // Per-domain mimicry sessions (rotate every 30 minutes)
  private readonly sessions = new Map<string, { session: MimicrySession; createdAt: number }>();

  private constructor() {}

  static getInstance(): StealthCoordinator {
    if (!StealthCoordinator.instance) {
      StealthCoordinator.instance = new StealthCoordinator();
    }
    return StealthCoordinator.instance;
  }

  private getSession(domain: string): MimicrySession {
    const existing = this.sessions.get(domain);
    const SESSION_TTL = 30 * 60 * 1000; // 30 min
    if (existing && Date.now() - existing.createdAt < SESSION_TTL) {
      return existing.session;
    }
    const session = this.mimicry.buildSession(domain);
    this.sessions.set(domain, { session, createdAt: Date.now() });
    return session;
  }

  /**
   * Full probe preparation pipeline:
   * 1. Get timing recommendation (decay-aware)
   * 2. Build mimicry headers
   * 3. Generate AI evasion variants
   * 4. Normalize URL toward baseline
   *
   * Returns a PreparedProbe ready for execution after delayMs.
   */
  async prepareProbe(
    url: string,
    payload: string,
    vulnClass: string,
    ctx: StealthContext
  ): Promise<PreparedProbe> {
    // 1. Timing
    const rec = this.timing.getRecommendation(
      ctx.sessionId, ctx.domain, ctx.vendor, ctx.stealthMode
    );

    // 2. Mimicry headers
    const session = this.getSession(ctx.domain);
    const referrerIdx = Math.floor(Math.random() * session.referrerChain.length);
    const headers = this.mimicry.buildHeaders(session, session.referrerChain[referrerIdx]);

    // 3. AI evasion variants (sorted by confidence)
    const aiVariants = this.aiEvasion.generateVariants(payload, vulnClass);

    // 4. Traffic normalization
    const normResult = this.normalizer.normalize(ctx.domain, url);

    logger.debug('[StealthCoordinator] probe prepared', {
      sessionId: ctx.sessionId, domain: ctx.domain, vendor: ctx.vendor,
      delayMs: rec.waitMs, anomalyScore: rec.estimatedAnomalyScore,
      normalizationScore: normResult.deviationScore,
      variantCount: aiVariants.length,
    });

    return {
      url: normResult.normalizedUrl,
      headers,
      delayMs: rec.waitMs,
      rationale: rec.rationale,
      aiVariants,
      normalizationScore: normResult.deviationScore,
    };
  }

  /** Execute warmup for a domain/vendor before probing. programId enforces scope on every request. */
  async runWarmup(domain: string, vendor: string, dryRun = false, programId?: number): Promise<WarmupResult> {
    return this.warmup.warmup(domain, vendor, dryRun, programId);
  }

  /** Record probe outcome so timing and decay engines can update state. */
  recordOutcome(sessionId: string, domain: string, vendor: string, succeeded: boolean, technique: string): void {
    const { EvasionAttempt } = require('../hunter/types'); // type-only, no runtime cost
    temporalDecay.recordAttempt(sessionId, {
      sessionId,
      technique,
      category: domain,
      succeeded,
      responseCode: succeeded ? 200 : 403,
      responseTimeMs: 0,
      attemptedAt: Date.now(),
    });
  }

  /** Human-readable status line for logging. */
  getStatus(sessionId: string, domain: string, vendor: string): string {
    const state = temporalDecay.getDecayState(sessionId, domain, vendor);
    const analysis = temporalDecay.analyzeSession(sessionId, domain);
    return `[stealth] anomaly=${state.estimatedAnomalyScore.toFixed(2)} ` +
      `decay=${state.decayProgress.toFixed(2)} ` +
      `pattern=${analysis.transitionPattern} ` +
      `wait=${Math.round(state.recommendedWaitMs / 1000)}s`;
  }
}

export const stealthCoordinator = StealthCoordinator.getInstance();
