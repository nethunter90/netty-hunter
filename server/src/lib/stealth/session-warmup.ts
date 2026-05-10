/**
 * Session Warmup
 * Pre-hunt protocol to establish a normal-traffic baseline in the defender's model
 * before beginning adversarial probes. Fires benign requests at human-like intervals.
 */
import axios from 'axios';
import { WarmupPlan, temporalDecay } from '../hunter/temporal-decay';
import { BehavioralMimicry } from './behavioral-mimicry';
import { ScopeGuard } from '../../middleware/scopeGuard';
import logger from '../../utils/logger';

export interface WarmupResult {
  completed: boolean;
  requestsFired: number;
  estimatedBaselineScore: number;  // 0–1 (lower = more normal-looking to defender)
  readyForProbing: boolean;
  elapsedMs: number;
}

const DEFAULT_PATHS = [
  '/', '/about', '/contact', '/faq', '/sitemap.xml',
  '/robots.txt', '/search?q=help', '/api/status', '/terms', '/privacy',
  '/blog', '/news', '/support', '/docs', '/pricing',
];

export class SessionWarmup {
  private readonly mimicry = new BehavioralMimicry();

  /**
   * Execute the warmup plan by firing benign-looking requests.
   * dryRun=true returns a plan without sending any HTTP traffic.
   */
  async execute(plan: WarmupPlan, options: { dryRun?: boolean; programId?: number } = {}): Promise<WarmupResult> {
    const { dryRun = false, programId } = options;
    const start = Date.now();
    const session = this.mimicry.buildSession(plan.domain);
    const scopeGuard = ScopeGuard.getInstance();
    let fired = 0;

    if (dryRun) {
      return {
        completed: true,
        requestsFired: 0,
        estimatedBaselineScore: 0.3,
        readyForProbing: true,
        elapsedMs: 0,
      };
    }

    for (let i = 0; i < plan.paths.length; i++) {
      const path = plan.paths[i % plan.paths.length];
      const url = `https://${plan.domain}${path}`;

      // Scope gate: skip any URL that is out-of-scope for the program
      if (programId !== undefined) {
        const { allowed, reason } = await scopeGuard.isInScope(url, programId);
        if (!allowed) {
          logger.warn('[SessionWarmup] skipping out-of-scope warmup URL', { url, reason });
          continue;
        }
      }
      const referrer = session.referrerChain[Math.min(i, session.referrerChain.length - 1)];
      const headers = this.mimicry.buildHeaders(session, referrer);

      try {
        await axios.get(url, {
          timeout: 6000,
          validateStatus: () => true,
          headers,
        });
        fired++;
        logger.debug('[SessionWarmup] benign request fired', { url, fired });
      } catch (err) {
        logger.debug('[SessionWarmup] request failed (non-fatal)', { url, err: String(err) });
      }

      // Inter-request delay from timing pattern
      const delay = session.timingPattern[i % session.timingPattern.length];
      if (delay > 0 && i < plan.paths.length - 1) {
        await new Promise(resolve => setTimeout(resolve, Math.min(delay, plan.intervalMs)));
      }
    }

    const elapsedMs = Date.now() - start;
    const baselineScore = this.estimateBaseline(fired, plan.requestCount);

    return {
      completed: fired >= plan.requestCount * 0.8,
      requestsFired: fired,
      estimatedBaselineScore: baselineScore,
      readyForProbing: baselineScore < 0.4,
      elapsedMs,
    };
  }

  /** Sample paths for normal browsing from defaults or override list. */
  sampleNormalPaths(domain: string, count: number, overrides?: string[]): string[] {
    const pool = overrides && overrides.length > 0 ? overrides : DEFAULT_PATHS;
    const shuffled = [...pool].sort(() => Math.random() - 0.5);
    return shuffled.slice(0, Math.min(count, shuffled.length));
  }

  /**
   * Rough estimate of normalcy score based on warmup completion ratio.
   * A fully completed warmup ≈ 0.15 (very normal), 0% warmup ≈ 0.9 (suspicious).
   */
  estimateBaseline(firedCount: number, targetCount: number): number {
    if (targetCount === 0) return 0.9;
    const completionRatio = Math.min(1, firedCount / targetCount);
    return Math.max(0.1, 0.9 - 0.75 * completionRatio);
  }

  /** Convenience: build + execute a warmup for a domain/vendor pair. */
  async warmup(domain: string, vendor: string, dryRun = false, programId?: number): Promise<WarmupResult> {
    const plan = temporalDecay.getWarmupPlan(domain, vendor);
    plan.paths = this.sampleNormalPaths(domain, plan.requestCount);
    return this.execute(plan, { dryRun, programId });
  }
}
