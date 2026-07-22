import * as crypto from 'crypto';
import { stealthLogger } from './stealth-logger';

const ENV = {
  enabled: () => process.env.DYNAMIC_RATE_LIMIT_ENABLED !== 'false',
  windowMs: () => parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000'),
  quotaWarnThreshold: () => parseFloat(process.env.RATE_LIMIT_QUOTA_WARN_THRESHOLD || '0.2'),
  maxBackoffMs: () => parseInt(process.env.RATE_LIMIT_MAX_BACKOFF_MS || '300000'),
  quarantineMs: () => parseInt(process.env.RATE_LIMIT_QUARANTINE_MS || '600000'),
  burstThreshold: () => parseInt(process.env.RATE_LIMIT_BURST_THRESHOLD || '3'),
  // A 429 with no Retry-After only triggers backoff once this many 429s land within
  // the burst window — so scattered/noise 429s among successes are ignored, while a
  // genuine rate limit (a rapid run of 429s) still trips it within ~a second.
  noiseBurstCount: () => parseInt(process.env.RATE_LIMIT_429_BURST_COUNT || '3'),
  noiseBurstWindowMs: () => parseInt(process.env.RATE_LIMIT_429_BURST_WINDOW_MS || '10000'),
  // 2026-07-21 readiness pass (item B, check 2): every other delay in this file
  // is a REACTION to a signal the target already sent (a discovered quota, an
  // observed rate, a burst of recent responses, a 429). Before any such signal
  // exists — i.e. the very first requests of a hunt, exactly the OBSERVE-phase
  // Promise.allSettled batch — none of them fire, so request #1..N against a
  // target that has said nothing yet go out with zero pacing. This is the
  // baseline floor that covers that gap: a minimum spacing between successive
  // DISPATCHES to the same target, enforced independent of any response ever
  // having been seen. Deliberately small — this is "don't look like a burst
  // tool," not throttling; real reactive delays still dominate once a signal
  // exists.
  baselineIntervalMs: () => parseInt(process.env.RATE_LIMIT_BASELINE_INTERVAL_MS || '200'),
};

interface RateBucket {
  target: string;
  endpoint: string;
  requestTimestamps: number[];
  discoveredLimit: number | null;
  remaining: number | null;
  resetTime: number | null;
  windowDurationMs: number;
  lastActivity: number;
  recent429s: number[]; // timestamps of recent 429s, for burst-vs-noise discrimination
  backoff: {
    active: boolean;
    until: number;
    consecutive429s: number;
    consecutive403s: number;
    lastBackoffMs: number;
  };
  quarantine: {
    active: boolean;
    until: number;
    count: number;
  };
  hardBan: {
    active: boolean;
    until: number;
    count: number;
  };
  // Baseline dispatch-spacing floor (target-level bucket only) — see
  // ENV.baselineIntervalMs. The next wall-clock time a request to this target
  // is allowed to fire with zero delay; reserved synchronously per check so a
  // batch of concurrent callers stagger instead of all reading the same value.
  nextAllowedDispatch: number;
}

interface CheckResult {
  allowed: boolean;
  recommendedDelay: number;
  retryAfter?: number;
  reason?: string;
  bucket?: {
    target: string;
    endpoint: string;
    discoveredLimit: number | null;
    remaining: number | null;
    currentRate: number;
    backoffActive: boolean;
    quarantineActive: boolean;
  };
}

interface ThrottleBreakdown {
  quotaDelay: number;
  rateDelay: number;
  burstDelay: number;
  backoffDelay: number;
  finalDelay: number;
  factors: string[];
}

class DynamicRateLimiter {
  private buckets: Map<string, RateBucket> = new Map();
  private targetBuckets: Map<string, RateBucket> = new Map();
  private burstHistory: Map<string, number[]> = new Map();
  private hardBanCallbacks: Array<(target: string, durationMs: number) => void> = [];
  private stats = {
    totalChecks: 0,
    totalThrottles: 0,
    total429s: 0,
    totalQuarantines: 0,
    totalBursts: 0,
    discoveredLimits: 0,
  };
  private cleanupInterval: ReturnType<typeof setInterval>;

  constructor() {
    this.cleanupInterval = setInterval(() => this.expireInactiveBuckets(), 60000);
  }

  private bucketKey(target: string, endpoint: string): string {
    return `${target}::${endpoint}`;
  }

  private getOrCreateBucket(target: string, endpoint: string): RateBucket {
    const key = this.bucketKey(target, endpoint);
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = {
        target,
        endpoint,
        requestTimestamps: [],
        discoveredLimit: null,
        remaining: null,
        resetTime: null,
        windowDurationMs: ENV.windowMs(),
        lastActivity: Date.now(),
        recent429s: [],
        backoff: { active: false, until: 0, consecutive429s: 0, consecutive403s: 0, lastBackoffMs: 0 },
        quarantine: { active: false, until: 0, count: 0 },
        hardBan: { active: false, until: 0, count: 0 },
        nextAllowedDispatch: 0,
      };
      this.buckets.set(key, bucket);
    }
    return bucket;
  }

  private getOrCreateTargetBucket(target: string): RateBucket {
    let bucket = this.targetBuckets.get(target);
    if (!bucket) {
      bucket = {
        target,
        endpoint: '*',
        requestTimestamps: [],
        discoveredLimit: null,
        remaining: null,
        resetTime: null,
        windowDurationMs: ENV.windowMs(),
        lastActivity: Date.now(),
        recent429s: [],
        backoff: { active: false, until: 0, consecutive429s: 0, consecutive403s: 0, lastBackoffMs: 0 },
        quarantine: { active: false, until: 0, count: 0 },
        hardBan: { active: false, until: 0, count: 0 },
        nextAllowedDispatch: 0,
      };
      this.targetBuckets.set(target, bucket);
    }
    return bucket;
  }

  private pruneWindow(bucket: RateBucket): void {
    const cutoff = Date.now() - bucket.windowDurationMs;
    bucket.requestTimestamps = bucket.requestTimestamps.filter(t => t > cutoff);
  }

  private getCurrentRate(bucket: RateBucket): number {
    this.pruneWindow(bucket);
    if (bucket.requestTimestamps.length < 2) return 0;
    const windowSec = bucket.windowDurationMs / 1000;
    return bucket.requestTimestamps.length / windowSec;
  }

  private expireInactiveBuckets(): void {
    const expireMs = 10 * 60 * 1000;
    const now = Date.now();
    for (const [key, bucket] of Array.from(this.buckets.entries())) {
      if (now - bucket.lastActivity > expireMs) {
        this.buckets.delete(key);
      }
    }
    for (const [key, bucket] of Array.from(this.targetBuckets.entries())) {
      if (now - bucket.lastActivity > expireMs) {
        this.targetBuckets.delete(key);
      }
    }
  }

  // ─── Component 2: Response Header Parser ───

  parseResponseHeaders(headers: Record<string, string>): {
    limit: number | null;
    remaining: number | null;
    resetTime: number | null;
    retryAfter: number | null;
    policy: string | null;
  } {
    const h = (name: string): string | undefined => {
      const lower = name.toLowerCase();
      for (const [k, v] of Object.entries(headers)) {
        if (k.toLowerCase() === lower) return v;
      }
      return undefined;
    };

    const parseNum = (val: string | undefined): number | null => {
      if (!val) return null;
      const n = parseFloat(val);
      return isNaN(n) ? null : n;
    };

    const limit = parseNum(h('x-ratelimit-limit') || h('ratelimit-limit') || h('x-rate-limit-limit'));
    const remaining = parseNum(h('x-ratelimit-remaining') || h('ratelimit-remaining') || h('x-rate-limit-remaining'));

    let resetTime: number | null = null;
    const resetRaw = h('x-ratelimit-reset') || h('ratelimit-reset') || h('x-rate-limit-reset');
    if (resetRaw) {
      const resetNum = parseFloat(resetRaw);
      if (!isNaN(resetNum)) {
        resetTime = resetNum > 1e12 ? resetNum : resetNum > 1e9 ? resetNum * 1000 : Date.now() + resetNum * 1000;
      }
    }

    let retryAfter: number | null = null;
    const retryRaw = h('retry-after');
    if (retryRaw) {
      const retryNum = parseFloat(retryRaw);
      if (!isNaN(retryNum)) {
        retryAfter = retryNum * 1000;
      } else {
        const d = new Date(retryRaw);
        if (!isNaN(d.getTime())) {
          retryAfter = d.getTime() - Date.now();
          if (retryAfter < 0) retryAfter = 1000;
        }
      }
    }

    const policy = h('x-ratelimit-policy') || null;

    return { limit, remaining, resetTime, retryAfter, policy };
  }

  // ─── Component 3: Adaptive Throttle Calculator ───

  private calculateQuotaDelay(bucket: RateBucket): { delay: number; factor: string | null } {
    if (bucket.discoveredLimit === null || bucket.remaining === null) {
      return { delay: 0, factor: null };
    }

    const ratio = bucket.remaining / bucket.discoveredLimit;

    if (bucket.remaining <= 0 && bucket.resetTime) {
      const waitMs = bucket.resetTime - Date.now();
      if (waitMs > 0) {
        return { delay: waitMs, factor: `Quota exhausted, waiting for reset (${Math.ceil(waitMs / 1000)}s)` };
      }
    }

    const warnThreshold = ENV.quotaWarnThreshold();

    if (ratio < 0.1) {
      stealthLogger.log('alert', {
        type: 'rate_limit_low_quota',
        target: bucket.target,
        endpoint: bucket.endpoint,
        remaining: bucket.remaining,
        limit: bucket.discoveredLimit,
        ratio
      });
      const baseDelay = bucket.windowDurationMs / Math.max(bucket.remaining, 1);
      return { delay: baseDelay * 5, factor: `Quota critical (<10%): ${bucket.remaining}/${bucket.discoveredLimit}` };
    }

    if (ratio < warnThreshold) {
      const baseDelay = bucket.windowDurationMs / Math.max(bucket.remaining, 1);
      return { delay: baseDelay * 3, factor: `Quota low (<${warnThreshold * 100}%): ${bucket.remaining}/${bucket.discoveredLimit}` };
    }

    if (ratio < 0.5) {
      const baseDelay = bucket.windowDurationMs / bucket.discoveredLimit;
      return { delay: baseDelay * 1.5, factor: `Quota moderate (<50%): ${bucket.remaining}/${bucket.discoveredLimit}` };
    }

    return { delay: 0, factor: null };
  }

  private calculateRateDelay(bucket: RateBucket): { delay: number; factor: string | null } {
    const limit = bucket.discoveredLimit;
    if (!limit) return { delay: 0, factor: null };

    const currentRate = this.getCurrentRate(bucket);
    const limitPerSec = limit / (bucket.windowDurationMs / 1000);
    const utilization = currentRate / limitPerSec;

    if (utilization > 0.95) {
      const pauseMs = (bucket.windowDurationMs / limit) * 3;
      return { delay: pauseMs, factor: `Rate >95% of limit (${currentRate.toFixed(2)}/${limitPerSec.toFixed(2)} req/s)` };
    }

    if (utilization > 0.8) {
      const slowdown = (utilization - 0.8) / 0.15;
      const pauseMs = (bucket.windowDurationMs / limit) * (1 + slowdown * 2);
      return { delay: pauseMs, factor: `Rate >80% of limit (${(utilization * 100).toFixed(0)}% utilization)` };
    }

    return { delay: 0, factor: null };
  }

  /** Reserves the next dispatch slot for `target`, independent of any response
   *  ever having been seen. Synchronous read-then-write on the target bucket —
   *  concurrent callers (an OBSERVE-phase Promise.allSettled batch) each run
   *  to completion before the next microtask, so they stagger onto successive
   *  slots instead of all reading the same "now". */
  private reserveBaselineSlot(targetBucket: RateBucket): { delay: number; factor: string | null } {
    const interval = ENV.baselineIntervalMs();
    if (interval <= 0) return { delay: 0, factor: null };
    const now = Date.now();
    const earliestSlot = Math.max(now, targetBucket.nextAllowedDispatch || 0);
    targetBucket.nextAllowedDispatch = earliestSlot + interval;
    const delay = earliestSlot - now;
    return delay > 0
      ? { delay, factor: `Baseline pacing floor (${interval}ms/request, no target signal yet)` }
      : { delay: 0, factor: null };
  }

  calculateThrottle(target: string, endpoint: string): ThrottleBreakdown {
    const bucket = this.getOrCreateBucket(target, endpoint);
    const targetBucket = this.getOrCreateTargetBucket(target);

    const quota = this.calculateQuotaDelay(bucket);
    const targetQuota = this.calculateQuotaDelay(targetBucket);
    const quotaDelay = Math.max(quota.delay, targetQuota.delay);

    const rate = this.calculateRateDelay(bucket);
    const targetRate = this.calculateRateDelay(targetBucket);
    const rateDelay = Math.max(rate.delay, targetRate.delay);

    const burstDelay = this.calculateBurstDampening(target, endpoint);
    const baseline = this.reserveBaselineSlot(targetBucket);

    let backoffDelay = 0;
    if (bucket.backoff.active && bucket.backoff.until > Date.now()) {
      backoffDelay = bucket.backoff.until - Date.now();
    }
    if (targetBucket.backoff.active && targetBucket.backoff.until > Date.now()) {
      backoffDelay = Math.max(backoffDelay, targetBucket.backoff.until - Date.now());
    }

    const finalDelay = Math.max(quotaDelay, rateDelay, burstDelay, baseline.delay, backoffDelay);
    const factors: string[] = [];
    if (quota.factor) factors.push(quota.factor);
    if (targetQuota.factor) factors.push(`[target] ${targetQuota.factor}`);
    if (rate.factor) factors.push(rate.factor);
    if (targetRate.factor) factors.push(`[target] ${targetRate.factor}`);
    if (burstDelay > 0) factors.push(`Burst dampening: ${Math.ceil(burstDelay)}ms cooldown`);
    if (baseline.factor) factors.push(baseline.factor);
    if (backoffDelay > 0) factors.push(`Backoff active: ${Math.ceil(backoffDelay / 1000)}s remaining`);

    return { quotaDelay, rateDelay, burstDelay, backoffDelay, finalDelay, factors };
  }

  // ─── Component 5: Burst Detection & Dampening ───

  private calculateBurstDampening(target: string, endpoint: string): number {
    const key = this.bucketKey(target, endpoint);
    const history = this.burstHistory.get(key) || [];
    const now = Date.now();

    const burstThreshold = ENV.burstThreshold();
    const in1s = history.filter(t => now - t < 1000).length;
    const in3s = history.filter(t => now - t < 3000).length;

    let burstDetected = false;
    let burstSize = 0;

    if (in1s >= burstThreshold) {
      burstDetected = true;
      burstSize = in1s;
    } else if (in3s >= 5) {
      burstDetected = true;
      burstSize = in3s;
    }

    if (burstDetected) {
      this.stats.totalBursts++;
      const baseDelay = 2000;
      const cooldown = burstSize * baseDelay * 1.5;
      const jitter = cooldown * (0.7 + Math.random() * 0.6);

      stealthLogger.log('alert', {
        type: 'rate_limit_burst',
        target,
        endpoint,
        burstSize,
        in1s,
        in3s,
        cooldownMs: Math.ceil(jitter)
      });

      return jitter;
    }

    return 0;
  }

  private recordBurst(target: string, endpoint: string): void {
    const key = this.bucketKey(target, endpoint);
    let history = this.burstHistory.get(key);
    if (!history) {
      history = [];
      this.burstHistory.set(key, history);
    }
    history.push(Date.now());
    while (history.length > 20) history.shift();
  }

  // ─── Component 1: Sliding Window - checkRateLimit ───

  // `force` bypasses the DYNAMIC_RATE_LIMIT_ENABLED escape hatch. It exists so
  // scopedHttp can guarantee pacing/quarantine for real (programId>0) targets
  // even if that env var is set to 'false' in the environment — the flag is a
  // dev/lab convenience (and this repo's test suite forces it off globally to
  // avoid cross-test bucket-state bleed; see
  // src/__tests__/setup/disable-rate-limiter.ts), not something that should be
  // able to silently disable pacing against a real bug-bounty target.
  checkRateLimit(target: string, endpoint: string = '/', force = false): CheckResult {
    this.stats.totalChecks++;

    if (!ENV.enabled() && !force) {
      return { allowed: true, recommendedDelay: 0 };
    }

    const bucket = this.getOrCreateBucket(target, endpoint);
    const targetBucket = this.getOrCreateTargetBucket(target);

    if (bucket.quarantine.active && bucket.quarantine.until > Date.now()) {
      return {
        allowed: false,
        recommendedDelay: 0,
        retryAfter: bucket.quarantine.until - Date.now(),
        reason: `Target quarantined until ${new Date(bucket.quarantine.until).toISOString()}`,
        bucket: this.bucketSummary(bucket)
      };
    }
    if (targetBucket.quarantine.active && targetBucket.quarantine.until > Date.now()) {
      return {
        allowed: false,
        recommendedDelay: 0,
        retryAfter: targetBucket.quarantine.until - Date.now(),
        reason: `Target quarantined (aggregate) until ${new Date(targetBucket.quarantine.until).toISOString()}`,
        bucket: this.bucketSummary(targetBucket)
      };
    }

    if (bucket.backoff.active && bucket.backoff.until > Date.now()) {
      return {
        allowed: false,
        recommendedDelay: 0,
        retryAfter: bucket.backoff.until - Date.now(),
        reason: `Backoff active (${bucket.backoff.consecutive429s} consecutive 429s)`,
        bucket: this.bucketSummary(bucket)
      };
    }

    const throttle = this.calculateThrottle(target, endpoint);

    if (throttle.finalDelay > 0) {
      this.stats.totalThrottles++;

      stealthLogger.log('timing_adjustment', {
        type: 'rate_limit_throttle',
        target,
        endpoint,
        delay: Math.ceil(throttle.finalDelay),
        factors: throttle.factors,
        discoveredLimit: bucket.discoveredLimit,
        remaining: bucket.remaining,
        currentRate: this.getCurrentRate(bucket)
      });

      return {
        allowed: true,
        recommendedDelay: Math.ceil(throttle.finalDelay),
        reason: throttle.factors.join('; '),
        bucket: this.bucketSummary(bucket)
      };
    }

    return {
      allowed: true,
      recommendedDelay: 0,
      bucket: this.bucketSummary(bucket)
    };
  }

  // ─── Component 4: Exponential Backoff + recordResponse ───

  recordResponse(target: string, endpoint: string, statusCode: number, headers: Record<string, string>): void {
    const bucket = this.getOrCreateBucket(target, endpoint);
    const targetBucket = this.getOrCreateTargetBucket(target);
    const now = Date.now();

    bucket.lastActivity = now;
    targetBucket.lastActivity = now;
    bucket.requestTimestamps.push(now);
    targetBucket.requestTimestamps.push(now);
    this.pruneWindow(bucket);
    this.pruneWindow(targetBucket);
    this.recordBurst(target, endpoint);

    const parsed = this.parseResponseHeaders(headers);

    if (parsed.limit !== null) {
      const oldLimit = bucket.discoveredLimit;
      bucket.discoveredLimit = oldLimit !== null ? Math.min(oldLimit, parsed.limit) : parsed.limit;
      targetBucket.discoveredLimit = targetBucket.discoveredLimit !== null
        ? Math.min(targetBucket.discoveredLimit, parsed.limit)
        : parsed.limit;

      if (oldLimit === null) {
        this.stats.discoveredLimits++;
        stealthLogger.log('alert', {
          type: 'rate_limit_discovered',
          target,
          endpoint,
          limit: parsed.limit,
          remaining: parsed.remaining,
          resetTime: parsed.resetTime ? new Date(parsed.resetTime).toISOString() : null,
          policy: parsed.policy
        });
      }
    }

    if (parsed.remaining !== null) {
      bucket.remaining = parsed.remaining;
    }
    if (parsed.resetTime !== null) {
      bucket.resetTime = parsed.resetTime;
    }

    if (statusCode === 429) {
      this.stats.total429s++;
      bucket.backoff.consecutive429s++;

      // Track 429 arrival times in a short window to tell a real rate limit (a rapid
      // run of 429s) from noise (scattered single 429s among successes).
      bucket.recent429s.push(now);
      const burstCutoff = now - ENV.noiseBurstWindowMs();
      bucket.recent429s = bucket.recent429s.filter(t => t > burstCutoff);

      const hasRetryAfter = parsed.retryAfter !== null && parsed.retryAfter > 0;
      const isBurst = bucket.recent429s.length >= ENV.noiseBurstCount();

      // Back off only on an explicit server Retry-After (never noise — the server
      // told us to wait) OR a genuine burst. A lone/sporadic 429 among successes is
      // treated as noise: no backoff. Quarantine (5 consecutive) still applies — but
      // consecutive429s is reset by any 2xx, so scattered 429s never reach it.
      if (hasRetryAfter || isBurst) {
        let backoffMs: number;
        if (hasRetryAfter) {
          backoffMs = parsed.retryAfter as number;
        } else if (bucket.backoff.lastBackoffMs > 0) {
          backoffMs = Math.min(bucket.backoff.lastBackoffMs * 2, ENV.maxBackoffMs());
        } else {
          backoffMs = 30000;
        }

        backoffMs = Math.min(backoffMs, ENV.maxBackoffMs());
        bucket.backoff.active = true;
        bucket.backoff.until = now + backoffMs;
        bucket.backoff.lastBackoffMs = backoffMs;

        stealthLogger.log('alert', {
          type: 'rate_limit_backoff',
          target,
          endpoint,
          statusCode: 429,
          consecutive429s: bucket.backoff.consecutive429s,
          recent429s: bucket.recent429s.length,
          trigger: hasRetryAfter ? 'retry-after' : 'burst',
          backoffMs,
          retryAfterHeader: parsed.retryAfter,
          until: new Date(bucket.backoff.until).toISOString()
        });
      } else {
        // Sporadic/noise 429 — record it but do NOT back off; let successes flow.
        stealthLogger.log('alert', {
          type: 'rate_limit_429_noise',
          target,
          endpoint,
          consecutive429s: bucket.backoff.consecutive429s,
          recent429s: bucket.recent429s.length,
        });
      }

      if (bucket.backoff.consecutive429s >= 5) {
        const quarantineMs = ENV.quarantineMs() * (bucket.quarantine.count > 0 ? 2 : 1);
        bucket.quarantine.active = true;
        bucket.quarantine.until = now + quarantineMs;
        bucket.quarantine.count++;
        targetBucket.quarantine.active = true;
        targetBucket.quarantine.until = now + quarantineMs;
        targetBucket.quarantine.count++;

        this.stats.totalQuarantines++;

        stealthLogger.log('alert', {
          type: 'rate_limit_quarantine',
          target,
          endpoint,
          consecutive429s: bucket.backoff.consecutive429s,
          quarantineMs,
          quarantineCount: bucket.quarantine.count,
          until: new Date(bucket.quarantine.until).toISOString()
        });
      }
    } else if (statusCode === 403) {
      bucket.backoff.consecutive403s++;
      targetBucket.backoff.consecutive403s++;

      if (targetBucket.backoff.consecutive403s >= 5) {
        const banMs = 3_600_000; // 1 hour — hard bans don't reset in minutes
        targetBucket.hardBan.active = true;
        targetBucket.hardBan.until = now + banMs;
        targetBucket.hardBan.count++;

        stealthLogger.log('alert', {
          type: 'hard_ip_ban_detected',
          target,
          consecutive403s: targetBucket.backoff.consecutive403s,
          until: new Date(targetBucket.hardBan.until).toISOString(),
        });

        this.hardBanCallbacks.forEach(cb => { try { cb(target, banMs); } catch {} });
      }
    } else if (statusCode >= 200 && statusCode < 400) {
      if (bucket.backoff.consecutive429s > 0) {
        bucket.backoff.consecutive429s = 0;
        bucket.backoff.active = false;
        bucket.backoff.until = 0;
        bucket.backoff.lastBackoffMs = 0;
      }
      if (bucket.backoff.consecutive403s > 0) bucket.backoff.consecutive403s = 0;
      if (targetBucket.backoff.consecutive403s > 0) targetBucket.backoff.consecutive403s = 0;
    }
  }

  // ─── Integration: getRateLimitDelay for Timing Obfuscation ───

  getRateLimitDelay(target: string, endpoint: string = '/'): number {
    const result = this.checkRateLimit(target, endpoint);
    return result.recommendedDelay;
  }

  // ─── Integration: getDetectionSignal for Auto-Adjuster ───

  getDetectionSignal(target: string): { type: string; value: number } | null {
    const targetBucket = this.targetBuckets.get(target);
    if (!targetBucket) return null;

    if (targetBucket.quarantine.active && targetBucket.quarantine.until > Date.now()) {
      return { type: 'rate_limit_dynamic', value: 35 };
    }

    if (targetBucket.backoff.consecutive429s > 0) {
      const baseWeight = 25;
      const amplified = baseWeight * (1 + targetBucket.backoff.consecutive429s * 0.3);
      return { type: 'rate_limit_dynamic', value: Math.min(amplified, 50) };
    }

    if (targetBucket.remaining !== null && targetBucket.discoveredLimit !== null) {
      const ratio = targetBucket.remaining / targetBucket.discoveredLimit;
      if (ratio < 0.1) {
        return { type: 'rate_limit_dynamic', value: 20 };
      }
    }

    return null;
  }

  isHardBanned(target: string): boolean {
    const b = this.targetBuckets.get(target);
    return !!b && b.hardBan.active && b.hardBan.until > Date.now();
  }

  onHardBan(cb: (target: string, durationMs: number) => void): void {
    this.hardBanCallbacks.push(cb);
  }

  // ─── Utility ───

  private bucketSummary(bucket: RateBucket) {
    return {
      target: bucket.target,
      endpoint: bucket.endpoint,
      discoveredLimit: bucket.discoveredLimit,
      remaining: bucket.remaining,
      currentRate: parseFloat(this.getCurrentRate(bucket).toFixed(3)),
      backoffActive: bucket.backoff.active && bucket.backoff.until > Date.now(),
      quarantineActive: bucket.quarantine.active && bucket.quarantine.until > Date.now(),
    };
  }

  isEnabled(): boolean {
    return ENV.enabled();
  }

  getBucketState(target: string, endpoint: string = '/'): RateBucket | null {
    const key = this.bucketKey(target, endpoint);
    return this.buckets.get(key) || null;
  }

  getAllBuckets(): Array<{
    target: string;
    endpoint: string;
    discoveredLimit: number | null;
    remaining: number | null;
    resetTime: string | null;
    currentRate: number;
    requestCount: number;
    backoff: { active: boolean; until: string | null; consecutive429s: number };
    quarantine: { active: boolean; until: string | null; count: number };
  }> {
    const result: any[] = [];
    for (const [, bucket] of Array.from(this.buckets.entries())) {
      this.pruneWindow(bucket);
      const now = Date.now();
      result.push({
        target: bucket.target,
        endpoint: bucket.endpoint,
        discoveredLimit: bucket.discoveredLimit,
        remaining: bucket.remaining,
        resetTime: bucket.resetTime ? new Date(bucket.resetTime).toISOString() : null,
        currentRate: parseFloat(this.getCurrentRate(bucket).toFixed(3)),
        requestCount: bucket.requestTimestamps.length,
        backoff: {
          active: bucket.backoff.active && bucket.backoff.until > now,
          until: bucket.backoff.until > now ? new Date(bucket.backoff.until).toISOString() : null,
          consecutive429s: bucket.backoff.consecutive429s,
        },
        quarantine: {
          active: bucket.quarantine.active && bucket.quarantine.until > now,
          until: bucket.quarantine.until > now ? new Date(bucket.quarantine.until).toISOString() : null,
          count: bucket.quarantine.count,
        },
      });
    }
    return result;
  }

  getStats() {
    const now = Date.now();
    let activeBackoffs = 0;
    let activeQuarantines = 0;

    for (const [, b] of Array.from(this.buckets.entries())) {
      if (b.backoff.active && b.backoff.until > now) activeBackoffs++;
      if (b.quarantine.active && b.quarantine.until > now) activeQuarantines++;
    }

    return {
      enabled: ENV.enabled(),
      totalTargetsTracked: this.targetBuckets.size,
      totalBuckets: this.buckets.size,
      activeBackoffs,
      activeQuarantines,
      ...this.stats,
      config: {
        windowMs: ENV.windowMs(),
        quotaWarnThreshold: ENV.quotaWarnThreshold(),
        maxBackoffMs: ENV.maxBackoffMs(),
        quarantineMs: ENV.quarantineMs(),
        burstThreshold: ENV.burstThreshold(),
      }
    };
  }

  resetTarget(target: string): void {
    for (const [key, bucket] of Array.from(this.buckets.entries())) {
      if (bucket.target === target) {
        this.buckets.delete(key);
      }
    }
    this.targetBuckets.delete(target);
    for (const [key] of Array.from(this.burstHistory.entries())) {
      if (key.startsWith(`${target}::`)) {
        this.burstHistory.delete(key);
      }
    }
  }

  resetAll(): void {
    this.buckets.clear();
    this.targetBuckets.clear();
    this.burstHistory.clear();
  }
}

export const dynamicRateLimiter = new DynamicRateLimiter();
