/**
 * DynamicRateLimiter — 429-backoff behaviour.
 *
 * Keys off status-code only (no latency tracking), so the mock is trivial:
 * call recordResponse() with the desired status code.
 *
 * Scenarios:
 *  1. Baseline — 2xx responses never block.
 *  2. Single 429 activates backoff; checkRateLimit returns allowed:false.
 *  3. Repeat 429 doubles the backoff window (exponential).
 *  4. Retry-After header overrides the default 30 s backoff.
 *  5. 2xx after 429 resets backoff (re-adaptation).
 *  6. Five consecutive 429s trigger quarantine (not just backoff).
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { dynamicRateLimiter } from '../lib/stealth/dynamic-rate-limiter';

const TARGET = 'target.example.com';
const EP = '/api/search';

beforeEach(() => {
  dynamicRateLimiter.resetAll();
});

describe('DynamicRateLimiter — 429 backoff', () => {
  it('allows requests when all responses are 2xx', () => {
    for (let i = 0; i < 5; i++) {
      dynamicRateLimiter.recordResponse(TARGET, EP, 200, {});
    }
    const result = dynamicRateLimiter.checkRateLimit(TARGET, EP);
    expect(result.allowed).toBe(true);
  });

  it('blocks immediately after a single 429 with ~30 s retryAfter', () => {
    dynamicRateLimiter.recordResponse(TARGET, EP, 429, {});

    const result = dynamicRateLimiter.checkRateLimit(TARGET, EP);

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('1 consecutive 429s');
    // Default first backoff is 30 000 ms; allow up to 500 ms of wall-clock drift.
    expect(result.retryAfter).toBeGreaterThan(29_500);
    expect(result.retryAfter).toBeLessThanOrEqual(30_000);
  });

  it('doubles the backoff window on the second consecutive 429', () => {
    dynamicRateLimiter.recordResponse(TARGET, EP, 429, {});
    dynamicRateLimiter.recordResponse(TARGET, EP, 429, {});

    const result = dynamicRateLimiter.checkRateLimit(TARGET, EP);

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('2 consecutive 429s');
    // 2nd 429: lastBackoffMs was 30 000 → new = 30 000 × 2 = 60 000 ms.
    expect(result.retryAfter).toBeGreaterThan(59_500);
    expect(result.retryAfter).toBeLessThanOrEqual(60_000);
  });

  it('respects the Retry-After header instead of the default 30 s', () => {
    dynamicRateLimiter.recordResponse(TARGET, EP, 429, { 'retry-after': '120' });

    const result = dynamicRateLimiter.checkRateLimit(TARGET, EP);

    expect(result.allowed).toBe(false);
    // 120 s × 1 000 = 120 000 ms; allow up to 500 ms clock drift.
    expect(result.retryAfter).toBeGreaterThan(119_500);
    expect(result.retryAfter).toBeLessThanOrEqual(120_000);
  });

  it('clears backoff after a 2xx — re-adapts to allowed', () => {
    dynamicRateLimiter.recordResponse(TARGET, EP, 429, {});
    expect(dynamicRateLimiter.checkRateLimit(TARGET, EP).allowed).toBe(false);

    dynamicRateLimiter.recordResponse(TARGET, EP, 200, {});

    const result = dynamicRateLimiter.checkRateLimit(TARGET, EP);
    expect(result.allowed).toBe(true);
  });

  it('quarantines the target after 5 consecutive 429s', () => {
    for (let i = 0; i < 5; i++) {
      dynamicRateLimiter.recordResponse(TARGET, EP, 429, {});
    }

    const result = dynamicRateLimiter.checkRateLimit(TARGET, EP);

    expect(result.allowed).toBe(false);
    expect(result.reason).toMatch(/quarantined/i);
    // Quarantine window is 10 min by default; retryAfter should reflect that.
    expect(result.retryAfter).toBeGreaterThan(590_000);
  });
});
