/**
 * DynamicRateLimiter — 429 backoff with noise/burst discrimination.
 *
 * A lone/sporadic 429 (no Retry-After) is treated as NOISE and does not back off;
 * a genuine rate limit shows up as a burst (>= RATE_LIMIT_429_BURST_COUNT 429s
 * within the burst window) or an explicit Retry-After, either of which backs off.
 * This stops scattered 429s among successes from throttling the hunt, while keeping
 * real-tighten detection fast and preserving the 5-consecutive-429 quarantine.
 */
import { describe, it, expect, beforeEach, beforeAll, afterAll } from 'vitest';
import { dynamicRateLimiter } from '../lib/stealth/dynamic-rate-limiter';

const TARGET = 'target.example.com';
const EP = '/api/search';

// The global test setup (src/__tests__/setup/disable-rate-limiter.ts) disables
// the limiter so other suites' scopedHttp calls aren't paced/quarantined by
// leftover cross-test bucket state. This file tests the limiter itself, so it
// must force it back on.
let prevEnabledFlag: string | undefined;
beforeAll(() => {
  prevEnabledFlag = process.env.DYNAMIC_RATE_LIMIT_ENABLED;
  process.env.DYNAMIC_RATE_LIMIT_ENABLED = 'true';
});
afterAll(() => {
  process.env.DYNAMIC_RATE_LIMIT_ENABLED = prevEnabledFlag;
});

beforeEach(() => {
  dynamicRateLimiter.resetAll();
});

describe('DynamicRateLimiter — 429 noise vs burst', () => {
  it('allows requests when all responses are 2xx', () => {
    for (let i = 0; i < 5; i++) dynamicRateLimiter.recordResponse(TARGET, EP, 200, {});
    expect(dynamicRateLimiter.checkRateLimit(TARGET, EP).allowed).toBe(true);
  });

  it('does NOT back off on a single sporadic 429 (noise)', () => {
    dynamicRateLimiter.recordResponse(TARGET, EP, 429, {});
    // One stray 429 with no Retry-After is noise — requests keep flowing.
    expect(dynamicRateLimiter.checkRateLimit(TARGET, EP).allowed).toBe(true);
  });

  it('does NOT back off on 2 scattered 429s below the burst threshold', () => {
    dynamicRateLimiter.recordResponse(TARGET, EP, 429, {});
    dynamicRateLimiter.recordResponse(TARGET, EP, 429, {});
    expect(dynamicRateLimiter.checkRateLimit(TARGET, EP).allowed).toBe(true);
  });

  it('backs off (~30 s) once a burst of 3 rapid 429s is seen', () => {
    for (let i = 0; i < 3; i++) dynamicRateLimiter.recordResponse(TARGET, EP, 429, {});
    const r = dynamicRateLimiter.checkRateLimit(TARGET, EP);
    expect(r.allowed).toBe(false);
    expect(r.retryAfter).toBeGreaterThan(29_500);
    expect(r.retryAfter).toBeLessThanOrEqual(30_000);
  });

  it('doubles the backoff on the next 429 after a burst', () => {
    for (let i = 0; i < 4; i++) dynamicRateLimiter.recordResponse(TARGET, EP, 429, {});
    const r = dynamicRateLimiter.checkRateLimit(TARGET, EP);
    expect(r.allowed).toBe(false);
    // 3rd 429 → 30 s; 4th → doubled to 60 s.
    expect(r.retryAfter).toBeGreaterThan(59_500);
    expect(r.retryAfter).toBeLessThanOrEqual(60_000);
  });

  it('honors an explicit Retry-After immediately, even on a single 429', () => {
    dynamicRateLimiter.recordResponse(TARGET, EP, 429, { 'retry-after': '120' });
    const r = dynamicRateLimiter.checkRateLimit(TARGET, EP);
    expect(r.allowed).toBe(false); // server said wait — never treated as noise
    expect(r.retryAfter).toBeGreaterThan(119_500);
    expect(r.retryAfter).toBeLessThanOrEqual(120_000);
  });

  it('clears backoff after a 2xx — re-adapts to allowed', () => {
    dynamicRateLimiter.recordResponse(TARGET, EP, 429, { 'retry-after': '60' });
    expect(dynamicRateLimiter.checkRateLimit(TARGET, EP).allowed).toBe(false);
    dynamicRateLimiter.recordResponse(TARGET, EP, 200, {});
    expect(dynamicRateLimiter.checkRateLimit(TARGET, EP).allowed).toBe(true);
  });

  it('quarantines the target after 5 consecutive 429s', () => {
    for (let i = 0; i < 5; i++) dynamicRateLimiter.recordResponse(TARGET, EP, 429, {});
    const r = dynamicRateLimiter.checkRateLimit(TARGET, EP);
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/quarantined/i);
    expect(r.retryAfter).toBeGreaterThan(590_000);
  });
});
