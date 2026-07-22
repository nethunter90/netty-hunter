/**
 * Wiring regression test for readiness-pass item B.
 *
 * dynamic-rate-limiter.test.ts and waf-adaptation.test.ts prove the limiter
 * class itself is correct in isolation. Neither asserts that scopedHttp's
 * scopedRequest() actually CALLS it — the global test setup
 * (setup/disable-rate-limiter.ts) disables the limiter everywhere else
 * precisely so those other suites don't observe it, which means nothing in
 * the green suite would catch a refactor that silently unwires the calls
 * (checkRateLimit()/recordResponse() calls removed from scoped-http.ts while
 * everything else keeps passing). This file is that guard: it force-enables
 * the limiter for programId>0 (mirroring scopedHttp's own force-enable rule)
 * and spies directly on the dynamicRateLimiter singleton scopedHttp imports.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../middleware/scopeGuard', () => ({
  ScopeGuard: {
    getInstance: vi.fn().mockReturnValue({
      isInScope: vi.fn().mockResolvedValue({ allowed: true }),
    }),
  },
}));

vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

vi.mock('axios', () => ({
  default: {
    get: vi.fn().mockResolvedValue({ status: 200, headers: {}, data: 'ok' }),
    post: vi.fn(),
    request: vi.fn(),
    isAxiosError: () => false,
  },
}));

import { scopedHttp } from '../lib/net/scoped-http';
import { dynamicRateLimiter } from '../lib/stealth/dynamic-rate-limiter';

const TARGET_URL = 'http://wiring-check.example.com/probe';
const REAL_PROGRAM_ID = 555; // >0 → scopedHttp forces the limiter on for this call

let prevEnabledFlag: string | undefined;
beforeEach(() => {
  prevEnabledFlag = process.env.DYNAMIC_RATE_LIMIT_ENABLED;
  dynamicRateLimiter.resetAll();
});
afterEach(() => {
  process.env.DYNAMIC_RATE_LIMIT_ENABLED = prevEnabledFlag;
  vi.restoreAllMocks();
});

describe('scopedHttp — dynamicRateLimiter wiring', () => {
  it('calls checkRateLimit() before dispatch and recordResponse() after, for a real (programId>0) target', async () => {
    process.env.DYNAMIC_RATE_LIMIT_ENABLED = 'false'; // prove the force-enable path, not the default-on path
    const checkSpy = vi.spyOn(dynamicRateLimiter, 'checkRateLimit');
    const recordSpy = vi.spyOn(dynamicRateLimiter, 'recordResponse');

    await scopedHttp.get(TARGET_URL, {}, REAL_PROGRAM_ID);

    expect(checkSpy).toHaveBeenCalledWith('wiring-check.example.com', '/probe', true);
    expect(recordSpy).toHaveBeenCalledWith('wiring-check.example.com', '/probe', 200, {});
  });

  it('does NOT force-enable for the local-lab sentinel (programId === -1)', async () => {
    process.env.DYNAMIC_RATE_LIMIT_ENABLED = 'false';
    const checkSpy = vi.spyOn(dynamicRateLimiter, 'checkRateLimit');

    await scopedHttp.get(TARGET_URL, {}, -1);

    expect(checkSpy).toHaveBeenCalledWith('wiring-check.example.com', '/probe', false);
  });

  it('a discovered quota actually delays the next dispatch to the same target (proactive pacing is live, not a no-op)', async () => {
    process.env.DYNAMIC_RATE_LIMIT_ENABLED = 'true';
    vi.useFakeTimers();
    try {
      // Seed a near-exhausted quota so checkRateLimit() recommends a real delay.
      dynamicRateLimiter.recordResponse('wiring-check.example.com', '/probe', 200, {
        'x-ratelimit-limit': '20',
        'x-ratelimit-remaining': '1',
      });
      const check = dynamicRateLimiter.checkRateLimit('wiring-check.example.com', '/probe');
      expect(check.recommendedDelay).toBeGreaterThan(0);

      const settleSpy = vi.fn();
      const pending = scopedHttp.get(TARGET_URL, {}, REAL_PROGRAM_ID).then(settleSpy);
      // Flush microtasks so applyRateLimit() reaches its setTimeout-based sleep,
      // without yet advancing the fake clock.
      await vi.advanceTimersByTimeAsync(0);
      expect(settleSpy).not.toHaveBeenCalled(); // still paced — hasn't resolved yet

      await vi.advanceTimersByTimeAsync(check.recommendedDelay);
      await pending;
      expect(settleSpy).toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });
});
