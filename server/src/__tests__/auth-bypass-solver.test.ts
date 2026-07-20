/**
 * AuthBypassSolver — no-op auth middleware detection.
 *
 * Proven live tonight (2026-07-10) against a real target (Kali-Web-IDE): a route
 * wrapped in `isAuthenticated` middleware was reachable with zero credentials
 * AND with an obviously-invalid credential, identically — because the middleware
 * itself was a no-op stub. The solver previously only fired when the baseline was
 * already 401/403 (bypass-header / JWT-none tricks); a baseline-200 endpoint
 * (reachable with no credentials at all) produced found:false and was silently
 * dropped — this is the exact shape of tonight's bug.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}));

const { mockAxiosFn } = vi.hoisted(() => ({ mockAxiosFn: vi.fn() }));
vi.mock('axios', () => ({
  default: Object.assign(mockAxiosFn, { request: mockAxiosFn, get: mockAxiosFn, post: mockAxiosFn }),
}));

vi.mock('../middleware/scopeGuard', () => ({
  ScopeGuard: {
    getInstance: vi.fn().mockReturnValue({
      isInScope: vi.fn().mockResolvedValue({ allowed: true }),
    }),
  },
}));

vi.mock('../db', () => ({ db: { insert: vi.fn(() => ({ values: vi.fn() })) } }));
vi.mock('../db/schema', () => ({ solverResults: {} }));
vi.mock('../lib/stealth', () => ({
  dynamicRateLimiter: {
    isHardBanned: () => false,
    recordResponse: vi.fn(),
    getDetectionSignal: () => null,
  },
  autoAdjuster: { evaluate: vi.fn() },
}));
vi.mock('../lib/intelligence/hunt-cortex', () => ({
  huntCortex: { emit: vi.fn(), subscribe: vi.fn() },
  SignalType: { TARGET_FRAGILITY_HIGH: 'target_fragility_high' },
}));

import axios from 'axios';
import { AuthBypassSolver } from '../agents/SolverPool';

const mockedAxios = mockAxiosFn;

function task(endpoint: string) {
  return {
    id: 't1', endpoint, vulnClass: 'auth_bypass' as const,
    programId: 0, sessionId: 0, priority: 5, confidence: 0.5, context: {},
  };
}

beforeEach(() => {
  mockedAxios.mockReset();
});

describe('AuthBypassSolver', () => {
  it('flags a no-op auth middleware distinctly (garbage credential succeeds identically to none)', async () => {
    // Baseline is 200 with no bypass tricks needed to reach it, so the solver
    // runs baseline + all 5 bypass-header attempts (none break early since
    // baseStatus isn't 401/403) + JWT-none + the new garbage-credential check —
    // 8 calls total. All return the same 200/body shape: the middleware doesn't
    // discriminate on anything it's given.
    mockedAxios.mockResolvedValue({ status: 200, data: '{"ok":true}', headers: {} });

    const solver = new AuthBypassSolver();
    const result = await solver.solve(task('http://localhost:5000/api/files/write'));

    expect(result.found).toBe(true);
    expect((result.evidence as { noopAuthMiddleware: boolean }).noopAuthMiddleware).toBe(true);
    expect(result.response).toMatch(/validates nothing/);
  });

  it('flags a plain missing-auth-check as a distinct, lower-confidence finding', async () => {
    // Baseline + all bypass/JWT-none attempts (calls 1-7) return the same body;
    // only the final garbage-credential call (call 8) differs in length — the
    // app is at least doing SOMETHING different, just not gating this route.
    mockedAxios.mockResolvedValue({ status: 200, data: '{"ok":true,"extra":"field"}', headers: {} });
    for (let i = 0; i < 7; i++) {
      mockedAxios.mockResolvedValueOnce({ status: 200, data: '{"ok":true}', headers: {} });
    }

    const solver = new AuthBypassSolver();
    const result = await solver.solve(task('http://localhost:5000/api/public-ish'));

    expect(result.found).toBe(true);
    expect((result.evidence as { noopAuthMiddleware: boolean }).noopAuthMiddleware).toBe(false);
    expect(result.response).toMatch(/no auth enforcement at all/);
  });

  it('does not fire when the endpoint is genuinely gated and no bypass trick works', async () => {
    // Baseline 401, every bypass-header attempt also 401, JWT-none also 401.
    mockedAxios.mockResolvedValue({ status: 401, data: '{"error":"unauthorized"}', headers: {} });

    const solver = new AuthBypassSolver();
    const result = await solver.solve(task('http://localhost:5000/api/admin'));

    expect(result.found).toBe(false);
  });

  it('still detects the existing IP-spoof-header bypass case', async () => {
    // Baseline 403, then the first spoof header (X-Original-URL) succeeds.
    mockedAxios
      .mockResolvedValueOnce({ status: 403, data: '{"error":"forbidden"}', headers: {} })
      .mockResolvedValueOnce({ status: 200, data: '{"ok":true}', headers: {} });

    const solver = new AuthBypassSolver();
    const result = await solver.solve(task('http://localhost:5000/admin/panel'));

    expect(result.found).toBe(true);
    expect(result.confidence).toBe(0.88);
  });
});
