/**
 * checkWafBypassAuthorization — the shared fail-closed gate (scope +
 * programs.wafBypassPolicy) that both synthesize() and HunterEngine's
 * gray-zone waf_blocked retry now go through. Extracted specifically so
 * nothing calls EvasionLibrary as a "peer" that bypasses this check — a
 * second, independently-written copy of an auth gate is how one drifts and
 * eventually fails open.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockIsInScope, mockGetInstance, mockLimit, mockSelect } = vi.hoisted(() => {
  const mockIsInScope = vi.fn();
  const mockGetInstance = vi.fn().mockReturnValue({ isInScope: mockIsInScope });
  const mockLimit = vi.fn();
  const mockWhere = vi.fn().mockReturnValue({ limit: mockLimit });
  const mockFrom = vi.fn().mockReturnValue({ where: mockWhere });
  const mockSelect = vi.fn().mockReturnValue({ from: mockFrom });
  return { mockIsInScope, mockGetInstance, mockLimit, mockSelect };
});

vi.mock('../db', () => ({ db: { select: mockSelect } }));
vi.mock('../db/schema', () => ({ programs: { id: 'id', wafBypassPolicy: 'wafBypassPolicy' } }));
vi.mock('drizzle-orm', () => ({ eq: vi.fn((a, b) => ({ a, b })) }));
vi.mock('../utils/logger', () => ({ default: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() } }));
vi.mock('../middleware/scopeGuard', () => ({ ScopeGuard: { getInstance: mockGetInstance } }));
vi.mock('../lib/stealth', () => ({ stealthCoordinator: { prepareProbe: vi.fn(), recordOutcome: vi.fn() } }));
vi.mock('../lib/stealth/ai-waf-evasion', () => ({
  AIWAFEvasion: class { generateVariants() { return []; } },
}));
vi.mock('../lib/hunter/temporal-decay', () => ({ temporalDecay: { getDecayState: vi.fn() } }));

import { checkWafBypassAuthorization } from '../agents/WAFBypass';

beforeEach(() => {
  mockIsInScope.mockReset();
  mockLimit.mockReset();
});

describe('checkWafBypassAuthorization', () => {
  it('allows unconditionally when no programId is given', async () => {
    const result = await checkWafBypassAuthorization('http://example.com', undefined);
    expect(result.allowed).toBe(true);
    expect(mockIsInScope).not.toHaveBeenCalled();
  });

  it('blocks when the target is out of scope, without ever checking policy', async () => {
    mockIsInScope.mockResolvedValue({ allowed: false, reason: 'not in scope' });

    const result = await checkWafBypassAuthorization('http://evil.example.com', 1);

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Out of scope');
    expect(mockLimit).not.toHaveBeenCalled();
  });

  it('blocks when the program explicitly disallows WAF bypass, even though the target is in scope', async () => {
    mockIsInScope.mockResolvedValue({ allowed: true });
    mockLimit.mockResolvedValue([{ wafBypassPolicy: 'disallowed' }]);

    const result = await checkWafBypassAuthorization('http://example.com', 1);

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('WAF bypass disallowed by program policy');
  });

  it('allows when in scope and policy is unspecified or allowed', async () => {
    mockIsInScope.mockResolvedValue({ allowed: true });
    mockLimit.mockResolvedValue([{ wafBypassPolicy: 'unspecified' }]);

    const result = await checkWafBypassAuthorization('http://example.com', 1);
    expect(result.allowed).toBe(true);
  });

  it('allows when the program row is missing entirely (defensive default)', async () => {
    mockIsInScope.mockResolvedValue({ allowed: true });
    mockLimit.mockResolvedValue([]);

    const result = await checkWafBypassAuthorization('http://example.com', 1);
    expect(result.allowed).toBe(true);
  });
});
