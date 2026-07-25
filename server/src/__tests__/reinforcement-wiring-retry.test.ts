/**
 * ReinforcementWiring.onRetryTechniqueOutcome — routes to the vendor-keyed
 * store method for waf_blocked and the stack-keyed one for
 * reflected_not_executed. Getting this routing backwards would silently
 * cross-pollinate the two axes the two RL domains exist to keep separate.
 *
 * Neither test below calls onHuntStart(), so provenance correctly resolves
 * to the "unknown" fail-closed default (this file tests routing, not
 * provenance resolution — see the segregation-proof tests for that).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockGetInstance, mockWafOutcome, mockPayloadOutcome } = vi.hoisted(() => {
  const mockWafOutcome = vi.fn().mockResolvedValue(undefined);
  const mockPayloadOutcome = vi.fn().mockResolvedValue(undefined);
  const mockGetInstance = vi.fn().mockReturnValue({
    recordWafEvasionOutcome: mockWafOutcome,
    recordPayloadMutationOutcome: mockPayloadOutcome,
  });
  return { mockGetInstance, mockWafOutcome, mockPayloadOutcome };
});

vi.mock('../intelligence/ReinforcementStore', () => ({
  UnifiedReinforcementStore: { getInstance: mockGetInstance },
}));

vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}));

import { ReinforcementWiring } from '../lib/hunter/reinforcement-wiring';

const wiring = new ReinforcementWiring();

beforeEach(() => {
  mockWafOutcome.mockClear();
  mockPayloadOutcome.mockClear();
});

describe('ReinforcementWiring.onRetryTechniqueOutcome', () => {
  it('routes waf_blocked to recordWafEvasionOutcome, keyed by vendor', () => {
    wiring.onRetryTechniqueOutcome('waf_blocked', 'cloudflare', 'xss', 'unicode_bypass', true);
    expect(mockWafOutcome).toHaveBeenCalledWith('cloudflare', 'xss', 'unicode_bypass', true, 'unknown');
    expect(mockPayloadOutcome).not.toHaveBeenCalled();
  });

  it('routes reflected_not_executed to recordPayloadMutationOutcome, keyed by stack', () => {
    wiring.onRetryTechniqueOutcome('reflected_not_executed', 'django', 'sqli', 'keyword-case', false);
    expect(mockPayloadOutcome).toHaveBeenCalledWith('django', 'sqli', 'keyword-case', false, 'unknown');
    expect(mockWafOutcome).not.toHaveBeenCalled();
  });
});
