/**
 * The two new RL domains added for the retry-failure-classifier write path:
 * waf_evasion_technique (keyed by WAF VENDOR) and payload_mutation_technique
 * (keyed by APP STACK) — kept as separate domains/keys so a vendor-specific
 * bypass can never get misattributed to the origin app's stack or vice versa.
 *
 * Updated 2026-07-23 for the RL provenance segregation handoff: every
 * record()/get() call now takes a required provenance argument, and every
 * stored/mocked key carries its provenance prefix ("real::", here) since
 * that's what upsert()/queryDomain() actually read/write now.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockInsert, mockValues, mockWhere, mockSelect } = vi.hoisted(() => {
  const mockValues = vi.fn().mockReturnValue({ onConflictDoUpdate: vi.fn().mockResolvedValue(undefined) });
  const mockInsert = vi.fn().mockReturnValue({ values: mockValues });
  const mockWhere = vi.fn();
  const mockFrom = vi.fn().mockReturnValue({ where: mockWhere });
  const mockSelect = vi.fn().mockReturnValue({ from: mockFrom });
  return { mockInsert, mockValues, mockWhere, mockSelect };
});

vi.mock('../db', () => ({
  db: { insert: mockInsert, select: mockSelect, update: vi.fn() },
}));

vi.mock('../db/schema', () => ({
  reinforcementStore: { domain: 'domain', key: 'key', id: 'id', successCount: 'successCount', totalCount: 'totalCount', lastUpdated: 'lastUpdated', weight: 'weight' },
}));

vi.mock('drizzle-orm', () => ({
  eq: vi.fn((a, b) => ({ a, b })),
  and: vi.fn((...args) => args),
  lt: vi.fn(),
  sql: (strings: TemplateStringsArray, ...values: unknown[]) => ({ strings, values }),
}));

vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}));

import { UnifiedReinforcementStore } from '../intelligence/ReinforcementStore';

const store = UnifiedReinforcementStore.getInstance();

beforeEach(() => {
  mockInsert.mockClear();
  mockValues.mockClear();
  mockWhere.mockReset();
});

describe('waf_evasion_technique domain', () => {
  it('records an outcome keyed by (vendor, vulnClass, technique) — not stack — with a provenance-prefixed key', async () => {
    await store.recordWafEvasionOutcome('cloudflare', 'xss', 'unicode_bypass', true, 'real');

    expect(mockInsert).toHaveBeenCalled();
    const payload = mockValues.mock.calls[0][0];
    expect(payload.domain).toBe('waf_evasion_technique');
    expect(payload.key).toBe('real::cloudflare:xss:unicode_bypass');
    expect(payload.successCount).toBe(1);
  });

  it('returns null when fewer than 3 samples exist (cold-start safe)', async () => {
    mockWhere.mockResolvedValue([
      { key: 'real::cloudflare:xss:unicode_bypass', successCount: 1, totalCount: 2 },
    ]);
    const result = await store.getBestWafEvasionTechnique('cloudflare', 'xss', 'real');
    expect(result).toBeNull();
  });

  it('returns the highest-rate technique once the sample gate clears, ignoring other vendors/classes', async () => {
    mockWhere.mockResolvedValue([
      { key: 'real::cloudflare:xss:unicode_bypass', successCount: 4, totalCount: 5 },
      { key: 'real::cloudflare:xss:case_variation', successCount: 1, totalCount: 4 },
      { key: 'real::akamai:xss:null_byte', successCount: 5, totalCount: 5 }, // different vendor — must not win
      { key: 'real::cloudflare:sqli:unicode_bypass', successCount: 5, totalCount: 5 }, // different vulnClass — must not win
    ]);
    const result = await store.getBestWafEvasionTechnique('cloudflare', 'xss', 'real');
    expect(result).toBe('unicode_bypass');
  });

  it('a "lab"-provenance row is never read by a "real"-provenance query (segregation)', async () => {
    mockWhere.mockResolvedValue([
      { key: 'lab::cloudflare:xss:unicode_bypass', successCount: 5, totalCount: 5 },
    ]);
    const result = await store.getBestWafEvasionTechnique('cloudflare', 'xss', 'real');
    expect(result).toBeNull();
  });
});

describe('payload_mutation_technique domain', () => {
  it('records an outcome keyed by (stack, vulnClass, technique) — not vendor — with a provenance-prefixed key', async () => {
    await store.recordPayloadMutationOutcome('express+node', 'sqli', 'hex-literal', false, 'real');

    const payload = mockValues.mock.calls[0][0];
    expect(payload.domain).toBe('payload_mutation_technique');
    expect(payload.key).toBe('real::express+node:sqli:hex-literal');
    expect(payload.successCount).toBe(0);
  });

  it('returns the highest-rate technique for the given stack once sample-gated', async () => {
    mockWhere.mockResolvedValue([
      { key: 'real::django:sqli:keyword-case', successCount: 4, totalCount: 4 },
      { key: 'real::django:sqli:hex-literal', successCount: 1, totalCount: 3 },
    ]);
    const result = await store.getBestPayloadMutationTechnique('django', 'sqli', 'real');
    expect(result).toBe('keyword-case');
  });

  it('does not cross-contaminate with the waf_evasion_technique domain despite similar key shape', async () => {
    // Same-looking key components, different domain — must be a distinct
    // read since the two domains are the whole point of keeping them apart.
    mockWhere.mockResolvedValue([]);
    const result = await store.getBestPayloadMutationTechnique('cloudflare', 'xss', 'real');
    expect(result).toBeNull();
  });
});
