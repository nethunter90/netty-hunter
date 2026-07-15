/**
 * TargetSelectionIntelligence — previously untested. Covers the new
 * scope/rules-aware factors added on top of the original payout/response-
 * time/history scoring: asset testability, bounty eligibility, severity
 * ceiling, and paying-vs-VDP status — all derived from the real per-asset
 * data synced from HackerOne into programs.metadata (see program-fetcher.ts/
 * sync-hackerone), with neutral (0.5) defaults for programs that don't have
 * it yet, and NO separate "RCE fit" term that could penalize a program for
 * lacking chain-friendly surface — that was an explicit design decision.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockTerminal, mockSelect } = vi.hoisted(() => {
  const mockTerminal = vi.fn();
  const chain: any = {
    from: vi.fn(() => chain),
    where: vi.fn(() => mockTerminal()),
    innerJoin: vi.fn(() => chain),
  };
  const mockSelect = vi.fn(() => chain);
  return { mockTerminal, mockSelect };
});

vi.mock('../db', () => ({ db: { select: mockSelect } }));
vi.mock('../db/schema', () => ({
  programs: { id: 'id', active: 'active' },
  findings: { id: 'id', campaignId: 'campaignId' },
  campaigns: { id: 'id', programId: 'programId' },
}));
vi.mock('drizzle-orm', () => ({
  eq: vi.fn((a, b) => ({ a, b })),
  desc: vi.fn(),
  sql: (strings: TemplateStringsArray, ...values: unknown[]) => ({ strings, values }),
}));
vi.mock('../utils/logger', () => ({ default: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() } }));

import { TargetSelectionIntelligence } from '../intelligence/TargetSelection';

const baseProgram = (overrides: Record<string, unknown> = {}) => ({
  id: 1, name: 'Test Program', platform: 'hackerone', scope: ['example.com'],
  outOfScope: [], maxPayout: 5000, avgPayout: 1000, responseTime: 48,
  successRate: 0, active: true, metadata: {}, ...overrides,
});

function queueQueries(programRow: Record<string, unknown>, huntCount = 0, findCount = 0) {
  mockTerminal
    .mockResolvedValueOnce([programRow])   // scorePrograms()'s own select
    .mockResolvedValueOnce([{ count: huntCount }])
    .mockResolvedValueOnce([{ count: findCount }]);
}

beforeEach(() => {
  mockTerminal.mockReset();
});

describe('TargetSelectionIntelligence — scope-aware factors', () => {
  it('uses neutral (0.5) defaults for a program with no scopeAssets metadata', async () => {
    queueQueries(baseProgram());
    const [score] = await new TargetSelectionIntelligence().scorePrograms();

    expect(score.factors.assetTestabilityScore).toBe(0.5);
    expect(score.factors.bountyEligibleScore).toBe(0.5);
    expect(score.factors.severityCeilingScore).toBe(0.5);
    expect(score.notes).toContain('No per-asset scope data — sync from HackerOne for a more precise score');
  });

  it('scores down (but does not zero) a program that is mostly non-web-testable scope', async () => {
    queueQueries(baseProgram({
      metadata: {
        scopeAssets: {
          inScope: [
            { type: 'ios', identifier: 'com.example.app', eligible: true },
            { type: 'android', identifier: 'com.example.app', eligible: true },
            { type: 'url', identifier: 'https://api.example.com', eligible: true },
          ],
          outOfScope: [],
        },
      },
    }));
    const [score] = await new TargetSelectionIntelligence().scorePrograms();

    expect(score.factors.assetTestabilityScore).toBeCloseTo(1 / 3);
    expect(score.roiScore).toBeGreaterThan(0); // not zeroed out
    expect(score.notes.some(n => n.includes('web-testable'))).toBe(true);
  });

  it('never adds a distinct RCE-fit penalty — testability is the only asset-type-derived factor', async () => {
    queueQueries(baseProgram({
      metadata: {
        scopeAssets: {
          inScope: [{ type: 'hardware', identifier: 'device-x', eligible: true, maxSeverity: 'critical' }],
          outOfScope: [],
        },
      },
    }));
    const [score] = await new TargetSelectionIntelligence().scorePrograms();

    // No hardware-only surface can host an RCE web chain, but there is no
    // separate factor punishing that beyond the general testability score —
    // confirm the factor set has exactly the documented keys, nothing extra.
    expect(Object.keys(score.factors).sort()).toEqual([
      'assetTestabilityScore', 'bountyEligibleScore', 'noiseScore', 'payingProgramScore',
      'payoutScore', 'platformScore', 'responseTimeScore', 'scopeBreadthScore', 'severityCeilingScore',
      'successRateScore',
    ].sort());
  });

  it('flags severity-capped scope without zeroing the score', async () => {
    queueQueries(baseProgram({
      metadata: {
        scopeAssets: {
          inScope: [
            { type: 'url', identifier: 'https://low.example.com', eligible: true, maxSeverity: 'low' },
            { type: 'url', identifier: 'https://none.example.com', eligible: true, maxSeverity: 'none' },
          ],
          outOfScope: [],
        },
      },
    }));
    const [score] = await new TargetSelectionIntelligence().scorePrograms();

    expect(score.factors.severityCeilingScore).toBe(0);
    expect(score.notes.some(n => n.toLowerCase().includes('cap'))).toBe(true);
    expect(score.roiScore).toBeGreaterThan(0);
  });

  it('scores a confirmed VDP-only program down but not to zero, with a clear note', async () => {
    queueQueries(baseProgram({ metadata: { offersBounties: false } }));
    const [score] = await new TargetSelectionIntelligence().scorePrograms();

    expect(score.factors.payingProgramScore).toBe(0.3);
    expect(score.notes.some(n => n.includes('VDP-only'))).toBe(true);
    expect(score.roiScore).toBeGreaterThan(0);
  });

  it('defaults an unknown (not confirmed false) offersBounties mildly optimistic, not zero', async () => {
    queueQueries(baseProgram({ metadata: {} }));
    const [score] = await new TargetSelectionIntelligence().scorePrograms();
    expect(score.factors.payingProgramScore).toBe(0.7);
  });
});
