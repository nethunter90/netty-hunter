/**
 * deriveAutonomyHuntMetrics is now the single derivation both
 * CampaignOrchestrator (orchestration-mode hunts) and routes/hunt.ts
 * (console-launched hunts) feed into AutonomyMaturityTracker — see
 * intelligence/hunt-metrics.ts for why this must not be re-derived per
 * call site. This tests the derivation directly against plain finding
 * rows, independent of either caller.
 */
import { describe, it, expect } from 'vitest';
import { deriveAutonomyHuntMetrics } from '../intelligence/hunt-metrics';

function makeFinding(overrides: Partial<{ verificationStatus: string; evidence: Array<{ tool?: string }> }> = {}) {
  return {
    verificationStatus: 'confirmed',
    evidence: [],
    ...overrides,
  } as any;
}

describe('deriveAutonomyHuntMetrics', () => {
  it('counts confirmed vs everything-else correctly', () => {
    const rows = [
      makeFinding({ verificationStatus: 'confirmed' }),
      makeFinding({ verificationStatus: 'confirmed' }),
      makeFinding({ verificationStatus: 'rejected' }),
      makeFinding({ verificationStatus: 'inconclusive' }),
    ];
    const m = deriveAutonomyHuntMetrics(rows, 0);
    expect(m.hypothesesGenerated).toBe(4);
    expect(m.hypothesesCorrect).toBe(2);
    expect(m.confirmedFindings).toBe(2);
    expect(m.falsePositives).toBe(2); // rejected + inconclusive, matches CampaignOrchestrator's prior semantics
  });

  it('a tool used only on confirmed findings counts as correct AND selected', () => {
    const rows = [
      makeFinding({ verificationStatus: 'confirmed', evidence: [{ tool: 'sqlmap' }] }),
    ];
    const m = deriveAutonomyHuntMetrics(rows, 0);
    expect(m.toolsCorrect).toBe(1);
    expect(m.toolsSelected).toBe(1);
  });

  it('a tool used only on rejected findings counts as selected but NOT correct', () => {
    const rows = [
      makeFinding({ verificationStatus: 'confirmed', evidence: [{ tool: 'sqlmap' }] }),
      makeFinding({ verificationStatus: 'rejected', evidence: [{ tool: 'xsstrike' }] }),
    ];
    const m = deriveAutonomyHuntMetrics(rows, 0);
    expect(m.toolsCorrect).toBe(1); // only sqlmap
    expect(m.toolsSelected).toBe(2); // sqlmap + xsstrike
  });

  it('empty findings list never divides by zero / never selects 0 tools (floor of 1)', () => {
    const m = deriveAutonomyHuntMetrics([], 0);
    expect(m.hypothesesGenerated).toBe(0);
    expect(m.confirmedFindings).toBe(0);
    expect(m.falsePositives).toBe(0);
    expect(m.toolsSelected).toBe(1); // Math.max(0, 1) floor, matches prior CampaignOrchestrator behavior
    expect(m.toolsCorrect).toBe(0);
  });

  it('reportQualityScore reflects whether any reports were generated', () => {
    const rows = [makeFinding({ verificationStatus: 'confirmed' })];
    expect(deriveAutonomyHuntMetrics(rows, 0).reportQualityScore).toBe(0);
    expect(deriveAutonomyHuntMetrics(rows, 3).reportQualityScore).toBe(0.8);
  });
});
