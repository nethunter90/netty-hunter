/**
 * DriftDetector.analyze — pillar drift must compare RATES, not raw counts.
 *
 * recentSnapshots spans a 1h window; baselineSnapshots spans a 23h window (24h
 * baseline minus the recent 1h). Summing raw activity counts across windows of
 * very different lengths and comparing them directly means a perfectly steady
 * activity rate reads as a huge "drop" purely because the baseline window is
 * ~23x longer — worse the busier a prior marathon session was, since that
 * inflates the baseline further. Fixed by normalizing to activity-per-snapshot
 * before comparing, the same way verdict drift already compares rates (%)
 * rather than raw counts.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { DriftDetector } from '../governance/drift-detector';
import type { GovernanceSnapshot, GovernancePillar } from '../governance/types';

const PILLAR: GovernancePillar = 'Prompt Injection Detection';
const OTHER_PILLARS: GovernancePillar[] = [
  'Pillar 1 - Kinetic Clause', 'Pillar 2 - Recursive Loop', 'Pillar 3 - Ethical Boundary',
  'Pillar 4 - Hardware Sovereignty', 'Pillar 5 - Multi-Agent Quorum', 'Safety Controls', 'Blue Team Oversight',
];

function snapshot(ageMs: number, pillarValue: number, verdicts?: Partial<GovernanceSnapshot['verdicts']>): GovernanceSnapshot {
  const pillarActivity = { [PILLAR]: pillarValue } as Record<GovernancePillar, number>;
  for (const p of OTHER_PILLARS) pillarActivity[p] = pillarValue;
  return {
    id: `s-${ageMs}`,
    timestamp: new Date(Date.now() - ageMs),
    config: { realToolsMode: false, scopeEnforcement: true, autoStealth: true, pillarSensitivities: {} as Record<GovernancePillar, number>, agentPermissions: {} },
    verdicts: { approved: 5, modified: 0, blocked: 5, total: 10, ...verdicts },
    pillarActivity,
    agentActivity: {},
    riskDistribution: { low: 5, medium: 3, high: 2, critical: 0 },
  };
}

describe('DriftDetector.analyze — pillar drift rate normalization', () => {
  let detector: DriftDetector;

  beforeEach(() => {
    detector = new DriftDetector();
  });

  it('does not flag a steady activity rate even when the baseline window has far more snapshots (marathon-session shape)', () => {
    // 24 snapshots across the 23h baseline window (one per hour, steady pace) —
    // matches how a long multi-hour hunting session would look.
    for (let h = 2; h <= 23; h++) {
      (detector as unknown as { snapshots: GovernanceSnapshot[] }).snapshots.push(snapshot(h * 3_600_000, 4));
    }
    // Recent window: a single snapshot at the SAME per-snapshot rate.
    (detector as unknown as { snapshots: GovernanceSnapshot[] }).snapshots.push(snapshot(30 * 60_000, 4));

    const analysis = detector.analyze();
    const drift = analysis.pillarDrift.find(p => p.pillar === PILLAR)!;

    expect(drift.flagged).toBe(false);
    expect(Math.abs(drift.activityChange)).toBeLessThan(10);
  });

  it('still flags a genuine drop in activity rate', () => {
    // Busy baseline: high per-snapshot activity throughout the 23h window.
    for (let h = 2; h <= 23; h++) {
      (detector as unknown as { snapshots: GovernanceSnapshot[] }).snapshots.push(snapshot(h * 3_600_000, 10));
    }
    // Recent window: activity has genuinely dropped to near zero.
    (detector as unknown as { snapshots: GovernanceSnapshot[] }).snapshots.push(snapshot(30 * 60_000, 0));

    const analysis = detector.analyze();
    const drift = analysis.pillarDrift.find(p => p.pillar === PILLAR)!;

    expect(drift.activityChange).toBeLessThan(-40);
    expect(drift.flagged).toBe(true);
  });

  it('returns no signal when the baseline window is too thin (episodic usage, not evidence of anything)', () => {
    (detector as unknown as { snapshots: GovernanceSnapshot[] }).snapshots.push(snapshot(20 * 3_600_000, 1));
    (detector as unknown as { snapshots: GovernanceSnapshot[] }).snapshots.push(snapshot(30 * 60_000, 0));

    const analysis = detector.analyze();
    const drift = analysis.pillarDrift.find(p => p.pillar === PILLAR)!;

    expect(drift.activityChange).toBe(0);
    expect(drift.flagged).toBe(false);
  });
});
