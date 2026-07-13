/**
 * ContextWriter — found live: hunt-findings.json was populated by
 * HunterEngine's fast-path confidence threshold (UPDATE phase, confidence
 * > 0.7), but CampaignOrchestrator's separate, more rigorous Layer 5
 * 4-layer verification pipeline never fed its outcome back — a finding
 * later rejected by real browser replay + AI review stayed listed as
 * "confirmed" in hunt-findings.json indefinitely, with no trace of the
 * rejection. The database's own `findings` table got this right
 * (verificationStatus updated on rejection); the parallel context-writer
 * bookkeeping just never learned about it. Fixed via a `dbId` correlation
 * threaded from persistFinding()'s return value.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('fs', () => ({
  promises: {
    mkdir: vi.fn().mockResolvedValue(undefined),
    writeFile: vi.fn().mockResolvedValue(undefined),
    appendFile: vi.fn().mockResolvedValue(undefined),
  },
}));

import { contextWriter } from '../lib/context-writer';

function currentFindings(): Array<{ id: string; dbId?: number; confidence: number }> {
  return (contextWriter as unknown as { findings: Array<{ id: string; dbId?: number; confidence: number }> }).findings;
}

beforeEach(() => {
  contextWriter.reset('session-1', 'http://example.com', 'claude');
});

describe('ContextWriter retraction', () => {
  it('retracts a finding once Layer 5 rejects it, by dbId', () => {
    contextWriter.addFinding({
      id: 'hyp-uuid-1', dbId: 42, vulnClass: 'xss', severity: 'medium',
      confidence: 0.84, endpoint: 'http://example.com/', description: 'fast-path guess',
      confirmedAt: new Date().toISOString(),
    });
    expect(currentFindings()).toHaveLength(1);

    contextWriter.retractFinding(42);

    expect(currentFindings()).toHaveLength(0);
  });

  it('leaves other findings untouched when retracting one by dbId', () => {
    contextWriter.addFinding({
      id: 'hyp-1', dbId: 1, vulnClass: 'xss', severity: 'medium', confidence: 0.84,
      description: 'a', confirmedAt: new Date().toISOString(),
    });
    contextWriter.addFinding({
      id: 'hyp-2', dbId: 2, vulnClass: 'race_condition', severity: 'medium', confidence: 0.92,
      description: 'b', confirmedAt: new Date().toISOString(),
    });

    contextWriter.retractFinding(1);

    const remaining = currentFindings();
    expect(remaining).toHaveLength(1);
    expect(remaining[0].dbId).toBe(2);
  });

  it('reconciles confidence once Layer 5 confirms with a different final value', () => {
    contextWriter.addFinding({
      id: 'hyp-1', dbId: 7, vulnClass: 'race_condition', severity: 'medium', confidence: 0.6,
      description: 'a', confirmedAt: new Date().toISOString(),
    });

    contextWriter.updateFindingConfidence(7, 0.95);

    expect(currentFindings()[0].confidence).toBe(0.95);
  });
});
