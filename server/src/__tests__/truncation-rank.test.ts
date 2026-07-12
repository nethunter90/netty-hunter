/**
 * truncationRank — MAX_HYPOTHESES cap survival priority.
 *
 * The 4 truncation call sites in HunterEngine sort the full hypothesis array
 * and splice it down to MAX_HYPOTHESES whenever it overflows. Before this,
 * they sorted purely by priority*confidence, so a hypothesis already deferred
 * by a vulnClassAllowlist (or already confirmed/rejected) kept whatever raw
 * score it had *before* being resolved and could permanently outrank — and
 * evict — a still-pending, lower-priority hypothesis that hasn't had a chance
 * to be probed yet. Confirmed live: crlf_injection hypotheses (priority 7,
 * confidence 0.55-0.8) never survived a single truncation pass on a target
 * that also produced race_condition hypotheses (priority 9, confidence 0.8,
 * but deferred by an allowlist) — the deferred ones kept winning purely on
 * stale score.
 */
import { describe, it, expect } from 'vitest';
import { truncationRank } from '../agents/HunterEngine';

function hyp(status: string, priority: number, confidence: number) {
  return { status, priority, confidence };
}

describe('truncationRank', () => {
  it('ranks a low-priority pending hypothesis above a high-priority deferred one', () => {
    const deferred = hyp('deferred', 9, 0.8); // score 7.2, but resolved — can never be probed again
    const pending = hyp('pending', 7, 0.6); // score 4.2, but still actionable

    expect(truncationRank(pending)).toBeGreaterThan(truncationRank(deferred));
  });

  it('ranks a low-priority probing hypothesis above a high-priority confirmed one', () => {
    const confirmed = hyp('confirmed', 10, 0.95); // score 9.5, already resolved
    const probing = hyp('probing', 5, 0.5); // score 2.5, still in flight

    expect(truncationRank(probing)).toBeGreaterThan(truncationRank(confirmed));
  });

  it('ranks a low-priority pending hypothesis above a high-priority rejected/inconclusive one', () => {
    const rejected = hyp('rejected', 10, 0.9);
    const inconclusive = hyp('inconclusive', 10, 0.9);
    const pending = hyp('pending', 1, 0.3);

    expect(truncationRank(pending)).toBeGreaterThan(truncationRank(rejected));
    expect(truncationRank(pending)).toBeGreaterThan(truncationRank(inconclusive));
  });

  it('falls back to priority*confidence ordering within the same actionability tier', () => {
    const highPending = hyp('pending', 9, 0.8);
    const lowPending = hyp('pending', 5, 0.5);
    expect(truncationRank(highPending)).toBeGreaterThan(truncationRank(lowPending));

    const highDeferred = hyp('deferred', 9, 0.8);
    const lowDeferred = hyp('deferred', 5, 0.5);
    expect(truncationRank(highDeferred)).toBeGreaterThan(truncationRank(lowDeferred));
  });

  it('reproduces the actual field scenario: crlf_injection survives race_condition after deferral', () => {
    const raceCondition = hyp('deferred', 9, 0.8); // excluded by vulnClassAllowlist
    const crlfInjection = hyp('pending', 7, 0.55); // allowed, still needs a probe

    const sorted = [raceCondition, crlfInjection].sort((a, b) => truncationRank(b) - truncationRank(a));
    expect(sorted[0]).toBe(crlfInjection);
  });
});
