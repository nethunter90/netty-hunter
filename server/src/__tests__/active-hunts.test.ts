/**
 * Active-hunt registry tests — the single-flight + real-abort safety core.
 *
 * These invariants are what make the $180 cost-runaway (~60 stacked launches)
 * structurally impossible: at most one hunt runs server-wide, concurrent
 * launches are rejected (not queued), and stop() actually invokes the engine's
 * stop() and frees the slot.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { activeHunts } from '../lib/state/active-hunts';
import type { Stoppable } from '../lib/state/active-hunts';

function makeHandle(): Stoppable & { stopped: number } {
  return { stopped: 0, stop() { this.stopped++; } };
}

describe('ActiveHuntRegistry — single-flight', () => {
  beforeEach(() => {
    // Ensure a clean slot between tests (stopAll clears active; release clears reservation).
    activeHunts.stopAll();
    activeHunts.release();
  });

  it('reserve() succeeds when idle and blocks a second reserve()', () => {
    expect(activeHunts.isActive()).toBe(false);
    expect(activeHunts.reserve('http://t/1')).toBe(true);
    // Second concurrent launch attempt is rejected, not queued.
    expect(activeHunts.reserve('http://t/2')).toBe(false);
    expect(activeHunts.isActive()).toBe(true);
  });

  it('10 rapid reserves → exactly ONE wins (the $180 scenario)', () => {
    const results = Array.from({ length: 10 }, (_, i) => activeHunts.reserve(`http://t/${i}`));
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(results[0]).toBe(true);            // first caller wins
    expect(results.slice(1).every(r => r === false)).toBe(true);
  });

  it('bind() promotes a reservation to a running hunt and exposes it via current()', () => {
    activeHunts.reserve('http://t/x');
    const h = makeHandle();
    activeHunts.bind({ id: 'sess-1', kind: 'hunt', handle: h, targetUrl: 'http://t/x', startedAt: Date.now() });
    expect(activeHunts.current()).toMatchObject({ id: 'sess-1', kind: 'hunt', targetUrl: 'http://t/x' });
    // Still single-flight after binding.
    expect(activeHunts.reserve('http://t/y')).toBe(false);
  });

  it('release(id) frees the slot so the next launch can proceed', () => {
    activeHunts.reserve('http://t/x');
    const h = makeHandle();
    activeHunts.bind({ id: 'sess-1', kind: 'hunt', handle: h, targetUrl: 'http://t/x', startedAt: Date.now() });
    activeHunts.release('sess-1');
    expect(activeHunts.isActive()).toBe(false);
    expect(activeHunts.reserve('http://t/next')).toBe(true);
  });

  it('release() with no id frees a pending reservation (setup-failed path)', () => {
    activeHunts.reserve('http://t/x');
    expect(activeHunts.isActive()).toBe(true);
    activeHunts.release();                      // setup threw before bind()
    expect(activeHunts.isActive()).toBe(false);
    expect(activeHunts.reserve('http://t/y')).toBe(true);
  });

  it('release(id) is a no-op for a non-matching id (late callback cannot clobber a newer hunt)', () => {
    activeHunts.reserve('http://t/a');
    const a = makeHandle();
    activeHunts.bind({ id: 'sess-A', kind: 'hunt', handle: a, targetUrl: 'http://t/a', startedAt: Date.now() });
    // A stale completion callback from an already-gone hunt:
    activeHunts.release('sess-OLD');
    // The current hunt is untouched.
    expect(activeHunts.current()).toMatchObject({ id: 'sess-A' });
  });
});

describe('ActiveHuntRegistry — real abort', () => {
  beforeEach(() => {
    activeHunts.stopAll();
    activeHunts.release();
  });

  it('stop(id) invokes the handle.stop() and frees the slot', () => {
    activeHunts.reserve('http://t/x');
    const h = makeHandle();
    activeHunts.bind({ id: 'sess-1', kind: 'hunt', handle: h, targetUrl: 'http://t/x', startedAt: Date.now() });
    expect(activeHunts.stop('sess-1')).toBe(true);
    expect(h.stopped).toBe(1);                 // real propagation, not just a flag flip
    expect(activeHunts.isActive()).toBe(false);
    expect(activeHunts.reserve('http://t/after-stop')).toBe(true);
  });

  it('stop(id) returns false when that id is not the active hunt', () => {
    expect(activeHunts.stop('nope')).toBe(false);
  });

  it('a throwing handle.stop() still releases the slot', () => {
    activeHunts.reserve('http://t/x');
    const thrower: Stoppable = { stop() { throw new Error('boom'); } };
    activeHunts.bind({ id: 'sess-1', kind: 'hunt', handle: thrower, targetUrl: 'http://t/x', startedAt: Date.now() });
    expect(() => activeHunts.stop('sess-1')).not.toThrow();
    expect(activeHunts.isActive()).toBe(false);
  });

  it('stopAll() halts whatever is running (emergency stop)', () => {
    activeHunts.reserve('http://t/x');
    const h = makeHandle();
    activeHunts.bind({ id: 'sess-1', kind: 'orchestration', handle: h, targetUrl: 'http://t/x', startedAt: Date.now() });
    expect(activeHunts.stopAll()).toBe(true);
    expect(h.stopped).toBe(1);
    expect(activeHunts.isActive()).toBe(false);
  });

  it('stopAll() returns false when nothing is running', () => {
    expect(activeHunts.stopAll()).toBe(false);
  });
});
