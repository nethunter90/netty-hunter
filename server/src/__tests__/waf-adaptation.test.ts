/**
 * WAF adaptation harness — drives the REAL dynamicRateLimiter against a mock WAF
 * whose policy changes over a simulated ~25-minute hunt, on a virtual clock (runs
 * in ms). Measures adaptation quality, not just "did it avoid a block":
 *   - Detection latency  — how fast it reacts once the WAF genuinely tightens.
 *   - Recovery time      — how long until requests stabilize after the WAF relaxes.
 *   - Throughput         — successful 2xx/min per phase (does it collapse?).
 *   - False adaptation   — does it throttle on SPORADIC noise 429s (real limit is
 *                          fine), or on pure server LATENCY (no 429 at all)?
 *
 * Sporadic is the sharp test: the limiter backs off 30s on the *first* 429, so
 * random one-off 429s can waste throughput even when the sustained limit is fine.
 * The clock is faked so the limiter's real constants (30s backoff, 300s cap, 10min
 * quarantine, 60s window) apply at real scale while the sim completes instantly.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { dynamicRateLimiter } from '../lib/stealth/dynamic-rate-limiter';

const TARGET = 'waf-lab.example.com';
const MIN = 60_000;
const START = 1_700_000_000_000;

// Deterministic PRNG so the report is reproducible (mulberry32).
function mulberry32(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface PhaseCfg {
  name: string;
  limitPerMin: number;
  noiseProb: number;
  latencyMs: number;
  retryAfter?: number;
}

function schedule(t: number): PhaseCfg {
  const m = t / MIN;
  if (m < 6)  return { name: 'A:baseline',       limitPerMin: 120, noiseProb: 0,    latencyMs: 40 };
  if (m < 12) return { name: 'B:tighten',        limitPerMin: 6,   noiseProb: 0,    latencyMs: 40, retryAfter: 5 };
  if (m < 13) return { name: 'C:relax',          limitPerMin: 120, noiseProb: 0,    latencyMs: 40 };
  if (m < 19) return { name: 'D:sporadic-noise', limitPerMin: 120, noiseProb: 0.10, latencyMs: 40 };
  return               { name: 'E:latency-only',  limitPerMin: 120, noiseProb: 0,    latencyMs: 800 };
}

class MockWAF {
  private accepts: number[] = [];
  constructor(private rand: () => number) {}
  handle(now: number, cfg: PhaseCfg): { status: number; headers: Record<string, string>; noise: boolean } {
    this.accepts = this.accepts.filter(ts => ts > now - 60_000);
    const overLimit = this.accepts.length >= cfg.limitPerMin;
    const noise = !overLimit && this.rand() < cfg.noiseProb;
    if (overLimit || noise) {
      const headers: Record<string, string> = cfg.retryAfter ? { 'retry-after': String(cfg.retryAfter) } : {};
      return { status: 429, headers, noise };
    }
    this.accepts.push(now);
    return { status: 200, headers: {}, noise: false };
  }
}

describe('WAF adaptation (sporadic policy, virtual clock)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(START);
    dynamicRateLimiter.resetAll();
  });
  afterEach(() => { vi.useRealTimers(); });

  it('measures detection latency, recovery, throughput, and false adaptation', () => {
    const rand = mulberry32(1337);
    const waf = new MockWAF(rand);

    let now = START;
    const setNow = (t: number) => { now = t; vi.setSystemTime(t); };
    const END = START + 25 * MIN;

    const phase: Record<string, { ok: number; blocked429: number; waitMs: number; noise429: number }> = {};
    const bump = (name: string) => (phase[name] ??= { ok: 0, blocked429: 0, waitMs: 0, noise429: 0 });

    let firstTightenBlockAt = -1;
    let reqsInBBeforeBlock = 0;
    let recoveryAt = -1;
    let sawTightenBlock = false;
    let consecOk = 0;
    const q0 = dynamicRateLimiter.getStats().totalQuarantines;
    let block429InE = 0, backoffActivationsInE = 0;

    let guard = 0;
    while (now < END && guard++ < 200_000) {
      const cfg = schedule(now - START);
      const p = bump(cfg.name);

      const check = dynamicRateLimiter.checkRateLimit(TARGET);
      if (!check.allowed) {
        const wait = Math.max(check.retryAfter ?? check.recommendedDelay ?? 1000, 200);
        p.waitMs += wait;
        if (cfg.name === 'E:latency-only') backoffActivationsInE++;
        setNow(now + wait);
        continue;
      }
      if (check.recommendedDelay > 0) setNow(now + check.recommendedDelay);

      const res = waf.handle(now, cfg);
      setNow(now + cfg.latencyMs);
      dynamicRateLimiter.recordResponse(TARGET, '/', res.status, res.headers);

      if (res.status === 200) {
        p.ok++;
        if (cfg.name === 'B:tighten') reqsInBBeforeBlock++;
        if (sawTightenBlock && recoveryAt < 0 && ++consecOk >= 2) recoveryAt = now;
      } else {
        p.blocked429++;
        if (res.noise) p.noise429++;
        if (cfg.name === 'B:tighten' && firstTightenBlockAt < 0) firstTightenBlockAt = now;
        if (cfg.name === 'B:tighten') sawTightenBlock = true;
        consecOk = 0;
        if (cfg.name === 'E:latency-only') block429InE++;
      }
    }

    const bStart = START + 6 * MIN;
    const cStart = START + 12 * MIN;
    const detectionLatencyMs = firstTightenBlockAt > 0 ? firstTightenBlockAt - bStart : -1;
    const recoveryMs = recoveryAt > 0 && firstTightenBlockAt > 0 ? recoveryAt - firstTightenBlockAt : -1;
    const tput = (name: string, mins: number) => +(bump(name).ok / mins).toFixed(1);
    const stats = dynamicRateLimiter.getStats();

    const rows = Object.entries(phase).map(([n, v]) =>
      `  ${n.padEnd(18)} ok=${String(v.ok).padStart(4)}  429=${String(v.blocked429).padStart(4)}` +
      `  noise429=${String(v.noise429).padStart(3)}  backoffWait=${(v.waitMs / 1000).toFixed(0)}s`);
    // eslint-disable-next-line no-console
    console.log(
      `\nWAF ADAPTATION REPORT (seed 1337)\n${rows.join('\n')}\n\n` +
      `  Detection latency (B tighten -> 1st 429): ${(detectionLatencyMs / 1000).toFixed(1)}s ` +
      `(${reqsInBBeforeBlock} reqs slipped through at old cadence)\n` +
      `  Recovery time (relax -> 2 stable 2xx):    ${recoveryMs < 0 ? 'n/a' : (recoveryMs / 1000).toFixed(1) + 's'}\n` +
      `  Throughput  baseline(A)=${tput('A:baseline', 6)}/min  tighten(B)=${tput('B:tighten', 6)}/min  ` +
      `noise(D)=${tput('D:sporadic-noise', 6)}/min  latency(E)=${tput('E:latency-only', 6)}/min\n` +
      `  FALSE ADAPTATION - noise(D): ${bump('D:sporadic-noise').noise429} sporadic 429s cost ` +
      `${(bump('D:sporadic-noise').waitMs / 1000).toFixed(0)}s of backoff (limit was never the bottleneck)\n` +
      `  FALSE ADAPTATION - latency(E): ${block429InE} 429s, ${backoffActivationsInE} backoff waits ` +
      `(limiter ignores latency -> expect 0)\n` +
      `  limiter stats: total429s=${stats.total429s} throttles=${stats.totalThrottles} ` +
      `quarantines=${stats.totalQuarantines}\n`);

    // Hard invariants = the guarantees that MUST hold. The rest are printed as
    // measurements (detection/recovery/throughput/noise-cost) for humans to judge —
    // this is a measurement harness, not an opinion on tuning.
    // (a) sim actually ran
    expect(bump('A:baseline').ok).toBeGreaterThan(0);
    // (b) reacts to a genuine tighten within one window
    expect(detectionLatencyMs).toBeGreaterThan(0);
    expect(detectionLatencyMs).toBeLessThan(60_000);
    // (c) eventually recovers (even if via a quarantine lockout)
    expect(recoveryMs).toBeGreaterThanOrEqual(0);
    expect(recoveryMs).toBeLessThan(15 * MIN);
    // (d) STRUCTURAL CORRECTNESS: pure server latency (no 429) is NEVER mistaken for
    //     rate limiting. This is the one property that must not regress.
    expect(block429InE).toBe(0);
    expect(backoffActivationsInE).toBe(0);
    void q0;
  });
});
