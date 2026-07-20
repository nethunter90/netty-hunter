/**
 * VerifierAgent pipeline tests.
 *
 * Tests the 4 layers and the final verdict logic that determines whether a
 * finding is "confirmed", "rejected", or "inconclusive".
 *
 * The layers are accessed via `(agent as any)` casts since they are private;
 * all external dependencies (db, axios, ModelRouter, logger, worker_threads)
 * are mocked at module level so no network or filesystem calls occur.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import crypto from 'crypto';

// ─── Module mocks (must be declared before any imports that trigger them) ────

vi.mock('../db', () => ({
  db: {
    select: vi.fn().mockReturnValue({
      from: vi.fn().mockReturnValue({
        where: vi.fn().mockReturnValue({
          orderBy: vi.fn().mockReturnValue({
            limit: vi.fn().mockResolvedValue([]),
          }),
          limit: vi.fn().mockResolvedValue([]),
        }),
      }),
    }),
  },
}));

vi.mock('../db/schema', () => ({
  findings: { dedupHash: 'dedupHash', createdAt: 'createdAt', id: 'id', verificationStatus: 'verificationStatus' },
  huntSessions: { id: 'id', sessionUuid: 'sessionUuid' },
}));

vi.mock('drizzle-orm', () => ({
  eq: vi.fn(),
  desc: vi.fn(),
  isNotNull: vi.fn(),
  and: vi.fn(),
}));

vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

vi.mock('../lib/stealth/browser-fingerprint', () => ({
  getRandomUserAgent: () => 'Mozilla/5.0 (Test)',
}));

vi.mock('../intelligence/ModelRouter', () => ({
  ModelRouter: {
    getInstance: vi.fn().mockReturnValue({
      reason: vi.fn().mockResolvedValue('{"confirmed":true,"reasoning":"looks legit","confidenceAdjustment":0}'),
    }),
  },
}));

vi.mock('../governance', () => ({
  promptInjectionDetector: {
    detect: vi.fn().mockReturnValue({ safe: true, score: 0, reasons: [] }),
  },
}));

// Worker mock — used by Layer3BrowserReplay.initialize()
vi.mock('worker_threads', () => {
  const EventEmitter = require('events');
  class FakeWorker extends EventEmitter {
    postMessage(msg: any) {
      if (msg.type === 'init') {
        // Simulate worker not ready → initialize() will catch and disable Layer 3
        setImmediate(() => this.emit('message', { type: 'ready' }));
      }
    }
    terminate() { return Promise.resolve(); }
  }
  return { Worker: FakeWorker };
});

vi.mock('../middleware/scopeGuard', () => ({
  ScopeGuard: {
    getInstance: vi.fn().mockReturnValue({
      isInScope: vi.fn().mockResolvedValue({ allowed: true }),
    }),
  },
}));

vi.mock('axios', () => ({
  default: { get: vi.fn() },
}));

// ─── Imports (after mocks) ────────────────────────────────────────────────────

import { VerifierAgent } from '../agents/VerifierAgent';
import type { SolverResult } from '../agents/SolverPool';
import { pendingEscalation } from '../lib/verification/verify-finding';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeSolverResult(overrides: Partial<SolverResult> = {}): SolverResult {
  return {
    taskId: 'task-1',
    solverId: 'solver-1',
    endpoint: 'http://target.com/search?q=test',
    vulnClass: 'cors',      // Not in mandatory gate list → mustPassBrowser = false
    found: true,
    confidence: 0.5,        // Below 0.7 → mustPassBrowser = false
    evidence: {},
    payload: '<test>',
    request: 'http://target.com/search?q=test',
    response: 'ok',
    duration: 500,
    toolsUsed: ['curl'],
    ...overrides,
  };
}

// Helper to build a confirmed L2 mock return
const l2Confirmed = { confirmed: true, statusCode: 200, responseSnippet: 'ok' };
const l2Rejected  = { confirmed: false, statusCode: 404, responseSnippet: 'not found' };
const l3Confirmed = { confirmed: true, screenshot: undefined, consoleAlerts: [], networkRequests: [] };
const l3Rejected  = { confirmed: false, consoleAlerts: [], networkRequests: [] };
const l4Confirmed = { confirmed: true, reasoning: 'valid vuln', confidenceAdjustment: 0 };
const l4Rejected  = { confirmed: false, reasoning: 'false positive', confidenceAdjustment: -0.2 };

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('VerifierAgent', () => {
  let agent: VerifierAgent;

  beforeEach(async () => {
    agent = new VerifierAgent();
    // Don't call initialize() — it spawns Playwright; mock layers directly instead
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  // ─── Layer 1: computeHash ────────────────────────────────────────────────

  describe('Layer1Dedup.computeHash', () => {
    it('is deterministic for the same input', () => {
      const l1 = (agent as any).layer1;
      const result = makeSolverResult();
      expect(l1.computeHash(result)).toBe(l1.computeHash(result));
    });

    it('strips query string from endpoint before hashing', () => {
      const l1 = (agent as any).layer1;
      const withQuery    = makeSolverResult({ endpoint: 'http://t.com/page?q=1' });
      const withoutQuery = makeSolverResult({ endpoint: 'http://t.com/page' });
      // Both should hash to the same value since query is stripped
      expect(l1.computeHash(withQuery)).toBe(l1.computeHash(withoutQuery));
    });

    it('normalises payload (lowercase, trimmed, 100 chars max)', () => {
      const l1 = (agent as any).layer1;
      const upper   = makeSolverResult({ payload: '  <SCRIPT>ALERT(1)</SCRIPT>  ' });
      const lower   = makeSolverResult({ payload: '<script>alert(1)</script>' });
      expect(l1.computeHash(upper)).toBe(l1.computeHash(lower));
    });

    it('produces different hashes for different vuln classes at same endpoint', () => {
      const l1 = (agent as any).layer1;
      const xss  = makeSolverResult({ vulnClass: 'xss' });
      const sqli = makeSolverResult({ vulnClass: 'sqli' });
      expect(l1.computeHash(xss)).not.toBe(l1.computeHash(sqli));
    });

    it('output is a valid SHA-256 hex string (64 chars)', () => {
      const l1 = (agent as any).layer1;
      const hash = l1.computeHash(makeSolverResult());
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  // ─── Layer 1: dedup check ────────────────────────────────────────────────

  describe('Layer1Dedup.check', () => {
    it('returns isDuplicate=true when hash is already in cache', async () => {
      const l1 = (agent as any).layer1;
      const result = makeSolverResult();
      const hash = l1.computeHash(result);
      const simhash = l1.computeSimHash(result);
      // Pre-populate cache
      l1.hashCache.add(hash);
      const check = await l1.check(hash, simhash);
      expect(check.isDuplicate).toBe(true);
      expect(check.existingHash).toBe(hash);
    });

    it('returns isDuplicate=false for a novel finding WITHOUT caching it yet', async () => {
      // check() runs before the verdict is known — a novel hash must not be
      // cached until recordIfConfirmed() commits it, otherwise a finding that
      // turns out to be rejected would still block future identical attempts.
      const l1 = (agent as any).layer1;
      const result = makeSolverResult({ taskId: 'novel-finding-999' });
      const hash = l1.computeHash(result);
      const simhash = l1.computeSimHash(result);
      const check = await l1.check(hash, simhash);
      expect(check.isDuplicate).toBe(false);
      expect(l1.hashCache.has(hash)).toBe(false);
    });

    it('recordIfConfirmed caches the hash only when verdict is "confirmed"', async () => {
      const l1 = (agent as any).layer1;
      const result = makeSolverResult({ taskId: 'rejected-then-confirmed' });
      const hash = l1.computeHash(result);
      const simhash = l1.computeSimHash(result);

      l1.recordIfConfirmed(hash, simhash, 'rejected');
      expect(l1.hashCache.has(hash)).toBe(false);

      l1.recordIfConfirmed(hash, simhash, 'confirmed');
      expect(l1.hashCache.has(hash)).toBe(true);
    });

    it('a rejected finding does not block a later re-attempt with the same hash', async () => {
      const l1 = (agent as any).layer1;
      const result = makeSolverResult({ taskId: 'retry-after-fix' });
      const hash = l1.computeHash(result);
      const simhash = l1.computeSimHash(result);

      const first = await l1.check(hash, simhash);
      expect(first.isDuplicate).toBe(false);
      l1.recordIfConfirmed(hash, simhash, 'rejected'); // no-op, verdict wasn't confirmed

      const second = await l1.check(hash, simhash);
      expect(second.isDuplicate).toBe(false);
    });
  });

  // ─── Layer 2: signal detection logic ─────────────────────────────────────

  describe('Layer2Reprobe signals', () => {
    it('returns confirmed=false when result.request is empty', async () => {
      const l2 = (agent as any).layer2;
      const r = await l2.reprobe(makeSolverResult({ request: '' }));
      expect(r.confirmed).toBe(false);
      expect(r.statusCode).toBe(0);
    });

    it('confirms XSS when payload appears in response body', async () => {
      const { default: axios } = await import('axios');
      (axios.get as ReturnType<typeof vi.fn>).mockResolvedValue({
        status: 200,
        data: 'page content <script>alert(1)</script> end',
      });
      const l2 = (agent as any).layer2;
      const r = await l2.reprobe(makeSolverResult({ vulnClass: 'xss', payload: '<script>alert(1)</script>' }));
      expect(r.confirmed).toBe(true);
    });

    it('confirms XSS when status < 400 even without payload in body', async () => {
      const { default: axios } = await import('axios');
      (axios.get as ReturnType<typeof vi.fn>).mockResolvedValue({
        status: 200,
        data: 'clean page',
      });
      const l2 = (agent as any).layer2;
      const r = await l2.reprobe(makeSolverResult({ vulnClass: 'xss', payload: '<img src=x>' }));
      expect(r.confirmed).toBe(true);
    });

    it('confirms SQLi when response contains SQL error pattern', async () => {
      const { default: axios } = await import('axios');
      (axios.get as ReturnType<typeof vi.fn>).mockResolvedValue({
        status: 500,
        data: "You have an error in your SQL syntax near '1' at line 1",
      });
      const l2 = (agent as any).layer2;
      const r = await l2.reprobe(makeSolverResult({ vulnClass: 'sqli', payload: "' OR 1=1 --" }));
      expect(r.confirmed).toBe(true);
    });

    it('confirms SSRF when response contains instance metadata marker', async () => {
      const { default: axios } = await import('axios');
      (axios.get as ReturnType<typeof vi.fn>).mockResolvedValue({
        status: 200,
        data: '{"ami-id":"ami-0abc12345"}',
      });
      const l2 = (agent as any).layer2;
      const r = await l2.reprobe(makeSolverResult({ vulnClass: 'ssrf', payload: 'http://169.254.169.254/' }));
      expect(r.confirmed).toBe(true);
    });

    it('confirms SSRF when response contains /etc/passwd content', async () => {
      const { default: axios } = await import('axios');
      (axios.get as ReturnType<typeof vi.fn>).mockResolvedValue({
        status: 200,
        data: 'root:x:0:0:root:/root:/bin/bash',
      });
      const l2 = (agent as any).layer2;
      const r = await l2.reprobe(makeSolverResult({ vulnClass: 'ssrf', payload: 'file:///etc/passwd' }));
      expect(r.confirmed).toBe(true);
    });

    it('rejects SQLi when no error and status >= 400', async () => {
      const { default: axios } = await import('axios');
      (axios.get as ReturnType<typeof vi.fn>).mockResolvedValue({
        status: 403,
        data: 'Forbidden',
      });
      const l2 = (agent as any).layer2;
      const r = await l2.reprobe(makeSolverResult({ vulnClass: 'sqli', payload: "' OR 1=1 --" }));
      expect(r.confirmed).toBe(false);
    });

    it('returns confirmed=false on network error', async () => {
      const { default: axios } = await import('axios');
      (axios.get as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('ECONNREFUSED'));
      const l2 = (agent as any).layer2;
      const r = await l2.reprobe(makeSolverResult());
      expect(r.confirmed).toBe(false);
      expect(r.statusCode).toBe(0);
    });

    it('truncates response snippet to 300 characters', async () => {
      const { default: axios } = await import('axios');
      (axios.get as ReturnType<typeof vi.fn>).mockResolvedValue({
        status: 200,
        data: 'a'.repeat(500),
      });
      const l2 = (agent as any).layer2;
      const r = await l2.reprobe(makeSolverResult({ found: true }));
      expect(r.responseSnippet.length).toBeLessThanOrEqual(300);
    });
  });

  // ─── Layer 4: AI response parsing ────────────────────────────────────────

  describe('Layer4AIConfirmation', () => {
    const evidence = {
      layer2: { confirmed: true, statusCode: 200, responseSnippet: 'ok' },
      layer3: { confirmed: true, consoleAlerts: [] },
    };

    function getL4WithResponse(response: string) {
      const a = new VerifierAgent();
      const l4 = (a as any).layer4;
      vi.spyOn((l4 as any).modelRouter, 'reason').mockResolvedValue(response);
      return l4;
    }

    function getL4WithError(err: Error) {
      const a = new VerifierAgent();
      const l4 = (a as any).layer4;
      vi.spyOn((l4 as any).modelRouter, 'reason').mockRejectedValue(err);
      return l4;
    }

    it('parses a clean JSON response correctly', async () => {
      const l4 = getL4WithResponse('{"confirmed":true,"reasoning":"clear vulnerability","confidenceAdjustment":0.2}');
      const r = await l4.confirm(makeSolverResult(), evidence);
      expect(r.confirmed).toBe(true);
      expect(r.reasoning).toBe('clear vulnerability');
      expect(r.confidenceAdjustment).toBe(0.2);
    });

    it('extracts JSON embedded in surrounding prose', async () => {
      const l4 = getL4WithResponse('Based on the evidence: {"confirmed":false,"reasoning":"false positive","confidenceAdjustment":-0.3} — my analysis is done.');
      const r = await l4.confirm(makeSolverResult(), evidence);
      expect(r.confirmed).toBe(false);
      expect(r.confidenceAdjustment).toBe(-0.3);
    });

    it('clamps confidenceAdjustment above +0.3 down to +0.3', async () => {
      const l4 = getL4WithResponse('{"confirmed":true,"reasoning":"x","confidenceAdjustment":99}');
      const r = await l4.confirm(makeSolverResult(), evidence);
      expect(r.confidenceAdjustment).toBe(0.3);
    });

    it('clamps confidenceAdjustment below -0.5 up to -0.5', async () => {
      const l4 = getL4WithResponse('{"confirmed":false,"reasoning":"x","confidenceAdjustment":-99}');
      const r = await l4.confirm(makeSolverResult(), evidence);
      expect(r.confidenceAdjustment).toBe(-0.5);
    });

    it('on model error returns errored=true (needs review), never a silent confirm', async () => {
      // Post-refactor (dd3d1b9): a dead L4 no longer rubber-stamps the L2∩L3
      // consensus. It returns errored=true so the verdict routes to inconclusive
      // rather than confirming on the other layers' raw booleans.
      const l4 = getL4WithError(new Error('LLM unavailable'));
      const bothConfirmed = {
        layer2: { confirmed: true, statusCode: 200, responseSnippet: 'ok' },
        layer3: { confirmed: true, consoleAlerts: [] },
      };
      const r = await l4.confirm(makeSolverResult(), bothConfirmed);
      expect(r.confirmed).toBe(false);
      expect(r.errored).toBe(true);
      expect(r.reasoning).toContain('unavailable');
    });

    it('degrades to false when LLM throws and L2/L3 disagree', async () => {
      const l4 = getL4WithError(new Error('LLM unavailable'));
      const mixed = {
        layer2: { confirmed: true, statusCode: 200, responseSnippet: 'ok' },
        layer3: { confirmed: false, consoleAlerts: [] },
      };
      const r = await l4.confirm(makeSolverResult(), mixed);
      expect(r.confirmed).toBe(false);
    });
  });

  // ─── Final verdict logic ──────────────────────────────────────────────────

  describe('Verdict logic (via VerifierAgent.verify)', () => {
    async function runVerify(result: SolverResult, {
      l1 = { isDuplicate: false },
      l2 = l2Confirmed,
      l3 = l3Confirmed,
      l4 = l4Confirmed,
    }: { l1?: any; l2?: any; l3?: any; l4?: any } = {}) {
      const a = new VerifierAgent();
      vi.spyOn((a as any).layer1, 'check').mockResolvedValue(l1);
      vi.spyOn((a as any).layer1, 'computeHash').mockReturnValue('aabbcc');
      vi.spyOn((a as any).layer1, 'computeSimHash').mockReturnValue(0n);
      vi.spyOn((a as any).layer2, 'reprobe').mockResolvedValue(l2);
      vi.spyOn((a as any).layer3, 'replay').mockResolvedValue(l3);
      vi.spyOn((a as any).layer4, 'confirm').mockResolvedValue(l4);
      return a.verify(result);
    }

    it('L1 duplicate → rejected immediately, skips all other layers', async () => {
      const l2spy = vi.fn();
      const a = new VerifierAgent();
      vi.spyOn((a as any).layer1, 'check').mockResolvedValue({ isDuplicate: true, existingHash: 'abc' });
      vi.spyOn((a as any).layer1, 'computeHash').mockReturnValue('abc');
      vi.spyOn((a as any).layer1, 'computeSimHash').mockReturnValue(0n);
      vi.spyOn((a as any).layer2, 'reprobe').mockImplementation(l2spy);
      const vr = await a.verify(makeSolverResult());
      expect(vr.finalVerdict).toBe('deduplicated');
      expect(vr.finalConfidence).toBe(0);
      expect(l2spy).not.toHaveBeenCalled();
    });

    it('HTTP-observable class (cors): L2+L4 confirm → confirmed with +0.05 boost (L3 does not vote)', async () => {
      const result = makeSolverResult({ confidence: 0.6, vulnClass: 'cors' });
      const vr = await runVerify(result);
      expect(vr.finalVerdict).toBe('confirmed');
      // HTTP-observable: l2 && l4 → +0.05 (L3 confirmation no longer boosts)
      expect(vr.finalConfidence).toBeCloseTo(0.65);
    });

    it('HTTP-observable class (cors): L2+L4 confirm with L3 absent → still confirmed (L3 n/a)', async () => {
      const result = makeSolverResult({ confidence: 0.6, vulnClass: 'cors' });
      const vr = await runVerify(result, { l3: l3Rejected });
      expect(vr.finalVerdict).toBe('confirmed');
      // L3 does not vote for HTTP-observable classes, so a rejected L3 is irrelevant.
      expect(vr.finalConfidence).toBeCloseTo(0.65);
    });

    it('L2+L4 confirm but L3 fails mandatory gate (xss) → inconclusive', async () => {
      // xss triggers mustPassBrowser; L3 not confirmed → mandatoryGatePassed = false
      const result = makeSolverResult({ confidence: 0.5, vulnClass: 'xss' });
      const vr = await runVerify(result, { l3: l3Rejected });
      expect(vr.finalVerdict).toBe('inconclusive');
    });

    it('high confidence alone no longer forces a browser gate (cors, conf 0.8) → confirmed', async () => {
      // Post-refactor: the mandatory browser gate is keyed on vuln CLASS
      // (xss/dom_xss), not on a confidence threshold. A high-confidence cors
      // finding is HTTP-observable and confirms on L2+L4.
      const result = makeSolverResult({ confidence: 0.8, vulnClass: 'cors' });
      const vr = await runVerify(result, { l3: l3Rejected });
      expect(vr.finalVerdict).toBe('confirmed');
    });

    it('L2+L3+L4 all confirm with mandatory gate (sqli, L3 confirmed) → confirmed', async () => {
      const result = makeSolverResult({ confidence: 0.5, vulnClass: 'sqli' });
      const vr = await runVerify(result);
      expect(vr.finalVerdict).toBe('confirmed');
    });

    it('HTTP-observable: neither L2 nor L4 confirm → rejected with -0.3 penalty', async () => {
      // Must reject L4 too — for HTTP-observable classes L2 and L4 are the voters
      // (L3 is n/a). A confirming L4 with a rejecting L2 would be "inconclusive".
      const result = makeSolverResult({ confidence: 0.6 });
      const vr = await runVerify(result, { l2: l2Rejected, l3: l3Rejected, l4: l4Rejected });
      expect(vr.finalVerdict).toBe('rejected');
      expect(vr.finalConfidence).toBeLessThan(0.6);
    });

    it('L2 confirms but L3 and L4 do not, no mandatory gate → inconclusive', async () => {
      const result = makeSolverResult({ vulnClass: 'cors', confidence: 0.5 });
      const vr = await runVerify(result, { l3: l3Rejected, l4: l4Rejected });
      // !l2l3Consensus (l3 false), !l2l4Consensus (l4 false), but l2 confirmed → not all-reject → inconclusive
      expect(vr.finalVerdict).toBe('inconclusive');
    });

    it('finalConfidence is always clamped to [0, 1]', async () => {
      // Negative clamp
      const result = makeSolverResult({ confidence: 0.1 });
      const vr = await runVerify(result, {
        l2: l2Rejected,
        l3: l3Rejected,
        l4: { confirmed: false, reasoning: 'nope', confidenceAdjustment: -0.5 },
      });
      expect(vr.finalConfidence).toBeGreaterThanOrEqual(0);

      // Upper clamp
      const result2 = makeSolverResult({ confidence: 0.95 });
      const vr2 = await runVerify(result2, {
        l4: { confirmed: true, reasoning: 'yes', confidenceAdjustment: 0.3 },
      });
      expect(vr2.finalConfidence).toBeLessThanOrEqual(1);
    });

    it('dedupHash in result matches computed hash', async () => {
      const result = makeSolverResult();
      const a = new VerifierAgent();
      vi.spyOn((a as any).layer1, 'check').mockResolvedValue({ isDuplicate: false });
      vi.spyOn((a as any).layer1, 'computeHash').mockReturnValue('deadbeef1234');
      vi.spyOn((a as any).layer1, 'computeSimHash').mockReturnValue(0n);
      vi.spyOn((a as any).layer2, 'reprobe').mockResolvedValue(l2Confirmed);
      vi.spyOn((a as any).layer3, 'replay').mockResolvedValue(l3Confirmed);
      vi.spyOn((a as any).layer4, 'confirm').mockResolvedValue(l4Confirmed);
      const vr = await a.verify(result);
      expect(vr.dedupHash).toBe('deadbeef1234');
    });

    it('rce and ssrf are HTTP-observable now, NOT browser-gated (L2+L4 → confirmed)', async () => {
      // Post-refactor only xss/dom_xss are browser-verifiable. rce/ssrf are
      // confirmed by L2 (live reprobe) + L4, with L3 not voting — so a rejected
      // L3 does not block them.
      for (const vulnClass of ['rce', 'ssrf'] as const) {
        const result = makeSolverResult({ vulnClass, confidence: 0.5 });
        const vr = await runVerify(result, { l3: l3Rejected });
        expect(vr.finalVerdict).toBe('confirmed');
      }
    });
  });

  // ─── rejectedByLayer invariant ─────────────────────────────────────────────
  // rejectedByLayer must be null iff finalVerdict === 'confirmed', and non-null
  // must name a real rejecting mechanism. This is ground truth set at the point
  // computeVerdict() decides — never reconstructed later by diffing .confirmed
  // flags, which would be an inference, not a fact.
  describe('rejectedByLayer invariant', () => {
    async function runVerify(result: SolverResult, {
      l1 = { isDuplicate: false },
      l2 = l2Confirmed,
      l3 = l3Confirmed,
      l4 = l4Confirmed,
    }: { l1?: any; l2?: any; l3?: any; l4?: any } = {}) {
      const a = new VerifierAgent();
      vi.spyOn((a as any).layer1, 'check').mockResolvedValue(l1);
      vi.spyOn((a as any).layer1, 'computeHash').mockReturnValue('aabbcc');
      vi.spyOn((a as any).layer1, 'computeSimHash').mockReturnValue(0n);
      vi.spyOn((a as any).layer2, 'reprobe').mockResolvedValue(l2);
      vi.spyOn((a as any).layer3, 'replay').mockResolvedValue(l3);
      vi.spyOn((a as any).layer4, 'confirm').mockResolvedValue(l4);
      return a.verify(result);
    }

    const VALID_LAYERS = new Set([
      'nonce_echo', 'l3_playwright', 'oob', 'stateful_oracle', 'l2_reprobe', 'l4_ai',
    ]);

    it('holds across representative computeVerdict paths: null iff confirmed, non-null names a real layer', async () => {
      const cases: Array<{ label: string; result: SolverResult; l2?: any; l3?: any; l4?: any }> = [
        { label: 'HTTP-observable confirmed', result: makeSolverResult({ vulnClass: 'cors', confidence: 0.6 }) },
        { label: 'HTTP-observable rejected', result: makeSolverResult({ vulnClass: 'cors' }), l2: l2Rejected, l3: l3Rejected, l4: l4Rejected },
        { label: 'HTTP-observable inconclusive (l2 only)', result: makeSolverResult({ vulnClass: 'cors' }), l3: l3Rejected, l4: l4Rejected },
        { label: 'HTTP-observable inconclusive (l4 only)', result: makeSolverResult({ vulnClass: 'cors' }), l2: l2Rejected, l3: l3Rejected },
        { label: 'browser-gated confirmed (xss, l3 confirms)', result: makeSolverResult({ vulnClass: 'xss', confidence: 0.5 }) },
        { label: 'browser-gated inconclusive (xss, l3 rejects, l4 confirms)', result: makeSolverResult({ vulnClass: 'xss', confidence: 0.5 }), l3: l3Rejected },
        { label: 'browser-gated rejected (xss, l3+l4 reject)', result: makeSolverResult({ vulnClass: 'xss', confidence: 0.5 }), l3: l3Rejected, l4: l4Rejected },
        { label: 'stateful oracle confirmed', result: makeSolverResult({ vulnClass: 'business_logic', toolsUsed: ['logic_exploit_agent'] }) },
        { label: 'stateful oracle inconclusive', result: makeSolverResult({ vulnClass: 'business_logic', toolsUsed: ['logic_exploit_agent'] }), l4: l4Rejected },
      ];

      for (const c of cases) {
        const vr = await runVerify(c.result, { l2: c.l2, l3: c.l3, l4: c.l4 });
        if (vr.finalVerdict === 'confirmed') {
          expect(vr.rejectedByLayer, c.label).toBeNull();
        } else {
          expect(vr.rejectedByLayer, c.label).not.toBeNull();
          expect(VALID_LAYERS.has(vr.rejectedByLayer as string), c.label).toBe(true);
        }
      }
    });

    it('L1 duplicate → rejectedByLayer is null (no oracle voted, L1 short-circuited)', async () => {
      const a = new VerifierAgent();
      vi.spyOn((a as any).layer1, 'check').mockResolvedValue({ isDuplicate: true, existingHash: 'abc' });
      vi.spyOn((a as any).layer1, 'computeHash').mockReturnValue('abc');
      vi.spyOn((a as any).layer1, 'computeSimHash').mockReturnValue(0n);
      const vr = await a.verify(makeSolverResult());
      expect(vr.finalVerdict).toBe('deduplicated');
      expect(vr.rejectedByLayer).toBeNull();
    });

    it('adaptation-retry override (the clean case): flip to confirmed clears rejectedByLayer to null', async () => {
      const lfiResult = makeSolverResult({
        vulnClass: 'lfi',
        endpoint: 'http://target.com/api/files/list?path=../../../../../../etc/passwd',
        request: 'http://target.com/api/files/list?path=../../../../../../etc/passwd',
        payload: '../../../../../../etc/passwd',
        confidence: 0.5,
      });
      const capabilityRealL4 = {
        confirmed: false, reasoning: 'ENOENT proves traversal reached scandir; wrong shape',
        confidenceAdjustment: 0, capabilityConfirmed: true, adaptationRule: 'target_directory_not_file',
      };
      const retryL4Confirmed = { confirmed: true, reasoning: 'directory listing succeeded', confidenceAdjustment: 0.1 };

      const a = new VerifierAgent();
      vi.spyOn((a as any).layer1, 'check').mockResolvedValue({ isDuplicate: false });
      vi.spyOn((a as any).layer1, 'computeHash').mockReturnValue('adapthash-override');
      vi.spyOn((a as any).layer1, 'computeSimHash').mockReturnValue(0n);
      const l2Spy = vi.spyOn((a as any).layer2, 'reprobe');
      l2Spy.mockResolvedValueOnce(l2Rejected).mockResolvedValueOnce(l2Confirmed);
      vi.spyOn((a as any).layer3, 'replay').mockResolvedValue(l3Rejected);
      const l4Spy = vi.spyOn((a as any).layer4, 'confirm');
      l4Spy.mockResolvedValueOnce(capabilityRealL4).mockResolvedValueOnce(retryL4Confirmed);

      // Sanity: the original (pre-retry) pass alone would have been rejected,
      // with rejectedByLayer naming the HTTP-observable authority (l2_reprobe) —
      // confirming there IS a real non-null value in play before the override,
      // so the subsequent null-clear is a genuine flip, not a no-op.
      const preRetryVerdict = (a as any).computeVerdict(
        lfiResult, l2Rejected, l3Rejected, capabilityRealL4, false, false,
      );
      expect(preRetryVerdict.finalVerdict).toBe('rejected');
      expect(preRetryVerdict.rejectedByLayer).toBe('l2_reprobe');

      const vr = await a.verify(lfiResult);
      expect(vr.finalVerdict).toBe('confirmed');
      expect(vr.rejectedByLayer).toBeNull();
    });

    it('l4.errored softening (the subtle case): actively sets rejectedByLayer to l4_ai, never leaves the pre-override value stale', async () => {
      // Pin the EXACT value, not just non-null — a stale value carried over from
      // the pre-override "rejected" verdict would also pass a bare non-null check.
      // The dead L4 backstop is the actual reason this is now inconclusive, so
      // the field must be actively overwritten to name it, not left untouched.
      const result = makeSolverResult({ vulnClass: 'cors', confidence: 0.5 });
      const erroredL4 = { confirmed: false, reasoning: 'model unavailable', confidenceAdjustment: 0, errored: true };

      const a = new VerifierAgent();
      vi.spyOn((a as any).layer1, 'check').mockResolvedValue({ isDuplicate: false });
      vi.spyOn((a as any).layer1, 'computeHash').mockReturnValue('erroredhash');
      vi.spyOn((a as any).layer1, 'computeSimHash').mockReturnValue(0n);
      vi.spyOn((a as any).layer2, 'reprobe').mockResolvedValue(l2Rejected);
      vi.spyOn((a as any).layer3, 'replay').mockResolvedValue(l3Rejected);
      vi.spyOn((a as any).layer4, 'confirm').mockResolvedValue(erroredL4);

      // Sanity: without the l4.errored override, this HTTP-observable path (l2
      // rejects, l4 rejects) would compute rejectedByLayer = 'l2_reprobe' — the
      // stale value the softening override must NOT leave behind.
      const preOverrideVerdict = (a as any).computeVerdict(
        result, l2Rejected, l3Rejected, erroredL4, false, false,
      );
      expect(preOverrideVerdict.finalVerdict).toBe('rejected');
      expect(preOverrideVerdict.rejectedByLayer).toBe('l2_reprobe');

      const vr = await a.verify(result);
      expect(vr.finalVerdict).toBe('inconclusive');
      expect(vr.rejectedByLayer).toBe('l4_ai');
    });
  });

  // ─── Payload-adaptation retry ──────────────────────────────────────────────
  // L4 can signal "capability real, proof payload mechanically wrong" — gated,
  // capped to exactly one retry, and must NEVER fire on a plain rejection.
  describe('Payload-adaptation retry', () => {
    async function runAdaptiveVerify(
      result: SolverResult,
      l4Sequence: any[],
      { l2Sequence, l3 = l3Rejected }: { l2Sequence?: any[]; l3?: any } = {}
    ) {
      const a = new VerifierAgent();
      vi.spyOn((a as any).layer1, 'check').mockResolvedValue({ isDuplicate: false });
      vi.spyOn((a as any).layer1, 'computeHash').mockReturnValue('adapthash');
      vi.spyOn((a as any).layer1, 'computeSimHash').mockReturnValue(0n);
      const l2Spy = vi.spyOn((a as any).layer2, 'reprobe');
      (l2Sequence ?? [l2Rejected, l2Rejected]).forEach(v => l2Spy.mockResolvedValueOnce(v));
      vi.spyOn((a as any).layer3, 'replay').mockResolvedValue(l3);
      const l4Spy = vi.spyOn((a as any).layer4, 'confirm');
      l4Sequence.forEach(v => l4Spy.mockResolvedValueOnce(v));
      return { vr: await a.verify(result), l2Spy, l4Spy };
    }

    const lfiResult = () => makeSolverResult({
      vulnClass: 'lfi',
      endpoint: 'http://target.com/api/files/list?path=../../../../../../etc/passwd',
      request: 'http://target.com/api/files/list?path=../../../../../../etc/passwd',
      payload: '../../../../../../etc/passwd',
      confidence: 0.5,
    });

    it('capability-real signal + known rule → retries with adapted URL and confirms', async () => {
      const capabilityRealL4 = {
        confirmed: false, reasoning: 'ENOENT proves traversal reached scandir; wrong shape',
        confidenceAdjustment: 0, capabilityConfirmed: true, adaptationRule: 'target_directory_not_file',
      };
      const retryL4Confirmed = { confirmed: true, reasoning: 'directory listing succeeded', confidenceAdjustment: 0.1 };

      const { vr, l2Spy, l4Spy } = await runAdaptiveVerify(
        lfiResult(),
        [capabilityRealL4, retryL4Confirmed],
        { l2Sequence: [l2Rejected, l2Confirmed] },
      );

      expect(vr.finalVerdict).toBe('confirmed');
      expect(vr.adaptation?.rule).toBe('target_directory_not_file');
      expect(vr.adaptation?.adaptedUrl).toContain('path=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2F');
      expect(vr.adaptation?.adaptedPayload).toBe('../../../../../../etc/');
      // Exactly one retry: L2/L4 each called at most twice (original + one retry).
      expect(l2Spy).toHaveBeenCalledTimes(2);
      expect(l4Spy).toHaveBeenCalledTimes(2);
    });

    it('capability-real signal but adapted payload also fails → original verdict stands, no churn', async () => {
      const capabilityRealL4 = {
        confirmed: false, reasoning: 'wrong shape', confidenceAdjustment: 0,
        capabilityConfirmed: true, adaptationRule: 'target_directory_not_file',
      };
      const retryL4Rejected = { confirmed: false, reasoning: 'still not proven', confidenceAdjustment: 0 };

      const { vr, l2Spy, l4Spy } = await runAdaptiveVerify(
        lfiResult(),
        [capabilityRealL4, retryL4Rejected],
        { l2Sequence: [l2Rejected, l2Rejected] },
      );

      expect(vr.finalVerdict).toBe('rejected');
      expect(vr.adaptation).toBeUndefined();
      expect(l2Spy).toHaveBeenCalledTimes(2);
      expect(l4Spy).toHaveBeenCalledTimes(2);
    });

    it('no capabilityConfirmed signal → genuinely-not-exploitable finding rejects WITHOUT any retry', async () => {
      const plainRejectedL4 = { confirmed: false, reasoning: 'not a vuln', confidenceAdjustment: -0.2 };

      const { vr, l2Spy, l4Spy } = await runAdaptiveVerify(lfiResult(), [plainRejectedL4]);

      expect(vr.finalVerdict).toBe('rejected');
      expect(vr.adaptation).toBeUndefined();
      // No retry fired — L2/L4 called exactly once each.
      expect(l2Spy).toHaveBeenCalledTimes(1);
      expect(l4Spy).toHaveBeenCalledTimes(1);
    });

    it('capabilityConfirmed true but adaptationRule unknown/null → no retry (no concrete adaptation)', async () => {
      const vagueL4 = {
        confirmed: false, reasoning: 'maybe real, unclear why it failed', confidenceAdjustment: 0,
        capabilityConfirmed: true, adaptationRule: null,
      };
      const { vr, l2Spy, l4Spy } = await runAdaptiveVerify(lfiResult(), [vagueL4]);
      expect(vr.finalVerdict).toBe('rejected');
      expect(vr.adaptation).toBeUndefined();
      expect(l2Spy).toHaveBeenCalledTimes(1);
      expect(l4Spy).toHaveBeenCalledTimes(1);
    });

    it('already-confirmed finding never triggers a retry (only fires when verdict is not confirmed)', async () => {
      const confirmedButFlagged = {
        confirmed: true, reasoning: 'confirmed on first pass', confidenceAdjustment: 0.1,
        capabilityConfirmed: true, adaptationRule: 'target_directory_not_file',
      };
      const { vr, l2Spy, l4Spy } = await runAdaptiveVerify(
        lfiResult(), [confirmedButFlagged], { l2Sequence: [l2Confirmed] },
      );
      expect(vr.finalVerdict).toBe('confirmed');
      expect(vr.adaptation).toBeUndefined();
      expect(l2Spy).toHaveBeenCalledTimes(1);
      expect(l4Spy).toHaveBeenCalledTimes(1);
    });
  });

  // ─── Stateful oracle authority (the root-bug fix) ─────────────────────────
  // Findings discovered by LogicExploitAgent are stateful — a bare L2 GET can't
  // replay them. For these, L2 must NOT vote; authority is L4 over captured proof.
  describe('Stateful oracle authority (discoveryTool)', () => {
    async function verdict(result: SolverResult, layers: { l2: any; l3?: any; l4: any }) {
      const a = new VerifierAgent();
      vi.spyOn((a as any).layer1, 'check').mockResolvedValue({ isDuplicate: false });
      vi.spyOn((a as any).layer1, 'computeHash').mockReturnValue('statefulhash');
      vi.spyOn((a as any).layer1, 'computeSimHash').mockReturnValue(0n);
      vi.spyOn((a as any).layer2, 'reprobe').mockResolvedValue(layers.l2);
      vi.spyOn((a as any).layer3, 'replay').mockResolvedValue(layers.l3 ?? l3Rejected);
      vi.spyOn((a as any).layer4, 'confirm').mockResolvedValue(layers.l4);
      return a.verify(result);
    }

    it('auth_bypass via agent: L2 rejects (bare GET hits 403) but L4 confirms → CONFIRMED', async () => {
      // The false-reject the fix removes: a stateless reprobe of a protected
      // endpoint returns 401/403, which previously sank the verdict. L2 is barred.
      const result = makeSolverResult({
        vulnClass: 'auth_bypass', confidence: 0.6, discoveryTool: 'logic_exploit_agent',
      });
      const vr = await verdict(result, { l2: l2Rejected, l4: l4Confirmed });
      expect(vr.finalVerdict).toBe('confirmed');
    });

    it('idor via agent: L2 confirms (URL returns 200) but L4 dissents → INCONCLUSIVE, not confirmed', async () => {
      // The false-confirm the fix removes: a 200 on the URL proves nothing about
      // cross-account access, so L2's "confirm" must not stand on its own.
      const result = makeSolverResult({
        vulnClass: 'idor', confidence: 0.6, discoveryTool: 'logic_exploit_agent',
      });
      const vr = await verdict(result, { l2: l2Confirmed, l4: l4Rejected });
      expect(vr.finalVerdict).toBe('inconclusive');
    });

    it('business_logic: discovery tool recovered from evidence.tool fallback (Path A) → CONFIRMED', async () => {
      // Path A (orchestrator L5) doesn't set discoveryTool explicitly; the agent
      // ProbeResult in evidence[0] carries .tool, which verify() falls back to.
      const result = makeSolverResult({
        vulnClass: 'business_logic', confidence: 0.6,
        evidence: { tool: 'logic_exploit_agent' },
      });
      const vr = await verdict(result, { l2: l2Rejected, l4: l4Confirmed });
      expect(vr.finalVerdict).toBe('confirmed');
    });

    it('control: same idor WITHOUT the stateful tag is HTTP-observable (L2 reject + L4 confirm → inconclusive)', async () => {
      // Proves the discoveryTool tag is what flips the outcome: a stateless idor
      // with the identical layer votes lands at "inconclusive" (one signal), not
      // "confirmed".
      const result = makeSolverResult({ vulnClass: 'idor', confidence: 0.6 });
      const vr = await verdict(result, { l2: l2Rejected, l4: l4Confirmed });
      expect(vr.finalVerdict).toBe('inconclusive');
    });
  });

  // ─── pendingEscalation: apply-on-confirm gate for post-exploit severity ────
  describe('pendingEscalation', () => {
    it('extracts a stashed impact_escalation from evidence', () => {
      const finding: any = { evidence: [
        { type: 'raw_http', data: 'GET /...' },
        { type: 'impact_escalation', severity: 'critical', cvssScore: 9.1, impact: 'cloud creds read' },
      ] };
      expect(pendingEscalation(finding)).toEqual({
        severity: 'critical', cvssScore: 9.1, impact: 'cloud creds read',
      });
    });

    it('returns null when no escalation entry is present', () => {
      expect(pendingEscalation({ evidence: [{ type: 'raw_http' }] } as any)).toBeNull();
    });

    it('returns null when the escalation entry has empty severity (guard)', () => {
      expect(pendingEscalation({
        evidence: [{ type: 'impact_escalation', severity: '', cvssScore: 9 }],
      } as any)).toBeNull();
    });

    it('returns null when evidence is not an array', () => {
      expect(pendingEscalation({ evidence: null } as any)).toBeNull();
    });
  });
});
