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
  findings: { dedupHash: 'dedupHash', createdAt: 'createdAt', id: 'id' },
  huntSessions: { id: 'id', sessionUuid: 'sessionUuid' },
}));

vi.mock('drizzle-orm', () => ({
  eq: vi.fn(),
  desc: vi.fn(),
  isNotNull: vi.fn(),
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

    it('returns isDuplicate=false and adds to cache for a novel finding', async () => {
      const l1 = (agent as any).layer1;
      const result = makeSolverResult({ taskId: 'novel-finding-999' });
      const hash = l1.computeHash(result);
      const simhash = l1.computeSimHash(result);
      const check = await l1.check(hash, simhash);
      expect(check.isDuplicate).toBe(false);
      expect(l1.hashCache.has(hash)).toBe(true);
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
