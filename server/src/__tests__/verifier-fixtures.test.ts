/**
 * Verifier golden-run fixtures (2026-06-19).
 *
 * These replay the verifier with FIXED inputs derived from the golden hunt
 * (Juice Shop :3050, backward mode, 3 confirmed findings). They are fully
 * deterministic — no live LLM/network/Playwright calls — and run in seconds.
 *
 * Regression contract:
 *   stateful_authbypass_jwt_session → confirmed   (CORE guard)
 *   xss_reflects_not_executes       → rejected    (browser gate contract)
 *   duplicate_finding               → deduplicated (dedup contract)
 *   stateful_l4_dissent_control     → inconclusive (never auto-reject a stateful finding)
 *
 * Mutation check (inline): stripping discoveryTool from the jwt_session fixture
 * MUST degrade the verdict from confirmed → inconclusive, proving the stateful
 * branch is doing the work (not the L4 mock alone).
 */
import { describe, it, expect, vi, afterEach } from 'vitest';

// ─── Module mocks (must be before any imports that trigger them) ──────────────

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
      reason: vi.fn().mockResolvedValue(
        '{"confirmed":true,"reasoning":"golden-run default","confidenceAdjustment":0}'
      ),
    }),
  },
}));

vi.mock('../lib/claude-client', () => ({
  ClaudeClient: { clearSession: vi.fn() },
}));

vi.mock('../governance', () => ({
  promptInjectionDetector: {
    detect: vi.fn().mockReturnValue({ safe: true, score: 0, reasons: [] }),
  },
}));

vi.mock('worker_threads', () => {
  const EventEmitter = require('events');
  class FakeWorker extends EventEmitter {
    postMessage(msg: any) {
      if (msg.type === 'init') {
        setImmediate(() => this.emit('message', { type: 'ready' }));
      }
    }
    terminate() { return Promise.resolve(); }
  }
  return { Worker: FakeWorker };
});

vi.mock('axios', () => ({ default: { get: vi.fn() } }));

// ─── Imports (after mocks) ────────────────────────────────────────────────────

import { VerifierAgent } from '../agents/VerifierAgent';
import type { SolverResult } from '../agents/SolverPool';

// ─── Frozen fixture data (captured from the 2026-06-19 golden run) ────────────

// rawHttpLog excerpt from finding 251 — SQLi auth bypass + admin config.
// Captures the 3-step stateful session: SQLi POST → admin JWT issued → admin
// config endpoint accessed unauthenticated.
const JWT_SESSION_RAW_HTTP_LOG = `\
=== VULNERABILITY CHAIN: SQLi AUTH BYPASS + UNAUTHENTICATED ADMIN CONFIG ===

--- STEP 1: SQLi Authentication Bypass (CONFIRMED) ---
REQUEST: POST /rest/user/login
BODY: {"email": "' OR 1=1--", "password": "anything"}
RESPONSE HTTP 200:
{
  "authentication": {
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiJ9fQ...",
    "umail": "admin@juice-sh.op"
  }
}
DECODED JWT PAYLOAD: {"id":1,"email":"admin@juice-sh.op","password":"0192023a7bbd73250516f069df18b500","role":"admin"}
→ MD5 hash 0192023a7bbd73250516f069df18b500 = "admin123" (trivially crackable)
→ JWT payload LEAKS the password hash inside the token itself

--- STEP 2: Unauthenticated Admin Config Endpoint (CONFIRMED) ---
REQUEST (NO auth header): GET /rest/admin/application-configuration
RESPONSE HEADERS: HTTP 200, access-control-allow-origin: *, content-length: 21730
RESPONSE BODY (excerpt):
{"config":{"server":{"port":3000,"baseUrl":"http://localhost:3000"},"application":{...},
"googleOauth":{"clientId":"1005568560502-6hm16lef8oh46hr2d98vf2ohlnj4nfhq.apps.googleusercontent.com"}}}

SAME ETag for unauthenticated, authenticated, and cross-origin requests — NO auth check whatsoever.

--- STEP 3: Cross-Origin Read Confirmed ---
REQUEST with Origin: https://evil.example.com
RESPONSE: access-control-allow-origin: * — config fully readable cross-origin`;

// rawHttpLog excerpt from finding 250 — multi-step credential chain.
const CREDENTIAL_CHAIN_RAW_HTTP_LOG = `\
CHAIN LINK 1 (SQLi dump):
  Response body snippet: {"id":1,"name":"admin@juice-sh.op","description":"0192023a7bbd73250516f069df18b500","price":4,...}
  All users dumped including: jim@juice-sh.op, bender@juice-sh.op, bjoern.kimminich@gmail.com

CHAIN LINK 2 (Hash cracked):
  MD5("admin123") = 0192023a7bbd73250516f069df18b500 — exact match confirmed; no salt used

CHAIN LINK 3 (Admin JWT issued):
  POST /rest/user/login → HTTP 200
  {"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...","bid":1,"umail":"admin@juice-sh.op"}}
  JWT payload: {"status":"success","data":{"id":1,"role":"admin","email":"admin@juice-sh.op","password":"0192023a7bbd73250516f069df18b500",...}}

CHAIN LINK 4 (Privileged endpoint accessed):
  GET /rest/admin/application-configuration → HTTP 200
  Full internal configuration exposed — complete admin privilege confirmed.`;

// ─── Fixture SolverResult builders ───────────────────────────────────────────

function makeStatefulAuthBypass(rawHttpLog: string, taskId = 'f-251'): SolverResult {
  return {
    taskId,
    solverId: 'logic_exploit_agent',
    endpoint: 'http://localhost:3050/rest/admin/application-configuration',
    vulnClass: 'auth_bypass',
    found: true,
    confidence: 0.95,
    evidence: {
      tool: 'logic_exploit_agent',
      rawHttpLog,
      output: rawHttpLog.slice(0, 400),
    },
    payload: "' OR 1=1--",
    request: 'http://localhost:3050/rest/user/login',
    response: '{"authentication":{"token":"eyJ0eXAi...","umail":"admin@juice-sh.op"}}',
    duration: 12000,
    toolsUsed: ['playwright'],
    discoveryTool: 'logic_exploit_agent',
  };
}

function makeXssReflectsNotExecutes(taskId = 'f-xss'): SolverResult {
  return {
    taskId,
    solverId: 'ffuf_probe',
    endpoint: 'http://localhost:3050/search?q=<script>alert(1)</script>',
    vulnClass: 'xss',
    found: true,
    confidence: 0.6,
    evidence: { responseBody: 'search results for <script>alert(1)</script> — shown as text' },
    payload: '<script>alert(1)</script>',
    request: 'http://localhost:3050/search?q=<script>alert(1)</script>',
    response: 'search results for <script>alert(1)</script>',
    duration: 300,
    toolsUsed: ['curl'],
  };
}

function makeDuplicateFinding(taskId = 'f-dup'): SolverResult {
  return {
    taskId,
    solverId: 'solver-1',
    endpoint: 'http://localhost:3050/rest/admin/application-configuration',
    vulnClass: 'auth_bypass',
    found: true,
    confidence: 0.8,
    evidence: {},
    payload: "' OR 1=1--",
    request: 'http://localhost:3050/rest/user/login',
    response: 'ok',
    duration: 500,
    toolsUsed: ['curl'],
    discoveryTool: 'logic_exploit_agent',
  };
}

// ─── Layer mock presets ───────────────────────────────────────────────────────

const L2_REJECTED_403 = { confirmed: false, statusCode: 403, responseSnippet: 'Unauthorized' };
const L2_CONFIRMED_200 = { confirmed: true, statusCode: 200, responseSnippet: 'ok' };
const L3_NOT_EXECUTED = { confirmed: false, consoleAlerts: [], networkRequests: [] };
const L4_CONFIRMED = { confirmed: true, reasoning: 'stateful evidence proves auth bypass', confidenceAdjustment: 0 };
const L4_REJECTED = { confirmed: false, reasoning: 'insufficient evidence', confidenceAdjustment: -0.2 };

// ─── Helper: run verify() with mocked layers ─────────────────────────────────

async function runFixture(
  result: SolverResult,
  opts: {
    l1?: { isDuplicate: boolean; existingHash?: string };
    l2?: typeof L2_REJECTED_403;
    l3?: typeof L3_NOT_EXECUTED;
    l4?: typeof L4_CONFIRMED;
  } = {}
) {
  const {
    l1 = { isDuplicate: false },
    l2 = L2_REJECTED_403,
    l3 = L3_NOT_EXECUTED,
    l4 = L4_CONFIRMED,
  } = opts;

  const agent = new VerifierAgent();
  vi.spyOn((agent as any).layer1, 'check').mockResolvedValue(l1);
  vi.spyOn((agent as any).layer1, 'computeHash').mockReturnValue('fixture-hash-' + result.taskId);
  vi.spyOn((agent as any).layer1, 'computeSimHash').mockReturnValue(0n);
  vi.spyOn((agent as any).layer2, 'reprobe').mockResolvedValue(l2);
  vi.spyOn((agent as any).layer3, 'replay').mockResolvedValue(l3);
  vi.spyOn((agent as any).layer4, 'confirm').mockResolvedValue(l4);
  return agent.verify(result);
}

// ─── Fixtures ─────────────────────────────────────────────────────────────────

describe('Verifier golden-run fixtures', () => {
  afterEach(() => { vi.clearAllMocks(); });

  // ── FIXTURE 1: stateful_authbypass_jwt_session (CORE REGRESSION GUARD) ─────
  //
  // The golden run's finding 251: SQLi auth bypass → admin JWT → unauthenticated
  // admin config access. L2 (bare GET to admin endpoint) returns 403 — that is
  // structurally CORRECT for a protected endpoint — but the stateful oracle already
  // proved bypass inside a real browser session. L4 receives the captured HTTP log
  // and confirms. The stateful branch must deliver "confirmed".
  describe('stateful_authbypass_jwt_session (finding #251 shape)', () => {
    it('MUST verdict confirmed: L2 rejects (403 on protected endpoint), L4 confirms over captured HTTP log', async () => {
      const result = makeStatefulAuthBypass(JWT_SESSION_RAW_HTTP_LOG);
      const vr = await runFixture(result, { l2: L2_REJECTED_403, l4: L4_CONFIRMED });
      expect(vr.finalVerdict).toBe('confirmed');
    });

    it('MUST confidence ≥ 0.9: stateful confirmed gets +0.05 boost, never capped below golden baseline', async () => {
      const result = makeStatefulAuthBypass(JWT_SESSION_RAW_HTTP_LOG);
      const vr = await runFixture(result, { l2: L2_REJECTED_403, l4: L4_CONFIRMED });
      // 0.95 (original) + 0 (L4 adj) + 0.05 (stateful boost) = 1.0 → capped at 0.95
      expect(vr.finalConfidence).toBeGreaterThanOrEqual(0.9);
      expect(vr.finalConfidence).toBeLessThanOrEqual(0.95);
    });

    // ── Mutation check: stateful branch is doing the work ──────────────────
    // Strip discoveryTool so the finding falls to the HTTP-observable path.
    // L2 rejects (403) + L4 confirms → inconclusive, NOT confirmed.
    // If this test stays green after the stateful branch is removed, the
    // fixture is not guarding anything.
    it('MUTATION GUARD: strip discoveryTool → verdict degrades to inconclusive (L2 barred lifted)', async () => {
      const result = makeStatefulAuthBypass(JWT_SESSION_RAW_HTTP_LOG);
      // Remove the stateful tag — simulates the branch being disabled
      const mutated: SolverResult = { ...result, discoveryTool: undefined, evidence: {} };
      const vr = await runFixture(mutated, { l2: L2_REJECTED_403, l4: L4_CONFIRMED });
      // Without stateful tag: HTTP-observable path, L2 rejected → at best inconclusive
      expect(vr.finalVerdict).not.toBe('confirmed');
      expect(vr.finalVerdict).toBe('inconclusive');
    });
  });

  // ── FIXTURE 2: stateful_credential_chain (finding #250 shape) ──────────────
  //
  // Multi-step credential chain: SQLi user dump → offline hash crack → admin login.
  // Same stateful oracle authority as #251 but via evidence.tool fallback (no
  // top-level discoveryTool) — tests the Path A recovery code in verify().
  describe('stateful_credential_chain — evidence.tool fallback (finding #250 shape)', () => {
    it('MUST verdict confirmed via evidence.tool fallback when discoveryTool not set', async () => {
      const result: SolverResult = {
        taskId: 'f-250',
        solverId: 'logic_exploit_agent',
        endpoint: 'http://localhost:3050/rest/user/login',
        vulnClass: 'auth_bypass',
        found: true,
        confidence: 0.95,
        // evidence carries .tool but top-level discoveryTool is absent (Path A)
        evidence: {
          tool: 'logic_exploit_agent',
          rawHttpLog: CREDENTIAL_CHAIN_RAW_HTTP_LOG,
          output: 'Multi-step credential chain confirmed admin access',
        },
        payload: 'SQLi dump → MD5 crack → admin123 login',
        request: 'http://localhost:3050/rest/user/login',
        response: '{"authentication":{"token":"eyJ0eXAi...","umail":"admin@juice-sh.op"}}',
        duration: 15000,
        toolsUsed: ['playwright'],
        // discoveryTool intentionally absent — verify() must fall back to evidence.tool
      };
      const vr = await runFixture(result, { l2: L2_REJECTED_403, l4: L4_CONFIRMED });
      expect(vr.finalVerdict).toBe('confirmed');
    });
  });

  // ── FIXTURE 3: xss_reflects_not_executes ───────────────────────────────────
  //
  // XSS that reflects in the response body (L2 confirmed) but the browser
  // never executes it (L3 false). L4 also dissents (no execution proof).
  // The browser gate must hold: only L3 execution → confirmed for XSS.
  // If a future L4-prompt change loosens this, L3 false must still block.
  describe('xss_reflects_not_executes', () => {
    it('MUST verdict rejected: XSS reflects in body (L2 true) but browser gate not passed (L3 false, L4 false)', async () => {
      const result = makeXssReflectsNotExecutes();
      const vr = await runFixture(result, {
        l2: L2_CONFIRMED_200,   // payload appears in response (reflection confirmed)
        l3: L3_NOT_EXECUTED,    // browser did not execute the script
        l4: L4_REJECTED,        // L4 also dissents: no execution proof
      });
      expect(vr.finalVerdict).toBe('rejected');
    });

    it('if L4 loosens (says confirmed) but L3 still false → inconclusive, never confirmed', async () => {
      // Guards against a prompt change that makes L4 always say "yes" for XSS.
      // Without L3 execution, XSS can only be inconclusive — the mandatory gate
      // cannot be bypassed by L4 alone.
      const result = makeXssReflectsNotExecutes();
      const vr = await runFixture(result, {
        l2: L2_CONFIRMED_200,
        l3: L3_NOT_EXECUTED,
        l4: L4_CONFIRMED,       // L4 says yes — must not override the mandatory gate
      });
      expect(vr.finalVerdict).toBe('inconclusive');
      expect(vr.finalVerdict).not.toBe('confirmed');
    });
  });

  // ── FIXTURE 4: duplicate_finding ───────────────────────────────────────────
  //
  // L1 sees a duplicate hash and short-circuits. All other layers must be skipped.
  describe('duplicate_finding', () => {
    it('MUST verdict deduplicated: L1 hit → all other layers skipped, confidence 0', async () => {
      const result = makeDuplicateFinding();
      const agent = new VerifierAgent();
      const l2spy = vi.fn();
      vi.spyOn((agent as any).layer1, 'check').mockResolvedValue({ isDuplicate: true, existingHash: 'known-hash-abc' });
      vi.spyOn((agent as any).layer1, 'computeHash').mockReturnValue('known-hash-abc');
      vi.spyOn((agent as any).layer1, 'computeSimHash').mockReturnValue(0n);
      vi.spyOn((agent as any).layer2, 'reprobe').mockImplementation(l2spy);
      const vr = await agent.verify(result);
      expect(vr.finalVerdict).toBe('deduplicated');
      expect(vr.finalConfidence).toBe(0);
      expect(l2spy).not.toHaveBeenCalled();
    });
  });

  // ── FIXTURE 5: stateful_l4_dissent_control ─────────────────────────────────
  //
  // Same stateful input as fixture 1 but L4 dissents (returns false). The
  // stateful oracle proved it — a stateless L4 failure must never auto-reject.
  // Verdict must be inconclusive (needs human review), never rejected.
  describe('stateful_l4_dissent_control', () => {
    it('MUST verdict inconclusive: stateful oracle proved it but L4 dissents → needs review, not auto-rejected', async () => {
      const result = makeStatefulAuthBypass(JWT_SESSION_RAW_HTTP_LOG, 'f-251-control');
      const vr = await runFixture(result, { l2: L2_REJECTED_403, l4: L4_REJECTED });
      expect(vr.finalVerdict).toBe('inconclusive');
      expect(vr.finalVerdict).not.toBe('rejected');
    });

    it('MUST verdict inconclusive even when L4 errors: dead L4 on a stateful finding is not a refutation', async () => {
      const result = makeStatefulAuthBypass(JWT_SESSION_RAW_HTTP_LOG, 'f-251-control-err');
      const l4Errored = { confirmed: false, reasoning: 'L4 unavailable', confidenceAdjustment: 0, errored: true };
      const vr = await runFixture(result, { l2: L2_REJECTED_403, l4: l4Errored });
      expect(vr.finalVerdict).toBe('inconclusive');
      expect(vr.finalVerdict).not.toBe('rejected');
    });
  });
});
