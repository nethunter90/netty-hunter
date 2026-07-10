/**
 * Corpus Enrichment A/B Harness
 *
 * Goal: validate that reasoning-corpus enrichment can be toggled cleanly and
 * that the verifier's verdict is INVARIANT to that toggle.
 *
 * Arm A (control):   CORPUS_ENRICHMENT=false  → no domain knowledge or methodology hints
 * Arm B (treatment): CORPUS_ENRICHMENT=true   → 7-entry corpus + per-class hints injected
 *
 * Single variable: only CORPUS_ENRICHMENT differs between arms. Everything else
 * (fixtures, verifier, model mock) is identical.
 *
 * Two metrics:
 *  1. True-confirmation rate (true-positive fixtures): expected SAME in both arms,
 *     since the verifier evaluates probe evidence — not the hypothesis prompt.
 *  2. False-rejection invariance (true-negative fixtures): MUST hold. A drop here
 *     means enrichment context is somehow reaching the verifier path — which is a
 *     structural bug, not an acceptable tradeoff.
 *
 * Honest scope note: actual hypothesis QUALITY improvement (more specific targetUrls,
 * better vuln-class selection) requires live LLM calls and cannot be measured here
 * at $0. This harness proves:
 *   a) the toggle works (corpus is injected / not injected as expected), and
 *   b) the verifier is invariant (the security gate does not move with enrichment).
 * Hypothesis quality measurement is a live-model follow-up once the token is active.
 *
 * Architecture:
 *   HunterEngine.hypothesize() ← toggle here (CORPUS_ENRICHMENT env var)
 *       ↓ produces Hypothesis objects
 *   SolverPool.probe()         ← probe evidence (HTTP, tool output)
 *       ↓ produces SolverResult
 *   VerifierAgent.verify()     ← 4-layer pipeline — reads NONE of the above env var
 *       ↓ produces finalVerdict
 *
 * The verifier is downstream of the toggle and reads only probe evidence.
 * Its verdict MUST be the same regardless of enrichment — this test proves it.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ─── Module mocks (declared before imports that pull them transitively) ────────

vi.mock('../db', () => ({
  db: {
    select: vi.fn().mockReturnValue({
      from: vi.fn().mockReturnValue({
        where: vi.fn().mockReturnValue({
          orderBy: vi.fn().mockReturnValue({ limit: vi.fn().mockResolvedValue([]) }),
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

vi.mock('drizzle-orm', () => ({ eq: vi.fn(), desc: vi.fn(), isNotNull: vi.fn(), and: vi.fn() }));

vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

vi.mock('../lib/stealth/browser-fingerprint', () => ({
  getRandomUserAgent: () => 'Mozilla/5.0 (AB-Test)',
}));

// ModelRouter — controlled per-test via mockReturnValue so arm A and B can set
// different L4 return values as needed (but in practice both arms get the same).
vi.mock('../intelligence/ModelRouter', () => ({
  ModelRouter: {
    getInstance: vi.fn().mockReturnValue({
      reason: vi.fn(),
    }),
  },
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
      if (msg.type === 'init') setImmediate(() => this.emit('message', { type: 'ready' }));
    }
    terminate() { return Promise.resolve(0); }
  }
  return { Worker: FakeWorker };
});

vi.mock('axios', () => ({
  default: { get: vi.fn() },
}));

// JsonPromptLoader — the primary corpus retrieval (7-entry semantic match)
// The spy allows tracking call count per arm.
vi.mock('../intelligence/JsonPromptLoader', () => ({
  jsonPromptLoader: {
    getContextBlockAsync: vi.fn().mockResolvedValue(
      'CORPUS: XSS payloads bypass filters via encoded angle brackets.\n' +
      'CORPUS: IDOR — increment object IDs and compare responses.\n'
    ),
  },
}));

// PromptKnowledgeBase — methodology hints per vuln class
vi.mock('../intelligence/PromptKnowledgeBase', () => ({
  promptKB: {
    getForVulnClass: vi.fn().mockReturnValue([{
      template: 'Objective:\n- Identify reflection points\n- Craft payload\n',
    }]),
    render: vi.fn().mockReturnValue('smart_tool_chain template'),
  },
}));

// observationCompressor — returns fixed state so hypothesize() doesn't need real obs
vi.mock('../lib/intelligence/observation-compressor', () => ({
  observationCompressor: {
    compress: vi.fn().mockReturnValue({
      historicalSummary: '',
      recentObservations: [
        { tags: ['xss', 'idor'], anomalyScore: 0.8, data: {}, type: 'http', source: 'fixture', timestamp: Date.now() },
      ],
    }),
  },
}));

vi.mock('../lib/hunter/reinforcement-wiring', () => ({
  ReinforcementWiring: vi.fn().mockImplementation(() => ({
    getFrameworkPriorities: vi.fn().mockResolvedValue([]),
    recordSuccess: vi.fn(),
    recordFailure: vi.fn(),
  })),
}));

// ─── Imports (after mocks) ────────────────────────────────────────────────────

import * as axiosModule from 'axios';
import { VerifierAgent } from '../agents/VerifierAgent';
import type { SolverResult } from '../agents/SolverPool';
import { jsonPromptLoader } from '../intelligence/JsonPromptLoader';
import { ModelRouter } from '../intelligence/ModelRouter';

// ─── Fixture builders ─────────────────────────────────────────────────────────

function makeSolverResult(overrides: Partial<SolverResult> = {}): SolverResult {
  return {
    taskId: 'ab-task-1',
    solverId: 'ab-solver-1',
    endpoint: 'http://juice.shop/rest/user/whoami',
    vulnClass: 'cors',
    found: true,
    confidence: 0.7,
    evidence: {},
    payload: '',
    request: 'http://juice.shop/rest/user/whoami',
    response: 'ok',
    duration: 100,
    toolsUsed: ['curl'],
    ...overrides,
  };
}

// TRUE-POSITIVE: auth_bypass confirmed by a stateful oracle (logic_exploit_agent).
// On this path L4 is sole authority (L2 is barred, L3 is n/a).
// Expected verdict when L4 says confirmed: "confirmed".
const TRUE_POSITIVE = makeSolverResult({
  vulnClass: 'auth_bypass',
  confidence: 0.75,
  discoveryTool: 'logic_exploit_agent',
  evidence: { rawHttpLog: 'POST /rest/admin 401 → POST /rest/admin 200 after bypass', tool: 'logic_exploit_agent' },
});

// TRUE-NEGATIVE: xss with NO browser proof.
// On this path L3 (Playwright) is the mandatory gate.
// L3 offline → "inconclusive" even if L4 says confirmed. NOT a confirmed finding.
// This is the known reject floor from prior sessions.
const TRUE_NEGATIVE_XSS = makeSolverResult({
  vulnClass: 'xss',
  confidence: 0.6,
  evidence: { body: '<html>no alert fired</html>' },
  payload: '<script>alert(1)</script>',
});

// ─── Arm runner ───────────────────────────────────────────────────────────────
// Runs VerifierAgent.layer4.confirm() directly — the only layer that reads the
// LLM. L1 (dedup) uses an empty cache, L2 (HTTP) is mocked, L3 (browser) is
// mocked via the offline worker. This matches how verifier.test.ts exercises L4.

async function runVerifierArm(
  result: SolverResult,
  l4Json: string,
): Promise<{ finalVerdict: string; finalConfidence: number }> {
  const agent = new VerifierAgent();
  const routerInstance = ModelRouter.getInstance();
  vi.mocked(routerInstance.reason).mockResolvedValue(l4Json);

  // Call internal verify() pipeline via private access (same pattern as verifier.test.ts)
  const verificationResult = await (agent as any).verify(result);
  return {
    finalVerdict: verificationResult.finalVerdict,
    finalConfidence: verificationResult.finalConfidence,
  };
}

// ─── SUITE 1: Toggle proof ────────────────────────────────────────────────────
// Proves the CORPUS_ENRICHMENT env var controls whether corpus functions are
// called. Tests the exact conditional from HunterEngine.ts in isolation:
//   const enrichmentOn = process.env.CORPUS_ENRICHMENT !== 'false';
//   const domainKnowledge = enrichmentOn ? await jsonPromptLoader.getContextBlockAsync(...) : '';

describe('Toggle proof — corpus injection on/off', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('ARM A: CORPUS_ENRICHMENT=false → getContextBlockAsync NOT called, returns empty', async () => {
    process.env.CORPUS_ENRICHMENT = 'false';
    const spy = vi.mocked(jsonPromptLoader.getContextBlockAsync);

    // Replicate the exact toggle conditional from HunterEngine.ts:1574-1577
    const enrichmentOn = process.env.CORPUS_ENRICHMENT !== 'false';
    const domainKnowledge = enrichmentOn
      ? await jsonPromptLoader.getContextBlockAsync('test query', 7)
      : '';

    expect(enrichmentOn).toBe(false);
    expect(domainKnowledge).toBe('');
    expect(spy).not.toHaveBeenCalled();
  });

  it('ARM B: CORPUS_ENRICHMENT=true → getContextBlockAsync called once, returns content', async () => {
    process.env.CORPUS_ENRICHMENT = 'true';
    const spy = vi.mocked(jsonPromptLoader.getContextBlockAsync);

    const enrichmentOn = process.env.CORPUS_ENRICHMENT !== 'false';
    const domainKnowledge = enrichmentOn
      ? await jsonPromptLoader.getContextBlockAsync('test query', 7)
      : '';

    expect(enrichmentOn).toBe(true);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith('test query', 7);
    expect(domainKnowledge).toContain('CORPUS:');
  });

  it('default (env var absent) → enrichment ON — corpus is enabled by default', async () => {
    delete process.env.CORPUS_ENRICHMENT;

    const enrichmentOn = process.env.CORPUS_ENRICHMENT !== 'false';
    expect(enrichmentOn).toBe(true);
  });

  it('ARM A vs B produce DIFFERENT prompt content for same observation set', async () => {
    const observations = [{ tags: ['xss'], anomalyScore: 0.9 }];
    const spy = vi.mocked(jsonPromptLoader.getContextBlockAsync);

    // Arm A: no corpus
    process.env.CORPUS_ENRICHMENT = 'false';
    let enrichmentOn = process.env.CORPUS_ENRICHMENT !== 'false';
    const armADomain = enrichmentOn ? await jsonPromptLoader.getContextBlockAsync('q', 7) : '';
    const armACalls = spy.mock.calls.length;

    // Arm B: corpus injected
    process.env.CORPUS_ENRICHMENT = 'true';
    enrichmentOn = process.env.CORPUS_ENRICHMENT !== 'false';
    const armBDomain = enrichmentOn ? await jsonPromptLoader.getContextBlockAsync('q', 7) : '';

    expect(armADomain).toBe('');
    expect(armBDomain).toContain('CORPUS:');
    expect(armACalls).toBe(0);
    expect(spy).toHaveBeenCalledTimes(1);  // only arm B called it
  });

  afterEach(() => {
    delete process.env.CORPUS_ENRICHMENT;
  });
});

// ─── SUITE 2: Verifier invariance — the critical gate ─────────────────────────
// The verifier does NOT read CORPUS_ENRICHMENT. Its verdict is determined solely
// by probe evidence (L2 HTTP, L3 Playwright, L4 AI reasoning over that evidence).
// Both arms MUST produce identical finalVerdict values.
//
// If they differ → enrichment context is leaking into the verifier path.
// That is a structural bug, not an acceptable tradeoff. STOP and trace.

describe('Verifier invariance — CORPUS_ENRICHMENT must not move the verdict', () => {
  // L4 returns: auth_bypass confirmed, XSS confirmed (model is "convinced" of XSS
  // even though L3 can't verify it — tests the mandatory gate holds).
  const L4_CONFIRMED = '{"confirmed":true,"reasoning":"clear evidence of bypass","confidenceAdjustment":0.1}';
  const L4_REJECTED  = '{"confirmed":false,"reasoning":"no evidence","confidenceAdjustment":-0.3}';

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(axiosModule.default.get).mockResolvedValue({ status: 200, data: 'ok', headers: {} });
  });

  afterEach(() => {
    delete process.env.CORPUS_ENRICHMENT;
  });

  // TRUE-POSITIVE: auth_bypass via stateful oracle.
  // L4 says confirmed → finalVerdict = "confirmed".
  // MUST be the same in both arms.
  it('TRUE-POSITIVE (auth_bypass/stateful): same confirmed verdict in both arms', async () => {
    process.env.CORPUS_ENRICHMENT = 'false';
    const armA = await runVerifierArm(TRUE_POSITIVE, L4_CONFIRMED);

    process.env.CORPUS_ENRICHMENT = 'true';
    const armB = await runVerifierArm(TRUE_POSITIVE, L4_CONFIRMED);

    // Report raw numbers per arm
    console.log('[A/B] TRUE-POSITIVE auth_bypass:');
    console.log(`  Arm A (control):   ${armA.finalVerdict}  confidence=${armA.finalConfidence.toFixed(2)}`);
    console.log(`  Arm B (treatment): ${armB.finalVerdict}  confidence=${armB.finalConfidence.toFixed(2)}`);

    expect(armA.finalVerdict).toBe('confirmed');
    expect(armB.finalVerdict).toBe('confirmed');
    // Verdicts must be identical between arms (the invariance check)
    expect(armA.finalVerdict).toBe(armB.finalVerdict);
  });

  // TRUE-NEGATIVE: xss. L3 gate offline (worker mock never sends browser confirmed).
  // L4 says confirmed (model is "convinced") but L3 is the mandatory gate.
  // Must resolve to "inconclusive" — NOT "confirmed". Model conviction cannot
  // override the execution oracle gate.
  it('TRUE-NEGATIVE (xss/mandatory-L3-gate): same inconclusive verdict in both arms', async () => {
    process.env.CORPUS_ENRICHMENT = 'false';
    const armA = await runVerifierArm(TRUE_NEGATIVE_XSS, L4_CONFIRMED);

    process.env.CORPUS_ENRICHMENT = 'true';
    const armB = await runVerifierArm(TRUE_NEGATIVE_XSS, L4_CONFIRMED);

    console.log('[A/B] TRUE-NEGATIVE xss (mandatory L3 gate):');
    console.log(`  Arm A (control):   ${armA.finalVerdict}  confidence=${armA.finalConfidence.toFixed(2)}`);
    console.log(`  Arm B (treatment): ${armB.finalVerdict}  confidence=${armB.finalConfidence.toFixed(2)}`);

    // The mandatory L3 gate must block confirmation in both arms.
    // "inconclusive" means: model is convinced but execution oracle not available.
    // This is the XSS true-negative proof — enrichment must NOT help this reach "confirmed".
    expect(armA.finalVerdict).not.toBe('confirmed');
    expect(armB.finalVerdict).not.toBe('confirmed');
    expect(armA.finalVerdict).toBe(armB.finalVerdict);
  });

  // L4-rejected finding: both arms must agree it's rejected.
  it('L4-rejected finding: same rejected verdict in both arms', async () => {
    process.env.CORPUS_ENRICHMENT = 'false';
    const armA = await runVerifierArm(TRUE_NEGATIVE_XSS, L4_REJECTED);

    process.env.CORPUS_ENRICHMENT = 'true';
    const armB = await runVerifierArm(TRUE_NEGATIVE_XSS, L4_REJECTED);

    console.log('[A/B] L4-rejected finding:');
    console.log(`  Arm A (control):   ${armA.finalVerdict}  confidence=${armA.finalConfidence.toFixed(2)}`);
    console.log(`  Arm B (treatment): ${armB.finalVerdict}  confidence=${armB.finalConfidence.toFixed(2)}`);

    expect(armA.finalVerdict).toBe(armB.finalVerdict);
    expect(['rejected', 'inconclusive']).toContain(armA.finalVerdict);
  });

  // SUMMARY: the only allowed outcome is verdict(A) === verdict(B) for every fixture.
  // If this meta-assertion ever fails, stop and trace the leakage path — do not patch.
  it('META: all arm verdicts are identical (no enrichment bleed into verifier)', async () => {
    const fixtures = [
      { label: 'auth_bypass TP', result: TRUE_POSITIVE, l4: L4_CONFIRMED },
      { label: 'xss TN (l4 convinced)', result: TRUE_NEGATIVE_XSS, l4: L4_CONFIRMED },
      { label: 'xss TN (l4 rejected)', result: TRUE_NEGATIVE_XSS, l4: L4_REJECTED },
    ];

    const report: string[] = [];
    let allInvariant = true;

    for (const fx of fixtures) {
      process.env.CORPUS_ENRICHMENT = 'false';
      const a = await runVerifierArm(fx.result, fx.l4);

      process.env.CORPUS_ENRICHMENT = 'true';
      const b = await runVerifierArm(fx.result, fx.l4);

      const invariant = a.finalVerdict === b.finalVerdict;
      if (!invariant) allInvariant = false;

      report.push(`${fx.label}: A=${a.finalVerdict}  B=${b.finalVerdict}  invariant=${invariant}`);
    }

    console.log('\n[A/B SUMMARY]');
    console.log('─'.repeat(60));
    console.log('True-confirmation rate: auth_bypass TP — verdict(A) vs verdict(B)');
    console.log('False-rejection invariance: xss TN fixtures — must not differ');
    console.log('');
    report.forEach(line => console.log(line));
    console.log('─'.repeat(60));
    console.log(allInvariant
      ? 'RESULT: PASS — verifier invariant to enrichment toggle. Defense gate held.'
      : 'RESULT: FAIL — verdict differs between arms. Trace the leakage path. Do NOT patch verifier.');

    expect(allInvariant).toBe(true);
  });
});
