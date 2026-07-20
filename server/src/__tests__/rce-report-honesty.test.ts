/**
 * RCE report-honesty tests (handoff Task 2c).
 *
 * Verifies both halves of Gate 2's honesty requirement using the REAL
 * Layer2Reprobe nonce-echo oracle (exported from VerifierAgent.ts) against
 * real local routes — same positive/negative pair as
 * scripts/gate2-rce-oracle-harness.ts, now as an automated regression test
 * wired through the actual DraftReportGenerator:
 *
 *   1. Confirm-half honesty: a report built from a genuinely confirmed rce
 *      finding cites the real oracle facts (param/payload/executed output,
 *      privilege if present) and NEVER contains an over-claim phrase ("full
 *      compromise", "root access", etc.) — even when the AI content
 *      generation is mocked to try to say one.
 *   2. Veto-path invariant: calling generate() with a non-confirmed
 *      finalVerdict (the /reflect refusal shape) must throw and produce NO
 *      report at all — not a low-confidence one, not a "possible" note.
 */
import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import express from "express";
import type { Server } from "http";
import { exec } from "child_process";

vi.mock("../middleware/scopeGuard", () => ({
  ScopeGuard: {
    getInstance: vi.fn().mockReturnValue({
      isInScope: vi.fn().mockResolvedValue({ allowed: true }),
    }),
  },
}));

vi.mock("../utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}));

// Mocked so the test doesn't depend on a live Claude/Ollama call. Configurable
// per-test via mockGenerate.mockResolvedValueOnce(...). vi.hoisted() is
// required here — vi.mock factories are hoisted above top-level const
// declarations, so a plain `const mockGenerate = vi.fn()` referenced inside
// the factory below would throw a TDZ ReferenceError at import time.
const { mockGenerate } = vi.hoisted(() => ({ mockGenerate: vi.fn() }));
vi.mock("../intelligence/ModelRouter", () => ({
  ModelRouter: {
    getInstance: vi.fn().mockReturnValue({ generate: mockGenerate }),
  },
}));

import { Layer2Reprobe } from "../agents/VerifierAgent";
import type { VerificationResult } from "../agents/VerifierAgent";
import type { SolverResult } from "../agents/SolverPool";
import { DraftReportGenerator } from "../intelligence/ReportGenerator";

const PORT = 48174;
let server: Server;

beforeAll(async () => {
  const app = express();

  // Genuinely vulnerable — same pattern as gate2-rce-oracle-harness.ts.
  app.get("/vuln", (req, res) => {
    const cmd = String(req.query.cmd ?? "");
    exec(`echo start ${cmd} end`, (_err, stdout, stderr) => {
      res.send(`<html><body>Result: ${stdout}${stderr}</body></html>`);
    });
  });

  // Decoy: reflects raw input, executes nothing.
  app.get("/reflect", (req, res) => {
    const cmd = String(req.query.cmd ?? "");
    res.send(`<html><body>You searched for: ${cmd}</body></html>`);
  });

  await new Promise<void>(resolve => { server = app.listen(PORT, resolve); });
});

afterAll(() => new Promise<void>(resolve => server.close(() => resolve())));

function makeResult(endpoint: string): SolverResult {
  return {
    taskId: "rce-honesty-test", solverId: "test", endpoint, vulnClass: "rce",
    found: true, confidence: 0.5, evidence: {}, payload: "", request: endpoint,
    response: "", duration: 0, toolsUsed: [],
  };
}

const RCE_OVERCLAIM_PHRASES = ["full compromise", "full server compromise", "root access", "full rce"];

describe("RCE report honesty (handoff 2c)", () => {
  it("confirm-half: cites real oracle facts (param/payload/output) and strips an over-claim even when the AI tries to state one", async () => {
    const layer2 = new Layer2Reprobe();
    const finding = makeResult(`http://localhost:${PORT}/vuln?cmd=test`);
    const l2 = await layer2.reprobe(finding);
    expect(l2.confirmed).toBe(true); // sanity — this is the same oracle proven in Gate 2

    const verification: VerificationResult = {
      findingId: finding.taskId,
      layer1_dedup: { isDuplicate: false } as unknown as VerificationResult["layer1_dedup"],
      layer2_reprobe: l2,
      layer3_playwright: { confirmed: false, consoleAlerts: [], networkRequests: [] } as unknown as VerificationResult["layer3_playwright"],
      layer4_ai: { confirmed: true, reasoning: "Command execution proven via nonce echo.", confidenceAdjustment: 0.2 } as unknown as VerificationResult["layer4_ai"],
      finalVerdict: "confirmed",
      rejectedByLayer: null,
      finalConfidence: 0.95,
      dedupHash: "test-hash",
    };

    // Simulate an AI response that (incorrectly) tries to over-claim — the
    // sanitizer must catch this regardless of what the model says.
    mockGenerate.mockResolvedValueOnce(JSON.stringify({
      summary: "Confirmed command execution leading to full server compromise of the target.",
      impact: "An attacker achieved full compromise and root access to the underlying system.",
      steps: ["Send the nonce-echo payload to the cmd parameter", "Observe the nonce in the response"],
    }));

    const gen = new DraftReportGenerator();
    const report = await gen.generate(finding, verification, {
      severity: "critical",
      programName: "Test Program",
      targetUrl: `http://localhost:${PORT}`,
      huntDate: "2026-07-03",
    });

    const combinedText = `${report.summary} ${report.impact} ${report.evidence.join(" ")}`.toLowerCase();

    for (const phrase of RCE_OVERCLAIM_PHRASES) {
      expect(combinedText).not.toContain(phrase);
    }

    // Cites the ACTUAL proven facts — not a generic template.
    expect(combinedText).toContain("cmd"); // the real injectable parameter
    expect(report.evidence.some(e => e.includes("nonce echo"))).toBe(true);
  });

  it("confirm-half fallback (AI generation fails): honest template never over-claims", async () => {
    const layer2 = new Layer2Reprobe();
    const finding = makeResult(`http://localhost:${PORT}/vuln?cmd=test`);
    const l2 = await layer2.reprobe(finding);

    const verification: VerificationResult = {
      findingId: finding.taskId,
      layer1_dedup: { isDuplicate: false } as unknown as VerificationResult["layer1_dedup"],
      layer2_reprobe: l2,
      layer3_playwright: { confirmed: false, consoleAlerts: [], networkRequests: [] } as unknown as VerificationResult["layer3_playwright"],
      layer4_ai: { confirmed: true, reasoning: "Command execution proven.", confidenceAdjustment: 0.2 } as unknown as VerificationResult["layer4_ai"],
      finalVerdict: "confirmed",
      rejectedByLayer: null,
      finalConfidence: 0.95,
      dedupHash: "test-hash-2",
    };

    mockGenerate.mockRejectedValueOnce(new Error("model unavailable"));

    const gen = new DraftReportGenerator();
    const report = await gen.generate(finding, verification, {
      severity: "critical",
      programName: "Test Program",
      targetUrl: `http://localhost:${PORT}`,
      huntDate: "2026-07-03",
    });

    const combinedText = `${report.summary} ${report.impact}`.toLowerCase();
    for (const phrase of RCE_OVERCLAIM_PHRASES) {
      expect(combinedText).not.toContain(phrase);
    }
    expect(combinedText).toContain("command execution");
  });

  it("veto path: a refused reprobe (/reflect) never reaches finalVerdict=confirmed, and generate() refuses to produce a report for it", async () => {
    const layer2 = new Layer2Reprobe();
    const finding = makeResult(`http://localhost:${PORT}/reflect?cmd=test`);
    const l2 = await layer2.reprobe(finding);
    expect(l2.confirmed).toBe(false); // the reflection guard holds — same proof as Gate 2

    const verification: VerificationResult = {
      findingId: finding.taskId,
      layer1_dedup: { isDuplicate: false } as unknown as VerificationResult["layer1_dedup"],
      layer2_reprobe: l2,
      layer3_playwright: { confirmed: false, consoleAlerts: [], networkRequests: [] } as unknown as VerificationResult["layer3_playwright"],
      layer4_ai: { confirmed: false, reasoning: "No execution evidence.", confidenceAdjustment: -0.3 } as unknown as VerificationResult["layer4_ai"],
      finalVerdict: "rejected",
      rejectedByLayer: "l2_reprobe",
      finalConfidence: 0.1,
      dedupHash: "test-hash-3",
    };

    mockGenerate.mockClear(); // isolate this test's call count from earlier tests in this file

    const gen = new DraftReportGenerator();
    await expect(gen.generate(finding, verification, {
      severity: "critical",
      programName: "Test Program",
      targetUrl: `http://localhost:${PORT}`,
      huntDate: "2026-07-03",
    })).rejects.toThrow(/refused/i);

    // The AI content generator must never even be invoked for a refused finding.
    expect(mockGenerate).not.toHaveBeenCalled();
  });
});
