/**
 * Info-disclosure report-honesty tests (Task 3, generalized from 2c).
 *
 * Same pattern as rce-report-honesty.test.ts: a real local /api/env-shaped
 * route, run through the real Layer2Reprobe + DraftReportGenerator, proving
 * the honesty policy cites actual disclosed field names (not "full database
 * access"), distinguishes credential-shaped fields from benign ones, and that
 * the report is submittable (populated PoC, correct endpoint) rather than
 * leaking filler content — the original /api/env diagnosis from the handoff.
 */
import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import express from "express";
import type { Server } from "http";

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

const PORT = 48175;
let server: Server;

const ENV_BODY = JSON.stringify({
  NODE_ENV: "production",
  PORT: "3000",
  DB_PASSWORD: "s3cr3tPassw0rd",
  AWS_SECRET_ACCESS_KEY: "AKIAFAKEEXAMPLE1234",
});

beforeAll(async () => {
  const app = express();
  // Unauthenticated info-disclosure endpoint — same shape as sentprime's /api/env.
  app.get("/api/env", (_req, res) => {
    res.set("content-type", "application/json").send(ENV_BODY);
  });
  await new Promise<void>(resolve => { server = app.listen(PORT, resolve); });
});

afterAll(() => new Promise<void>(resolve => server.close(() => resolve())));

function makeResult(endpoint: string): SolverResult {
  return {
    taskId: "info-disclosure-honesty-test", solverId: "test", endpoint, vulnClass: "info_disclosure",
    found: true, confidence: 0.9, evidence: {}, payload: "", request: endpoint,
    response: ENV_BODY, duration: 0, toolsUsed: [],
  };
}

const OVERCLAIM_PHRASES = ["full database access", "full database dump", "entire user database", "all credentials exposed"];

describe("Info-disclosure report honesty (Task 3)", () => {
  it("cites the actual disclosed field names, distinguishes credential-shaped fields, and never overclaims", async () => {
    const layer2 = new Layer2Reprobe();
    const finding = makeResult(`http://localhost:${PORT}/api/env`);
    const l2 = await layer2.reprobe(finding);
    expect(l2.confirmed).toBe(true); // generic status<400 && found oracle — genuinely reachable

    const rawEvidence = `GET /api/env HTTP/1.1\n\nHTTP/1.1 200 OK\ncontent-type: application/json\n\n${ENV_BODY}`;

    const verification: VerificationResult = {
      findingId: finding.taskId,
      layer1_dedup: { isDuplicate: false } as unknown as VerificationResult["layer1_dedup"],
      layer2_reprobe: l2,
      layer3_playwright: { confirmed: false, consoleAlerts: [], networkRequests: [] } as unknown as VerificationResult["layer3_playwright"],
      layer4_ai: { confirmed: true, reasoning: "Unauthenticated endpoint returns environment data.", confidenceAdjustment: 0.2 } as unknown as VerificationResult["layer4_ai"],
      finalVerdict: "confirmed",
      rejectedByLayer: null,
      finalConfidence: 0.95,
      dedupHash: "test-hash-env",
    };

    // AI mock deliberately tries to overclaim — the sanitizer must catch it.
    mockGenerate.mockResolvedValueOnce(JSON.stringify({
      summary: "Unauthenticated access to /api/env grants full database access to the attacker.",
      impact: "This gives an attacker full database access and all credentials exposed for the entire system.",
      steps: ["Send GET /api/env with no authentication", "Observe the JSON response containing configuration data"],
    }));

    const gen = new DraftReportGenerator();
    const report = await gen.generate(finding, verification, {
      severity: "high",
      programName: "Test Program",
      targetUrl: `http://localhost:${PORT}`,
      huntDate: "2026-07-03",
      rawEvidence,
      sessionId: 'test-session',
    });

    const combinedText = `${report.summary} ${report.impact} ${report.evidence.join(" ")}`.toLowerCase();

    for (const phrase of OVERCLAIM_PHRASES) {
      expect(combinedText).not.toContain(phrase);
    }

    // Cites the ACTUAL field names observed, not a generic template.
    expect(combinedText).toContain("db_password");
    expect(combinedText).toContain("aws_secret_access_key");
    expect(report.evidence.some(e => e.toLowerCase().includes("credential/secret-shaped"))).toBe(true);

    // Submittable: no filler description (VULN_DESCRIPTIONS.info_disclosure exists),
    // populated PoC (not N/A), correct endpoint label.
    expect(report.vulnerability).not.toContain("A info_disclosure vulnerability was identified");
    expect(report.proofOfConcept).not.toContain("N/A");
    expect(report.proofOfConcept).toContain(ENV_BODY.slice(0, 50));
    expect(report.title).toContain("/api/env");
    expect(report.affectedAssets).toContain(`http://localhost:${PORT}/api/env`);
  });

  it("fallback (AI generation fails): honest template cites real fields, never overclaims", async () => {
    const layer2 = new Layer2Reprobe();
    const finding = makeResult(`http://localhost:${PORT}/api/env`);
    const l2 = await layer2.reprobe(finding);

    const rawEvidence = `GET /api/env HTTP/1.1\n\nHTTP/1.1 200 OK\n\n${ENV_BODY}`;

    const verification: VerificationResult = {
      findingId: finding.taskId,
      layer1_dedup: { isDuplicate: false } as unknown as VerificationResult["layer1_dedup"],
      layer2_reprobe: l2,
      layer3_playwright: { confirmed: false, consoleAlerts: [], networkRequests: [] } as unknown as VerificationResult["layer3_playwright"],
      layer4_ai: { confirmed: true, reasoning: "Env data returned unauthenticated.", confidenceAdjustment: 0.2 } as unknown as VerificationResult["layer4_ai"],
      finalVerdict: "confirmed",
      rejectedByLayer: null,
      finalConfidence: 0.95,
      dedupHash: "test-hash-env-2",
    };

    mockGenerate.mockRejectedValueOnce(new Error("model unavailable"));

    const gen = new DraftReportGenerator();
    const report = await gen.generate(finding, verification, {
      severity: "high",
      programName: "Test Program",
      targetUrl: `http://localhost:${PORT}`,
      huntDate: "2026-07-03",
      rawEvidence,
      sessionId: 'test-session',
    });

    const combinedText = `${report.summary} ${report.impact}`.toLowerCase();
    for (const phrase of OVERCLAIM_PHRASES) {
      expect(combinedText).not.toContain(phrase);
    }
    expect(combinedText).toContain("db_password");
  });
});
