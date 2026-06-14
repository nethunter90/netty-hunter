import { Router, Request, Response } from "express";
import logger from "../utils/logger";
import { SolverPool } from "../agents/SolverPool";
import type { SolverResult } from "../agents/SolverPool";

// Adaptive (LLM-assisted) scanner router.
//
//  GET  /ollama-status  – reports whether the local Ollama server is reachable
//                          and which models it advertises.
//  POST /run            – runs an adaptive scan against a user-supplied target
//                          using the real SolverPool, returning a GenericScanResult
//                          (see CTFBenchmark.tsx GenericScanResult / startGenericScan).

const router = Router();
const OLLAMA_BASE_URL = process.env.OLLAMA_BASE_URL || "http://localhost:11434";

interface AdaptiveTrace {
  phase: string;
  action: string;
  result: string;
  durationMs: number;
}

// ── GET /ollama-status ────────────────────────────────────────────────────────
router.get("/ollama-status", async (_req: Request, res: Response) => {
  try {
    const resp = await fetch(`${OLLAMA_BASE_URL}/api/tags`, {
      signal: AbortSignal.timeout(2500),
    });
    if (!resp.ok) {
      return res.json({ available: false, models: [], baseUrl: OLLAMA_BASE_URL });
    }
    const data = (await resp.json()) as { models?: Array<{ name: string }> };
    const models = (data.models || []).map(m => m.name);
    return res.json({ available: true, models, baseUrl: OLLAMA_BASE_URL });
  } catch (err: any) {
    // Unreachable / timeout — Ollama is offline. Not a server error.
    return res.json({ available: false, models: [], baseUrl: OLLAMA_BASE_URL });
  }
});

// ── POST /run ─────────────────────────────────────────────────────────────────
router.post("/run", async (req: Request, res: Response) => {
  const { targetUrl } = req.body as { targetUrl?: string };

  if (!targetUrl) {
    return res.status(400).json({ error: "targetUrl is required" });
  }

  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error("only http/https targets are supported");
    }
  } catch (err: any) {
    return res.status(400).json({ error: `Invalid targetUrl: ${err.message}` });
  }

  const startMs = Date.now();
  try {
    const ollamaAvailable = await fetch(`${OLLAMA_BASE_URL}/api/tags`, {
      signal: AbortSignal.timeout(2000),
    }).then(r => r.ok).catch(() => false);

    // Drive the real solver pool against the target. Each solver probes one
    // endpoint-per-vuln-class and returns a SolverResult with evidence.
    const pool = new SolverPool(8);
    const budget = { maxRequests: 200, requestsMade: 0 };
    let solverResults: SolverResult[] = [];
    try {
      solverResults = await pool.spawnSolvers(
        targetUrl,
        {},
        { programId: 0, sessionId: 0, budget }
      );
    } catch (err: any) {
      logger.warn("adaptive-scan:/run solver pool error", { err: err.message, targetUrl });
    }

    const detected = solverResults.filter(r => r.found);

    const findings = detected.map(r => {
      const trace: AdaptiveTrace[] = [
        {
          phase: "probe",
          action: `${r.toolsUsed.join("+") || "http-probe"} ${r.vulnClass} @ ${r.endpoint}`,
          result: `found=${r.found} confidence=${Math.round(r.confidence * 100)}%`,
          durationMs: r.duration,
        },
      ];
      const severity =
        r.vulnClass === "sqli" || r.vulnClass === "ssrf" || r.vulnClass === "rce"
          ? "high"
          : r.vulnClass === "xss" || r.vulnClass === "idor"
          ? "medium"
          : "low";
      const evidenceStr =
        typeof r.evidence === "object" && r.evidence
          ? JSON.stringify(r.evidence).slice(0, 500)
          : String(r.response || "").slice(0, 500);
      return {
        endpoint: r.endpoint,
        vulnerability: r.vulnClass,
        severity,
        confidence: r.confidence,
        evidence: evidenceStr || `Payload: ${r.payload}`,
        technique: r.toolsUsed.join(", ") || "adaptive-probe",
        trace,
      };
    });

    const result = {
      targetUrl,
      findings,
      totalEndpointsScanned: 1,
      totalLLMCalls: 0,
      totalTimeMs: Date.now() - startMs,
      modelUsed: ollamaAvailable ? "ollama" : "pattern-probe",
    };

    return res.json(result);
  } catch (err: any) {
    logger.error("adaptive-scan:/run failed", { err: err.message, targetUrl });
    return res.status(500).json({ error: err.message });
  }
});

export default router;
