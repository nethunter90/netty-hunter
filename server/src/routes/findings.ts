import { Router, Request, Response } from "express";
import path from "path";
import crypto from "crypto";
import { mkdirSync, writeFileSync } from "fs";
import { Worker } from "worker_threads";
import { v4 as uuidv4 } from "uuid";
import logger from "../utils/logger";

// Findings router.
//
//  POST /verify-browser – replays a finding in a real (Playwright) browser using
//                          the same worker the VerifierAgent's Layer-3 gate drives,
//                          persists the screenshot under evidence/<id>/, and returns
//                          a `browserVerification` block matching CTFBenchmark.tsx.

const router = Router();

interface ReplayResult {
  confirmed: boolean;
  screenshot?: string;
  consoleAlerts: string[];
  networkRequests: string[];
}

// Spawn the shared playwright worker (compiled .js in prod, tsx-eval in dev),
// run a single replay, and tear it down. Mirrors VerifierAgent.Layer3 spawn logic.
function spawnWorker(): Worker {
  const workerSrc = path.join(__dirname, "..", "workers", "playwright-worker");
  const jsFile = `${workerSrc}.js`;
  const tsFile = `${workerSrc}.ts`;
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { existsSync } = require("fs") as typeof import("fs");
  if (existsSync(jsFile)) {
    return new Worker(jsFile);
  }
  const tsxCjs = require.resolve("tsx/cjs");
  const code = `require(${JSON.stringify(tsxCjs)}); require(${JSON.stringify(tsFile)});`;
  return new Worker(code, { eval: true });
}

async function replayInBrowser(payloadResult: {
  taskId: string;
  endpoint: string;
  vulnClass: string;
  payload: string;
  found: boolean;
  confidence: number;
  request?: string;
}): Promise<ReplayResult> {
  const worker = spawnWorker();
  try {
    // Wait for browser ready.
    await new Promise<void>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("worker init timeout")), 30_000);
      worker.once("message", (msg: any) => {
        clearTimeout(t);
        if (msg.type === "ready") resolve();
        else reject(new Error(`unexpected worker message: ${msg.type}`));
      });
      worker.postMessage({ type: "init" });
    });

    const id = uuidv4();
    const data = await new Promise<ReplayResult>((resolve) => {
      const t = setTimeout(() => {
        resolve({ confirmed: false, consoleAlerts: ["REPLAY_TIMEOUT"], networkRequests: [] });
      }, 35_000);
      const onMsg = (msg: any) => {
        if (msg.id !== id) return;
        clearTimeout(t);
        worker.off("message", onMsg);
        if (msg.type === "result") resolve(msg.data as ReplayResult);
        else resolve({ confirmed: false, consoleAlerts: [String(msg.message)], networkRequests: [] });
      };
      worker.on("message", onMsg);
      worker.postMessage({ type: "replay", id, result: payloadResult });
    });

    return data;
  } finally {
    try {
      worker.postMessage({ type: "close" });
    } catch { /* ignore */ }
    // Give the worker a moment to exit cleanly, then force-terminate.
    setTimeout(() => { worker.terminate().catch(() => {}); }, 2000);
  }
}

// ── POST /verify-browser ──────────────────────────────────────────────────────
router.post("/verify-browser", async (req: Request, res: Response) => {
  const { endpoint, vulnerability, confidence, evidence, technique, runId } = req.body as {
    endpoint?: string;
    vulnerability?: string;
    severity?: string;
    confidence?: number;
    evidence?: string;
    technique?: string;
    benchmarkMode?: string;
    runId?: string;
  };

  if (!endpoint || !vulnerability) {
    return res.status(400).json({ error: "endpoint and vulnerability are required" });
  }

  const startMs = Date.now();
  const verificationId = runId || `verify-${Date.now()}`;

  try {
    // Build the SolverResult-shaped payload the worker expects. We derive a
    // best-effort payload from the supplied evidence/technique.
    const payload = (evidence || "").match(/payload[:=]?\s*(.+)/i)?.[1]?.trim() || evidence || "";
    const replay = await replayInBrowser({
      taskId: verificationId,
      endpoint,
      vulnClass: vulnerability,
      payload,
      found: true,
      confidence: confidence ?? 0.5,
      request: endpoint,
    });

    const durationMs = Date.now() - startMs;

    // Persist the screenshot (if any) to evidence/<id>/ — same convention the
    // CampaignOrchestrator uses for Playwright artifacts.
    const evidenceAttachments: Array<{
      id: string;
      type: string;
      path: string;
      mimeType: string;
      sizeBytes: number;
      capturedAt: string;
      label?: string;
    }> = [];

    let screenshotHashAfter: string | undefined;
    if (replay.screenshot) {
      try {
        const evidenceDir = path.join(process.cwd(), "evidence", verificationId);
        mkdirSync(evidenceDir, { recursive: true });
        const buf = Buffer.from(replay.screenshot, "base64");
        const shotPath = path.join(evidenceDir, "browser_verify_screenshot.png");
        writeFileSync(shotPath, buf);
        screenshotHashAfter = crypto.createHash("sha256").update(buf).digest("hex");
        evidenceAttachments.push({
          id: uuidv4(),
          type: "screenshot",
          path: shotPath,
          mimeType: "image/png",
          sizeBytes: buf.length,
          capturedAt: new Date().toISOString(),
          label: `${vulnerability} @ ${endpoint}`,
        });
      } catch (err: any) {
        logger.warn("findings:/verify-browser screenshot persist failed", { err: err.message });
      }
    }

    const status: "verified" | "false_positive" | "error" = replay.consoleAlerts.includes("REPLAY_TIMEOUT")
      ? "error"
      : replay.confirmed
      ? "verified"
      : "false_positive";

    const browserVerification = {
      status,
      confidence: replay.confirmed ? Math.max(confidence ?? 0.5, 0.85) : (confidence ?? 0.5) * 0.5,
      domChangedSignificantly: replay.consoleAlerts.length > 0,
      visualChangedSignificantly: !!replay.screenshot,
      evidenceAttachments,
      traceZipPath: null as string | null,
      screenshotHashAfter,
      durationMs,
      verifiedAt: new Date().toISOString(),
      errorMessage: status === "error" ? replay.consoleAlerts.join("; ") : undefined,
    };

    logger.info("findings:/verify-browser complete", { endpoint, vulnerability, status, technique });
    return res.json({ browserVerification });
  } catch (err: any) {
    logger.error("findings:/verify-browser failed", { err: err.message, endpoint });
    return res.json({
      browserVerification: {
        status: "error",
        confidence: 0,
        domChangedSignificantly: false,
        visualChangedSignificantly: false,
        evidenceAttachments: [],
        traceZipPath: null,
        durationMs: Date.now() - startMs,
        verifiedAt: new Date().toISOString(),
        errorMessage: err.message,
      },
    });
  }
});

export default router;
