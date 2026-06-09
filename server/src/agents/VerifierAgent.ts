/**
 * VerifierAgent – Browser-Based Finding Verification
 * Replays exploits in Playwright to confirm/deny findings.
 * 4-Layer Anti-Hallucination Pipeline:
 *   Layer 1: Static Deduplication (hash-based)
 *   Layer 2: Dynamic Re-probe (HTTP re-test)
 *   Layer 3: Browser Replay (Playwright exploit replay)
 *   Layer 4: AI Confirmation (LLM-based analysis)
 * Mandatory Validation Gate: confirmed hypotheses MUST pass Layer 3.
 */
import crypto from "crypto";
import path from "path";
import { Worker } from "worker_threads";
import { v4 as uuidv4 } from "uuid";
import { getRandomUserAgent } from "../lib/stealth/browser-fingerprint";
import { db } from "../db";
import { findings } from "../db/schema";
import { eq, desc, isNotNull } from "drizzle-orm";
import logger from "../utils/logger";
import { ModelRouter } from "../intelligence/ModelRouter";
import type { SolverResult } from "./SolverPool";
import { SimHashDedup } from "../lib/intelligence/simhash";

export interface VerificationResult {
  findingId: string;
  layer1_dedup: { isDuplicate: boolean; existingHash?: string };
  layer2_reprobe: { confirmed: boolean; statusCode: number; responseSnippet: string };
  layer3_playwright: { confirmed: boolean; screenshot?: string; consoleAlerts: string[]; networkRequests: string[] };
  layer4_ai: { confirmed: boolean; reasoning: string; confidenceAdjustment: number };
  finalVerdict: "confirmed" | "rejected" | "inconclusive";
  finalConfidence: number;
  dedupHash: string;
}

// ─── Layer 1: Static Deduplication ───────────────────────────────────────────
class Layer1Dedup {
  private hashCache = new Set<string>();
  private simHash = new SimHashDedup();

  async initialize(): Promise<void> {
    // Preload the last 500 dedup hashes from DB so restarts don't reprocess
    // findings that were already confirmed before the process stopped.
    const recent = await db.select({ dedupHash: findings.dedupHash })
      .from(findings)
      .where(isNotNull(findings.dedupHash))
      .orderBy(desc(findings.createdAt))
      .limit(500);
    for (const row of recent) {
      if (row.dedupHash) this.hashCache.add(row.dedupHash);
    }
  }

  computeHash(result: SolverResult): string {
    const normalized = {
      endpoint: result.endpoint.replace(/\?.*$/, ""),
      vulnClass: result.vulnClass,
      payloadNormalized: result.payload.toLowerCase().trim().slice(0, 100),
    };
    return crypto.createHash("sha256").update(JSON.stringify(normalized)).digest("hex");
  }

  computeSimHash(result: SolverResult): bigint {
    const text = `${result.endpoint} ${result.vulnClass} ${result.payload.toLowerCase().slice(0, 200)}`;
    // Anchor to the endpoint path so identical payloads at different endpoints
    // never produce near-duplicate hashes (prevents dedup-bypass DoS).
    let anchor: string;
    try {
      const u = new URL(result.endpoint);
      const paramKeys = [...u.searchParams.keys()].sort().join(",");
      anchor = u.pathname + (paramKeys ? `?[${paramKeys}]` : "");
    } catch {
      anchor = result.endpoint.split("?")[0];
    }
    return this.simHash.computeSimHash(text, anchor);
  }

  async check(hash: string, simhash: bigint): Promise<{ isDuplicate: boolean; existingHash?: string }> {
    if (this.hashCache.has(hash)) {
      return { isDuplicate: true, existingHash: hash };
    }

    // Check DB for exact duplicate
    const existing = await db.select({ id: findings.id })
      .from(findings)
      .where(eq(findings.dedupHash, hash))
      .limit(1);

    if (existing.length > 0) {
      this.hashCache.add(hash);
      return { isDuplicate: true, existingHash: hash };
    }

    // Near-duplicate check via SimHash (same vuln class + similar endpoint/payload)
    if (this.simHash.isDuplicate(simhash)) {
      this.hashCache.add(hash);
      return { isDuplicate: true, existingHash: "simhash-near-duplicate" };
    }

    this.hashCache.add(hash);
    return { isDuplicate: false };
  }
}

// ─── Layer 2: Dynamic Re-probe ────────────────────────────────────────────────
class Layer2Reprobe {
  async reprobe(result: SolverResult): Promise<{ confirmed: boolean; statusCode: number; responseSnippet: string }> {
    if (!result.request) {
      return { confirmed: false, statusCode: 0, responseSnippet: "No request to replay" };
    }

    try {
      const { default: axios } = await import("axios");
      const resp = await axios.get(result.request, {
        timeout: 10000,
        validateStatus: () => true,
        headers: { "User-Agent": getRandomUserAgent() },
      });

      const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);

      // Re-check for the same signals that confirmed the original finding
      let confirmed = false;
      if (result.vulnClass === "xss" && result.payload) {
        confirmed = body.includes(result.payload) || resp.status < 400;
      } else if (result.vulnClass === "sqli") {
        confirmed = /sql|syntax|mysql|ora-\d+/i.test(body) || resp.status < 400;
      } else if (result.vulnClass === "ssrf") {
        confirmed = body.includes("ami-id") || body.match(/root:.*:0:0:/) !== null;
      } else {
        confirmed = resp.status < 400 && result.found;
      }

      return {
        confirmed,
        statusCode: resp.status,
        responseSnippet: body.slice(0, 300),
      };
    } catch {
      return { confirmed: false, statusCode: 0, responseSnippet: "Reprobe failed" };
    }
  }
}

// ─── Layer 3: Browser Replay (Worker-Isolated, Mandatory Validation Gate) ─────
// Playwright runs in a dedicated worker thread so its page lifecycle never
// blocks the main event loop during concurrent verifications.
class Layer3BrowserReplay {
  private worker: Worker | null = null;
  // Explicit flag so callers/logs can tell Layer 3 was unavailable (vs. just unconfirmed)
  layer3Available = false;
  private pending = new Map<string, { resolve: (v: any) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();
  private static readonly REPLAY_TIMEOUT_MS = 35_000;

  private spawnWorker(): Worker {
    // In dev (tsx), __filename ends with .ts; in prod it's compiled .js.
    const workerSrc = path.join(__dirname, '..', 'workers', 'playwright-worker');
    const tsFile = `${workerSrc}.ts`;
    const jsFile = `${workerSrc}.js`;

    // Prefer compiled JS (production); fall back to in-process tsx eval (development)
    const { existsSync } = require('fs') as typeof import('fs');
    if (existsSync(jsFile)) {
      return new Worker(jsFile);
    }
    // Bootstrap: register tsx CJS loader then require the .ts source
    const tsxCjs = require.resolve('tsx/cjs');
    const code = `require(${JSON.stringify(tsxCjs)}); require(${JSON.stringify(tsFile)});`;
    return new Worker(code, { eval: true });
  }

  async initialize(): Promise<void> {
    if (this.worker) return;
    let spawned: Worker | null = null;
    try {
      const w = this.spawnWorker();
      spawned = w;
      w.on('message', (msg: any) => {
        if (msg.type === 'result' || msg.type === 'error') {
          const pending = this.pending.get(msg.id);
          if (!pending) return;
          clearTimeout(pending.timer);
          this.pending.delete(msg.id);
          if (msg.type === 'result') pending.resolve(msg.data);
          else pending.reject(new Error(msg.message));
        }
      });
      w.on('error', err => logger.warn('[VerifierAgent] Worker error', { err }));
      w.on('exit', () => { this.worker = null; });

      // Wait for browser-ready signal
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Worker init timeout')), 30_000);
        w.once('message', (msg: any) => {
          clearTimeout(timeout);
          if (msg.type === 'ready') resolve();
          else reject(new Error(`Unexpected worker message: ${msg.type}`));
        });
        w.postMessage({ type: 'init' });
      });

      this.worker = w;
      this.layer3Available = true;
      logger.info('[VerifierAgent] Browser worker initialised with fingerprint hardening');
    } catch (err) {
      this.layer3Available = false;
      // Terminate a half-spawned worker so a failed init doesn't leak a thread.
      if (spawned) { try { await spawned.terminate(); } catch { /* ignore */ } }
      this.worker = null;
      logger.warn('Playwright worker launch failed – Layer 3 will be skipped (verdicts degrade to L2/L4)', { err });
    }
  }

  async replay(result: SolverResult): Promise<{
    confirmed: boolean;
    screenshot?: string;
    consoleAlerts: string[];
    networkRequests: string[];
  }> {
    if (!this.worker) {
      return { confirmed: false, consoleAlerts: [], networkRequests: [] };
    }

    const id = uuidv4();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          logger.warn('[VerifierAgent] Worker replay timed out', { id });
          resolve({ confirmed: false, consoleAlerts: [], networkRequests: [] });
        }
      }, Layer3BrowserReplay.REPLAY_TIMEOUT_MS);

      this.pending.set(id, { resolve, reject, timer });
      this.worker!.postMessage({
        type: 'replay',
        id,
        result: {
          taskId: result.taskId,
          endpoint: result.endpoint,
          vulnClass: result.vulnClass,
          payload: result.payload,
          found: result.found,
          confidence: result.confidence,
          request: result.request,
        },
      });
    });
  }

  async close(): Promise<void> {
    if (this.worker) {
      this.worker.postMessage({ type: 'close' });
      // Drain pending promises so callers don't hang
      for (const [, p] of this.pending) {
        clearTimeout(p.timer);
        p.resolve({ confirmed: false, consoleAlerts: [], networkRequests: [] });
      }
      this.pending.clear();
      this.worker = null;
    }
  }
}

// ─── Layer 4: AI Confirmation ─────────────────────────────────────────────────
class Layer4AIConfirmation {
  private modelRouter = ModelRouter.getInstance();

  async confirm(result: SolverResult, previousLayers: {
    layer2: { confirmed: boolean; statusCode: number; responseSnippet: string };
    layer3: { confirmed: boolean; consoleAlerts: string[] };
    layer3Available?: boolean;
    screenshot?: string;
  }): Promise<{ confirmed: boolean; reasoning: string; confidenceAdjustment: number; visionUsed: boolean }> {

    // Vision analysis — fire in parallel with text prompt construction if screenshot available
    let visionDescription = '';
    let visionUsed = false;
    if (previousLayers.screenshot) {
      try {
        const visionPrompt =
          `Security vulnerability verification screenshot. ` +
          `Payload sent: "${result.payload}" to ${result.endpoint} testing for ${result.vulnClass}. ` +
          `Does the screenshot show evidence of a successful exploit? ` +
          `Look for: JavaScript alerts, injected content, error messages revealing internals, ` +
          `unexpected redirects, or any sign the payload executed. ` +
          `Reply in 2-3 sentences only.`;
        const desc = await this.modelRouter.describeScreenshot(previousLayers.screenshot, visionPrompt);
        if (desc) {
          visionDescription = desc.trim();
          visionUsed = true;
          logger.info('VerifierAgent: Vision analysis complete', { vulnClass: result.vulnClass, desc: visionDescription.slice(0, 100) });
        }
      } catch { /* non-critical — degrade silently */ }
    }

    const prompt = `You are a senior security researcher reviewing a potential vulnerability finding.

Endpoint: ${result.endpoint}
Vulnerability Class: ${result.vulnClass}
Payload Used: ${result.payload}
Original Confidence: ${result.confidence}

Layer 2 (HTTP Reprobe):
- Confirmed: ${previousLayers.layer2.confirmed}
- Status Code: ${previousLayers.layer2.statusCode}
- Response: ${previousLayers.layer2.responseSnippet}

Layer 3 (Browser Replay):
- Confirmed: ${previousLayers.layer3.confirmed}
- Console/Dialog alerts: ${JSON.stringify(previousLayers.layer3.consoleAlerts)}
${visionDescription ? `\nVision Model Analysis:\n${visionDescription}\n` : ''}
Based on ALL the evidence above, determine:
1. Is this a genuine vulnerability (not a false positive)?
2. What is the confidence adjustment (-0.5 to +0.3)?
3. Brief reasoning.

Return JSON: { "confirmed": boolean, "reasoning": string, "confidenceAdjustment": number }`;

    try {
      const response = await this.modelRouter.reason(prompt);
      try {
        const { promptInjectionDetector } = await import('../governance');
        const check = promptInjectionDetector.detect(response, 'verifier-l4', 'Layer4AIConfirmation');
        if (!check.safe) {
          logger.warn('[VerifierAgent] Prompt injection in L4 response', { score: check.score, reasons: check.reasons });
        }
      } catch { /* non-critical */ }
      const parsed = JSON.parse(response.match(/\{[\s\S]+\}/)?.[0] || "{}");
      return {
        confirmed: Boolean(parsed.confirmed),
        reasoning: String(parsed.reasoning || "AI analysis complete"),
        confidenceAdjustment: Math.min(0.3, Math.max(-0.5, Number(parsed.confidenceAdjustment) || 0)),
        visionUsed,
      };
    } catch (err) {
      logger.warn("VerifierAgent: Layer 4 AI confirmation failed — degrading to L2/L3 consensus", {
        err: String(err), endpoint: result.endpoint, vulnClass: result.vulnClass,
      });
      // Fallback when the AI layer is down. If Layer 3 actually ran, require
      // both HTTP reprobe AND browser replay to agree (conservative consensus).
      // If Layer 3 was UNAVAILABLE (worker failed to launch), it reports
      // confirmed:false by default — so don't let its absence veto a solid L2
      // confirmation; fall back to the HTTP reprobe alone.
      const l3Ran = previousLayers.layer3Available !== false;
      const aiConfirmed = l3Ran
        ? previousLayers.layer2.confirmed && previousLayers.layer3.confirmed
        : previousLayers.layer2.confirmed;
      return {
        confirmed: aiConfirmed,
        reasoning: l3Ran
          ? "AI analysis unavailable – verdict based on L2 HTTP re-probe + L3 browser replay consensus"
          : "AI analysis unavailable and L3 browser replay offline – verdict based on L2 HTTP re-probe alone",
        confidenceAdjustment: aiConfirmed ? 0 : -0.2,
        visionUsed: false,
      };
    }
  }
}

// ─── VerifierAgent (Pipeline Orchestrator) ────────────────────────────────────
export class VerifierAgent {
  private layer1 = new Layer1Dedup();
  private layer2 = new Layer2Reprobe();
  private layer3 = new Layer3BrowserReplay();
  private layer4 = new Layer4AIConfirmation();

  async initialize(): Promise<void> {
    await this.layer1.initialize();
    await this.layer3.initialize();
  }

  async verify(result: SolverResult): Promise<VerificationResult> {
    const findingId = result.taskId;
    const dedupHash = this.layer1.computeHash(result);
    const simhash = this.layer1.computeSimHash(result);

    logger.info("VerifierAgent: Starting 4-layer verification", {
      findingId,
      endpoint: result.endpoint,
      vulnClass: result.vulnClass,
    });

    // Layer 1: Deduplication (exact SHA-256 + SimHash near-duplicate)
    const l1 = await this.layer1.check(dedupHash, simhash);
    if (l1.isDuplicate) {
      logger.info("VerifierAgent: L1 deduplicated", { findingId, hash: dedupHash });
      return {
        findingId,
        layer1_dedup: l1,
        layer2_reprobe: { confirmed: false, statusCode: 0, responseSnippet: "Deduplicated" },
        layer3_playwright: { confirmed: false, consoleAlerts: [], networkRequests: [] },
        layer4_ai: { confirmed: false, reasoning: "Duplicate finding", confidenceAdjustment: -1 },
        finalVerdict: "rejected",
        finalConfidence: 0,
        dedupHash,
      };
    }

    // Layer 2: HTTP Reprobe
    const l2 = await this.layer2.reprobe(result);
    logger.info("VerifierAgent: L2 reprobe complete", { confirmed: l2.confirmed });

    // Layer 3: Browser Replay (Mandatory Gate for confirmed hypotheses)
    // If confidence > 0.7 or vulnClass is high-severity, MUST pass browser validation
    const mustPassBrowser = result.confidence > 0.7 || ["xss", "sqli", "rce", "ssrf"].includes(result.vulnClass);
    const l3 = await this.layer3.replay(result);
    logger.info("VerifierAgent: L3 browser replay complete", { confirmed: l3.confirmed });

    // Layer 4: AI Confirmation (includes vision analysis if screenshot available)
    const l4 = await this.layer4.confirm(result, {
      layer2: l2,
      layer3: l3,
      layer3Available: this.layer3.layer3Available,
      screenshot: l3.screenshot,
    });
    logger.info("VerifierAgent: L4 AI confirmation", { confirmed: l4.confirmed, visionUsed: l4.visionUsed });

    // Final Verdict Logic
    const l2l3Consensus = l2.confirmed && l3.confirmed;
    const l2l4Consensus = l2.confirmed && l4.confirmed;
    // Mandatory browser gate stays fail-closed: high-severity findings MUST pass
    // Layer 3 browser replay. This is an immutable governance contract — when
    // Playwright is offline, high-severity findings are intentionally NOT
    // auto-confirmed (operator must install the browser to verify them).
    const mandatoryGatePassed = !mustPassBrowser || l3.confirmed;
    if (mustPassBrowser && this.layer3.layer3Available === false) {
      logger.warn("VerifierAgent: high-severity finding cannot pass mandatory browser gate — Playwright Layer 3 offline", {
        endpoint: result.endpoint, vulnClass: result.vulnClass,
      });
    }

    let finalVerdict: "confirmed" | "rejected" | "inconclusive";
    let finalConfidence = result.confidence + l4.confidenceAdjustment;

    if (l2l3Consensus && l4.confirmed && mandatoryGatePassed) {
      finalVerdict = "confirmed";
      finalConfidence = Math.min(0.98, finalConfidence + 0.1);
    } else if (l2l4Consensus && mandatoryGatePassed) {
      finalVerdict = "confirmed";
      finalConfidence = Math.min(0.9, finalConfidence);
    } else if (!l2.confirmed && !l3.confirmed) {
      finalVerdict = "rejected";
      finalConfidence = Math.max(0, finalConfidence - 0.3);
    } else {
      finalVerdict = "inconclusive";
    }

    logger.info("VerifierAgent: Verification complete", { findingId, finalVerdict, finalConfidence });

    return {
      findingId,
      layer1_dedup: l1,
      layer2_reprobe: l2,
      layer3_playwright: l3,
      layer4_ai: l4,
      finalVerdict,
      finalConfidence: Math.max(0, Math.min(1, finalConfidence)),
      dedupHash,
    };
  }

  async close(): Promise<void> {
    await this.layer3.close();
  }
}

export default VerifierAgent;
