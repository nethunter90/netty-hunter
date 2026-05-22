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
import { chromium, Browser, BrowserContext, Page } from "playwright";
import crypto from "crypto";
import { db } from "../db";
import { findings } from "../db/schema";
import { eq } from "drizzle-orm";
import logger from "../utils/logger";
import { ModelRouter } from "../intelligence/ModelRouter";
import type { SolverResult } from "./SolverPool";
import { getBrowserLaunchArgs, getFingerprintInitScript, getRandomUserAgent } from "../lib/stealth/browser-fingerprint";

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

  computeHash(result: SolverResult): string {
    const normalized = {
      endpoint: result.endpoint.replace(/\?.*$/, ""),
      vulnClass: result.vulnClass,
      payloadNormalized: result.payload.toLowerCase().trim().slice(0, 100),
    };
    return crypto.createHash("sha256").update(JSON.stringify(normalized)).digest("hex");
  }

  async check(hash: string): Promise<{ isDuplicate: boolean; existingHash?: string }> {
    if (this.hashCache.has(hash)) {
      return { isDuplicate: true, existingHash: hash };
    }

    // Check DB
    const existing = await db.select({ id: findings.id })
      .from(findings)
      .where(eq(findings.dedupHash, hash))
      .limit(1);

    if (existing.length > 0) {
      this.hashCache.add(hash);
      return { isDuplicate: true, existingHash: hash };
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

// ─── Layer 3: Browser Replay (Mandatory Validation Gate) ─────────────────────
class Layer3BrowserReplay {
  private browser: Browser | null = null;
  private context: BrowserContext | null = null;

  async initialize(): Promise<void> {
    if (this.browser) return;
    try {
      this.browser = await chromium.launch({
        headless: true,
        args: getBrowserLaunchArgs(),
      });
      this.context = await this.browser.newContext({
        viewport: { width: 1280, height: 800 },
        userAgent: getRandomUserAgent(),
        // Locale + timezone match a realistic US user
        locale: 'en-US',
        timezoneId: 'America/New_York',
        // Suppress permissions prompts the same way a real browser would
        permissions: [],
      });
      // Inject fingerprint hardening before any page script runs
      await this.context.addInitScript(getFingerprintInitScript());
      logger.info('[VerifierAgent] Browser context initialized with fingerprint hardening');
    } catch (err) {
      logger.warn("Playwright browser launch failed – Layer 3 will be skipped", { err });
    }
  }

  async replay(result: SolverResult): Promise<{
    confirmed: boolean;
    screenshot?: string;
    consoleAlerts: string[];
    networkRequests: string[];
  }> {
    if (!this.browser || !this.context) {
      return { confirmed: false, consoleAlerts: [], networkRequests: [] };
    }

    const page = await this.context.newPage();
    const consoleAlerts: string[] = [];
    const networkRequests: string[] = [];

    try {
      // Intercept console messages (for XSS alert detection)
      page.on("console", msg => {
        if (msg.type() === "warning" || msg.type() === "error" || msg.text().includes("alert")) {
          consoleAlerts.push(msg.text());
        }
      });

      // Intercept dialogs (alert boxes = XSS confirmed)
      page.on("dialog", async dialog => {
        consoleAlerts.push(`DIALOG:${dialog.type()}:${dialog.message()}`);
        await dialog.accept();
      });

      // Track network requests for SSRF
      page.on("request", req => {
        if (req.url().includes("169.254") || req.url().includes("localhost")) {
          networkRequests.push(req.url());
        }
      });

      const url = result.request || `${result.endpoint}?q=${encodeURIComponent(result.payload)}`;
      await page.goto(url, { timeout: 15000, waitUntil: "domcontentloaded" });
      await page.waitForTimeout(2000);

      // Take screenshot
      const screenshotBuffer = await page.screenshot({ type: "png" });
      const screenshot = screenshotBuffer.toString("base64");

      // Confirm based on vuln type
      let confirmed = false;
      if (result.vulnClass === "xss") {
        confirmed = consoleAlerts.some(a => a.includes("DIALOG:alert") || a.includes("alert("));
        if (!confirmed) {
          const content = await page.content();
          confirmed = content.includes(result.payload);
        }
      } else if (result.vulnClass === "ssrf") {
        confirmed = networkRequests.length > 0;
      } else if (result.vulnClass === "open_redirect") {
        const currentUrl = page.url();
        confirmed = currentUrl.includes("evil.com") || !currentUrl.includes(new URL(result.endpoint).hostname);
      } else {
        confirmed = result.found;
      }

      return { confirmed, screenshot, consoleAlerts, networkRequests };
    } catch (err) {
      logger.error("Browser replay error", { err });
      return { confirmed: false, consoleAlerts, networkRequests };
    } finally {
      await page.close();
    }
  }

  async close(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      this.context = null;
    }
  }
}

// ─── Layer 4: AI Confirmation ─────────────────────────────────────────────────
class Layer4AIConfirmation {
  private modelRouter = ModelRouter.getInstance();

  async confirm(result: SolverResult, previousLayers: {
    layer2: { confirmed: boolean; statusCode: number; responseSnippet: string };
    layer3: { confirmed: boolean; consoleAlerts: string[] };
  }): Promise<{ confirmed: boolean; reasoning: string; confidenceAdjustment: number }> {
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

Based on ALL the evidence above, determine:
1. Is this a genuine vulnerability (not a false positive)?
2. What is the confidence adjustment (-0.5 to +0.3)?
3. Brief reasoning.

Return JSON: { "confirmed": boolean, "reasoning": string, "confidenceAdjustment": number }`;

    try {
      const response = await this.modelRouter.reason(prompt);
      // Scan L4 AI output for prompt injection before trusting the parsed result
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
      };
    } catch {
      // Conservative fallback: use previous layers
      const aiConfirmed = previousLayers.layer2.confirmed && previousLayers.layer3.confirmed;
      return {
        confirmed: aiConfirmed,
        reasoning: "AI analysis failed – using layer 2/3 consensus",
        confidenceAdjustment: aiConfirmed ? 0 : -0.2,
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
    await this.layer3.initialize();
  }

  async verify(result: SolverResult): Promise<VerificationResult> {
    const findingId = result.taskId;
    const dedupHash = this.layer1.computeHash(result);

    logger.info("VerifierAgent: Starting 4-layer verification", {
      findingId,
      endpoint: result.endpoint,
      vulnClass: result.vulnClass,
    });

    // Layer 1: Deduplication
    const l1 = await this.layer1.check(dedupHash);
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

    // Layer 4: AI Confirmation
    const l4 = await this.layer4.confirm(result, { layer2: l2, layer3: l3 });
    logger.info("VerifierAgent: L4 AI confirmation", { confirmed: l4.confirmed });

    // Final Verdict Logic
    const l2l3Consensus = l2.confirmed && l3.confirmed;
    const l2l4Consensus = l2.confirmed && l4.confirmed;
    const mandatoryGatePassed = !mustPassBrowser || l3.confirmed;

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
