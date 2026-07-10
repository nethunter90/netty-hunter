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
import { ClaudeClient } from "../lib/claude-client";
import type { SolverResult } from "./SolverPool";
import { SimHashDedup } from "../lib/intelligence/simhash";
import { adaptPayload, isKnownAdaptationRule } from "../lib/verification/payload-adaptation";

export interface VerificationResult {
  findingId: string;
  layer1_dedup: { isDuplicate: boolean; existingHash?: string };
  layer2_reprobe: { confirmed: boolean; statusCode: number; responseSnippet: string };
  layer3_playwright: { confirmed: boolean; screenshot?: string; consoleAlerts: string[]; networkRequests: string[] };
  layer4_ai: { confirmed: boolean; reasoning: string; confidenceAdjustment: number; errored?: boolean };
  finalVerdict: "confirmed" | "rejected" | "inconclusive" | "deduplicated";
  finalConfidence: number;
  dedupHash: string;
  /**
   * Set when a payload-adaptation retry ran (L4 signalled "capability real,
   * proof payload mechanically wrong"). Only present when the retry actually
   * flipped the verdict to confirmed — see VerifierAgent.verify() for the gate.
   * statusCode/responseSnippet/screenshot/reasoning are the RETRY's own L2/L3/L4
   * evidence (distinct from the top-level layer2_reprobe/layer3_playwright/
   * layer4_ai fields above, which stay the ORIGINAL failing payload's evidence)
   * — this is what a report must cite as the actual proof, since that's what
   * was actually demonstrated.
   */
  adaptation?: {
    rule: string; adaptedUrl: string; adaptedPayload: string;
    statusCode: number; responseSnippet: string; screenshot?: string;
  };
}

// Tools whose findings are STATEFUL — only reproducible inside a live
// multi-step/multi-identity browser session. A stateless L2 HTTP reprobe cannot
// replay these, so it is barred from voting on their verdict (see verify()).
const STATEFUL_ORACLE_TOOLS = new Set<string>(["logic_exploit_agent"]);

// Vuln classes where an out-of-band callback (an Interactsh/local beacon that
// actually fired) is a definitional, non-destructive proof of execution: the
// target reached our controlled server, which can only happen if the injected
// payload ran out-of-band. A stateless L2 reprobe cannot replay an already-fired
// callback, so for these classes an OOB hit is the authoritative oracle and L2
// must not veto it. Does NOT touch the xss/dom_xss mandatory L3 gate.
const OOB_ORACLE_CLASSES = new Set<string>(["rce", "ssrf", "xxe", "sqli", "rfi", "ssti"]);

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

  async check(hash: string, simhash: bigint, skipHash?: string): Promise<{ isDuplicate: boolean; existingHash?: string }> {
    // Skip all dedup checks when this is an intentional re-verification of a known
    // finding (operator clicked "verify" again). The hash must match exactly so
    // this cannot be exploited to bypass dedup for genuinely new findings.
    if (skipHash && hash === skipHash) {
      return { isDuplicate: false };
    }

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
export class Layer2Reprobe {
  async reprobe(result: SolverResult): Promise<{ confirmed: boolean; statusCode: number; responseSnippet: string }> {
    // result.request is sometimes a campaign/finding ID (numeric string) rather than
    // a URL — e.g. for LogicExploitAgent-confirmed findings. Fall back to result.endpoint
    // so L2 still reaches the target instead of bailing immediately.
    const isHttpUrl = (u: unknown): u is string => {
      if (typeof u !== "string" || !u) return false;
      try { const p = new URL(u); return p.protocol === "http:" || p.protocol === "https:"; }
      catch { return false; }
    };
    const reprobeUrl = isHttpUrl(result.request) ? result.request
      : isHttpUrl(result.endpoint) ? result.endpoint
      : null;

    if (!reprobeUrl) {
      return { confirmed: false, statusCode: 0, responseSnippet: "No replayable URL" };
    }

    // rce gets its own independent, non-destructive proof gate rather than
    // falling through to the generic `status<400 && found` check below — that
    // generic check proves nothing about actual code execution. Self-verifying:
    // a random nonce that can only appear in the response if the injected
    // command was actually executed (not merely reflected — the exact-match +
    // anti-reflection guard in reprobeRceNonceEcho rules that out).
    if (result.vulnClass === "rce") {
      return await this.reprobeRceNonceEcho(reprobeUrl, result.authHeaders);
    }

    try {
      const { default: axios } = await import("axios");
      const resp = await axios.get(reprobeUrl, {
        timeout: 10000,
        validateStatus: () => true,
        headers: { "User-Agent": getRandomUserAgent(), ...result.authHeaders },
      });

      const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);

      // Re-check for the same signals that confirmed the original finding
      let confirmed = false;
      if (result.vulnClass === "xss" && result.payload) {
        confirmed = body.includes(result.payload) || resp.status < 400;
      } else if (result.vulnClass === "sqli") {
        // Matches actual SQL error phrases. Intentionally excludes bare "sql"/"sqlite" which appear
        // in filenames inside ENOENT messages from path-traversal probes (false-positive vector).
        confirmed = /you have an error in your sql syntax|mysql_error|sql syntax error|ora-\d+|sqlstate\[|unclosed quotation mark|psql:|sqlite error:|syntax error near|Warning.*mysql_/i.test(body) || resp.status < 400;
      } else if (result.vulnClass === "ssrf") {
        confirmed = body.includes("ami-id") || body.match(/root:.*:0:0:/) !== null;
      } else if (result.vulnClass === "lfi" || result.vulnClass === "rfi") {
        // Positive content oracle: confirm ONLY on an exact file-disclosure signature,
        // never on a bare status code. Reading /etc/passwd (or win.ini) is the canonical
        // NON-DESTRUCTIVE LFI PoC — the response literally contains the file. This kills
        // both false positives (a 200 "file not found" page has no passwd signature) and
        // false negatives (a real disclosure confirms regardless of status-code quirks —
        // the old `status<400 && found` else-branch was the source of the LFI misses).
        confirmed = /root:.*:0:0:/.test(body)                       // /etc/passwd root line
          || /(daemon|bin|sys|nobody):[^:]*:\d+:\d+:/.test(body)    // other passwd entries
          || /\[(fonts|extensions|mci extensions)\]/i.test(body)    // win.ini sections
          || /for 16-bit app support/i.test(body);                  // win.ini boilerplate
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

  /**
   * Read-only RCE proof — nonce-echo oracle (handoff Task 2a, method 2).
   * Injects a fresh random nonce via `echo <nonce>` command-injection variants
   * into each query parameter and confirms ONLY if the response contains that
   * EXACT nonce. Self-verifying, no human judgment: a coincidental match is
   * not possible (the nonce is generated per-call and never sent anywhere
   * else), and the anti-reflection guard (`!body.includes(variant)`) rules out
   * the payload merely bouncing back unexecuted. Non-destructive — `echo` has
   * no side effects on the target. Proves command execution only; does not
   * by itself prove interactive shell access, file read/write, or full
   * compromise — callers must not escalate the claim beyond that.
   */
  private async reprobeRceNonceEcho(
    reprobeUrl: string,
    authHeaders?: Record<string, string>,
  ): Promise<{ confirmed: boolean; statusCode: number; responseSnippet: string }> {
    let url: URL;
    try {
      url = new URL(reprobeUrl);
    } catch {
      return { confirmed: false, statusCode: 0, responseSnippet: "Invalid URL" };
    }

    const params = Array.from(url.searchParams.keys());
    if (params.length === 0) {
      return { confirmed: false, statusCode: 0, responseSnippet: "No injectable parameter for nonce-echo probe" };
    }

    // Fresh, unguessable per-call nonce — never transmitted anywhere but this probe.
    const nonce = `rcp${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`;
    const variants = [`; echo ${nonce}`, `| echo ${nonce}`, `\`echo ${nonce}\``, `$(echo ${nonce})`];

    const { default: axios } = await import("axios");
    for (const variant of variants) {
      for (const param of params) {
        const probeUrl = new URL(url.toString());
        probeUrl.searchParams.set(param, variant);
        try {
          const resp = await axios.get(probeUrl.toString(), {
            timeout: 8000,
            validateStatus: () => true,
            headers: { "User-Agent": getRandomUserAgent(), ...authHeaders },
          });
          const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
          // Exact nonce present AND the literal injected string is not echoed
          // back verbatim — the latter would mean reflection, not execution.
          if (body.includes(nonce) && !body.includes(variant)) {
            return {
              confirmed: true,
              statusCode: resp.status,
              responseSnippet: `Command execution confirmed via nonce echo (param="${param}", payload="${variant}"): ${body.slice(0, 300)}`,
            };
          }
        } catch {
          // Try the next variant/param — a single failed request isn't a verdict.
        }
      }
    }

    return { confirmed: false, statusCode: 0, responseSnippet: "Nonce echo not observed in any variant/parameter" };
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
      w.on('exit', () => {
        // A dead worker must un-set the mandatory-gate flag too — otherwise every
        // XSS finding after a mid-session crash silently reads as "browser tested
        // it and found nothing" (rejected) instead of "oracle offline" (inconclusive).
        this.worker = null;
        this.layer3Available = false;
        logger.warn('[VerifierAgent] Browser worker exited — Layer 3 offline until next init');
      });

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
  }): Promise<{
    confirmed: boolean; reasoning: string; confidenceAdjustment: number; visionUsed: boolean; errored?: boolean;
    capabilityConfirmed?: boolean; adaptationRule?: string | null;
  }> {

    const visionUsed = false;

    // Stateful oracle findings (logic_exploit_agent) need special handling in the
    // L4 prompt: L2's bare-GET result is structurally inapplicable to multi-step
    // stateful exploits and actively misleads L4 (e.g., an admin endpoint returning
    // 200 to L2's unauthenticated GET looks "public" but the stateful session proved
    // it was restricted before the bypass). Surface rawHttpLog explicitly instead.
    const evidenceTool = (result.evidence as { tool?: string } | undefined)?.tool;
    const isStatefulOracle = STATEFUL_ORACLE_TOOLS.has(
      String(result.discoveryTool ?? evidenceTool ?? "")
    );
    const capturedHttpLog = isStatefulOracle
      ? (result.evidence as { rawHttpLog?: string } | undefined)?.rawHttpLog?.slice(0, 2000) ?? null
      : null;

    // Expand evidence window for stateful findings — rawHttpLog is buried at the
    // end of the ProbeResult JSON and gets cut off at the default 600-char limit.
    const evidenceLimit = isStatefulOracle ? 1500 : 600;
    const origEvidence = result.evidence
      ? (typeof result.evidence === "string" ? result.evidence : JSON.stringify(result.evidence)).slice(0, evidenceLimit)
      : null;
    const origResponse = result.response ? String(result.response).slice(0, 300) : null;

    const authBypassNote = result.vulnClass === "auth_bypass"
      ? isStatefulOracle
        ? `\nIMPORTANT — auth_bypass rule: confirming requires evidence that a previously\n` +
          `RESTRICTED endpoint (returning 401/403 for unauthenticated requests) became\n` +
          `accessible after a bypass technique was applied. Check the captured HTTP session\n` +
          `below for the before/after state — the stateful agent recorded both the\n` +
          `unauthenticated attempt and the bypassed attempt.\n`
        : `\nIMPORTANT — auth_bypass rule: confirming requires evidence that a previously\n` +
          `RESTRICTED endpoint (returning 401/403 for unauthenticated requests) became\n` +
          `accessible after a bypass technique was applied. A public endpoint that returns\n` +
          `200 without any auth is NOT an auth bypass — it is expected behaviour.\n`
      : "";

    // For stateful oracle findings, note that L2 reprobe is inapplicable (a bare
    // stateless GET cannot reproduce a multi-step, multi-identity flow) and should
    // not factor into the assessment.
    const layer2Section = isStatefulOracle
      ? `Layer 2 (HTTP Reprobe): NOT APPLICABLE — this finding was confirmed by a\n` +
        `multi-step stateful browser session. A bare GET cannot reproduce the multi-\n` +
        `step flow (e.g. dual-session IDOR, JWT bypass, race condition). Do NOT use\n` +
        `L2 reprobe status to accept or reject this finding.`
      : `Layer 2 (HTTP Reprobe):\n` +
        `- Confirmed: ${previousLayers.layer2.confirmed}\n` +
        `- Status Code: ${previousLayers.layer2.statusCode}\n` +
        `- Response: ${previousLayers.layer2.responseSnippet}`;

    const prompt = `You are a senior security researcher reviewing a potential vulnerability finding.

Endpoint: ${result.endpoint}
Vulnerability Class: ${result.vulnClass}
Payload Used: ${result.payload}
Original Confidence: ${result.confidence}
${authBypassNote}
Original Probe Evidence (what the stateful agent captured during discovery):
${origEvidence ?? "Not available"}

Original Solver Response:
${origResponse ?? "Not available"}
${capturedHttpLog ? `\nCaptured HTTP Session (primary evidence — before/after state from stateful browser):\n${capturedHttpLog}\n` : ""}
${layer2Section}

Layer 3 (Browser Replay):
- Confirmed: ${previousLayers.layer3.confirmed}
- Console/Dialog alerts: ${JSON.stringify(previousLayers.layer3.consoleAlerts)}
Based on ALL the evidence above, determine:
1. Is this a genuine vulnerability (not a false positive)?
2. What is the confidence adjustment (-0.5 to +0.3)?
3. Brief reasoning.
4. Separately: is the underlying CAPABILITY real (the target is provably
   unsanitized/exploitable) even if THIS SPECIFIC payload's proof failed for a
   mechanical/endpoint-shape reason — not because the vuln is absent? Only say
   yes when the evidence itself proves the mechanism reached the vulnerable sink
   (e.g. an ENOENT/500 error naming the exact injected path proves the traversal
   was passed unsanitized to a filesystem call — it just targeted the wrong
   shape). If so, set "capabilityConfirmed": true and pick the ONE matching rule
   from this fixed list (do NOT invent new rule names, do NOT set a rule for
   anything not in this list):
   - "target_directory_not_file": the endpoint reads via a directory-listing
     call (scandir/readdir) and errored (ENOENT/400) because the payload
     targeted a file instead of a directory.
   If no rule from the list applies, or you are not certain the capability is
   real, set "capabilityConfirmed": false and "adaptationRule": null.

Return JSON: { "confirmed": boolean, "reasoning": string, "confidenceAdjustment": number, "capabilityConfirmed": boolean, "adaptationRule": string | null }`;

    // Stateless per-finding session: L4 is a self-contained judgment, so it gets
    // a fresh thread. Sharing the "default" thread across concurrent verifications
    // races the message list into an assistant-terminated array (the "must end
    // with a user message" 400) and bleeds unrelated findings together.
    const l4Session = `verify-${result.taskId}`;
    try {
      const response = await this.modelRouter.reason(prompt, l4Session);
      // A flagged response previously only logged a warning and its verdict was
      // parsed and trusted anyway — meaning a target whose response body feeds
      // this prompt (e.g. the captured HTTP evidence above) could inject a
      // "confirmed: true" verdict for a finding that isn't real, with nothing
      // but a log line to show for it. Discard the verdict instead: same
      // errored/needs-review shape already used below for an unparseable response.
      try {
        const { promptInjectionDetector } = await import('../governance');
        const check = promptInjectionDetector.detect(response, 'verifier-l4', 'Layer4AIConfirmation');
        if (!check.safe) {
          logger.warn('[VerifierAgent] Prompt injection in L4 response — discarding verdict, needs review', { score: check.score, reasons: check.reasons });
          return { confirmed: false, reasoning: `L4 response flagged as prompt injection (score ${check.score}) — needs manual review`, confidenceAdjustment: 0, visionUsed, errored: true };
        }
      } catch { /* non-critical — detector unavailable, proceed with verdict as before */ }

      const parsed = this.extractJson(response);
      if (!parsed) {
        // Unrecoverable structured output is "unknown", not "false". errored lets
        // the verdict route to inconclusive (needs review) rather than rejecting a
        // possibly-real finding via a broken parse.
        logger.warn("VerifierAgent: L4 output unparseable — marking needs-review", {
          endpoint: result.endpoint, vulnClass: result.vulnClass, sample: response.slice(0, 160),
        });
        return { confirmed: false, reasoning: "L4 output unparseable — needs review", confidenceAdjustment: 0, visionUsed, errored: true };
      }
      const adaptationRule = isKnownAdaptationRule(parsed.adaptationRule) ? parsed.adaptationRule : null;
      return {
        confirmed: Boolean(parsed.confirmed),
        reasoning: String(parsed.reasoning || "AI analysis complete"),
        confidenceAdjustment: Math.min(0.3, Math.max(-0.5, Number(parsed.confidenceAdjustment) || 0)),
        visionUsed,
        // Only trust capabilityConfirmed when paired with a rule we actually implement —
        // a signal with no concrete adaptation is not actionable, so treat it as absent.
        capabilityConfirmed: Boolean(parsed.capabilityConfirmed) && adaptationRule !== null,
        adaptationRule,
      };
    } catch (err) {
      logger.warn("VerifierAgent: Layer 4 AI confirmation failed — needs review (not auto-rejected)", {
        err: String(err), endpoint: result.endpoint, vulnClass: result.vulnClass,
      });
      // L4 is the reasoning backstop. When it's down we do NOT hand the verdict to
      // the other layers' raw booleans — that was the fail-into-worst-default the
      // old code did. errored routes the verdict to inconclusive.
      return { confirmed: false, reasoning: "L4 AI analysis unavailable — needs review", confidenceAdjustment: 0, visionUsed: false, errored: true };
    } finally {
      ClaudeClient.clearSession(l4Session);
    }
  }

  /** Extract the first balanced JSON object from a model response, tolerating
   *  ``` fences and surrounding prose. Returns null if nothing parses. */
  private extractJson(raw: string): Record<string, unknown> | null {
    if (!raw) return null;
    const unfenced = raw.replace(/```(?:json)?/gi, "");
    const start = unfenced.indexOf("{");
    if (start === -1) return null;
    let depth = 0, inStr = false, esc = false;
    for (let i = start; i < unfenced.length; i++) {
      const ch = unfenced[i];
      if (inStr) {
        if (esc) esc = false;
        else if (ch === "\\") esc = true;
        else if (ch === '"') inStr = false;
        continue;
      }
      if (ch === '"') inStr = true;
      else if (ch === "{") depth++;
      else if (ch === "}") {
        if (--depth === 0) {
          try { return JSON.parse(unfenced.slice(start, i + 1)) as Record<string, unknown>; }
          catch { return null; }
        }
      }
    }
    return null;
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

  async verify(result: SolverResult, options?: { skipDedupHash?: string }): Promise<VerificationResult> {
    const findingId = result.taskId;
    const dedupHash = this.layer1.computeHash(result);
    const simhash = this.layer1.computeSimHash(result);

    logger.info("VerifierAgent: Starting 4-layer verification", {
      findingId,
      endpoint: result.endpoint,
      vulnClass: result.vulnClass,
    });

    // Layer 1: Deduplication (exact SHA-256 + SimHash near-duplicate)
    // skipDedupHash lets operator-initiated re-verification bypass this layer so
    // the finding can get a fresh L2→L3→L4 verdict without being blocked as a
    // "duplicate" of itself. The hunt loop never passes skipDedupHash.
    const l1 = await this.layer1.check(dedupHash, simhash, options?.skipDedupHash);
    if (l1.isDuplicate) {
      logger.info("VerifierAgent: L1 deduplicated", { findingId, hash: dedupHash });
      return {
        findingId,
        layer1_dedup: l1,
        layer2_reprobe: { confirmed: false, statusCode: 0, responseSnippet: "Deduplicated" },
        layer3_playwright: { confirmed: false, consoleAlerts: [], networkRequests: [] },
        layer4_ai: { confirmed: false, reasoning: "Duplicate finding", confidenceAdjustment: -1 },
        finalVerdict: "deduplicated",
        finalConfidence: 0,
        dedupHash,
      };
    }

    // Layer 2: HTTP Reprobe
    const l2 = await this.layer2.reprobe(result);
    logger.info("VerifierAgent: L2 reprobe complete", { confirmed: l2.confirmed });

    // ── Discovery-oracle classification ──────────────────────────────────────
    // A finding discovered by the Claude-directed stateful Playwright agent
    // (LogicExploitAgent) only exists INSIDE a multi-step, often multi-identity
    // session: forged session state, mid-flight request interception, dual-context
    // BOLA, race windows. A bare stateless L2 GET structurally cannot reproduce
    // that flow — for auth_bypass it would hit 401/403 (false reject); for idor /
    // business_logic a 200 on the URL proves nothing about cross-account access
    // (false confirm). So for these findings L2 must NOT vote. The discovery run
    // was ITSELF a real browser oracle (Playwright) with hard-evidence
    // requirements — a stronger oracle than L3's single-page replay — so authority
    // passes to L4 reasoning over the captured request/response proof.
    const discoveryTool = result.discoveryTool
      ?? (result.evidence as { tool?: string } | undefined)?.tool;
    const statefulOracle = STATEFUL_ORACLE_TOOLS.has(String(discoveryTool ?? ""));

    // Layer 3: Browser Replay.
    // Browser-verifiable classes are those a real browser can PROVE by observing
    // execution (DOM XSS et al). For these, L3 is the authoritative oracle and
    // remains a mandatory gate below. HTTP-observable classes (auth_bypass, sqli
    // row-deltas, cors headers, idor, info_disclosure, ssrf via OOB…) cannot be
    // proven or disproven by a browser — for them L3 is n/a and must not vote.
    const browserVerifiable = ["xss", "dom_xss"].includes(result.vulnClass);
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

    // ── Final verdict: per-class oracle authority ────────────────────────────
    let { finalVerdict, finalConfidence } = this.computeVerdict(
      result, l2, l3, l4, browserVerifiable, statefulOracle
    );

    // ── Payload-adaptation retry (gated, capped at exactly one attempt) ──────
    // Fires ONLY when L4 explicitly signalled the capability is real but this
    // specific proof payload failed for a mechanical/endpoint-shape reason, AND
    // it named a rule we actually implement a concrete transform for. A finding
    // that's genuinely not exploitable never reaches here — capabilityConfirmed
    // is false and no retry churn happens. This never loosens verification: the
    // adapted payload runs through the exact same L2/L3/L4 gate as any proof.
    let adaptation: VerificationResult["adaptation"];
    if (finalVerdict !== "confirmed" && l4.capabilityConfirmed && l4.adaptationRule) {
      const urlToAdapt = this.reprobeUrl(result);
      const adapted = urlToAdapt ? adaptPayload(l4.adaptationRule, urlToAdapt) : null;
      if (adapted) {
        logger.info("VerifierAgent: retrying with adapted payload", {
          findingId, rule: adapted.rule, adaptedUrl: adapted.adaptedUrl,
        });
        const adaptedResult: SolverResult = {
          ...result,
          endpoint: adapted.adaptedUrl,
          request: adapted.adaptedUrl,
          payload: adapted.adaptedPayload,
        };
        // Re-run L2/L3/L4 directly on the adapted payload — deliberately bypasses
        // L1 (this is a same-finding retry, not a new discovery; running it through
        // L1 would permanently pollute the SimHash dedup store with an attempt that
        // never gets persisted). Capped to exactly this one attempt — no recursion.
        const retryL2 = await this.layer2.reprobe(adaptedResult);
        const retryL3 = browserVerifiable ? await this.layer3.replay(adaptedResult) : l3;
        const retryL4 = await this.layer4.confirm(adaptedResult, {
          layer2: retryL2, layer3: retryL3, layer3Available: this.layer3.layer3Available, screenshot: retryL3.screenshot,
        });
        const retryVerdict = this.computeVerdict(adaptedResult, retryL2, retryL3, retryL4, browserVerifiable, statefulOracle);
        if (retryVerdict.finalVerdict === "confirmed") {
          // The adapted proof legitimately passed the SAME gate — adopt it as the
          // real evidence instead of the original failed payload.
          finalVerdict = "confirmed";
          finalConfidence = retryVerdict.finalConfidence;
          adaptation = {
            rule: adapted.rule, adaptedUrl: adapted.adaptedUrl, adaptedPayload: adapted.adaptedPayload,
            statusCode: retryL2.statusCode, responseSnippet: retryL2.responseSnippet, screenshot: retryL3.screenshot,
          };
          logger.info("VerifierAgent: adaptation retry succeeded", { findingId, rule: adapted.rule });
        } else {
          // Adapted payload also failed the gate — keep the ORIGINAL verdict/
          // evidence untouched. No churn, no partial credit.
          logger.info("VerifierAgent: adaptation retry did not confirm — original verdict stands", {
            findingId, retryVerdict: retryVerdict.finalVerdict,
          });
        }
      }
    }

    // L4 is the reasoning backstop; if it errored, a missing oracle is "unknown",
    // which is needs-review, never a refutation. Never hard-reject on a dead L4.
    if (l4.errored && finalVerdict === "rejected") {
      finalVerdict = "inconclusive";
      finalConfidence = result.confidence + l4.confidenceAdjustment;
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
      ...(adaptation ? { adaptation } : {}),
    };
  }

  /** Same URL resolution Layer2Reprobe uses — needed here to derive the adaptation target. */
  private reprobeUrl(result: SolverResult): string | null {
    const isHttpUrl = (u: unknown): u is string => {
      if (typeof u !== "string" || !u) return false;
      try { const p = new URL(u); return p.protocol === "http:" || p.protocol === "https:"; }
      catch { return false; }
    };
    if (isHttpUrl(result.request)) return result.request;
    if (isHttpUrl(result.endpoint)) return result.endpoint;
    return null;
  }

  private computeVerdict(
    result: SolverResult,
    l2: { confirmed: boolean },
    l3: { confirmed: boolean },
    l4: { confirmed: boolean; confidenceAdjustment: number },
    browserVerifiable: boolean,
    statefulOracle: boolean,
  ): { finalVerdict: "confirmed" | "rejected" | "inconclusive"; finalConfidence: number } {
    // Fixes the structural bug where confirmation hard-required L2 and the reject
    // branch fired on (!L2 && !L3) while ignoring L4 — so a correct L4 "confirmed"
    // was discarded whenever the HTTP/browser oracles were unreachable or simply
    // inapplicable to the vuln class. Now each oracle votes only where it has a
    // real test, and a positive proof is never vetoed by an oracle that is n/a.
    let finalVerdict: "confirmed" | "rejected" | "inconclusive";
    let finalConfidence = result.confidence + l4.confidenceAdjustment;

    if (browserVerifiable) {
      // Mandatory browser gate (governance contract — preserved and made STRICTER):
      // a browser-verifiable finding MUST be proven by a real L3 execution oracle.
      // No L2-reflection substitute, no rubber-stamp. When Playwright is offline
      // the finding is never auto-confirmed.
      if (this.layer3.layer3Available === false) {
        logger.warn("VerifierAgent: browser-verifiable finding cannot pass mandatory gate — Playwright Layer 3 offline", {
          endpoint: result.endpoint, vulnClass: result.vulnClass,
        });
        finalVerdict = l4.confirmed ? "inconclusive" : "rejected";
        if (finalVerdict === "rejected") finalConfidence = Math.max(0, finalConfidence - 0.3);
      } else if (l3.confirmed) {
        finalVerdict = "confirmed";
        finalConfidence = Math.min(0.98, finalConfidence + (l4.confirmed ? 0.1 : 0.05));
      } else if (l4.confirmed) {
        // Model believes it but execution was not proven in the browser —
        // needs a human look, never a silent rejection.
        finalVerdict = "inconclusive";
      } else {
        finalVerdict = "rejected";
        finalConfidence = Math.max(0, finalConfidence - 0.3);
      }
    } else if (result.oobConfirmed && OOB_ORACLE_CLASSES.has(result.vulnClass)) {
      // OOB oracle: a beacon that actually fired is definitional, non-destructive
      // proof of out-of-band execution (rce / ssrf / xxe / blind-sqli / rfi / ssti).
      // The target reached our controlled server — impossible unless the injected
      // payload ran. A stateless L2 reprobe cannot replay an already-fired callback,
      // so it must not veto this. This is the strongest proof in the pipeline; an L4
      // dissent does not downgrade it. (Does not touch the xss/dom_xss L3 gate above.)
      finalVerdict = "confirmed";
      finalConfidence = Math.min(0.98, finalConfidence + 0.15);
    } else if (statefulOracle) {
      // Stateful agent-discovered finding (idor / auth_bypass / business_logic via
      // the Claude-directed Playwright agent). L2 is barred — a contextless GET
      // cannot replay a multi-identity / multi-step flow, so its vote here is noise
      // (it would falsely reject auth_bypass on a 401 and falsely confirm idor on a
      // 200). The discovery run was a real browser oracle with hard-evidence
      // requirements; authority passes to L4 reasoning over the captured proof.
      // NOTE: this does NOT touch the xss/dom_xss mandatory L3 gate above — those
      // remain gated exactly as before. (Governance: Playwright gate preserved.)
      if (l4.confirmed) {
        finalVerdict = "confirmed";
        finalConfidence = Math.min(0.95, finalConfidence + 0.05);
      } else {
        // L4 dissent or error on a finding a stateful oracle already proved → needs
        // a human, never an auto-reject driven by an inapplicable stateless reprobe.
        finalVerdict = "inconclusive";
      }
    } else {
      // HTTP-observable class: L2 (live reprobe) is authoritative, L4 corroborates,
      // L3 is n/a and does not vote.
      if (l2.confirmed && l4.confirmed) {
        finalVerdict = "confirmed";
        finalConfidence = Math.min(0.95, finalConfidence + 0.05);
      } else if (l2.confirmed || l4.confirmed) {
        // One authoritative signal, the other silent or dissenting → needs review.
        finalVerdict = "inconclusive";
      } else {
        finalVerdict = "rejected";
        finalConfidence = Math.max(0, finalConfidence - 0.3);
      }
    }
    return { finalVerdict, finalConfidence };
  }

  async close(): Promise<void> {
    await this.layer3.close();
  }
}

export default VerifierAgent;
