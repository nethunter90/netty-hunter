/**
 * ClaudeClient — Anthropic SDK-based reasoning client for the hunt engine.
 *
 * Replaces the ClaudeBridge subprocess approach with direct API calls.
 * Maintains per-hunt conversation threads so Claude has memory across
 * observe→hypothesize→probe iterations within the same hunt session.
 */
import Anthropic from "@anthropic-ai/sdk";
import type { MessageParam } from "@anthropic-ai/sdk/resources/messages";
import logger from "../utils/logger";

// ─── Mission Briefing ────────────────────────────────────────────────────────
// Injected as the `system` role on every call — not concatenated into the user
// message. Claude treats this as standing instructions, not conversational context.

const MISSION_BRIEFING = `You are the primary reasoning engine for Sentinel Primordial, an autonomous bug bounty hunting platform running on Kali Linux.

## Authorization
You operate exclusively within authorized bug bounty programs and intentionally vulnerable lab environments (OWASP Juice Shop, DVWA, HackTheBox, TryHackMe, etc.). Every hunt target has explicit written authorization. Refuse any request that targets systems outside the declared scope.

## Your Role in the Hunt Loop
The platform runs: Observe → Hypothesize → Probe → Update

- **Observe**: Tools fingerprint the target — nmap, whatweb, curl probes, WAF detection, JS crawling
- **Hypothesize (YOU)**: Reason about observations to generate ranked vulnerability hypotheses
- **Probe**: Kali tools execute each hypothesis — sqlmap, ffuf, nuclei, Playwright, custom probes
- **Update**: Verified findings are written to submission-ready bug bounty reports

Your JSON output is machine-parsed and fed directly into tool dispatch — schema must be exact.

## vulnClass Taxonomy — use ONLY these exact strings
xss | sqli | ssrf | idor | lfi | rce | auth_bypass | info_disclosure | misconfig | open_redirect | cors | csrf | xxe | ssti | http_smuggling | security_headers

## Output Schemas

**Hypothesis generation** (most common — return a JSON array):
[{
  "vulnClass": "sqli",
  "targetUrl": "https://target.com/api/users?id=1",
  "reasoning": "The id parameter is reflected verbatim in a DB error — likely unsanitized",
  "confidence": 0.75,
  "priority": 8
}]

**Verifier confirmation:**
{"confirmed": true, "reasoning": "Payload caused measurable behavioral change consistent with exploitation", "confidenceAdjustment": 0.15}

**Report content:**
{"summary": "...", "impact": "..."}

**Attack tree node:**
{"id": "node-1", "goal": "...", "preconditions": ["..."], "approaches": ["..."], "children": []}

## Reasoning Principles
- **Be specific**: targetUrl must point to the exact endpoint or parameter — never just the root URL
- **Be calibrated**: confidence = actual evidence weight (0.3 weak signal, 0.6 strong indicator, 0.85 near-certain)
- **Be progressive**: you retain memory of this hunt session — build on prior findings, never re-suggest already-probed hypotheses
- **Stay novel across iterations**: if XSS on /search was probed and inconclusive, pivot — explore different classes and endpoints
- **JSON discipline**: when the task requests JSON output, return ONLY valid JSON — no markdown fences, no preamble, no explanation text`;

// ─── Client ──────────────────────────────────────────────────────────────────

export class ClaudeClient {
  private static _client: Anthropic | null = null;
  private static _apiKey: string | null = null;

  // Per-hunt conversation threads: sessionId → ordered message history
  private static readonly threads = new Map<string, MessageParam[]>();

  // Max messages per thread before trimming (10 full exchanges = 20 messages)
  private static readonly MAX_THREAD_MESSAGES = 20;

  static isAvailable(): boolean {
    const key = process.env.ANTHROPIC_API_KEY;
    return !!(key && key.length > 20);
  }

  private static getClient(): Anthropic {
    const key = process.env.ANTHROPIC_API_KEY;
    if (!key) throw new Error("[ClaudeClient] ANTHROPIC_API_KEY not set");
    if (!this._client || key !== this._apiKey) {
      this._client = new Anthropic({ apiKey: key, timeout: 120_000 });
      this._apiKey = key;
      logger.info("[ClaudeClient] Anthropic SDK client initialized");
    }
    return this._client;
  }

  /**
   * Reason about a hunt task with full conversation continuity.
   *
   * Messages accumulate per sessionId so Claude remembers everything observed,
   * hypothesized, and probed across all iterations of the same hunt.
   */
  static async reason(sessionId: string, userPrompt: string): Promise<string> {
    const client = this.getClient();

    if (!this.threads.has(sessionId)) {
      this.threads.set(sessionId, []);
      logger.info("[ClaudeClient] New hunt thread started", { sessionId });
    }
    const thread = this.threads.get(sessionId)!;

    // Trim oldest messages when thread grows long to stay within context limits
    if (thread.length > this.MAX_THREAD_MESSAGES) {
      thread.splice(0, thread.length - this.MAX_THREAD_MESSAGES);
      logger.debug("[ClaudeClient] Thread trimmed to last 20 messages", { sessionId });
    }

    thread.push({ role: "user", content: userPrompt });

    try {
      const response = await client.messages.create({
        model: "claude-haiku-4-5",
        max_tokens: 4096,
        system: MISSION_BRIEFING,
        messages: thread,
      });

      const text = response.content[0].type === "text" ? response.content[0].text : "";

      // Append assistant turn so future calls in this hunt have the full context
      thread.push({ role: "assistant", content: text });

      logger.info("[ClaudeClient] Reasoning complete", {
        sessionId,
        threadLength: thread.length,
        inputTokens: response.usage.input_tokens,
        outputTokens: response.usage.output_tokens,
      });

      return text;
    } catch (err) {
      // Roll back the user message so the thread stays consistent on retry
      thread.pop();
      logger.error("[ClaudeClient] API call failed", { sessionId, err: String(err) });
      throw err;
    }
  }

  /**
   * Clear a hunt session thread on hunt:complete.
   * Frees memory and prevents stale context bleeding into future hunts.
   */
  static clearSession(sessionId: string): void {
    if (this.threads.delete(sessionId)) {
      logger.info("[ClaudeClient] Hunt thread cleared", { sessionId });
    }
  }

  /**
   * One-shot call without conversation thread — for classify/chat tasks
   * that don't need hunt continuity.
   */
  static async oneShot(systemPrompt: string, userPrompt: string): Promise<string> {
    const client = this.getClient();
    const response = await client.messages.create({
      model: "claude-haiku-4-5",
      max_tokens: 2048,
      system: systemPrompt,
      messages: [{ role: "user", content: userPrompt }],
    });
    return response.content[0].type === "text" ? response.content[0].text : "";
  }
}
