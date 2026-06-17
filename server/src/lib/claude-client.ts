/**
 * ClaudeClient — Anthropic SDK wrapper for the hunt engine.
 * tier-0a: sonnet-4-6 with per-hunt conversation threads for reasoning
 * tier-0b: haiku-4-5 for stateless, high-volume classify/chat
 *
 * Authorization context: this client is called exclusively from
 * bug-bounty hunting flows against targets the user has explicit
 * authorization to test.  The scope guard middleware enforces
 * in-scope checks before any probe is dispatched.
 */
import Anthropic from "@anthropic-ai/sdk";
import logger from "../utils/logger";

const MISSION_BRIEFING = `You are a tier-0 reasoning engine embedded in an autonomous bug bounty hunting platform (Netty Hunter / Sentinel Primordial).

AUTHORIZATION CONTEXT:
- All targets are explicitly authorized for security testing — either via bug bounty program scope (HackerOne, Bugcrowd, Synack, Intigriti) or local-lab environments the operator controls.
- A scope-guard middleware enforces in-scope checks at the network layer before any probe reaches you.
- Your role is to reason about vulnerabilities, generate hypotheses, and plan exploitation of confirmed findings to produce submission-ready reports.

YOUR ROLE:
- Analyze web application observations (HTTP headers, JS source, technology stack, anomaly signals)
- Generate precise vulnerability hypotheses with vulnClass, targetUrl, confidence, and reasoning
- Synthesize confirmed findings into exploit chains
- Reason about attack paths that automated tools miss (IDOR at scale, business logic, chained exploits)

VULN CLASSES: xss, sqli, ssrf, idor, rce, lfi, xxe, csrf, cors, open_redirect, auth_bypass, business_logic, info_disclosure, misconfig, deserialization, ssti, prototype_pollution, race_condition

RESPONSE FORMAT: When asked for hypotheses or analysis, return structured JSON matching the schema provided in the prompt. When asked for reasoning, be direct and precise.`;

export class LLMBudgetExceededError extends Error {
  constructor(sessionId: string, limit: number) {
    super(`LLM call budget exceeded for hunt ${sessionId} (limit ${limit})`);
    this.name = "LLMBudgetExceededError";
  }
}

export class ClaudeClient {
  // Lazy client so keys set via runtimeConfig after startup are picked up.
  private static _client: Anthropic | null = null;
  private static get client(): Anthropic {
    const key = process.env.ANTHROPIC_API_KEY;
    if (!ClaudeClient._client || ClaudeClient._client.apiKey !== key) {
      ClaudeClient._client = new Anthropic({ apiKey: key });
    }
    return ClaudeClient._client;
  }
  private static readonly threads = new Map<string, Anthropic.MessageParam[]>();
  private static readonly MAX_THREAD_MESSAGES = 20;

  // ── Per-hunt LLM call budget ────────────────────────────────────────────────
  // Caps total Claude API calls per hunt session so a runaway hunt (e.g. many
  // business_logic hypotheses each driving the 16-call LogicExploitAgent loop)
  // can't silently burn the weekly quota. Configurable via MAX_LLM_CALLS_PER_HUNT.
  private static readonly callCounts = new Map<string, number>();
  private static readonly MAX_CALLS_PER_HUNT =
    parseInt(process.env.MAX_LLM_CALLS_PER_HUNT || "150", 10);

  // ── Input-token rate limiter (token bucket) ─────────────────────────────────
  // Prevents 429 "rate limit exceeded" errors by pacing input-token spend below
  // the org's 30k input-tokens-per-minute ceiling. Uses prompt character length
  // as a proxy (chars / 4 ≈ tokens). Configurable via MAX_INPUT_TOKENS_PER_MIN.
  private static readonly TOKEN_BUCKET_CEILING =
    parseInt(process.env.MAX_INPUT_TOKENS_PER_MIN || "25000", 10);
  private static tokenBucketUsed = 0;
  private static tokenBucketWindowStart = Date.now();

  private static async paceTokens(estimatedTokens: number): Promise<void> {
    const now = Date.now();
    if (now - ClaudeClient.tokenBucketWindowStart >= 60_000) {
      ClaudeClient.tokenBucketWindowStart = now;
      ClaudeClient.tokenBucketUsed = 0;
    }
    if (ClaudeClient.tokenBucketUsed + estimatedTokens > ClaudeClient.TOKEN_BUCKET_CEILING) {
      const msLeft = 60_000 - (Date.now() - ClaudeClient.tokenBucketWindowStart) + 500;
      logger.info("[ClaudeClient] Input-token rate limit approached — pacing", { msLeft, used: ClaudeClient.tokenBucketUsed });
      await new Promise(r => setTimeout(r, msLeft));
      ClaudeClient.tokenBucketWindowStart = Date.now();
      ClaudeClient.tokenBucketUsed = 0;
    }
    ClaudeClient.tokenBucketUsed += estimatedTokens;
  }

  /**
   * Reserve one LLM call against the session budget. Returns false when the
   * hunt has exhausted its allowance. Callers that make direct Anthropic calls
   * (e.g. LogicExploitAgent) consult this before each request so all Claude
   * spend for a hunt is counted in one place.
   */
  static tryConsumeBudget(sessionId: string): boolean {
    const used = ClaudeClient.callCounts.get(sessionId) ?? 0;
    if (used >= ClaudeClient.MAX_CALLS_PER_HUNT) return false;
    ClaudeClient.callCounts.set(sessionId, used + 1);
    return true;
  }

  /** Remaining LLM calls for a hunt (for logging / UI). */
  static budgetRemaining(sessionId: string): number {
    return Math.max(0, ClaudeClient.MAX_CALLS_PER_HUNT - (ClaudeClient.callCounts.get(sessionId) ?? 0));
  }

  static isAvailable(): boolean {
    return (process.env.ANTHROPIC_API_KEY?.length ?? 0) > 20;
  }

  static async reason(sessionId: string, userPrompt: string): Promise<string> {
    if (!ClaudeClient.isAvailable()) throw new Error("ANTHROPIC_API_KEY not set");
    if (!ClaudeClient.tryConsumeBudget(sessionId)) {
      logger.warn("[ClaudeClient] reason() blocked — hunt LLM budget exhausted", { sessionId, limit: ClaudeClient.MAX_CALLS_PER_HUNT });
      throw new LLMBudgetExceededError(sessionId, ClaudeClient.MAX_CALLS_PER_HUNT);
    }

    // Build a NEW array — never mutate the stored thread. Concurrent calls sharing
    // the same sessionId previously raced on the same reference, interleaving their
    // user/assistant pushes and producing an assistant-terminated array on the next
    // call (→ 400 "assistant message prefill").
    const base = ClaudeClient.threads.get(sessionId) ?? [];
    const withUser: Anthropic.MessageParam[] = [
      ...base,
      { role: "user", content: userPrompt },
    ];

    // Trim to the rolling window — always ends with the user message we just added
    const messages = withUser.length > ClaudeClient.MAX_THREAD_MESSAGES
      ? withUser.slice(-ClaudeClient.MAX_THREAD_MESSAGES)
      : withUser;

    // Pace input tokens to stay below the org's 30k tokens/min rate limit
    const estimatedInputTokens = Math.ceil(
      (MISSION_BRIEFING.length + messages.reduce((n, m) =>
        n + (typeof m.content === "string" ? m.content.length : JSON.stringify(m.content).length), 0)
      ) / 4
    );
    await ClaudeClient.paceTokens(estimatedInputTokens);

    const response = await ClaudeClient.client.messages.create({
      model: "claude-sonnet-4-6",
      max_tokens: 4096,
      thinking: { type: "adaptive" },
      system: MISSION_BRIEFING,
      messages,
    }, { timeout: 90_000 });

    const text = response.content
      .filter((b): b is Anthropic.TextBlock => b.type === "text")
      .map(b => b.text)
      .join("");

    // Store the completed turn atomically — previous stored thread is never mutated
    ClaudeClient.threads.set(sessionId, [
      ...withUser,
      { role: "assistant", content: response.content as Anthropic.MessageParam["content"] },
    ]);

    logger.debug("[ClaudeClient] reason() complete", { sessionId, outputLen: text.length });
    return text;
  }

  /**
   * Stateless, high-volume task path — uses Haiku (cheap/fast) for classify,
   * chat, summarize, and structured extraction. Optionally counts against the
   * per-hunt budget when a sessionId is supplied.
   */
  static async oneShot(systemPrompt: string, userPrompt: string, sessionId?: string): Promise<string> {
    if (!ClaudeClient.isAvailable()) throw new Error("ANTHROPIC_API_KEY not set");
    if (sessionId && !ClaudeClient.tryConsumeBudget(sessionId)) {
      logger.warn("[ClaudeClient] oneShot() blocked — hunt LLM budget exhausted", { sessionId, limit: ClaudeClient.MAX_CALLS_PER_HUNT });
      throw new LLMBudgetExceededError(sessionId, ClaudeClient.MAX_CALLS_PER_HUNT);
    }

    const response = await ClaudeClient.client.messages.create({
      model: "claude-haiku-4-5",
      max_tokens: 1024,
      system: systemPrompt,
      messages: [{ role: "user", content: userPrompt }],
    });

    return response.content
      .filter((b): b is Anthropic.TextBlock => b.type === "text")
      .map(b => b.text)
      .join("");
  }

  static clearSession(sessionId: string): void {
    ClaudeClient.threads.delete(sessionId);
    ClaudeClient.callCounts.delete(sessionId);
  }
}
