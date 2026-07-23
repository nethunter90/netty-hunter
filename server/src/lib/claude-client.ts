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
import { runtimeConfig } from "./runtime-config";

// ── Pricing (USD per million tokens) ────────────────────────────────────────
// 2026-07-22: current published pricing. Cache read/creation tokens are
// billed at different rates than plain input by Anthropic (writes ~1.25x,
// reads ~0.1x base input) — this table doesn't model that distinction and
// instead charges ALL input-shaped tokens (input + cache_creation +
// cache_read) at the base input rate. That's a deliberate overestimate, not
// an oversight: for a SPEND CAP, overestimating cost is the safe direction
// (stops slightly early rather than slightly late) — undercounting is the
// failure mode that matters here ("close but wrong is worse than none").
// claude-sonnet-5 is introductory pricing through 2026-08-31; becomes
// $3/$15 per M after — update PRICING when that lapses.
interface ModelPricing { inputPerM: number; outputPerM: number; }
const PRICING: Record<string, ModelPricing> = {
  "claude-sonnet-5": { inputPerM: 2, outputPerM: 10 },
  "claude-haiku-4-5": { inputPerM: 1, outputPerM: 5 },
};
const DEFAULT_PRICING: ModelPricing = { inputPerM: 3, outputPerM: 15 }; // conservative fallback for an unrecognized model — Opus-tier, not Haiku-tier, so an unknown model can't silently under-cost

function costForUsage(model: string, usage: Anthropic.Usage): number {
  const pricing = PRICING[model] ?? DEFAULT_PRICING;
  const inputShapedTokens = usage.input_tokens
    + (usage.cache_creation_input_tokens ?? 0)
    + (usage.cache_read_input_tokens ?? 0);
  const inputCost = (inputShapedTokens / 1_000_000) * pricing.inputPerM;
  const outputCost = (usage.output_tokens / 1_000_000) * pricing.outputPerM;
  return inputCost + outputCost;
}

export interface SpendRecord {
  callCount: number;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
}

export class LLMDollarBudgetExceededError extends Error {
  constructor(sessionId: string, spentUsd: number, capUsd: number) {
    super(`LLM dollar budget exceeded for hunt ${sessionId}: $${spentUsd.toFixed(4)} spent, cap is $${capUsd.toFixed(2)}`);
    this.name = "LLMDollarBudgetExceededError";
  }
}

// The model every hunt-reasoning call uses — this reason() method, and
// LogicExploitAgent's direct SDK calls (its cache pre-warm + real tool-use
// loop both must stay in sync with whatever this resolves to, or the
// pre-warmed prompt cache is for a different model than the one actually
// used). Runtime-configurable via Settings ("Claude Reasoning Model") so a
// full hunt can be re-run on a different model (e.g. claude-opus-4-8) without
// a code change or restart — read fresh on every call, not cached at startup.
const DEFAULT_REASON_MODEL = "claude-sonnet-5";
export function getReasonModel(): string {
  return runtimeConfig.get("CLAUDE_REASON_MODEL") || DEFAULT_REASON_MODEL;
}

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

  // ── Dollar/token spend accounting — the actual cap, per Amendment/handoff ──
  // Call-count (MAX_CALLS_PER_HUNT below) is cost-blind: a 200-token call and
  // a 4096-token call both count as "1". This is the PRIMARY cap. Recorded
  // here, at createMessage() — the one place every LLM call in the process
  // funnels through (LogicExploitAgent's tool-use loop included, as of the
  // 2026-07-22 chokepoint fix) — so it sees 100% of spend, not just the paths
  // that happened to call reason()/oneShot() directly.
  private static readonly spend = new Map<string, SpendRecord>();
  private static readonly MAX_USD_PER_HUNT =
    parseFloat(process.env.MAX_LLM_USD_PER_HUNT || "2.00");
  // Sessions matching this prefix are RECORDED (so the total spend figure
  // isn't blind to them) but never dollar-capped — there's no "hunt" to
  // attribute a per-hunt cap to (operator chat, cache pre-warm before a
  // sessionId exists, etc.).
  static readonly UNCAPPED_BUCKET = "__uncapped__";

  static getSpend(sessionId: string): SpendRecord {
    return ClaudeClient.spend.get(sessionId) ?? { callCount: 0, inputTokens: 0, outputTokens: 0, costUsd: 0 };
  }

  private static recordSpend(sessionId: string, model: string, usage: Anthropic.Usage): SpendRecord {
    const prior = ClaudeClient.getSpend(sessionId);
    const cost = costForUsage(model, usage);
    const updated: SpendRecord = {
      callCount: prior.callCount + 1,
      inputTokens: prior.inputTokens + usage.input_tokens + (usage.cache_creation_input_tokens ?? 0) + (usage.cache_read_input_tokens ?? 0),
      outputTokens: prior.outputTokens + usage.output_tokens,
      costUsd: prior.costUsd + cost,
    };
    ClaudeClient.spend.set(sessionId, updated);
    return updated;
  }

  static isDollarBudgetExhausted(sessionId: string): boolean {
    return ClaudeClient.getSpend(sessionId).costUsd >= ClaudeClient.MAX_USD_PER_HUNT;
  }

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

  // Serializes every token reservation through one async chain so the
  // check-and-reserve is ATOMIC across concurrent callers. The post-exploit
  // narrative fan-out + chain synthesis fire multiple SDK calls in the same
  // tick; previously each read stale headroom and fired together (check-then-act
  // race — same shape as the old prefill array race), blowing past the ceiling
  // before any recorded its spend and producing back-to-back 429s. Chaining
  // forces each caller to observe every prior reservation, and the pacing wait
  // (when triggered) holds the whole chain so queued callers wait behind it.
  private static pacerChain: Promise<void> = Promise.resolve();

  /**
   * Reserve estimated input tokens against the shared per-minute bucket,
   * pacing (awaiting the window) when the reservation would breach the ceiling.
   * Public so callers that issue Anthropic requests directly (LogicExploitAgent's
   * tool-use loop) pace through the SAME bucket as reason()/oneShot() — one gate
   * for all Claude spend, rather than each path walking into the 429 separately.
   */
  static paceTokens(estimatedTokens: number): Promise<void> {
    const run = ClaudeClient.pacerChain.then(() => ClaudeClient.reserveTokens(estimatedTokens));
    // Keep the chain alive even if a reservation rejects, so one failure can't
    // wedge every subsequent caller.
    ClaudeClient.pacerChain = run.catch(() => {});
    return run;
  }

  private static async reserveTokens(estimatedTokens: number): Promise<void> {
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

  /** Calls already consumed for a hunt — the counterpart persistCheckpoint()
   *  needs alongside getSpend() to save a restorable ledger (see restoreSession()). */
  static getCallCount(sessionId: string): number {
    return ClaudeClient.callCounts.get(sessionId) ?? 0;
  }

  static isAvailable(): boolean {
    return (process.env.ANTHROPIC_API_KEY?.length ?? 0) > 20;
  }

  /**
   * THE shared SDK-invocation primitive. Every Claude API call in this
   * process — reason(), oneShot(), and LogicExploitAgent's tool-use loop and
   * cache pre-warm — routes through here, and nowhere else calls
   * `.messages.create()` directly (enforced by scripts/check-llm-bypass.ts,
   * mirroring the axios/tool-exec import guards). This is what makes the
   * dollar cap below actually see 100% of spend instead of whatever subset
   * of call sites happened to remember to check a budget first.
   *
   * Enforcement order: dollar cap (primary — the only cost-aware check) →
   * call-count cap (secondary, cost-blind, cheap backstop) → token-rate
   * pacing (avoids 429s, not a spend control) → the real call → usage
   * recording. Both caps throw (fail closed); callers that need a graceful
   * stop instead of a rejection (LogicExploitAgent's loop) catch the
   * specific error class and break cleanly — see that file's comment on
   * why a budget-cut probe is marked truncated, never "not vulnerable".
   */
  static async createMessage(
    params: Omit<Anthropic.MessageCreateParams, "stream">,
    sessionId: string | undefined,
    estimatedInputTokens: number,
  ): Promise<Anthropic.Message> {
    if (!ClaudeClient.isAvailable()) throw new Error("ANTHROPIC_API_KEY not set");

    const budgetKey = sessionId ?? ClaudeClient.UNCAPPED_BUCKET;
    if (sessionId) {
      if (ClaudeClient.isDollarBudgetExhausted(sessionId)) {
        const spend = ClaudeClient.getSpend(sessionId);
        logger.warn("[ClaudeClient] createMessage() blocked — hunt dollar budget exhausted", {
          sessionId, spentUsd: spend.costUsd, capUsd: ClaudeClient.MAX_USD_PER_HUNT,
        });
        throw new LLMDollarBudgetExceededError(sessionId, spend.costUsd, ClaudeClient.MAX_USD_PER_HUNT);
      }
      if (!ClaudeClient.tryConsumeBudget(sessionId)) {
        logger.warn("[ClaudeClient] createMessage() blocked — hunt LLM call-count budget exhausted", { sessionId, limit: ClaudeClient.MAX_CALLS_PER_HUNT });
        throw new LLMBudgetExceededError(sessionId, ClaudeClient.MAX_CALLS_PER_HUNT);
      }
    }

    await ClaudeClient.paceTokens(estimatedInputTokens);

    const response = await ClaudeClient.client.messages.create(
      params as Anthropic.MessageCreateParamsNonStreaming,
      { timeout: 90_000 },
    );

    const spend = ClaudeClient.recordSpend(budgetKey, params.model, response.usage);
    logger.debug("[ClaudeClient] createMessage() complete", {
      sessionId: budgetKey, model: params.model,
      inputTokens: response.usage.input_tokens, outputTokens: response.usage.output_tokens,
      callCostUsd: costForUsage(params.model, response.usage), sessionTotalUsd: spend.costUsd,
    });

    return response;
  }

  static async reason(sessionId: string, userPrompt: string): Promise<string> {
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

    const response = await ClaudeClient.createMessage({
      model: getReasonModel(),
      max_tokens: 4096,
      thinking: { type: "adaptive" },
      system: MISSION_BRIEFING,
      messages,
    }, sessionId, estimatedInputTokens);

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
    // Pace Haiku calls through the shared bucket too. The PostExploitAgent
    // narrative fan-out issues these concurrently (one per confirmed finding)
    // and they count against the org input-token limit just like Sonnet calls —
    // they were the unpaced burst behind the back-to-back 429s.
    const estimatedInputTokens = Math.ceil((systemPrompt.length + userPrompt.length) / 4);

    // sessionId is optional here (e.g. operator chat, routes/chat.ts) — when
    // absent, createMessage() still RECORDS the spend (under a shared
    // uncapped bucket) so the total dollar figure isn't blind to it, but
    // skips cap enforcement since there's no hunt to attribute a cap to.
    const response = await ClaudeClient.createMessage({
      model: "claude-haiku-4-5",
      max_tokens: 1024,
      system: systemPrompt,
      messages: [{ role: "user", content: userPrompt }],
    }, sessionId, estimatedInputTokens);

    return response.content
      .filter((b): b is Anthropic.TextBlock => b.type === "text")
      .map(b => b.text)
      .join("");
  }

  static clearSession(sessionId: string): void {
    ClaudeClient.threads.delete(sessionId);
    ClaudeClient.callCounts.delete(sessionId);
    ClaudeClient.spend.delete(sessionId);
  }

  /**
   * Restore a previously-checkpointed spend/call-count ledger for a resumed
   * hunt (budget chokepoint Phase 3 must-have #3). Both caps live in
   * process-local in-memory Maps keyed by sessionId — a resume that skips
   * this and lets a fresh HunterEngine just resume issuing calls would see
   * an EMPTY ledger for that sessionId (spend resets to $0, calls reset to
   * 0), silently re-granting a full fresh budget on top of what was already
   * spent. That's an unbounded cap bypass across a pause/resume cycle,
   * which defeats the entire point of the dollar cap this ledger enforces.
   * Called once, before runLoop() resumes, with the exact SpendRecord and
   * call count persistCheckpoint() saved.
   */
  static restoreSession(sessionId: string, spend: SpendRecord, callCount: number): void {
    ClaudeClient.spend.set(sessionId, spend);
    ClaudeClient.callCounts.set(sessionId, callCount);
  }
}
