/**
 * ModelRouter – Claude-only model routing.
 * Tier 0a: Claude SDK (Sonnet) for reason/analyze — stateful per-hunt threads.
 * Tier 0b: Claude CLI bridge — secondary path when SDK key is absent.
 * Tier 0c: Claude Haiku for classify/chat/summarize/code — fast, cheap tasks.
 *
 * No Ollama fallback. Claude failure throws ClaudeUnavailableError, which the
 * hunt engine treats as a hard stop — no silent degradation to a weaker model.
 */
import logger from "../utils/logger";
import { ClaudeBridge } from "../lib/claude-bridge";
import { ClaudeClient } from "../lib/claude-client";

type TaskType = "reason" | "code" | "analyze" | "classify" | "chat" | "summarize";

export class ClaudeUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ClaudeUnavailableError";
  }
}

export class ModelRouter {
  private static instance: ModelRouter;

  /** Which provider handled the last generate() call. */
  lastProvider: "claude" | "default" = "default";

  static getInstance(): ModelRouter {
    if (!ModelRouter.instance) ModelRouter.instance = new ModelRouter();
    return ModelRouter.instance;
  }

  async generate(prompt: string, taskType: TaskType = "chat", options: {
    systemPrompt?: string;
    temperature?: number;
    maxTokens?: number;
    sessionId?: string;
  } = {}): Promise<string> {
    const fullPrompt = options.systemPrompt
      ? `${options.systemPrompt}\n\n${prompt}`
      : prompt;

    // Tier 0a / 0b: Sonnet-class reasoning for high-stakes tasks
    if (taskType === "reason" || taskType === "analyze") {
      // 2026-07-22 (budget chokepoint fix): previously fell back to a shared
      // literal "default" sessionId when the caller omitted one — every
      // caller that forgot to pass a real id shared ONE budget/thread
      // counter, so one module's spend could silently exhaust or collide
      // with another's (and, for concurrent hunts, with each other). Fail
      // closed instead — same fat-finger discipline as ScopeGuard's
      // invalid-programId check: a missing id is a caller bug to fix, not
      // something to paper over with a shared bucket.
      if (!options.sessionId) {
        throw new ClaudeUnavailableError(
          `ModelRouter.generate() called with taskType="${taskType}" and no sessionId — every reason/analyze call must be attributed to a real budget key, not the old shared "default" fallback.`,
        );
      }

      if (ClaudeClient.isAvailable()) {
        try {
          const result = await ClaudeClient.reason(options.sessionId, fullPrompt);
          this.lastProvider = "claude";
          return result;
        } catch (err) {
          logger.warn("ModelRouter: Claude SDK failed, trying CLI bridge", { err: String(err) });
        }
      }

      const cliAvailable = await ClaudeBridge.isAvailable();
      if (cliAvailable) {
        try {
          const result = await ClaudeBridge.reasonWithHuntContext(fullPrompt);
          this.lastProvider = "claude";
          return result;
        } catch (err) {
          logger.warn("ModelRouter: Claude CLI bridge also failed", { err: String(err) });
        }
      }

      throw new ClaudeUnavailableError(
        "Claude unavailable — both SDK and CLI bridge failed. Check ANTHROPIC_API_KEY and Claude CLI auth.",
      );
    }

    // Tier 0c: Haiku for classify / chat / summarize / code
    if (ClaudeClient.isAvailable()) {
      try {
        const sys = options.systemPrompt
          || "You are a precise security analysis assistant. Answer concisely and return valid JSON when asked.";
        const result = await ClaudeClient.oneShot(sys, prompt, options.sessionId);
        this.lastProvider = "claude";
        return result;
      } catch (err) {
        logger.warn("ModelRouter: Claude Haiku failed", { err: String(err), taskType });
      }
    }

    throw new ClaudeUnavailableError(
      `Claude unavailable for ${taskType} task — check ANTHROPIC_API_KEY.`,
    );
  }

  async reason(prompt: string, sessionId?: string): Promise<string> {
    return this.generate(prompt, "reason", {
      systemPrompt: "You are an expert security researcher and bug bounty hunter. Analyze carefully and respond with precise, structured JSON when asked.",
      temperature: 0.05,
      sessionId,
    });
  }

  async classify(prompt: string): Promise<string> {
    return this.generate(prompt, "classify", { temperature: 0.0 });
  }

  async code(prompt: string): Promise<string> {
    return this.generate(prompt, "code", { temperature: 0.1 });
  }

  async chat(prompt: string): Promise<string> {
    return this.generate(prompt, "chat", { temperature: 0.7 });
  }

  // Kept for API compatibility — no embed models without Ollama.
  async getBestEmbedModel(): Promise<string | null> { return null; }

  // Kept for API compatibility — reports available Claude models.
  async getModels(): Promise<string[]> {
    return ClaudeClient.isAvailable() ? ["claude-sonnet", "claude-haiku"] : [];
  }
}

export default ModelRouter;
