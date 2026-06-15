/**
 * ModelRouter – Intelligent task-type-aware model routing.
 * Tier 0a: Claude SDK (Sonnet) for reason/analyze — per-hunt conversation threads
 * Tier 0b: Claude CLI bridge — fallback when SDK unavailable
 * Tier 1:  Ollama — local model for lower-cost tasks
 */
import axios from "axios";
import logger from "../utils/logger";
import { runtimeConfig } from "../lib/runtime-config";
import { ClaudeBridge } from "../lib/claude-bridge";
import { ClaudeClient } from "../lib/claude-client";
import { UnifiedReinforcementStore } from "./ReinforcementStore";

type TaskType = "reason" | "code" | "analyze" | "classify" | "chat" | "summarize";

interface ModelConfig {
  name: string;
  taskTypes: TaskType[];
  contextWindow: number;
  speed: "fast" | "medium" | "slow";
}

interface OllamaResponse {
  response: string;
  done: boolean;
  eval_count?: number;
}

// ─── Circuit Breaker ──────────────────────────────────────────────────────────
// Prevents repeated calls to an unresponsive Ollama instance.
// CLOSED → normal; OPEN → Ollama down, skip immediately; HALF_OPEN → recovery probe.
type CircuitState = "CLOSED" | "OPEN" | "HALF_OPEN";

export class ModelRouter {
  private static instance: ModelRouter;
  private readonly defaultBaseUrl: string;
  private availableModels: string[] = [];
  private lastModelCheck = 0;
  private readonly MODEL_CHECK_TTL = 60000; // 1 minute

  private get baseUrl(): string {
    return runtimeConfig.get("OLLAMA_BASE_URL") || this.defaultBaseUrl;
  }

  // Circuit breaker state
  private circuitState: CircuitState = "CLOSED";
  private failureCount = 0;
  private lastFailureTime = 0;
  private readonly FAILURE_THRESHOLD = 3;    // trips circuit after 3 consecutive failures
  private readonly RECOVERY_TIMEOUT = 30_000; // 30 s before allowing a recovery probe

  // Models that cannot generate text and must never be used for inference
  private readonly EMBEDDING_MODEL_PATTERNS = ["embedding", "embed", "rerank"];

  private readonly PREFERRED_MODELS: ModelConfig[] = [
    // Installed reasoning models
    { name: "deepseek-r1:8b", taskTypes: ["reason", "analyze"], contextWindow: 32768, speed: "slow" },
    { name: "deepseek-r1:7b", taskTypes: ["reason", "analyze"], contextWindow: 32768, speed: "slow" },
    { name: "deepseek-r1:1.5b", taskTypes: ["reason", "analyze"], contextWindow: 8192, speed: "medium" },
    // Installed general models
    { name: "gpt-oss:20b", taskTypes: ["reason", "analyze", "chat", "code"], contextWindow: 32768, speed: "medium" },
    { name: "devstral-small-2", taskTypes: ["code", "reason", "analyze"], contextWindow: 32768, speed: "medium" },
    { name: "qwen2.5-coder:7b", taskTypes: ["code", "chat"], contextWindow: 32768, speed: "medium" },
    // Security-focused models
    { name: "hf.co/mav23/Pentest_AI-GGUF:Q4_K_S", taskTypes: ["reason", "analyze", "chat"], contextWindow: 8192, speed: "medium" },
    { name: "jimscard/whiterabbit-neo:13b", taskTypes: ["reason", "analyze"], contextWindow: 8192, speed: "slow" },
    // General fallbacks
    { name: "llama3.2", taskTypes: ["chat", "classify", "summarize", "code", "reason"], contextWindow: 8192, speed: "medium" },
    { name: "llama3.1:8b", taskTypes: ["reason", "code", "analyze"], contextWindow: 16384, speed: "medium" },
    { name: "mistral:7b", taskTypes: ["reason", "code", "chat"], contextWindow: 8192, speed: "medium" },
  ];

  constructor() {
    this.defaultBaseUrl = process.env.OLLAMA_BASE_URL || "http://localhost:11434";
  }

  static getInstance(): ModelRouter {
    if (!ModelRouter.instance) ModelRouter.instance = new ModelRouter();
    return ModelRouter.instance;
  }

  private activeBaseUrl = "";
  /** Which provider handled the last generate() call — readable by callers for tagging. */
  lastProvider: "claude" | "ollama" | "default" = "default";
  /** Exact model name used in the last generate() call. */
  lastUsedModel = "";

  // ── Circuit breaker helpers ────────────────────────────────────────────────
  private recordSuccess(): void {
    this.failureCount = 0;
    if (this.circuitState !== "CLOSED") {
      logger.info("ModelRouter: Circuit CLOSED — Ollama recovered");
      this.circuitState = "CLOSED";
    }
  }

  private recordFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    if (this.failureCount >= this.FAILURE_THRESHOLD && this.circuitState === "CLOSED") {
      logger.error("ModelRouter: Circuit OPEN — Ollama unreachable after repeated failures", {
        failures: this.failureCount,
      });
      this.circuitState = "OPEN";
    }
  }

  /** Returns true when a call to Ollama should be attempted. */
  isHealthy(): boolean {
    if (this.circuitState === "OPEN") {
      if (Date.now() - this.lastFailureTime > this.RECOVERY_TIMEOUT) {
        this.circuitState = "HALF_OPEN";
        logger.info("ModelRouter: Circuit HALF_OPEN — attempting recovery probe");
        return true;
      }
      return false;
    }
    return true; // CLOSED or HALF_OPEN
  }

  /** Active health check — pings /api/tags and updates circuit state. */
  async healthCheck(): Promise<boolean> {
    try {
      await axios.get(`${this.baseUrl}/api/tags`, { timeout: 5000 });
      this.recordSuccess();
      return true;
    } catch {
      this.recordFailure();
      return false;
    }
  }

  private async getAvailableModels(): Promise<string[]> {
    const currentBaseUrl = this.baseUrl;
    // Invalidate cache if the backend URL changed
    if (currentBaseUrl !== this.activeBaseUrl) {
      this.lastModelCheck = 0;
      this.activeBaseUrl = currentBaseUrl;
    }
    if (Date.now() - this.lastModelCheck < this.MODEL_CHECK_TTL && this.availableModels.length > 0) {
      return this.availableModels;
    }

    try {
      const resp = await axios.get(`${currentBaseUrl}/api/tags`, { timeout: 5000 });
      this.availableModels = (resp.data.models || []).map((m: { name: string }) => m.name);
      this.lastModelCheck = Date.now();
      // Successful health check should also close any open circuit so chat
      // works immediately after the user starts Ollama and clicks Scan.
      this.recordSuccess();
      logger.info("ModelRouter: Available models", { models: this.availableModels });
      return this.availableModels;
    } catch {
      logger.warn("ModelRouter: Could not reach Ollama, using fallback");
      return [];
    }
  }

  private isEmbeddingModel(name: string): boolean {
    const lower = name.toLowerCase();
    return this.EMBEDDING_MODEL_PATTERNS.some(p => lower.includes(p));
  }

  private async selectModel(taskType: TaskType): Promise<string> {
    const allAvailable = await this.getAvailableModels();
    const available = allAvailable.filter(m => !this.isEmbeddingModel(m));

    // User's explicit model choice always wins (set via Settings → Local AI)
    const userChosen = runtimeConfig.get("OLLAMA_DEFAULT_MODEL") || process.env.OLLAMA_DEFAULT_MODEL;
    if (userChosen && available.includes(userChosen)) {
      return userChosen;
    }

    // Match preferred profiles against actually-installed model names
    // Return the full installed name (e.g. "llama3.2:3b"), not the profile stub
    const candidates = this.PREFERRED_MODELS.filter(m =>
      m.taskTypes.includes(taskType) &&
      available.some(a => a.startsWith(m.name.split(":")[0]))
    );

    if (candidates.length > 0) {
      if (taskType === "reason" || taskType === "analyze") {
        candidates.sort((a, b) => {
          const speedOrder = { slow: 0, medium: 1, fast: 2 };
          return speedOrder[a.speed] - speedOrder[b.speed];
        });
      } else {
        candidates.sort((a, b) => {
          const speedOrder = { fast: 0, medium: 1, slow: 2 };
          return speedOrder[a.speed] - speedOrder[b.speed];
        });
      }
      // Return the actual installed model name rather than the profile stub
      const profilePrefix = candidates[0].name.split(":")[0];
      return available.find(a => a.startsWith(profilePrefix)) ?? candidates[0].name;
    }

    // Fall back to any available model
    if (available.length > 0) return available[0];

    // Nothing available — return configured default so the error from Ollama is clear
    return userChosen || "llama3.2";
  }

  async generate(prompt: string, taskType: TaskType = "chat", options: {
    systemPrompt?: string;
    temperature?: number;
    maxTokens?: number;
    sessionId?: string;
  } = {}): Promise<string> {
    // Tier 0a: Claude SDK (Sonnet) — per-hunt conversation thread, best quality
    if (taskType === "reason" || taskType === "analyze") {
      if (ClaudeClient.isAvailable()) {
        try {
          logger.info("ModelRouter: routing to Claude API (SDK)", { taskType });
          const sid = options.sessionId ?? "default";
          const fullPrompt = options.systemPrompt
            ? `${options.systemPrompt}\n\n${prompt}`
            : prompt;
          const result = await ClaudeClient.reason(sid, fullPrompt);
          this.lastProvider = "claude";
          return result;
        } catch (err) {
          logger.warn("ModelRouter: Claude SDK failed, trying CLI bridge", { err: String(err) });
        }
      }

      // Tier 0b: Claude CLI bridge — fallback when SDK key unavailable
      const claudeAvailable = await ClaudeBridge.isAvailable();
      if (claudeAvailable) {
        let preferClaude = true;
        try {
          const rl = UnifiedReinforcementStore.getInstance();
          const better = await rl.getBetterModel(taskType);
          if (better === "ollama") {
            preferClaude = false;
            logger.info("ModelRouter: RL data suggests Ollama for this task", { taskType });
          }
        } catch { /* non-fatal — default to Claude */ }

        if (preferClaude) {
          logger.info("ModelRouter: routing to Claude Code CLI", { taskType });
          try {
            const fullPrompt = options.systemPrompt
              ? `${options.systemPrompt}\n\n${prompt}`
              : prompt;
            const result = await ClaudeBridge.reasonWithHuntContext(fullPrompt);
            this.lastProvider = "claude";
            this.lastUsedModel = "claude";
            return result;
          } catch (err) {
            logger.warn("ModelRouter: Claude bridge failed, falling back to Ollama", { err: String(err) });
          }
        }
      }
    }

    // Tier 0c: Claude Haiku for high-volume, low-complexity tasks. This is the
    // cheap tier of the model split — classify/chat/summarize never need Sonnet's
    // depth, so route them to Haiku when the SDK is available (falls back to
    // Ollama on error or budget exhaustion).
    if (taskType === "classify" || taskType === "chat" || taskType === "summarize") {
      if (ClaudeClient.isAvailable()) {
        try {
          const sys = options.systemPrompt
            || "You are a precise security analysis assistant. Answer concisely and return valid JSON when asked.";
          const result = await ClaudeClient.oneShot(sys, prompt, options.sessionId);
          this.lastProvider = "claude";
          logger.debug("ModelRouter: routed to Claude Haiku", { taskType });
          return result;
        } catch (err) {
          logger.warn("ModelRouter: Claude Haiku failed/over-budget, falling back to Ollama", { err: String(err), taskType });
        }
      }
    }

    if (!this.isHealthy()) {
      throw new Error("ModelRouter: Circuit OPEN — Ollama is unavailable (will retry after recovery timeout)");
    }

    const model = await this.selectModel(taskType);
    this.lastUsedModel = model;
    const messages: { role: string; content: string }[] = [];

    if (options.systemPrompt) {
      messages.push({ role: "system", content: options.systemPrompt });
    }
    messages.push({ role: "user", content: prompt });

    const MAX_RETRIES = 2;
    let lastErr: unknown;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      if (attempt > 0) {
        // Exponential backoff: 1 s, 2 s
        await new Promise(r => setTimeout(r, 1000 * attempt));
        logger.warn("ModelRouter: Retrying generation", { model, attempt, taskType });
      }

      try {
        const resp = await axios.post<OllamaResponse>(
          `${this.baseUrl}/api/chat`,
          {
            model,
            messages,
            stream: false,
            options: {
              temperature: options.temperature ?? 0.1,
              num_predict: options.maxTokens ?? 2048,
              num_ctx: 8192,
              num_thread: 8,
            },
          },
          { timeout: 120000 }
        );

        const content = (resp.data as unknown as { message: { content: string } }).message?.content || resp.data.response || "";
        this.recordSuccess();
        this.lastProvider = "ollama";
        return content;
      } catch (err) {
        lastErr = err;
        logger.warn("ModelRouter: Generation attempt failed", { model, attempt, err: String(err) });
        this.recordFailure();
      }
    }

    throw new Error(`ModelRouter: Generation failed after ${MAX_RETRIES + 1} attempts — ${String(lastErr)}`);
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

  // ── Model type classification ──────────────────────────────────────────────
  private static readonly EMBED_PATTERNS   = /embed|minilm|bge-|e5-|sentence/i;
  private static readonly VISION_PATTERNS  = /vision|llava|bakllava|moondream|minicpm-v|cogvlm|internvl|qwen.*vl|llama.*vision/i;

  /** LLM-only models — excludes embed and vision models. */
  async getLLMModels(): Promise<string[]> {
    const all = await this.getAvailableModels();
    return all.filter(m =>
      !ModelRouter.EMBED_PATTERNS.test(m) &&
      !ModelRouter.VISION_PATTERNS.test(m)
    );
  }

  /** Embedding models only. */
  async getEmbedModels(): Promise<string[]> {
    const all = await this.getAvailableModels();
    return all.filter(m => ModelRouter.EMBED_PATTERNS.test(m));
  }

  /** Vision/multimodal models only. */
  async getVisionModels(): Promise<string[]> {
    const all = await this.getAvailableModels();
    return all.filter(m => ModelRouter.VISION_PATTERNS.test(m));
  }

  /** Returns the best available embed model, or null if none installed. */
  async getBestEmbedModel(): Promise<string | null> {
    const embeds = await this.getEmbedModels();
    if (embeds.length === 0) return null;
    // Prefer well-known high-quality embed models
    const preferred = ['nomic-embed-text', 'mxbai-embed-large', 'bge-large', 'all-minilm', 'e5-'];
    for (const p of preferred) {
      const match = embeds.find(m => m.toLowerCase().startsWith(p));
      if (match) return match;
    }
    return embeds[0];
  }

  /**
   * Describe a screenshot using the best available vision model.
   * Returns null if no vision model is installed or the call fails.
   * @param base64Image - PNG/JPEG image encoded as base64 string
   * @param prompt      - Instruction for the vision model
   */
  async describeScreenshot(base64Image: string, prompt: string): Promise<string | null> {
    const visionModels = await this.getVisionModels();
    if (visionModels.length === 0) return null;
    if (!this.isHealthy()) return null;

    try {
      const resp = await axios.post(
        `${this.baseUrl}/api/generate`,
        { model: visionModels[0], prompt, images: [base64Image], stream: false },
        { timeout: 30_000 }
      );
      this.recordSuccess();
      return (resp.data as OllamaResponse).response ?? null;
    } catch (err) {
      logger.debug("ModelRouter: Vision model call failed", { model: visionModels[0], err: String(err) });
      return null;
    }
  }

  async chat(prompt: string): Promise<string> {
    return this.generate(prompt, "chat", { temperature: 0.7 });
  }

  async getModels(): Promise<string[]> {
    return this.getAvailableModels();
  }

  /** Returns the model name that would be selected for the given task type. */
  async getActiveModelName(taskType: TaskType = "chat"): Promise<string> {
    return this.selectModel(taskType);
  }
}

export default ModelRouter;
