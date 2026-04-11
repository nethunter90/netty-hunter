/**
 * ModelRouter – Intelligent task-type-aware model routing for Ollama.
 * Routes requests to the best available model based on task type.
 */
import axios from "axios";
import logger from "../utils/logger";

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
  private readonly baseUrl: string;
  private availableModels: string[] = [];
  private lastModelCheck = 0;
  private readonly MODEL_CHECK_TTL = 60000; // 1 minute

  // Circuit breaker state
  private circuitState: CircuitState = "CLOSED";
  private failureCount = 0;
  private lastFailureTime = 0;
  private readonly FAILURE_THRESHOLD = 3;    // trips circuit after 3 consecutive failures
  private readonly RECOVERY_TIMEOUT = 30_000; // 30 s before allowing a recovery probe

  private readonly PREFERRED_MODELS: ModelConfig[] = [
    { name: "deepseek-r1:7b", taskTypes: ["reason", "analyze"], contextWindow: 32768, speed: "slow" },
    { name: "deepseek-r1:1.5b", taskTypes: ["reason", "analyze"], contextWindow: 8192, speed: "medium" },
    { name: "llama3.2:3b", taskTypes: ["chat", "classify", "summarize", "code"], contextWindow: 8192, speed: "fast" },
    { name: "llama3.2", taskTypes: ["chat", "classify", "summarize", "code", "reason"], contextWindow: 8192, speed: "medium" },
    { name: "llama3.1:8b", taskTypes: ["reason", "code", "analyze"], contextWindow: 16384, speed: "medium" },
    { name: "mistral:7b", taskTypes: ["reason", "code", "chat"], contextWindow: 8192, speed: "medium" },
    { name: "codellama:7b", taskTypes: ["code"], contextWindow: 4096, speed: "medium" },
    { name: "phi3:mini", taskTypes: ["chat", "classify"], contextWindow: 4096, speed: "fast" },
  ];

  constructor() {
    this.baseUrl = process.env.OLLAMA_BASE_URL || "http://localhost:11434";
  }

  static getInstance(): ModelRouter {
    if (!ModelRouter.instance) ModelRouter.instance = new ModelRouter();
    return ModelRouter.instance;
  }

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
    if (Date.now() - this.lastModelCheck < this.MODEL_CHECK_TTL && this.availableModels.length > 0) {
      return this.availableModels;
    }

    try {
      const resp = await axios.get(`${this.baseUrl}/api/tags`, { timeout: 5000 });
      this.availableModels = (resp.data.models || []).map((m: { name: string }) => m.name);
      this.lastModelCheck = Date.now();
      logger.info("ModelRouter: Available models", { models: this.availableModels });
      return this.availableModels;
    } catch {
      logger.warn("ModelRouter: Could not reach Ollama, using fallback");
      return [];
    }
  }

  private async selectModel(taskType: TaskType): Promise<string> {
    const available = await this.getAvailableModels();

    // Filter preferred models by task type and availability
    const candidates = this.PREFERRED_MODELS.filter(m =>
      m.taskTypes.includes(taskType) &&
      available.some(a => a.startsWith(m.name.split(":")[0]))
    );

    if (candidates.length > 0) {
      // Prefer slower/better models for reasoning tasks
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
      return candidates[0].name;
    }

    // Fall back to any available model
    if (available.length > 0) return available[0];

    // Last resort default
    return process.env.OLLAMA_DEFAULT_MODEL || "llama3.2";
  }

  async generate(prompt: string, taskType: TaskType = "chat", options: {
    systemPrompt?: string;
    temperature?: number;
    maxTokens?: number;
  } = {}): Promise<string> {
    if (!this.isHealthy()) {
      throw new Error("ModelRouter: Circuit OPEN — Ollama is unavailable (will retry after recovery timeout)");
    }

    const model = await this.selectModel(taskType);
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
            },
          },
          { timeout: 120000 }
        );

        const content = (resp.data as unknown as { message: { content: string } }).message?.content || resp.data.response || "";
        this.recordSuccess();
        return content;
      } catch (err) {
        lastErr = err;
        logger.warn("ModelRouter: Generation attempt failed", { model, attempt, err: String(err) });
        this.recordFailure();
      }
    }

    throw new Error(`ModelRouter: Generation failed after ${MAX_RETRIES + 1} attempts — ${String(lastErr)}`);
  }

  async reason(prompt: string): Promise<string> {
    return this.generate(prompt, "reason", {
      systemPrompt: "You are an expert security researcher and bug bounty hunter. Analyze carefully and respond with precise, structured JSON when asked.",
      temperature: 0.05,
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

  async getModels(): Promise<string[]> {
    return this.getAvailableModels();
  }
}

export default ModelRouter;
