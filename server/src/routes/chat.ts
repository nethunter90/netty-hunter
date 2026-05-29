import { Router, Request, Response } from "express";
import ModelRouter from "../intelligence/ModelRouter";
import logger from "../utils/logger";

const router = Router();
const modelRouter = ModelRouter.getInstance();

const SYSTEM_PROMPT = `You are an expert bug bounty hunter and offensive security researcher embedded in the Sentinel Primordial platform.
You help hunters with: reconnaissance strategy, payload crafting, vulnerability analysis, report writing, scope interpretation, and tool usage.
Be concise, technical, and actionable. Use markdown for code blocks. If asked about a target, always remind the user to stay within scope.`;

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

// POST /chat — send a message, get a response from the active local model
router.post("/", async (req: Request, res: Response) => {
  const { message, history = [] } = req.body as { message: string; history?: ChatMessage[] };
  if (!message || typeof message !== "string" || message.trim().length === 0) {
    return res.status(400).json({ error: "message required" });
  }

  try {
    // Build a context-aware prompt from history
    const historyContext = (history as ChatMessage[])
      .slice(-6) // last 3 exchanges
      .map(m => `${m.role === "user" ? "User" : "Assistant"}: ${m.content}`)
      .join("\n");

    const prompt = historyContext
      ? `${historyContext}\nUser: ${message.trim()}`
      : message.trim();

    const response = await modelRouter.chat(prompt.length > 6000 ? prompt.slice(-6000) : prompt);

    // Return which model answered
    const models = await modelRouter.getModels();
    logger.debug("[Chat] response generated", { models: models.length });

    return res.json({ response, model: models[0] ?? "unknown" });
  } catch (err) {
    logger.warn("[Chat] model unavailable", { err: String(err) });
    return res.status(503).json({
      error: "No local LLM available. Start Ollama and pull a model, or configure LM Studio.",
    });
  }
});

// GET /chat/status — check if a model is reachable
router.get("/status", async (_req: Request, res: Response) => {
  try {
    const models = await modelRouter.getModels();
    return res.json({ available: models.length > 0, models });
  } catch {
    return res.json({ available: false, models: [] });
  }
});

export default router;
