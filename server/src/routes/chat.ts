import { Router, Request, Response } from "express";
import ModelRouter from "../intelligence/ModelRouter";
import {
  extractCommandPlan,
  executeCommandPlan,
  stripCommandBlock,
  ExecutionResult,
} from "../lib/shell/command-executor";
import logger from "../utils/logger";

const router = Router();
const modelRouter = ModelRouter.getInstance();

const SYSTEM_PROMPT = `You are an expert bug bounty hunter and offensive security researcher embedded in the Sentinel Primordial platform, running on the operator's own Kali Linux desktop. You can EXECUTE commands on the operator's machine on their behalf.

WHEN to emit a command: any time the user asks you to launch, run, scan, open, start, stop, install, or change something on their machine ("pull up wireshark", "run nmap on 10.0.0.1", "show my network interfaces", "change my MAC address", "fire off subfinder on example.com"). Use any Kali tool that fits — recon, exploitation, traffic capture, fuzzing, anything.

WHEN NOT to emit one: pure questions, explanations, payload crafting, theory, advice. Just answer in plain text.

COMMAND FORMAT (single line, must be valid JSON inside the brackets):
  [CMD: {"bin": "<binary>", "args": ["<arg1>", "<arg2>"], "detached": <bool>, "description": "<one-liner>"}]

For multi-step (each step runs in order, stops on first failure):
  [CMD: {"steps": [{"bin":"ip","args":["link","set","eth0","down"]}, {"bin":"macchanger","args":["-r","eth0"]}, {"bin":"ip","args":["link","set","eth0","up"]}], "detached": false, "description": "Randomize MAC on eth0"}]

Rules:
- "bin" = binary name only (e.g. "nmap"), never a full shell line. Put every flag/value in args[] as a separate string.
- "detached": true for GUI apps (wireshark, burpsuite, firefox, terminal emulators, ghidra, msfconsole, etc.) so the server doesn't block. false for CLI tools whose output you want to show.
- Emit ONE command block per reply, at the very end. Add a short plain-text explanation BEFORE the block so the user knows what's about to happen.
- If you're unsure of an interface name or value, ask before running.
- Stay within scope — if the user is asking about a target outside their declared bug-bounty scope, remind them.

Examples:
  User: "pull up wireshark"
  You: "Launching Wireshark.\\n[CMD: {\\"bin\\":\\"wireshark\\",\\"args\\":[],\\"detached\\":true,\\"description\\":\\"Open Wireshark\\"}]"

  User: "show my network interfaces"
  You: "Running ip addr.\\n[CMD: {\\"bin\\":\\"ip\\",\\"args\\":[\\"addr\\"],\\"description\\":\\"List network interfaces\\"}]"

  User: "what is SSRF?"
  You: "SSRF (Server-Side Request Forgery) is when an attacker tricks a server into making HTTP requests to attacker-chosen URLs… (no command emitted)"`;

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
    // Build a context-aware prompt prefixed with the system rules so the model
    // knows about the CMD sentinel.
    const historyContext = (history as ChatMessage[])
      .slice(-6) // last 3 exchanges
      .map(m => `${m.role === "user" ? "User" : "Assistant"}: ${m.content}`)
      .join("\n");

    const prompt = [
      SYSTEM_PROMPT,
      historyContext,
      `User: ${message.trim()}`,
      `Assistant:`,
    ].filter(Boolean).join("\n\n");

    const capped = prompt.length > 8000 ? prompt.slice(-8000) : prompt;
    const raw = await modelRouter.chat(capped);

    // Parse + execute any [CMD: {...}] sentinel the model produced.
    let executed: ExecutionResult | null = null;
    let executionError: string | null = null;
    const plan = extractCommandPlan(raw);
    if (plan) {
      try {
        executed = await executeCommandPlan(plan);
      } catch (e: any) {
        executionError = String(e?.message || e).slice(0, 200);
        logger.warn("[Chat] command execution failed", { err: executionError });
      }
    }

    const cleanResponse = stripCommandBlock(raw);
    const display = executionError
      ? `${cleanResponse}\n\n⚠ Command blocked: ${executionError}`.trim()
      : cleanResponse;

    // Return which model answered
    const models = await modelRouter.getModels();
    logger.debug("[Chat] response generated", {
      models: models.length,
      executed: executed ? executed.outputs.length : 0,
      blocked: Boolean(executionError),
    });

    return res.json({
      response: display,
      model: models[0] ?? "unknown",
      executed,
    });
  } catch (err) {
    const msg = String(err);
    logger.warn("[Chat] model error", { err: msg });
    const isConnRefused = msg.includes("ECONNREFUSED") || msg.includes("connect");
    return res.status(503).json({
      error: isConnRefused
        ? "Cannot reach Ollama. Make sure `ollama serve` is running."
        : `Model error: ${msg.replace("Error: Model generation failed: ", "").slice(0, 200)}`,
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
