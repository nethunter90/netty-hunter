import { Router, Request, Response } from "express";
import { promises as fs } from "fs";
import path from "path";
import ModelRouter from "../intelligence/ModelRouter";
import { ClaudeClient } from "../lib/claude-client";
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
- INSTALLS: there is no interactive terminal, so always pass the non-interactive/assume-yes flag — apt/apt-get use \`-y\` (e.g. \`["install","-y","ssrfmap"]\`), pip uses no prompt by default, npm/cargo/go are non-interactive. A command that waits for a [Y/n] prompt will hang and time out. Package installs get a 5-minute timeout; everything else gets 30s.
- Emit ONE command block per reply, at the very end. Add a short plain-text explanation BEFORE the block so the user knows what's about to happen.
- If you're unsure of an interface name or value, ask before running.
- Stay within scope — if the user is asking about a target outside their declared bug-bounty scope, remind them.

Examples:
  User: "pull up wireshark"
  You: "Launching Wireshark.\\n[CMD: {\\"bin\\":\\"wireshark\\",\\"args\\":[],\\"detached\\":true,\\"description\\":\\"Open Wireshark\\"}]"

  User: "show my network interfaces"
  You: "Running ip addr.\\n[CMD: {\\"bin\\":\\"ip\\",\\"args\\":[\\"addr\\"],\\"description\\":\\"List network interfaces\\"}]"

  User: "what is SSRF?"
  You: "SSRF (Server-Side Request Forgery) is when an attacker tricks a server into making HTTP requests to attacker-chosen URLs… (no command emitted)"

RESPONSE FORMAT — always follow these rules:
- Use markdown. Bullet lists over run-on sentences. \`inline code\` for tool names, flags, payloads. Fenced code blocks (\`\`\`bash) for multi-line commands or output examples.
- Be concise. Lead with the key point. No preamble like "Sure!" or "Of course!".
- If the answer has multiple steps or items, use a numbered list.
- Max 3–4 short paragraphs for pure text answers. Never write an essay.`;


interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

async function loadHuntContext(): Promise<string> {
  try {
    const [live, findings] = await Promise.allSettled([
      fs.readFile(path.join(process.cwd(), "context/hunt-live.json"), "utf-8"),
      fs.readFile(path.join(process.cwd(), "context/hunt-findings.json"), "utf-8"),
    ]);
    const liveStr = live.status === "fulfilled" ? live.value.slice(0, 900) : null;
    const findingsStr = findings.status === "fulfilled" ? findings.value.slice(0, 700) : null;
    if (!liveStr && !findingsStr) return "";
    const parts: string[] = [];
    if (liveStr) parts.push(`Live hunt state:\n${liveStr}`);
    if (findingsStr) parts.push(`Current findings:\n${findingsStr}`);
    return `\n\n--- LIVE HUNT CONTEXT ---\n${parts.join("\n\n")}\n--- END CONTEXT ---`;
  } catch {
    return "";
  }
}

// POST /chat — send a message, get a response
router.post("/", async (req: Request, res: Response) => {
  const { message, history = [] } = req.body as { message: string; history?: ChatMessage[] };
  if (!message || typeof message !== "string" || message.trim().length === 0) {
    return res.status(400).json({ error: "message required" });
  }

  // Build conversation context string from recent history
  const historyText = (history as ChatMessage[])
    .slice(-6)
    .map(m => `${m.role === "user" ? "User" : "Assistant"}: ${m.content}`)
    .join("\n");
  const userMsg = historyText
    ? `${historyText}\n\nUser: ${message.trim()}`
    : message.trim();

  // Parse + execute any [CMD: {...}] sentinel the model produced.
  async function withExecution(raw: string): Promise<{ display: string; executed: ExecutionResult | null }> {
    let executed: ExecutionResult | null = null;
    let executionError: string | null = null;
    const plan = extractCommandPlan(raw);
    if (plan) {
      try {
        executed = await executeCommandPlan(plan);
      } catch (e: unknown) {
        executionError = String((e as Error)?.message || e).slice(0, 200);
        logger.warn("[Chat] command execution failed", { err: executionError });
      }
    }
    const clean = stripCommandBlock(raw);
    const display = executionError ? `${clean}\n\n⚠ Command blocked: ${executionError}`.trim() : clean;
    return { display, executed };
  }

  // Primary: Claude SDK (Haiku) with live hunt context — doesn't count against
  // per-hunt budget (no sessionId) since this is operator chat, not engine calls.
  if (ClaudeClient.isAvailable()) {
    try {
      const huntCtx = await loadHuntContext();
      const sys = SYSTEM_PROMPT + huntCtx;
      const raw = await ClaudeClient.oneShot(sys, userMsg);
      const { display, executed } = await withExecution(raw);
      logger.debug("[Chat] Claude Haiku responded", { msgLen: message.length, huntCtx: huntCtx.length > 0 });
      return res.json({ response: display, model: "claude-haiku-4-5", executed });
    } catch (err) {
      logger.warn("[Chat] Claude SDK failed, falling back to Ollama", { err: String(err) });
    }
  }

  // Retry: ModelRouter.chat() (also Claude Haiku under the hood — there is no
  // Ollama tier anymore) in case the primary call above hit a transient error
  // even though Claude was reported available.
  try {
    const prompt = [SYSTEM_PROMPT, historyText, `User: ${message.trim()}`, `Assistant:`]
      .filter(Boolean).join("\n\n");
    const capped = prompt.length > 8000 ? prompt.slice(-8000) : prompt;
    const raw = await modelRouter.chat(capped);
    const { display, executed } = await withExecution(raw);
    // Same Haiku tier as the primary path above — modelRouter.getModels()
    // returns a static capability list, not the model actually used, so
    // report the real one instead of mislabeling this as "claude-sonnet".
    return res.json({ response: display, model: "claude-haiku-4-5", executed });
  } catch (err) {
    const msg = String(err);
    logger.warn("[Chat] model error", { err: msg });
    return res.status(503).json({
      error: msg.includes("ClaudeUnavailableError") || msg.includes("Claude unavailable")
        ? "Claude unavailable. Check that ANTHROPIC_API_KEY is set correctly."
        : `Model error: ${msg.slice(0, 200)}`,
    });
  }
});

// GET /chat/status — check if any model is reachable
router.get("/status", async (_req: Request, res: Response) => {
  if (ClaudeClient.isAvailable()) {
    return res.json({ available: true, models: ["claude-haiku-4-5"] });
  }
  try {
    const models = await modelRouter.getModels();
    return res.json({ available: models.length > 0, models });
  } catch {
    return res.json({ available: false, models: [] });
  }
});

export default router;
