/**
 * ClaudeBridge — invokes the Claude Code CLI as a subprocess for hard reasoning.
 *
 * When the local model (Ollama) fails or produces low-quality output, the hunt
 * engine calls ClaudeBridge.reason() which runs `claude -p "<prompt>"` and returns
 * the response. This gives the hunt loop frontier-model reasoning without any API
 * integration code — just a shell invocation against the already-installed CLI.
 *
 * The bridge also writes a task log to context/claude-tasks.jsonl so you can see
 * exactly what was asked and what Claude answered during a hunt.
 */
import { execFile } from "child_process";
import { promises as fs } from "fs";
import path from "path";
import logger from "../utils/logger";

const CONTEXT_DIR = path.join(process.cwd(), "context");
const TASK_LOG = path.join(CONTEXT_DIR, "claude-tasks.jsonl");

async function ensureContextDir(): Promise<void> {
  await fs.mkdir(CONTEXT_DIR, { recursive: true });
}

function execFileAsync(
  cmd: string,
  args: string[],
  opts: { timeout?: number; cwd?: string }
): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { ...opts, maxBuffer: 1024 * 1024 * 10 }, (err, stdout, stderr) => {
      if (err) reject(new Error(`${err.message}\nstderr: ${stderr?.slice(0, 500)}`));
      else resolve(stdout.trim());
    });
  });
}

export class ClaudeBridge {
  private static _available: boolean | null = null;

  /** Check once whether `claude` CLI is installed and on PATH. */
  static async isAvailable(): Promise<boolean> {
    if (this._available !== null) return this._available;
    try {
      await execFileAsync("claude", ["--version"], { timeout: 5000 });
      this._available = true;
      logger.info("[ClaudeBridge] claude CLI detected — frontier reasoning available");
    } catch {
      this._available = false;
      logger.info("[ClaudeBridge] claude CLI not found — falling back to local model");
    }
    return this._available;
  }

  /**
   * Send a single prompt to Claude Code non-interactively.
   * Uses `claude -p` which runs one prompt and exits — safe to call from async loops.
   */
  static async reason(prompt: string, timeoutMs = 120_000): Promise<string> {
    await ensureContextDir();
    const start = Date.now();

    const response = await execFileAsync(
      "claude",
      ["--print", "-p", prompt],
      { timeout: timeoutMs, cwd: process.cwd() }
    );

    // Log to task file so the terminal/Claude Code can review what was asked
    const entry = {
      ts: new Date().toISOString(),
      durationMs: Date.now() - start,
      promptSnippet: prompt.slice(0, 300),
      responseSnippet: response.slice(0, 300),
    };
    await fs.appendFile(TASK_LOG, JSON.stringify(entry) + "\n").catch(() => {});

    return response;
  }

  /**
   * Reason with live hunt context automatically prepended.
   * Reads context/hunt-live.json so Claude has full situational awareness.
   */
  static async reasonWithHuntContext(task: string, timeoutMs = 120_000): Promise<string> {
    let contextPrefix = "";
    try {
      const liveCtx = await fs.readFile(
        path.join(CONTEXT_DIR, "hunt-live.json"),
        "utf-8"
      );
      contextPrefix = `Current hunt state:\n${liveCtx}\n\n`;
    } catch { /* context file may not exist yet — proceed without it */ }

    return this.reason(contextPrefix + task, timeoutMs);
  }

  /** Reset availability cache — useful after installing claude CLI mid-session. */
  static resetAvailabilityCache(): void {
    this._available = null;
  }
}
