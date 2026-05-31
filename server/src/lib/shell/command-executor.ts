/**
 * Command Executor — runs commands the AI emits via a `[CMD: {...}]` sentinel
 * in chat replies. Two shapes supported:
 *
 *   Single:    [CMD: { "bin": "ip", "args": ["addr"], "description": "..." }]
 *   Multi-step:[CMD: { "steps": [{...}, {...}], "description": "..." }]
 *
 * GUI apps launch detached + unref'd (server doesn't block). CLI tools run
 * sequentially with execFile (no shell), stdout/stderr captured and capped.
 * Three catastrophic patterns are blocked (rm -rf /, dd to /dev/sdX, mkfs).
 * Everything else is allowed — this is the operator's own Kali box.
 */
import { execFile, spawn } from "child_process";
import { promisify } from "util";
import logger from "../../utils/logger";

const execFileAsync = promisify(execFile);

export interface CommandStep {
  bin: string;
  args?: string[];
}

export interface CommandPlan {
  steps: CommandStep[];
  detached: boolean;
  description: string;
}

export interface StepOutput {
  command: string;
  stdout: string;
  stderr: string;
  exitCode: number;
  error?: string;
}

export interface ExecutionResult {
  plan: CommandPlan;
  outputs: StepOutput[];
  pid?: number;
}

// Apps that should launch in the background and return immediately
const GUI_APPS = new Set([
  "wireshark", "burpsuite", "burp", "zaproxy", "owasp-zap", "zap.sh",
  "firefox", "chromium", "google-chrome", "brave-browser",
  "metasploit", "msfconsole", "armitage",
  "ghidra", "ghidra.sh", "ida", "ida64", "ida-pro", "cutter", "binaryninja",
  "ettercap-graphical", "wireshark-gtk",
  "gnome-terminal", "xterm", "konsole", "alacritty", "kitty", "tilix", "terminator",
  "nautilus", "code", "code-insiders", "subl", "sublime_text",
]);

// Output caps (per step) so chat doesn't get drowned in giant output
const STDOUT_CAP = 8 * 1024;  // 8 KB
const STDERR_CAP = 2 * 1024;  // 2 KB
const STEP_TIMEOUT_MS = 30_000;

const CMD_BLOCK_RE = /\[CMD:\s*(\{[\s\S]*?\})\s*\]/;

/** Pull a `[CMD: { ... }]` block out of an AI response, or return null. */
export function extractCommandPlan(aiResponse: string): CommandPlan | null {
  if (typeof aiResponse !== "string") return null;
  const m = aiResponse.match(CMD_BLOCK_RE);
  if (!m) return null;
  let parsed: any;
  try {
    parsed = JSON.parse(m[1]);
  } catch (e) {
    logger.warn("[CommandExecutor] Failed to parse CMD block", { err: String(e) });
    return null;
  }

  // Normalize single → steps array
  let steps: CommandStep[];
  if (Array.isArray(parsed.steps) && parsed.steps.length > 0) {
    steps = parsed.steps.map((s: any) => ({
      bin: String(s.bin || ""),
      args: Array.isArray(s.args) ? s.args.map((a: any) => String(a)) : [],
    }));
  } else if (typeof parsed.bin === "string") {
    steps = [{ bin: parsed.bin, args: Array.isArray(parsed.args) ? parsed.args.map((a: any) => String(a)) : [] }];
  } else {
    return null;
  }

  steps = steps.filter(s => s.bin.length > 0);
  if (steps.length === 0) return null;

  const detached = Boolean(parsed.detached) || (steps.length === 1 && GUI_APPS.has(steps[0].bin.toLowerCase()));
  const description = String(parsed.description || `Run ${steps.map(s => s.bin).join(" → ")}`).slice(0, 200);

  return { steps, detached, description };
}

/** Strip the CMD block from the AI's text before rendering to the user. */
export function stripCommandBlock(text: string): string {
  if (typeof text !== "string") return "";
  return text.replace(CMD_BLOCK_RE, "").trim();
}

/**
 * Catastrophic patterns we refuse to run even on the operator's own box.
 * Everything else (including powerful pentest tools) is allowed.
 */
function assertNotCatastrophic(step: CommandStep): void {
  const bin = step.bin.toLowerCase();
  const args = (step.args || []).map(a => a.toLowerCase());

  // rm -rf / or rm -rf /*
  if (bin === "rm" && args.some(a => a === "-rf" || a === "-fr" || a === "--recursive" || a.startsWith("-r"))) {
    const targets = args.filter(a => !a.startsWith("-"));
    if (targets.some(t => t === "/" || t === "/*" || t === "/." || t === "~" || t === "$HOME")) {
      throw new Error("Refused: rm -rf on filesystem root");
    }
  }

  // dd of=/dev/sdX (whole-disk write)
  if (bin === "dd") {
    if (args.some(a => /^of=\/dev\/(sd|nvme|hd|vd)[a-z]+$/i.test(a))) {
      throw new Error("Refused: dd to a raw block device");
    }
  }

  // mkfs.* /dev/sdX
  if (/^mkfs(\.|$)/.test(bin)) {
    if (args.some(a => /^\/dev\/(sd|nvme|hd|vd)[a-z]+$/i.test(a))) {
      throw new Error("Refused: mkfs on a raw block device");
    }
  }
}

function capOutput(s: string | Buffer | undefined, cap: number): string {
  if (!s) return "";
  const str = typeof s === "string" ? s : s.toString("utf8");
  if (str.length <= cap) return str;
  return str.slice(0, cap) + `\n…[truncated ${str.length - cap} bytes]`;
}

/** Execute a parsed plan. Detached = spawn + unref + return PID. */
export async function executeCommandPlan(plan: CommandPlan): Promise<ExecutionResult> {
  for (const step of plan.steps) {
    assertNotCatastrophic(step);
  }

  // Detached: launch the first step in the background and return.
  if (plan.detached) {
    const [first, ...rest] = plan.steps;
    if (rest.length > 0) {
      logger.warn("[CommandExecutor] Detached plan ignored extra steps", { count: rest.length });
    }
    const child = spawn(first.bin, first.args || [], {
      detached: true,
      stdio: "ignore",
    });
    child.on("error", err => logger.warn("[CommandExecutor] Detached launch error", { bin: first.bin, err: String(err) }));
    child.unref();
    return {
      plan,
      outputs: [{
        command: `${first.bin} ${(first.args || []).join(" ")}`.trim(),
        stdout: "",
        stderr: "",
        exitCode: 0,
      }],
      pid: child.pid,
    };
  }

  // Sequential CLI execution; stop on first non-zero exit.
  const outputs: StepOutput[] = [];
  for (const step of plan.steps) {
    const display = `${step.bin} ${(step.args || []).join(" ")}`.trim();
    try {
      const { stdout, stderr } = await execFileAsync(step.bin, step.args || [], {
        timeout: STEP_TIMEOUT_MS,
        maxBuffer: 4 * 1024 * 1024,
      });
      outputs.push({
        command: display,
        stdout: capOutput(stdout, STDOUT_CAP),
        stderr: capOutput(stderr, STDERR_CAP),
        exitCode: 0,
      });
    } catch (err: any) {
      outputs.push({
        command: display,
        stdout: capOutput(err.stdout, STDOUT_CAP),
        stderr: capOutput(err.stderr, STDERR_CAP),
        exitCode: typeof err.code === "number" ? err.code : 1,
        error: err.killed ? "timed out" : (err.code === "ENOENT" ? `not installed: ${step.bin}` : String(err.message || err).slice(0, 200)),
      });
      break; // stop on first failure
    }
  }
  return { plan, outputs };
}
