/**
 * Dispatch Tool — the mandatory external-tool-execution chokepoint.
 *
 * Every invocation of an offensive security binary (nmap, ffuf, nuclei,
 * sqlmap, gobuster, whatweb, ...) must go through dispatchTool(). Raw
 * `exec`/`execSync`, or a `spawn` call with its shell option turned on —
 * anything that runs a command through a shell — is disallowed outside this
 * module; the CI import-guard (see scripts/check-tool-exec.ts, Phase 2)
 * fails the build if it finds one.
 *
 * This is the third of three egress chokepoints, mirroring scoped-http.ts
 * (Node HTTP) and scoped-browser-route.ts (Playwright browser contexts).
 * It exists because a 2026-07-21 audit found FIVE call sites invoking these
 * same tools while bypassing ScopeGuard entirely — and while auditing those,
 * a live remote-code-execution chain: lib/orchestration/layer5-meta-agents.ts
 * harvests href/src/action values out of a TARGET's own HTML with no
 * shell-metacharacter filtering, persists them into missionMemory, and
 * re-dispatches them next agent cycle into whatweb/nikto/nuclei/sqlmap/
 * metasploit/hydra/hashcat via shell-string exec() with no or weak escaping.
 * A hostile bounty target could run arbitrary commands on the operator's own
 * machine through this platform's ordinary recon->crawl->scan cycle. That
 * chain is stopgapped (commit 812cf40) pending migration to this module.
 *
 * Design constraints (why this shape, not another):
 *
 * 1. Array args, never a shell. The signature takes a pre-tokenized `args`
 *    array — there is no code path in this module that concatenates a
 *    command string or turns a shell option on. (Dispatches via `spawn`
 *    with stdin explicitly closed rather than `execFile` — see
 *    execFileNoStdin()'s own comment for why.) This is what makes shell
 *    injection structurally impossible here, not just escaped: an escaping
 *    bug (as found in layer5-meta-agents.ts's double-quote-only sqlmap call)
 *    can't recur because there's never a shell to escape *for*.
 *
 * 2. execFile + array args stops shell injection but NOT argument injection
 *    — a value that looks like a flag (leading "-") can still be reparsed
 *    by the TOOL's own arg parser rather than treated as positional data.
 *    Concretely: `new URL("http://--evil-flag.example.com").hostname` is the
 *    literal string "--evil-flag.example.com" (confirmed — WHATWG URL does
 *    not enforce DNS label rules), so a bare `{domain}` placeholder token
 *    can become a value most getopt-style CLIs will treat as a long option.
 *    substituteTemplate() rejects any token that is PURELY a placeholder
 *    (e.g. exactly "{url}" or "{domain}", no surrounding literal text) whose
 *    substituted value starts with "-". Tokens with surrounding literal
 *    text (e.g. "-u{url}" is not a bare placeholder — such templates should
 *    not exist, and buildCommandFromTemplate's own convention of one
 *    placeholder per token is preserved here) are unaffected.
 *
 * 3. isInScope() is checked HERE, immediately before exec, not left to the
 *    caller. This closes the CampaignOrchestrator TOCTOU gap (params.targetUrl
 *    scope-checked once at campaign start, never re-checked before the later
 *    solver-pool supplement dispatch) and the routes/tools.ts /:id/test gap
 *    (a private-IP regex blocklist, not ScopeGuard) structurally: no caller
 *    of this module can skip the check, because it isn't theirs to skip.
 *
 * Mirrors the pattern already proven safe in agents/HunterEngine.ts:
 * buildCommandFromTemplate() (:741-761, tokenize-then-substitute, URL-
 * validated) and runTool() (:3299-3374, execFileAsync with an args array).
 */
import { spawn } from "child_process";
import { ScopeGuard } from "../../middleware/scopeGuard";
import { checkAutomatedScanningAuthorization, checkFuzzingAuthorization } from "../../agents/ActionPolicyGate";
import { hasShellUnsafeChars, hasShellUnsafeUrlChars } from "./shell-safe";
import logger from "../../utils/logger";

const guard = ScopeGuard.getInstance();

class ToolExecError extends Error {
  constructor(message: string, public readonly stdout: string, public readonly stderr: string) {
    super(message);
    this.name = "ToolExecError";
  }
}

/** spawn() instead of execFile(): execFile's default stdin is inherited from
 *  this process, and at least one real tool (nuclei, confirmed live) reads
 *  from stdin when spawned non-interactively and hangs forever waiting for
 *  EOF that never comes — invisible in a terminal (which sends EOF/closes on
 *  its own) but real under a server process, where the tool would otherwise
 *  only ever exit via timeoutMs's SIGTERM. stdio: ["ignore", ...] closes
 *  stdin immediately so any such read fails/returns right away instead. */
function execFileNoStdin(
  file: string, args: string[], opts: { timeout: number; env: NodeJS.ProcessEnv },
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { env: opts.env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill("SIGTERM");
      reject(new ToolExecError(`Command timed out after ${opts.timeout}ms: ${file} ${args.join(" ")}`, stdout, stderr));
    }, opts.timeout);

    child.stdout?.on("data", (d) => { stdout += d; });
    child.stderr?.on("data", (d) => { stderr += d; });
    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(new ToolExecError(`Command failed (exit ${code}): ${file} ${args.join(" ")}`, stdout, stderr));
      }
    });
  });
}

export class ToolOutOfScopeError extends Error {
  constructor(public readonly target: string, public readonly reason: string) {
    super(`Out of scope: ${target} — ${reason}`);
    this.name = "ToolOutOfScopeError";
  }
}

export class ToolTargetInvalidError extends Error {
  constructor(public readonly target: string) {
    super(`Not a valid http(s) URL: ${target}`);
    this.name = "ToolTargetInvalidError";
  }
}

export class ToolArgumentInjectionError extends Error {
  constructor(public readonly token: string, public readonly substituted: string) {
    super(`Substituted value for placeholder "${token}" is flag-shaped (starts with "-"): "${substituted}" — refusing to pass it as a bare argument`);
    this.name = "ToolArgumentInjectionError";
  }
}

export class ToolShellUnsafeError extends Error {
  constructor(public readonly kind: "domain" | "url", public readonly value: string) {
    super(`${kind === "domain" ? "Hostname" : "URL"} contains a shell metacharacter, refusing to substitute it into a tool argument: "${value}"`);
    this.name = "ToolShellUnsafeError";
  }
}

export class ToolPolicyBlockedError extends Error {
  constructor(public readonly tool: string, public readonly reason: string) {
    super(`Tool dispatch blocked by program policy: ${tool} — ${reason}`);
    this.name = "ToolPolicyBlockedError";
  }
}

// 2026-07-23 (blocker #3, Test 0): dispatchTool() is the proven SOLE
// shell-exec funnel (check-tool-exec.ts) — every one of its ~12 callers
// (SolverPool, the orchestration layers, bounty-intelligence, routes/tools,
// routes/bounty, ...) reaches exec through here, structurally, by the same
// mechanism that makes shell injection impossible in this module. The
// behavioral-rules policy gate built for HunterEngine.runTool() only
// covered runTool()'s own SEPARATE execFileAsync path (HunterEngine.ts:3673
// — a second, independently-safe-but-separate exec path that predates
// dispatchTool() and is check-tool-exec-allowlisted for that reason, not
// exempted from POLICY). SolverPool and every other dispatchTool() caller
// bypassed the policy gate entirely until this check — verified live via
// the CI guard below, which would have flagged this the moment it existed.
const FUZZING_TOOLS = new Set(["ffuf", "gobuster", "feroxbuster", "wfuzz", "arjun"]);

export interface DispatchToolParams {
  /** The binary to execFile — e.g. "nmap", "sqlmap", "nikto". Never a shell string. */
  tool: string;
  /** The URL dispatchTool scope-checks and derives {url}/{domain} substitutions from. */
  target: string;
  /** Pre-tokenized argument template. Each element may contain {url}/{domain}
   *  placeholders (one placeholder per token, matching buildCommandFromTemplate's
   *  convention) or be a literal flag/value with no placeholder at all. */
  args: string[];
  programId: number | null | undefined;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
}

export interface DispatchToolResult {
  stdout: string;
  stderr: string;
  durationMs: number;
  bin: string;
  args: string[];
}

/** Tokenize-then-substitute, mirroring HunterEngine.buildCommandFromTemplate —
 *  but with the argument-injection guard added: a token that is PURELY a
 *  placeholder must not resolve to a flag-shaped value. */
function substituteArgs(args: string[], safeUrl: string, domain: string): string[] {
  return args.map(tok => {
    const isBarePlaceholder = tok === "{url}" || tok === "{domain}";
    const substituted = tok.replace(/\{url\}/g, safeUrl).replace(/\{domain\}/g, domain);
    if (isBarePlaceholder && substituted.startsWith("-")) {
      throw new ToolArgumentInjectionError(tok, substituted);
    }
    return substituted;
  });
}

export async function dispatchTool(params: DispatchToolParams): Promise<DispatchToolResult> {
  const { tool, target, args, programId, timeoutMs = 60_000, env } = params;

  // 1. Scope check — immediately before exec, not left to the caller.
  const { allowed, reason } = await guard.isInScope(target, programId);
  if (!allowed) {
    logger.warn("[dispatchTool] Blocked out-of-scope tool dispatch", { tool, target, programId, reason });
    throw new ToolOutOfScopeError(target, reason);
  }

  // 1b. Behavioral-rules policy check (2026-07-23, blocker #3) — same
  // isActionAllowed()-backed gate as HunterEngine.runTool()'s own copy,
  // enforced HERE too since this is a structurally separate physical exec
  // path (see the module-level comment above FUZZING_TOOLS). Conservative
  // per the earlier amendment: ALL of nuclei is gated as scanning, not
  // per-template-mode.
  if (tool === "nuclei") {
    const auth = await checkAutomatedScanningAuthorization(target, programId ?? undefined);
    if (!auth.allowed) {
      logger.warn("[dispatchTool] Blocked by automated-scanning policy", { tool, target, programId, reason: auth.reason });
      throw new ToolPolicyBlockedError(tool, auth.reason ?? "automated scanning not authorized");
    }
  } else if (FUZZING_TOOLS.has(tool)) {
    const auth = await checkFuzzingAuthorization(target, programId ?? undefined);
    if (!auth.allowed) {
      logger.warn("[dispatchTool] Blocked by fuzzing policy", { tool, target, programId, reason: auth.reason });
      throw new ToolPolicyBlockedError(tool, auth.reason ?? "fuzzing not authorized");
    }
  }

  // 2. URL-validate the target before it's substituted into anything.
  let safeUrl: string;
  let domain: string;
  try {
    const u = new URL(target);
    if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("non-http(s) protocol");
    safeUrl = u.toString();
    domain = u.hostname;
  } catch {
    throw new ToolTargetInvalidError(target);
  }

  // 2b. Shell-metacharacter guard — closes the residual one level down from
  // execFile/array-args: several dispatched tools are themselves shell
  // SCRIPTS (reconftw.sh, testssl.sh, zap.sh, ...) that may interpolate
  // their own argument unquoted internally. See lib/net/shell-safe.ts.
  if (hasShellUnsafeChars(domain)) {
    throw new ToolShellUnsafeError("domain", domain);
  }
  if (hasShellUnsafeUrlChars(safeUrl)) {
    throw new ToolShellUnsafeError("url", safeUrl);
  }

  // 3. Tokenize-and-substitute with the argument-injection guard.
  const substitutedArgs = substituteArgs(args, safeUrl, domain);

  const start = Date.now();
  const { stdout, stderr } = await execFileNoStdin(tool, substitutedArgs, {
    timeout: timeoutMs,
    env: env ?? process.env,
  });
  const durationMs = Date.now() - start;

  logger.info("[dispatchTool] Tool dispatched", { tool, target, args: substitutedArgs, durationMs });

  return { stdout, stderr, durationMs, bin: tool, args: substitutedArgs };
}
