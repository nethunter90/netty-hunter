/**
 * CI import-guard for the LLM-spend chokepoint.
 *
 * Every Anthropic API call in this process must go through
 * ClaudeClient.createMessage() (server/src/lib/claude-client.ts) — the one
 * place dollar/token spend is recorded and the per-hunt budget cap is
 * enforced. A 2026-07-22 audit found LogicExploitAgent held its own
 * Anthropic SDK client instance and called the raw messages-create endpoint
 * directly — tryConsumeBudget()/paceTokens() were consulted correctly beforehand, but
 * the actual spend never touched ClaudeClient, so it was invisible to any
 * dollar accounting built on top of it. That was the highest-volume LLM
 * spend path in the codebase (up to 16 calls per business_logic/idor
 * hypothesis) and the exact shape of bypass this guard exists to catch
 * before it recurs — the same "chokepoint I named doesn't exist yet" lesson
 * as the axios/tool-exec guards.
 *
 * 2026-07-25 (handoff C, Phase 2 rewrite): the ORIGINAL version of this
 * guard only knew the SDK shape (SDK-client construction / messages-create call) and
 * only walked src/ — both were real gaps. The CLI-bridge $0-cost bug
 * (ClaudeBridge.reason(), a subprocess exec of the model CLI binary) was the exact same
 * category of bypass — a real Claude call outside ClaudeClient's accounting
 * — in a shape this guard couldn't see at all, and it was fixed in
 * ModelRouter.ts without ever tripping this guard. Now detects BOTH
 * mechanisms:
 *   - SDK shape (unchanged): runtime import of @anthropic-ai/sdk, direct
 *     client construction, direct messages-create/messages-stream calls.
 *   - Subprocess-bridge shape (new): execFile/execFileSync/spawn/spawnSync
 *     invoking a known model-CLI binary ("claude", extend KNOWN_MODEL_CLIS
 *     if a sibling bridge is ever added) with its first argument.
 *
 * Allowlist discipline: this project's other three import-guards
 * (check-scope-egress, check-tool-exec, check-rl-bypass) all use a small,
 * human-reviewed ALLOWLIST with a one-line justification per entry, not an
 * automated reachability graph from the live engine's entry points. Same
 * choice here, for the same reason — a reachability analyzer is a second,
 * much larger system to build and trust, and this project already has a
 * working, auditable convention. The three standalone dev harnesses
 * (gate1-pacer-harness.ts, gate1-cache-harness.ts, expand-prompts.mjs)
 * construct their own SDK client legitimately — verified NOT referenced
 * anywhere in src/ or package.json (handoff C Phase 0), so they cannot fire
 * during a live hunt — and are allowlisted explicitly below, the same way
 * scoped-http.ts's webhook/OSINT callers are allowlisted in
 * check-scope-egress.ts. Widening SRC_ROOT to scripts/ without this
 * allowlist would have cried wolf on all three.
 *
 * Pure scan logic — no filesystem walking here (that's
 * scripts/check-llm-bypass.ts, the CLI wrapper).
 */

export const ALLOWLIST: Record<string, string> = {
  "lib/claude-client.ts": "the chokepoint itself — the only place the Anthropic SDK client is constructed and its message-creation endpoint is called directly",
  "../scripts/gate1-pacer-harness.ts": "standalone dev harness for pacer verification — not imported/referenced anywhere in src/ or package.json, cannot run during a live hunt (handoff C Phase 0)",
  "../scripts/gate1-cache-harness.ts": "standalone dev harness for cache verification — same reachability argument as gate1-pacer-harness.ts",
  "../scripts/expand-prompts.mjs": "standalone one-off dataset-expansion script, not TypeScript, never imported from src/ — same reachability argument",
  "../scripts/budget-reconciliation-anchor.ts": "standalone dashboard-reconciliation harness (handoff C Phase 1) — calls ClaudeClient itself, not the SDK directly; allowlisted for the import of ClaudeClient's own file, not a bypass",
  "../scripts/budget-cache-reconciliation-anchor.ts": "same as budget-reconciliation-anchor.ts",
  "lib/claude-bridge.ts": "the CLI-bridge chokepoint itself — the only place the model CLI binary is legitimately invoked; its spend is attributed via ClaudeClient.recordExternalCall() (see ModelRouter.ts)",
};

const RUNTIME_IMPORT_PATTERNS = [
  /^\s*import\s+(?!type\b)\w+\s*(?:,\s*\{[^}]*\})?\s*from\s*["']@anthropic-ai\/sdk["']/m, // default (or default+named)
  /^\s*import\s+(?!type\b)\*\s*as\s+\w+\s*from\s*["']@anthropic-ai\/sdk["']/m,            // namespace
  /^\s*import\s+(?!type\b)\{[^}]*\}\s*from\s*["']@anthropic-ai\/sdk["']/m,                // named only
  /require\(\s*["']@anthropic-ai\/sdk["']\s*\)/,                                          // require
  /import\(\s*["']@anthropic-ai\/sdk["']\s*\)/,                                           // dynamic import
];

const CONSTRUCT_PATTERN = /\bnew\s+Anthropic\s*\(/;
const DIRECT_CALL_PATTERN = /\.messages\.(create|stream)\s*\(/;

// Subprocess-bridge shape: execFile/spawn invoking a known model-CLI binary
// as its first argument. Matches any identifier CONTAINING "execFile" or
// "spawn", not just the four bare child_process exports — confirmed live
// necessary, not theoretical: claude-bridge.ts (the real, legitimate bridge
// this guard needs to recognize) calls its own execFileAsync() wrapper, not
// execFile() directly, and the exact-name-only version of this pattern
// missed it entirely (caught by this file's own test suite, not by
// inspection — see llm-bypass-guard.test.ts). If the legitimate bridge
// wraps execFile in a differently-named helper, an illegitimate second
// bridge doing the same is exactly the shape this guard exists to catch;
// requiring the LITERAL name "execFile" would have missed both. Belt-and-
// suspenders like DIRECT_CALL_PATTERN above — matches the call shape
// textually rather than tracking import bindings, same precision level
// this project's other guards already operate at (see check-scope-egress.ts's
// own line-window comments for the same tradeoff, made explicitly).
const KNOWN_MODEL_CLIS = ["claude"]; // extend if a sibling CLI-bridge is ever added
const MODEL_CLI_ALTERNATION = KNOWN_MODEL_CLIS.map(b => b.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
const SUBPROCESS_BRIDGE_PATTERN = new RegExp(
  `\\b\\w*(?:execFile|spawn)\\w*\\s*\\(\\s*["'](${MODEL_CLI_ALTERNATION})["']`
);

export interface LlmBypassViolation {
  reason: string;
}

export function scanContent(content: string, relPath: string): LlmBypassViolation[] {
  if (relPath in ALLOWLIST) return [];

  const violations: LlmBypassViolation[] = [];

  for (const pattern of RUNTIME_IMPORT_PATTERNS) {
    if (pattern.test(content)) {
      violations.push({ reason: "imports @anthropic-ai/sdk at runtime — use ClaudeClient.createMessage() (or `import type` if only SDK types are needed)" });
      break;
    }
  }

  if (CONSTRUCT_PATTERN.test(content)) {
    violations.push({ reason: "constructs an Anthropic SDK client instance directly — it must only ever be instantiated inside ClaudeClient" });
  }

  if (DIRECT_CALL_PATTERN.test(content)) {
    violations.push({ reason: "calls the SDK's message-creation/streaming endpoint directly — route through ClaudeClient.createMessage() so spend is recorded and the budget cap is enforced" });
  }

  if (SUBPROCESS_BRIDGE_PATTERN.test(content)) {
    violations.push({ reason: "invokes a model CLI binary (execFile/spawn) directly — this is the exact shape that caused the CLI-bridge $0-cost bug; route through ClaudeBridge (lib/claude-bridge.ts) so spend is attributed via ClaudeClient.recordExternalCall()" });
  }

  return violations;
}
