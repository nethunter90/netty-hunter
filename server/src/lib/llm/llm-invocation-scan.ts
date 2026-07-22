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
 * Detects, outside the ALLOWLIST:
 *   - any RUNTIME import/require of @anthropic-ai/sdk (named, default,
 *     namespace, dynamic import, require) — `import type` is allowed (no
 *     runtime construction capability, used for SDK type references only,
 *     e.g. LogicExploitAgent.ts's Anthropic.Message/MessageParam types).
 *   - direct SDK-client construction, and raw messages-create/messages-
 *     stream calls on any binding — belt-and-suspenders for a namespace-
 *     imported or aliased SDK reference.
 *
 * Pure scan logic — no filesystem walking here (that's
 * scripts/check-llm-bypass.ts, the CLI wrapper).
 */

export const ALLOWLIST: Record<string, string> = {
  "lib/claude-client.ts": "the chokepoint itself — the only place the Anthropic SDK client is constructed and its message-creation endpoint is called directly",
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

  return violations;
}
