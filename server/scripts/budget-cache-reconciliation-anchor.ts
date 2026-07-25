/**
 * Handoff C, Phase 1 — cache-token reconciliation anchor (v2, LEA-free).
 *
 * v1 borrowed LogicExploitAgent's SYSTEM_BLOCK as a ready-made large prefix.
 * Two problems with that shortcut, both dodged here: (1) importing
 * LogicExploitAgent.ts pulls in Playwright + a chain of other modules and
 * hung intermittently in a bare tsx context — a real, separate finding
 * (filed, not fixed, not part of this handoff) — and (2) SYSTEM_BLOCK is
 * only ~1970 chars / ~490 tokens, under the ~1024-token minimum cacheable-
 * prefix floor, so even a clean import could never have produced a cache
 * entry. This version constructs its own oversized (2000+ token) stable
 * prefix inline, marks it cache_control:ephemeral directly, and imports
 * nothing but ClaudeClient.
 *
 * Call 1 (cold): expect cache_creation_input_tokens > 0, cache_read == 0.
 * Call 2 (within the 5-minute TTL, identical prefix): expect
 * cache_read_input_tokens > 0, cache_creation == 0. Both go through
 * ClaudeClient.createMessage() -> costForUsage(), so the printed cost is
 * exactly what the corrected cache-pricing multipliers compute — the
 * number to check against the Anthropic dashboard's cache line items.
 *
 * Run: npx tsx scripts/budget-cache-reconciliation-anchor.ts
 */
import "dotenv/config";
import { ClaudeClient, getReasonModel } from "../src/lib/claude-client";

const SESSION_ID = "budget-cache-anchor-v2-" + Date.now();

// A single repeated sentence, comfortably over the ~1024-token cacheable-
// prefix floor. Deterministic content (not random) so cache_control's
// exact-prefix-match requirement is satisfied identically across calls 1 and 2.
const FILLER_SENTENCE = "The quick brown fox jumps over the lazy dog near the riverbank at dawn. ";
const LARGE_STABLE_PREFIX = FILLER_SENTENCE.repeat(180); // ~180*74 = ~13.3K chars, well over 2000 tokens

async function main() {
  console.log(`[cache-anchor-v2] session key: ${SESSION_ID}`);
  console.log(`[cache-anchor-v2] prefix size: ${LARGE_STABLE_PREFIX.length} chars (~${Math.round(LARGE_STABLE_PREFIX.length / 4)} tokens estimate)`);
  console.log(`[cache-anchor-v2] wall-clock start (UTC): ${new Date().toISOString()}`);

  const systemBlock = [
    { type: "text" as const, text: LARGE_STABLE_PREFIX, cache_control: { type: "ephemeral" as const } },
  ];

  for (let i = 1; i <= 2; i++) {
    const start = Date.now();
    const response = await ClaudeClient.createMessage({
      model: getReasonModel(),
      max_tokens: 15,
      system: systemBlock,
      messages: [{ role: "user", content: `This is reconciliation call ${i}. Reply with just the word "ack".` }],
    }, SESSION_ID, 3500);
    const durationMs = Date.now() - start;
    const u = response.usage;
    console.log(`[cache-anchor-v2] call ${i} (${durationMs}ms): input=${u.input_tokens} cache_creation=${u.cache_creation_input_tokens ?? 0} cache_read=${u.cache_read_input_tokens ?? 0} output=${u.output_tokens}`);
  }

  const final = ClaudeClient.getSpend(SESSION_ID);
  console.log(`[cache-anchor-v2] wall-clock end (UTC): ${new Date().toISOString()}`);
  console.log(`[cache-anchor-v2] FINAL in-code total: callCount=${final.callCount} inputTokens=${final.inputTokens} outputTokens=${final.outputTokens} costUsd=${final.costUsd.toFixed(6)}`);
  console.log(`[cache-anchor-v2] Check the Anthropic console usage dashboard for this exact wall-clock window's cache read/write line items to reconcile.`);
  process.exit(0);
}

main().catch(err => {
  console.error("[cache-anchor-v2] failed:", err);
  process.exit(1);
});
