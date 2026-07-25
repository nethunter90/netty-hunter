/**
 * Handoff C, Phase 1 — dashboard reconciliation anchor.
 *
 * Makes a small, KNOWN set of real Claude API calls directly through
 * ClaudeClient (the sole accounting primitive), logging exact in-code
 * token/dollar totals for each call. Purpose: give a human a narrow,
 * precise window to check against the Anthropic console billing/usage
 * dashboard, to validate costForUsage()'s cache-token pricing correction
 * against real billed amounts — something this script cannot do itself
 * (no dashboard API access). Deliberately tiny (a handful of short calls)
 * to keep real-money cost minimal while still producing cache read/write
 * activity (same system prompt reused across calls -> cache hits after
 * the first call) worth reconciling.
 *
 * Run: npx tsx scripts/budget-reconciliation-anchor.ts
 */
import "dotenv/config";
import { ClaudeClient } from "../src/lib/claude-client";

const SESSION_ID = "budget-reconciliation-anchor-" + Date.now();

async function main() {
  console.log(`[anchor] session key: ${SESSION_ID}`);
  console.log(`[anchor] wall-clock start (UTC): ${new Date().toISOString()}`);

  const systemPrompt = "You are a terse assistant. Answer in one short sentence.";

  for (let i = 1; i <= 3; i++) {
    const start = Date.now();
    const answer = await ClaudeClient.oneShot(systemPrompt, `Say the number ${i} and nothing else.`, SESSION_ID);
    const durationMs = Date.now() - start;
    const spend = ClaudeClient.getSpend(SESSION_ID);
    console.log(`[anchor] call ${i}: "${answer.trim()}" (${durationMs}ms) | cumulative: callCount=${spend.callCount} inputTokens=${spend.inputTokens} outputTokens=${spend.outputTokens} costUsd=${spend.costUsd.toFixed(6)}`);
  }

  const final = ClaudeClient.getSpend(SESSION_ID);
  console.log(`[anchor] wall-clock end (UTC): ${new Date().toISOString()}`);
  console.log(`[anchor] FINAL in-code total: callCount=${final.callCount} inputTokens=${final.inputTokens} outputTokens=${final.outputTokens} costUsd=${final.costUsd.toFixed(6)}`);
  console.log(`[anchor] Check the Anthropic console usage dashboard for this exact wall-clock window to reconcile.`);
}

main().catch(err => {
  console.error("[anchor] failed:", err);
  process.exit(1);
});
