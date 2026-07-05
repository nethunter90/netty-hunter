/**
 * Gate 1 live verification harness (Netty Hunter recall-unblock handoff).
 *
 * Exercises the REAL logic_exploit_agent caching objects (SYSTEM_BLOCK, TOOLS,
 * tagRollingCacheBreakpoint) across a realistic multi-turn loop — not a
 * synthetic cold/warm pair. Each turn appends a "messy" tool_result shaped like
 * genuine tool output (embedded ISO timestamps, random UUIDs, varying byte
 * length) to stress-test whether the rolling breakpoint survives content noise
 * the way real curl/nuclei/api_request output would.
 *
 * Run: npx tsx scripts/gate1-cache-harness.ts
 * Requires: ANTHROPIC_API_KEY in the environment (loaded from server/.env).
 */
import "dotenv/config";
import Anthropic from "@anthropic-ai/sdk";
import { randomUUID } from "crypto";
import { SYSTEM_BLOCK, TOOLS, tagRollingCacheBreakpoint } from "../src/agents/LogicExploitAgent";

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// Shapes a tool_result the way the real executeTool() does for api_request —
// JSON with headers (Date, X-Request-Id) and a body — so byte-noise (fresh
// timestamp + UUID every turn) is present exactly where the handoff flagged
// the risk, not sanitized out of the test.
function messyToolResult(toolUseId: string, turn: number): Anthropic.ToolResultBlockParam {
  const body = JSON.stringify({
    status: 200,
    headers: {
      date: new Date().toUTCString(),
      "x-request-id": randomUUID(),
      "content-type": "application/json",
    },
    body: JSON.stringify({
      url: `https://example-target.test/api/resource/${turn}`,
      title: `Resource page ${turn}`,
      text: `Some observed page content for turn ${turn}. `.repeat(20 + turn * 3),
    }),
  });
  return { type: "tool_result", tool_use_id: toolUseId, content: body };
}

async function main() {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error("ANTHROPIC_API_KEY not set — aborting (this harness must hit the live API).");
    process.exit(1);
  }

  const messages: Anthropic.MessageParam[] = [
    {
      role: "user",
      content:
        "HYPOTHESIS:\nVulnerability class: idor\nTarget URL: https://example-target.test/api/resource/1\n" +
        "Reasoning: sequential numeric IDs observed in prior responses.\nConfidence: 70%\n\n" +
        "Follow the reverse loop: state your OBJECTIVE, BLUEPRINT the normal flow first, then DEVIATE to confirm or rule out this vulnerability.",
    },
  ];

  const TURNS = 6; // representative slice of the real ≤16-call loop
  const results: { turn: number; cacheRead: number; cacheCreation: number; inputTokens: number }[] = [];

  for (let turn = 1; turn <= TURNS; turn++) {
    const response = await client.messages.create({
      model: "claude-sonnet-4-6",
      max_tokens: 512,
      system: SYSTEM_BLOCK,
      tools: TOOLS,
      tool_choice: { type: "auto" },
      messages: tagRollingCacheBreakpoint(messages),
    });

    const cacheRead = response.usage.cache_read_input_tokens ?? 0;
    const cacheCreation = response.usage.cache_creation_input_tokens ?? 0;
    const inputTokens = response.usage.input_tokens ?? 0;
    results.push({ turn, cacheRead, cacheCreation, inputTokens });
    console.log(
      `[turn ${turn}] cache_read=${cacheRead} cache_creation=${cacheCreation} input_tokens=${inputTokens} stop_reason=${response.stop_reason}`
    );

    // Append the assistant turn exactly as the real probe() loop does.
    messages.push({ role: "assistant", content: response.content as Anthropic.MessageParam["content"] });

    // Force tool calls to keep the loop growing like a real probe. Every
    // tool_use block in the response needs a tool_result — parallel tool use
    // is on by default, so a single-toolUse assumption here would 400 exactly
    // like a real multi-tool-call turn would if the caller dropped one.
    const toolUses = response.content.filter((b): b is Anthropic.ToolUseBlock => b.type === "tool_use");
    if (toolUses.length === 0) {
      console.log(`[turn ${turn}] no tool_use in response (stop_reason=${response.stop_reason}) — ending loop early`);
      break;
    }

    messages.push({
      role: "user",
      content: toolUses.map(tu => messyToolResult(tu.id, turn)),
    });
  }

  console.log("\n=== Gate 1 summary ===");
  const cold = results[0];
  const warm = results.slice(1);
  console.log(`Cold call (turn 1): cache_creation=${cold.cacheCreation}, cache_read=${cold.cacheRead}`);
  const coldOk = cold.cacheCreation > 0 && cold.cacheRead === 0;
  console.log(coldOk ? "✅ cold call wrote the cache as expected" : "❌ cold call did not write the cache — check prefix length vs the model's minimum floor");

  let allWarmOk = true;
  for (const r of warm) {
    const ok = r.cacheRead > 0;
    if (!ok) allWarmOk = false;
    console.log(
      `Turn ${r.turn}: cache_read=${r.cacheRead} cache_creation=${r.cacheCreation} input_tokens=${r.inputTokens} ${ok ? "✅ hit" : "❌ MISS"}`
    );
  }

  console.log(allWarmOk
    ? "\n✅ GATE 1 (loop cache): every warm turn hit the cache despite fresh timestamps/UUIDs in tool_result each turn."
    : "\n❌ GATE 1 (loop cache): at least one warm turn missed — the rolling breakpoint is NOT surviving real tool_result noise. Investigate before trusting the pacer relief in a live hunt.");
}

main().catch(err => {
  console.error("Harness failed:", err);
  process.exit(1);
});
