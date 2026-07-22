/**
 * CI import-guard CLI for the LLM-spend chokepoint.
 * Scan logic lives in src/lib/llm/llm-invocation-scan.ts (see that file's
 * own comment for what's checked and why); this is just the filesystem walk
 * + process.exit wiring. Run: npx tsx scripts/check-llm-bypass.ts
 */
import { readFileSync, readdirSync, statSync } from "fs";
import { join, relative } from "path";
import { scanContent, ALLOWLIST } from "../src/lib/llm/llm-invocation-scan";

const SRC_ROOT = join(__dirname, "..", "src");
const EXCLUDED_DIRS = new Set(["__tests__", "fixtures", "workspace", "node_modules"]);

function walk(dir: string, files: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (EXCLUDED_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      walk(full, files);
    } else if (entry.endsWith(".ts") && !entry.endsWith(".d.ts")) {
      files.push(full);
    }
  }
  return files;
}

function main(): void {
  const violations: Array<{ file: string; reason: string }> = [];

  for (const absPath of walk(SRC_ROOT)) {
    const relPath = relative(SRC_ROOT, absPath).replace(/\\/g, "/");
    const content = readFileSync(absPath, "utf-8");
    for (const v of scanContent(content, relPath)) {
      violations.push({ file: relPath, reason: v.reason });
    }
  }

  if (violations.length > 0) {
    console.error("\n[check-llm-bypass] FAILED — Anthropic SDK usage found outside ClaudeClient:\n");
    for (const v of violations) {
      console.error(`  src/${v.file}\n    ${v.reason}`);
    }
    console.error(
      "\nEvery LLM call must go through ClaudeClient.createMessage() (server/src/lib/claude-client.ts), " +
      "the one place dollar/token spend is recorded and the per-hunt budget is enforced. If this file " +
      "genuinely only needs the SDK's TypeScript types, use `import type Anthropic from \"@anthropic-ai/sdk\"` " +
      "instead of a runtime import. If it has a real, reviewed reason to bypass the chokepoint, add it to the " +
      "ALLOWLIST in src/lib/llm/llm-invocation-scan.ts with a one-line justification — do not silently ignore this.\n"
    );
    process.exit(1);
  }

  console.log(`[check-llm-bypass] OK — no Anthropic SDK usage outside ClaudeClient (${Object.keys(ALLOWLIST).length} file allowlisted).`);
}

main();
