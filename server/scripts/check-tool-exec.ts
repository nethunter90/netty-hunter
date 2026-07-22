/**
 * CI import-guard CLI for the external-tool-execution chokepoint.
 * Scan logic lives in src/lib/net/tool-exec-scan.ts (see that file's own
 * comment for what's checked and why); this is just the filesystem walk +
 * process.exit wiring. Run: npx tsx scripts/check-tool-exec.ts
 */
import { readFileSync, readdirSync, statSync } from "fs";
import { join, relative } from "path";
import { scanContent, ALLOWLIST, SHELL_SPAWN_ALLOWLIST } from "../src/lib/net/tool-exec-scan";

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
    console.error("\n[check-tool-exec] FAILED — shell-invoking tool execution found outside dispatchTool():\n");
    for (const v of violations) {
      console.error(`  src/${v.file}\n    ${v.reason}`);
    }
    console.error(
      "\nEvery external-tool invocation must go through dispatchTool() (server/src/lib/net/dispatch-tool.ts), " +
      "which scope-checks the target and execFiles with an array of arguments — never a shell. If this file " +
      "genuinely needs a raw exec/execSync or a shell-invoking execFile/spawn call with no target-facing data " +
      "reaching it, add it to the ALLOWLIST/SHELL_SPAWN_ALLOWLIST in scripts/check-tool-exec.ts with a " +
      "one-line justification — do not silently ignore this.\n"
    );
    process.exit(1);
  }

  console.log(`[check-tool-exec] OK — no shell-invoking tool execution outside dispatchTool() (${Object.keys(ALLOWLIST).length} import-allowlisted, ${Object.keys(SHELL_SPAWN_ALLOWLIST).length} shell-spawn-allowlisted).`);
}

if (require.main === module) {
  main();
}
