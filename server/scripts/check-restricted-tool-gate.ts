/**
 * CI guard for the restricted-tool (scanning/fuzzing) policy gate —
 * readiness blocker #3, Test 0.
 *
 * check-tool-exec.ts already proves dispatchTool() + HunterEngine.runTool()
 * are the ONLY two places a real binary gets exec'd in this codebase (every
 * other raw exec/spawn is disallowed). That means there is no THIRD path
 * for nuclei/ffuf/gobuster/feroxbuster/wfuzz/arjun to bypass the policy gate
 * through — the only realistic regression is someone editing one of these
 * two known chokepoints and quietly removing the gate call (a nuclei/fuzzer
 * dispatch would then silently run unauthorized against a real program with
 * no error, no test failure — the same "looks complete, isn't" shape as
 * every other gate this sprint). This guard is a POSITIVE-presence check on
 * those two specific files, not an absence-scan across the tree (that's
 * check-tool-exec.ts's job, and check-rl-bypass.ts's, for their own
 * chokepoints).
 *
 * Run: npx tsx scripts/check-restricted-tool-gate.ts
 * Wired as a `pretest` hook.
 */
import { readFileSync } from "fs";
import { join } from "path";

const SRC_ROOT = join(__dirname, "..", "src");

interface GatedFile {
  path: string;
  mustContain: string[];
}

const GATED_FILES: GatedFile[] = [
  {
    path: "lib/net/dispatch-tool.ts",
    mustContain: [
      "checkAutomatedScanningAuthorization",
      "checkFuzzingAuthorization",
      'tool === "nuclei"',
      "FUZZING_TOOLS",
    ],
  },
  {
    path: "agents/HunterEngine.ts",
    mustContain: [
      "checkAutomatedScanningAuthorization",
      "checkFuzzingAuthorization",
      'toolName === "nuclei"',
      "FUZZING_TOOLS",
    ],
  },
];

function main(): void {
  const violations: Array<{ file: string; missing: string }> = [];

  for (const gated of GATED_FILES) {
    const absPath = join(SRC_ROOT, gated.path);
    let content: string;
    try {
      content = readFileSync(absPath, "utf-8");
    } catch {
      violations.push({ file: gated.path, missing: "file not found — has it moved?" });
      continue;
    }
    for (const marker of gated.mustContain) {
      if (!content.includes(marker)) {
        violations.push({ file: gated.path, missing: marker });
      }
    }
  }

  if (violations.length > 0) {
    console.error("\n[check-restricted-tool-gate] FAILED — the restricted-tool policy gate is missing from a known exec chokepoint:\n");
    for (const v of violations) {
      console.error(`  src/${v.file}\n    missing: ${v.missing}`);
    }
    console.error(
      "\nnuclei/ffuf/gobuster/feroxbuster/wfuzz/arjun dispatch must be gated by " +
      "checkAutomatedScanningAuthorization()/checkFuzzingAuthorization() (agents/ActionPolicyGate.ts) " +
      "at BOTH dispatchTool() and HunterEngine.runTool() — these are the only two places " +
      "a real binary gets exec'd (see check-tool-exec.ts). If this is a deliberate, reviewed " +
      "change to how the gate is structured, update GATED_FILES in " +
      "scripts/check-restricted-tool-gate.ts to match — do not silently remove the check.\n"
    );
    process.exit(1);
  }

  console.log(`[check-restricted-tool-gate] OK — restricted-tool policy gate present in both known exec chokepoints (${GATED_FILES.length} files checked).`);
}

main();
