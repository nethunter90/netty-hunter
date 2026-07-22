/**
 * CI import-guard for the external-tool-execution chokepoint.
 *
 * Every invocation of an offensive security binary (nmap, ffuf, nuclei,
 * sqlmap, gobuster, whatweb, ...) must go through dispatchTool()
 * (server/src/lib/net/dispatch-tool.ts), which scope-checks the target and
 * execFiles with an array of arguments — never a shell. A 2026-07-21 audit
 * found a live remote-code-execution chain: lib/orchestration/layer5-meta-
 * agents.ts harvested a target's own HTML unfiltered and fed it back into
 * whatweb/nikto/nuclei/sqlmap/metasploit/hydra/hashcat via shell-string
 * exec() with no or weak escaping. That chain is stopgapped and being
 * migrated onto dispatchTool(); this guard exists so it (and anything like
 * it) can't recur once the migration lands.
 *
 * Two independent things are checked, because "execFile is safe" has a sharp
 * exception that a guard encoding only "exec/execSync bad, execFile/spawn
 * good" would miss entirely:
 *
 *   1. Importing `exec`/`execSync` from child_process AT ALL (any form —
 *      named, namespace, dynamic import, require) is an unconditional
 *      violation outside the allowlist. Both ALWAYS invoke a shell; there is
 *      no safe way to call them with attacker-reachable data, and no
 *      wrapper/alias/promisify layer around them changes that — this check
 *      is on the IMPORT, not the call-site text, specifically so an aliased
 *      wrapper (`const execAsync = promisify(exec)`, `this.exec()` wrapping
 *      it, etc.) can't dodge detection the way a call-site-only regex would.
 *
 *   2. `execFile`/`execFileSync`/`spawn`/`spawnSync` — normally safe (array
 *      args, no shell) — become exactly as dangerous as exec/execSync in two
 *      cases: the options object sets `shell: true` (or a shell path
 *      string), or argv[0] itself IS a shell (`sh`, `bash`, `zsh`, `dash`, or
 *      an absolute path to one) — `execFile('bash', ['-c', str])` spawns a
 *      shell directly and `str` is injectable again, identically to raw
 *      exec(). Checked per call site, not per import, since these functions
 *      are legitimately used everywhere for real tool binaries.
 *
 * Every detection form here is covered by a synthetic-fixture proof in
 * server/src/__tests__/check-tool-exec-guard.test.ts — a guard that misses
 * an invocation form is false structural confidence, per the axios/browser
 * guards' own track record of missing a form on the first pass.
 *
 * Pure scan logic — no filesystem walking here (that's scripts/check-tool-exec.ts,
 * the CLI wrapper, kept thin so this module can be unit-tested directly from
 * src/__tests__ without a tsconfig rootDir violation).
 */
// Files allowed to import exec/execSync directly. Adding to this list is a
// deliberate, reviewable decision — each entry states WHY it's safe.
export const ALLOWLIST: Record<string, string> = {
  "lib/orchestration/layer5-codegen-agent.ts":
    "runs a single fully static string ('npx tsc --noEmit --pretty 2>&1 | head -50') " +
    "for the codegen agent's own self-validation — no external input reaches it",
  "lib/stealth/cleanup-manager.ts":
    "cleanClipboard() runs two fully static strings (xclip/xsel clipboard clear) " +
    "with no interpolation of any kind",
};

// Files allowed to invoke execFile/spawn with a shell binary as argv[0], or
// shell:true — none today; this exists so a legitimate future need is a
// reviewable addition, not a silent bypass.
export const SHELL_SPAWN_ALLOWLIST: Record<string, string> = {};

// exec/execSync import, any form: named, namespace (`import * as cp`), dynamic
// import(), require(). Captures the bound alias for namespace/require forms
// so property-access calls (`cp.exec(`) are also detected.
const NAMED_IMPORT_PATTERN =
  /import\s*\{([^}]*)\}\s*from\s*["']child_process["']/;
const NAMESPACE_IMPORT_PATTERN =
  /import\s*\*\s*as\s*(\w+)\s*from\s*["']child_process["']/;
const REQUIRE_NAMESPACE_PATTERN =
  /(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*["']child_process["']\s*\)/;
const REQUIRE_NAMED_PATTERN =
  /(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*["']child_process["']\s*\)/;
const DYNAMIC_IMPORT_NAMED_PATTERN =
  /(?:const|let|var)\s*\{([^}]*)\}\s*=\s*await\s+import\(\s*["']child_process["']\s*\)/;
const DYNAMIC_IMPORT_NAMESPACE_PATTERN =
  /(?:const|let|var)\s+(\w+)\s*=\s*await\s+import\(\s*["']child_process["']\s*\)/;

const DANGEROUS_NAMED = new Set(["exec", "execSync"]);
const SHELL_FAMILY_NAMED = new Set(["execFile", "execFileSync", "spawn", "spawnSync"]);

interface NamedBinding {
  original: string; // the real export name from child_process, e.g. "exec"
  local: string;     // the name calls in THIS file actually use, e.g. "runShell"
}

function extractNamedBindings(clause: string): NamedBinding[] {
  // "exec, execFile as ef, spawn" -> [{original:"exec",local:"exec"}, {original:"execFile",local:"ef"}, ...]
  return clause.split(",").map(s => s.trim()).filter(Boolean).map(part => {
    const asMatch = part.match(/^(\w+)\s+as\s+(\w+)$/);
    return asMatch ? { original: asMatch[1], local: asMatch[2] } : { original: part, local: part };
  });
}

export interface ToolExecViolation {
  reason: string;
}

/**
 * Returns every dangerous binding this file's child_process import(s) make
 * available: a Set of local names bound to exec/execSync (unconditional
 * violation) and a Set bound to the execFile/spawn family (conditional —
 * checked per call site), plus any namespace aliases (`cp` in `import * as
 * cp from "child_process"`) whose property access needs the same treatment.
 */
function collectBindings(content: string): { dangerousNames: Set<string>; shellFamilyNames: Set<string>; namespaceAliases: Set<string> } {
  const dangerousNames = new Set<string>();
  const shellFamilyNames = new Set<string>();
  const namespaceAliases = new Set<string>();

  for (const pattern of [NAMED_IMPORT_PATTERN, REQUIRE_NAMED_PATTERN, DYNAMIC_IMPORT_NAMED_PATTERN]) {
    const m = content.match(pattern);
    if (m) {
      for (const { original, local } of extractNamedBindings(m[1])) {
        if (DANGEROUS_NAMED.has(original)) dangerousNames.add(local);
        if (SHELL_FAMILY_NAMED.has(original)) shellFamilyNames.add(local);
      }
    }
  }
  for (const pattern of [NAMESPACE_IMPORT_PATTERN, REQUIRE_NAMESPACE_PATTERN, DYNAMIC_IMPORT_NAMESPACE_PATTERN]) {
    const m = content.match(pattern);
    if (m) namespaceAliases.add(m[1]);
  }

  return { dangerousNames, shellFamilyNames, namespaceAliases };
}

const SHELL_BINARY_FIRST_ARG =
  /\(\s*["'](\/bin\/|\/usr\/bin\/)?\s*(sh|bash|zsh|dash)["']/;
const SHELL_OPTION_PATTERN = /\bshell\s*:\s*(true|["'][^"']*["'])/;

/** Scans a fixed-size window after a call-site match for the shell:true/path
 *  option — approximates "same call" without a full parser, matching this
 *  project's established precision level for these guards (see
 *  check-scope-egress.ts's own line-window comments). */
function windowAfter(content: string, index: number, size = 300): string {
  return content.slice(index, index + size);
}

export function scanContent(content: string, relPath: string): ToolExecViolation[] {
  const violations: ToolExecViolation[] = [];
  const { dangerousNames, shellFamilyNames, namespaceAliases } = collectBindings(content);

  const isAllowlisted = relPath in ALLOWLIST;
  const isShellSpawnAllowlisted = relPath in SHELL_SPAWN_ALLOWLIST;

  // 1. exec/execSync import (any binding form) — unconditional violation.
  if (!isAllowlisted) {
    if (dangerousNames.size > 0) {
      violations.push({ reason: `imports ${[...dangerousNames].join("/")} from child_process — always shell-invoking; use dispatchTool()` });
    }
    for (const alias of namespaceAliases) {
      const nsPattern = new RegExp(`\\b${alias}\\.(exec|execSync)\\s*\\(`);
      if (nsPattern.test(content)) {
        violations.push({ reason: `calls ${alias}.exec()/${alias}.execSync() (namespace import of child_process) — always shell-invoking; use dispatchTool()` });
      }
    }
  }

  // 2. execFile/execFileSync/spawn/spawnSync as a shell — argv[0] is a shell
  //    binary, or shell:true/shell:"<path>" is set for this call.
  if (!isShellSpawnAllowlisted) {
    const shellFamilyCallNames = new Set<string>([...shellFamilyNames]);
    for (const alias of namespaceAliases) {
      for (const fn of SHELL_FAMILY_NAMED) shellFamilyCallNames.add(`${alias}.${fn}`);
    }
    for (const name of shellFamilyCallNames) {
      const escaped = name.replace(".", "\\.");
      const callPattern = new RegExp(`\\b${escaped}\\s*\\(`, "g");
      let m: RegExpExecArray | null;
      while ((m = callPattern.exec(content)) !== null) {
        const callStart = m.index;
        const window = windowAfter(content, callStart);
        if (SHELL_BINARY_FIRST_ARG.test(window.slice(0, 60)) || SHELL_OPTION_PATTERN.test(window)) {
          violations.push({ reason: `${name}(...) invokes a shell directly (argv[0] is sh/bash/zsh/dash, or shell:true/shell:"<path>" is set) — exactly as injectable as exec()/execSync(); use dispatchTool()` });
        }
      }
    }
  }

  return violations;
}

