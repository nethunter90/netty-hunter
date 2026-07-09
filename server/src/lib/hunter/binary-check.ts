/**
 * Startup binary availability check.
 *
 * The hunt engine shells out to a number of Kali tools. When one is missing the
 * relevant probe silently degrades mid-hunt, which is hard to diagnose. This
 * runs once at boot and logs a clear summary of which tools are present so the
 * operator knows the real capability surface up front. It does NOT fail the
 * boot — the platform runs (degraded) with only curl/axios.
 *
 * HUNT_TOOLS is the single source of truth for the engine's binary set — the
 * routes/hunt.ts `/tools/preflight` endpoint (used by the Orchestration panel)
 * reuses this same list instead of maintaining its own copy, so the two no
 * longer drift out of sync.
 */
import { execFile } from "child_process";
import { promisify } from "util";
import logger from "../../utils/logger";

const execFileAsync = promisify(execFile);

export const HUNT_TOOLS: Array<{ name: string; binary: string; tier: "critical" | "important" | "optional" }> = [
  { name: "nmap",      binary: "nmap",      tier: "critical"  },
  { name: "nuclei",    binary: "nuclei",    tier: "critical"  },
  { name: "ffuf",      binary: "ffuf",      tier: "critical"  },
  { name: "sqlmap",    binary: "sqlmap",    tier: "critical"  },
  { name: "nikto",     binary: "nikto",     tier: "important" },
  { name: "gobuster",  binary: "gobuster",  tier: "important" },
  { name: "whatweb",   binary: "whatweb",   tier: "important" },
  { name: "dalfox",    binary: "dalfox",    tier: "important" },
  { name: "tplmap",    binary: "tplmap",    tier: "important" },
  { name: "jwt_tool",  binary: "jwt_tool",  tier: "optional"  },
  { name: "xsser",     binary: "xsser",     tier: "optional"  },
  { name: "ssrfmap",   binary: "ssrfmap",   tier: "optional"  },
  { name: "nosqlmap",  binary: "nosqlmap",  tier: "optional"  },
  { name: "corsy",     binary: "corsy",     tier: "optional"  },
  { name: "smuggler",  binary: "smuggler",  tier: "optional"  },
];

async function has(binary: string): Promise<boolean> {
  try {
    await execFileAsync("which", [binary], { timeout: 2000 });
    return true;
  } catch {
    return false;
  }
}

export async function checkBinariesAtStartup(): Promise<void> {
  try {
    const results = await Promise.all(HUNT_TOOLS.map(async t => [t, await has(t.binary)] as const));
    const present = results.filter(([, ok]) => ok).map(([t]) => t.name);
    const missingCritical = results.filter(([t, ok]) => !ok && t.tier === "critical").map(([t]) => t.name);
    const missingOther = results.filter(([t, ok]) => !ok && t.tier !== "critical").map(([t]) => t.name);

    logger.info("[BinaryCheck] Tool availability", {
      present,
      missingCritical,
      missingOther,
    });

    if (missingCritical.length > 0) {
      logger.warn(
        `[BinaryCheck] Missing CRITICAL tools (${missingCritical.join(", ")}) — ` +
        `surface-discovery coverage is reduced; hunts fall back to HTTP/axios probes only.`
      );
    }
  } catch (err) {
    logger.debug("[BinaryCheck] availability check failed (non-fatal)", { err: String(err) });
  }
}
