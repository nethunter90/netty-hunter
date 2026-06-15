/**
 * Startup binary availability check.
 *
 * The hunt engine shells out to a number of Kali tools. When one is missing the
 * relevant probe silently degrades mid-hunt, which is hard to diagnose. This
 * runs once at boot and logs a clear summary of which tools are present so the
 * operator knows the real capability surface up front. It does NOT fail the
 * boot — the platform runs (degraded) with only curl/axios.
 */
import { execFile } from "child_process";
import { promisify } from "util";
import logger from "../../utils/logger";

const execFileAsync = promisify(execFile);

// Tools the engine/solvers shell out to. "critical" ones materially reduce
// coverage when absent; the rest are situational enhancers.
const CRITICAL = ["nmap", "nuclei", "sqlmap", "ffuf"];
const OPTIONAL = ["whatweb", "nikto", "gobuster", "subfinder", "tplmap", "zaproxy", "curl"];

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
    const all = [...CRITICAL, ...OPTIONAL];
    const results = await Promise.all(all.map(async b => [b, await has(b)] as const));
    const present = results.filter(([, ok]) => ok).map(([b]) => b);
    const missingCritical = CRITICAL.filter(b => !present.includes(b));
    const missingOptional = OPTIONAL.filter(b => !present.includes(b));

    logger.info("[BinaryCheck] Tool availability", {
      present,
      missingCritical,
      missingOptional,
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
