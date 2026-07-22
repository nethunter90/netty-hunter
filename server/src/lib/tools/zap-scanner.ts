/**
 * OWASP ZAP Scanner Integration
 * Runs ZAP as a daemon, spiders the target, and converts passive-scan
 * alerts into Hypothesis-compatible findings for the hunt pipeline.
 */
import axios from "axios";
import { spawn, ChildProcess } from "child_process";
import { promisify } from "util";
import { exec } from "child_process";
import logger from "../../utils/logger";

const execAsync = promisify(exec);

// ─── Config ──────────────────────────────────────────────────────────────────

const ZAP_BASE    = (process.env.ZAP_API_URL  || "http://127.0.0.1:8080").replace(/\/$/, "");
const ZAP_KEY     = process.env.ZAP_API_KEY   || "";
const ZAP_AUTO    = process.env.ZAP_AUTO_START === "true";
// How long to wait for ZAP to boot before giving up
const ZAP_BOOT_MS = 45_000;
// Spider timeout per hunt (ms)
const SPIDER_MS   = 60_000;

// ─── Vuln class mapping ───────────────────────────────────────────────────────

const CWE_CLASS: Record<number, string> = {
  89:  "sqli",
  564: "sqli",
  79:  "xss",
  80:  "xss",
  87:  "xss",
  22:  "lfi",
  918: "ssrf",
  78:  "rce",
  77:  "rce",
  94:  "rce",
  611: "xxe",
  352: "csrf",
  601: "open_redirect",
  200: "info_disclosure",
  209: "info_disclosure",
  287: "broken_auth",
  306: "broken_auth",
  284: "idor",
  639: "idor",
  502: "deserialization",
  113: "crlf_injection",
  943: "sqli",
};

const NAME_CLASS: Array<[RegExp, string]> = [
  [/sql\s*inject/i,              "sqli"],
  [/cross.site\s*script/i,       "xss"],
  [/path\s*traversal/i,          "lfi"],
  [/remote\s*file\s*inclus/i,    "rfi"],
  [/server.side\s*request/i,     "ssrf"],
  [/remote\s*code\s*exec/i,      "rce"],
  [/xml.external\s*entity/i,     "xxe"],
  [/csrf|cross.site\s*request/i, "csrf"],
  [/open\s*redirect/i,           "open_redirect"],
  [/information\s*disclos/i,     "info_disclosure"],
  [/broken\s*auth/i,             "broken_auth"],
  [/access\s*control/i,          "idor"],
  [/deserializ/i,                "deserialization"],
  [/cors/i,                      "cors"],
  [/response\s*split/i,          "crlf_injection"],
  [/security\s*misconfig/i,      "misconfig"],
];

function toVulnClass(name: string, cweId: number): string {
  if (CWE_CLASS[cweId]) return CWE_CLASS[cweId];
  for (const [re, vc] of NAME_CLASS) if (re.test(name)) return vc;
  return "misconfig";
}

// ─── Risk → confidence/priority ──────────────────────────────────────────────

function scoreAlert(risk: string, confidence: string): { conf: number; priority: number } {
  const r = risk.toLowerCase();
  const c = confidence.toLowerCase();
  if (r === "high"   && c === "high")   return { conf: 0.75, priority: 8 };
  if (r === "high"   && c === "medium") return { conf: 0.65, priority: 7 };
  if (r === "high")                     return { conf: 0.55, priority: 7 };
  if (r === "medium" && c === "high")   return { conf: 0.60, priority: 6 };
  if (r === "medium")                   return { conf: 0.50, priority: 5 };
  return { conf: 0.40, priority: 4 };
}

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ZapHypothesis {
  vulnClass: string;
  targetUrl: string;
  reasoning: string;
  confidence: number;
  priority: number;
  cweId?: number;
  evidence?: string;
  parameter?: string;
}

export interface ZapScanResult {
  available: boolean;
  hypotheses: ZapHypothesis[];
  endpointsDiscovered: string[];
  alertCount: number;
  duration: number;
}

// ─── Scanner ─────────────────────────────────────────────────────────────────

class ZapScanner {
  private daemon: ChildProcess | null = null;

  // ── Check if ZAP daemon responds ──────────────────────────────────────────
  async isRunning(): Promise<boolean> {
    try {
      await axios.get(`${ZAP_BASE}/JSON/core/view/version/`, {
        params: { apikey: ZAP_KEY },
        timeout: 3_000,
      });
      return true;
    } catch {
      return false;
    }
  }

  // ── Find the ZAP binary ──────────────────────────────────────────────────
  private async findBin(): Promise<string | null> {
    for (const bin of ["zaproxy", "zap.sh", "/usr/bin/zaproxy"]) {
      try {
        await execAsync(`which ${bin}`);
        return bin;
      } catch { /* not found */ }
    }
    return null;
  }

  // ── Start ZAP daemon if auto-start is enabled ────────────────────────────
  async ensureDaemon(): Promise<boolean> {
    if (await this.isRunning()) return true;
    if (!ZAP_AUTO) return false;

    const bin = await this.findBin();
    if (!bin) {
      logger.debug("[ZAP] binary not found — install with: apt install zaproxy");
      return false;
    }

    logger.info("[ZAP] Starting daemon...");
    this.daemon = spawn(bin, [
      "-daemon",
      "-port", "8080",
      "-host", "127.0.0.1",
      "-config", `api.key=${ZAP_KEY || "sentinel-zap"}`,
      "-config", "api.disablekey=false",
      "-config", "connection.timeoutInSecs=20",
      "-silent",
    ], { detached: false, stdio: "ignore" });

    this.daemon.on("error", err => logger.debug("[ZAP] daemon error", { err: String(err) }));

    // Wait for ZAP to become responsive
    const deadline = Date.now() + ZAP_BOOT_MS;
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 2_000));
      if (await this.isRunning()) {
        logger.info("[ZAP] Daemon ready");
        return true;
      }
    }
    logger.warn("[ZAP] Daemon did not become ready in time");
    return false;
  }

  // ── Main scan entry point ────────────────────────────────────────────────
  async scan(targetUrl: string, authHeaders?: Record<string, string>): Promise<ZapScanResult> {
    const t0 = Date.now();
    const empty: ZapScanResult = { available: false, hypotheses: [], endpointsDiscovered: [], alertCount: 0, duration: 0 };

    if (!await this.ensureDaemon()) {
      logger.debug("[ZAP] Not available — skipping");
      return { ...empty, duration: Date.now() - t0 };
    }

    try {
      // Inject auth headers as replacement headers so ZAP uses them during spider
      if (authHeaders && Object.keys(authHeaders).length > 0) {
        for (const [key, value] of Object.entries(authHeaders)) {
          await axios.get(`${ZAP_BASE}/JSON/replacer/action/addRule/`, {
            params: {
              apikey: ZAP_KEY,
              description: `auth-${key}`,
              enabled: "true",
              matchType: "REQ_HEADER",
              matchString: key,
              replacement: value,
            },
            timeout: 5_000,
          }).catch(() => {});
        }
      }

      // 2026-07-21 readiness pass (item A/E — containment-for-real): ZAP's
      // spider is a SEPARATE process that makes its own outbound requests —
      // invisible to scopedHttp entirely, since this Node process never makes
      // those requests itself. Previously handed `contextName: ""` (no
      // context = no scope restriction) with `recurse: "true"`, so ZAP could
      // spider off-host to anything it discovered a link to, with zero
      // re-validation from this codebase. Create a real ZAP Context scoped to
      // the target's own host via an include-regex BEFORE spidering, so ZAP
      // is structurally confined to it regardless of what it finds.
      const targetHost = new URL(targetUrl).hostname;
      const contextName = `hunt-${Date.now()}`;
      let scopedContextName = "";
      try {
        await axios.get(`${ZAP_BASE}/JSON/context/action/newContext/`, {
          params: { apikey: ZAP_KEY, contextName },
          timeout: 5_000,
        });
        const escapedHost = targetHost.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        await axios.get(`${ZAP_BASE}/JSON/context/action/includeInContext/`, {
          params: {
            apikey: ZAP_KEY,
            contextName,
            regex: `^https?://${escapedHost}(:[0-9]+)?/.*$`,
          },
          timeout: 5_000,
        });
        scopedContextName = contextName;
      } catch (err) {
        // Non-fatal, but a real containment degradation — if the Context
        // can't be created, fall through to an unscoped spider rather than
        // failing the whole scan. Logged loudly so this isn't silent.
        logger.warn("[ZAP] Failed to create scope-restricting Context — spidering WITHOUT host restriction", {
          targetHost, err: String(err),
        });
      }

      // Start spider, restricted to the Context created above (empty string
      // if Context creation failed — see the warning just above).
      const spiderRes = await axios.get(`${ZAP_BASE}/JSON/spider/action/scan/`, {
        params: {
          apikey: ZAP_KEY,
          url: targetUrl,
          maxChildren: 10,
          recurse: "true",
          contextName: scopedContextName,
          subtreeOnly: "false",
        },
        timeout: 10_000,
      });
      const spiderScanId = spiderRes.data.scan;

      // Poll spider until complete or timeout
      const spiderDeadline = Date.now() + SPIDER_MS;
      while (Date.now() < spiderDeadline) {
        const st = await axios.get(`${ZAP_BASE}/JSON/spider/view/status/`, {
          params: { apikey: ZAP_KEY, scanId: spiderScanId },
          timeout: 5_000,
        });
        if (parseInt(st.data.status, 10) >= 100) break;
        await new Promise(r => setTimeout(r, 3_000));
      }

      // Collect discovered URLs
      const urlsRes = await axios.get(`${ZAP_BASE}/JSON/spider/view/results/`, {
        params: { apikey: ZAP_KEY, scanId: spiderScanId },
        timeout: 10_000,
      });
      const endpointsDiscovered: string[] = (urlsRes.data.results || []).slice(0, 100);

      // Pull passive-scan alerts from the spider traversal
      const alertsRes = await axios.get(`${ZAP_BASE}/JSON/core/view/alerts/`, {
        params: { apikey: ZAP_KEY, baseurl: targetUrl, start: 0, count: 200 },
        timeout: 10_000,
      });
      const rawAlerts: any[] = (alertsRes.data.alerts || [])
        .filter((a: any) => a.risk !== "Informational" && a.confidence !== "False Positive");

      // Deduplicate by name+parameter (ZAP reports the same vuln multiple times across URLs)
      const seen = new Set<string>();
      const hypotheses: ZapHypothesis[] = [];

      for (const a of rawAlerts) {
        const key = `${a.name}::${a.param || ""}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const cweId = parseInt(a.cweid, 10) || 0;
        const { conf, priority } = scoreAlert(a.risk, a.confidence);
        const vulnClass = toVulnClass(a.name, cweId);

        hypotheses.push({
          vulnClass,
          targetUrl: a.url || targetUrl,
          reasoning: `ZAP passive scan: ${a.name} [${a.risk} / ${a.confidence}]` +
            (a.param ? ` on parameter "${a.param}"` : "") +
            (cweId ? ` (CWE-${cweId})` : "") +
            (a.description ? `. ${a.description.slice(0, 200)}` : ""),
          confidence: conf,
          priority,
          cweId: cweId || undefined,
          evidence: a.evidence || a.attack || undefined,
          parameter: a.param || undefined,
        });
      }

      return {
        available: true,
        hypotheses,
        endpointsDiscovered,
        alertCount: rawAlerts.length,
        duration: Date.now() - t0,
      };
    } catch (err) {
      logger.debug("[ZAP] Scan error (non-critical)", { err: String(err) });
      return { available: true, hypotheses: [], endpointsDiscovered: [], alertCount: 0, duration: Date.now() - t0 };
    }
  }

  // ── Clean up auth header rules after a hunt ──────────────────────────────
  async clearReplacerRules(): Promise<void> {
    try {
      await axios.get(`${ZAP_BASE}/JSON/replacer/view/rules/`, {
        params: { apikey: ZAP_KEY }, timeout: 3_000,
      }).then(r => Promise.all(
        (r.data.rules || [])
          .filter((rule: any) => String(rule.description).startsWith("auth-"))
          .map((rule: any) =>
            axios.get(`${ZAP_BASE}/JSON/replacer/action/removeRule/`, {
              params: { apikey: ZAP_KEY, description: rule.description }, timeout: 3_000,
            }).catch(() => {})
          )
      ));
    } catch { /* non-fatal */ }
  }
}

export const zapScanner = new ZapScanner();
