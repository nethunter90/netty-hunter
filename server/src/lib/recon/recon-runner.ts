/**
 * ReconRunner — Phase 0 passive OSINT before the hypothesis loop.
 *
 * Runs crt.sh certificate transparency + WaybackMachine CDX in parallel,
 * resolves discovered subdomains via DNS, probes alive status, and surfaces
 * a structured ReconContext that HunterEngine injects into every hypothesize()
 * call so the model reasons over a real attack surface, not just a root URL.
 *
 * All requests are read-only and hit public OSINT APIs — no contact with
 * the target itself except lightweight HEAD probes on discovered subdomains.
 */
import axios from "axios";
import { scopedHttp } from "../net/scoped-http";
import dns from "dns";
import { join } from "path";
import { writeFile, mkdir } from "fs/promises";
import logger from "../../utils/logger";

function isLocalTarget(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    /^127\./.test(hostname) ||
    /^10\./.test(hostname) ||
    /^192\.168\./.test(hostname) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(hostname) ||
    /^::1$/.test(hostname)
  );
}

const INTERESTING_PATH_PATTERNS = [
  /\/admin/i, /\/upload/i, /\/backup/i, /\/config/i, /\/api\//i,
  /\/login/i, /\/manage/i, /\/dashboard/i, /\/console/i, /\/setup/i,
  /\/install/i, /\/debug/i, /\/test\b/i, /\/dev\//i, /\/internal/i,
  /\/private/i, /\/portal/i, /\.git\//i, /\.env/i, /\/swagger/i,
  /\/graphql/i, /\/actuator/i, /\/phpinfo/i, /\/wp-admin/i,
];

export interface SubdomainRecord {
  subdomain: string;
  resolvedIp?: string;
  alive: boolean;
  httpStatus?: number;
}

export interface ReconContext {
  targetUrl: string;
  targetDomain: string;
  collectedAt: number;
  subdomains: SubdomainRecord[];
  interestingUrls: string[];
  historicalPathCount: number;
  summary: string;
}

export class ReconRunner {
  private readonly domain: string;
  private readonly scheme: string;

  constructor(
    private readonly targetUrl: string,
    private readonly sessionId: string,
    private readonly emitter: (event: string, data: unknown) => void = () => {},
    private readonly programId?: number,
  ) {
    try {
      const u = new URL(targetUrl);
      this.domain = u.hostname;
      this.scheme = u.protocol.replace(":", "");
    } catch {
      this.domain = targetUrl;
      this.scheme = "https";
    }
  }

  async run(): Promise<ReconContext> {
    this.emit("recon:start", { sessionId: this.sessionId, domain: this.domain });
    logger.info("[ReconRunner] Phase 0 OSINT started", { domain: this.domain });

    // Skip external OSINT for local/private targets — crt.sh and Wayback have no
    // records for localhost or RFC-1918 addresses and will always fail noisily.
    if (isLocalTarget(this.domain)) {
      logger.info("[ReconRunner] Local target — skipping crt.sh and Wayback CDX", { domain: this.domain });
      const ctx: ReconContext = {
        targetUrl: this.targetUrl,
        targetDomain: this.domain,
        collectedAt: Date.now(),
        subdomains: [],
        interestingUrls: [],
        historicalPathCount: 0,
        summary: `Attack surface for ${this.domain}:\n• Local/private target — passive OSINT skipped`,
      };
      await this.persist(ctx);
      this.emit("recon:complete", { sessionId: this.sessionId, subdomains: 0, alive: 0, interestingUrls: 0, historicalPathCount: 0 });
      return ctx;
    }

    const [subResult, waybackResult] = await Promise.allSettled([
      this.fetchCrtSh(),
      this.fetchWaybackInteresting(),
    ]);

    const rawSubdomains = subResult.status === "fulfilled" ? subResult.value : [];
    const wayback = waybackResult.status === "fulfilled"
      ? waybackResult.value
      : { interesting: [], total: 0 };

    if (subResult.status === "rejected") {
      logger.warn("[ReconRunner] crt.sh failed (non-critical)", { err: String(subResult.reason) });
    }
    if (waybackResult.status === "rejected") {
      logger.warn("[ReconRunner] Wayback CDX failed (non-critical)", { err: String(waybackResult.reason) });
    }

    const subdomains = await this.resolveAndProbe(rawSubdomains.slice(0, 25));

    const ctx: ReconContext = {
      targetUrl: this.targetUrl,
      targetDomain: this.domain,
      collectedAt: Date.now(),
      subdomains,
      interestingUrls: wayback.interesting,
      historicalPathCount: wayback.total,
      summary: "",
    };
    ctx.summary = this.buildSummary(ctx);

    await this.persist(ctx);

    const aliveCount = subdomains.filter(s => s.alive).length;
    this.emit("recon:complete", {
      sessionId: this.sessionId,
      subdomains: subdomains.length,
      alive: aliveCount,
      interestingUrls: wayback.interesting.length,
      historicalPathCount: wayback.total,
    });
    logger.info("[ReconRunner] Phase 0 OSINT complete", {
      domain: this.domain,
      subdomains: subdomains.length,
      alive: aliveCount,
      interestingUrls: wayback.interesting.length,
    });

    return ctx;
  }

  private async fetchCrtSh(): Promise<string[]> {
    const url = `https://crt.sh/?q=%.${this.domain}&output=json`;
    const r = await axios.get<Array<{ name_value: string }>>(url, {
      timeout: 18000,
      headers: { "User-Agent": "sentinel-recon/1.0 (bug-bounty-osint)" },
    });

    const unique = new Set<string>();
    for (const entry of r.data) {
      for (const name of entry.name_value.split("\n")) {
        const clean = name.trim().replace(/^\*\./, "");
        if (clean && clean.endsWith(`.${this.domain}`) && !clean.includes("*")) {
          unique.add(clean);
        }
      }
    }
    this.emit("recon:subdomains_raw", { count: unique.size });
    return [...unique];
  }

  private async fetchWaybackInteresting(): Promise<{ interesting: string[]; total: number }> {
    const r = await axios.get<string[][]>("http://web.archive.org/cdx/search/cdx", {
      timeout: 22000,
      params: {
        url: `*.${this.domain}/*`,
        output: "json",
        fl: "original",
        collapse: "urlkey",
        limit: 3000,
      },
    });

    const rows = r.data;
    if (!Array.isArray(rows) || rows.length < 2) return { interesting: [], total: 0 };

    const urls = rows.slice(1).map(row => row[0]).filter(Boolean);
    const interesting = urls
      .filter(u => INTERESTING_PATH_PATTERNS.some(rx => rx.test(u)))
      .slice(0, 40);

    return { interesting, total: urls.length };
  }

  private async resolveAndProbe(subdomains: string[]): Promise<SubdomainRecord[]> {
    const resolveOne = (hostname: string): Promise<string | null> =>
      new Promise(resolve => dns.lookup(hostname, (err, addr) => resolve(err ? null : addr)));

    const probeOne = async (subdomain: string, ip: string): Promise<{ alive: boolean; httpStatus?: number }> => {
      try {
        const r = await scopedHttp.request({
          url: `${this.scheme}://${subdomain}`,
          method: "HEAD",
          timeout: 4000,
          maxRedirects: 2,
          validateStatus: () => true,
        }, this.programId);
        return { alive: true, httpStatus: r.status };
      } catch {
        return { alive: false };
      }
    };

    // Resolve all DNS in parallel then probe alive ones
    const resolved = await Promise.all(
      subdomains.map(async (sub): Promise<SubdomainRecord> => {
        const ip = await resolveOne(sub).catch(() => null);
        if (!ip) return { subdomain: sub, alive: false };

        const probe = await probeOne(sub, ip).catch(() => ({ alive: false }));
        return { subdomain: sub, resolvedIp: ip, ...probe };
      })
    );

    return resolved;
  }

  private buildSummary(ctx: ReconContext): string {
    const alive = ctx.subdomains.filter(s => s.alive);
    const lines: string[] = [
      `Attack surface for ${ctx.targetDomain}:`,
    ];

    if (ctx.subdomains.length > 0) {
      lines.push(`• ${ctx.subdomains.length} subdomains discovered via certificate transparency`);
      if (alive.length > 0) {
        lines.push(
          `• ${alive.length} subdomains alive: ${alive.slice(0, 8).map(s => `${s.subdomain} (HTTP ${s.httpStatus})`).join(", ")}${alive.length > 8 ? " ..." : ""}`
        );
      }
    } else {
      lines.push("• No subdomains discovered (single-host target or crt.sh unavailable)");
    }

    if (ctx.historicalPathCount > 0) {
      lines.push(`• ${ctx.historicalPathCount} historical URLs in Wayback Machine`);
    }

    if (ctx.interestingUrls.length > 0) {
      lines.push(
        `• ${ctx.interestingUrls.length} high-priority historical paths (admin/api/upload/config/debug):`,
        ...ctx.interestingUrls.slice(0, 20).map(u => `  ${u}`)
      );
    }

    return lines.join("\n");
  }

  private async persist(ctx: ReconContext): Promise<void> {
    try {
      const dir = join(process.cwd(), "context");
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, "recon-context.json"), JSON.stringify(ctx, null, 2));
    } catch (err) {
      logger.warn("[ReconRunner] Failed to persist recon context", { err: String(err) });
    }
  }

  private emit(event: string, data: unknown): void {
    try { this.emitter(event, data); } catch { /* non-critical */ }
  }
}
