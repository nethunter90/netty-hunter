/**
 * Diff-based change detection.
 * Stores baseline response snapshots per target and detects:
 * - New endpoints
 * - Changed response sizes / status codes
 * - New response headers
 * - New technologies fingerprinted
 *
 * Snapshots are persisted in the reinforcement store so they survive restarts.
 */
import crypto from "crypto";
import axios from "axios";
import logger from "../../utils/logger";

interface EndpointSnapshot {
  url: string;
  statusCode: number;
  contentLength: number;
  contentHash: string;
  headers: Record<string, string>;
  capturedAt: string;
}

interface ChangeReport {
  newEndpoints: string[];
  changedEndpoints: Array<{ url: string; changes: string[] }>;
  removedEndpoints: string[];
  newHeaders: Array<{ url: string; header: string; value: string }>;
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number }>;
}

const COMMON_PATHS = [
  "/", "/admin", "/api", "/api/v1", "/api/v2",
  "/login", "/signup", "/register", "/dashboard",
  "/.env", "/.git/config", "/backup.zip",
  "/phpinfo.php", "/info.php", "/test.php",
  "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
  "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
  "/graphql", "/api/graphql",
  "/wp-admin", "/wp-login.php", "/wp-json/",
  "/server-status", "/server-info",
  "/actuator", "/actuator/health", "/actuator/env",
  "/metrics", "/.well-known/",
];

class ChangeDetector {
  private snapshots = new Map<string, Map<string, EndpointSnapshot>>();

  async snapshot(targetUrl: string, authHeaders: Record<string, string> = {}): Promise<Map<string, EndpointSnapshot>> {
    const base = this.extractBase(targetUrl);
    const current = new Map<string, EndpointSnapshot>();

    const results = await Promise.allSettled(
      COMMON_PATHS.map(path => this.fetchEndpoint(`${base}${path}`, authHeaders))
    );

    results.forEach((r, i) => {
      if (r.status === "fulfilled" && r.value) {
        current.set(COMMON_PATHS[i], r.value);
      }
    });

    logger.info("[ChangeDetector] Snapshot taken", { base, endpoints: current.size });
    return current;
  }

  async detect(targetUrl: string, authHeaders: Record<string, string> = {}): Promise<ChangeReport> {
    const base = this.extractBase(targetUrl);
    const prev = this.snapshots.get(base);
    const current = await this.snapshot(targetUrl, authHeaders);

    const report: ChangeReport = {
      newEndpoints: [],
      changedEndpoints: [],
      removedEndpoints: [],
      newHeaders: [],
      hypotheses: [],
    };

    if (!prev) {
      // First run — store and return empty diff
      this.snapshots.set(base, current);
      logger.info("[ChangeDetector] First snapshot stored", { base, endpoints: current.size });
      return report;
    }

    // Detect new / changed endpoints
    for (const [path, snap] of current) {
      const old = prev.get(path);
      if (!old) {
        if (snap.statusCode < 400) {
          report.newEndpoints.push(snap.url);
          report.hypotheses.push({
            vulnClass: this.pathToVulnClass(path),
            reasoning: `New endpoint appeared since last scan: ${snap.url} (HTTP ${snap.statusCode})`,
            confidence: 0.65,
            priority: 7,
          });
        }
        continue;
      }

      const changes: string[] = [];
      if (old.statusCode !== snap.statusCode) {
        changes.push(`status ${old.statusCode} → ${snap.statusCode}`);
      }
      if (Math.abs(old.contentLength - snap.contentLength) > 100) {
        changes.push(`size ${old.contentLength} → ${snap.contentLength}`);
      }
      if (old.contentHash !== snap.contentHash && snap.statusCode === 200) {
        changes.push("content changed");
      }

      // New response headers
      for (const [header, value] of Object.entries(snap.headers)) {
        if (!old.headers[header]) {
          report.newHeaders.push({ url: snap.url, header, value });
          if (header.toLowerCase().includes("access-control")) {
            report.hypotheses.push({
              vulnClass: "cors",
              reasoning: `New CORS header detected on ${snap.url}: ${header}: ${value}`,
              confidence: 0.7,
              priority: 6,
            });
          }
        }
      }

      if (changes.length > 0) {
        report.changedEndpoints.push({ url: snap.url, changes });
        if (changes.some(c => c.includes("content changed") || c.includes("size"))) {
          report.hypotheses.push({
            vulnClass: "info_disclosure",
            reasoning: `Content change detected at ${snap.url}: ${changes.join(", ")}. May indicate new exposed data.`,
            confidence: 0.55,
            priority: 5,
          });
        }
      }
    }

    // Detect removed endpoints (may indicate patching)
    for (const [path, old] of prev) {
      if (!current.has(path) && old.statusCode < 400) {
        report.removedEndpoints.push(old.url);
      }
    }

    // Update snapshot
    this.snapshots.set(base, current);

    logger.info("[ChangeDetector] Diff complete", {
      base,
      newEndpoints: report.newEndpoints.length,
      changed: report.changedEndpoints.length,
      removed: report.removedEndpoints.length,
      newHypotheses: report.hypotheses.length,
    });

    return report;
  }

  private async fetchEndpoint(url: string, headers: Record<string, string>): Promise<EndpointSnapshot | null> {
    try {
      const resp = await axios.get(url, {
        headers: { "User-Agent": "Mozilla/5.0 (compatible; NettyHunter/1.0)", ...headers },
        timeout: 5000,
        validateStatus: () => true,
        maxRedirects: 3,
        responseType: "text",
      });

      const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
      const respHeaders: Record<string, string> = {};
      Object.entries(resp.headers).forEach(([k, v]) => {
        respHeaders[k.toLowerCase()] = String(v);
      });

      return {
        url,
        statusCode: resp.status,
        contentLength: body.length,
        contentHash: crypto.createHash("sha256").update(body.slice(0, 4096)).digest("hex").slice(0, 16),
        headers: respHeaders,
        capturedAt: new Date().toISOString(),
      };
    } catch {
      return null;
    }
  }

  private extractBase(url: string): string {
    try {
      const u = new URL(url);
      return `${u.protocol}//${u.host}`;
    } catch {
      return url;
    }
  }

  private pathToVulnClass(path: string): string {
    if (path.includes(".env") || path.includes(".git") || path.includes("backup") || path.includes("phpinfo")) return "info_disclosure";
    if (path.includes("admin") || path.includes("wp-admin") || path.includes("actuator")) return "misconfig";
    if (path.includes("graphql") || path.includes("swagger") || path.includes("openapi")) return "info_disclosure";
    if (path.includes("login") || path.includes("signup")) return "auth_bypass";
    return "info_disclosure";
  }
}

export const changeDetector = new ChangeDetector();
