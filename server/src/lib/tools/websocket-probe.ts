import http, { IncomingMessage } from "http";
import https from "https";
import logger from "../../utils/logger";
import { scopedHttp } from "../net/scoped-http";
import { ScopeGuard } from "../../middleware/scopeGuard";

interface WSVuln {
  endpoint: string;
  issue: string;       // "no_origin_check" | "unauthenticated_access" | "reflection" | "open_endpoint"
  severity: "high" | "medium" | "low";
  detail: string;
}

interface WSProbeResult {
  endpointsFound: string[];
  vulns: WSVuln[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string; raw: WSVuln }>;
}

const WS_PATHS = [
  "/ws",
  "/websocket",
  "/socket",
  "/socket.io",
  "/cable",
  "/actioncable",
  "/ws/v1",
  "/ws/v2",
];

function toWsUrl(httpUrl: string): string {
  return httpUrl.replace(/^https:\/\//, "wss://").replace(/^http:\/\//, "ws://");
}

function toHttpUrl(wsUrl: string): string {
  return wsUrl.replace(/^wss:\/\//, "https://").replace(/^ws:\/\//, "http://");
}

interface WsCheckResult {
  status: number | null;
  body: string;
}

/**
 * axios cannot observe a genuine "101 Switching Protocols" response — Node's
 * HTTP client fires an 'upgrade' event instead of resolving the request
 * normally for status 101, and axios has no listener for it, so the request
 * just hangs until its own timeout and gets silently discarded in a catch
 * block. That meant every technique below that depends on seeing a real 101
 * (i.e. all of them, against any server that actually completes the
 * handshake) could never fire against a genuine WebSocket endpoint —
 * confirmed by testing axios against a real Node http "upgrade" response,
 * which timed out every time rather than resolving with status 101. This
 * uses the raw http/https module directly and listens for both "response"
 * (a normal, non-upgrading reply — 404, 400, etc.) and "upgrade" (the actual
 * 101 case) so a real handshake acceptance is observed instead of discarded.
 */
async function checkWsUpgrade(url: string, headers: Record<string, string>, timeoutMs = 5000, programId?: number): Promise<WsCheckResult> {
  const scopeCheck = await ScopeGuard.getInstance().isInScope(url, programId);
  if (!scopeCheck.allowed) {
    logger.warn("[WebSocketProber] checkWsUpgrade blocked by ScopeGuard", { url, reason: scopeCheck.reason });
    return { status: null, body: "" };
  }
  return new Promise((resolve) => {
    let settled = false;
    const settle = (result: WsCheckResult) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const lib = url.startsWith("https://") ? https : http;
    let req: ReturnType<typeof http.request>;
    try {
      req = lib.request(url, { method: "GET", headers, timeout: timeoutMs }, (res: IncomingMessage) => {
        let body = "";
        res.on("data", (chunk) => { if (body.length < 65536) body += String(chunk); });
        res.on("end", () => settle({ status: res.statusCode ?? null, body }));
        res.on("error", () => settle({ status: res.statusCode ?? null, body }));
      });
    } catch {
      settle({ status: null, body: "" });
      return;
    }

    req.on("upgrade", (res: IncomingMessage, socket) => {
      settle({ status: res.statusCode ?? 101, body: "" });
      socket.destroy();
    });
    req.on("timeout", () => { req.destroy(); settle({ status: null, body: "" }); });
    req.on("error", () => settle({ status: null, body: "" }));
    req.end();
  });
}

class WebSocketProber {
  async detectEndpoints(baseUrl: string, authHeaders?: Record<string, string>, programId?: number): Promise<string[]> {
    const base = baseUrl.replace(/\/$/, "");
    const found: string[] = [];

    // Fetch the base page and look for ws:// or wss:// references in the response body
    try {
      const res = await scopedHttp.get(base, {
        headers: { ...(authHeaders || {}) },
        timeout: 5000,
        validateStatus: () => true,
      }, programId);
      const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
      const matches = body.match(/(wss?:\/\/[^\s"']+)/g) || [];
      for (const match of matches) {
        const clean = match.replace(/[)"'>]+$/, "");
        if (!found.includes(clean)) {
          found.push(clean);
        }
      }
    } catch (err) {
      logger.debug("[WebSocketProber] Failed to fetch base URL for WS reference scan", { baseUrl, err: String(err) });
    }

    // Probe known WS paths — anything that responds with 101 or 400 (not 404) suggests a WS endpoint
    await Promise.allSettled(
      WS_PATHS.map(async (path) => {
        const url = `${base}${path}`;
        const res = await checkWsUpgrade(url, {
          ...(authHeaders || {}),
          "Upgrade": "websocket",
          "Connection": "Upgrade",
          "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
          "Sec-WebSocket-Version": "13",
        }, 5000, programId);
        if (res.status !== null && res.status !== 404) {
          const wsUrl = toWsUrl(url);
          if (!found.includes(wsUrl)) {
            found.push(wsUrl);
          }
        }
      })
    );

    return found;
  }

  async testEndpoint(wsUrl: string, authHeaders?: Record<string, string>, programId?: number): Promise<WSVuln[]> {
    const vulns: WSVuln[] = [];
    const httpUrl = toHttpUrl(wsUrl);

    // Test 1: Connect with a mismatched (evil) Origin header → if 101 accepted → no_origin_check
    {
      const res = await checkWsUpgrade(httpUrl, {
        ...(authHeaders || {}),
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version": "13",
        "Origin": "https://evil.com",
      }, 5000, programId);
      if (res.status === 101) {
        vulns.push({
          endpoint: wsUrl,
          issue: "no_origin_check",
          severity: "high",
          detail: `WebSocket endpoint accepted connection from Origin: https://evil.com (HTTP 101). No origin validation is enforced.`,
        });
      }
    }

    // Test 2: Connect with no auth headers → if 101 accepted → unauthenticated_access
    {
      const res = await checkWsUpgrade(httpUrl, {
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version": "13",
      }, 5000, programId);
      if (res.status === 101) {
        vulns.push({
          endpoint: wsUrl,
          issue: "unauthenticated_access",
          severity: "high",
          detail: `WebSocket endpoint accepted unauthenticated connection (HTTP 101) with no auth headers. Authentication is not enforced.`,
        });
      }
    }

    // Test 3: Send a reflection probe message → check if echoed back verbatim → reflection.
    // A genuine upgrade (101) has no HTTP body to reflect into — this only fires
    // against a target that responds without actually completing the handshake.
    const probeToken = `ws-reflect-probe-${Date.now()}`;
    {
      const res = await checkWsUpgrade(httpUrl, {
        ...(authHeaders || {}),
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version": "13",
        "X-Probe": probeToken,
      }, 5000, programId);
      if (res.body.includes(probeToken)) {
        vulns.push({
          endpoint: wsUrl,
          issue: "reflection",
          severity: "medium",
          detail: `WebSocket endpoint reflected the probe token "${probeToken}" verbatim in the HTTP response body. Possible reflection/XSS vector.`,
        });
      }
    }

    return vulns;
  }

  async probe(baseUrl: string, authHeaders?: Record<string, string>, programId?: number): Promise<WSProbeResult> {
    const result: WSProbeResult = {
      endpointsFound: [],
      vulns: [],
      hypotheses: [],
    };

    try {
      result.endpointsFound = await this.detectEndpoints(baseUrl, authHeaders, programId);
    } catch (err) {
      logger.debug("[WebSocketProber] detectEndpoints failed", { baseUrl, err: String(err) });
      return result;
    }

    for (const endpoint of result.endpointsFound) {
      try {
        const endpointVulns = await this.testEndpoint(endpoint, authHeaders, programId);
        result.vulns.push(...endpointVulns);
      } catch (err) {
        logger.debug("[WebSocketProber] testEndpoint failed", { endpoint, err: String(err) });
      }
    }

    // raw: the WSVuln itself — HunterEngine attaches this to the hypothesis's
    // evidence so the PROBE phase can recognize it was already actively
    // confirmed here (a real HTTP 101 handshake acceptance with a mismatched
    // Origin / no auth headers, or a verbatim-reflected probe token) and skip
    // re-dispatching it to a generic tool. csrf/broken_auth/xss all pass
    // toolSupportsClass via nuclei/dalfox's declared vulnClasses, but none of
    // those tools' actual templates test WebSocket handshake behavior — the
    // gate passing is coincidental, not real coverage.
    for (const vuln of result.vulns) {
      if (vuln.issue === "no_origin_check") {
        result.hypotheses.push({
          vulnClass: "csrf",
          reasoning: `WebSocket endpoint ${vuln.endpoint} accepts connections from arbitrary origins. A malicious page can initiate cross-origin WebSocket connections and perform CSRF-like actions.`,
          confidence: 0.7,
          priority: 8,
          endpoint: vuln.endpoint,
          raw: vuln,
        });
      } else if (vuln.issue === "unauthenticated_access") {
        result.hypotheses.push({
          vulnClass: "broken_auth",
          reasoning: `WebSocket endpoint ${vuln.endpoint} accepts unauthenticated connections. Sensitive data or functionality may be accessible without valid credentials.`,
          confidence: 0.75,
          priority: 9,
          endpoint: vuln.endpoint,
          raw: vuln,
        });
      } else if (vuln.issue === "reflection") {
        result.hypotheses.push({
          vulnClass: "xss",
          reasoning: `WebSocket endpoint ${vuln.endpoint} reflects input back to the client verbatim. This may be exploitable for reflected or stored XSS via WebSocket messages.`,
          confidence: 0.65,
          priority: 7,
          endpoint: vuln.endpoint,
          raw: vuln,
        });
      }
    }

    return result;
  }
}

export const webSocketProber = new WebSocketProber();
