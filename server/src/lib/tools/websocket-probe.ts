import axios from "axios";
import logger from "../../utils/logger";

interface WSVuln {
  endpoint: string;
  issue: string;       // "no_origin_check" | "unauthenticated_access" | "reflection" | "open_endpoint"
  severity: "high" | "medium" | "low";
  detail: string;
}

interface WSProbeResult {
  endpointsFound: string[];
  vulns: WSVuln[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number }>;
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

class WebSocketProber {
  async detectEndpoints(baseUrl: string, authHeaders?: Record<string, string>): Promise<string[]> {
    const base = baseUrl.replace(/\/$/, "");
    const found: string[] = [];

    // Fetch the base page and look for ws:// or wss:// references in the response body
    try {
      const res = await axios.get(base, {
        headers: { ...(authHeaders || {}) },
        timeout: 5000,
        validateStatus: () => true,
      });
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
        try {
          const res = await axios.get(url, {
            headers: {
              ...(authHeaders || {}),
              "Upgrade": "websocket",
              "Connection": "Upgrade",
              "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
              "Sec-WebSocket-Version": "13",
            },
            timeout: 5000,
            validateStatus: () => true,
          });
          if (res.status !== 404) {
            const wsUrl = toWsUrl(url);
            if (!found.includes(wsUrl)) {
              found.push(wsUrl);
            }
          }
        } catch (err) {
          logger.debug("[WebSocketProber] Path probe error", { url, err: String(err) });
        }
      })
    );

    return found;
  }

  async testEndpoint(wsUrl: string, authHeaders?: Record<string, string>): Promise<WSVuln[]> {
    const vulns: WSVuln[] = [];
    const httpUrl = toHttpUrl(wsUrl);

    // Test 1: Connect with a mismatched (evil) Origin header → if 101 accepted → no_origin_check
    try {
      const res = await axios.get(httpUrl, {
        headers: {
          ...(authHeaders || {}),
          "Upgrade": "websocket",
          "Connection": "Upgrade",
          "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
          "Sec-WebSocket-Version": "13",
          "Origin": "https://evil.com",
        },
        timeout: 5000,
        validateStatus: () => true,
      });
      if (res.status === 101) {
        vulns.push({
          endpoint: wsUrl,
          issue: "no_origin_check",
          severity: "high",
          detail: `WebSocket endpoint accepted connection from Origin: https://evil.com (HTTP 101). No origin validation is enforced.`,
        });
      }
    } catch (err) {
      logger.debug("[WebSocketProber] Origin check test error", { wsUrl, err: String(err) });
    }

    // Test 2: Connect with no auth headers → if 101 accepted → unauthenticated_access
    try {
      const res = await axios.get(httpUrl, {
        headers: {
          "Upgrade": "websocket",
          "Connection": "Upgrade",
          "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
          "Sec-WebSocket-Version": "13",
        },
        timeout: 5000,
        validateStatus: () => true,
      });
      if (res.status === 101) {
        vulns.push({
          endpoint: wsUrl,
          issue: "unauthenticated_access",
          severity: "high",
          detail: `WebSocket endpoint accepted unauthenticated connection (HTTP 101) with no auth headers. Authentication is not enforced.`,
        });
      }
    } catch (err) {
      logger.debug("[WebSocketProber] Unauthenticated access test error", { wsUrl, err: String(err) });
    }

    // Test 3: Send a reflection probe message → check if echoed back verbatim → reflection
    // Since we cannot open a true WS frame without the ws package, we send an HTTP GET
    // with a probe value in a header and check if it appears in the response body.
    const probeToken = `ws-reflect-probe-${Date.now()}`;
    try {
      const res = await axios.get(httpUrl, {
        headers: {
          ...(authHeaders || {}),
          "Upgrade": "websocket",
          "Connection": "Upgrade",
          "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
          "Sec-WebSocket-Version": "13",
          "X-Probe": probeToken,
        },
        timeout: 5000,
        validateStatus: () => true,
      });
      const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
      if (body.includes(probeToken)) {
        vulns.push({
          endpoint: wsUrl,
          issue: "reflection",
          severity: "medium",
          detail: `WebSocket endpoint reflected the probe token "${probeToken}" verbatim in the HTTP response body. Possible reflection/XSS vector.`,
        });
      }
    } catch (err) {
      logger.debug("[WebSocketProber] Reflection probe test error", { wsUrl, err: String(err) });
    }

    return vulns;
  }

  async probe(baseUrl: string, authHeaders?: Record<string, string>): Promise<WSProbeResult> {
    const result: WSProbeResult = {
      endpointsFound: [],
      vulns: [],
      hypotheses: [],
    };

    try {
      result.endpointsFound = await this.detectEndpoints(baseUrl, authHeaders);
    } catch (err) {
      logger.debug("[WebSocketProber] detectEndpoints failed", { baseUrl, err: String(err) });
      return result;
    }

    for (const endpoint of result.endpointsFound) {
      try {
        const endpointVulns = await this.testEndpoint(endpoint, authHeaders);
        result.vulns.push(...endpointVulns);
      } catch (err) {
        logger.debug("[WebSocketProber] testEndpoint failed", { endpoint, err: String(err) });
      }
    }

    for (const vuln of result.vulns) {
      if (vuln.issue === "no_origin_check") {
        result.hypotheses.push({
          vulnClass: "csrf",
          reasoning: `WebSocket endpoint ${vuln.endpoint} accepts connections from arbitrary origins. A malicious page can initiate cross-origin WebSocket connections and perform CSRF-like actions.`,
          confidence: 0.7,
          priority: 8,
        });
      } else if (vuln.issue === "unauthenticated_access") {
        result.hypotheses.push({
          vulnClass: "broken_auth",
          reasoning: `WebSocket endpoint ${vuln.endpoint} accepts unauthenticated connections. Sensitive data or functionality may be accessible without valid credentials.`,
          confidence: 0.75,
          priority: 9,
        });
      } else if (vuln.issue === "reflection") {
        result.hypotheses.push({
          vulnClass: "xss",
          reasoning: `WebSocket endpoint ${vuln.endpoint} reflects input back to the client verbatim. This may be exploitable for reflected or stored XSS via WebSocket messages.`,
          confidence: 0.65,
          priority: 7,
        });
      }
    }

    return result;
  }
}

export const webSocketProber = new WebSocketProber();
