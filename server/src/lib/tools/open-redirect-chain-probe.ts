import axios from "axios";
import logger from "../../utils/logger";

interface RedirectVuln {
  url: string;
  param: string;
  redirectsTo: string;
  chainable: boolean;    // can be chained with OAuth
  xssChainable: boolean; // can chain to XSS via javascript: or data: URI
  severity: "critical" | "high" | "medium";
  detail: string;
}

interface OpenRedirectResult {
  vulns: RedirectVuln[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string }>;
}

const REDIRECT_PARAMS = [
  "redirect",
  "next",
  "url",
  "return",
  "returnUrl",
  "returnTo",
  "redirect_uri",
  "redirect_url",
  "goto",
  "destination",
  "dest",
  "target",
  "redir",
  "location",
  "forward",
  "back",
];

const REDIRECT_PAYLOADS = [
  "https://evil.com",                              // basic external redirect
  "//evil.com",                                    // protocol-relative
  "https://evil.com%2F@target.com",               // credentials bypass
  "javascript:alert(1)",                           // XSS via javascript: URI
  "data:text/html,<script>alert(1)</script>",      // data: URI XSS
];

class OpenRedirectChainProber {
  async probe(
    targetUrl: string,
    authHeaders: Record<string, string> = {}
  ): Promise<OpenRedirectResult> {
    // Detect OAuth endpoints from baseline page
    const hasOAuthEndpoints = await this.detectOAuthEndpoints(targetUrl, authHeaders);

    // Build all probe tasks: GET (query param) + POST (body) for every param × payload
    type ProbeTask = {
      url: string;
      param: string;
      payload: string;
      method: "GET" | "POST";
      body?: Record<string, string>;
    };

    const tasks: ProbeTask[] = [];
    for (const param of REDIRECT_PARAMS) {
      for (const payload of REDIRECT_PAYLOADS) {
        // GET via query string
        tasks.push({
          url: `${targetUrl}?${param}=${encodeURIComponent(payload)}`,
          param,
          payload,
          method: "GET",
        });
        // POST via body
        tasks.push({
          url: targetUrl,
          param,
          payload,
          method: "POST",
          body: { [param]: payload },
        });
      }
    }

    const settled = await Promise.allSettled(
      tasks.map(task => this.probeOne(task.url, task.param, task.payload, task.method, task.body, authHeaders, hasOAuthEndpoints))
    );

    // Collect non-null results, deduplicate by (param, redirectsTo)
    const seen = new Set<string>();
    const vulns: RedirectVuln[] = [];
    for (const r of settled) {
      if (r.status === "fulfilled" && r.value !== null) {
        const key = `${r.value.param}::${r.value.redirectsTo}`;
        if (!seen.has(key)) {
          seen.add(key);
          vulns.push(r.value);
        }
      }
    }

    const hypotheses = this.buildHypotheses(vulns, hasOAuthEndpoints);

    logger.info("[OpenRedirectChainProber] Probe complete", {
      target: targetUrl,
      vulnsFound: vulns.length,
      hasOAuth: hasOAuthEndpoints,
      hypothesisCount: hypotheses.length,
    });

    return { vulns, hypotheses };
  }

  private async probeOne(
    url: string,
    param: string,
    payload: string,
    method: "GET" | "POST",
    body: Record<string, string> | undefined,
    authHeaders: Record<string, string>,
    hasOAuthEndpoints: boolean
  ): Promise<RedirectVuln | null> {
    try {
      const config = {
        headers: {
          ...authHeaders,
          ...(method === "POST" ? { "Content-Type": "application/x-www-form-urlencoded" } : {}),
        },
        timeout: 5000,
        validateStatus: () => true,
        maxRedirects: 0,
      };

      const response = method === "GET"
        ? await axios.get(url, config)
        : await axios.post(url, new URLSearchParams(body ?? {}).toString(), config);

      const status = response.status;
      const locationHeader: string = (response.headers["location"] as string | undefined) ?? "";

      // Must be a redirect status with a Location header pointing at our payload
      const isRedirectStatus = [301, 302, 303, 307, 308].includes(status);
      if (!isRedirectStatus || !locationHeader) return null;

      const redirectsToEvil =
        locationHeader.includes("evil.com") ||
        locationHeader.startsWith("javascript:") ||
        locationHeader.startsWith("data:");

      if (!redirectsToEvil) return null;

      const redirectsTo = locationHeader;
      const xssChainable =
        redirectsTo.startsWith("javascript:") || redirectsTo.startsWith("data:");
      const chainable = redirectsTo.includes("evil.com") && hasOAuthEndpoints;

      let severity: RedirectVuln["severity"];
      if (xssChainable || (chainable && hasOAuthEndpoints)) {
        severity = "critical";
      } else if (chainable || redirectsTo.includes("evil.com")) {
        severity = redirectsTo.includes("evil.com") && hasOAuthEndpoints ? "critical" : "high";
      } else {
        severity = "medium";
      }

      // Recompute severity cleanly
      if (xssChainable) {
        severity = "critical";
      } else if (chainable) {
        severity = "critical";
      } else {
        severity = redirectsTo.includes("evil.com") ? "high" : "medium";
      }

      const detail = xssChainable
        ? `Open redirect via param '${param}' (${method}) → '${redirectsTo}' — XSS chainable via ${redirectsTo.startsWith("javascript:") ? "javascript:" : "data:"} URI`
        : chainable
          ? `Open redirect via param '${param}' (${method}) → '${redirectsTo}' — OAuth token theft possible; OAuth endpoints detected on target`
          : `Open redirect via param '${param}' (${method}) → '${redirectsTo}'`;

      logger.warn("[OpenRedirectChainProber] Redirect vuln found", {
        url,
        param,
        method,
        redirectsTo,
        severity,
      });

      return { url, param, redirectsTo, chainable, xssChainable, severity, detail };
    } catch {
      // Timeouts and connection errors are expected for many params/payloads
      return null;
    }
  }

  private async detectOAuthEndpoints(
    targetUrl: string,
    authHeaders: Record<string, string>
  ): Promise<boolean> {
    try {
      const response = await axios.get(targetUrl, {
        headers: authHeaders,
        timeout: 5000,
        validateStatus: () => true,
        maxRedirects: 3,
      });
      const body: string =
        typeof response.data === "string" ? response.data : JSON.stringify(response.data);
      return /\/oauth|\/auth/i.test(body);
    } catch {
      return false;
    }
  }

  private buildHypotheses(
    vulns: RedirectVuln[],
    hasOAuthEndpoints: boolean
  ): Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string }> {
    if (vulns.length === 0) return [];

    const hypotheses: Array<{
      vulnClass: string;
      reasoning: string;
      confidence: number;
      priority: number;
      endpoint: string;
    }> = [];

    // Base open_redirect hypothesis — these are aggregate hypotheses across
    // possibly several vulnerable params/URLs, so there's no single "the"
    // endpoint; the first matching vuln's URL is used as a representative,
    // already-confirmed-vulnerable anchor rather than the hunt's root URL.
    const paramSample = [...new Set(vulns.map(v => v.param))].slice(0, 3).join(", ");
    hypotheses.push({
      vulnClass: "open_redirect",
      reasoning: `Open redirect confirmed on ${vulns.length} parameter(s) (${paramSample}) — attacker can redirect victims to arbitrary external domains.`,
      confidence: 0.75,
      priority: 7,
      endpoint: vulns[0].url,
    });

    // OAuth misconfiguration chain
    const chainableVulns = vulns.filter(v => v.chainable);
    if (chainableVulns.length > 0) {
      hypotheses.push({
        vulnClass: "oauth_misconfiguration",
        reasoning: `Open redirect on param(s) ${[...new Set(chainableVulns.map(v => v.param))].join(", ")} is chainable with OAuth endpoints detected on target — redirect_uri bypass may allow OAuth token theft.`,
        confidence: 0.7,
        priority: 9,
        endpoint: chainableVulns[0].url,
      });
    }

    // XSS chain
    const xssVulns = vulns.filter(v => v.xssChainable);
    if (xssVulns.length > 0) {
      const xssParams = [...new Set(xssVulns.map(v => v.param))].join(", ");
      hypotheses.push({
        vulnClass: "xss",
        reasoning: `Open redirect on param(s) ${xssParams} accepts javascript: or data: URIs — direct XSS execution possible via redirect chain.`,
        confidence: 0.8,
        priority: 9,
        endpoint: xssVulns[0].url,
      });
    }

    return hypotheses;
  }
}

export const openRedirectChainProber = new OpenRedirectChainProber();
