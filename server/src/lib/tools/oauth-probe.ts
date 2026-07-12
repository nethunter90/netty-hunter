import axios from "axios";
import logger from "../../utils/logger";

interface OAuthVuln {
  issue: string;
  endpoint: string;
  severity: "high" | "medium" | "low";
  detail: string;
}

interface OAuthProbeResult {
  oauthEndpointsFound: string[];
  vulns: OAuthVuln[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string; raw: OAuthVuln }>;
}

const axiosOpts = {
  timeout: 6000,
  validateStatus: () => true,
  maxRedirects: 0,
};

class OAuthProber {
  private getBase(targetUrl: string): string {
    try {
      const u = new URL(targetUrl);
      return `${u.protocol}//${u.host}`;
    } catch {
      return targetUrl.replace(/\/$/, "");
    }
  }

  private isOAuthIndicator(
    status: number,
    headers: Record<string, string | string[] | undefined>,
    bodyLength: number,
    baseline: { status: number; bodyLength: number }
  ): boolean {
    const location = (headers["location"] as string | undefined) || "";
    if (/[?&](code|token|oauth)=/i.test(location) || /oauth/i.test(location)) return true;
    if (status !== 200) return false;
    // A bare 200 is not real signal on its own — many apps (especially SPAs with
    // client-side routing) serve an identical 200 catch-all shell for literally
    // any unmatched path. Juice Shop does exactly this: /oauth/authorize and a
    // guaranteed-bogus path both return the same index.html with status 200,
    // which used to make this function report every guessed OAuth path as
    // "found" — false-positiving every downstream vuln test against a page that
    // was never an OAuth endpoint. Only trust a 200 that's distinguishable from
    // the baseline (different status, or a real body-length difference).
    if (baseline.status === 200 && bodyLength === baseline.bodyLength) return false;
    return true;
  }

  private async discoverEndpoints(
    base: string,
    authHeaders: Record<string, string>
  ): Promise<{ found: string[]; authEndpoint: string | null; tokenEndpoint: string | null; responseTypesSupported: string[] }> {
    const paths = [
      "/oauth/authorize",
      "/oauth2/authorize",
      "/auth/oauth",
      "/connect/authorize",
      "/oauth/token",
      "/oauth2/token",
      "/auth/token",
      "/.well-known/openid-configuration",
      "/.well-known/oauth-authorization-server",
    ];

    const found: string[] = [];
    let authEndpoint: string | null = null;
    let tokenEndpoint: string | null = null;
    let responseTypesSupported: string[] = [];

    let baseline = { status: 0, bodyLength: 0 };
    try {
      const baselineResp = await axios.get(`${base}/__nh_oauth_baseline_${Date.now()}__`, { ...axiosOpts, headers: authHeaders });
      const baselineBody = typeof baselineResp.data === "string" ? baselineResp.data : JSON.stringify(baselineResp.data || "");
      baseline = { status: baselineResp.status, bodyLength: baselineBody.length };
    } catch (err) {
      logger.debug(`[oauth-probe] Baseline request error: ${err}`);
    }

    await Promise.allSettled(
      paths.map(async (path) => {
        const url = `${base}${path}`;
        try {
          const resp = await axios.get(url, { ...axiosOpts, headers: authHeaders });
          const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data || "");
          if (this.isOAuthIndicator(resp.status, resp.headers as Record<string, string | string[] | undefined>, body.length, baseline)) {
            found.push(url);
            logger.debug(`[oauth-probe] Found OAuth endpoint: ${url}`);
          }

          // Parse OIDC discovery document
          if (
            (path === "/.well-known/openid-configuration" || path === "/.well-known/oauth-authorization-server") &&
            resp.status === 200 &&
            resp.data &&
            typeof resp.data === "object"
          ) {
            const doc = resp.data as Record<string, unknown>;
            if (typeof doc.authorization_endpoint === "string") {
              authEndpoint = doc.authorization_endpoint;
              if (!found.includes(authEndpoint)) found.push(authEndpoint);
            }
            if (typeof doc.token_endpoint === "string") {
              tokenEndpoint = doc.token_endpoint;
              if (!found.includes(tokenEndpoint)) found.push(tokenEndpoint);
            }
            if (Array.isArray(doc.response_types_supported)) {
              responseTypesSupported = doc.response_types_supported as string[];
            }
          }
        } catch (err) {
          logger.debug(`[oauth-probe] Error probing ${url}: ${err}`);
        }
      })
    );

    // Fall back to guessing auth endpoint from known paths
    if (!authEndpoint) {
      for (const p of ["/oauth/authorize", "/oauth2/authorize", "/connect/authorize", "/auth/oauth"]) {
        const candidate = `${base}${p}`;
        if (found.includes(candidate)) {
          authEndpoint = candidate;
          break;
        }
      }
    }

    return { found, authEndpoint, tokenEndpoint, responseTypesSupported };
  }

  async probe(targetUrl: string, authHeaders?: Record<string, string>): Promise<OAuthProbeResult> {
    const base = this.getBase(targetUrl);
    const headers = authHeaders || {};
    const vulns: OAuthVuln[] = [];

    const { found: oauthEndpointsFound, authEndpoint, responseTypesSupported } =
      await this.discoverEndpoints(base, headers);

    if (!authEndpoint) {
      logger.debug("[oauth-probe] No authorization endpoint found, skipping vuln tests");
      return { oauthEndpointsFound, vulns, hypotheses: [] };
    }

    const callbackUri = `${base}/callback`;

    // --- Test 1: Missing state parameter ---
    try {
      const url = `${authEndpoint}?response_type=code&client_id=test&redirect_uri=${encodeURIComponent(callbackUri)}`;
      const resp = await axios.get(url, { ...axiosOpts, headers });
      if (resp.status === 200 || (resp.status >= 300 && resp.status < 400)) {
        const location = (resp.headers["location"] as string | undefined) || "";
        const isCodeEndpoint = /[?&]code=/.test(location) || resp.status === 200;
        if (isCodeEndpoint) {
          vulns.push({
            issue: "missing_state",
            endpoint: authEndpoint,
            severity: "medium",
            detail: `Authorization endpoint accepted request without 'state' parameter (CSRF risk). Status: ${resp.status}`,
          });
          logger.debug("[oauth-probe] missing_state vuln detected");
        }
      }
    } catch (err) {
      logger.debug(`[oauth-probe] missing_state test error: ${err}`);
    }

    // --- Test 2: Open redirect_uri ---
    try {
      const evilUri = "https://evil.com/steal";
      const url = `${authEndpoint}?response_type=code&client_id=test&redirect_uri=${encodeURIComponent(evilUri)}&state=xyz`;
      const resp = await axios.get(url, { ...axiosOpts, headers });
      const location = (resp.headers["location"] as string | undefined) || "";
      if (resp.status >= 300 && resp.status < 400 && location.includes("evil.com")) {
        vulns.push({
          issue: "open_redirect_uri",
          endpoint: authEndpoint,
          severity: "high",
          detail: `Authorization endpoint redirected to unvalidated redirect_uri 'https://evil.com/steal'. Location: ${location}`,
        });
        logger.debug("[oauth-probe] open_redirect_uri vuln detected");
      }
    } catch (err) {
      logger.debug(`[oauth-probe] open_redirect_uri test error: ${err}`);
    }

    // --- Test 3: Implicit flow enabled ---
    const implicitInDiscovery =
      responseTypesSupported.length === 0 || responseTypesSupported.some((rt) => rt === "token" || rt.includes("token"));
    if (implicitInDiscovery) {
      try {
        const url = `${authEndpoint}?response_type=token&client_id=test&redirect_uri=${encodeURIComponent(callbackUri)}&state=xyz`;
        const resp = await axios.get(url, { ...axiosOpts, headers });
        if (resp.status !== 400 && resp.status !== 403) {
          vulns.push({
            issue: "implicit_flow",
            endpoint: authEndpoint,
            severity: "medium",
            detail: `Implicit flow (response_type=token) was not rejected. Status: ${resp.status}. Tokens exposed in URL fragments are vulnerable to leakage.`,
          });
          logger.debug("[oauth-probe] implicit_flow vuln detected");
        }
      } catch (err) {
        logger.debug(`[oauth-probe] implicit_flow test error: ${err}`);
      }
    }

    // --- Test 4: Token in URL ---
    try {
      const url = `${authEndpoint}?response_type=token&client_id=test&redirect_uri=${encodeURIComponent(callbackUri)}&state=xyz`;
      const resp = await axios.get(url, { ...axiosOpts, headers });
      const location = (resp.headers["location"] as string | undefined) || "";
      const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data || "");
      const hasTokenInUrl = /[?&#]access_token=/.test(location) || /[?&#]access_token=/.test(body);
      if (hasTokenInUrl) {
        vulns.push({
          issue: "token_in_url",
          endpoint: authEndpoint,
          severity: "medium",
          detail: `access_token appears in URL query string or redirect location, exposing it to browser history, logs, and referrer headers.`,
        });
        logger.debug("[oauth-probe] token_in_url vuln detected");
      }
    } catch (err) {
      logger.debug(`[oauth-probe] token_in_url test error: ${err}`);
    }

    // --- Test 5: PKCE not enforced ---
    try {
      const url = `${authEndpoint}?response_type=code&client_id=test&redirect_uri=${encodeURIComponent(callbackUri)}&state=xyz`;
      // No code_challenge or code_challenge_method params
      const resp = await axios.get(url, { ...axiosOpts, headers });
      if (resp.status !== 400 && resp.status !== 403) {
        vulns.push({
          issue: "pkce_not_required",
          endpoint: authEndpoint,
          severity: "medium",
          detail: `Authorization endpoint accepted authorization code request without PKCE (code_challenge). Status: ${resp.status}. Public clients are vulnerable to authorization code interception.`,
        });
        logger.debug("[oauth-probe] pkce_not_required vuln detected");
      }
    } catch (err) {
      logger.debug(`[oauth-probe] pkce_not_required test error: ${err}`);
    }

    // --- Test 6: Client secret in JS ---
    try {
      const pageResp = await axios.get(targetUrl, { ...axiosOpts, headers });
      const pageBody = typeof pageResp.data === "string" ? pageResp.data : JSON.stringify(pageResp.data || "");

      const secretPattern = /client_?secret["'`\s]*[:=]["'`\s]*([A-Za-z0-9_\-]{8,})/i;

      if (secretPattern.test(pageBody)) {
        vulns.push({
          issue: "secret_exposure",
          endpoint: targetUrl,
          severity: "high",
          detail: `Possible client_secret found hardcoded in the base page HTML/JS.`,
        });
        logger.debug("[oauth-probe] secret_exposure in base page");
      } else {
        // Extract linked JS files
        const jsUrls: string[] = [];
        const scriptTagRe = /<script[^>]+src=["']([^"']+\.js[^"']*)/gi;
        let match: RegExpExecArray | null;
        while ((match = scriptTagRe.exec(pageBody)) !== null && jsUrls.length < 3) {
          const src = match[1];
          const jsUrl = src.startsWith("http") ? src : src.startsWith("/") ? `${base}${src}` : `${base}/${src}`;
          jsUrls.push(jsUrl);
        }

        await Promise.allSettled(
          jsUrls.map(async (jsUrl) => {
            try {
              const jsResp = await axios.get(jsUrl, { ...axiosOpts, headers });
              const jsBody = typeof jsResp.data === "string" ? jsResp.data : JSON.stringify(jsResp.data || "");
              if (secretPattern.test(jsBody)) {
                vulns.push({
                  issue: "secret_exposure",
                  endpoint: jsUrl,
                  severity: "high",
                  detail: `Possible client_secret found hardcoded in JS file: ${jsUrl}`,
                });
                logger.debug(`[oauth-probe] secret_exposure in JS: ${jsUrl}`);
              }
            } catch (err) {
              logger.debug(`[oauth-probe] JS fetch error for ${jsUrl}: ${err}`);
            }
          })
        );
      }
    } catch (err) {
      logger.debug(`[oauth-probe] secret_exposure test error: ${err}`);
    }

    // Build hypotheses from vulns
    const hypotheses = vulns.map((v) => ({
      vulnClass: "oauth_misconfiguration",
      reasoning: v.detail,
      confidence: v.severity === "high" ? 0.8 : 0.65,
      priority: v.severity === "high" ? 9 : 7,
      endpoint: v.endpoint,
      // Full detection detail — HunterEngine attaches this to the hypothesis's
      // evidence so the PROBE phase can recognize this hypothesis was already
      // actively confirmed here (a real authorization-endpoint response — missing
      // state, open redirect_uri, implicit flow accepted, etc.) and skip
      // re-dispatching it to nuclei's misconfig-tag fallback, which has no
      // templates that test OAuth flow semantics.
      raw: v,
    }));

    return { oauthEndpointsFound, vulns, hypotheses };
  }
}

export const oauthProber = new OAuthProber();
