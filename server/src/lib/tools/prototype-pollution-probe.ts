import axios from "axios";
import logger from "../../utils/logger";

interface PollutionResult {
  url: string;
  vector: string;
  payload: string;
  reflected: boolean;
  serverError: boolean;
  severity: "high" | "medium";
  detail: string;
}

interface PollutionProbeResult {
  tested: number;
  vulns: PollutionResult[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string }>;
}

const MARKER = "__pp_netty__";

class PrototypePollutionProber {
  private buildTestUrls(
    baseUrl: string
  ): Array<{ url: string; vector: string; payload: string; method?: string; body?: string; contentType?: string }> {
    const results: Array<{
      url: string;
      vector: string;
      payload: string;
      method?: string;
      body?: string;
      contentType?: string;
    }> = [];

    const hasQuery = baseUrl.includes("?");
    const sep = hasQuery ? "&" : "?";

    results.push({
      url: `${baseUrl}${sep}__proto__[polluted]=${MARKER}`,
      vector: "query_param_bracket",
      payload: `__proto__[polluted]=${MARKER}`,
    });

    results.push({
      url: `${baseUrl}${sep}__proto__.polluted=${MARKER}`,
      vector: "query_param_dot",
      payload: `__proto__.polluted=${MARKER}`,
    });

    results.push({
      url: `${baseUrl}${sep}constructor.prototype.polluted=${MARKER}`,
      vector: "query_param_constructor_dot",
      payload: `constructor.prototype.polluted=${MARKER}`,
    });

    results.push({
      url: `${baseUrl}${sep}constructor[prototype][polluted]=${MARKER}`,
      vector: "query_param_constructor_bracket",
      payload: `constructor[prototype][polluted]=${MARKER}`,
    });

    results.push({
      url: `${baseUrl}${sep}__proto__[toString]=${MARKER}`,
      vector: "query_param_proto_tostring",
      payload: `__proto__[toString]=${MARKER}`,
    });

    if (hasQuery) {
      results.push({
        url: `${baseUrl}&__proto__[polluted]=${MARKER}`,
        vector: "query_param_append",
        payload: `&__proto__[polluted]=${MARKER}`,
      });
    }

    if (baseUrl.includes("/api")) {
      results.push({
        url: baseUrl,
        vector: "json_body_proto",
        payload: `{"__proto__":{"polluted":"${MARKER}"}}`,
        method: "POST",
        body: JSON.stringify({ __proto__: { polluted: MARKER } }),
        contentType: "application/json",
      });

      results.push({
        url: baseUrl,
        vector: "json_body_constructor",
        payload: `{"constructor":{"prototype":{"polluted":"${MARKER}"}}}`,
        method: "POST",
        body: JSON.stringify({ constructor: { prototype: { polluted: MARKER } } }),
        contentType: "application/json",
      });
    }

    return results;
  }

  private async testUrl(
    url: string,
    vector: string,
    payload: string,
    authHeaders?: Record<string, string>,
    method?: string,
    body?: string,
    contentType?: string
  ): Promise<PollutionResult | null> {
    try {
      const headers: Record<string, string> = { ...(authHeaders ?? {}) };
      if (contentType) {
        headers["Content-Type"] = contentType;
      }

      let response;
      if (method === "POST") {
        response = await axios.post(url, body, {
          headers,
          timeout: 7000,
          validateStatus: () => true,
        });
      } else {
        response = await axios.get(url, {
          headers,
          timeout: 7000,
          validateStatus: () => true,
        });
      }

      const responseText = typeof response.data === "string"
        ? response.data
        : JSON.stringify(response.data);

      const reflected = responseText.includes(MARKER);
      const serverError = response.status === 500;

      if (!reflected && !serverError) {
        return null;
      }

      const severity: "high" | "medium" = reflected ? "high" : "medium";
      const detail = reflected
        ? `Prototype pollution marker reflected in response via ${vector}`
        : `Server returned 500 after prototype pollution attempt via ${vector}`;

      logger.debug(`[PrototypePollutionProber] Found vuln at ${url} vector=${vector} reflected=${reflected} serverError=${serverError}`);

      return {
        url,
        vector,
        payload,
        reflected,
        serverError,
        severity,
        detail,
      };
    } catch (err) {
      logger.debug(`[PrototypePollutionProber] Error testing ${url}: ${(err as Error).message}`);
      return null;
    }
  }

  async probe(targetUrl: string, authHeaders?: Record<string, string>): Promise<PollutionProbeResult> {
    const testCases = this.buildTestUrls(targetUrl);

    const settledResults = await Promise.allSettled(
      testCases.map((tc) =>
        this.testUrl(tc.url, tc.vector, tc.payload, authHeaders, tc.method, tc.body, tc.contentType)
      )
    );

    const vulns: PollutionResult[] = settledResults
      .filter((r): r is PromiseFulfilledResult<PollutionResult> => r.status === "fulfilled" && r.value !== null)
      .map((r) => r.value);

    const hypotheses = vulns.map((v) => ({
      vulnClass: "prototype_pollution",
      reasoning: v.detail,
      confidence: v.reflected ? 0.75 : 0.5,
      priority: 8,
      endpoint: v.url,
    }));

    return {
      tested: testCases.length,
      vulns,
      hypotheses,
    };
  }
}

export const prototypePollutionProber = new PrototypePollutionProber();
