import axios, { AxiosRequestConfig } from "axios";
import logger from "../../utils/logger";

interface RaceResult {
  endpoint: string;
  method: string;
  concurrency: number;
  distinctStatusCodes: number[];
  successCount: number;
  anomalyCount: number;
  isDuplicate: boolean;
  responseVariance: boolean;
  severity: "critical" | "high" | "medium";
  detail: string;
}

interface RaceProbeResult {
  endpointsTested: number;
  vulns: RaceResult[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string }>;
}

const STATE_CHANGE_PATHS = [
  "/purchase",
  "/buy",
  "/checkout",
  "/apply-coupon",
  "/redeem",
  "/transfer",
  "/vote",
  "/like",
  "/claim",
  "/activate",
  "/verify",
  "/order",
  "/payment",
];

class RaceConditionDetector {
  private detectStateEndpoints(
    targetUrl: string
  ): Array<{ url: string; method: "POST" | "GET" }> {
    let baseUrl: string;
    let targetPath: string;

    try {
      const parsed = new URL(targetUrl);
      baseUrl = `${parsed.protocol}//${parsed.host}`;
      targetPath = parsed.pathname;
    } catch {
      baseUrl = targetUrl;
      targetPath = "";
    }

    const endpoints: Array<{ url: string; method: "POST" | "GET" }> = [];

    for (const path of STATE_CHANGE_PATHS) {
      endpoints.push({ url: `${baseUrl}${path}`, method: "POST" });
    }

    if (
      targetPath &&
      STATE_CHANGE_PATHS.some((seg) => targetPath.includes(seg.replace("/", "")))
    ) {
      const alreadyIncluded = endpoints.some((e) => e.url === targetUrl);
      if (!alreadyIncluded) {
        endpoints.push({ url: targetUrl, method: "POST" });
      }
    }

    return endpoints;
  }

  private async raceEndpoint(
    url: string,
    method: "POST" | "GET",
    concurrency: number = 15,
    authHeaders?: Record<string, string>
  ): Promise<RaceResult | null> {
    const requestConfig: AxiosRequestConfig = {
      method,
      url,
      timeout: 8000,
      validateStatus: () => true,
      headers: {
        ...(authHeaders ?? {}),
      },
    };

    const requests = Array.from({ length: concurrency }, () =>
      axios.request(requestConfig)
    );

    const results = await Promise.allSettled(requests);

    const statuses: number[] = [];
    const bodyLengths: number[] = [];

    for (const result of results) {
      if (result.status === "fulfilled") {
        statuses.push(result.value.status);
        const body = result.value.data;
        const bodyStr =
          typeof body === "string" ? body : JSON.stringify(body ?? "");
        bodyLengths.push(bodyStr.length);
      }
    }

    if (statuses.length === 0) {
      return null;
    }

    const successCount = statuses.filter((s) => s >= 200 && s < 300).length;
    const distinctStatusCodes = [...new Set(statuses)];
    const isDuplicate = successCount > 1;

    const distinctBodyLengths = new Set(bodyLengths);
    const responseVariance = distinctBodyLengths.size > 2;

    if (!isDuplicate && !responseVariance) {
      return null;
    }

    const anomalyCount = Math.max(0, successCount - 1);

    let severity: "critical" | "high" | "medium";
    if (isDuplicate && successCount > 2) {
      severity = "critical";
    } else if (isDuplicate) {
      severity = "high";
    } else {
      severity = "medium";
    }

    let detail: string;
    if (isDuplicate) {
      detail = `${successCount} concurrent requests all succeeded (expected at most 1). Possible duplicate action (e.g. coupon applied ${successCount} times). Anomalies: ${anomalyCount}.`;
    } else {
      detail = `Response bodies varied significantly across ${concurrency} concurrent requests (${distinctBodyLengths.size} distinct lengths), suggesting inconsistent server state.`;
    }

    return {
      endpoint: url,
      method,
      concurrency,
      distinctStatusCodes,
      successCount,
      anomalyCount,
      isDuplicate,
      responseVariance,
      severity,
      detail,
    };
  }

  async probe(
    targetUrl: string,
    authHeaders?: Record<string, string>
  ): Promise<RaceProbeResult> {
    const endpoints = this.detectStateEndpoints(targetUrl);

    const raceJobs = endpoints.map(({ url, method }) =>
      this.raceEndpoint(url, method, 15, authHeaders).catch((err) => {
        logger.warn(`RaceConditionDetector: error probing ${url}: ${err?.message}`);
        return null;
      })
    );

    const settled = await Promise.allSettled(raceJobs);

    const vulns: RaceResult[] = [];
    for (const result of settled) {
      if (result.status === "fulfilled" && result.value !== null) {
        vulns.push(result.value);
      }
    }

    const hypotheses = vulns.map((vuln) => ({
      vulnClass: "race_condition",
      reasoning: vuln.detail,
      confidence: vuln.isDuplicate ? 0.8 : 0.55,
      priority: vuln.severity === "critical" ? 9 : 7,
      endpoint: vuln.endpoint,
    }));

    return {
      endpointsTested: endpoints.length,
      vulns,
      hypotheses,
    };
  }
}

export const raceConditionDetector = new RaceConditionDetector();
