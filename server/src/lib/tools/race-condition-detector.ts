import axios, { AxiosRequestConfig } from "axios";
import logger from "../../utils/logger";
import { getCsrfHeaders } from "./csrf-aware-request";

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
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string; raw: RaceResult }>;
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
  // Per-target cache: STATE_CHANGE_PATHS is a blind list of guessed route
  // names tried against every target. A SPA that serves its index.html
  // shell for any path (client-side routing with a server-side catch-all)
  // returns an identical 200 for a guessed "/purchase" and a nonexistent
  // "/__whatever__" alike — 15 concurrent requests against a catch-all
  // trivially "all succeed," which isDuplicate would misread as a real
  // race condition on every single guessed path. Same baseline-diff fix
  // already applied to oauth-probe.ts's false-positive bug: fetch one
  // guaranteed-bogus path per target and compare status+bodyLength before
  // trusting a guessed endpoint is a real, distinct route.
  private baselineCache = new Map<string, { status: number; bodyLength: number }>();

  private async getBaseline(baseUrl: string, authHeaders?: Record<string, string>): Promise<{ status: number; bodyLength: number } | null> {
    if (this.baselineCache.has(baseUrl)) return this.baselineCache.get(baseUrl)!;
    try {
      const bogusPath = `/__nettyhunter_baseline_${Math.random().toString(36).slice(2)}__`;
      const resp = await axios.get(`${baseUrl}${bogusPath}`, {
        timeout: 8000,
        validateStatus: () => true,
        headers: authHeaders ?? {},
      });
      const body = resp.data;
      const bodyStr = typeof body === "string" ? body : JSON.stringify(body ?? "");
      const baseline = { status: resp.status, bodyLength: bodyStr.length };
      this.baselineCache.set(baseUrl, baseline);
      return baseline;
    } catch {
      return null;
    }
  }

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
    authHeaders?: Record<string, string>,
    baseline?: { status: number; bodyLength: number } | null,
  ): Promise<RaceResult | null> {
    // Warm the CSRF token cache BEFORE building the burst — discovering it
    // inline per-request (as csrfAwareRequest does for single-shot probes) would
    // stagger the requests' timing and defeat the point of a concurrent burst.
    // A POST that's rejected purely for a missing CSRF token would otherwise
    // never expose a real race window at all.
    let csrfExtra: Record<string, string> = {};
    if (method === "POST") {
      try {
        csrfExtra = await getCsrfHeaders(new URL(url).origin, authHeaders);
      } catch {
        // discovery failure — proceed without it, same as before this existed
      }
    }

    const requestConfig: AxiosRequestConfig = {
      method,
      url,
      timeout: 8000,
      validateStatus: () => true,
      headers: {
        ...(authHeaders ?? {}),
        ...csrfExtra,
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

    // Indistinguishable from a bogus path this target never routes to
    // (e.g. a SPA's catch-all shell) — "all 15 succeeded" is guaranteed
    // here regardless of any real business logic, so it's not a signal.
    if (baseline && statuses[0] === baseline.status && bodyLengths[0] === baseline.bodyLength) {
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

    let baseUrl: string;
    try {
      baseUrl = new URL(targetUrl).origin;
    } catch {
      baseUrl = targetUrl;
    }
    const baseline = await this.getBaseline(baseUrl, authHeaders);

    const raceJobs = endpoints.map(({ url, method }) =>
      this.raceEndpoint(url, method, 15, authHeaders, baseline).catch((err) => {
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
      // Full detection detail — HunterEngine attaches this to the hypothesis's
      // evidence so the PROBE phase can recognize this hypothesis was already
      // actively confirmed here and skip re-dispatching it to a generic tool
      // (nuclei/curl_probe) that has no way to test for a race condition.
      raw: vuln,
    }));

    return {
      endpointsTested: endpoints.length,
      vulns,
      hypotheses,
    };
  }
}

export const raceConditionDetector = new RaceConditionDetector();
