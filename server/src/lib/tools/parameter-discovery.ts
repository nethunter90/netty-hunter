/**
 * Arjun-style hidden HTTP parameter fuzzer.
 * Sends batches of parameters and detects which ones influence the server response.
 */
import { scopedHttp } from "../net/scoped-http";
import logger from "../../utils/logger";

interface DiscoveredParam {
  name: string;
  method: "GET" | "POST";
  url: string;
  evidence: string;
  type: "reflected" | "behavior_change" | "error_trigger";
}

interface ParamDiscoveryResult {
  discovered: DiscoveredParam[];
  tested: number;
  hypotheses: Array<{
    vulnClass: string;
    reasoning: string;
    targetUrl: string;
    confidence: number;
    priority: number;
  }>;
}

const WORDLIST: string[] = [
  "id", "user_id", "userId", "account_id", "file", "path", "url", "redirect", "next", "return",
  "returnUrl", "callback", "page", "limit", "offset", "sort", "order", "filter", "search", "q",
  "query", "token", "key", "api_key", "apiKey", "secret", "password", "hash", "sig", "signature",
  "debug", "test", "admin", "format", "type", "mode", "action", "method", "cmd", "command", "exec",
  "load", "include", "require", "dir", "folder", "template", "theme", "lang", "locale", "currency",
  "country", "email", "username", "name", "ref", "source", "dest", "to", "from", "subject", "body",
  "data", "payload", "content", "input", "value", "field", "param", "arg", "variable", "config",
  "settings", "prefs", "preferences", "role", "permission", "access", "scope", "grant", "auth",
  "code", "state", "nonce", "csrf", "xsrf", "_csrf", "__proto__", "constructor", "prototype",
];

const BATCH_SIZE = 20;
const MAX_CONCURRENCY = 5;
const REQUEST_TIMEOUT = 8000;

function buildGetUrl(baseUrl: string, params: string[]): string {
  const qs = params
    .map((p) => `${encodeURIComponent(p)}=netty_${encodeURIComponent(p)}_test`)
    .join("&");
  const sep = baseUrl.includes("?") ? "&" : "?";
  return `${baseUrl}${sep}${qs}`;
}

function buildPostBody(params: string[]): Record<string, string> {
  const body: Record<string, string> = {};
  for (const p of params) {
    body[p] = `netty_${p}_test`;
  }
  return body;
}

function markerFor(param: string): string {
  return `netty_${param}_test`;
}

function responseDiffers(
  baseStatus: number,
  baseLength: number,
  baseSnippet: string,
  newStatus: number,
  newBody: string,
): boolean {
  if (newStatus !== baseStatus) return true;
  if (Math.abs(newBody.length - baseLength) > 50) return true;
  // Reflected marker check is done per-param in binary search; here we do a bulk check
  return false;
}

function anyMarkerReflected(params: string[], body: string): boolean {
  return params.some((p) => body.includes(markerFor(p)));
}

async function runBatches<T>(
  tasks: Array<() => Promise<T>>,
  concurrency: number,
): Promise<Array<PromiseSettledResult<T>>> {
  const results: Array<PromiseSettledResult<T>> = [];
  for (let i = 0; i < tasks.length; i += concurrency) {
    const slice = tasks.slice(i, i + concurrency).map((fn) => fn());
    const settled = await Promise.allSettled(slice);
    results.push(...settled);
  }
  return results;
}

class ParameterDiscovery {
  async discover(
    targetUrl: string,
    authHeaders?: Record<string, string>,
    programId?: number,
  ): Promise<ParamDiscoveryResult> {
    const headers: Record<string, string> = {
      "User-Agent": "netty-hunter/1.0",
      ...(authHeaders ?? {}),
    };

    // 1. Baseline
    let baseStatus = 200;
    let baseLength = 0;
    let baseSnippet = "";
    try {
      const baseRes = await scopedHttp.get(targetUrl, {
        headers,
        timeout: REQUEST_TIMEOUT,
        validateStatus: () => true,
      }, programId);
      baseStatus = baseRes.status;
      const baseBody: string =
        typeof baseRes.data === "string"
          ? baseRes.data
          : JSON.stringify(baseRes.data);
      baseLength = baseBody.length;
      baseSnippet = baseBody.slice(0, 500);
      logger.debug(`[param-discovery] baseline ${targetUrl} status=${baseStatus} len=${baseLength}`);
    } catch (err) {
      logger.warn(`[param-discovery] baseline request failed for ${targetUrl}: ${err}`);
    }

    const wordlist = WORDLIST.slice(0, 80);
    const batches: string[][] = [];
    for (let i = 0; i < wordlist.length; i += BATCH_SIZE) {
      batches.push(wordlist.slice(i, i + BATCH_SIZE));
    }

    const discovered: DiscoveredParam[] = [];
    const discoveredSet = new Set<string>(); // dedupe by name+method

    // Helper: binary search a batch to find the specific triggering params
    const binarySearch = async (
      params: string[],
      method: "GET" | "POST",
    ): Promise<string[]> => {
      if (params.length === 0) return [];
      if (params.length === 1) return params;

      const mid = Math.floor(params.length / 2);
      const left = params.slice(0, mid);
      const right = params.slice(mid);
      const found: string[] = [];

      for (const half of [left, right]) {
        try {
          let status: number;
          let body: string;

          if (method === "GET") {
            const url = buildGetUrl(targetUrl, half);
            const res = await scopedHttp.get(url, {
              headers,
              timeout: REQUEST_TIMEOUT,
              validateStatus: () => true,
            }, programId);
            status = res.status;
            body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
          } else {
            const res = await scopedHttp.post(targetUrl, buildPostBody(half), {
              headers: { ...headers, "Content-Type": "application/json" },
              timeout: REQUEST_TIMEOUT,
              validateStatus: () => true,
            }, programId);
            status = res.status;
            body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
          }

          const differs =
            responseDiffers(baseStatus, baseLength, baseSnippet, status, body) ||
            anyMarkerReflected(half, body);

          if (differs) {
            if (half.length === 1) {
              found.push(half[0]);
            } else {
              const sub = await binarySearch(half, method);
              found.push(...sub);
            }
          }
        } catch (err) {
          logger.debug(`[param-discovery] binary-search error (${method}): ${err}`);
        }
      }

      return found;
    };

    // 2. GET batch tasks
    const getTasks = batches.map((batch) => async () => {
      const url = buildGetUrl(targetUrl, batch);
      try {
        const res = await scopedHttp.get(url, {
          headers,
          timeout: REQUEST_TIMEOUT,
          validateStatus: () => true,
        }, programId);
        const body =
          typeof res.data === "string" ? res.data : JSON.stringify(res.data);
        const differs =
          responseDiffers(baseStatus, baseLength, baseSnippet, res.status, body) ||
          anyMarkerReflected(batch, body);

        if (differs) {
          logger.debug(`[param-discovery] GET batch triggered, binary-searching ${batch.length} params`);
          const hits = await binarySearch(batch, "GET");
          for (const param of hits) {
            const key = `GET:${param}`;
            if (discoveredSet.has(key)) continue;
            discoveredSet.add(key);

            const paramRes = await scopedHttp.get(buildGetUrl(targetUrl, [param]), {
              headers,
              timeout: REQUEST_TIMEOUT,
              validateStatus: () => true,
            }, programId);
            const paramBody =
              typeof paramRes.data === "string"
                ? paramRes.data
                : JSON.stringify(paramRes.data);

            let type: DiscoveredParam["type"];
            let evidence: string;

            if (paramBody.includes(markerFor(param))) {
              type = "reflected";
              evidence = `marker ${markerFor(param)} reflected in GET response body`;
            } else if (paramRes.status >= 400) {
              type = "error_trigger";
              evidence = `GET response status changed to ${paramRes.status}`;
            } else {
              type = "behavior_change";
              evidence = `GET response length changed (base ${baseLength} → ${paramBody.length})`;
            }

            discovered.push({ name: param, method: "GET", url: targetUrl, evidence, type });
          }
        }
      } catch (err) {
        logger.debug(`[param-discovery] GET batch error: ${err}`);
      }
    });

    // 3. POST batch tasks
    const postTasks = batches.map((batch) => async () => {
      try {
        const res = await scopedHttp.post(targetUrl, buildPostBody(batch), {
          headers: { ...headers, "Content-Type": "application/json" },
          timeout: REQUEST_TIMEOUT,
          validateStatus: () => true,
        }, programId);
        const body =
          typeof res.data === "string" ? res.data : JSON.stringify(res.data);
        const differs =
          responseDiffers(baseStatus, baseLength, baseSnippet, res.status, body) ||
          anyMarkerReflected(batch, body);

        if (differs) {
          logger.debug(`[param-discovery] POST batch triggered, binary-searching ${batch.length} params`);
          const hits = await binarySearch(batch, "POST");
          for (const param of hits) {
            const key = `POST:${param}`;
            if (discoveredSet.has(key)) continue;
            discoveredSet.add(key);

            const singleBody = buildPostBody([param]);
            const paramRes = await scopedHttp.post(targetUrl, singleBody, {
              headers: { ...headers, "Content-Type": "application/json" },
              timeout: REQUEST_TIMEOUT,
              validateStatus: () => true,
            }, programId);
            const paramBody =
              typeof paramRes.data === "string"
                ? paramRes.data
                : JSON.stringify(paramRes.data);

            let type: DiscoveredParam["type"];
            let evidence: string;

            if (paramBody.includes(markerFor(param))) {
              type = "reflected";
              evidence = `marker ${markerFor(param)} reflected in POST response body`;
            } else if (paramRes.status >= 400) {
              type = "error_trigger";
              evidence = `POST response status changed to ${paramRes.status}`;
            } else {
              type = "behavior_change";
              evidence = `POST response length changed (base ${baseLength} → ${paramBody.length})`;
            }

            discovered.push({ name: param, method: "POST", url: targetUrl, evidence, type });
          }
        }
      } catch (err) {
        logger.debug(`[param-discovery] POST batch error: ${err}`);
      }
    });

    // Run GET then POST batches, max concurrency 5
    await runBatches(getTasks, MAX_CONCURRENCY);
    await runBatches(postTasks, MAX_CONCURRENCY);

    // 4. Build hypotheses
    const hypotheses: ParamDiscoveryResult["hypotheses"] = [];
    for (const dp of discovered) {
      if (dp.type === "reflected") {
        hypotheses.push({
          vulnClass: "xss",
          reasoning: `Parameter "${dp.name}" reflects user input in the response — potential XSS injection point`,
          targetUrl: `${dp.url}${dp.url.includes("?") ? "&" : "?"}${encodeURIComponent(dp.name)}=<payload>`,
          confidence: 0.65,
          priority: 7,
        });
      } else if (dp.type === "error_trigger") {
        hypotheses.push({
          vulnClass: "info_disclosure",
          reasoning: `Parameter "${dp.name}" triggers an error response — may expose stack traces or internal details`,
          targetUrl: dp.url,
          confidence: 0.6,
          priority: 6,
        });
      } else {
        hypotheses.push({
          vulnClass: "idor",
          reasoning: `Parameter "${dp.name}" alters server behavior — possible IDOR or access-control bypass`,
          targetUrl: dp.url,
          confidence: 0.55,
          priority: 6,
        });
      }
    }

    logger.info(
      `[param-discovery] ${targetUrl} — tested ${wordlist.length} params, discovered ${discovered.length}`,
    );

    return {
      discovered,
      tested: wordlist.length,
      hypotheses,
    };
  }
}

export const parameterDiscovery = new ParameterDiscovery();
