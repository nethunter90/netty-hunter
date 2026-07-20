/**
 * Scoped HTTP — the mandatory transport-layer egress chokepoint.
 *
 * Every outbound request a prober makes — including every redirect hop —
 * must go through scopedHttp. Raw `axios` (or any other HTTP client) is
 * disallowed outside this module; the CI import-guard (see
 * scripts/check-scope-egress.ts) fails the build if it finds one.
 *
 * Why a manual redirect loop instead of axios's built-in follow-redirects:
 * follow-redirects invokes its `beforeRedirect` hook SYNCHRONOUSLY and does
 * not await its return value (confirmed by reading
 * node_modules/follow-redirects/index.js:478-494 — `beforeRedirect(...)` is
 * called, then `_sanitizeOptions`/`_performRequest()` run immediately after,
 * with no promise awaited in between). A scope check needs an async DB read
 * plus DNS resolution, so a `beforeRedirect` hook cannot reliably block a
 * hop — the redirected request would already be in flight by the time the
 * check's promise resolves, silently defeating the guard. Forcing
 * `maxRedirects: 0` on the underlying axios call and following hops
 * ourselves, awaiting a real scope decision before each one, is the only
 * way to make this genuinely synchronous-safe.
 *
 * The entry hop dispatches via axios.get/axios.post (matching the verb the
 * caller used) rather than axios.request, purely so existing call sites and
 * their test mocks (which stub axios.get/axios.post directly) keep working
 * unchanged. Only a redirect hop — a new URL this module derives itself —
 * uses axios.request, since no caller mocks that path today.
 *
 * programId is required (not optional) on every call — see
 * scopeGuard.ts's classifyProgramPolicy for the three-way policy. There is
 * no "skip if missing" path anymore; a missing/invalid programId fails
 * closed inside ScopeGuard itself.
 */
import axios, { AxiosRequestConfig, AxiosResponse } from "axios";
import { ScopeGuard } from "../../middleware/scopeGuard";
import logger from "../../utils/logger";

export class OutOfScopeError extends Error {
  constructor(public readonly url: string, public readonly reason: string) {
    super(`Out of scope: ${url} — ${reason}`);
    this.name = "OutOfScopeError";
  }
}

export class MaxRedirectsExceededError extends Error {
  constructor(public readonly url: string) {
    super(`Max redirects exceeded following: ${url}`);
    this.name = "MaxRedirectsExceededError";
  }
}

const guard = ScopeGuard.getInstance();
const DEFAULT_MAX_REDIRECTS = 5; // matches axios's own historical default

async function assertInScope(url: string, programId: number | null | undefined): Promise<void> {
  const { allowed, reason } = await guard.isInScope(url, programId);
  if (!allowed) {
    logger.warn("[scopedHttp] Blocked out-of-scope egress", { url, programId, reason });
    throw new OutOfScopeError(url, reason);
  }
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/** Resolve the next hop's method/body per RFC 7231 §6.4, mirroring
 *  follow-redirects' own behavior (index.js:437-450) so migrating callers
 *  see no behavior change beyond the added scope check. */
function nextHopMethodAndBody(
  statusCode: number,
  method: string,
  data: unknown,
): { method: string; data: unknown } {
  const upperMethod = method.toUpperCase();
  if ((statusCode === 301 || statusCode === 302) && upperMethod === "POST") {
    return { method: "GET", data: undefined };
  }
  if (statusCode === 303 && !/^(GET|HEAD)$/.test(upperMethod)) {
    return { method: "GET", data: undefined };
  }
  return { method: upperMethod, data }; // 307/308, or already GET/HEAD — preserve
}

type EntryVerb = "GET" | "POST" | "REQUEST";

async function scopedRequest(
  entryVerb: EntryVerb,
  config: AxiosRequestConfig & { url: string },
  programId: number | null | undefined,
): Promise<AxiosResponse> {
  const callerMaxRedirects = config.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const { url: initialUrl, method: initialMethodRaw, data: initialData, ...restConfig } = config;
  let currentUrl = initialUrl;
  let currentMethod = (initialMethodRaw || (entryVerb === "POST" ? "POST" : "GET")).toUpperCase();
  let currentData = initialData;
  let redirectsFollowed = 0;

  for (;;) {
    await assertInScope(currentUrl, programId);

    const hopConfig: AxiosRequestConfig = { ...restConfig, maxRedirects: 0 };
    const isFirstHop = redirectsFollowed === 0;
    const resp: AxiosResponse =
      isFirstHop && entryVerb === "GET" ? await axios.get(currentUrl, hopConfig) :
      isFirstHop && entryVerb === "POST" ? await axios.post(currentUrl, currentData, hopConfig) :
      await axios.request({ ...hopConfig, url: currentUrl, method: currentMethod, data: currentData });

    const isRedirect = REDIRECT_STATUSES.has(resp.status);
    const location = resp.headers?.location as string | undefined;

    if (!isRedirect || !location || callerMaxRedirects === 0) {
      return resp; // terminal response, or caller explicitly wants no auto-follow
    }
    if (redirectsFollowed >= callerMaxRedirects) {
      throw new MaxRedirectsExceededError(currentUrl);
    }

    const nextUrl = new URL(location, currentUrl).toString();
    const { method: nextMethod, data: nextData } = nextHopMethodAndBody(resp.status, currentMethod, currentData);

    currentUrl = nextUrl;
    currentMethod = nextMethod;
    currentData = nextData;
    redirectsFollowed++;
    // loop back: assertInScope() re-validates this hop before it's ever sent
  }
}

export const scopedHttp = {
  async get(url: string, config: AxiosRequestConfig = {}, programId?: number | null): Promise<AxiosResponse> {
    return scopedRequest("GET", { ...config, url, method: "GET" }, programId);
  },
  async post(url: string, data?: unknown, config: AxiosRequestConfig = {}, programId?: number | null): Promise<AxiosResponse> {
    return scopedRequest("POST", { ...config, url, method: "POST", data }, programId);
  },
  async request(config: AxiosRequestConfig & { url: string }, programId?: number | null): Promise<AxiosResponse> {
    return scopedRequest("REQUEST", config, programId);
  },
};
