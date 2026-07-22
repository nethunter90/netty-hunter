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
 *
 * 2026-07-21 readiness pass (item B): dynamicRateLimiter existed (real,
 * unit-tested class) but had zero callers outside its own test files — every
 * direct probe HTTP call fired with no pacing at all, proven live from raw
 * logs (36 requests in a single OBSERVE-phase batch sharing one timestamp).
 * Wired here, at the one place every probe's request actually goes through,
 * so pacing (and reactive 429/403/backoff learning) applies uniformly
 * regardless of which prober or tool issued the call.
 */
import axios, { AxiosRequestConfig, AxiosResponse } from "axios";
import { ScopeGuard } from "../../middleware/scopeGuard";
import { dynamicRateLimiter } from "../stealth/dynamic-rate-limiter";
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

export class RateLimitedError extends Error {
  constructor(public readonly url: string, public readonly reason: string, public readonly retryAfter?: number) {
    super(`Rate limited: ${url} — ${reason}`);
    this.name = "RateLimitedError";
  }
}

const guard = ScopeGuard.getInstance();
const DEFAULT_MAX_REDIRECTS = 5; // matches axios's own historical default
// Hard ceiling on any single proactive pacing wait — calculateQuotaDelay() can
// in principle recommend waiting until a discovered quota's reset time, which
// could be minutes away. Capping keeps one hop from silently stalling a whole
// probe cycle; a longer wait is better expressed as quarantine (which throws)
// than as a delay nobody is watching.
const MAX_PROACTIVE_DELAY_MS = 30_000;

async function assertInScope(url: string, programId: number | null | undefined): Promise<void> {
  const { allowed, reason } = await guard.isInScope(url, programId);
  if (!allowed) {
    logger.warn("[scopedHttp] Blocked out-of-scope egress", { url, programId, reason });
    throw new OutOfScopeError(url, reason);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/** Proactive pacing gate — checked before every hop actually goes out.
 *  `programId > 0` (a real bug-bounty program, not the -1 local-lab sentinel
 *  or an absent/invalid id) forces pacing on regardless of
 *  DYNAMIC_RATE_LIMIT_ENABLED — see checkRateLimit()'s `force` param. */
async function applyRateLimit(url: string, programId: number | null | undefined): Promise<void> {
  let target: string;
  let endpoint: string;
  try {
    const parsed = new URL(url);
    target = parsed.hostname;
    endpoint = parsed.pathname || "/";
  } catch {
    return; // unparseable URL — let assertInScope() reject it instead
  }

  const forceEnabled = typeof programId === "number" && programId > 0;
  const check = dynamicRateLimiter.checkRateLimit(target, endpoint, forceEnabled);
  if (!check.allowed) {
    logger.warn("[scopedHttp] Blocked by rate limiter (quarantine/backoff active)", {
      url, target, endpoint, reason: check.reason, retryAfter: check.retryAfter,
    });
    throw new RateLimitedError(url, check.reason ?? "quarantined", check.retryAfter);
  }
  if (check.recommendedDelay > 0) {
    const delay = Math.min(check.recommendedDelay, MAX_PROACTIVE_DELAY_MS);
    logger.info("[scopedHttp] Pacing outbound request", { url, target, endpoint, delayMs: delay, reason: check.reason });
    await sleep(delay);
  }
}

/** Reactive feedback gate — feeds the real response back so future checks adapt. */
function recordRateLimitResponse(url: string, statusCode: number, headers: Record<string, unknown>): void {
  let target: string;
  let endpoint: string;
  try {
    const parsed = new URL(url);
    target = parsed.hostname;
    endpoint = parsed.pathname || "/";
  } catch {
    return;
  }
  const stringHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers ?? {})) {
    if (v !== undefined && v !== null) stringHeaders[k] = String(v);
  }
  dynamicRateLimiter.recordResponse(target, endpoint, statusCode, stringHeaders);
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
    await applyRateLimit(currentUrl, programId);

    const hopConfig: AxiosRequestConfig = { ...restConfig, maxRedirects: 0 };
    const isFirstHop = redirectsFollowed === 0;
    let resp: AxiosResponse;
    try {
      resp =
        isFirstHop && entryVerb === "GET" ? await axios.get(currentUrl, hopConfig) :
        isFirstHop && entryVerb === "POST" ? await axios.post(currentUrl, currentData, hopConfig) :
        await axios.request({ ...hopConfig, url: currentUrl, method: currentMethod, data: currentData });
    } catch (err) {
      if (axios.isAxiosError(err) && err.response) {
        recordRateLimitResponse(currentUrl, err.response.status, err.response.headers as Record<string, unknown>);
      }
      throw err;
    }
    recordRateLimitResponse(currentUrl, resp.status, resp.headers as Record<string, unknown>);

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
